//! Outbreak pipeline hooks and bounded background rescans. Content never
//! leaves the host; mailbox removal belongs to adapters for #41/#51.
use crate::Pipeline;
use currawong_core::{Direction, ScanReport};
use currawong_integrations::export::{emit, Event, EventKind};
use currawong_outbreak::{
    similarity, Content, Detection, Feature, Message, Remediation, Store, MAX_PARTS,
};
use currawong_scan::{ClamdAddress, ClamdClient, EngineResult, ScanOutcome};
use currawong_spool::Envelope;
use sha2::{Digest as _, Sha256};
use std::{collections::BTreeMap, sync::Arc};
use tokio::io::AsyncReadExt;

pub struct LogRemediation;
impl Remediation for LogRemediation {
    fn remediate(&self, detection: &Detection) -> Result<(), String> {
        tracing::warn!(message_id=%detection.message_id, tenant=%detection.tenant,
            source=%detection.source, indicator=%detection.indicator,
            "retro detection: mailbox remediation adapter not configured");
        Ok(())
    }
}

pub fn emit_detection(detection: &Detection) {
    tracing::warn!(message_id=%detection.message_id,tenant=%detection.tenant,
        source=%detection.source,indicator=%detection.indicator,"post-delivery threat detected");
    emit(detection_event(detection));
}

pub fn detection_event(detection: &Detection) -> Event {
    Event::new(
        Some(&detection.tenant),
        EventKind::VerdictChanged {
            message_id: detection.message_id.clone(),
            from: "deliver".into(),
            to: "retro_detection".into(),
            changed_by: format!("outbreak:{}:{}", detection.source, detection.indicator),
        },
    )
}

/// One 256-row page, looked up against the local intel store only. A fake
/// Syncer can populate the same store in offline integration tests.
pub fn retro_intel_page(
    store: &Store,
    intel: &currawong_intel::Store,
    after: i64,
    now: i64,
) -> Result<Option<i64>, String> {
    let page = store.indicator_page(after)?;
    if page.is_empty() {
        return Ok(None);
    }
    for (_, kind, value) in &page {
        let kind = currawong_intel::Kind::parse(kind).ok_or("invalid outbreak indicator kind")?;
        let candidates = if kind == currawong_intel::Kind::Url {
            currawong_intel::url_candidates(value)
        } else {
            vec![(kind, value.clone())]
        };
        for hit in intel.lookup_many(&candidates, now)? {
            store.detect(
                kind.as_str(),
                value,
                &format!("intel:{}:{}", hit.source, hit.threat),
            )?;
        }
    }
    Ok(page.last().map(|row| row.0))
}

impl Pipeline {
    fn outbreak_tenants(&self, env: &Envelope) -> BTreeMap<String, Vec<String>> {
        let mut groups = BTreeMap::new();
        for rcpt in env.rcpt_to.iter().take(256) {
            let domain = rcpt.rsplit_once('@').map(|(_, d)| d).unwrap_or("");
            let tenant = if env.direction == Direction::Outbound {
                env.tenant_id.as_deref()
            } else {
                self.cfg
                    .relay
                    .tenants
                    .iter()
                    .find(|t| t.domains.iter().any(|d| d.eq_ignore_ascii_case(domain)))
                    .map(|t| t.id.as_str())
            };
            groups
                .entry(tenant.unwrap_or("").to_string())
                .or_insert_with(Vec::new)
                .push(rcpt.clone());
        }
        groups
    }

    pub async fn check_outbreak(&self, env: &Envelope, body: &str, report: &mut ScanReport) {
        self.check_outbreak_at(env, body, report, currawong_intel::now())
            .await;
    }

    /// Caller-supplied time is the sole hold clock; no sleeps in tests.
    pub async fn check_outbreak_at(
        &self,
        env: &Envelope,
        body: &str,
        report: &mut ScanReport,
        now: i64,
    ) {
        let Some(store) = &self.outbreak else {
            return;
        };
        let result = match store {
            Ok(store) => self.outbreak_assess(store, env, body, report, now).await,
            Err(err) => Err(err.clone()),
        };
        match result {
            Ok(result) => {
                if result.held {
                    report.defer = true;
                    report.flags.push("outbreak.held".into());
                    report
                        .notes
                        .push("outbreak hold: attachment inside first-seen delay window".into());
                }
                if result.messages >= self.cfg.outbreak.campaign_threshold {
                    report.flags.push("campaign".into());
                }
                if result.truncated {
                    report.notes.push(
                        "outbreak campaign/index limits reached; counts are lower bounds".into(),
                    );
                }
                report.outbreak = Some(result);
            }
            Err(err) => {
                report.defer = true;
                report
                    .notes
                    .push(format!("outbreak store unavailable: {err}"));
            }
        }
    }

    async fn outbreak_assess(
        &self,
        store: &Arc<Store>,
        env: &Envelope,
        body: &str,
        report: &ScanReport,
        now: i64,
    ) -> Result<currawong_core::report::OutbreakReport, String> {
        let mut content = Content::from_report(report, body);
        let mut retained = Vec::new();
        let mut budget = 32 * 1024 * 1024_usize;
        let mut limited =
            report.parts.len() > MAX_PARTS || report.urls.len() > currawong_outbreak::MAX_URLS;
        for part in report.parts.iter().take(MAX_PARTS) {
            let attachment = part.is_attachment || part.filename.is_some();
            if !attachment && self.cfg.outbreak.retain_parts_hours == 0 {
                continue;
            }
            let Some(path) = &part.path else {
                continue;
            };
            let max = if self.cfg.outbreak.retain_parts_hours > 0 {
                self.cfg.outbreak.max_part_bytes as usize
            } else {
                256 * 1024
            };
            let amount = (part.size.min(max as u64) as usize).min(budget);
            if amount == 0 {
                limited = true;
                break;
            }
            let file = tokio::fs::File::open(path)
                .await
                .map_err(|e| e.to_string())?;
            let mut bytes = Vec::new();
            file.take(amount as u64)
                .read_to_end(&mut bytes)
                .await
                .map_err(|e| e.to_string())?;
            budget = budget.saturating_sub(bytes.len());
            if let Some(digest) = attachment.then(|| similarity::digest(&bytes)).flatten() {
                content.features.push(Feature {
                    kind: "attachment".into(),
                    value: part.sha256.clone(),
                    content_type: part.content_type.clone(),
                    digest: Some(digest),
                });
            }
            if self.cfg.outbreak.retain_parts_hours > 0 && bytes.len() as u64 == part.size {
                retained.push((part.sha256.clone(), bytes));
            } else if self.cfg.outbreak.retain_parts_hours > 0 {
                limited = true;
            }
        }
        let groups = self.outbreak_tenants(env);
        let id = env.id.to_string();
        let sender = env.mail_from.to_ascii_lowercase();
        let direction = env.direction;
        let hold_types = self.cfg.outbreak.hold_types.clone();
        let risky = report
            .parts
            .iter()
            .any(|p| currawong_outbreak::hold_type(p).is_some());
        let hashes: Vec<_> = report
            .parts
            .iter()
            .filter(|p| p.is_attachment || p.filename.is_some())
            .filter(|p| {
                currawong_outbreak::hold_type(p)
                    .is_some_and(|kind| hold_types.iter().any(|s| s == kind))
                    || (risky
                        && hold_types.iter().any(|s| s == "risky_archive")
                        && [
                            "application/zip",
                            "application/x-7z-compressed",
                            "application/x-tar",
                            "application/gzip",
                        ]
                        .contains(&p.content_type.as_str()))
            })
            .take(MAX_PARTS)
            .map(|p| p.sha256.clone())
            .collect();
        let store = Arc::clone(store);
        tokio::task::spawn_blocking(move || {
            let mut result = currawong_core::report::OutbreakReport::default();
            // Register every tenant before evaluating min_tenants, so one
            // multi-tenant SMTP message has no recipient-order dependence.
            if direction == Direction::Inbound {
                for hash in &hashes {
                    for tenant in groups.keys() {
                        store.hold(hash, tenant, now)?;
                    }
                }
            }
            for (tenant, recipients) in &groups {
                let counts = store.observe(
                    &Message {
                        id: &id,
                        tenant,
                        direction,
                        sender: &sender,
                        recipients,
                    },
                    &content,
                    now,
                )?;
                result.messages = counts.messages;
                result.tenants = counts.tenants;
                result.senders = counts.senders;
                result.truncated |= counts.truncated || limited;
                if direction == Direction::Inbound {
                    for hash in &hashes {
                        let (held, age) = store.hold(hash, tenant, now)?;
                        result.held |= held;
                        if held {
                            if let Some(deadline) = store.hold_deadline(hash)? {
                                result.hold_until =
                                    Some(result.hold_until.map_or(deadline, |d| d.max(deadline)));
                            }
                        }
                        result.first_seen_minutes =
                            Some(result.first_seen_minutes.map_or(age, |a| a.min(age)));
                    }
                }
            }
            for (hash, bytes) in retained {
                result.truncated |= !store.retain(&hash, &bytes, now)?;
            }
            Ok(result)
        })
        .await
        .map_err(|e| e.to_string())?
    }

    pub async fn index_delivered(&self, staged_id: &str, env: &Envelope) -> Result<(), String> {
        self.copy_outbreak_record(staged_id, env, true, None).await
    }

    pub async fn stage_outbreak_copy(&self, staged_id: &str, env: &Envelope) -> Result<(), String> {
        self.copy_outbreak_record(staged_id, env, false, None).await
    }

    /// Recipient actions can redirect outside a tenant's domains. Preserve
    /// the policy owner's tenant while recording the actual delivery targets.
    pub async fn index_delivered_for(
        &self,
        staged_id: &str,
        env: &Envelope,
        tenant: Option<&str>,
    ) -> Result<(), String> {
        self.copy_outbreak_record(staged_id, env, true, tenant)
            .await
    }

    async fn copy_outbreak_record(
        &self,
        staged_id: &str,
        env: &Envelope,
        delivered: bool,
        tenant: Option<&str>,
    ) -> Result<(), String> {
        let Some(store) = &self.outbreak else {
            return Ok(());
        };
        let store = Arc::clone(store.as_ref().map_err(Clone::clone)?);
        let groups = tenant.map_or_else(
            || self.outbreak_tenants(env),
            |tenant| {
                BTreeMap::from([(
                    tenant.to_string(),
                    env.rcpt_to.iter().take(256).cloned().collect(),
                )])
            },
        );
        let id = env.id.to_string();
        let staged_id = staged_id.to_string();
        let sender = env.mail_from.clone();
        let direction = env.direction;
        tokio::task::spawn_blocking(move || {
            for (tenant, recipients) in groups {
                let message = Message {
                    id: &id,
                    tenant: &tenant,
                    direction,
                    sender: &sender,
                    recipients: &recipients,
                };
                if delivered {
                    store.deliver(&staged_id, &message, currawong_intel::now())?;
                } else {
                    store.stage_copy(&staged_id, &message)?;
                }
            }
            Ok(())
        })
        .await
        .map_err(|e| e.to_string())?
    }

    /// Each scheduler pass handles one intel page and one retained part per engine.
    /// Persistent cursors survive restarts; failed scans do not advance them.
    pub async fn outbreak_tick(&self) -> Result<(), String> {
        let Some(store) = &self.outbreak else {
            return Ok(());
        };
        let store = Arc::clone(store.as_ref().map_err(Clone::clone)?);
        let now = currawong_intel::now();
        let intel = self.intel.as_ref().map(|i| Arc::clone(&i.store));
        let tick_store = Arc::clone(&store);
        let remediation = Arc::clone(&self.outbreak_remediation);
        let index = tokio::task::spawn_blocking(move || {
            tick_store.purge(now)?;
            if let Some(intel) = intel {
                let revision = intel.revision()?;
                if tick_store.state("intel_revision")?.as_deref() != Some(&revision) {
                    if tick_store.state("intel_target")?.as_deref() != Some(&revision) {
                        tick_store.set_state("intel_target", &revision)?;
                        tick_store.set_state("intel_cursor", "0")?;
                    }
                    let after = tick_store
                        .state("intel_cursor")?
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(0);
                    match retro_intel_page(&tick_store, &intel, after, now)? {
                        Some(cursor) => {
                            tick_store.set_state("intel_cursor", &cursor.to_string())?
                        }
                        None => tick_store.set_state("intel_revision", &revision)?,
                    }
                }
            }
            tick_store.notify(remediation.as_ref(), emit_detection)?;
            Ok::<_, String>(())
        })
        .await
        .map_err(|e| e.to_string())?;
        if self.cfg.outbreak.retain_parts_hours == 0 {
            return index;
        }
        // Independent engine cursors: a broken clamd cannot block YARA,
        // and a failed parser worker cannot block signature rescans.
        let yara = self.outbreak_yara_tick(&store, now).await;
        let clam = self.outbreak_clam_tick(&store, now).await;
        let notified = store.notify(self.outbreak_remediation.as_ref(), emit_detection);
        index?;
        yara?;
        clam?;
        notified?;
        Ok(())
    }

    async fn outbreak_yara_tick(&self, store: &Store, now: i64) -> Result<(), String> {
        let Some(engine) = &self.yara else {
            return Ok(());
        };
        let rules = engine.current();
        let revision = format!(
            "{}:{}",
            rules.generation,
            hex::encode(Sha256::digest(rules.encoded.as_bytes()))
        );
        let Some((hash, bytes)) = next_part(store, "yara", &revision, now)? else {
            return Ok(());
        };
        let pool = self
            .pool
            .as_ref()
            .ok_or("outbreak retro scan needs parser worker")?;
        let file = tempfile::NamedTempFile::new().map_err(|e| e.to_string())?;
        tokio::fs::write(file.path(), &bytes)
            .await
            .map_err(|e| e.to_string())?;
        match pool
            .scan_file_with_rules(
                "outbreak-retro",
                file.path(),
                &self.cfg.scanner.extract,
                Some(&rules),
            )
            .await
        {
            ScanOutcome::Parsed(parsed) => {
                for hit in parsed.yara {
                    store.detect(
                        "sha256",
                        &hash,
                        &format!("yara:{}:{}", hit.namespace, hit.rule),
                    )?;
                }
            }
            ScanOutcome::Failed { reason } | ScanOutcome::Unavailable { reason } => {
                return Err(reason)
            }
        }
        store.set_state("yara_cursor", &hash)
    }

    async fn outbreak_clam_tick(&self, store: &Store, now: i64) -> Result<(), String> {
        if self.cfg.scanner.clamd.address.is_empty() {
            return Ok(());
        }
        let clam = ClamdClient::new(ClamdAddress::parse(&self.cfg.scanner.clamd.address)?, false);
        let revision = clam.version().await?;
        let Some((hash, bytes)) = next_part(store, "clamav", &revision, now)? else {
            return Ok(());
        };
        match clam.scan_message(&bytes, &[]).await {
            EngineResult::Malware { signature } => {
                store.detect("sha256", &hash, &format!("clamav:{signature}"))?
            }
            EngineResult::Failed { reason, .. } => return Err(reason),
            _ => {}
        }
        store.set_state("clamav_cursor", &hash)
    }
}

fn next_part(
    store: &Store,
    engine: &str,
    revision: &str,
    now: i64,
) -> Result<Option<(String, Vec<u8>)>, String> {
    let done = format!("{engine}_revision");
    let target = format!("{engine}_target");
    let cursor = format!("{engine}_cursor");
    if store.state(&done)?.as_deref() == Some(revision) {
        return Ok(None);
    }
    if store.state(&target)?.as_deref() != Some(revision) {
        store.set_state(&target, revision)?;
        store.set_state(&cursor, "")?;
    }
    let after = store.state(&cursor)?.unwrap_or_default();
    let part = store.retained_page(&after, now)?.into_iter().next();
    if part.is_none() {
        store.set_state(&done, revision)?;
    }
    Ok(part)
}
