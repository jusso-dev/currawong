//! Auth, parse, scan, DLP and the policy decision.
use currawong_auth::{strip_forged, AuthChecker, KeyStore, StoredKey, GATEWAY_TENANT};
use currawong_core::{
    config::Config, AuthResults, Direction, EngineFinding, PartFlag, ScanReport, Verdict,
};
use currawong_parser::{parse::parse_bytes_with, text::DlpText, ParseResponse};
use currawong_policy::{
    canonical_domain, default_pack, evaluate_message, Context, MessageDecision, PolicySet,
};
use currawong_scan::engines::yara::{self, CompiledRules, PollWatcher};
use currawong_scan::{
    combine, ClamdAddress, ClamdClient, EngineOutput, FileTypeScanner, ScanItem, ScanOutcome,
    Scanner, WorkerPool, YaraEngine,
};
use currawong_spool::Envelope;
use std::{path::Path, sync::Arc};

pub struct Pipeline {
    pub cfg: Arc<Config>,
    pub auth: AuthChecker,
    pub pool: Option<WorkerPool>,
    pub yara: Option<Arc<YaraEngine>>,
    /// YARA is configured but its rules could not be loaded: fail closed.
    pub yara_error: Option<String>,
    _yara_watch: Option<PollWatcher>,
    /// DKIM and ARC keys. `None` means nothing is signed or sealed.
    pub keys: Option<Arc<KeyStore>>,
    pub policies: PolicySet,
    policy_stamp: Option<currawong_policy::Stamp>,
}

impl Pipeline {
    pub fn new(cfg: Arc<Config>, auth: AuthChecker) -> Self {
        let pool = worker_binary(&cfg).map(|binary| {
            WorkerPool::new(
                binary,
                cfg.scanner.job_timeout_secs,
                cfg.scanner.max_jobs_per_worker as u64,
            )
            .with_limits(cfg.scanner.worker_memory_mib, cfg.scanner.worker_cpu_secs)
            .with_rules_load_timeout(cfg.scanner.yara.load_timeout_secs)
        });
        let (yara, yara_error) = match yara_engine(&cfg) {
            Ok(yara) => (yara, None),
            Err(err) => {
                tracing::error!(%err, "yara rules unavailable, mail fails closed");
                (None, Some(err))
            }
        };
        let _yara_watch = yara.as_ref().and_then(|engine| match engine.watch() {
            Ok(watcher) => Some(watcher),
            Err(err) => {
                tracing::error!(%err, "yara hot reload disabled");
                None
            }
        });
        Self {
            cfg,
            auth,
            pool,
            yara,
            yara_error,
            _yara_watch,
            keys: None,
            policies: default_pack().clone(),
            policy_stamp: None,
        }
    }

    pub fn with_keys(mut self, keys: KeyStore) -> Self {
        self.keys = Some(Arc::new(keys));
        self
    }

    /// Forged Authentication-Results left in older spool files (accepted
    /// before DATA stripped them) are removed from `body_path` too, so they
    /// are never delivered. Returns the cleaned bytes.
    pub async fn strip_spooled(
        &self,
        raw: &[u8],
        body_path: Option<&Path>,
    ) -> Result<Vec<u8>, String> {
        let cleaned = strip_forged(raw, self.auth.authserv_id());
        if cleaned.len() != raw.len() {
            if let Some(path) = body_path {
                rewrite_body(path, &cleaned)
                    .await
                    .map_err(|err| format!("could not strip forged headers: {err}"))?;
            }
        }
        Ok(cleaned)
    }

    /// Our Authentication-Results, for inbound mail only: on outbound mail
    /// it would leak internal addresses and attest a meaningless SPF result.
    pub fn auth_headers(&self, env: &Envelope, report: &ScanReport) -> Vec<String> {
        match env.direction {
            Direction::Inbound => report.auth.iter().map(auth_header).collect(),
            Direction::Outbound => Vec::new(),
        }
    }

    /// Headers the deliverer prepends. Inbound: Authentication-Results, plus
    /// an ARC set when a stage modified the message. Outbound: DKIM
    /// signatures with the tenant's active keys. Replaces any earlier set so
    /// re-evaluating deferred mail never stacks. `Err` when the tenant has a
    /// key but signing failed.
    pub async fn delivery_headers(
        &self,
        env: &Envelope,
        raw: &[u8],
        report: &ScanReport,
    ) -> Result<Vec<String>, String> {
        if env.direction == Direction::Inbound {
            if report.modified {
                if let Some(sealer) = self.arc_sealer().await {
                    let sealed = self.auth.check_and_seal(raw, env, Some(&sealer)).await;
                    return Ok(vec![sealed.header]);
                }
            }
            return Ok(self.auth_headers(env, report));
        }
        let (Some(keys), Some(tenant), true) =
            (&self.keys, &env.tenant_id, self.cfg.dkim.sign_outbound)
        else {
            return Ok(Vec::new());
        };
        let (keys, tenant_id, owned) = (Arc::clone(keys), tenant.clone(), raw.to_vec());
        let signed = tokio::task::spawn_blocking(move || {
            currawong_auth::sign_outbound(&keys, &owned, &tenant_id)
        })
        .await
        .map_err(|err| err.to_string())??;
        if signed.is_empty() {
            tracing::warn!(id = %env.id, %tenant, "no active DKIM key for sender domain");
            return Ok(Vec::new());
        }
        Ok(vec![signed])
    }

    /// Active gateway key for the authserv-id domain, RSA first because
    /// RFC 8617 verifiers are only required to support rsa-sha256.
    async fn arc_sealer(&self) -> Option<StoredKey> {
        if !self.cfg.dkim.seal_arc {
            return None;
        }
        let keys = Arc::clone(self.keys.as_ref()?);
        let domain = self.auth.authserv_id().to_string();
        let found =
            tokio::task::spawn_blocking(move || keys.signing_keys(GATEWAY_TENANT, &domain, now()))
                .await
                .map_err(|err| err.to_string())
                .and_then(|found| found);
        match found {
            Ok(mut found) => {
                found.sort_by_key(|key| key.algorithm != "rsa-sha256");
                found.into_iter().next()
            }
            Err(err) => {
                tracing::error!(%err, "ARC key lookup failed");
                None
            }
        }
    }

    pub fn with_policies(mut self, policies: PolicySet) -> Self {
        self.policies = policies;
        self
    }

    /// Load the configured policies again if their source changed. Runs the
    /// file and SQLite reads on a blocking thread. Returns whether they changed.
    pub async fn reload_policies(&mut self) -> Result<bool, String> {
        let cfg = self.cfg.policy.clone();
        let last = self.policy_stamp.clone();
        let loaded = tokio::task::spawn_blocking(move || {
            let stamp = currawong_policy::stamp(&cfg)?;
            if last.as_ref() == Some(&stamp) {
                return Ok(None);
            }
            Ok(Some((stamp, currawong_policy::load(&cfg))))
        })
        .await
        .map_err(|err| err.to_string())?
        .map_err(|err: currawong_policy::PolicyError| err.to_string())?;
        let Some((stamp, set)) = loaded else {
            return Ok(false);
        };
        // A bad source is reported once, then again only after it changes.
        self.policy_stamp = Some(stamp);
        let set = set.map_err(|err| err.to_string())?;
        if set == self.policies {
            return Ok(false);
        }
        for policy in set.policies.iter().filter(|p| !p.override_floor.is_empty()) {
            tracing::warn!(
                policy = %policy.id,
                rules = ?policy.override_floor,
                "policy lifts the built-in floor for the mail it matches"
            );
        }
        self.policies = set;
        Ok(true)
    }

    /// One verdict for the whole message. See `assess` for per-recipient decisions.
    pub async fn evaluate(
        &mut self,
        env: &Envelope,
        raw: &[u8],
        body_path: Option<&Path>,
    ) -> (ScanReport, Verdict) {
        let (report, decision) = self.assess(env, raw, body_path).await;
        (report, decision.verdict())
    }

    pub async fn assess(
        &mut self,
        env: &Envelope,
        raw: &[u8],
        body_path: Option<&Path>,
    ) -> (ScanReport, MessageDecision) {
        let mut report = ScanReport::new(env.id.clone());
        let auth = self.auth.check(raw, env).await;
        // The DMARC record could not be fetched, so its policy is unknown:
        // retry rather than deliver a possible p=reject spoof.
        if auth.dmarc.result == "temperror" {
            report.defer = true;
            report
                .notes
                .push("dmarc temperror: policy DNS unreachable".into());
        }
        report.auth = Some(auth);
        if !self.cfg.scanner.enabled {
            // No worker: decoded text bodies only; documents mark it incomplete.
            self.scan_dlp(env, &currawong_parser::text::body_text(raw), &mut report);
            let decision = self.decide(env, &report);
            return (report, decision);
        }
        let rules = self.yara.as_ref().map(|engine| engine.current());
        let parsed = self.parse(env, raw, body_path, rules.as_deref()).await;
        drop(rules);
        report.parts = parsed.parts.clone();
        report.urls = parsed.urls.clone();
        report.yara = parsed.yara.clone();
        self.scan_dlp(env, &parsed.dlp, &mut report);
        let parser_failed = parsed.error.is_some();
        if let Some(err) = parsed.error {
            report.notes.push(err);
        }
        self.fold_part_flags(&mut report);
        let mut outputs = Vec::new();
        let filetype = FileTypeScanner {
            treat_macros_as_active: self.cfg.scanner.treat_macros_as_active,
            treat_executables_as_active: self.cfg.scanner.treat_executables_as_active,
            limits: self.cfg.scanner.extract.clone(),
        };
        let result = filetype
            .scan(&ScanItem {
                name: "message.eml",
                bytes: raw,
            })
            .await;
        outputs.push(finding("filetype", &result));
        if self.yara.is_some() {
            outputs.push(finding("yara", &yara::result_for(&report.yara)));
        }
        if let Some(reason) = &self.yara_error {
            outputs.push(finding(
                "yara",
                &currawong_scan::EngineResult::Failed {
                    reason: format!("rules unavailable: {reason}"),
                    unreachable: false,
                },
            ));
        }
        if !self.cfg.scanner.clamd.address.is_empty() {
            match ClamdAddress::parse(&self.cfg.scanner.clamd.address) {
                Ok(address) => {
                    let client = ClamdClient::new(address, self.cfg.scanner.clamd.required);
                    let result = client
                        .scan(&ScanItem {
                            name: "message.eml",
                            bytes: raw,
                        })
                        .await;
                    let mut output = finding("clamav", &result);
                    output.required = self.cfg.scanner.clamd.required;
                    outputs.push(output);
                }
                Err(err) => {
                    outputs.push(EngineOutput {
                        name: "clamav".into(),
                        result: currawong_scan::EngineResult::Failed {
                            reason: err,
                            unreachable: self.cfg.scanner.clamd.required,
                        },
                        required: self.cfg.scanner.clamd.required,
                    });
                }
            }
        }
        let combined = combine(&outputs, parser_failed);
        report.malware = combined.malware;
        report.active_content = report.active_content || combined.active_content;
        report.defer = report.defer || combined.defer;
        report.fail_closed = combined.fail_closed;
        report.notes.extend(combined.notes);
        for output in &outputs {
            report.engines.push(EngineFinding {
                engine: output.name.clone(),
                result: format!("{:?}", output.result),
                detail: String::new(),
            });
        }
        let decision = self.decide(env, &report);
        (report, decision)
    }

    /// Tenant and direction per recipient: a message can reach several tenants,
    /// and submitted mail to a local mailbox is decided for that mailbox.
    fn decide(&self, env: &Envelope, report: &ScanReport) -> MessageDecision {
        let tenants = &self.cfg.relay.tenants;
        let tenant_of = |domain: &str| {
            tenants
                .iter()
                .find(|t| t.domains.iter().any(|d| canonical_domain(d) == domain))
                .map(|t| t.id.as_str())
        };
        let is_local = |domain: &str| {
            tenant_of(domain).is_some()
                || self
                    .cfg
                    .domains
                    .accept
                    .iter()
                    .any(|d| canonical_domain(d) == domain)
        };
        let sender_tenant = env
            .tenant_id
            .as_deref()
            .or_else(|| tenant_of(&domain_of(&env.mail_from)));
        let empty = [String::new()];
        let rcpts = if env.rcpt_to.is_empty() {
            &empty[..]
        } else {
            &env.rcpt_to
        };
        let contexts: Vec<Context> = rcpts
            .iter()
            .map(|rcpt| {
                let domain = domain_of(rcpt);
                let direction = match env.direction {
                    Direction::Outbound if !is_local(&domain) => Direction::Outbound,
                    _ => Direction::Inbound,
                };
                Context {
                    tenant_id: match direction {
                        Direction::Inbound => tenant_of(&domain),
                        Direction::Outbound => sender_tenant,
                    },
                    direction,
                    sender: &env.mail_from,
                    // The SMTP session does not record the login on the envelope yet,
                    // so outbound user and group scopes do not match.
                    sender_identity: None,
                    recipient: rcpt,
                }
            })
            .collect();
        let mut decision = evaluate_message(report, &contexts, &self.policies);
        if !tenants.is_empty() {
            for d in decision
                .decisions
                .iter_mut()
                .filter(|d| d.tenant_id.is_none())
            {
                tracing::warn!(id = %env.id, recipient = %d.recipient, "no tenant for recipient");
                d.explanation
                    .push("no tenant for this recipient: only platform policies applied".into());
            }
        }
        decision
    }

    /// Outbound mail, and inbound when configured. Logs counts only.
    fn scan_dlp(&self, env: &Envelope, text: &DlpText, report: &mut ScanReport) {
        let profile = &self.cfg.dlp;
        if !profile.enabled || (env.direction == Direction::Inbound && !profile.scan_inbound) {
            return;
        }
        let mut dlp = currawong_dlp::scan(&text.text, profile);
        dlp.incomplete |= text.incomplete;
        if !dlp.counts.is_empty() || dlp.incomplete {
            tracing::info!(id = %env.id, counts = ?dlp.counts, incomplete = dlp.incomplete, "dlp findings");
        }
        report.dlp = Some(dlp);
    }

    fn fold_part_flags(&self, report: &mut ScanReport) {
        for part in &report.parts {
            if self.cfg.scanner.treat_executables_as_active
                && part.flags.contains(&PartFlag::Executable)
            {
                report.active_content = true;
                report.notes.push(format!(
                    "executable {}",
                    part.filename.as_deref().unwrap_or("attachment")
                ));
            }
            if self.cfg.scanner.treat_macros_as_active && part.flags.contains(&PartFlag::HasMacro) {
                report.active_content = true;
                report.notes.push(format!(
                    "macro {}",
                    part.filename.as_deref().unwrap_or("attachment")
                ));
            }
            if part.flags.contains(&PartFlag::LimitExceeded) {
                report.fail_closed = true;
                report
                    .notes
                    .push("archive extraction limit exceeded".into());
            }
        }
    }

    async fn parse(
        &mut self,
        env: &Envelope,
        raw: &[u8],
        body_path: Option<&Path>,
        rules: Option<&CompiledRules>,
    ) -> ParseResponse {
        if let (Some(pool), Some(path)) = (self.pool.as_mut(), body_path) {
            return match pool
                .scan_file_with_rules(env.id.as_str(), path, &self.cfg.scanner.extract, rules)
                .await
            {
                ScanOutcome::Parsed(response) => response,
                ScanOutcome::Failed { reason } => ParseResponse::failed(env.id.as_str(), reason),
            };
        }
        parse_bytes_with(
            env.id.as_str(),
            raw,
            &self.cfg.scanner.extract,
            rules.map(|compiled| &compiled.rules),
        )
    }
}

fn finding(name: &str, result: &currawong_scan::EngineResult) -> EngineOutput {
    EngineOutput {
        name: name.into(),
        result: result.clone(),
        required: false,
    }
}

fn yara_engine(cfg: &Config) -> Result<Option<Arc<YaraEngine>>, String> {
    let dir = &cfg.scanner.yara.rules_dir;
    if !cfg.scanner.enabled || dir.as_os_str().is_empty() {
        return Ok(None);
    }
    YaraEngine::new(dir).map(|engine| Some(Arc::new(engine)))
}

pub fn worker_binary(cfg: &Config) -> Option<std::path::PathBuf> {
    if let Some(path) = &cfg.scanner.worker_binary {
        if path.exists() {
            return Some(path.clone());
        }
    }
    let exe = std::env::current_exe().ok()?;
    let candidate = exe.parent()?.join("currawong-parser-worker");
    if candidate.exists() {
        Some(candidate)
    } else {
        None
    }
}

fn domain_of(address: &str) -> String {
    address
        .rsplit_once('@')
        .map(|(_, d)| canonical_domain(d))
        .unwrap_or_default()
}

pub fn auth_header(auth: &AuthResults) -> String {
    auth.header.clone()
}

/// Atomically replace a spool body (write beside it, fsync, rename).
async fn rewrite_body(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;
    let tmp = path.with_extension("eml.strip");
    let mut file = tokio::fs::File::create(&tmp).await?;
    file.write_all(bytes).await?;
    file.sync_all().await?;
    tokio::fs::rename(&tmp, path).await
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}
