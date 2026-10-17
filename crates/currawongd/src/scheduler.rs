//! Run the pipeline before delivery. Unscanned mail is never handed to the deliverer.
use currawong_core::{config::Config, Direction, MessageId, ScanReport, Verdict};
use currawong_policy::{canonical_domain, Action, Decision};
use currawong_quarantine::{Hold, QuarantineStore, RELEASE_PIPELINE};
use currawong_smtp::delivery::{build_dsn, is_null_sender};
use currawong_spool::{Envelope, RcptStatus, Spool, SpoolState};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{io::Cursor, path::PathBuf};
use time::OffsetDateTime;

use crate::pipeline::Pipeline;

/// Tenant redirect and bcc are skipped once mail has passed through this
/// gateway this many times. Platform and mandatory ones always apply.
const MAX_OWN_HOPS: usize = 3;

/// Everything decided for a message whose recipients must be split. Saved
/// before any copy is made, so a retry finishes this plan instead of
/// deciding again under policies that may have changed.
#[derive(Debug, Serialize, Deserialize)]
struct Plan {
    /// Our headers for every copy: Authentication-Results (inbound), ARC
    /// set (modified inbound) or DKIM signatures (outbound).
    #[serde(default)]
    headers: Vec<String>,
    bounce: bool,
    groups: Vec<Vec<Decision>>,
}

/// One failing message is logged and skipped; it does not stall the rest.
pub async fn classify_pending(
    spool: &Spool,
    pipeline: &mut Pipeline,
    quarantine: &QuarantineStore,
) -> Result<(), String> {
    let incoming = spool
        .list(SpoolState::Incoming)
        .await
        .map_err(|err| err.to_string())?;
    let deferred = spool
        .list(SpoolState::Deferred)
        .await
        .map_err(|err| err.to_string())?;
    let now = OffsetDateTime::now_utc();
    let due = incoming
        .into_iter()
        .filter(|env| pending_scan(env) || env.pipeline == RELEASE_PIPELINE)
        .chain(
            deferred
                .into_iter()
                .filter(|env| env.pipeline == "scan_defer")
                .filter(|env| env.next_attempt_at.is_none_or(|when| when <= now))
                .map(|mut env| {
                    env.state = SpoolState::Deferred;
                    env
                }),
        );
    let mut released = Vec::new();
    for env in due {
        let id = env.id.clone();
        if env.pipeline == RELEASE_PIPELINE {
            released.push(env);
        } else if let Err(err) = classify_one(spool, pipeline, quarantine, env).await {
            tracing::error!(%id, %err, "classification failed");
        }
    }
    for env in released {
        let id = env.id.clone();
        if let Err(err) = deliver_released(spool, pipeline, env).await {
            tracing::error!(%id, %err, "released message not queued for delivery, will retry");
        }
    }
    Ok(())
}

/// A message released from quarantine is delivered without running policy
/// again, so this one release cannot be quarantined a second time. The
/// release itself is in the quarantine audit trail, and trains the Bayes
/// classifier. Inbound mail keeps the headers it was held with; outbound
/// mail is signed now.
async fn deliver_released(
    spool: &Spool,
    pipeline: &Pipeline,
    mut env: Envelope,
) -> Result<(), String> {
    let raw = spool
        .read_body(&env.id)
        .await
        .map_err(|err| err.to_string())?;
    if env.direction == Direction::Outbound {
        let report = ScanReport::new(env.id.clone());
        env.prepend_headers = pipeline.delivery_headers(&env, &raw, &report).await?;
    }
    pipeline.learn_released(&env, &raw).await;
    env.pipeline = "deliver".into();
    spool.update(&env).await.map_err(|err| err.to_string())?;
    tracing::info!(id = %env.id, "released from quarantine, policy skipped");
    Ok(())
}

async fn classify_one(
    spool: &Spool,
    pipeline: &mut Pipeline,
    quarantine: &QuarantineStore,
    mut env: Envelope,
) -> Result<(), String> {
    let raw = spool
        .read_body(&env.id)
        .await
        .map_err(|err| err.to_string())?;
    let body_path = spool_body(spool, &env);
    let raw = pipeline.strip_spooled(&raw, body_path.as_deref()).await?;
    let plan_path = plan_path(spool, &env.id);
    let mut bimi_auth = None;
    let plan = match tokio::fs::read(&plan_path).await {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(|err| err.to_string())?,
        Err(_) => {
            let (report, decision) = pipeline.assess(&env, &raw, body_path.as_deref()).await;
            bimi_auth = report.auth.clone();
            let mut groups: Vec<Vec<Decision>> = decision
                .split()
                .into_iter()
                .map(|group| group.into_iter().cloned().collect())
                .collect();
            let delivers = groups
                .iter()
                .flatten()
                .any(|d| matches!(d.verdict, Verdict::Deliver));
            let headers = if !delivers {
                pipeline.auth_headers(&env, &report)
            } else {
                match pipeline.delivery_headers(&env, &raw, &report).await {
                    Ok(headers) => headers,
                    // Never send a tenant's mail unsigned when it has a key.
                    Err(reason) => {
                        tracing::error!(id = %env.id, %reason, "outbound signing failed, deferring");
                        for d in groups.iter_mut().flatten() {
                            if matches!(d.verdict, Verdict::Deliver) {
                                d.verdict = Verdict::Defer {
                                    reason: reason.clone(),
                                };
                            }
                        }
                        Vec::new()
                    }
                }
            };
            let plan = Plan {
                headers,
                bounce: bounce_allowed(&env, &report, &raw),
                groups,
            };
            if plan.groups.len() > 1 {
                write_atomic(
                    &plan_path,
                    &serde_json::to_vec(&plan).map_err(|e| e.to_string())?,
                )
                .await?;
            }
            plan
        }
    };
    let cfg = &pipeline.cfg;
    if plan.groups.len() > 1 {
        // Copies get ids derived from the original and their recipients, so a
        // retry finds them instead of making more. They carry the plan's
        // decision and are not scanned again.
        for group in &plan.groups[1..] {
            let rcpts: Vec<String> = group.iter().map(|d| d.recipient.clone()).collect();
            let mut sorted = rcpts.clone();
            sorted.sort();
            let id = derived_id(&env.id, &sorted.join("\n"));
            if spool.load(&id).await.is_ok() {
                continue;
            }
            let mut copy = env.clone();
            copy.id = id;
            copy.state = SpoolState::Incoming;
            copy.next_attempt_at = None;
            copy.pipeline = "pending".into();
            narrow(&mut copy, &rcpts);
            tracing::info!(id = %env.id, split = %copy.id, "recipients differ, message split");
            spool
                .accept(copy.clone(), Cursor::new(raw.clone()))
                .await
                .map_err(|err| err.to_string())?;
            act(spool, quarantine, cfg, copy, &raw, &group[0], &plan).await?;
        }
        let rcpts: Vec<String> = plan.groups[0].iter().map(|d| d.recipient.clone()).collect();
        narrow(&mut env, &rcpts);
        spool.update(&env).await.map_err(|err| err.to_string())?;
        let _ = tokio::fs::remove_file(&plan_path).await;
    }
    let id = env.id.clone();
    let quarantined = matches!(plan.groups[0][0].verdict, Verdict::Quarantine { .. });
    act(spool, quarantine, cfg, env, &raw, &plan.groups[0][0], &plan).await?;
    if let (true, Some(auth)) = (quarantined, bimi_auth) {
        pipeline.queue_bimi(id, auth);
    }
    Ok(())
}

async fn act(
    spool: &Spool,
    quarantine: &QuarantineStore,
    cfg: &Config,
    mut env: Envelope,
    raw: &[u8],
    decision: &Decision,
    plan: &Plan,
) -> Result<(), String> {
    tracing::info!(id = %env.id, explanation = %decision.explanation.join("; "), "policy decision");
    // Replace, never extend: a re-evaluated deferred message must not
    // carry a second set of our headers.
    env.prepend_headers = plan.headers.clone();
    let finish = |env: &Envelope| {
        let id = env.id.clone();
        async move {
            spool
                .transition(&id, SpoolState::Done)
                .await
                .map_err(|err| err.to_string())
        }
    };
    match &decision.verdict {
        Verdict::Deliver => {
            apply_actions(&mut env, decision, cfg, raw);
            env.pipeline = "deliver".into();
            spool.update(&env).await.map_err(|err| err.to_string())?;
        }
        Verdict::Defer { reason } => {
            env.pipeline = "scan_defer".into();
            env.attempts = env.attempts.saturating_add(1);
            env.next_attempt_at = Some(OffsetDateTime::now_utc() + time::Duration::minutes(5));
            tracing::info!(id = %env.id, %reason, "scan deferred");
            spool.update(&env).await.map_err(|err| err.to_string())?;
            if env.state != SpoolState::Deferred {
                spool
                    .transition(&env.id, SpoolState::Deferred)
                    .await
                    .map_err(|err| err.to_string())?;
            }
        }
        Verdict::Quarantine { reason } => {
            let reason = match decision.queue() {
                Some(queue) => format!("{reason} (queue {queue})"),
                None => reason.clone(),
            };
            let hold = Hold {
                message_id: env.id.clone(),
                tenant_id: decision.tenant_id.clone(),
                queue: decision.queue().unwrap_or("policy").to_string(),
                reason: reason.clone(),
                reasons: decision.explanation.clone(),
                sender: env.mail_from.clone(),
                recipients: env.rcpt_to.clone(),
                score: None,
                direction: env.direction,
                headers: env.prepend_headers.clone(),
            };
            quarantine
                .hold(&hold, raw, OffsetDateTime::now_utc())
                .await
                .map_err(|err| err.to_string())?;
            env.pipeline = "quarantine".into();
            spool.update(&env).await.map_err(|err| err.to_string())?;
            finish(&env).await?;
            tracing::info!(id = %env.id, %reason, "quarantined");
        }
        // Mail is already accepted, so a reject is a bounce, and only to a
        // sender we can trust; anything else would be backscatter.
        Verdict::Reject { code, reason } => {
            // The policy id stays in our log, not in mail to the sender.
            let detail = format!("{code} message refused by recipient policy");
            env.rcpt_status = env
                .rcpt_to
                .iter()
                .map(|address| RcptStatus {
                    address: address.clone(),
                    status: "perm".into(),
                    detail: detail.clone(),
                })
                .collect();
            if plan.bounce && !env.dsn_sent {
                let dsn = bounce(&env, cfg);
                if spool.load(&dsn.id).await.is_err() {
                    let body = build_dsn(&cfg.gateway.hostname, &env, raw, &detail);
                    spool
                        .accept(dsn, Cursor::new(body))
                        .await
                        .map_err(|err| err.to_string())?;
                }
                env.dsn_sent = true;
            } else if !plan.bounce {
                tracing::info!(id = %env.id, "sender not verified, rejected without a bounce");
            }
            env.pipeline = "reject".into();
            spool.update(&env).await.map_err(|err| err.to_string())?;
            finish(&env).await?;
            tracing::info!(id = %env.id, policy = %reason, %detail, "rejected");
        }
        Verdict::Discard => {
            env.pipeline = "discard".into();
            spool.update(&env).await.map_err(|err| err.to_string())?;
            finish(&env).await?;
            tracing::info!(id = %env.id, "discarded");
        }
    }
    currawong_integrations::export::emit(currawong_integrations::export::Event::message_verdict(
        env.tenant_id.as_deref(),
        &env.id,
        env.direction,
        &env.mail_from,
        &env.rcpt_to,
        &decision.verdict,
    ));
    Ok(())
}

/// Bounce only to senders we can stand behind: our own authenticated users,
/// or a sender SPF or DMARC vouched for. Never to the null sender or to
/// automatic mail.
fn bounce_allowed(env: &Envelope, report: &ScanReport, raw: &[u8]) -> bool {
    if is_null_sender(&env.mail_from) {
        return false;
    }
    let auto = headers(raw).iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("auto-submitted") && !value.trim().eq_ignore_ascii_case("no")
    });
    if auto {
        return false;
    }
    let submitted = env.direction == Direction::Outbound || env.tenant_id.is_some();
    let verified = report.auth.as_ref().is_some_and(|auth| {
        auth.spf.result.eq_ignore_ascii_case("pass")
            || auth.dmarc.result.eq_ignore_ascii_case("pass")
    });
    submitted || verified
}

/// The DSN envelope: from the null sender, back to the original sender, under
/// an id derived from the original so a retry cannot queue a second one.
fn bounce(env: &Envelope, cfg: &Config) -> Envelope {
    let mut dsn = env.clone();
    dsn.id = derived_id(&env.id, "dsn");
    dsn.mail_from = String::new();
    // The gateway sends the bounce; it is not the submitting user's mail.
    dsn.authenticated_as = None;
    dsn.rcpt_to = vec![env.mail_from.clone()];
    dsn.received_at = OffsetDateTime::now_utc();
    dsn.remote_ip = std::net::Ipv4Addr::LOCALHOST.into();
    dsn.helo = cfg.gateway.hostname.clone();
    dsn.attempts = 0;
    dsn.next_attempt_at = None;
    dsn.state = SpoolState::Incoming;
    dsn.direction = Direction::Inbound;
    dsn.tls_version = None;
    dsn.tls_cipher = None;
    dsn.rcpt_status = Vec::new();
    dsn.prepend_headers = Vec::new();
    dsn.dsn_sent = true;
    dsn.pipeline = "pending".into();
    dsn
}

/// A spool-safe id (26 upper-case hex characters) derived from another id.
fn derived_id(id: &MessageId, salt: &str) -> MessageId {
    let digest = Sha256::digest(format!("{id}\n{salt}"));
    MessageId(hex::encode_upper(digest)[..26].to_string())
}

fn plan_path(spool: &Spool, id: &MessageId) -> PathBuf {
    spool.root().join("split").join(format!("{id}.json"))
}

async fn write_atomic(path: &std::path::Path, bytes: &[u8]) -> Result<(), String> {
    let dir = path.parent().ok_or("plan path has no parent")?;
    tokio::fs::create_dir_all(dir)
        .await
        .map_err(|err| err.to_string())?;
    let tmp = path.with_extension("json.tmp");
    let mut file = tokio::fs::File::create(&tmp)
        .await
        .map_err(|err| err.to_string())?;
    tokio::io::AsyncWriteExt::write_all(&mut file, bytes)
        .await
        .map_err(|err| err.to_string())?;
    file.sync_all().await.map_err(|err| err.to_string())?;
    tokio::fs::rename(&tmp, path)
        .await
        .map_err(|err| err.to_string())
}

fn narrow(env: &mut Envelope, rcpts: &[String]) {
    env.rcpt_to = rcpts.to_vec();
    env.rcpt_status
        .retain(|status| rcpts.contains(&status.address));
}

/// Header, redirect and bcc actions, applied before delivery. Redirect and bcc
/// only reach the recipient tenant's domains or `policy.forward_domains`.
/// Tenant ones stop on mail that has looped through this gateway.
fn apply_actions(env: &mut Envelope, decision: &Decision, cfg: &Config, raw: &[u8]) {
    let looping = own_hops(raw, &cfg.gateway.hostname) >= MAX_OWN_HOPS;
    let mut redirect = Vec::new();
    let mut bcc = Vec::new();
    for (action, enforced) in decision.actions.iter().zip(&decision.enforced) {
        match action {
            Action::AddHeader { name, value } => {
                env.prepend_headers.push(format!("{name}: {value}\r\n"))
            }
            Action::Redirect(to) | Action::Bcc(to) => {
                if !forward_allowed(cfg, decision.tenant_id.as_deref(), to) {
                    tracing::warn!(id = %env.id, %to, "policy forward target not allowed, skipped");
                } else if looping && !enforced {
                    tracing::warn!(id = %env.id, %to, "mail is looping, policy forward skipped");
                } else if matches!(action, Action::Redirect(_)) {
                    redirect.push(to.clone());
                } else {
                    bcc.push(to.clone());
                }
            }
            _ => {}
        }
    }
    if redirect.is_empty() && bcc.is_empty() {
        return;
    }
    let mut rcpts = if redirect.is_empty() {
        env.rcpt_to.clone()
    } else {
        redirect
    };
    for to in bcc {
        if !rcpts.contains(&to) {
            rcpts.push(to);
        }
    }
    rcpts.dedup();
    // Delivery reads rcpt_status when it has entries, so keep both in step.
    if !env.rcpt_status.is_empty() {
        env.rcpt_status = rcpts
            .iter()
            .map(|address| {
                env.rcpt_status
                    .iter()
                    .find(|s| &s.address == address)
                    .cloned()
                    .unwrap_or_else(|| RcptStatus {
                        address: address.clone(),
                        status: "pending".into(),
                        detail: String::new(),
                    })
            })
            .collect();
    }
    env.rcpt_to = rcpts;
}

fn forward_allowed(cfg: &Config, tenant: Option<&str>, to: &str) -> bool {
    let Some((_, domain)) = to.rsplit_once('@') else {
        return false;
    };
    let domain = canonical_domain(domain);
    let owned = cfg.relay.tenants.iter().any(|t| {
        tenant.is_none_or(|id| t.id == id)
            && t.domains.iter().any(|d| canonical_domain(d) == domain)
    });
    let local = tenant.is_none()
        && cfg
            .domains
            .accept
            .iter()
            .any(|d| canonical_domain(d) == domain);
    owned
        || local
        || cfg
            .policy
            .forward_domains
            .iter()
            .any(|d| canonical_domain(d) == domain)
}

/// Unfolded header fields of the message.
fn headers(raw: &[u8]) -> Vec<(String, String)> {
    let end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or(raw.len());
    let mut out: Vec<(String, String)> = Vec::new();
    for line in String::from_utf8_lossy(&raw[..end]).split('\n') {
        let line = line.trim_end_matches('\r');
        if line.starts_with([' ', '\t']) {
            if let Some((_, value)) = out.last_mut() {
                value.push(' ');
                value.push_str(line.trim());
            }
        } else if let Some((name, value)) = line.split_once(':') {
            out.push((name.trim().to_string(), value.trim().to_string()));
        }
    }
    out
}

/// `Received` fields this gateway wrote on delivery (`by <hostname> with ESMTP`).
fn own_hops(raw: &[u8], hostname: &str) -> usize {
    let marker = format!("by {} with esmtp", hostname.to_ascii_lowercase());
    headers(raw)
        .iter()
        .filter(|(name, value)| {
            name.eq_ignore_ascii_case("received") && value.to_ascii_lowercase().contains(&marker)
        })
        .count()
}

fn spool_body(spool: &Spool, env: &Envelope) -> Option<std::path::PathBuf> {
    let path = spool
        .root()
        .join(env.state.dir_name())
        .join(format!("{}.eml", env.id));
    path.exists().then_some(path)
}

/// Delivery is only legal once the pipeline has marked the message.
pub fn ready_to_deliver(env: &Envelope) -> bool {
    env.pipeline == "deliver"
}

pub fn pending_scan(env: &Envelope) -> bool {
    matches!(env.pipeline.as_str(), "pending" | "scan_defer" | "")
}
