//! Run the pipeline before delivery. Unscanned mail is never handed to the deliverer.
use currawong_core::{config::Config, Verdict};
use currawong_policy::{canonical_domain, Action, Decision};
use currawong_quarantine::QuarantineStore;
use currawong_smtp::delivery::{build_dsn, is_null_sender};
use currawong_spool::{Envelope, RcptStatus, Spool, SpoolState};
use sha2::{Digest, Sha256};
use std::io::Cursor;
use time::OffsetDateTime;

use crate::pipeline::{auth_header, Pipeline};

/// Redirect and bcc are skipped on mail that has already made this many hops.
const MAX_HOPS: usize = 25;

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
    let due = incoming.into_iter().filter(pending_scan).chain(
        deferred
            .into_iter()
            .filter(|env| env.pipeline == "scan_defer")
            .filter(|env| env.next_attempt_at.is_none_or(|when| when <= now))
            .map(|mut env| {
                env.state = SpoolState::Deferred;
                env
            }),
    );
    for env in due {
        let id = env.id.clone();
        if let Err(err) = classify_one(spool, pipeline, quarantine, env).await {
            tracing::error!(%id, %err, "classification failed");
        }
    }
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
    let (report, decision) = pipeline.assess(&env, &raw, body_path.as_deref()).await;
    let auth = report.auth.as_ref().map(auth_header);
    let cfg = &pipeline.cfg;
    let groups = decision.split();
    if groups.len() > 1 {
        // Copies get ids derived from the original and their recipients, so a
        // retry after an error or crash finds them instead of making more. They
        // carry this pass's decision and are not scanned again.
        for group in &groups[1..] {
            let rcpts: Vec<String> = group.iter().map(|d| d.recipient.clone()).collect();
            let id = split_id(&env, &rcpts);
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
            act(spool, quarantine, cfg, copy, &raw, group[0], auth.clone()).await?;
        }
        let rcpts: Vec<String> = groups[0].iter().map(|d| d.recipient.clone()).collect();
        narrow(&mut env, &rcpts);
        spool.update(&env).await.map_err(|err| err.to_string())?;
    }
    act(spool, quarantine, cfg, env, &raw, groups[0][0], auth).await
}

async fn act(
    spool: &Spool,
    quarantine: &QuarantineStore,
    cfg: &Config,
    mut env: Envelope,
    raw: &[u8],
    decision: &Decision,
    auth: Option<String>,
) -> Result<(), String> {
    tracing::info!(id = %env.id, explanation = %decision.explanation.join("; "), "policy decision");
    env.prepend_headers.extend(auth);
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
            quarantine
                .hold(env.id.as_str(), &reason, raw)
                .map_err(|err| err.to_string())?;
            env.pipeline = "quarantine".into();
            spool.update(&env).await.map_err(|err| err.to_string())?;
            finish(&env).await?;
            tracing::info!(id = %env.id, %reason, "quarantined");
        }
        // Mail is already accepted, so a reject is a bounce to the sender.
        Verdict::Reject { code, reason } => {
            let detail = format!("{code} message refused by policy {reason}");
            env.rcpt_status = env
                .rcpt_to
                .iter()
                .map(|address| RcptStatus {
                    address: address.clone(),
                    status: "perm".into(),
                    detail: detail.clone(),
                })
                .collect();
            if !env.dsn_sent && !is_null_sender(&env.mail_from) {
                spool
                    .accept(
                        bounce(&env, cfg),
                        Cursor::new(build_dsn(&cfg.gateway.hostname, &env, raw, &detail)),
                    )
                    .await
                    .map_err(|err| err.to_string())?;
                env.dsn_sent = true;
            }
            env.pipeline = "reject".into();
            spool.update(&env).await.map_err(|err| err.to_string())?;
            finish(&env).await?;
            tracing::info!(id = %env.id, %detail, "rejected");
        }
        Verdict::Discard => {
            env.pipeline = "discard".into();
            spool.update(&env).await.map_err(|err| err.to_string())?;
            finish(&env).await?;
            tracing::info!(id = %env.id, "discarded");
        }
    }
    Ok(())
}

/// The DSN envelope: from the null sender, back to the original sender.
fn bounce(env: &Envelope, cfg: &Config) -> Envelope {
    let mut dsn = env.clone();
    dsn.id = Envelope::new_id();
    dsn.mail_from = String::new();
    dsn.rcpt_to = vec![env.mail_from.clone()];
    dsn.received_at = OffsetDateTime::now_utc();
    dsn.remote_ip = std::net::Ipv4Addr::LOCALHOST.into();
    dsn.helo = cfg.gateway.hostname.clone();
    dsn.attempts = 0;
    dsn.next_attempt_at = None;
    dsn.state = SpoolState::Incoming;
    dsn.direction = currawong_core::Direction::Inbound;
    dsn.tls_version = None;
    dsn.tls_cipher = None;
    dsn.rcpt_status = Vec::new();
    dsn.prepend_headers = Vec::new();
    dsn.dsn_sent = true;
    dsn.pipeline = "pending".into();
    dsn
}

fn split_id(env: &Envelope, rcpts: &[String]) -> currawong_core::MessageId {
    let mut sorted = rcpts.to_vec();
    sorted.sort();
    let digest = Sha256::digest(format!("{}\n{}", env.id, sorted.join("\n")));
    currawong_core::MessageId(hex::encode_upper(digest)[..26].to_string())
}

fn narrow(env: &mut Envelope, rcpts: &[String]) {
    env.rcpt_to = rcpts.to_vec();
    env.rcpt_status
        .retain(|status| rcpts.contains(&status.address));
}

/// Header, redirect and bcc actions, applied before delivery. Redirect and bcc
/// only reach the recipient tenant's domains or `policy.forward_domains`, and
/// never on mail that looks like it is looping.
fn apply_actions(env: &mut Envelope, decision: &Decision, cfg: &Config, raw: &[u8]) {
    let mut redirect = Vec::new();
    let mut bcc = Vec::new();
    for action in &decision.actions {
        match action {
            Action::AddHeader { name, value } => {
                env.prepend_headers.push(format!("{name}: {value}\r\n"))
            }
            Action::Redirect(to) | Action::Bcc(to) => {
                if !forward_allowed(cfg, decision.tenant_id.as_deref(), to) {
                    tracing::warn!(id = %env.id, %to, "policy forward target not allowed, skipped");
                } else if hops(raw) >= MAX_HOPS {
                    tracing::warn!(id = %env.id, %to, "too many hops, policy forward skipped");
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

fn hops(raw: &[u8]) -> usize {
    let end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or(raw.len());
    raw[..end]
        .split(|b| *b == b'\n')
        .filter(|line| line.len() >= 9 && line[..9].eq_ignore_ascii_case(b"received:"))
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
