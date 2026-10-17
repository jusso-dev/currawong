//! Run the pipeline before delivery. Unscanned mail is never handed to the deliverer.
use currawong_core::Verdict;
use currawong_policy::Action;
use currawong_quarantine::QuarantineStore;
use currawong_spool::{Envelope, Spool, SpoolState};
use std::io::Cursor;
use time::OffsetDateTime;

use crate::pipeline::{auth_header, Pipeline};

pub async fn classify_pending(
    spool: &Spool,
    pipeline: &mut Pipeline,
    quarantine: &QuarantineStore,
) -> Result<(), String> {
    let incoming = spool
        .list(SpoolState::Incoming)
        .await
        .map_err(|err| err.to_string())?;
    for env in incoming {
        if env.pipeline == "deliver" || env.pipeline == "quarantine" {
            continue;
        }
        classify_one(spool, pipeline, quarantine, env).await?;
    }
    let deferred = spool
        .list(SpoolState::Deferred)
        .await
        .map_err(|err| err.to_string())?;
    for env in deferred {
        if env.pipeline != "scan_defer" {
            continue;
        }
        if let Some(when) = env.next_attempt_at {
            if when > OffsetDateTime::now_utc() {
                continue;
            }
        }
        let mut env = env;
        env.state = SpoolState::Deferred;
        classify_one(spool, pipeline, quarantine, env).await?;
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
    let groups = decision.split();
    // Recipients with a different outcome move to their own spool copy, decided on the next pass.
    // Copies are written before the original is narrowed, so a crash can duplicate, not lose, mail.
    if groups.len() > 1 {
        for group in &groups[1..] {
            let mut copy = env.clone();
            copy.id = Envelope::new_id();
            copy.rcpt_to = group.iter().map(|d| d.recipient.clone()).collect();
            copy.rcpt_status
                .retain(|status| copy.rcpt_to.contains(&status.address));
            copy.pipeline = "pending".into();
            copy.next_attempt_at = None;
            tracing::info!(id = %env.id, split = %copy.id, "recipients differ, message split");
            spool
                .accept(copy, Cursor::new(raw.clone()))
                .await
                .map_err(|err| err.to_string())?;
        }
        env.rcpt_to = groups[0].iter().map(|d| d.recipient.clone()).collect();
        env.rcpt_status
            .retain(|status| env.rcpt_to.contains(&status.address));
    }
    let decided = groups[0][0];
    let verdict = decided.verdict.clone();
    tracing::info!(id = %env.id, explanation = %decided.explanation.join("; "), "policy decision");
    if let Some(auth) = &report.auth {
        env.prepend_headers.push(auth_header(auth));
    }
    match &verdict {
        Verdict::Deliver => {
            apply_actions(&mut env, &decided.actions);
            env.pipeline = "deliver".into();
            spool.update(&env).await.map_err(|err| err.to_string())?;
        }
        Verdict::Defer { reason } => {
            env.pipeline = "scan_defer".into();
            env.attempts = env.attempts.saturating_add(1);
            env.next_attempt_at = Some(OffsetDateTime::now_utc() + time::Duration::minutes(5));
            tracing::info!(id = %env.id, %reason, "scan deferred");
            spool.update(&env).await.map_err(|err| err.to_string())?;
            spool
                .transition(&env.id, SpoolState::Deferred)
                .await
                .map_err(|err| err.to_string())?;
        }
        Verdict::Quarantine { .. } | Verdict::Reject { .. } | Verdict::Discard => {
            let reason = match &verdict {
                Verdict::Quarantine { reason } | Verdict::Reject { reason, .. } => reason.clone(),
                _ => "discard".into(),
            };
            quarantine
                .hold(env.id.as_str(), &reason, &raw)
                .map_err(|err| err.to_string())?;
            env.pipeline = "quarantine".into();
            spool.update(&env).await.map_err(|err| err.to_string())?;
            spool
                .transition(&env.id, SpoolState::Done)
                .await
                .map_err(|err| err.to_string())?;
            tracing::info!(id = %env.id, %reason, "quarantined");
        }
    }
    Ok(())
}

/// Delivery-time actions. Banner, encryption and TLS enforcement are not wired into delivery yet.
fn apply_actions(env: &mut Envelope, actions: &[Action]) {
    for action in actions {
        match action {
            Action::AddHeader { name, value } => {
                env.prepend_headers.push(format!("{name}: {value}\r\n"))
            }
            Action::Redirect(to) => env.rcpt_to = vec![to.clone()],
            Action::Bcc(to) if !env.rcpt_to.contains(to) => env.rcpt_to.push(to.clone()),
            Action::Banner(_) | Action::Encrypt | Action::RequireTls => {
                tracing::warn!(id = %env.id, ?action, "policy action not applied yet")
            }
            _ => {}
        }
    }
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
