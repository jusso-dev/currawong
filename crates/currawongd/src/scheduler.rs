//! Run the pipeline before delivery. Unscanned mail is never handed to the deliverer.
use currawong_core::Verdict;
use currawong_quarantine::QuarantineStore;
use currawong_spool::{Envelope, Spool, SpoolState};
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
    let (report, verdict) = pipeline.evaluate(&env, &raw, body_path.as_deref()).await;
    if let Some(auth) = &report.auth {
        env.prepend_headers.push(auth_header(auth));
    }
    match &verdict {
        Verdict::Deliver => {
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
    currawong_integrations::export::emit(currawong_integrations::export::Event::message_verdict(
        env.tenant_id.as_deref(),
        &env.id,
        env.direction,
        &env.mail_from,
        &env.rcpt_to,
        &verdict,
    ));
    Ok(())
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
