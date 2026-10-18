//! The `encrypt`, `encrypt_smime` and `encrypt_portal` actions. The original
//! is never delivered: its encrypted form (S/MIME) or a portal notice per
//! recipient is spooled as new mail under an id derived from the original,
//! so a retry finds it instead of making another. When neither can be made
//! the original is quarantined.
use crate::{pipeline::Pipeline, scheduler::derived_id};
use async_trait::async_trait;
use currawong_admin::routes::portal::CodeMailer;
use currawong_core::{config::Config, Direction, TlsRequirement};
use currawong_dlp::encrypt::{code_mail, notice, smime::Recipient, Issued, Route};
use currawong_policy::{Action, Decision};
use currawong_quarantine::{Hold, QuarantineStore};
use currawong_spool::{Envelope, Spool, SpoolState};
use std::{io::Cursor, sync::Arc};
use time::OffsetDateTime;

/// Kept on quarantine index rows, so a release encrypts as the policy asked.
pub use currawong_quarantine::EncryptMode as Mode;

/// The encryption a decision asks for. `encrypt`, or both specific
/// actions together, means either will do.
pub fn requested(decision: &Decision) -> Option<Mode> {
    let has = |action: Action| decision.actions.contains(&action);
    match (
        has(Action::Encrypt),
        has(Action::EncryptSmime),
        has(Action::EncryptPortal),
    ) {
        (false, false, false) => None,
        (false, true, false) => Some(Mode::Smime),
        (false, false, true) => Some(Mode::Portal),
        _ => Some(Mode::Auto),
    }
}

/// Where mail that cannot be encrypted goes: the store and the index entry
/// the policy decision would have made (its reason is filled in here).
pub struct Fallback<'a> {
    pub store: &'a QuarantineStore,
    pub hold: Hold,
}

/// `raw` is the message as it arrived, quarantined when it cannot be
/// encrypted; `sent` is what the recipients get (links may be rewritten).
pub async fn deliver_encrypted(
    spool: &Spool,
    quarantine: &Fallback<'_>,
    pipeline: &Pipeline,
    mut env: Envelope,
    raw: &[u8],
    sent: &[u8],
    mode: Mode,
) -> Result<(), String> {
    let cfg = &pipeline.cfg;
    let now = OffsetDateTime::now_utc();
    if mode != Mode::Portal {
        match smime(cfg, &env.rcpt_to, sent, now.unix_timestamp() as u64) {
            Ok(Ok(body)) => {
                let id = derived_id(&env.id, "smime");
                if spool.load(&id).await.is_err() {
                    let headers = if env.direction == Direction::Outbound {
                        pipeline.dkim_headers(&env, &body).await?
                    } else {
                        Vec::new()
                    };
                    // Header actions stay; our signatures are for the new body.
                    let mut extra = env.prepend_headers.clone();
                    extra.retain(|h| !h.to_ascii_lowercase().starts_with("dkim-signature:"));
                    let copy = copy_of(
                        &env,
                        id,
                        env.rcpt_to.clone(),
                        None,
                        [headers, extra].concat(),
                    );
                    spool
                        .accept(copy, Cursor::new(body))
                        .await
                        .map_err(|err| err.to_string())?;
                }
                tracing::info!(id = %env.id, "sent as S/MIME");
                return finish(spool, &mut env, "encrypted").await;
            }
            Ok(Err(missing)) if mode == Mode::Smime => {
                return hold(
                    spool,
                    quarantine,
                    &mut env,
                    raw,
                    &format!("encrypt_smime: no S/MIME certificate for {missing}"),
                )
                .await;
            }
            Ok(Err(missing)) => {
                tracing::info!(id = %env.id, %missing, "no S/MIME certificate, using the portal");
            }
            Err(err) => return hold(spool, quarantine, &mut env, raw, &err).await,
        }
    }
    let Some(portal) = pipeline.portal.clone() else {
        return hold(
            spool,
            quarantine,
            &mut env,
            raw,
            "encrypt: the encryption portal is not enabled",
        )
        .await;
    };
    let from = sender(cfg);
    let base = cfg.encrypt.portal.base_url.trim_end_matches('/');
    // The code mail later follows the notice: same tenant, same TLS policy.
    let route = Route {
        tenant_id: env.tenant_id.clone(),
        tls: env.tls,
    };
    for rcpt in env.rcpt_to.clone() {
        let id = derived_id(&env.id, &format!("portal\n{rcpt}"));
        if spool.load(&id).await.is_ok() {
            continue;
        }
        let (store, owned, to, route) = (
            Arc::clone(&portal),
            sent.to_vec(),
            rcpt.clone(),
            route.clone(),
        );
        let token = tokio::task::spawn_blocking(move || {
            store.store(&to, &owned, &route, now.unix_timestamp() as u64)
        })
        .await
        .map_err(|err| err.to_string())?
        .map_err(|err| err.to_string())?;
        let body = notice(
            raw,
            &from,
            &rcpt,
            &format!("{base}/portal/{token}"),
            &rfc5322(now),
            &format!("{id}@{}", cfg.gateway.hostname),
        );
        let mut copy = copy_of(&env, id, vec![rcpt], Some(&from), Vec::new());
        copy.direction = Direction::Outbound;
        copy.prepend_headers = pipeline.dkim_headers(&copy, &body).await?;
        spool
            .accept(copy, Cursor::new(body))
            .await
            .map_err(|err| err.to_string())?;
    }
    tracing::info!(id = %env.id, "held in the encryption portal");
    finish(spool, &mut env, "encrypted").await
}

/// The S/MIME form, or the first recipient with no usable certificate.
fn smime(
    cfg: &Config,
    rcpts: &[String],
    raw: &[u8],
    now: u64,
) -> Result<Result<Vec<u8>, String>, String> {
    let Some(dir) = &cfg.encrypt.smime_certs_dir else {
        return Ok(Err(rcpts.first().cloned().unwrap_or_default()));
    };
    let mut recipients = Vec::new();
    for rcpt in rcpts {
        match Recipient::find(dir, rcpt, now) {
            Ok(Some(found)) => recipients.push(found),
            Ok(None) => return Ok(Err(rcpt.clone())),
            Err(err) => {
                tracing::warn!(%rcpt, %err, "S/MIME certificate unusable");
                return Ok(Err(rcpt.clone()));
            }
        }
    }
    currawong_dlp::encrypt::smime::encrypt(raw, &recipients)
        .map(Ok)
        .map_err(|err| err.to_string())
}

/// New mail ready for delivery, carrying the original's TLS requirement.
fn copy_of(
    env: &Envelope,
    id: currawong_core::MessageId,
    rcpts: Vec<String>,
    mail_from: Option<&str>,
    headers: Vec<String>,
) -> Envelope {
    let mut copy = env.clone();
    copy.id = id;
    copy.rcpt_to = rcpts;
    copy.rcpt_status = Vec::new();
    copy.state = SpoolState::Incoming;
    copy.attempts = 0;
    copy.next_attempt_at = None;
    copy.dsn_sent = false;
    copy.prepend_headers = headers;
    copy.pipeline = "deliver".into();
    if let Some(from) = mail_from {
        copy.mail_from = from.to_string();
        copy.authenticated_as = None;
    }
    copy
}

async fn finish(spool: &Spool, env: &mut Envelope, pipeline: &str) -> Result<(), String> {
    env.pipeline = pipeline.into();
    spool.update(env).await.map_err(|err| err.to_string())?;
    spool
        .transition(&env.id, SpoolState::Done)
        .await
        .map_err(|err| err.to_string())
}

/// Mail a policy asked to encrypt is held, never sent in clear.
async fn hold(
    spool: &Spool,
    quarantine: &Fallback<'_>,
    env: &mut Envelope,
    raw: &[u8],
    reason: &str,
) -> Result<(), String> {
    let hold = Hold {
        reason: format!("{reason} (queue {})", quarantine.hold.queue),
        ..quarantine.hold.clone()
    };
    quarantine
        .store
        .hold(&hold, raw, OffsetDateTime::now_utc())
        .await
        .map_err(|err| err.to_string())?;
    tracing::warn!(id = %env.id, %reason, "could not encrypt, quarantined");
    finish(spool, env, "quarantine").await
}

fn sender(cfg: &Config) -> String {
    match cfg.encrypt.portal.from.trim() {
        "" => format!("postmaster@{}", cfg.gateway.hostname),
        from => from.to_string(),
    }
}

fn rfc5322(at: OffsetDateTime) -> String {
    at.format(&time::format_description::well_known::Rfc2822)
        .unwrap_or_else(|_| "Thu, 01 Jan 1970 00:00:00 +0000".into())
}

/// Mails portal codes by spooling them for delivery. The code opens the
/// message, so it never goes in clear: at least `require_tls`, and DANE when
/// the held message's policy asked for it.
pub struct SpoolMailer {
    pub spool: Arc<Spool>,
    pub cfg: Arc<Config>,
}

#[async_trait]
impl CodeMailer for SpoolMailer {
    async fn send_code(&self, issued: &Issued) -> Result<(), String> {
        let from = sender(&self.cfg);
        let recipient = issued.recipient.as_str();
        let id = Envelope::new_id();
        let now = OffsetDateTime::now_utc();
        let body = code_mail(
            &from,
            recipient,
            &issued.code,
            &rfc5322(now),
            &format!("{id}@{}", self.cfg.gateway.hostname),
        );
        let env = Envelope {
            id,
            tenant_id: issued.route.tenant_id.clone(),
            authenticated_as: None,
            mail_from: from,
            rcpt_to: vec![recipient.to_string()],
            received_at: now,
            remote_ip: std::net::Ipv4Addr::LOCALHOST.into(),
            helo: self.cfg.gateway.hostname.clone(),
            attempts: 0,
            next_attempt_at: None,
            state: SpoolState::Incoming,
            direction: Direction::Outbound,
            tls_version: None,
            tls_cipher: None,
            rcpt_status: Vec::new(),
            prepend_headers: Vec::new(),
            dsn_sent: false,
            tls: issued.route.tls.max(TlsRequirement::Required),
            pipeline: "deliver".into(),
        };
        self.spool
            .accept(env, Cursor::new(body))
            .await
            .map(|_| ())
            .map_err(|err| err.to_string())
    }
}
