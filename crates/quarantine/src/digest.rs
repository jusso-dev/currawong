//! Per-user digests of newly held items in user queues, sent as mail through
//! the spool, with signed release and delete links.
use crate::{derived_id, Item, Link, LinkAction, LinkSigner, QuarantineError, QuarantineStore};
use askama::Template;
use currawong_core::{config::Config, Direction, MessageId};
use currawong_spool::{Envelope, Spool, SpoolState};
use mail_builder::{
    headers::{date::Date, text::Text},
    MessageBuilder,
};
use std::{collections::BTreeMap, io::Cursor};
use time::OffsetDateTime;

const LAST_DIGEST: &str = "last_digest_at";

#[derive(Debug, Clone)]
pub struct DigestSettings {
    pub from: String,
    pub base_url: String,
    pub link_ttl_hours: u64,
    pub interval_hours: u64,
    pub hostname: String,
}

impl DigestSettings {
    pub fn from_config(cfg: &Config) -> Self {
        let q = &cfg.quarantine;
        Self {
            from: if q.digest_from.is_empty() {
                format!("quarantine@{}", cfg.gateway.hostname)
            } else {
                q.digest_from.clone()
            },
            base_url: q.link_base_url.trim_end_matches('/').to_string(),
            link_ttl_hours: q.link_ttl_hours,
            interval_hours: q.digest_interval_hours,
            hostname: cfg.gateway.hostname.clone(),
        }
    }
}

struct Entry {
    sender: String,
    subject: String,
    queue: String,
    received: String,
    release: String,
    delete: String,
}

#[derive(Template)]
#[template(path = "digest.html")]
struct DigestHtml<'a> {
    recipient: &'a str,
    entries: &'a [Entry],
}

#[derive(Template)]
#[template(path = "digest.txt")]
struct DigestText<'a> {
    recipient: &'a str,
    entries: &'a [Entry],
}

/// One digest per recipient for items not yet in a digest, at most once per
/// `interval_hours`. Digest ids derive from the items, so a retry after a
/// crash finds the digest instead of queueing a second one. Returns the
/// number of digests queued.
pub async fn send_digests(
    store: &QuarantineStore,
    spool: &Spool,
    signer: &LinkSigner,
    settings: &DigestSettings,
    now: OffsetDateTime,
) -> Result<usize, QuarantineError> {
    let at = now.unix_timestamp();
    let interval = i64::try_from(settings.interval_hours.saturating_mul(3600)).unwrap_or(i64::MAX);
    let last = store.meta(LAST_DIGEST)?.and_then(|v| v.parse::<i64>().ok());
    if last.is_some_and(|last| at.saturating_sub(last) < interval) {
        return Ok(0);
    }
    let mut groups: BTreeMap<(Option<String>, String), Vec<Item>> = BTreeMap::new();
    for item in store.undigested(at)? {
        groups
            .entry((item.tenant_id.clone(), item.recipient.clone()))
            .or_default()
            .push(item);
    }
    let ttl = i64::try_from(settings.link_ttl_hours.saturating_mul(3600)).unwrap_or(i64::MAX);
    let mut sent = 0;
    for ((tenant_id, recipient), items) in groups {
        let entries: Vec<Entry> = items
            .iter()
            .map(|item| {
                let url = |action| {
                    let token = signer.sign(&Link {
                        item_id: item.id.clone(),
                        recipient: item.recipient.clone(),
                        action,
                        expires_at: at.saturating_add(ttl).min(item.expires_at),
                    });
                    format!("{}/quarantine/link/{token}", settings.base_url)
                };
                Entry {
                    sender: item.sender.clone(),
                    subject: item.subject.clone(),
                    queue: item.queue.clone(),
                    received: received(item.created_at),
                    release: url(LinkAction::Release),
                    delete: url(LinkAction::Delete),
                }
            })
            .collect();
        let ids: Vec<String> = items.iter().map(|item| item.id.clone()).collect();
        let id = MessageId(derived_id(&ids.join("\n"), "digest"));
        if spool.load(&id).await.is_err() {
            let body = render(&id, &recipient, &entries, settings, at)?;
            let env = envelope(id.clone(), tenant_id, &recipient, settings, now);
            spool
                .accept(env, Cursor::new(body))
                .await
                .map_err(|err| QuarantineError::Store(err.to_string()))?;
        }
        store.mark_digested(&ids, at)?;
        tracing::info!(%id, count = ids.len(), "quarantine digest queued");
        sent += 1;
    }
    store.set_meta(LAST_DIGEST, &at.to_string())?;
    Ok(sent)
}

fn render(
    id: &MessageId,
    recipient: &str,
    entries: &[Entry],
    settings: &DigestSettings,
    at: i64,
) -> Result<Vec<u8>, QuarantineError> {
    let template = |err: askama::Error| QuarantineError::Store(err.to_string());
    let html = DigestHtml { recipient, entries }
        .render()
        .map_err(template)?;
    let text = DigestText { recipient, entries }
        .render()
        .map_err(template)?;
    let subject = match entries.len() {
        1 => "Quarantine digest: 1 message held for you".to_string(),
        n => format!("Quarantine digest: {n} messages held for you"),
    };
    MessageBuilder::new()
        .from(settings.from.as_str())
        .to(recipient)
        .subject(subject)
        .message_id(format!("{id}@{}", settings.hostname))
        .date(Date::new(at))
        .header("Auto-Submitted", Text::new("auto-generated"))
        .text_body(text)
        .html_body(html)
        .write_to_vec()
        .map_err(|err| QuarantineError::Store(err.to_string()))
}

/// Generated here and holding only escaped index fields, so it goes straight
/// to delivery: scanning it could quarantine the digest itself.
fn envelope(
    id: MessageId,
    tenant_id: Option<String>,
    recipient: &str,
    settings: &DigestSettings,
    now: OffsetDateTime,
) -> Envelope {
    Envelope {
        id,
        tenant_id,
        authenticated_as: None,
        mail_from: settings.from.clone(),
        rcpt_to: vec![recipient.to_string()],
        received_at: now,
        remote_ip: std::net::Ipv4Addr::LOCALHOST.into(),
        helo: settings.hostname.clone(),
        attempts: 0,
        next_attempt_at: None,
        state: SpoolState::Incoming,
        direction: Direction::Inbound,
        tls_version: None,
        tls_cipher: None,
        rcpt_status: Vec::new(),
        prepend_headers: Vec::new(),
        dsn_sent: false,
        pipeline: "deliver".into(),
    }
}

fn received(at: i64) -> String {
    let format = time::macros::format_description!("[year]-[month]-[day] [hour]:[minute] UTC");
    OffsetDateTime::from_unix_timestamp(at)
        .ok()
        .and_then(|when| when.format(&format).ok())
        .unwrap_or_default()
}
