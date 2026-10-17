//! Quarantine: a per-tenant index in SQLite, message bytes in a blob store,
//! release and delete behind role checks with an audit trail, retention
//! purge, and user digests with signed links.
//!
//! Index calls are synchronous and short; blob and spool calls are async.
mod audit;
pub mod digest;
pub mod http;
pub mod links;
pub mod store;

pub use audit::{AuditEvent, AuditSink, SqliteAudit};
pub use links::{Link, LinkAction, LinkError, LinkSigner};
pub use store::{open_blob_store, BlobStore, FsBlobStore, S3BlobStore};

use currawong_core::{
    config::{QuarantineConfig, ADMIN_RELEASE_QUEUES},
    Direction, MessageId,
};
use currawong_spool::{Envelope, Spool, SpoolState};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    io::Cursor,
    path::Path,
    sync::{Arc, Mutex},
};
use time::OffsetDateTime;

/// Applied in order. `PRAGMA user_version` records how many have run.
const MIGRATIONS: &[&str] = &[include_str!("../migrations/0001_quarantine.sql")];

/// Spool `pipeline` of a released message: the scheduler delivers it without
/// running policy again, so it cannot be quarantined a second time, and
/// trains the Bayes classifier on it.
pub const RELEASE_PIPELINE: &str = "release";

#[derive(Debug, thiserror::Error)]
pub enum QuarantineError {
    #[error("quarantine item not found")]
    NotFound,
    #[error("not allowed")]
    Forbidden,
    #[error("{0}")]
    BadRequest(String),
    #[error("item was already released or deleted")]
    Conflict,
    #[error(transparent)]
    Link(#[from] LinkError),
    #[error("link was already used")]
    LinkUsed,
    #[error("quarantine store: {0}")]
    Store(String),
}

fn db(err: impl std::fmt::Display) -> QuarantineError {
    QuarantineError::Store(err.to_string())
}

/// RBAC roles from docs/ARCHITECTURE.md.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    PlatformAdmin,
    MspAdmin,
    TenantAdmin,
    Auditor,
    EndUser,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PlatformAdmin => "platform_admin",
            Self::MspAdmin => "msp_admin",
            Self::TenantAdmin => "tenant_admin",
            Self::Auditor => "auditor",
            Self::EndUser => "end_user",
        }
    }
}

/// Who is acting. The admin API (#39) builds one from its session; a digest
/// link acts as the `EndUser` it was sent to. `actor` is the user's address
/// for end users. Every role but `PlatformAdmin` is bound to `tenant_id`;
/// MSP child tenants are resolved by #39.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Principal {
    pub actor: String,
    pub role: Role,
    pub tenant_id: Option<String>,
}

/// A message to hold, with one index row per recipient.
#[derive(Debug, Clone)]
pub struct Hold {
    pub message_id: MessageId,
    pub tenant_id: Option<String>,
    pub queue: String,
    pub reason: String,
    /// Policy explanation.
    pub reasons: Vec<String>,
    /// Envelope sender, used again on release.
    pub sender: String,
    pub recipients: Vec<String>,
    pub score: Option<f64>,
    pub direction: Direction,
    /// Our headers (Authentication-Results), prepended again on release.
    pub headers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Item {
    pub id: String,
    pub tenant_id: Option<String>,
    pub message_id: String,
    pub queue: String,
    pub recipient: String,
    pub sender: String,
    pub subject: String,
    pub score: Option<f64>,
    pub reason: String,
    pub reasons: Vec<String>,
    pub direction: Direction,
    #[serde(skip)]
    pub headers: Vec<String>,
    pub created_at: i64,
    pub expires_at: i64,
    pub released_at: Option<i64>,
    pub released_by: Option<String>,
    pub deleted_at: Option<i64>,
    pub deleted_by: Option<String>,
}

impl Item {
    /// Neither released nor deleted.
    pub fn held(&self) -> bool {
        self.released_at.is_none() && self.deleted_at.is_none()
    }
}

const ITEM_COLUMNS: &str = "id, tenant_id, message_id, queue, recipient, sender, subject, score, \
     reason, reasons_json, direction, headers_json, created_at, expires_at, released_at, \
     released_by, deleted_at, deleted_by";

fn item_from_row(row: &rusqlite::Row) -> rusqlite::Result<Item> {
    let json = |index: usize| -> rusqlite::Result<Vec<String>> {
        let text: String = row.get(index)?;
        serde_json::from_str(&text).map_err(|err| {
            rusqlite::Error::FromSqlConversionFailure(
                index,
                rusqlite::types::Type::Text,
                err.into(),
            )
        })
    };
    let direction: String = row.get(10)?;
    Ok(Item {
        id: row.get(0)?,
        tenant_id: row.get(1)?,
        message_id: row.get(2)?,
        queue: row.get(3)?,
        recipient: row.get(4)?,
        sender: row.get(5)?,
        subject: row.get(6)?,
        score: row.get(7)?,
        reason: row.get(8)?,
        reasons: json(9)?,
        direction: if direction == "outbound" {
            Direction::Outbound
        } else {
            Direction::Inbound
        },
        headers: json(11)?,
        created_at: row.get(12)?,
        expires_at: row.get(13)?,
        released_at: row.get(14)?,
        released_by: row.get(15)?,
        deleted_at: row.get(16)?,
        deleted_by: row.get(17)?,
    })
}

#[derive(Clone)]
pub struct QuarantineStore {
    conn: Arc<Mutex<Connection>>,
    blobs: Arc<dyn BlobStore>,
    audit: Arc<dyn AuditSink>,
    cfg: Arc<QuarantineConfig>,
    /// One release or delete at a time, so a double click cannot inject twice.
    actions: Arc<tokio::sync::Mutex<()>>,
}

impl std::fmt::Debug for QuarantineStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuarantineStore").finish_non_exhaustive()
    }
}

impl QuarantineStore {
    /// `dir/quarantine.sqlite` and file blobs under `dir/blobs`, with the
    /// default retention and queues.
    pub fn open(dir: impl AsRef<Path>) -> Result<Self, QuarantineError> {
        let dir = dir.as_ref();
        std::fs::create_dir_all(dir).map_err(db)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).map_err(db)?;
        }
        let conn = Connection::open(dir.join("quarantine.sqlite")).map_err(db)?;
        let done: usize = conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .map_err(db)?;
        for (index, sql) in MIGRATIONS.iter().enumerate().skip(done) {
            conn.execute_batch(sql).map_err(db)?;
            conn.pragma_update(None, "user_version", index + 1)
                .map_err(db)?;
        }
        let conn = Arc::new(Mutex::new(conn));
        Ok(Self {
            audit: Arc::new(SqliteAudit::new(Arc::clone(&conn))),
            conn,
            blobs: Arc::new(FsBlobStore::open(dir.join("blobs")).map_err(db)?),
            cfg: Arc::new(QuarantineConfig::default()),
            actions: Arc::new(tokio::sync::Mutex::new(())),
        })
    }

    pub fn with_config(mut self, cfg: &QuarantineConfig) -> Self {
        self.cfg = Arc::new(cfg.clone());
        self
    }

    pub fn with_blobs(mut self, blobs: Arc<dyn BlobStore>) -> Self {
        self.blobs = blobs;
        self
    }

    /// Replace the built-in audit table, for the admin crate's audit log.
    pub fn with_audit(mut self, audit: Arc<dyn AuditSink>) -> Self {
        self.audit = audit;
        self
    }

    /// The built-in append-only audit table.
    pub fn audit_table(&self) -> SqliteAudit {
        SqliteAudit::new(Arc::clone(&self.conn))
    }

    pub fn config(&self) -> &QuarantineConfig {
        &self.cfg
    }

    fn conn(&self) -> Result<std::sync::MutexGuard<'_, Connection>, QuarantineError> {
        self.conn.lock().map_err(db)
    }

    fn retention_days(&self, queue: &str) -> u64 {
        self.cfg
            .queue_retention_days
            .get(queue)
            .copied()
            .unwrap_or(self.cfg.retention_days)
    }

    /// Queues an end user may act on.
    pub fn user_queue(&self, queue: &str) -> bool {
        !ADMIN_RELEASE_QUEUES.contains(&queue)
            && self.cfg.user_release_queues.iter().any(|q| q == queue)
    }

    /// Store the bytes, then one row per recipient. Row ids derive from the
    /// message and recipient, so holding again after a crash adds nothing.
    pub async fn hold(
        &self,
        hold: &Hold,
        raw: &[u8],
        now: OffsetDateTime,
    ) -> Result<Vec<String>, QuarantineError> {
        let message_id = hold.message_id.as_str();
        self.blobs.put(message_id, raw).await.map_err(db)?;
        let now = now.unix_timestamp();
        let days = i64::try_from(self.retention_days(&hold.queue)).unwrap_or(i64::MAX / 86_400);
        let expires = now.saturating_add(days.saturating_mul(86_400));
        let subject = subject(raw);
        let reasons = serde_json::to_string(&hold.reasons).map_err(db)?;
        let headers = serde_json::to_string(&hold.headers).map_err(db)?;
        let direction = match hold.direction {
            Direction::Inbound => "inbound",
            Direction::Outbound => "outbound",
        };
        let mut conn = self.conn()?;
        let tx = conn.transaction().map_err(db)?;
        let mut ids = Vec::new();
        for recipient in &hold.recipients {
            let id = derived_id(message_id, recipient);
            tx.execute(
                "INSERT OR IGNORE INTO quarantine (id, tenant_id, message_id, queue, recipient,
                 sender, subject, score, reason, reasons_json, direction, headers_json,
                 created_at, expires_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
                params![
                    id,
                    hold.tenant_id,
                    message_id,
                    hold.queue,
                    recipient,
                    hold.sender,
                    subject,
                    hold.score,
                    hold.reason,
                    reasons,
                    direction,
                    headers,
                    now,
                    expires
                ],
            )
            .map_err(db)?;
            ids.push(id);
        }
        tx.commit().map_err(db)?;
        Ok(ids)
    }

    /// The hold reason of a message.
    pub fn reason(&self, message_id: &str) -> Result<String, QuarantineError> {
        self.conn()?
            .query_row(
                "SELECT reason FROM quarantine WHERE message_id = ?1 LIMIT 1",
                [message_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(db)?
            .ok_or(QuarantineError::NotFound)
    }

    /// BIMI logo and VMC status for the quarantine UI, as JSON.
    pub fn set_bimi(&self, message_id: &str, json: &str) -> Result<(), QuarantineError> {
        store::check_key(message_id).map_err(|err| QuarantineError::BadRequest(err.to_string()))?;
        let changed = self
            .conn()?
            .execute(
                "UPDATE quarantine SET bimi_json = ?2 WHERE message_id = ?1",
                params![message_id, json],
            )
            .map_err(db)?;
        if changed == 0 {
            return Err(QuarantineError::NotFound);
        }
        Ok(())
    }

    pub fn bimi(&self, message_id: &str) -> Result<Option<String>, QuarantineError> {
        store::check_key(message_id).map_err(|err| QuarantineError::BadRequest(err.to_string()))?;
        Ok(self
            .conn()?
            .query_row(
                "SELECT bimi_json FROM quarantine WHERE message_id = ?1 LIMIT 1",
                [message_id],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()
            .map_err(db)?
            .flatten())
    }

    pub fn get(&self, id: &str) -> Result<Option<Item>, QuarantineError> {
        self.conn()?
            .query_row(
                &format!("SELECT {ITEM_COLUMNS} FROM quarantine WHERE id = ?1"),
                [id],
                item_from_row,
            )
            .optional()
            .map_err(db)
    }

    /// Items the principal may see, newest first, optionally one queue.
    pub fn list(
        &self,
        principal: &Principal,
        queue: Option<&str>,
    ) -> Result<Vec<Item>, QuarantineError> {
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare(&format!(
                "SELECT {ITEM_COLUMNS} FROM quarantine
                 WHERE (?1 IS NULL OR queue = ?1) ORDER BY created_at DESC, id LIMIT 1000"
            ))
            .map_err(db)?;
        let items = stmt
            .query_map([queue], item_from_row)
            .map_err(db)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(db)?;
        Ok(items
            .into_iter()
            .filter(|item| self.can_see(principal, item))
            .collect())
    }

    fn can_see(&self, principal: &Principal, item: &Item) -> bool {
        match principal.role {
            Role::PlatformAdmin => true,
            Role::MspAdmin | Role::TenantAdmin | Role::Auditor => {
                principal.tenant_id.is_some() && principal.tenant_id == item.tenant_id
            }
            Role::EndUser => {
                principal.tenant_id == item.tenant_id
                    && principal.actor.eq_ignore_ascii_case(&item.recipient)
                    && self.user_queue(&item.queue)
            }
        }
    }

    /// Role checks for release and delete. Auditors only read. End users act
    /// only on their own items in user queues. Malware, virus and PSPF
    /// releases need an administrator and a reason.
    fn authorise(
        &self,
        principal: &Principal,
        item: &Item,
        action: LinkAction,
        reason: Option<&str>,
    ) -> Result<(), QuarantineError> {
        if principal.role == Role::Auditor || !self.can_see(principal, item) {
            return Err(QuarantineError::Forbidden);
        }
        let restricted = ADMIN_RELEASE_QUEUES.contains(&item.queue.as_str());
        if action == LinkAction::Release && restricted && reason.is_none_or(|r| r.trim().is_empty())
        {
            return Err(QuarantineError::BadRequest(format!(
                "releasing a {} item needs a reason",
                item.queue
            )));
        }
        Ok(())
    }

    fn audit(
        &self,
        principal: &Principal,
        item: &Item,
        action: &str,
        reason: Option<&str>,
        detail: Option<String>,
        now: i64,
    ) -> Result<(), QuarantineError> {
        self.audit
            .record(&AuditEvent {
                at: now,
                actor: principal.actor.clone(),
                role: principal.role.as_str().into(),
                tenant_id: item.tenant_id.clone(),
                item_id: item.id.clone(),
                action: action.into(),
                reason: reason.map(str::to_string),
                detail,
            })
            .map_err(QuarantineError::Store)
    }

    /// Release or delete as `principal`. A release returns the spool id of
    /// the re-injected message.
    pub async fn act(
        &self,
        spool: &Spool,
        principal: &Principal,
        item_id: &str,
        action: LinkAction,
        reason: Option<&str>,
        now: OffsetDateTime,
    ) -> Result<Option<MessageId>, QuarantineError> {
        self.perform(spool, principal, item_id, action, reason, None, now)
            .await
    }

    /// `link` is a verified digest link, spent once the action succeeds.
    #[allow(clippy::too_many_arguments)]
    async fn perform(
        &self,
        spool: &Spool,
        principal: &Principal,
        item_id: &str,
        action: LinkAction,
        reason: Option<&str>,
        link: Option<&links::Verified>,
        now: OffsetDateTime,
    ) -> Result<Option<MessageId>, QuarantineError> {
        let _one = self.actions.lock().await;
        let now = now.unix_timestamp();
        let item = self.get(item_id)?.ok_or(QuarantineError::NotFound)?;
        if let Err(err) = self.authorise(principal, &item, action, reason) {
            if matches!(err, QuarantineError::Forbidden) {
                let denied = format!("denied:{}", action.as_str());
                self.audit(principal, &item, &denied, reason, None, now)?;
            }
            return Err(err);
        }
        if let Some(link) = link {
            if self.spent(link)? {
                return Err(QuarantineError::LinkUsed);
            }
        }
        if !item.held() {
            return Err(QuarantineError::Conflict);
        }
        let done = match action {
            LinkAction::Release => self.release(spool, principal, &item, reason, now).await?,
            LinkAction::Delete => self.delete(principal, &item, reason, now).await?,
        };
        if let Some(link) = link {
            self.spend(link, now)?;
        }
        Ok(done)
    }

    /// A digest link acts as the end user it was addressed to, on the action
    /// it names.
    pub async fn act_on_link(
        &self,
        spool: &Spool,
        signer: &LinkSigner,
        token: &str,
        now: OffsetDateTime,
    ) -> Result<(Item, LinkAction), QuarantineError> {
        let verified = signer.verify(token, now.unix_timestamp())?;
        let link = &verified.link;
        let item = self.get(&link.item_id)?.ok_or(QuarantineError::NotFound)?;
        let principal = Principal {
            actor: link.recipient.clone(),
            role: Role::EndUser,
            tenant_id: item.tenant_id.clone(),
        };
        self.perform(
            spool,
            &principal,
            &item.id,
            link.action,
            None,
            Some(&verified),
            now,
        )
        .await?;
        Ok((item, link.action))
    }

    fn spent(&self, link: &links::Verified) -> Result<bool, QuarantineError> {
        self.conn()?
            .query_row(
                "SELECT COUNT(*) > 0 FROM quarantine_links WHERE mac = ?1",
                [&link.mac],
                |row| row.get(0),
            )
            .map_err(db)
    }

    /// Spent after the action succeeds; the action lock makes check and
    /// spend one step.
    fn spend(&self, link: &links::Verified, now: i64) -> Result<(), QuarantineError> {
        self.conn()?
            .execute(
                "INSERT OR IGNORE INTO quarantine_links (mac, expires_at, used_at) VALUES (?1, ?2, ?3)",
                params![link.mac, link.link.expires_at, now],
            )
            .map(|_| ())
            .map_err(db)
    }

    /// Re-inject the original bytes for this one recipient, marked so the
    /// scheduler delivers without policy. The spool id derives from the item,
    /// so a retry after a crash finds the same message.
    async fn release(
        &self,
        spool: &Spool,
        principal: &Principal,
        item: &Item,
        reason: Option<&str>,
        now: i64,
    ) -> Result<Option<MessageId>, QuarantineError> {
        let raw = self.blobs.get(&item.message_id).await.map_err(db)?;
        let env = release_envelope(item, now);
        if spool.load(&env.id).await.is_err() {
            spool
                .accept(env.clone(), Cursor::new(raw.clone()))
                .await
                .map_err(db)?;
        }
        self.conn()?
            .execute(
                "UPDATE quarantine SET released_at = ?2, released_by = ?3 WHERE id = ?1",
                params![item.id, now, principal.actor],
            )
            .map_err(db)?;
        self.audit(
            principal,
            item,
            "release",
            reason,
            Some(env.id.to_string()),
            now,
        )?;
        tracing::info!(item = %item.id, released = %env.id, actor = %principal.actor, "quarantine item released");
        Ok(Some(env.id))
    }

    async fn delete(
        &self,
        principal: &Principal,
        item: &Item,
        reason: Option<&str>,
        now: i64,
    ) -> Result<Option<MessageId>, QuarantineError> {
        self.conn()?
            .execute(
                "UPDATE quarantine SET deleted_at = ?2, deleted_by = ?3 WHERE id = ?1",
                params![item.id, now, principal.actor],
            )
            .map_err(db)?;
        let still_held: bool = self
            .conn()?
            .query_row(
                "SELECT COUNT(*) > 0 FROM quarantine WHERE message_id = ?1
                 AND released_at IS NULL AND deleted_at IS NULL",
                [&item.message_id],
                |row| row.get(0),
            )
            .map_err(db)?;
        if !still_held {
            self.blobs.delete(&item.message_id).await.map_err(db)?;
        }
        self.audit(principal, item, "delete", reason, None, now)?;
        Ok(None)
    }

    /// Remove expired items from the index and their bytes from the blob
    /// store, and spent links that have expired. Blobs go first, so a failed
    /// pass leaves rows to retry from.
    pub async fn purge(&self, now: OffsetDateTime) -> Result<usize, QuarantineError> {
        let now = now.unix_timestamp();
        let expired: Vec<Item> = {
            let conn = self.conn()?;
            let mut stmt = conn
                .prepare(&format!(
                    "SELECT {ITEM_COLUMNS} FROM quarantine WHERE expires_at <= ?1"
                ))
                .map_err(db)?;
            let rows = stmt
                .query_map([now], item_from_row)
                .map_err(db)?
                .collect::<Result<_, _>>()
                .map_err(db)?;
            rows
        };
        let system = Principal {
            actor: "system".into(),
            role: Role::PlatformAdmin,
            tenant_id: None,
        };
        let mut purged = 0;
        for item in &expired {
            let others: bool = self
                .conn()?
                .query_row(
                    "SELECT COUNT(*) > 0 FROM quarantine WHERE message_id = ?1 AND expires_at > ?2",
                    params![item.message_id, now],
                    |row| row.get(0),
                )
                .map_err(db)?;
            if !others {
                self.blobs.delete(&item.message_id).await.map_err(db)?;
            }
            self.conn()?
                .execute("DELETE FROM quarantine WHERE id = ?1", [&item.id])
                .map_err(db)?;
            self.audit(&system, item, "purge", None, None, now)?;
            purged += 1;
        }
        self.conn()?
            .execute("DELETE FROM quarantine_links WHERE expires_at <= ?1", [now])
            .map_err(db)?;
        Ok(purged)
    }

    /// Held items in user queues not yet in a digest.
    pub(crate) fn undigested(&self, now: i64) -> Result<Vec<Item>, QuarantineError> {
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare(&format!(
                "SELECT {ITEM_COLUMNS} FROM quarantine WHERE digested_at IS NULL
                 AND released_at IS NULL AND deleted_at IS NULL AND expires_at > ?1
                 ORDER BY tenant_id, recipient, created_at, id"
            ))
            .map_err(db)?;
        let items: Vec<Item> = stmt
            .query_map([now], item_from_row)
            .map_err(db)?
            .collect::<Result<_, _>>()
            .map_err(db)?;
        Ok(items
            .into_iter()
            .filter(|item| self.user_queue(&item.queue))
            .collect())
    }

    pub(crate) fn mark_digested(&self, ids: &[String], now: i64) -> Result<(), QuarantineError> {
        let mut conn = self.conn()?;
        let tx = conn.transaction().map_err(db)?;
        for id in ids {
            tx.execute(
                "UPDATE quarantine SET digested_at = ?2 WHERE id = ?1",
                params![id, now],
            )
            .map_err(db)?;
        }
        tx.commit().map_err(db)
    }

    pub(crate) fn meta(&self, key: &str) -> Result<Option<String>, QuarantineError> {
        self.conn()?
            .query_row(
                "SELECT value FROM quarantine_meta WHERE key = ?1",
                [key],
                |row| row.get(0),
            )
            .optional()
            .map_err(db)
    }

    pub(crate) fn set_meta(&self, key: &str, value: &str) -> Result<(), QuarantineError> {
        self.conn()?
            .execute(
                "INSERT INTO quarantine_meta (key, value) VALUES (?1, ?2)
                 ON CONFLICT (key) DO UPDATE SET value = excluded.value",
                params![key, value],
            )
            .map(|_| ())
            .map_err(db)
    }
}

fn release_envelope(item: &Item, now: i64) -> Envelope {
    Envelope {
        id: MessageId(derived_id(&item.id, "release")),
        tenant_id: item.tenant_id.clone(),
        authenticated_as: None,
        mail_from: item.sender.clone(),
        rcpt_to: vec![item.recipient.clone()],
        received_at: OffsetDateTime::from_unix_timestamp(now)
            .unwrap_or_else(|_| OffsetDateTime::now_utc()),
        remote_ip: std::net::Ipv4Addr::LOCALHOST.into(),
        helo: "localhost".into(),
        attempts: 0,
        next_attempt_at: None,
        state: SpoolState::Incoming,
        direction: item.direction,
        tls_version: None,
        tls_cipher: None,
        rcpt_status: Vec::new(),
        prepend_headers: item.headers.clone(),
        dsn_sent: false,
        pipeline: RELEASE_PIPELINE.into(),
    }
}

/// A spool-safe id (26 upper-case hex characters) derived from another id.
pub(crate) fn derived_id(id: &str, salt: &str) -> String {
    let digest = Sha256::digest(format!("{id}\n{salt}"));
    hex::encode_upper(digest)[..26].to_string()
}

fn subject(raw: &[u8]) -> String {
    let subject = mail_parser::MessageParser::default()
        .parse_headers(raw)
        .and_then(|message| message.subject().map(str::to_string))
        .unwrap_or_default();
    subject
        .chars()
        .filter(|c| !c.is_control())
        .take(500)
        .collect()
}
