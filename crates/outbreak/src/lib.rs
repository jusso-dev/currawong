//! Local outbreak protection (ADR 0010). All timestamps are supplied by the
//! caller, making retry windows and retention deterministic in offline tests.
pub mod similarity;
use currawong_core::{
    config::OutbreakConfig, report::OutbreakReport, Direction, PartFlag, ScanReport,
};
use currawong_intel::{normalise, Kind};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use similarity::Digest;
use std::{
    collections::{BTreeSet, HashSet},
    path::Path,
    sync::Mutex,
};

pub const MAX_PARTS: usize = 64;
pub const MAX_URLS: usize = 64;
const MAX_CANDIDATES: usize = 4096;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Feature {
    pub kind: String,
    pub value: String,
    pub content_type: String,
    pub digest: Option<Digest>,
}

/// Metadata only; no part paths, raw mail or body text are persisted here.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Content {
    pub features: Vec<Feature>,
}

impl Content {
    pub fn from_report(report: &ScanReport, body: &str) -> Self {
        let mut features = Vec::new();
        for part in report.parts.iter().take(MAX_PARTS) {
            if let Some(value) = normalise(Kind::Sha256, &part.sha256) {
                features.push(Feature {
                    kind: if part.is_attachment || part.filename.is_some() {
                        "sha256"
                    } else {
                        "body_sha256"
                    }
                    .into(),
                    value,
                    content_type: part.content_type.chars().take(256).collect(),
                    digest: None,
                });
            }
        }
        for url in report
            .urls
            .iter()
            .take(MAX_URLS)
            .filter(|u| u.len() <= 2048)
        {
            if let Some(value) = normalise(Kind::Url, url) {
                features.push(Feature {
                    kind: "url".into(),
                    value,
                    content_type: String::new(),
                    digest: None,
                });
            }
        }
        if let Some(digest) = similarity::digest(similarity::normalise_body(body).as_bytes()) {
            features.push(Feature {
                kind: "body".into(),
                value: String::new(),
                content_type: String::new(),
                digest: Some(digest),
            });
        }
        Self { features }
    }
}

#[derive(Debug, Clone)]
pub struct Message<'a> {
    pub id: &'a str,
    pub tenant: &'a str,
    pub direction: Direction,
    pub sender: &'a str,
    pub recipients: &'a [String],
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Detection {
    pub message_id: String,
    pub tenant: String,
    pub direction: String,
    pub sender: String,
    pub recipients: Vec<String>,
    pub delivered_at: i64,
    pub source: String,
    pub indicator: String,
}

/// Real mailbox adapters (#41/#51) implement this seam. Success means the
/// notification was accepted, never that mailbox content was removed.
pub trait Remediation: Send + Sync {
    fn remediate(&self, detection: &Detection) -> Result<(), String>;
}

pub struct Store {
    conn: Mutex<Connection>,
    pub config: OutbreakConfig,
}
fn db(err: impl std::fmt::Display) -> String {
    format!("outbreak store: {err}")
}

impl Store {
    pub fn open(path: &Path, config: OutbreakConfig) -> Result<Self, String> {
        config.validate()?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(db)?;
        }
        let conn = Connection::open(path).map_err(db)?;
        conn.busy_timeout(std::time::Duration::from_secs(5))
            .map_err(db)?;
        let version: u32 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .map_err(db)?;
        if version > 1 {
            return Err(db("schema is newer than this build"));
        }
        conn.execute_batch("PRAGMA auto_vacuum=INCREMENTAL; PRAGMA journal_mode=WAL;
            PRAGMA foreign_keys=ON;
            CREATE TABLE IF NOT EXISTS messages (
                id TEXT NOT NULL, tenant TEXT NOT NULL, direction TEXT NOT NULL,
                sender TEXT NOT NULL, recipients TEXT NOT NULL, seen INTEGER NOT NULL,
                delivered INTEGER, campaign_id TEXT NOT NULL, PRIMARY KEY(id,tenant));
            CREATE INDEX IF NOT EXISTS message_seen ON messages(seen);
            CREATE INDEX IF NOT EXISTS message_delivered ON messages(delivered);
            CREATE TABLE IF NOT EXISTS features (
                id TEXT NOT NULL, tenant TEXT NOT NULL, kind TEXT NOT NULL, value TEXT NOT NULL,
                content_type TEXT NOT NULL, digest TEXT, seen INTEGER NOT NULL, delivered INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY(id,tenant,kind,value),
                FOREIGN KEY(id,tenant) REFERENCES messages(id,tenant) ON DELETE CASCADE);
            CREATE INDEX IF NOT EXISTS feature_lookup ON features(kind,value,seen);
            CREATE INDEX IF NOT EXISTS feature_retro ON features(delivered);
            CREATE TABLE IF NOT EXISTS buckets (
                id TEXT NOT NULL, tenant TEXT NOT NULL, kind TEXT NOT NULL, bucket TEXT NOT NULL,
                digest TEXT NOT NULL, seen INTEGER NOT NULL, PRIMARY KEY(id,tenant,kind,bucket,digest),
                FOREIGN KEY(id,tenant) REFERENCES messages(id,tenant) ON DELETE CASCADE);
            CREATE INDEX IF NOT EXISTS bucket_lookup ON buckets(kind,bucket,seen);
            CREATE TABLE IF NOT EXISTS first_seen (hash TEXT PRIMARY KEY, first INTEGER NOT NULL, last INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS sightings (hash TEXT NOT NULL, tenant TEXT NOT NULL, seen INTEGER NOT NULL,
                PRIMARY KEY(hash,tenant), FOREIGN KEY(hash) REFERENCES first_seen(hash) ON DELETE CASCADE);
            CREATE TABLE IF NOT EXISTS clean (hash TEXT PRIMARY KEY, expires INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS retained (hash TEXT PRIMARY KEY, data BLOB NOT NULL, expires INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS detections (id TEXT NOT NULL, tenant TEXT NOT NULL, source TEXT NOT NULL,
                indicator TEXT NOT NULL, notified INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY(id,tenant,source,indicator),
                FOREIGN KEY(id,tenant) REFERENCES messages(id,tenant) ON DELETE CASCADE);
            CREATE TABLE IF NOT EXISTS usage (id INTEGER PRIMARY KEY, messages INTEGER NOT NULL, retained_bytes INTEGER NOT NULL);
            INSERT OR IGNORE INTO usage VALUES(1,0,0);
            CREATE TRIGGER IF NOT EXISTS count_message_insert AFTER INSERT ON messages BEGIN UPDATE usage SET messages=messages+1 WHERE id=1; END;
            CREATE TRIGGER IF NOT EXISTS count_message_delete AFTER DELETE ON messages BEGIN UPDATE usage SET messages=messages-1 WHERE id=1; END;
            CREATE TRIGGER IF NOT EXISTS count_retained_insert AFTER INSERT ON retained BEGIN UPDATE usage SET retained_bytes=retained_bytes+length(new.data) WHERE id=1; END;
            CREATE TRIGGER IF NOT EXISTS count_retained_delete AFTER DELETE ON retained BEGIN UPDATE usage SET retained_bytes=retained_bytes-length(old.data) WHERE id=1; END;
            CREATE TABLE IF NOT EXISTS state (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            PRAGMA user_version=1;").map_err(db)?;
        Ok(Self {
            conn: Mutex::new(conn),
            config,
        })
    }

    /// Stage metadata at scan time. Retried observations keep their original
    /// timestamp, and each message/tenant contributes once to campaign counts.
    pub fn observe(
        &self,
        message: &Message<'_>,
        content: &Content,
        now: i64,
    ) -> Result<OutbreakReport, String> {
        let mut conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        let tx = conn.transaction().map_err(db)?;
        tx.execute("INSERT INTO messages VALUES(?1,?2,?3,?4,?5,?6,NULL,?1) ON CONFLICT(id,tenant) DO NOTHING",
            params![message.id,message.tenant, match message.direction {Direction::Inbound=>"inbound",Direction::Outbound=>"outbound"},
                message.sender,serde_json::to_string(&message.recipients.iter().take(256).collect::<Vec<_>>()).map_err(db)?,now]).map_err(db)?;
        // Keep the first staged metadata; a split plan can be resumed safely.
        for f in content.features.iter().take(MAX_PARTS * 2 + MAX_URLS + 1) {
            let digest = f
                .digest
                .as_ref()
                .map(|d| serde_json::to_string(d).expect("integer array"));
            tx.execute(
                "INSERT OR IGNORE INTO features VALUES(?1,?2,?3,?4,?5,?6,?7,0)",
                params![
                    message.id,
                    message.tenant,
                    f.kind,
                    f.value,
                    f.content_type,
                    digest,
                    now
                ],
            )
            .map_err(db)?;
            if let Some(d) = &f.digest {
                for bucket in similarity::bands(d) {
                    tx.execute(
                        "INSERT OR IGNORE INTO buckets VALUES(?1,?2,?3,?4,?5,?6)",
                        params![message.id, message.tenant, f.kind, bucket, digest, now],
                    )
                    .map_err(db)?;
                }
            }
        }
        let mut matches = BTreeSet::from([(
            message.id.to_string(),
            message.tenant.to_string(),
            message.sender.to_string(),
        )]);
        let mut truncated = false;
        let mut examined = 0;
        let cutoff = now - self.config.campaign_window_minutes as i64 * 60;
        for f in &content.features {
            if f.kind == "body_sha256" {
                continue;
            }
            let keys: Vec<_> = match &f.digest {
                Some(d) => similarity::bands(d).collect(),
                None => vec![f.value.clone()],
            };
            for key in keys {
                let sql = if f.digest.is_some() {
                    "SELECT m.campaign_id,m.tenant,m.sender,b.digest FROM buckets b JOIN messages m USING(id,tenant) WHERE b.kind=?1 AND b.bucket=?2 AND b.seen>=?3 LIMIT 4097"
                } else {
                    "SELECT m.campaign_id,m.tenant,m.sender,f.digest FROM features f JOIN messages m USING(id,tenant) WHERE f.kind=?1 AND f.value=?2 AND f.seen>=?3 LIMIT 4097"
                };
                let mut stmt = tx.prepare_cached(sql).map_err(db)?;
                let rows = stmt
                    .query_map(params![f.kind, key, cutoff], |r| {
                        Ok((
                            r.get::<_, String>(0)?,
                            r.get::<_, String>(1)?,
                            r.get::<_, String>(2)?,
                            r.get::<_, Option<String>>(3)?,
                        ))
                    })
                    .map_err(db)?;
                for (index, row) in rows.enumerate() {
                    if index == MAX_CANDIDATES || examined >= MAX_CANDIDATES {
                        truncated = true;
                        break;
                    }
                    examined += 1;
                    let (id, tenant, sender, digest) = row.map_err(db)?;
                    if let Some(a) = &f.digest {
                        let Some(b) = digest.and_then(|s| serde_json::from_str::<Digest>(&s).ok())
                        else {
                            continue;
                        };
                        if !similarity::similar(a, &b) {
                            continue;
                        }
                    }
                    matches.insert((id, tenant, sender));
                }
                if truncated {
                    break;
                }
            }
            if truncated {
                break;
            }
        }
        // Count message ids, not recipients or repeated feature matches.
        let messages = matches.iter().map(|m| &m.0).collect::<HashSet<_>>().len() as u64;
        let tenants = matches.iter().map(|m| &m.1).collect::<HashSet<_>>().len() as u64;
        let senders = matches.iter().map(|m| &m.2).collect::<HashSet<_>>().len() as u64;
        // Bound index cardinality even between scheduled retention passes.
        self.enforce_capacity(&tx)?;
        tx.commit().map_err(db)?;
        Ok(OutbreakReport {
            messages,
            tenants,
            senders,
            truncated,
            ..Default::default()
        })
    }

    pub fn deliver(&self, staged_id: &str, message: &Message<'_>, now: i64) -> Result<(), String> {
        self.copy_record(staged_id, message, Some(now))
    }

    pub fn stage_copy(&self, staged_id: &str, message: &Message<'_>) -> Result<(), String> {
        self.copy_record(staged_id, message, None)
    }

    fn copy_record(
        &self,
        staged_id: &str,
        message: &Message<'_>,
        delivered: Option<i64>,
    ) -> Result<(), String> {
        let mut conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        let tx = conn.transaction().map_err(db)?;
        tx.execute("INSERT INTO messages SELECT ?1,?2,direction,sender,?3,seen,?4,campaign_id FROM messages WHERE id=?5 LIMIT 1 ON CONFLICT(id,tenant) DO UPDATE SET recipients=excluded.recipients,delivered=COALESCE(messages.delivered,excluded.delivered)",
            params![message.id,message.tenant,serde_json::to_string(message.recipients).map_err(db)?,delivered,staged_id]).map_err(db)?;
        tx.execute("INSERT OR IGNORE INTO features SELECT ?1,?2,kind,value,content_type,digest,seen,0 FROM features WHERE id=?3",params![message.id,message.tenant,staged_id]).map_err(db)?;
        self.enforce_capacity(&tx)?;
        if delivered.is_some() {
            tx.execute(
                "UPDATE features SET delivered=1 WHERE id=?1 AND tenant=?2",
                params![message.id, message.tenant],
            )
            .map_err(db)?;
        }
        tx.commit().map_err(db)
    }

    fn enforce_capacity(&self, conn: &Connection) -> Result<(), String> {
        let count: i64 = conn
            .query_row("SELECT messages FROM usage WHERE id=1", [], |r| r.get(0))
            .map_err(db)?;
        let excess = count - self.config.max_messages as i64;
        if excess > 0 {
            conn.execute("DELETE FROM messages WHERE rowid IN (SELECT rowid FROM messages ORDER BY seen LIMIT ?1)",[excess]).map_err(db)?;
        }
        Ok(())
    }

    /// Record first sighting globally, then decide whether this hash is still
    /// inside its fixed hold window. Clean cache is explicit, never inferred
    /// from the absence of a signature in the initial scan.
    pub fn hold(&self, hash: &str, tenant: &str, now: i64) -> Result<(bool, u64), String> {
        let mut conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        let tx = conn.transaction().map_err(db)?;
        tx.execute("INSERT INTO first_seen VALUES(?1,?2,?2) ON CONFLICT(hash) DO UPDATE SET last=MAX(last,excluded.last)",params![hash,now]).map_err(db)?;
        tx.execute("INSERT INTO sightings VALUES(?1,?2,?3) ON CONFLICT(hash,tenant) DO UPDATE SET seen=MAX(seen,excluded.seen)",params![hash,tenant,now]).map_err(db)?;
        let first: i64 = tx
            .query_row("SELECT first FROM first_seen WHERE hash=?1", [hash], |r| {
                r.get(0)
            })
            .map_err(db)?;
        let tenants: u64 = tx
            .query_row(
                "SELECT COUNT(*) FROM sightings WHERE hash=?1 AND seen>=?2",
                params![hash, now - self.config.hold_minutes as i64 * 60],
                |r| r.get(0),
            )
            .map_err(db)?;
        let clean: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM clean WHERE hash=?1 AND expires>?2)",
                params![hash, now],
                |r| r.get(0),
            )
            .map_err(db)?;
        tx.commit().map_err(db)?;
        let age = now.saturating_sub(first).max(0) as u64;
        let allow = self
            .config
            .known_clean_sha256
            .iter()
            .any(|s| s.eq_ignore_ascii_case(hash));
        Ok((
            !clean
                && !allow
                && age < self.config.hold_minutes * 60
                && tenants >= self.config.min_tenants,
            age / 60,
        ))
    }

    pub fn hold_deadline(&self, hash: &str) -> Result<Option<i64>, String> {
        let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        let first: Option<i64> = conn
            .query_row("SELECT first FROM first_seen WHERE hash=?1", [hash], |r| {
                r.get(0)
            })
            .optional()
            .map_err(db)?;
        Ok(first.map(|first| first + self.config.hold_minutes as i64 * 60))
    }

    pub fn mark_clean(&self, hash: &str, expires: i64) -> Result<(), String> {
        self.conn.lock().unwrap_or_else(|p|p.into_inner()).execute("INSERT INTO clean VALUES(?1,?2) ON CONFLICT(hash) DO UPDATE SET expires=excluded.expires",params![hash,expires]).map_err(db)?;
        Ok(())
    }

    pub fn retain(&self, hash: &str, bytes: &[u8], now: i64) -> Result<bool, String> {
        if self.config.retain_parts_hours == 0 || bytes.len() as u64 > self.config.max_part_bytes {
            return Ok(false);
        }
        if hex::encode(Sha256::digest(bytes)) != hash {
            return Err(db("retained part hash mismatch"));
        }
        let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        let exists: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM retained WHERE hash=?1)",
                [hash],
                |r| r.get(0),
            )
            .map_err(db)?;
        let used: u64 = conn
            .query_row("SELECT retained_bytes FROM usage WHERE id=1", [], |r| {
                r.get(0)
            })
            .map_err(db)?;
        if !exists && used + bytes.len() as u64 > self.config.max_retained_bytes {
            return Ok(false);
        }
        conn.execute("INSERT INTO retained VALUES(?1,?2,?3) ON CONFLICT(hash) DO UPDATE SET expires=MAX(expires,excluded.expires)",params![hash,bytes,now+self.config.retain_parts_hours as i64*3600]).map_err(db)?;
        Ok(true)
    }

    pub fn purge(&self, now: i64) -> Result<(), String> {
        let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        let cutoff = now - self.config.retention_days as i64 * 86400;
        conn.execute(
            "DELETE FROM messages WHERE COALESCE(delivered,seen)<?1",
            [cutoff],
        )
        .map_err(db)?;
        conn.execute("DELETE FROM first_seen WHERE last<?1", [cutoff])
            .map_err(db)?;
        conn.execute("DELETE FROM clean WHERE expires<=?1", [now])
            .map_err(db)?;
        conn.execute("DELETE FROM retained WHERE expires<=?1", [now])
            .map_err(db)?;
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE); PRAGMA incremental_vacuum(1024);")
            .map_err(db)
    }

    /// Keyset pages keep retro work bounded. Only delivered records qualify.
    pub fn indicator_page(&self, after: i64) -> Result<Vec<(i64, String, String)>, String> {
        let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        let mut stmt=conn.prepare("SELECT f.rowid,CASE f.kind WHEN 'body_sha256' THEN 'sha256' ELSE f.kind END,f.value FROM features f WHERE f.delivered=1 AND f.kind IN ('sha256','body_sha256','url') AND f.rowid>?1 ORDER BY f.rowid LIMIT 256").map_err(db)?;
        let rows = stmt
            .query_map([after], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .map_err(db)?;
        rows.collect::<Result<_, _>>().map_err(db)
    }

    pub fn retained_page(&self, after: &str, now: i64) -> Result<Vec<(String, Vec<u8>)>, String> {
        let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        let mut stmt=conn.prepare("SELECT hash,data FROM retained WHERE hash>?1 AND expires>?2 AND EXISTS(SELECT 1 FROM features f JOIN messages m USING(id,tenant) WHERE f.kind IN ('sha256','body_sha256') AND f.value=hash AND m.delivered IS NOT NULL) ORDER BY hash LIMIT 1").map_err(db)?;
        let rows = stmt
            .query_map(params![after, now], |r| Ok((r.get(0)?, r.get(1)?)))
            .map_err(db)?;
        rows.collect::<Result<_, _>>().map_err(db)
    }

    pub fn state(&self, key: &str) -> Result<Option<String>, String> {
        self.conn
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .query_row("SELECT value FROM state WHERE key=?1", [key], |r| r.get(0))
            .optional()
            .map_err(db)
    }
    pub fn set_state(&self, key: &str, value: &str) -> Result<(), String> {
        self.conn.lock().unwrap_or_else(|p|p.into_inner()).execute("INSERT INTO state VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",params![key,value]).map_err(db)?;
        Ok(())
    }

    /// Durable detection outbox: a failed remediation is retried, successful
    /// notifications are not repeated on every feed refresh or daemon restart.
    pub fn detect(&self, kind: &str, value: &str, source: &str) -> Result<(), String> {
        let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        conn.execute("INSERT OR IGNORE INTO detections(id,tenant,source,indicator) SELECT f.id,f.tenant,?3,?2 FROM features f JOIN messages m USING(id,tenant) WHERE (f.kind=?1 OR (?1='sha256' AND f.kind='body_sha256')) AND f.value=?2 AND m.delivered IS NOT NULL",params![kind,value,source]).map_err(db)?;
        Ok(())
    }
    pub fn notify(
        &self,
        remediation: &dyn Remediation,
        mut emit: impl FnMut(&Detection),
    ) -> Result<usize, String> {
        let pending: Vec<Detection> = {
            let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
            let mut stmt=conn.prepare("SELECT m.id,m.tenant,m.direction,m.sender,m.recipients,m.delivered,d.source,d.indicator FROM detections d JOIN messages m USING(id,tenant) WHERE d.notified=0 LIMIT 256").map_err(db)?;
            let rows = stmt
                .query_map([], |r| {
                    Ok(Detection {
                        message_id: r.get(0)?,
                        tenant: r.get(1)?,
                        direction: r.get(2)?,
                        sender: r.get(3)?,
                        recipients: serde_json::from_str(&r.get::<_, String>(4)?)
                            .unwrap_or_default(),
                        delivered_at: r.get(5)?,
                        source: r.get(6)?,
                        indicator: r.get(7)?,
                    })
                })
                .map_err(db)?;
            rows.collect::<Result<_, _>>().map_err(db)?
        };
        let mut done = 0;
        let mut failure = None;
        for detection in pending {
            if let Err(err) = remediation.remediate(&detection) {
                failure = Some(err);
                continue;
            }
            emit(&detection);
            self.conn.lock().unwrap_or_else(|p|p.into_inner()).execute("UPDATE detections SET notified=1 WHERE id=?1 AND tenant=?2 AND source=?3 AND indicator=?4",params![detection.message_id,detection.tenant,detection.source,detection.indicator]).map_err(db)?;
            done += 1;
        }
        if let Some(err) = failure {
            Err(err)
        } else {
            Ok(done)
        }
    }
}

/// Selection uses verified parser flags and attachment metadata. Archive
/// members are individual parts, so a risky member also selects its parent.
pub fn hold_type(part: &currawong_core::PartInfo) -> Option<&'static str> {
    let flags = &part.flags;
    if flags.contains(&PartFlag::Executable) {
        Some("executable")
    } else if flags.contains(&PartFlag::HasMacro) {
        Some("macro_office")
    } else if flags.contains(&PartFlag::DiskImage) {
        Some("disk_image")
    } else if flags.iter().any(|f| {
        matches!(
            f,
            PartFlag::PdfJavaScript
                | PartFlag::PdfLaunch
                | PartFlag::PdfAutoAction
                | PartFlag::PdfForm
                | PartFlag::PdfRemoteAction
        )
    }) {
        Some("active_pdf")
    } else if part.content_type == "image/svg+xml" || flags.contains(&PartFlag::SvgActive) {
        Some("svg")
    } else if part.content_type == "text/html" && (part.is_attachment || part.filename.is_some()) {
        Some("html")
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    fn message<'a>(id: &'a str, tenant: &'a str, sender: &'a str) -> Message<'a> {
        Message {
            id,
            tenant,
            direction: Direction::Inbound,
            sender,
            recipients: &[],
        }
    }
    fn content() -> Content {
        Content {
            features: vec![
                Feature {
                    kind: "sha256".into(),
                    value: "a".repeat(64),
                    content_type: "text/plain".into(),
                    digest: None,
                },
                Feature {
                    kind: "url".into(),
                    value: "https://example.test/path".into(),
                    content_type: String::new(),
                    digest: None,
                },
            ],
        }
    }
    #[test]
    fn index_deliver_split_and_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("outbreak.db");
        let store = Store::open(&path, OutbreakConfig::default()).unwrap();
        let msg = message("one", "a", "sender");
        store.observe(&msg, &content(), 100).unwrap();
        assert!(store.indicator_page(0).unwrap().is_empty());
        store.deliver("one", &msg, 101).unwrap();
        store
            .deliver("one", &message("copy", "b", "sender"), 102)
            .unwrap();
        store.deliver("one", &msg, 103).unwrap();
        assert_eq!(store.indicator_page(0).unwrap().len(), 4);
        drop(store);
        let store = Store::open(&path, OutbreakConfig::default()).unwrap();
        store.detect("sha256", &"a".repeat(64), "test").unwrap();
        let calls = Calls(AtomicUsize::new(0));
        let mut tenants = Vec::new();
        assert_eq!(
            store
                .notify(&calls, |d| tenants.push(d.tenant.clone()))
                .unwrap(),
            2
        );
        assert_eq!(
            tenants.into_iter().collect::<BTreeSet<_>>(),
            BTreeSet::from(["a".into(), "b".into()])
        );
        assert_eq!(calls.0.load(Ordering::SeqCst), 2);
        assert_eq!(store.notify(&calls, |_| panic!("duplicate")).unwrap(), 0);
    }
    struct Calls(AtomicUsize);
    impl Remediation for Calls {
        fn remediate(&self, _: &Detection) -> Result<(), String> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }
    #[test]
    fn hold_fixed_window_tenants_clean_and_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("outbreak.db");
        let config = OutbreakConfig {
            min_tenants: 2,
            ..Default::default()
        };
        let store = Store::open(&path, config.clone()).unwrap();
        assert_eq!(store.hold("hash", "a", 100).unwrap(), (false, 0));
        assert_eq!(store.hold("hash", "b", 160).unwrap(), (true, 1));
        drop(store);
        let store = Store::open(&path, config).unwrap();
        assert_eq!(store.hold("hash", "a", 1899).unwrap(), (true, 29));
        assert_eq!(store.hold("hash", "a", 1900).unwrap(), (false, 30));
        assert_eq!(store.hold("hash", "b", 2000).unwrap(), (false, 31));
        store.mark_clean("new", 9999).unwrap();
        store.hold("new", "a", 100).unwrap();
        assert!(!store.hold("new", "b", 100).unwrap().0);
    }
    #[test]
    fn campaign_counts_cross_tenants_without_retry_inflation() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("db"), OutbreakConfig::default()).unwrap();
        let content = content();
        let one = message("one", "a", "alice");
        assert_eq!(store.observe(&one, &content, 100).unwrap().messages, 1);
        assert_eq!(store.observe(&one, &content, 120).unwrap().messages, 1);
        let result = store
            .observe(&message("two", "b", "bob"), &content, 130)
            .unwrap();
        assert_eq!((result.messages, result.tenants, result.senders), (2, 2, 2));
        let result = store
            .observe(&message("two", "c", "bob"), &content, 130)
            .unwrap();
        assert_eq!((result.messages, result.tenants, result.senders), (2, 3, 2));
        assert_eq!(
            store
                .observe(&message("three", "a", "alice"), &content, 4000)
                .unwrap()
                .messages,
            1
        );
    }
    #[test]
    fn similar_body_and_attachments_cluster_in_buckets() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("db"), OutbreakConfig::default()).unwrap();
        let base="Please review invoice for our recent services and contact your account manager for questions about payment terms. ".repeat(10);
        let digest = similarity::digest(base.as_bytes()).unwrap();
        let one = Content {
            features: vec![Feature {
                kind: "attachment".into(),
                value: "one".into(),
                content_type: "text/plain".into(),
                digest: Some(digest),
            }],
        };
        store
            .observe(&message("one", "a", "alice"), &one, 100)
            .unwrap();
        let digest = similarity::digest(base.replace("recent", "current").as_bytes()).unwrap();
        let two = Content {
            features: vec![Feature {
                kind: "attachment".into(),
                value: "two".into(),
                content_type: "text/plain".into(),
                digest: Some(digest),
            }],
        };
        assert_eq!(
            store
                .observe(&message("two", "b", "bob"), &two, 101)
                .unwrap()
                .messages,
            2
        );
    }
    #[test]
    fn retention_purge_disk_bounds_and_disabled_default() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db");
        let bytes = b"benign retained marker";
        let hash = hex::encode(Sha256::digest(bytes));
        let disabled = Store::open(&path, OutbreakConfig::default()).unwrap();
        assert!(!disabled.retain(&hash, bytes, 100).unwrap());
        drop(disabled);
        let cfg = OutbreakConfig {
            retention_days: 1,
            retain_parts_hours: 1,
            max_part_bytes: 30,
            max_retained_bytes: 30,
            ..Default::default()
        };
        let store = Store::open(&path, cfg).unwrap();
        let msg = message("one", "a", "alice");
        let content = Content {
            features: vec![Feature {
                kind: "sha256".into(),
                value: hash.clone(),
                content_type: "text/plain".into(),
                digest: None,
            }],
        };
        store.observe(&msg, &content, 100).unwrap();
        store.retain(&hash, bytes, 100).unwrap();
        assert!(store.retained_page("", 101).unwrap().is_empty());
        store.deliver("one", &msg, 100).unwrap();
        assert_eq!(store.retained_page("", 101).unwrap().len(), 1);
        assert!(store.retain(&hash, bytes, 101).unwrap()); // existing blob uses no extra quota
        let other = b"another benign retained marker";
        let other_hash = hex::encode(Sha256::digest(other));
        assert!(!store.retain(&other_hash, other, 100).unwrap());
        assert!(store.retain(&"b".repeat(64), b"bad hash", 100).is_err());
        store.hold("held", "a", 100).unwrap();
        store.purge(3701).unwrap();
        assert!(store.retained_page("", 3701).unwrap().is_empty());
        store.purge(90000).unwrap();
        assert!(store.indicator_page(0).unwrap().is_empty());
        assert_eq!(store.hold("held", "a", 90000).unwrap(), (true, 0));
    }
    #[test]
    fn failed_remediation_remains_pending() {
        struct Fails;
        impl Remediation for Fails {
            fn remediate(&self, _: &Detection) -> Result<(), String> {
                Err("offline adapter".into())
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("db"), OutbreakConfig::default()).unwrap();
        let msg = message("one", "a", "alice");
        store.observe(&msg, &content(), 100).unwrap();
        store.deliver("one", &msg, 100).unwrap();
        store.detect("sha256", &"a".repeat(64), "feed").unwrap();
        assert!(store.notify(&Fails, |_| panic!("not accepted")).is_err());
        let calls = Calls(AtomicUsize::new(0));
        assert_eq!(store.notify(&calls, |_| {}).unwrap(), 1);
    }
    #[test]
    fn cardinality_eviction_and_schema_guard() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db");
        let store = Store::open(
            &path,
            OutbreakConfig {
                max_messages: 1,
                ..Default::default()
            },
        )
        .unwrap();
        store
            .observe(&message("one", "a", "alice"), &content(), 100)
            .unwrap();
        store
            .observe(&message("two", "a", "alice"), &content(), 101)
            .unwrap();
        let conn = store.conn.lock().unwrap();
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM messages", [], |r| r.get::<_, u64>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM features", [], |r| r.get::<_, u64>(0))
                .unwrap(),
            2
        );
        conn.pragma_update(None, "user_version", 2).unwrap();
        drop(conn);
        drop(store);
        assert!(Store::open(&path, OutbreakConfig::default()).is_err());
    }

    #[test]
    fn ordinary_body_hash_is_indexed_but_does_not_link_unrelated_mail() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("db"), OutbreakConfig::default()).unwrap();
        let content = Content {
            features: vec![Feature {
                kind: "body_sha256".into(),
                value: "a".repeat(64),
                content_type: "text/plain".into(),
                digest: None,
            }],
        };
        let one = message("one", "a", "alice");
        store.observe(&one, &content, 100).unwrap();
        store.deliver("one", &one, 100).unwrap();
        let result = store
            .observe(&message("two", "b", "bob"), &content, 101)
            .unwrap();
        assert_eq!((result.messages, result.tenants, result.senders), (1, 1, 1));
        assert_eq!(store.indicator_page(0).unwrap()[0].1, "sha256");
        store.detect("sha256", &"a".repeat(64), "test").unwrap();
        assert_eq!(
            store.notify(&Calls(AtomicUsize::new(0)), |_| {}).unwrap(),
            1
        );
    }

    #[test]
    fn hot_bucket_is_bounded_and_counts_include_current_message() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("db"), OutbreakConfig::default()).unwrap();
        {
            let mut conn = store.conn.lock().unwrap();
            let tx = conn.transaction().unwrap();
            for i in 0..4100 {
                let id = i.to_string();
                tx.execute(
                    "INSERT INTO messages VALUES(?1,'tenant','inbound','sender','[]',100,NULL,?1)",
                    [&id],
                )
                .unwrap();
                tx.execute(
                    "INSERT INTO features VALUES(?1,'tenant','sha256',?2,'text/plain',NULL,100,0)",
                    params![id, "a".repeat(64)],
                )
                .unwrap();
            }
            tx.commit().unwrap();
        }
        let result = store
            .observe(
                &message("current", "new-tenant", "new-sender"),
                &content(),
                101,
            )
            .unwrap();
        assert!(result.truncated);
        assert!(result.messages <= 4097);
        assert_eq!(result.tenants, 2);
        assert_eq!(result.senders, 2);
    }
}
