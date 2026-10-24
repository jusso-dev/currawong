//! SQLite indicator store. Syncs write through one connection and lookups
//! read through another (WAL), so a large feed replace does not hold up
//! mail. Each feed's rows are replaced in one transaction: a lookup sees the
//! old set or the new one, never half of each.
use crate::{Indicator, Kind};
use currawong_core::IntelHit;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use std::{path::Path, sync::Mutex};

/// Applied in order. `PRAGMA user_version` records how many have run.
const MIGRATIONS: &[&str] = &[include_str!("../migrations/0001_indicators.sql")];

/// Sync state of one feed. Times are Unix seconds.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FeedStatus {
    pub source: String,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    pub last_attempt: Option<i64>,
    pub last_success: Option<i64>,
    pub last_error: Option<String>,
    pub indicators: i64,
}

pub struct Store {
    writer: Mutex<Connection>,
    reader: Mutex<Connection>,
    /// Rows of a feed whose last good sync is older than this stop matching.
    expire_after_secs: i64,
}

fn db(err: impl std::fmt::Display) -> String {
    format!("intel store: {err}")
}

impl Store {
    /// Open or create the store, creating its directory.
    pub fn open(path: &Path, expire_after_secs: i64) -> Result<Self, String> {
        if let Some(dir) = path.parent().filter(|dir| !dir.as_os_str().is_empty()) {
            std::fs::create_dir_all(dir).map_err(|err| db(format!("{}: {err}", dir.display())))?;
        }
        let writer = Connection::open(path).map_err(db)?;
        writer
            .pragma_update(None, "journal_mode", "WAL")
            .map_err(db)?;
        writer
            .pragma_update(None, "synchronous", "NORMAL")
            .map_err(db)?;
        writer
            .busy_timeout(std::time::Duration::from_secs(10))
            .map_err(db)?;
        let done: usize = writer
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .map_err(db)?;
        if done > MIGRATIONS.len() {
            return Err(db(format!(
                "schema version {done} is newer than this build ({})",
                MIGRATIONS.len()
            )));
        }
        for (index, sql) in MIGRATIONS.iter().enumerate().skip(done) {
            writer.execute_batch(sql).map_err(db)?;
            writer
                .pragma_update(None, "user_version", index + 1)
                .map_err(db)?;
        }
        let reader = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(db)?;
        reader
            .busy_timeout(std::time::Duration::from_secs(5))
            .map_err(db)?;
        Ok(Self {
            writer: Mutex::new(writer),
            reader: Mutex::new(reader),
            expire_after_secs: expire_after_secs.max(1),
        })
    }

    /// Replace every indicator of `source` with `indicators`, keeping the
    /// first-seen time of those already known. Returns the stored count.
    pub fn replace_source(
        &self,
        source: &str,
        indicators: &[Indicator],
        now: i64,
        etag: Option<&str>,
        last_modified: Option<&str>,
    ) -> Result<usize, String> {
        let mut conn = self.writer.lock().unwrap_or_else(|p| p.into_inner());
        let tx = conn.transaction().map_err(db)?;
        tx.execute(
            "INSERT INTO feeds (source) VALUES (?1) ON CONFLICT (source) DO NOTHING",
            params![source],
        )
        .map_err(db)?;
        let sync_id: i64 = tx
            .query_row(
                "UPDATE feeds SET sync_id = sync_id + 1 WHERE source = ?1 RETURNING sync_id",
                params![source],
                |row| row.get(0),
            )
            .map_err(db)?;
        {
            let mut insert = tx
                .prepare_cached(
                    "INSERT INTO indicators
                        (kind, value, source, threat, first_seen, last_seen, expires, sync_id)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                     ON CONFLICT (kind, value, source) DO UPDATE SET
                        threat = excluded.threat, last_seen = excluded.last_seen,
                        expires = excluded.expires, sync_id = excluded.sync_id",
                )
                .map_err(db)?;
            for item in indicators {
                insert
                    .execute(params![
                        item.kind.as_str(),
                        item.value,
                        source,
                        item.threat,
                        item.first_seen.unwrap_or(now).min(now),
                        now,
                        item.expires,
                        sync_id
                    ])
                    .map_err(db)?;
            }
        }
        tx.execute(
            "DELETE FROM indicators WHERE source = ?1 AND sync_id != ?2",
            params![source, sync_id],
        )
        .map_err(db)?;
        let count: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM indicators WHERE source = ?1",
                params![source],
                |row| row.get(0),
            )
            .map_err(db)?;
        tx.execute(
            "UPDATE feeds SET etag = ?2, last_modified = ?3, last_attempt = ?4,
                last_success = ?4, last_error = NULL, indicators = ?5
             WHERE source = ?1",
            params![source, etag, last_modified, now, count],
        )
        .map_err(db)?;
        tx.commit().map_err(db)?;
        Ok(count as usize)
    }

    /// The feed answered 304 Not Modified: its data is current.
    pub fn record_not_modified(&self, source: &str, now: i64) -> Result<(), String> {
        let conn = self.writer.lock().unwrap_or_else(|p| p.into_inner());
        conn.execute(
            "UPDATE feeds SET last_attempt = ?2, last_success = ?2, last_error = NULL
             WHERE source = ?1",
            params![source, now],
        )
        .map_err(db)?;
        Ok(())
    }

    /// A failed sync. The previous indicators stay.
    pub fn record_failure(&self, source: &str, now: i64, error: &str) -> Result<(), String> {
        let conn = self.writer.lock().unwrap_or_else(|p| p.into_inner());
        conn.execute(
            "INSERT INTO feeds (source, last_attempt, last_error) VALUES (?1, ?2, ?3)
             ON CONFLICT (source) DO UPDATE SET last_attempt = ?2, last_error = ?3",
            params![source, now, error],
        )
        .map_err(db)?;
        Ok(())
    }

    /// Drop feeds no longer configured, and their indicators.
    pub fn retain_sources(&self, keep: &[&str]) -> Result<usize, String> {
        let mut conn = self.writer.lock().unwrap_or_else(|p| p.into_inner());
        let tx = conn.transaction().map_err(db)?;
        let stored: Vec<String> = {
            let mut stmt = tx.prepare("SELECT source FROM feeds").map_err(db)?;
            let rows = stmt.query_map([], |row| row.get(0)).map_err(db)?;
            rows.collect::<Result<_, _>>().map_err(db)?
        };
        let mut removed = 0;
        for source in stored.iter().filter(|s| !keep.contains(&s.as_str())) {
            removed += tx
                .execute("DELETE FROM indicators WHERE source = ?1", params![source])
                .map_err(db)?;
            tx.execute("DELETE FROM feeds WHERE source = ?1", params![source])
                .map_err(db)?;
        }
        tx.commit().map_err(db)?;
        Ok(removed)
    }

    pub fn status(&self, source: &str) -> Result<Option<FeedStatus>, String> {
        let conn = self.reader.lock().unwrap_or_else(|p| p.into_inner());
        conn.query_row(
            "SELECT source, etag, last_modified, last_attempt, last_success, last_error, indicators
             FROM feeds WHERE source = ?1",
            params![source],
            |row| {
                Ok(FeedStatus {
                    source: row.get(0)?,
                    etag: row.get(1)?,
                    last_modified: row.get(2)?,
                    last_attempt: row.get(3)?,
                    last_success: row.get(4)?,
                    last_error: row.get(5)?,
                    indicators: row.get(6)?,
                })
            },
        )
        .optional()
        .map_err(db)
    }

    /// Indicators matching any of `candidates` (already normalised), from
    /// feeds that synced recently enough and are still valid at `now`.
    pub fn lookup_many(
        &self,
        candidates: &[(Kind, String)],
        now: i64,
    ) -> Result<Vec<IntelHit>, String> {
        let conn = self.reader.lock().unwrap_or_else(|p| p.into_inner());
        let mut stmt = conn
            .prepare_cached(
                "SELECT i.source, i.threat FROM indicators i
                 JOIN feeds f ON f.source = i.source
                 WHERE i.kind = ?1 AND i.value = ?2
                   AND f.last_success >= ?3
                   AND (i.expires IS NULL OR i.expires > ?4)
                 ORDER BY i.source",
            )
            .map_err(db)?;
        let mut hits = Vec::new();
        for (kind, value) in candidates {
            let rows = stmt
                .query_map(
                    params![kind.as_str(), value, now - self.expire_after_secs, now],
                    |row| {
                        Ok(IntelHit {
                            kind: kind.as_str().to_string(),
                            value: value.clone(),
                            source: row.get(0)?,
                            threat: row.get(1)?,
                        })
                    },
                )
                .map_err(db)?;
            for hit in rows {
                hits.push(hit.map_err(db)?);
            }
        }
        Ok(hits)
    }

    pub fn lookup(&self, kind: Kind, value: &str, now: i64) -> Result<Vec<IntelHit>, String> {
        self.lookup_many(&[(kind, value.to_string())], now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn indicator(kind: Kind, value: &str) -> Indicator {
        Indicator {
            kind,
            value: value.into(),
            threat: "phishing".into(),
            first_seen: None,
            expires: None,
        }
    }

    #[test]
    fn intel_store_migrates_and_reopens() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub/intel.sqlite");
        let store = Store::open(&path, 3600).unwrap();
        store
            .replace_source(
                "feed",
                &[indicator(Kind::Domain, "evil.example")],
                100,
                None,
                None,
            )
            .unwrap();
        drop(store);
        let store = Store::open(&path, 3600).unwrap();
        let version: usize = store
            .reader
            .lock()
            .unwrap()
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, MIGRATIONS.len());
        assert_eq!(
            store
                .lookup(Kind::Domain, "evil.example", 100)
                .unwrap()
                .len(),
            1
        );
        // A database from a newer build is refused, not written over.
        store
            .writer
            .lock()
            .unwrap()
            .pragma_update(None, "user_version", 99)
            .unwrap();
        drop(store);
        assert!(Store::open(&path, 3600).err().unwrap().contains("newer"));
    }

    #[test]
    fn intel_store_replaces_one_source_atomically() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("intel.sqlite"), 3600).unwrap();
        let first = [
            indicator(Kind::Domain, "old.example"),
            indicator(Kind::Url, "https://keep.example/"),
        ];
        assert_eq!(
            store
                .replace_source("a", &first, 100, Some("\"v1\""), None)
                .unwrap(),
            2
        );
        store
            .replace_source(
                "b",
                &[indicator(Kind::Domain, "old.example")],
                100,
                None,
                None,
            )
            .unwrap();
        let second = [
            indicator(Kind::Url, "https://keep.example/"),
            indicator(Kind::Url, "https://keep.example/"),
            indicator(Kind::Sha256, &"a".repeat(64)),
        ];
        assert_eq!(
            store.replace_source("a", &second, 200, None, None).unwrap(),
            2
        );
        let hits = store.lookup(Kind::Domain, "old.example", 200).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].source, "b");
        assert_eq!(
            store.lookup(Kind::Sha256, &"a".repeat(64), 200).unwrap()[0].source,
            "a"
        );
        let first_seen: i64 = store
            .reader
            .lock()
            .unwrap()
            .query_row(
                "SELECT first_seen FROM indicators WHERE value = 'https://keep.example/'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(first_seen, 100);
        let status = store.status("a").unwrap().unwrap();
        assert_eq!((status.last_success, status.indicators), (Some(200), 2));
        assert_eq!(status.etag, None);
    }

    #[test]
    fn intel_store_expires_stale_feeds_and_invalid_indicators() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("intel.sqlite"), 1000).unwrap();
        let mut limited = indicator(Kind::Domain, "short.example");
        limited.expires = Some(150);
        store
            .replace_source(
                "a",
                &[indicator(Kind::Domain, "evil.example"), limited],
                100,
                None,
                None,
            )
            .unwrap();
        assert_eq!(
            store
                .lookup(Kind::Domain, "short.example", 120)
                .unwrap()
                .len(),
            1
        );
        assert!(store
            .lookup(Kind::Domain, "short.example", 151)
            .unwrap()
            .is_empty());
        // A failed sync keeps the data until the feed is too old to trust.
        store.record_failure("a", 900, "boom").unwrap();
        assert_eq!(
            store
                .lookup(Kind::Domain, "evil.example", 1100)
                .unwrap()
                .len(),
            1
        );
        assert!(store
            .lookup(Kind::Domain, "evil.example", 1101)
            .unwrap()
            .is_empty());
        store.record_not_modified("a", 1200).unwrap();
        assert_eq!(
            store
                .lookup(Kind::Domain, "evil.example", 1300)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(store.status("a").unwrap().unwrap().last_error, None);
        assert_eq!(store.retain_sources(&["b"]).unwrap(), 2);
        assert!(store.status("a").unwrap().is_none());
    }
}
