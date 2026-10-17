//! Greylisting on (network, sender, recipient). A delivered message that
//! passed aligned DMARC records (sender domain, network), so later mail for
//! that domain from that network skips the delay. A forged MAIL FROM from
//! another network gains nothing.
use super::{net_key, CheckResult, ConnCtx, ConnectionCheck, RcptCtx};
use async_trait::async_trait;
use rusqlite::{Connection, OptionalExtension};
use sha2::{Digest, Sha256};
use std::{
    net::IpAddr,
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};

/// New triplets from one network that may wait at once. Past this the
/// oldest waiting triplet from that network is dropped for each new one.
const MAX_PENDING_PER_NET: i64 = 1_000;
/// A triplet that never retried is forgotten after a day.
const PENDING_TTL_SECS: i64 = 86_400;
/// Passed triplets and DMARC passes are forgotten after 36 idle days.
const PASSED_TTL_SECS: i64 = 36 * 86_400;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GreylistDecision {
    Pass,
    Delay,
}

#[derive(Clone)]
pub struct GreylistCheck {
    conn: Arc<Mutex<Connection>>,
    delay: Duration,
    now: Arc<dyn Fn() -> i64 + Send + Sync>,
}

impl GreylistCheck {
    pub fn open(path: &Path, delay_secs: u64) -> Result<Self, String> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|err| err.to_string())?;
            }
        }
        let conn = Connection::open(path).map_err(|err| err.to_string())?;
        conn.busy_timeout(Duration::from_secs(5))
            .map_err(|err| err.to_string())?;
        // Losing the last few greylist rows in a crash costs one more delay,
        // so an fsync per RCPT is not worth paying.
        conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;")
            .map_err(|err| err.to_string())?;
        migrate(&conn).map_err(|err| err.to_string())?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS greylist (
                triplet_hash TEXT PRIMARY KEY,
                net TEXT NOT NULL,
                first_seen INTEGER NOT NULL,
                last_seen INTEGER NOT NULL,
                passed INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS greylist_net ON greylist (net, passed);
            CREATE TABLE IF NOT EXISTS dmarc_pass (
                sender_domain TEXT NOT NULL,
                net TEXT NOT NULL,
                allowed_at INTEGER NOT NULL,
                PRIMARY KEY (sender_domain, net)
            );
            DROP TABLE IF EXISTS dmarc_allow;",
        )
        .map_err(|err| err.to_string())?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            delay: Duration::from_secs(delay_secs),
            now: Arc::new(|| time::OffsetDateTime::now_utc().unix_timestamp()),
        })
    }

    pub fn with_clock(mut self, now: Arc<dyn Fn() -> i64 + Send + Sync>) -> Self {
        self.now = now;
        self
    }

    pub fn decide(
        &self,
        ip: IpAddr,
        sender: &str,
        recipient: &str,
    ) -> Result<GreylistDecision, String> {
        let now = (self.now)();
        let net = net_key(ip);
        let sender_domain = sender.rsplit_once('@').map(|(_, d)| d.to_ascii_lowercase());
        let key = triplet(&net, sender, recipient);
        let conn = self.conn.lock().map_err(|_| "greylist lock poisoned")?;
        let sql = |err: rusqlite::Error| err.to_string();
        if let Some(domain) = &sender_domain {
            let allowed: Option<i64> = conn
                .query_row(
                    "SELECT allowed_at FROM dmarc_pass WHERE sender_domain = ?1 AND net = ?2",
                    rusqlite::params![domain, net],
                    |row| row.get(0),
                )
                .optional()
                .map_err(sql)?;
            if allowed.is_some_and(|at| now.saturating_sub(at) < PASSED_TTL_SECS) {
                return Ok(GreylistDecision::Pass);
            }
        }
        let row: Option<(i64, i64)> = conn
            .query_row(
                "SELECT first_seen, passed FROM greylist WHERE triplet_hash = ?1",
                [&key],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(sql)?;
        match row {
            None => {
                let pending: i64 = conn
                    .query_row(
                        "SELECT COUNT(*) FROM greylist WHERE net = ?1 AND passed = 0",
                        [&net],
                        |row| row.get(0),
                    )
                    .map_err(sql)?;
                // A busy network keeps its newest waiting triplets: the oldest
                // are dropped, so a flood cannot lock out a real retry for good.
                if pending >= MAX_PENDING_PER_NET {
                    conn.execute(
                        "DELETE FROM greylist WHERE triplet_hash IN (
                            SELECT triplet_hash FROM greylist WHERE net = ?1 AND passed = 0
                            ORDER BY first_seen, rowid LIMIT ?2)",
                        rusqlite::params![net, pending - MAX_PENDING_PER_NET + 1],
                    )
                    .map_err(sql)?;
                }
                conn.execute(
                    "INSERT INTO greylist (triplet_hash, net, first_seen, last_seen, passed)
                     VALUES (?1, ?2, ?3, ?3, 0)",
                    rusqlite::params![key, net, now],
                )
                .map_err(sql)?;
                Ok(GreylistDecision::Delay)
            }
            Some((first_seen, passed))
                if passed != 0 || now.saturating_sub(first_seen) >= self.delay.as_secs() as i64 =>
            {
                conn.execute(
                    "UPDATE greylist SET passed = 1, last_seen = ?2 WHERE triplet_hash = ?1",
                    rusqlite::params![key, now],
                )
                .map_err(sql)?;
                Ok(GreylistDecision::Pass)
            }
            Some(_) => Ok(GreylistDecision::Delay),
        }
    }

    /// Record an aligned DMARC pass for `sender_domain` from the network of `ip`.
    pub fn allow_aligned_dmarc(&self, sender_domain: &str, ip: IpAddr) -> Result<(), String> {
        let domain = sender_domain.to_ascii_lowercase();
        let now = (self.now)();
        let conn = self.conn.lock().map_err(|_| "greylist lock poisoned")?;
        conn.execute(
            "INSERT INTO dmarc_pass (sender_domain, net, allowed_at) VALUES (?1, ?2, ?3)
             ON CONFLICT(sender_domain, net) DO UPDATE SET allowed_at = excluded.allowed_at",
            rusqlite::params![domain, net_key(ip), now],
        )
        .map_err(|err| err.to_string())?;
        Ok(())
    }

    /// Delete stale triplets and DMARC passes. Returns the rows removed.
    pub fn expire(&self) -> Result<usize, String> {
        let now = (self.now)();
        let conn = self.conn.lock().map_err(|_| "greylist lock poisoned")?;
        let mut removed = conn
            .execute(
                "DELETE FROM greylist
                 WHERE (passed = 0 AND last_seen < ?1) OR (passed != 0 AND last_seen < ?2)",
                rusqlite::params![now - PENDING_TTL_SECS, now - PASSED_TTL_SECS],
            )
            .map_err(|err| err.to_string())?;
        removed += conn
            .execute(
                "DELETE FROM dmarc_pass WHERE allowed_at < ?1",
                [now - PASSED_TTL_SECS],
            )
            .map_err(|err| err.to_string())?;
        Ok(removed)
    }
}

/// Tables from before the network columns hold triplets hashed differently,
/// so they cannot be converted. Drop them: the cost is one more delay.
fn migrate(conn: &Connection) -> rusqlite::Result<()> {
    let current: bool = conn
        .prepare("SELECT 1 FROM pragma_table_info('greylist') WHERE name = 'last_seen'")?
        .exists([])?;
    let exists: bool = conn
        .prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'greylist'")?
        .exists([])?;
    if exists && !current {
        tracing::warn!("replacing greylist table from an older schema");
        conn.execute_batch("DROP INDEX IF EXISTS greylist_net; DROP TABLE greylist;")?;
    }
    Ok(())
}

fn triplet(net: &str, sender: &str, recipient: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(net.as_bytes());
    hasher.update(b"|");
    hasher.update(sender.trim().to_ascii_lowercase().as_bytes());
    hasher.update(b"|");
    hasher.update(recipient.trim().to_ascii_lowercase().as_bytes());
    hex::encode(hasher.finalize())
}

#[async_trait]
impl ConnectionCheck for GreylistCheck {
    async fn on_connect(&self, _ctx: &ConnCtx) -> CheckResult {
        CheckResult::Pass
    }

    async fn on_rcpt(&self, ctx: &RcptCtx) -> CheckResult {
        let this = self.clone();
        let ctx = ctx.clone();
        let decision = tokio::task::spawn_blocking(move || {
            this.decide(ctx.ip, &ctx.mail_from, &ctx.recipient)
        })
        .await
        .map_err(|err| err.to_string())
        .and_then(|result| result);
        match decision {
            Ok(GreylistDecision::Pass) => CheckResult::Pass,
            Ok(GreylistDecision::Delay) => {
                CheckResult::TempFail("451 4.7.1 greylisted, try again later".into())
            }
            Err(err) => {
                // The database error stays in the log, not in the reply.
                tracing::warn!(%err, "greylist unavailable");
                CheckResult::TempFail("451 4.3.0 temporary local problem, try again later".into())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicI64, Ordering};

    fn clocked(dir: &Path) -> (GreylistCheck, Arc<AtomicI64>) {
        let clock = Arc::new(AtomicI64::new(1_000_000));
        let reader = Arc::clone(&clock);
        let check = GreylistCheck::open(&dir.join("grey.sqlite"), 300)
            .unwrap()
            .with_clock(Arc::new(move || reader.load(Ordering::SeqCst)));
        (check, clock)
    }

    #[test]
    fn dmarc_pass_is_per_network_and_rows_expire() {
        let dir = tempfile::tempdir().unwrap();
        let (check, clock) = clocked(dir.path());
        let home: IpAddr = "198.51.100.7".parse().unwrap();
        let forger: IpAddr = "203.0.113.66".parse().unwrap();
        check.allow_aligned_dmarc("bigcorp.test", home).unwrap();
        assert_eq!(
            check
                .decide(home, "ceo@bigcorp.test", "a@example.test")
                .unwrap(),
            GreylistDecision::Pass
        );
        assert_eq!(
            check
                .decide(forger, "ceo@bigcorp.test", "a@example.test")
                .unwrap(),
            GreylistDecision::Delay,
            "a forged MAIL FROM from another network must still be greylisted"
        );
        clock.fetch_add(PASSED_TTL_SECS + 1, Ordering::SeqCst);
        assert!(check.expire().unwrap() >= 2);
        assert_eq!(
            check
                .decide(home, "ceo@bigcorp.test", "a@example.test")
                .unwrap(),
            GreylistDecision::Delay
        );
    }

    #[test]
    fn pending_rows_are_capped_by_evicting_the_oldest() {
        let dir = tempfile::tempdir().unwrap();
        let (check, clock) = clocked(dir.path());
        let ip: IpAddr = "203.0.113.5".parse().unwrap();
        for n in 0..MAX_PENDING_PER_NET + 50 {
            clock.fetch_add(1, Ordering::SeqCst);
            check
                .decide(ip, &format!("s{n}@spam.test"), "a@example.test")
                .unwrap();
        }
        // The legitimate sender arrives during the flood and retries later.
        check
            .decide(ip, "real@sender.test", "a@example.test")
            .unwrap();
        {
            let conn = check.conn.lock().unwrap();
            let rows: i64 = conn
                .query_row("SELECT COUNT(*) FROM greylist", [], |row| row.get(0))
                .unwrap();
            assert_eq!(rows, MAX_PENDING_PER_NET);
        }
        clock.fetch_add(301, Ordering::SeqCst);
        assert_eq!(
            check
                .decide(ip, "real@sender.test", "a@example.test")
                .unwrap(),
            GreylistDecision::Pass,
            "a new triplet must still be recorded when the network is full"
        );
    }

    #[test]
    fn an_old_schema_is_replaced_instead_of_failing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("grey.sqlite");
        Connection::open(&path)
            .unwrap()
            .execute_batch(
                "CREATE TABLE greylist (triplet_hash TEXT PRIMARY KEY, first_seen INTEGER NOT NULL, passed INTEGER NOT NULL);
                 INSERT INTO greylist VALUES ('abc', 1, 1);
                 CREATE TABLE dmarc_allow (sender_domain TEXT PRIMARY KEY, allowed_at INTEGER NOT NULL);",
            )
            .unwrap();
        let check = GreylistCheck::open(&path, 300).unwrap();
        assert_eq!(
            check
                .decide("203.0.113.5".parse().unwrap(), "a@b.test", "c@example.test")
                .unwrap(),
            GreylistDecision::Delay
        );
        // Reopening the new schema keeps its rows.
        drop(check);
        let check = GreylistCheck::open(&path, 0).unwrap();
        assert_eq!(
            check
                .decide("203.0.113.5".parse().unwrap(), "a@b.test", "c@example.test")
                .unwrap(),
            GreylistDecision::Pass
        );
    }

    #[tokio::test]
    async fn database_errors_are_not_sent_to_the_client() {
        let dir = tempfile::tempdir().unwrap();
        let (check, _) = clocked(dir.path());
        check
            .conn
            .lock()
            .unwrap()
            .execute_batch("DROP TABLE greylist")
            .unwrap();
        let result = check
            .on_rcpt(&RcptCtx {
                ip: "203.0.113.5".parse().unwrap(),
                mail_from: "a@b.test".into(),
                recipient: "c@example.test".into(),
            })
            .await;
        match result {
            CheckResult::TempFail(line) => {
                assert!(line.starts_with("451 4.3.0"), "{line}");
                assert!(!line.contains("greylist"), "{line}");
                assert!(!line.to_ascii_lowercase().contains("table"), "{line}");
            }
            other => panic!("unexpected {other:?}"),
        }
    }
}
