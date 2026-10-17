//! Greylisting on (network, sender, recipient). Senders that later pass
//! aligned DMARC are recorded so the triplet is skipped next time.
use super::{CheckResult, ConnCtx, ConnectionCheck, RcptCtx};
use async_trait::async_trait;
use rusqlite::Connection;
use sha2::{Digest, Sha256};
use std::{
    net::IpAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GreylistDecision {
    Pass,
    Delay,
}

pub struct GreylistCheck {
    db: PathBuf,
    delay: Duration,
    now: Arc<dyn Fn() -> i64 + Send + Sync>,
}

impl GreylistCheck {
    pub fn open(path: &Path, delay_secs: u64) -> Result<Self, String> {
        let check = Self {
            db: path.to_path_buf(),
            delay: Duration::from_secs(delay_secs),
            now: Arc::new(|| time::OffsetDateTime::now_utc().unix_timestamp()),
        };
        check.with_conn(|_| Ok(()))?;
        Ok(check)
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
        let sender_domain = sender.rsplit_once('@').map(|(_, d)| d.to_ascii_lowercase());
        let key = triplet(ip, sender, recipient);
        self.with_conn(|conn| {
            if let Some(domain) = &sender_domain {
                let allowed: i64 = conn
                    .query_row(
                        "SELECT COUNT(*) FROM dmarc_allow WHERE sender_domain = ?1",
                        [domain],
                        |row| row.get(0),
                    )
                    .unwrap_or(0);
                if allowed > 0 {
                    return Ok(GreylistDecision::Pass);
                }
            }
            let row: Option<(i64, i64)> = conn
                .query_row(
                    "SELECT first_seen, passed FROM greylist WHERE triplet_hash = ?1",
                    [&key],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .ok();
            match row {
                None => {
                    conn.execute(
                        "INSERT INTO greylist (triplet_hash, first_seen, passed) VALUES (?1, ?2, 0)",
                        rusqlite::params![key, now],
                    )
                    .map_err(|err| err.to_string())?;
                    Ok(GreylistDecision::Delay)
                }
                Some((_, passed)) if passed != 0 => Ok(GreylistDecision::Pass),
                Some((first_seen, _)) if now.saturating_sub(first_seen) >= self.delay.as_secs() as i64 => {
                    conn.execute(
                        "UPDATE greylist SET passed = 1 WHERE triplet_hash = ?1",
                        [&key],
                    )
                    .map_err(|err| err.to_string())?;
                    Ok(GreylistDecision::Pass)
                }
                Some(_) => Ok(GreylistDecision::Delay),
            }
        })
    }

    pub fn allow_aligned_dmarc(&self, sender_domain: &str) -> Result<(), String> {
        let domain = sender_domain.to_ascii_lowercase();
        let now = (self.now)();
        self.with_conn(|conn| {
            conn.execute(
                "INSERT INTO dmarc_allow (sender_domain, allowed_at) VALUES (?1, ?2)
                 ON CONFLICT(sender_domain) DO UPDATE SET allowed_at = excluded.allowed_at",
                rusqlite::params![domain, now],
            )
            .map_err(|err| err.to_string())?;
            Ok(())
        })
    }

    fn with_conn<T>(&self, f: impl FnOnce(&Connection) -> Result<T, String>) -> Result<T, String> {
        if let Some(parent) = self.db.parent() {
            std::fs::create_dir_all(parent).map_err(|err| err.to_string())?;
        }
        let conn = Connection::open(&self.db).map_err(|err| err.to_string())?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS greylist (
                triplet_hash TEXT PRIMARY KEY,
                first_seen INTEGER NOT NULL,
                passed INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS dmarc_allow (
                sender_domain TEXT PRIMARY KEY,
                allowed_at INTEGER NOT NULL
            );",
        )
        .map_err(|err| err.to_string())?;
        f(&conn)
    }
}

fn triplet(ip: IpAddr, sender: &str, recipient: &str) -> String {
    let prefix = match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.0", o[0], o[1], o[2])
        }
        IpAddr::V6(v6) => format!(
            "{:x}:{:x}:{:x}:{:x}::/64",
            u16::from_be_bytes([v6.octets()[0], v6.octets()[1]]),
            u16::from_be_bytes([v6.octets()[2], v6.octets()[3]]),
            u16::from_be_bytes([v6.octets()[4], v6.octets()[5]]),
            u16::from_be_bytes([v6.octets()[6], v6.octets()[7]])
        ),
    };
    let mut hasher = Sha256::new();
    hasher.update(prefix.as_bytes());
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
        match self.decide(ctx.ip, &ctx.mail_from, &ctx.recipient) {
            Ok(GreylistDecision::Pass) => CheckResult::Pass,
            Ok(GreylistDecision::Delay) => {
                CheckResult::TempFail("451 4.7.1 greylisted, try again later".into())
            }
            Err(err) => CheckResult::TempFail(format!("451 4.3.0 greylist unavailable: {err}")),
        }
    }
}
