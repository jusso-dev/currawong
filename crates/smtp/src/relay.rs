//! Trusted networks and SMTP AUTH credentials for outbound relay.
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use currawong_core::config::TenantConfig;
use dashmap::DashMap;
use ipnet::IpNet;
use rusqlite::{params, Connection, OptionalExtension};
use std::{
    net::IpAddr,
    path::Path,
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};

/// Failed AUTH attempts one address may make inside `FAILURE_WINDOW`.
const MAX_FAILURES_PER_IP: u32 = 10;
const FAILURE_WINDOW: Duration = Duration::from_secs(15 * 60);
/// Above this many tracked addresses, expired failure windows are swept.
const MAX_TRACKED_IPS: usize = 10_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthContext {
    pub tenant_id: String,
    pub principal: String,
    /// MAIL FROM addresses this SMTP AUTH login may use, lower case. `None`
    /// for a trusted network, which may send as any address in the tenant's
    /// domains.
    pub senders: Option<Vec<String>>,
}

#[derive(Debug, Clone)]
pub struct Tenant {
    pub id: String,
    pub domains: Vec<String>,
    pub cidrs: Vec<IpNet>,
}

pub struct Relay {
    tenants: Vec<Tenant>,
    conn: Option<Mutex<Connection>>,
    failures: DashMap<IpAddr, (u32, Instant)>,
}

impl Relay {
    pub fn open(database: &Path, tenants: &[TenantConfig]) -> Result<Self, String> {
        let tenants = tenants
            .iter()
            .map(|tenant| {
                let cidrs = tenant
                    .trusted_cidrs
                    .iter()
                    .map(|cidr| {
                        cidr.parse::<IpNet>()
                            .map_err(|err| format!("{cidr}: {err}"))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(Tenant {
                    id: tenant.id.clone(),
                    domains: tenant
                        .domains
                        .iter()
                        .map(|domain| domain.to_ascii_lowercase())
                        .collect(),
                    cidrs,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        if let Some(parent) = database.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|err| err.to_string())?;
            }
        }
        let conn = Connection::open(database).map_err(|err| err.to_string())?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS relay_credentials (
                id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                username TEXT NOT NULL UNIQUE,
                argon2_hash TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS relay_addresses (
                username TEXT NOT NULL,
                address TEXT NOT NULL,
                PRIMARY KEY (username, address)
            );",
        )
        .map_err(|err| err.to_string())?;
        Ok(Self {
            tenants,
            conn: Some(Mutex::new(conn)),
            failures: DashMap::new(),
        })
    }

    pub fn empty() -> Self {
        Self {
            tenants: Vec::new(),
            conn: None,
            failures: DashMap::new(),
        }
    }

    pub fn tenant_for_ip(&self, ip: IpAddr) -> Option<&Tenant> {
        let ip = ip.to_canonical();
        self.tenants
            .iter()
            .filter(|tenant| tenant.cidrs.iter().any(|net| net.contains(&ip)))
            .max_by_key(|tenant| {
                tenant
                    .cidrs
                    .iter()
                    .filter(|net| net.contains(&ip))
                    .map(|net| net.prefix_len())
                    .max()
                    .unwrap_or(0)
            })
    }

    pub fn owns_domain(&self, tenant_id: &str, domain: &str) -> bool {
        let domain = domain.to_ascii_lowercase();
        self.tenants.iter().any(|tenant| {
            tenant.id == tenant_id
                && tenant
                    .domains
                    .iter()
                    .any(|owned| owned.eq_ignore_ascii_case(&domain))
        })
    }

    pub fn upsert_credential(
        &self,
        tenant_id: &str,
        username: &str,
        password: &str,
    ) -> Result<(), String> {
        let salt = SaltString::generate(&mut OsRng);
        let hash = Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .map_err(|err| err.to_string())?
            .to_string();
        let id = format!("{tenant_id}:{username}");
        self.with_conn(|conn| {
            conn.execute(
                "INSERT INTO relay_credentials (id, tenant_id, username, argon2_hash)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(id) DO UPDATE SET argon2_hash = excluded.argon2_hash",
                params![id, tenant_id, username, hash],
            )
            .map_err(|err| err.to_string())?;
            Ok(())
        })
    }

    /// Let `username` send as `address` as well as its own login address.
    pub fn add_sender_address(&self, username: &str, address: &str) -> Result<(), String> {
        self.with_conn(|conn| {
            conn.execute(
                "INSERT OR IGNORE INTO relay_addresses (username, address) VALUES (?1, ?2)",
                params![username, address.to_ascii_lowercase()],
            )
            .map_err(|err| err.to_string())?;
            Ok(())
        })
    }

    /// The login itself when it is an address, plus listed aliases.
    fn sender_addresses(&self, username: &str) -> Result<Vec<String>, String> {
        let mut out = Vec::new();
        if username.contains('@') {
            out.push(username.to_ascii_lowercase());
        }
        self.with_conn(|conn| {
            let mut stmt = conn
                .prepare("SELECT address FROM relay_addresses WHERE username = ?1")
                .map_err(|err| err.to_string())?;
            let rows = stmt
                .query_map(params![username], |row| row.get::<_, String>(0))
                .map_err(|err| err.to_string())?;
            for row in rows {
                out.push(row.map_err(|err| err.to_string())?);
            }
            Ok(())
        })?;
        Ok(out)
    }

    /// Check a username and password. This is blocking (SQLite and Argon2),
    /// so async callers run it on a blocking thread. Unknown users are
    /// verified against a dummy hash so they take as long as a wrong password.
    pub fn authenticate(
        &self,
        username: &str,
        password: &str,
    ) -> Result<Option<AuthContext>, String> {
        if self.conn.is_none() {
            return Ok(None);
        }
        let row: Option<(String, String)> = self.with_conn(|conn| {
            conn.query_row(
                "SELECT tenant_id, argon2_hash FROM relay_credentials WHERE username = ?1",
                params![username],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|err| err.to_string())
        })?;
        let (tenant_id, hash) = match row {
            Some((tenant_id, hash)) => (Some(tenant_id), hash),
            None => (None, dummy_hash().to_string()),
        };
        let parsed = PasswordHash::new(&hash).map_err(|err| err.to_string())?;
        let verified = Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok();
        Ok(match tenant_id {
            Some(tenant_id) if verified => Some(AuthContext {
                tenant_id,
                principal: username.to_string(),
                senders: Some(self.sender_addresses(username)?),
            }),
            _ => None,
        })
    }

    /// True when `ip` has used up its failed AUTH attempts for now.
    pub fn auth_locked(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        self.failures.get(&ip).is_some_and(|entry| {
            entry.1.elapsed() < FAILURE_WINDOW && entry.0 >= MAX_FAILURES_PER_IP
        })
    }

    pub fn record_auth_failure(&self, ip: IpAddr) {
        let ip = ip.to_canonical();
        if self.failures.len() >= MAX_TRACKED_IPS {
            self.failures
                .retain(|_, entry| entry.1.elapsed() < FAILURE_WINDOW);
        }
        let mut entry = self.failures.entry(ip).or_insert((0, Instant::now()));
        if entry.1.elapsed() >= FAILURE_WINDOW {
            *entry = (0, Instant::now());
        }
        entry.0 = entry.0.saturating_add(1);
    }

    fn with_conn<T>(&self, f: impl FnOnce(&Connection) -> Result<T, String>) -> Result<T, String> {
        let conn = self
            .conn
            .as_ref()
            .ok_or_else(|| "relay database is not configured".to_string())?;
        let conn = conn.lock().map_err(|_| "relay database lock poisoned")?;
        f(&conn)
    }
}

/// A valid hash of a random password, so unknown users cost one Argon2 verify.
fn dummy_hash() -> &'static str {
    static DUMMY: OnceLock<String> = OnceLock::new();
    DUMMY.get_or_init(|| {
        let salt = SaltString::generate(&mut OsRng);
        let mut password = [0u8; 32];
        argon2::password_hash::rand_core::RngCore::fill_bytes(&mut OsRng, &mut password);
        Argon2::default()
            .hash_password(&password, &salt)
            .map(|hash| hash.to_string())
            .expect("argon2 hashes a random password")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failures_lock_an_address() {
        let relay = Relay::empty();
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        let mapped: IpAddr = "::ffff:203.0.113.9".parse().unwrap();
        for _ in 0..MAX_FAILURES_PER_IP {
            assert!(!relay.auth_locked(ip));
            relay.record_auth_failure(mapped);
        }
        assert!(relay.auth_locked(ip));
        assert!(!relay.auth_locked("203.0.113.10".parse().unwrap()));
    }

    #[test]
    fn unknown_user_still_runs_a_verify() {
        let dir = tempfile::tempdir().unwrap();
        let relay = Relay::open(&dir.path().join("relay.sqlite"), &[]).unwrap();
        relay.upsert_credential("ten", "ada", "right").unwrap();
        assert!(relay.authenticate("nobody", "right").unwrap().is_none());
        assert!(dummy_hash().starts_with("$argon2"));
        assert_eq!(
            relay
                .authenticate("ada", "right")
                .unwrap()
                .unwrap()
                .tenant_id,
            "ten"
        );
        assert!(relay.authenticate("ada", "wrong").unwrap().is_none());
    }
}
