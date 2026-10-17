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
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex, OnceLock,
    },
    time::{Duration, Instant},
};

/// Failed AUTH attempts one source (an IPv4 address or an IPv6 /64) or one
/// username may make inside `FAILURE_WINDOW`.
const MAX_FAILURES: u32 = 10;
const FAILURE_WINDOW: Duration = Duration::from_secs(15 * 60);
/// Failure counters kept at once. When full, expired windows are swept at
/// most once a minute and new keys are not tracked until there is room.
const MAX_TRACKED: usize = 10_000;
const SWEEP_EVERY: Duration = Duration::from_secs(60);
/// Argon2 verifications in flight at once. Each needs about 19 MiB and a core.
pub const MAX_CONCURRENT_VERIFY: usize = 4;

/// Result of `Relay::login`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Login {
    Accepted(AuthContext),
    Rejected,
    /// Too many recent failures for this source or username. No verify ran.
    Locked,
    Unavailable(String),
}

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
    failures: DashMap<String, (u32, Instant)>,
    last_sweep: Mutex<Instant>,
    verify_slots: tokio::sync::Semaphore,
    in_flight: AtomicUsize,
    peak_in_flight: AtomicUsize,
    verifies: AtomicU64,
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
            last_sweep: Mutex::new(Instant::now()),
            verify_slots: tokio::sync::Semaphore::new(MAX_CONCURRENT_VERIFY),
            in_flight: AtomicUsize::new(0),
            peak_in_flight: AtomicUsize::new(0),
            verifies: AtomicU64::new(0),
        })
    }

    pub fn empty() -> Self {
        Self {
            tenants: Vec::new(),
            conn: None,
            failures: DashMap::new(),
            last_sweep: Mutex::new(Instant::now()),
            verify_slots: tokio::sync::Semaphore::new(MAX_CONCURRENT_VERIFY),
            in_flight: AtomicUsize::new(0),
            peak_in_flight: AtomicUsize::new(0),
            verifies: AtomicU64::new(0),
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
        self.verifies.fetch_add(1, Ordering::SeqCst);
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

    /// Check a login without blocking the runtime: refuse at once when the
    /// source or username is locked out, cap concurrent Argon2 work, count
    /// failures, and clear both counters on success.
    pub async fn login(self: &Arc<Self>, ip: IpAddr, username: String, password: String) -> Login {
        let user = user_key(&username);
        if self.auth_locked(ip) || self.locked(&user) {
            return Login::Locked;
        }
        let Ok(_permit) = self.verify_slots.acquire().await else {
            return Login::Unavailable("verifier closed".into());
        };
        let running = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak_in_flight.fetch_max(running, Ordering::SeqCst);
        let relay = Arc::clone(self);
        let checked = tokio::task::spawn_blocking(move || relay.authenticate(&username, &password))
            .await
            .map_err(|err| err.to_string())
            .and_then(|result| result);
        self.in_flight.fetch_sub(1, Ordering::SeqCst);
        match checked {
            Ok(Some(context)) => {
                self.failures.remove(&ip_key(ip));
                self.failures.remove(&user);
                Login::Accepted(context)
            }
            Ok(None) => {
                self.record_auth_failure(ip);
                self.record_failure(user);
                Login::Rejected
            }
            Err(err) => Login::Unavailable(err),
        }
    }

    /// True when `ip` (or its IPv6 /64) has used up its failed AUTH attempts.
    pub fn auth_locked(&self, ip: IpAddr) -> bool {
        self.locked(&ip_key(ip))
    }

    pub fn record_auth_failure(&self, ip: IpAddr) {
        self.record_failure(ip_key(ip));
    }

    /// Argon2 verifications run so far, including dummy ones.
    pub fn verify_count(&self) -> u64 {
        self.verifies.load(Ordering::SeqCst)
    }

    /// Most Argon2 verifications that have run at once.
    pub fn peak_verifications(&self) -> usize {
        self.peak_in_flight.load(Ordering::SeqCst)
    }

    fn locked(&self, key: &str) -> bool {
        self.failures
            .get(key)
            .is_some_and(|entry| entry.1.elapsed() < FAILURE_WINDOW && entry.0 >= MAX_FAILURES)
    }

    fn record_failure(&self, key: String) {
        if !self.failures.contains_key(&key) && self.failures.len() >= MAX_TRACKED {
            self.sweep();
            if self.failures.len() >= MAX_TRACKED {
                return;
            }
        }
        let mut entry = self.failures.entry(key).or_insert((0, Instant::now()));
        if entry.1.elapsed() >= FAILURE_WINDOW {
            *entry = (0, Instant::now());
        }
        entry.0 = entry.0.saturating_add(1);
    }

    fn sweep(&self) {
        {
            let mut last = self.last_sweep.lock().expect("sweep clock");
            if last.elapsed() < SWEEP_EVERY {
                return;
            }
            *last = Instant::now();
        }
        self.failures
            .retain(|_, entry| entry.1.elapsed() < FAILURE_WINDOW);
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

/// IPv4 addresses are counted alone; IPv6 by /64, since one host owns a /64.
fn ip_key(ip: IpAddr) -> String {
    match ip.to_canonical() {
        IpAddr::V4(v4) => format!("ip:{v4}"),
        IpAddr::V6(v6) => {
            let s = v6.segments();
            format!("ip:{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
        }
    }
}

fn user_key(username: &str) -> String {
    format!("user:{}", username.to_ascii_lowercase())
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
    fn failures_lock_an_address_and_ipv6_counts_by_64() {
        let relay = Relay::empty();
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        let mapped: IpAddr = "::ffff:203.0.113.9".parse().unwrap();
        for _ in 0..MAX_FAILURES {
            assert!(!relay.auth_locked(ip));
            relay.record_auth_failure(mapped);
        }
        assert!(relay.auth_locked(ip));
        assert!(!relay.auth_locked("203.0.113.10".parse().unwrap()));
        for n in 0..MAX_FAILURES as u16 {
            relay.record_auth_failure(IpAddr::from([0x2001, 0xdb8, 0, 7, 0, 0, 0, n + 1]));
        }
        assert!(relay.auth_locked("2001:db8:0:7::ffff".parse().unwrap()));
        assert!(!relay.auth_locked("2001:db8:0:8::1".parse().unwrap()));
    }

    fn relay_with_ada(dir: &Path) -> Arc<Relay> {
        let relay = Relay::open(&dir.join("relay.sqlite"), &[]).unwrap();
        relay.upsert_credential("ten", "ada", "right").unwrap();
        Arc::new(relay)
    }

    #[tokio::test]
    async fn unknown_user_still_runs_a_verify() {
        let dir = tempfile::tempdir().unwrap();
        let relay = relay_with_ada(dir.path());
        let before = relay.verify_count();
        assert!(relay.authenticate("nobody", "right").unwrap().is_none());
        assert_eq!(
            relay.verify_count(),
            before + 1,
            "unknown user skipped Argon2"
        );
        assert!(relay.authenticate("ada", "wrong").unwrap().is_none());
        assert_eq!(relay.verify_count(), before + 2);
        let context = relay.authenticate("ada", "right").unwrap().unwrap();
        assert_eq!(context.tenant_id, "ten");
    }

    #[tokio::test]
    async fn login_counts_per_user_and_success_resets_the_source() {
        let dir = tempfile::tempdir().unwrap();
        let relay = relay_with_ada(dir.path());
        let home: IpAddr = "198.51.100.1".parse().unwrap();
        for _ in 0..MAX_FAILURES - 1 {
            assert_eq!(
                relay.login(home, "ada".into(), "wrong".into()).await,
                Login::Rejected
            );
        }
        assert!(matches!(
            relay.login(home, "ada".into(), "right".into()).await,
            Login::Accepted(_)
        ));
        assert!(
            !relay.failures.contains_key(&ip_key(home)),
            "success clears the source"
        );
        // Ten wrong guesses from ten different addresses lock the username.
        for n in 0..MAX_FAILURES as u8 {
            let ip = IpAddr::from([203, 0, 113, n + 1]);
            assert_eq!(
                relay.login(ip, "ADA".into(), "wrong".into()).await,
                Login::Rejected
            );
        }
        let before = relay.verify_count();
        assert_eq!(
            relay.login(home, "ada".into(), "right".into()).await,
            Login::Locked
        );
        assert_eq!(
            relay.verify_count(),
            before,
            "a locked login runs no verify"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_verifications_are_capped() {
        let dir = tempfile::tempdir().unwrap();
        let relay = relay_with_ada(dir.path());
        let mut tasks = Vec::new();
        for n in 0..16u8 {
            let relay = Arc::clone(&relay);
            tasks.push(tokio::spawn(async move {
                relay
                    .login(IpAddr::from([192, 0, 2, n]), format!("user{n}"), "x".into())
                    .await
            }));
        }
        for task in tasks {
            assert_eq!(task.await.unwrap(), Login::Rejected);
        }
        assert!(relay.peak_verifications() <= MAX_CONCURRENT_VERIFY);
        assert!(relay.peak_verifications() >= 1);
    }

    #[test]
    fn full_failure_table_does_not_sweep_on_every_failure() {
        let relay = Relay::empty();
        for n in 0..MAX_TRACKED as u32 {
            relay.record_failure(format!("user:u{n}"));
        }
        relay.record_failure("user:extra".into());
        assert_eq!(relay.failures.len(), MAX_TRACKED, "new keys wait for room");
    }
}
