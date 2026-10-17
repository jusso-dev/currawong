//! DKIM private keys encrypted at rest. Only active selectors sign; a retired
//! selector stays published for seven days so mail in flight still verifies.
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use rand::RngCore;
use rusqlite::{params, Connection};
use std::{
    fmt, fs,
    io::Write,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

const RETIRED_PUBLISH_SECS: u64 = 7 * 24 * 60 * 60;

/// Tenant that owns the gateway's own keys. ARC sets are sealed with the
/// active key stored under this tenant for the authserv-id domain.
pub const GATEWAY_TENANT: &str = "_gateway";

#[derive(Clone)]
pub struct StoredKey {
    pub id: String,
    pub tenant_id: String,
    pub domain: String,
    pub selector: String,
    pub algorithm: String,
    /// PKCS#8 DER. Wiped on drop and never printed by `Debug`.
    pub private_key: Zeroizing<Vec<u8>>,
    pub public_txt: String,
    pub created_at: u64,
    pub retired_at: Option<u64>,
    pub active: bool,
}

impl fmt::Debug for StoredKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoredKey")
            .field("id", &self.id)
            .field("tenant_id", &self.tenant_id)
            .field("domain", &self.domain)
            .field("selector", &self.selector)
            .field("algorithm", &self.algorithm)
            .field("private_key", &"<redacted>")
            .field("created_at", &self.created_at)
            .field("retired_at", &self.retired_at)
            .field("active", &self.active)
            .finish()
    }
}

impl StoredKey {
    /// DNS name and value to publish, e.g. `sel._domainkey.example.test`.
    pub fn dns_name(&self) -> String {
        format!("{}._domainkey.{}", self.selector, self.domain)
    }
}

/// New key for `tenant_id`/`domain`/`selector`. `algorithm` is `ed25519` or
/// `rsa` (always RSA-2048).
pub fn generate(
    tenant_id: &str,
    domain: &str,
    selector: &str,
    algorithm: &str,
) -> Result<StoredKey, String> {
    let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if domain.is_empty() || selector.is_empty() || tenant_id.is_empty() {
        return Err("tenant, domain and selector are required".into());
    }
    if !selector
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
    {
        return Err(format!("selector {selector:?} is not a DNS label"));
    }
    let (algorithm, private_key, public_txt) = match algorithm {
        "ed25519" => {
            let (der, txt) = crate::sign::ed25519_material()?;
            ("ed25519", der, txt)
        }
        "rsa" | "rsa-sha256" => {
            let (der, txt) = crate::sign::rsa_material()?;
            ("rsa-sha256", der, txt)
        }
        other => return Err(format!("unknown DKIM algorithm {other}")),
    };
    Ok(StoredKey {
        id: format!("{tenant_id}:{domain}:{selector}"),
        tenant_id: tenant_id.into(),
        domain,
        selector: selector.into(),
        algorithm: algorithm.into(),
        private_key,
        public_txt,
        created_at: now_secs(),
        retired_at: None,
        active: true,
    })
}

pub struct KeyStore {
    path: PathBuf,
    kek: Zeroizing<[u8; 32]>,
}

impl KeyStore {
    /// Opens the store. A missing key-encryption key is only created when
    /// the store holds no keys; otherwise every key would be undecryptable.
    pub fn open(database: &Path, kek_path: &Path) -> Result<Self, String> {
        if let Some(parent) = database.parent() {
            fs::create_dir_all(parent).map_err(|err| err.to_string())?;
        }
        let conn = Connection::open(database).map_err(|err| err.to_string())?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS dkim_keys (
                id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                domain TEXT NOT NULL,
                selector TEXT NOT NULL,
                algorithm TEXT NOT NULL,
                private_key_enc BLOB NOT NULL,
                public_txt TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                retired_at INTEGER,
                active INTEGER NOT NULL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS dkim_keys_selector ON dkim_keys(domain, selector);",
        )
        .map_err(|err| err.to_string())?;
        let stored: i64 = conn
            .query_row("SELECT COUNT(*) FROM dkim_keys", [], |row| row.get(0))
            .map_err(|err| err.to_string())?;
        let kek = load_kek(kek_path, stored > 0)?;
        Ok(Self {
            path: database.to_path_buf(),
            kek,
        })
    }

    pub fn insert(&self, key: &StoredKey) -> Result<(), String> {
        self.with_conn(|conn| insert_row(conn, &self.kek, key))
    }

    /// Adds `key` and retires the active keys of the same algorithm for its
    /// tenant and domain, in one transaction.
    pub fn rotate(&self, key: &StoredKey, now: u64) -> Result<(), String> {
        self.with_conn(|conn| {
            let tx = conn
                .unchecked_transaction()
                .map_err(|err| err.to_string())?;
            tx.execute(
                "UPDATE dkim_keys SET active = 0, retired_at = ?4
                 WHERE tenant_id = ?1 AND domain = ?2 AND algorithm = ?3 AND active = 1",
                params![key.tenant_id, key.domain, key.algorithm, now as i64],
            )
            .map_err(|err| err.to_string())?;
            insert_row(&tx, &self.kek, key)?;
            tx.commit().map_err(|err| err.to_string())
        })
    }

    pub fn signing_keys(
        &self,
        tenant_id: &str,
        domain: &str,
        now: u64,
    ) -> Result<Vec<StoredKey>, String> {
        Ok(self
            .list(tenant_id, domain)?
            .into_iter()
            .filter(|key| key.active && key.retired_at.is_none() && publishable(key, now))
            .collect())
    }

    pub fn publishable_keys(
        &self,
        tenant_id: &str,
        domain: &str,
        now: u64,
    ) -> Result<Vec<StoredKey>, String> {
        Ok(self
            .list(tenant_id, domain)?
            .into_iter()
            .filter(|key| publishable(key, now))
            .collect())
    }

    pub fn retire(&self, id: &str, now: u64) -> Result<(), String> {
        self.with_conn(|conn| {
            conn.execute(
                "UPDATE dkim_keys SET active = 0, retired_at = ?2 WHERE id = ?1",
                params![id, now as i64],
            )
            .map_err(|err| err.to_string())?;
            Ok(())
        })
    }

    fn list(&self, tenant_id: &str, domain: &str) -> Result<Vec<StoredKey>, String> {
        let domain = domain.trim_end_matches('.').to_ascii_lowercase();
        self.with_conn(|conn| {
            let mut stmt = conn
                .prepare("SELECT id, tenant_id, domain, selector, algorithm, private_key_enc, public_txt, created_at, retired_at, active FROM dkim_keys WHERE tenant_id = ?1 AND domain = ?2 ORDER BY created_at")
                .map_err(|err| err.to_string())?;
            let rows = stmt
                .query_map(params![tenant_id, domain], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, Vec<u8>>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, i64>(7)?,
                        row.get::<_, Option<i64>>(8)?,
                        row.get::<_, i64>(9)?,
                    ))
                })
                .map_err(|err| err.to_string())?;
            let mut out = Vec::new();
            for row in rows {
                let (id, tenant_id, domain, selector, algorithm, enc, public_txt, created_at, retired_at, active) = row.map_err(|err| err.to_string())?;
                out.push(StoredKey {
                    id,
                    tenant_id,
                    domain,
                    selector,
                    algorithm,
                    private_key: decrypt(&self.kek, &enc)?,
                    public_txt,
                    created_at: created_at as u64,
                    retired_at: retired_at.map(|v| v as u64),
                    active: active != 0,
                });
            }
            Ok(out)
        })
    }

    fn with_conn<T>(&self, f: impl FnOnce(&Connection) -> Result<T, String>) -> Result<T, String> {
        let conn = Connection::open(&self.path).map_err(|err| err.to_string())?;
        f(&conn)
    }
}

fn insert_row(conn: &Connection, kek: &[u8; 32], key: &StoredKey) -> Result<(), String> {
    let enc = encrypt(kek, &key.private_key)?;
    conn.execute(
        "INSERT INTO dkim_keys (id, tenant_id, domain, selector, algorithm, private_key_enc, public_txt, created_at, retired_at, active)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            key.id,
            key.tenant_id,
            key.domain,
            key.selector,
            key.algorithm,
            enc,
            key.public_txt,
            key.created_at as i64,
            key.retired_at.map(|v| v as i64),
            key.active as i64
        ],
    )
    .map_err(|err| err.to_string())?;
    Ok(())
}

pub fn publishable(key: &StoredKey, now: u64) -> bool {
    if key.active && key.retired_at.is_none() {
        return true;
    }
    match key.retired_at {
        Some(retired) => now.saturating_sub(retired) <= RETIRED_PUBLISH_SECS,
        None => key.active,
    }
}

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_secs()
}

fn load_kek(path: &Path, keys_exist: bool) -> Result<Zeroizing<[u8; 32]>, String> {
    if path.exists() {
        let bytes = Zeroizing::new(fs::read(path).map_err(|err| err.to_string())?);
        let kek: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| "dkim kek must be 32 bytes".to_string())?;
        return Ok(Zeroizing::new(kek));
    }
    if keys_exist {
        return Err(format!(
            "dkim kek {} is missing but the key store holds keys; restore it rather than generating a new one",
            path.display()
        ));
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| err.to_string())?;
    }
    let mut kek = Zeroizing::new([0u8; 32]);
    rand::rngs::OsRng.fill_bytes(kek.as_mut());
    // Created 0600 before any key byte is written.
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|err| err.to_string())?;
    file.write_all(kek.as_ref())
        .and_then(|_| file.sync_all())
        .map_err(|err| err.to_string())?;
    Ok(kek)
}

fn encrypt(kek: &[u8; 32], plain: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = Aes256Gcm::new_from_slice(kek).map_err(|err| err.to_string())?;
    let mut nonce_bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let mut out = nonce_bytes.to_vec();
    let ct = cipher
        .encrypt(nonce, plain)
        .map_err(|err| err.to_string())?;
    out.extend(ct);
    Ok(out)
}

fn decrypt(kek: &[u8; 32], blob: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
    if blob.len() < 12 {
        return Err("encrypted key is truncated".into());
    }
    let cipher = Aes256Gcm::new_from_slice(kek).map_err(|err| err.to_string())?;
    let nonce = Nonce::from_slice(&blob[..12]);
    cipher
        .decrypt(nonce, &blob[12..])
        .map(Zeroizing::new)
        .map_err(|err| err.to_string())
}
