//! DKIM private keys encrypted at rest. Only the active selector signs.
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use rand::RngCore;
use rusqlite::{params, Connection};
use std::{
    fs,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const RETIRED_PUBLISH_SECS: u64 = 7 * 24 * 60 * 60;

#[derive(Debug, Clone)]
pub struct StoredKey {
    pub id: String,
    pub tenant_id: String,
    pub domain: String,
    pub selector: String,
    pub algorithm: String,
    pub private_key: Vec<u8>,
    pub public_txt: String,
    pub created_at: u64,
    pub retired_at: Option<u64>,
    pub active: bool,
}

pub struct KeyStore {
    path: PathBuf,
    kek: [u8; 32],
}

impl KeyStore {
    pub fn open(database: &Path, kek_path: &Path) -> Result<Self, String> {
        if let Some(parent) = database.parent() {
            fs::create_dir_all(parent).map_err(|err| err.to_string())?;
        }
        let kek = load_kek(kek_path)?;
        let store = Self {
            path: database.to_path_buf(),
            kek,
        };
        store.with_conn(|conn| {
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
                );",
            )
            .map_err(|err| err.to_string())?;
            Ok(())
        })?;
        Ok(store)
    }

    pub fn insert(&self, key: &StoredKey) -> Result<(), String> {
        let enc = encrypt(&self.kek, &key.private_key)?;
        self.with_conn(|conn| {
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
        })
    }

    pub fn signing_keys(&self, domain: &str, now: u64) -> Result<Vec<StoredKey>, String> {
        Ok(self
            .list(domain)?
            .into_iter()
            .filter(|key| key.active && key.retired_at.is_none() && publishable(key, now))
            .collect())
    }

    pub fn publishable_keys(&self, domain: &str, now: u64) -> Result<Vec<StoredKey>, String> {
        Ok(self
            .list(domain)?
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

    fn list(&self, domain: &str) -> Result<Vec<StoredKey>, String> {
        self.with_conn(|conn| {
            let mut stmt = conn
                .prepare("SELECT id, tenant_id, domain, selector, algorithm, private_key_enc, public_txt, created_at, retired_at, active FROM dkim_keys WHERE domain = ?1")
                .map_err(|err| err.to_string())?;
            let rows = stmt
                .query_map(params![domain], |row| {
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

fn load_kek(path: &Path) -> Result<[u8; 32], String> {
    if path.exists() {
        let bytes = fs::read(path).map_err(|err| err.to_string())?;
        let kek: [u8; 32] = bytes
            .try_into()
            .map_err(|_| "dkim kek must be 32 bytes".to_string())?;
        return Ok(kek);
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| err.to_string())?;
    }
    let mut kek = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut kek);
    fs::write(path, kek).map_err(|err| err.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
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

fn decrypt(kek: &[u8; 32], blob: &[u8]) -> Result<Vec<u8>, String> {
    if blob.len() < 12 {
        return Err("encrypted key is truncated".into());
    }
    let cipher = Aes256Gcm::new_from_slice(kek).map_err(|err| err.to_string())?;
    let nonce = Nonce::from_slice(&blob[..12]);
    cipher
        .decrypt(nonce, &blob[12..])
        .map_err(|err| err.to_string())
}
