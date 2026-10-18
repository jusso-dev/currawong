//! Secure pull portal store. A held message is sealed with AES-256-GCM under
//! the portal key and bound to its token. The recipient asks for a six digit
//! code, which is mailed to them and is valid for ten minutes; five wrong
//! codes lock the message for good.
//!
//! Files per message in `dir`: `<token>.json` (recipient, route, expiry,
//! code hash and failure count), written first, and `<token>.bin` (nonce
//! and ciphertext).
use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, KeyInit, Nonce,
};
use currawong_core::TlsRequirement;
use rand::{Rng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    sync::Mutex,
};
use zeroize::Zeroizing;

/// How long an issued code opens the message.
pub const CODE_TTL_SECS: u64 = 10 * 60;
/// Wrong codes before the message is locked.
pub const MAX_FAILURES: u32 = 5;
/// A new code is mailed at most this often per message.
pub const CODE_INTERVAL_SECS: u64 = 60;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PortalError {
    #[error("no such message")]
    NotFound,
    #[error("the message has expired")]
    Expired,
    #[error("the message is locked after too many wrong codes")]
    Locked,
    #[error("wrong code, {remaining} attempts left")]
    WrongCode { remaining: u32 },
    #[error("no code has been requested, or it has expired")]
    NoCode,
    #[error("a code was sent recently, try again in {retry_after} seconds")]
    RateLimited { retry_after: u64 },
    #[error("portal store: {0}")]
    Store(String),
}

/// How mail for a held message is sent: the code mail goes the same way as
/// the original, with at least `require_tls`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Route {
    #[serde(default)]
    pub tenant_id: Option<String>,
    #[serde(default)]
    pub tls: TlsRequirement,
}

/// A code to mail to `recipient`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Issued {
    pub recipient: String,
    pub code: String,
    pub route: Route,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Record {
    recipient: String,
    #[serde(default)]
    route: Route,
    /// Unix seconds.
    created_at: u64,
    expires_at: u64,
    /// SHA-256 of the portal key, token and code. Cleared once used.
    #[serde(default)]
    code_hash: Option<String>,
    #[serde(default)]
    code_expires_at: u64,
    #[serde(default)]
    code_issued_at: u64,
    #[serde(default)]
    failures: u32,
}

pub struct PortalStore {
    dir: PathBuf,
    key: Zeroizing<[u8; 32]>,
    retention_secs: u64,
    /// Serialises read-modify-write of the records.
    lock: Mutex<()>,
}

impl PortalStore {
    /// Opens the store, creating the 32-byte key (mode 0600) when it is
    /// missing and no message is held. Without the key held messages are lost.
    pub fn open(dir: &Path, key_path: &Path, retention_days: u64) -> Result<Self, PortalError> {
        fs::create_dir_all(dir).map_err(store_err)?;
        let held = fs::read_dir(dir)
            .map_err(store_err)?
            .flatten()
            .any(|e| e.path().extension().is_some_and(|x| x == "bin"));
        let key = load_key(key_path, held)?;
        Ok(Self {
            dir: dir.to_path_buf(),
            key,
            retention_secs: retention_days.max(1).saturating_mul(86_400),
            lock: Mutex::new(()),
        })
    }

    /// Hold `raw` for `recipient`. Returns the link token.
    pub fn store(
        &self,
        recipient: &str,
        raw: &[u8],
        route: &Route,
        now: u64,
    ) -> Result<String, PortalError> {
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        let token = hex::encode(bytes);
        let cipher = Aes256Gcm::new_from_slice(self.key.as_ref()).map_err(store_err)?;
        let mut nonce = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let sealed = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: raw,
                    aad: token.as_bytes(),
                },
            )
            .map_err(store_err)?;
        let mut blob = nonce.to_vec();
        blob.extend(sealed);
        let record = Record {
            recipient: recipient.to_string(),
            route: route.clone(),
            created_at: now,
            expires_at: now.saturating_add(self.retention_secs),
            code_hash: None,
            code_expires_at: 0,
            code_issued_at: 0,
            failures: 0,
        };
        // The record first: `purge_expired` walks records, so a sealed body
        // never outlives a failed write unseen.
        self.save(&token, &record)?;
        if let Err(err) = write_atomic(&self.path(&token, "bin"), &blob) {
            let _ = fs::remove_file(self.path(&token, "json"));
            return Err(err);
        }
        Ok(token)
    }

    /// The recipient the message is held for.
    pub fn recipient(&self, token: &str, now: u64) -> Result<String, PortalError> {
        let record = self.load(token)?;
        if now > record.expires_at {
            return Err(PortalError::Expired);
        }
        Ok(record.recipient)
    }

    /// A new six digit code for the message. The caller mails it to the
    /// returned recipient; it replaces any earlier code.
    pub fn issue_code(&self, token: &str, now: u64) -> Result<Issued, PortalError> {
        let _guard = self.lock.lock().unwrap_or_else(|p| p.into_inner());
        let mut record = self.load(token)?;
        self.usable(&record, now)?;
        let next = record.code_issued_at.saturating_add(CODE_INTERVAL_SECS);
        if record.code_issued_at > 0 && now < next {
            return Err(PortalError::RateLimited {
                retry_after: next - now,
            });
        }
        let code = format!("{:06}", rand::rngs::OsRng.gen_range(0..1_000_000u32));
        record.code_hash = Some(self.code_hash(token, &code));
        record.code_issued_at = now;
        record.code_expires_at = now.saturating_add(CODE_TTL_SECS);
        self.save(token, &record)?;
        Ok(Issued {
            recipient: record.recipient,
            code,
            route: record.route,
        })
    }

    /// Clear a lock and any live code, for an administrator who has
    /// confirmed the recipient. The recipient then asks for a new code.
    pub fn unlock(&self, token: &str) -> Result<(), PortalError> {
        let _guard = self.lock.lock().unwrap_or_else(|p| p.into_inner());
        let mut record = self.load(token)?;
        record.failures = 0;
        record.code_hash = None;
        record.code_issued_at = 0;
        self.save(token, &record)
    }

    /// The message, when `code` is the live code. A used code is spent.
    pub fn open_message(&self, token: &str, code: &str, now: u64) -> Result<Vec<u8>, PortalError> {
        let _guard = self.lock.lock().unwrap_or_else(|p| p.into_inner());
        let mut record = self.load(token)?;
        self.usable(&record, now)?;
        let Some(expected) = record.code_hash.clone() else {
            return Err(PortalError::NoCode);
        };
        if now > record.code_expires_at {
            return Err(PortalError::NoCode);
        }
        if self.code_hash(token, code.trim()) != expected {
            record.failures += 1;
            if record.failures >= MAX_FAILURES {
                record.code_hash = None;
                self.save(token, &record)?;
                return Err(PortalError::Locked);
            }
            self.save(token, &record)?;
            return Err(PortalError::WrongCode {
                remaining: MAX_FAILURES - record.failures,
            });
        }
        record.code_hash = None;
        self.save(token, &record)?;
        let blob = fs::read(self.path(token, "bin")).map_err(store_err)?;
        if blob.len() < 12 {
            return Err(PortalError::Store(format!("{token} is truncated")));
        }
        let cipher = Aes256Gcm::new_from_slice(self.key.as_ref()).map_err(store_err)?;
        cipher
            .decrypt(
                Nonce::from_slice(&blob[..12]),
                Payload {
                    msg: &blob[12..],
                    aad: token.as_bytes(),
                },
            )
            .map_err(|_| PortalError::Store(format!("{token} does not decrypt with this key")))
    }

    /// Delete messages past their retention, and sealed bodies left without
    /// a record by a crash. Returns how many messages went.
    pub fn purge_expired(&self, now: u64) -> Result<usize, PortalError> {
        let _guard = self.lock.lock().unwrap_or_else(|p| p.into_inner());
        let mut removed = 0;
        for entry in fs::read_dir(&self.dir).map_err(store_err)?.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|x| x == "bin") && !path.with_extension("json").exists()
            {
                let _ = fs::remove_file(&path);
                continue;
            }
            let Some(token) = path
                .file_stem()
                .and_then(|s| s.to_str())
                .filter(|_| path.extension().is_some_and(|x| x == "json"))
            else {
                continue;
            };
            if self.load(token).is_ok_and(|r| now > r.expires_at) {
                let _ = fs::remove_file(self.path(token, "bin"));
                let _ = fs::remove_file(&path);
                removed += 1;
            }
        }
        Ok(removed)
    }

    fn usable(&self, record: &Record, now: u64) -> Result<(), PortalError> {
        if now > record.expires_at {
            return Err(PortalError::Expired);
        }
        if record.failures >= MAX_FAILURES {
            return Err(PortalError::Locked);
        }
        Ok(())
    }

    fn code_hash(&self, token: &str, code: &str) -> String {
        let mut hash = Sha256::new();
        hash.update(self.key.as_ref());
        hash.update(token.as_bytes());
        hash.update(b"\n");
        hash.update(code.as_bytes());
        hex::encode(hash.finalize())
    }

    /// Tokens are 64 lower-case hex characters, so they never name another path.
    fn path(&self, token: &str, ext: &str) -> PathBuf {
        self.dir.join(format!("{token}.{ext}"))
    }

    fn load(&self, token: &str) -> Result<Record, PortalError> {
        if token.len() != 64
            || !token
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(PortalError::NotFound);
        }
        let bytes = match fs::read(self.path(token, "json")) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return Err(PortalError::NotFound)
            }
            Err(err) => return Err(store_err(err)),
        };
        serde_json::from_slice(&bytes).map_err(store_err)
    }

    fn save(&self, token: &str, record: &Record) -> Result<(), PortalError> {
        let bytes = serde_json::to_vec(record).map_err(store_err)?;
        write_atomic(&self.path(token, "json"), &bytes)
    }
}

/// Header fields for mail the portal sends. `date` is RFC 5322.
fn headers(from: &str, recipient: &str, subject: &str, date: &str, id: &str) -> String {
    format!(
        "From: {from}\r\nTo: {recipient}\r\nSubject: {subject}\r\nDate: {date}\r\n\
         Message-ID: <{id}>\r\nAuto-Submitted: auto-generated\r\nMIME-Version: 1.0\r\n\
         Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n"
    )
}

/// The mail a recipient gets in place of a held message. Names the sender
/// but not the subject, which may itself be sensitive.
pub fn notice(
    original: &[u8],
    from: &str,
    recipient: &str,
    link: &str,
    date: &str,
    id: &str,
) -> Vec<u8> {
    let (fields, _) = super::split_message(original);
    let sender: String = super::field_value(&fields, "from")
        .unwrap_or_else(|| "Someone".into())
        .chars()
        .filter(|c| !c.is_control())
        .take(200)
        .collect();
    let mut out = headers(from, recipient, "You have a secure message", date, id);
    out.push_str(&format!(
        "{sender} sent you a message that is held securely.\r\n\r\n\
         Open it here: {link}\r\n\r\n\
         When you open the link you can ask for a one-time code. It is emailed to\r\n\
         this address and works for ten minutes. After five wrong codes the\r\n\
         message is locked.\r\n"
    ));
    out.into_bytes()
}

/// The mail carrying a one-time code.
pub fn code_mail(from: &str, recipient: &str, code: &str, date: &str, id: &str) -> Vec<u8> {
    let mut out = headers(from, recipient, "Your one-time code", date, id);
    out.push_str(&format!(
        "Your code to open the secure message is {code}\r\n\r\n\
         It works for ten minutes. If you did not ask for it, you can ignore this email.\r\n"
    ));
    out.into_bytes()
}

fn store_err(err: impl std::fmt::Display) -> PortalError {
    PortalError::Store(err.to_string())
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), PortalError> {
    let tmp = path.with_extension("tmp");
    let mut file = private_file(&tmp)?;
    file.write_all(bytes).map_err(store_err)?;
    file.sync_all().map_err(store_err)?;
    fs::rename(&tmp, path).map_err(store_err)
}

fn private_file(path: &Path) -> Result<fs::File, PortalError> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .map_err(|err| PortalError::Store(format!("{}: {err}", path.display())))
}

fn load_key(path: &Path, held: bool) -> Result<Zeroizing<[u8; 32]>, PortalError> {
    if path.exists() {
        let bytes = Zeroizing::new(fs::read(path).map_err(store_err)?);
        let key: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| PortalError::Store("portal key must be 32 bytes".into()))?;
        return Ok(Zeroizing::new(key));
    }
    if held {
        return Err(PortalError::Store(format!(
            "portal key {} is missing but messages are held; restore it rather than generating a new one",
            path.display()
        )));
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(store_err)?;
    }
    let mut key = Zeroizing::new([0u8; 32]);
    rand::rngs::OsRng.fill_bytes(key.as_mut());
    // Written beside it and renamed, so a crash never leaves a short key.
    write_atomic(path, key.as_ref())?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_790_000_000;
    const MESSAGE: &[u8] = b"Subject: Payroll\r\n\r\nTFN 123 456 782\r\n";

    fn store() -> (tempfile::TempDir, PortalStore) {
        let dir = tempfile::tempdir().unwrap();
        let store =
            PortalStore::open(&dir.path().join("held"), &dir.path().join("key"), 30).unwrap();
        (dir, store)
    }

    fn wrong(code: &str) -> String {
        let n: u32 = code.parse().unwrap();
        format!("{:06}", (n + 1) % 1_000_000)
    }

    #[test]
    fn encrypt_portal_opens_only_with_the_right_code() {
        let (dir, store) = store();
        let token = store
            .store(
                "partner@partner.example.com.au",
                MESSAGE,
                &Route::default(),
                NOW,
            )
            .unwrap();
        // Sealed at rest.
        let blob = fs::read(dir.path().join("held").join(format!("{token}.bin"))).unwrap();
        assert!(!blob.windows(11).any(|w| w == b"123 456 782"));
        assert_eq!(
            store.open_message(&token, "000000", NOW),
            Err(PortalError::NoCode)
        );
        let Issued {
            recipient: rcpt,
            code,
            ..
        } = store.issue_code(&token, NOW).unwrap();
        assert_eq!(rcpt, "partner@partner.example.com.au");
        assert_eq!(code.len(), 6);
        assert!(code.bytes().all(|b| b.is_ascii_digit()));
        assert_eq!(
            store.open_message(&token, &wrong(&code), NOW),
            Err(PortalError::WrongCode { remaining: 4 })
        );
        assert_eq!(store.open_message(&token, &code, NOW + 5).unwrap(), MESSAGE);
        // One time: the same code does not open it again.
        assert_eq!(
            store.open_message(&token, &code, NOW + 6),
            Err(PortalError::NoCode)
        );
        // Unknown and malformed tokens are not found.
        assert_eq!(
            store.recipient(&"0".repeat(64), NOW),
            Err(PortalError::NotFound)
        );
        assert_eq!(store.recipient("../key", NOW), Err(PortalError::NotFound));
    }

    #[test]
    fn encrypt_portal_locks_after_five_wrong_codes() {
        let (_dir, store) = store();
        let token = store
            .store(
                "partner@partner.example.com.au",
                MESSAGE,
                &Route::default(),
                NOW,
            )
            .unwrap();
        let Issued { code, .. } = store.issue_code(&token, NOW).unwrap();
        for remaining in (1..MAX_FAILURES).rev() {
            assert_eq!(
                store.open_message(&token, &wrong(&code), NOW),
                Err(PortalError::WrongCode { remaining })
            );
        }
        assert_eq!(
            store.open_message(&token, &wrong(&code), NOW),
            Err(PortalError::Locked)
        );
        // Locked for good: the right code and a fresh code do not help.
        assert_eq!(
            store.open_message(&token, &code, NOW),
            Err(PortalError::Locked)
        );
        assert_eq!(
            store.issue_code(&token, NOW + 3600),
            Err(PortalError::Locked)
        );
    }

    #[test]
    fn encrypt_portal_code_expires_after_ten_minutes_and_is_rate_limited() {
        let (_dir, store) = store();
        let token = store
            .store("a@example.com.au", MESSAGE, &Route::default(), NOW)
            .unwrap();
        let Issued { code, .. } = store.issue_code(&token, NOW).unwrap();
        assert_eq!(
            store.issue_code(&token, NOW + 10),
            Err(PortalError::RateLimited { retry_after: 50 })
        );
        assert_eq!(
            store.open_message(&token, &code, NOW + CODE_TTL_SECS + 1),
            Err(PortalError::NoCode)
        );
        let Issued { code: fresh, .. } = store.issue_code(&token, NOW + CODE_TTL_SECS + 1).unwrap();
        assert_eq!(
            store
                .open_message(&token, &fresh, NOW + CODE_TTL_SECS + 2)
                .unwrap(),
            MESSAGE
        );
    }

    #[test]
    fn encrypt_portal_messages_expire_and_purge() {
        let (dir, store) = store();
        let token = store
            .store("a@example.com.au", MESSAGE, &Route::default(), NOW)
            .unwrap();
        let late = NOW + 31 * 86_400;
        assert_eq!(store.issue_code(&token, late), Err(PortalError::Expired));
        assert_eq!(store.purge_expired(NOW).unwrap(), 0);
        assert_eq!(store.purge_expired(late).unwrap(), 1);
        assert_eq!(store.recipient(&token, NOW), Err(PortalError::NotFound));
        assert_eq!(fs::read_dir(dir.path().join("held")).unwrap().count(), 0);
    }

    #[test]
    fn encrypt_portal_key_is_kept_and_needed() {
        let dir = tempfile::tempdir().unwrap();
        let (held, key) = (dir.path().join("held"), dir.path().join("key"));
        let store = PortalStore::open(&held, &key, 30).unwrap();
        let token = store
            .store("a@example.com.au", MESSAGE, &Route::default(), NOW)
            .unwrap();
        drop(store);
        // Reopened with the same key, the message still opens.
        let store = PortalStore::open(&held, &key, 30).unwrap();
        let Issued { code, .. } = store.issue_code(&token, NOW).unwrap();
        assert_eq!(store.open_message(&token, &code, NOW).unwrap(), MESSAGE);
        // A lost key is not silently replaced while messages are held.
        fs::remove_file(&key).unwrap();
        assert!(PortalStore::open(&held, &key, 30).is_err());
    }

    #[test]
    fn encrypt_portal_keeps_the_route_and_unlocks() {
        let (_dir, store) = store();
        let route = Route {
            tenant_id: Some("t1".into()),
            tls: TlsRequirement::Dane,
        };
        let token = store
            .store("a@example.com.au", MESSAGE, &route, NOW)
            .unwrap();
        let issued = store.issue_code(&token, NOW).unwrap();
        assert_eq!(issued.route, route);
        for _ in 0..MAX_FAILURES {
            let _ = store.open_message(&token, &wrong(&issued.code), NOW);
        }
        assert_eq!(
            store.issue_code(&token, NOW + 120),
            Err(PortalError::Locked)
        );
        store.unlock(&token).unwrap();
        // The old code is gone; a new one opens the message.
        assert_eq!(
            store.open_message(&token, &issued.code, NOW + 120),
            Err(PortalError::NoCode)
        );
        let fresh = store.issue_code(&token, NOW + 121).unwrap();
        assert_eq!(
            store.open_message(&token, &fresh.code, NOW + 122).unwrap(),
            MESSAGE
        );
        assert_eq!(store.unlock(&"f".repeat(64)), Err(PortalError::NotFound));
    }

    #[test]
    fn encrypt_portal_purges_sealed_bodies_without_a_record() {
        let (dir, store) = store();
        let held = dir.path().join("held");
        let token = store
            .store("a@example.com.au", MESSAGE, &Route::default(), NOW)
            .unwrap();
        let orphan = held.join(format!("{}.bin", "a".repeat(64)));
        fs::write(&orphan, b"sealed").unwrap();
        assert_eq!(store.purge_expired(NOW).unwrap(), 0);
        assert!(!orphan.exists());
        assert!(held.join(format!("{token}.bin")).exists());
        // No temporary files are left behind by the key or record writes.
        assert!(fs::read_dir(dir.path())
            .unwrap()
            .flatten()
            .all(|e| e.path().extension().is_none_or(|x| x != "tmp")));
    }
}
