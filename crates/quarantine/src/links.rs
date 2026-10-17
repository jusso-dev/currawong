//! Signed digest links. A token names one item, its recipient, an action and
//! an expiry, and carries an HMAC-SHA256 over them. Single use is enforced by
//! the store, which records each token's MAC when it is spent.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use currawong_core::secret::Secret;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::{fs, io, path::Path};

type HmacSha256 = Hmac<Sha256>;

const VERSION: &str = "v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkAction {
    Release,
    Delete,
}

impl LinkAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Release => "release",
            Self::Delete => "delete",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        match text {
            "release" => Some(Self::Release),
            "delete" => Some(Self::Delete),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    pub item_id: String,
    pub recipient: String,
    pub action: LinkAction,
    /// Unix seconds.
    pub expires_at: i64,
}

/// A verified link, with the MAC that marks it spent.
#[derive(Debug, Clone)]
pub struct Verified {
    pub link: Link,
    pub mac: String,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum LinkError {
    #[error("link is not valid")]
    Invalid,
    #[error("link has expired")]
    Expired,
}

#[derive(Clone)]
pub struct LinkSigner {
    key: Secret<Vec<u8>>,
}

impl std::fmt::Debug for LinkSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LinkSigner(***)")
    }
}

impl LinkSigner {
    pub fn new(key: Vec<u8>) -> io::Result<Self> {
        if key.len() < 32 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "quarantine link key must be at least 32 bytes",
            ));
        }
        Ok(Self {
            key: Secret::new(key),
        })
    }

    /// Read the key file, or create a random 32-byte one with mode 0600.
    pub fn load_or_create(path: &Path) -> io::Result<Self> {
        if path.exists() {
            return Self::new(fs::read(path)?);
        }
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut key = vec![0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut key);
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        io::Write::write_all(&mut options.open(path)?, &key)?;
        Self::new(key)
    }

    fn mac(&self) -> HmacSha256 {
        HmacSha256::new_from_slice(self.key.expose()).expect("HMAC takes any key length")
    }

    pub fn sign(&self, link: &Link) -> String {
        let payload = payload(link);
        let mut mac = self.mac();
        mac.update(payload.as_bytes());
        let tag = mac.finalize().into_bytes();
        format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(payload),
            URL_SAFE_NO_PAD.encode(tag)
        )
    }

    /// Check the MAC in constant time, then the expiry.
    pub fn verify(&self, token: &str, now: i64) -> Result<Verified, LinkError> {
        let (payload, tag) = token.split_once('.').ok_or(LinkError::Invalid)?;
        let payload = URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|_| LinkError::Invalid)?;
        let tag = URL_SAFE_NO_PAD
            .decode(tag)
            .map_err(|_| LinkError::Invalid)?;
        let mut mac = self.mac();
        mac.update(&payload);
        mac.verify_slice(&tag).map_err(|_| LinkError::Invalid)?;
        let text = String::from_utf8(payload).map_err(|_| LinkError::Invalid)?;
        let link = parse(&text).ok_or(LinkError::Invalid)?;
        if link.expires_at <= now {
            return Err(LinkError::Expired);
        }
        Ok(Verified {
            link,
            mac: hex::encode(tag),
        })
    }
}

fn payload(link: &Link) -> String {
    format!(
        "{VERSION}\n{}\n{}\n{}\n{}",
        link.action.as_str(),
        link.item_id,
        link.recipient,
        link.expires_at
    )
}

fn parse(text: &str) -> Option<Link> {
    let mut fields = text.split('\n');
    if fields.next()? != VERSION {
        return None;
    }
    let link = Link {
        action: LinkAction::parse(fields.next()?)?,
        item_id: fields.next()?.to_string(),
        recipient: fields.next()?.to_string(),
        expires_at: fields.next()?.parse().ok()?,
    };
    fields.next().is_none().then_some(link)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn link() -> Link {
        Link {
            item_id: "01ARZ3NDEKTSV4RRFFQ69G5FAV".into(),
            recipient: "user@example.test".into(),
            action: LinkAction::Release,
            expires_at: 1_000,
        }
    }

    #[test]
    fn signed_links_verify_until_they_expire() {
        let signer = LinkSigner::new(vec![7; 32]).unwrap();
        let token = signer.sign(&link());
        assert_eq!(signer.verify(&token, 999).unwrap().link, link());
        assert_eq!(
            signer.verify(&token, 1_000).unwrap_err(),
            LinkError::Expired
        );
    }

    #[test]
    fn tampered_or_foreign_links_fail() {
        let signer = LinkSigner::new(vec![7; 32]).unwrap();
        let token = signer.sign(&link());
        let other = LinkSigner::new(vec![8; 32]).unwrap();
        assert_eq!(other.verify(&token, 0).unwrap_err(), LinkError::Invalid);
        // Same MAC, payload changed to a delete.
        let (_, tag) = token.split_once('.').unwrap();
        let mut forged = link();
        forged.action = LinkAction::Delete;
        let forged = format!("{}.{tag}", URL_SAFE_NO_PAD.encode(payload(&forged)));
        assert_eq!(signer.verify(&forged, 0).unwrap_err(), LinkError::Invalid);
        assert_eq!(
            signer.verify("nonsense", 0).unwrap_err(),
            LinkError::Invalid
        );
        assert!(LinkSigner::new(vec![1; 16]).is_err());
    }

    #[test]
    fn key_file_is_created_private_and_reused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys/link.key");
        let first = LinkSigner::load_or_create(&path).unwrap();
        let second = LinkSigner::load_or_create(&path).unwrap();
        let token = first.sign(&link());
        second.verify(&token, 0).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        assert_eq!(format!("{first:?}"), "LinkSigner(***)");
    }
}
