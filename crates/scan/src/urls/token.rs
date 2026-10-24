//! Signed click tokens: `base64url(json).base64url(hmac-sha256)`.
//!
//! The MAC covers the encoded claims (URL, message id, recipient, issue
//! time and expiry) and is checked in constant time before anything in the
//! token is decoded.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use currawong_core::Secret;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::path::Path;

type HmacSha256 = Hmac<Sha256>;

/// Shortest key accepted from the key file.
pub const MIN_KEY_BYTES: usize = 32;
/// Longer tokens are refused before decoding.
pub const MAX_TOKEN_BYTES: usize = 16 * 1024;
/// Separates these MACs from any other use of the same key.
const DOMAIN: &[u8] = b"currawong-url-v1.";

/// What a token vouches for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claims {
    /// The original link.
    pub u: String,
    /// Message id the link was delivered in.
    pub m: String,
    /// Recipients of the copy, comma separated. Empty when unknown.
    #[serde(default)]
    pub r: String,
    /// Issued (message arrival), Unix seconds.
    #[serde(default)]
    pub t: u64,
    /// Expiry, Unix seconds.
    pub e: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TokenError {
    #[error("malformed token")]
    Malformed,
    #[error("token signature does not match")]
    BadSignature,
    #[error("token expired")]
    Expired,
}

#[derive(Clone)]
pub struct UrlSigner {
    key: Secret<Vec<u8>>,
}

impl UrlSigner {
    pub fn new(key: Vec<u8>) -> Result<Self, String> {
        if key.len() < MIN_KEY_BYTES {
            return Err(format!(
                "URL signing key must be at least {MIN_KEY_BYTES} bytes"
            ));
        }
        Ok(Self {
            key: Secret::new(key),
        })
    }

    /// Read the key from a secret file. Trailing whitespace is ignored so a
    /// key written by `openssl rand -hex 32 > file` works.
    pub fn from_file(path: &Path) -> Result<Self, String> {
        let mut key = std::fs::read(path)
            .map_err(|err| format!("URL signing key {}: {err}", path.display()))?;
        while key.last().is_some_and(u8::is_ascii_whitespace) {
            key.pop();
        }
        Self::new(key)
    }

    fn mac(&self) -> HmacSha256 {
        let mut mac = HmacSha256::new_from_slice(self.key.expose()).expect("any key length");
        mac.update(DOMAIN);
        mac
    }

    pub fn sign(&self, claims: &Claims) -> String {
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).expect("claims serialise"));
        let mut mac = self.mac();
        mac.update(payload.as_bytes());
        let tag = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
        format!("{payload}.{tag}")
    }

    /// Separate MAC domain: a continuation cannot be used as a delivery token.
    /// Binds the original token, inspected destination, and five-minute expiry.
    pub fn continuation(&self, token: &str, destination: &str, now: u64) -> String {
        let expiry = now.saturating_add(300);
        let mut mac = HmacSha256::new_from_slice(self.key.expose()).expect("any key length");
        mac.update(b"currawong-continue-v1.");
        mac.update(token.as_bytes());
        mac.update(b"\0");
        mac.update(destination.as_bytes());
        mac.update(&expiry.to_be_bytes());
        format!(
            "{expiry}.{}",
            URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
        )
    }
    pub fn verify_continuation(
        &self,
        value: &str,
        token: &str,
        destination: &str,
        now: u64,
    ) -> bool {
        let Some((expiry, tag)) = value.split_once('.') else {
            return false;
        };
        let Ok(expiry) = expiry.parse::<u64>() else {
            return false;
        };
        if expiry < now || expiry > now.saturating_add(300) {
            return false;
        }
        let Ok(tag) = URL_SAFE_NO_PAD.decode(tag) else {
            return false;
        };
        let mut mac = HmacSha256::new_from_slice(self.key.expose()).expect("any key length");
        mac.update(b"currawong-continue-v1.");
        mac.update(token.as_bytes());
        mac.update(b"\0");
        mac.update(destination.as_bytes());
        mac.update(&expiry.to_be_bytes());
        mac.verify_slice(&tag).is_ok()
    }

    /// Check the MAC, then the expiry against `now` (Unix seconds).
    pub fn verify(&self, token: &str, now: u64) -> Result<Claims, TokenError> {
        if token.len() > MAX_TOKEN_BYTES {
            return Err(TokenError::Malformed);
        }
        let (payload, tag) = token.split_once('.').ok_or(TokenError::Malformed)?;
        let tag = URL_SAFE_NO_PAD
            .decode(tag)
            .map_err(|_| TokenError::Malformed)?;
        let mut mac = self.mac();
        mac.update(payload.as_bytes());
        mac.verify_slice(&tag)
            .map_err(|_| TokenError::BadSignature)?;
        let json = URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|_| TokenError::Malformed)?;
        let claims: Claims = serde_json::from_slice(&json).map_err(|_| TokenError::Malformed)?;
        if claims.e < now {
            return Err(TokenError::Expired);
        }
        Ok(claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims() -> Claims {
        Claims {
            u: "https://example.com/a?b=c".into(),
            m: "01ARZ3NDEKTSV4RRFFQ69G5FAV".into(),
            r: "dest@example.test".into(),
            t: 500,
            e: 2_000,
        }
    }

    #[test]
    fn urls_token_round_trips_and_expires() {
        let signer = UrlSigner::new(vec![7; 32]).unwrap();
        let token = signer.sign(&claims());
        assert_eq!(signer.verify(&token, 1_000).unwrap(), claims());
        assert_eq!(signer.verify(&token, 2_001), Err(TokenError::Expired));
    }

    #[test]
    fn urls_token_rejects_tampering_and_other_keys() {
        let signer = UrlSigner::new(vec![7; 32]).unwrap();
        let token = signer.sign(&claims());
        let (payload, tag) = token.split_once('.').unwrap();
        let mut forged = claims();
        forged.u = "https://evil.test/".into();
        let forged_payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&forged).unwrap());
        assert_eq!(
            signer.verify(&format!("{forged_payload}.{tag}"), 0),
            Err(TokenError::BadSignature)
        );
        let mut flipped = tag.as_bytes().to_vec();
        flipped[0] = if flipped[0] == b'A' { b'B' } else { b'A' };
        let flipped = format!("{payload}.{}", String::from_utf8(flipped).unwrap());
        assert_eq!(signer.verify(&flipped, 0), Err(TokenError::BadSignature));
        assert_eq!(signer.verify(payload, 0), Err(TokenError::Malformed));
        assert_eq!(signer.verify("", 0), Err(TokenError::Malformed));
        let other = UrlSigner::new(vec![8; 32]).unwrap();
        assert_eq!(other.verify(&token, 0), Err(TokenError::BadSignature));
        assert!(UrlSigner::new(vec![1; 31]).is_err());
    }
}

#[cfg(test)]
mod continuation_tests {
    use super::*;
    #[test]
    fn continuation_is_short_lived_and_bound_to_token_and_destination() {
        let signer = UrlSigner::new(vec![7; 32]).unwrap();
        let value = signer.continuation("original", "https://example.com/", 100);
        assert!(signer.verify_continuation(&value, "original", "https://example.com/", 101));
        assert!(!signer.verify_continuation(&value, "other", "https://example.com/", 101));
        assert!(!signer.verify_continuation(&value, "original", "https://changed.com/", 101));
        assert!(!signer.verify_continuation(&value, "original", "https://example.com/", 401));
        assert!(!signer.verify_continuation("1", "original", "https://example.com/", 101));
        assert!(signer.verify(&value, 101).is_err());
    }
}
