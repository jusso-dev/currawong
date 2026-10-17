//! Webhooks signed with HMAC-SHA256.
//!
//! The body is `{"schema":"currawong.event.v1","events":[...]}`. The signature
//! covers `{timestamp}.{body}` and is sent as `X-Currawong-Signature: v1=<hex>`
//! with the Unix timestamp in `X-Currawong-Timestamp`.
use super::{tls, Event, ExportError, Exporter};
use currawong_core::{ResidencyGuard, Secret};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::{path::Path, sync::Arc};
use time::OffsetDateTime;
use url::Url;

pub const SIGNATURE_HEADER: &str = "x-currawong-signature";
pub const TIMESTAMP_HEADER: &str = "x-currawong-timestamp";
/// Receivers should refuse signatures older or newer than this.
pub const TOLERANCE_SECS: i64 = 300;

type HmacSha256 = Hmac<Sha256>;

pub struct WebhookExporter {
    url: Url,
    secret: Secret<Vec<u8>>,
    guard: Arc<ResidencyGuard>,
    client: reqwest::Client,
}

impl WebhookExporter {
    pub fn new(
        guard: Arc<ResidencyGuard>,
        url: &str,
        secret: Secret<Vec<u8>>,
        ca_file: Option<&Path>,
    ) -> Result<Self, ExportError> {
        if secret.expose().len() < 16 {
            return Err(ExportError::Config(
                "webhook secret must be at least 16 bytes".into(),
            ));
        }
        let url = tls::checked_url(&guard, url)?;
        let client = tls::http_client(guard.clone(), ca_file)?;
        Ok(Self {
            url,
            secret,
            guard,
            client,
        })
    }
}

/// `v1=<hex HMAC-SHA256 of "{timestamp}.{body}">`.
pub fn sign(secret: &[u8], timestamp: i64, body: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC takes any key length");
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(body);
    format!("v1={}", hex::encode(mac.finalize().into_bytes()))
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SignatureError {
    #[error("signature header is malformed")]
    Malformed,
    #[error("timestamp is outside the allowed window")]
    Stale,
    #[error("signature does not match")]
    Mismatch,
}

/// Check a received webhook. The comparison is constant time.
pub fn verify(
    secret: &[u8],
    timestamp: &str,
    body: &[u8],
    signature: &str,
    now_unix: i64,
) -> Result<(), SignatureError> {
    let ts: i64 = timestamp.parse().map_err(|_| SignatureError::Malformed)?;
    if (now_unix - ts).abs() > TOLERANCE_SECS {
        return Err(SignatureError::Stale);
    }
    let hex_sig = signature
        .strip_prefix("v1=")
        .ok_or(SignatureError::Malformed)?;
    let raw = hex::decode(hex_sig).map_err(|_| SignatureError::Malformed)?;
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC takes any key length");
    mac.update(timestamp.as_bytes());
    mac.update(b".");
    mac.update(body);
    mac.verify_slice(&raw).map_err(|_| SignatureError::Mismatch)
}

pub fn body(batch: &[Event]) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "schema": super::event::SCHEMA,
        "events": batch,
    }))
    .expect("events serialise")
}

#[async_trait::async_trait]
impl Exporter for WebhookExporter {
    fn name(&self) -> &'static str {
        "webhook"
    }

    async fn send(&self, batch: &[Event]) -> Result<(), ExportError> {
        self.guard.check(&self.url)?;
        let body = body(batch);
        let ts = OffsetDateTime::now_utc().unix_timestamp();
        let signature = sign(self.secret.expose(), ts, &body);
        let response = self
            .client
            .post(self.url.clone())
            .header("content-type", "application/json")
            .header(TIMESTAMP_HEADER, ts.to_string())
            .header(SIGNATURE_HEADER, signature)
            .body(body)
            .send()
            .await
            .map_err(|err| ExportError::Transport(tls::error_chain(&err)))?;
        if !response.status().is_success() {
            return Err(ExportError::Transport(format!(
                "webhook returned {}",
                response.status()
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::export::{event::tests::samples, testutil};
    use currawong_core::config::ResidencyConfig;

    const SECRET: &[u8] = b"test-secret-0123456789";

    fn guard() -> Arc<ResidencyGuard> {
        Arc::new(ResidencyGuard::from_config(&ResidencyConfig::default()).unwrap())
    }

    #[tokio::test]
    async fn export_webhook_signature_verifies_over_tls() {
        let dir = tempfile::tempdir().unwrap();
        let server = testutil::HttpsServer::start(dir.path(), 200, None).await;
        let exporter = WebhookExporter::new(
            guard(),
            &server.url("/hook"),
            Secret::new(SECRET.to_vec()),
            Some(&server.ca_file),
        )
        .unwrap();
        let batch = samples();
        exporter.send(&batch).await.unwrap();
        let req = server.requests.lock().unwrap().remove(0);
        assert_eq!(req.path, "/hook");
        let ts = req.header(TIMESTAMP_HEADER).unwrap();
        let sig = req.header(SIGNATURE_HEADER).unwrap();
        let now = OffsetDateTime::now_utc().unix_timestamp();
        verify(SECRET, ts, &req.body, sig, now).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&req.body).unwrap();
        assert_eq!(parsed["schema"], "currawong.event.v1");
        assert_eq!(parsed["events"].as_array().unwrap().len(), batch.len());

        let mut tampered = req.body.clone();
        tampered[10] ^= 1;
        assert_eq!(
            verify(SECRET, ts, &tampered, sig, now),
            Err(SignatureError::Mismatch)
        );
        assert_eq!(
            verify(b"another-secret-000000", ts, &req.body, sig, now),
            Err(SignatureError::Mismatch)
        );
        assert_eq!(
            verify(SECRET, ts, &req.body, sig, now + 3600),
            Err(SignatureError::Stale)
        );
    }

    #[tokio::test]
    async fn export_webhook_refuses_an_untrusted_certificate() {
        let dir = tempfile::tempdir().unwrap();
        let server = testutil::HttpsServer::start(dir.path(), 200, None).await;
        // No private CA: the self-signed test certificate must fail verification.
        let exporter = WebhookExporter::new(
            guard(),
            &server.url("/"),
            Secret::new(SECRET.to_vec()),
            None,
        )
        .unwrap();
        let err = exporter.send(&samples()).await.unwrap_err();
        assert!(matches!(err, ExportError::Transport(_)), "{err}");
        assert!(server.requests.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn export_webhook_refuses_foreign_and_plain_http_urls() {
        let secret = || Secret::new(SECRET.to_vec());
        let err = WebhookExporter::new(guard(), "https://siem.example.com/hook", secret(), None)
            .err()
            .unwrap();
        assert!(matches!(err, ExportError::Residency(_)), "{err}");
        let err = WebhookExporter::new(guard(), "http://10.0.0.5/hook", secret(), None)
            .err()
            .unwrap();
        assert!(matches!(err, ExportError::Config(_)), "{err}");
    }

    #[tokio::test]
    async fn export_webhook_redirects_are_checked_against_residency() {
        let dir = tempfile::tempdir().unwrap();
        // Only `localhost` is allowed. 127.0.0.1 is reachable but not allowed.
        let cfg = ResidencyConfig {
            allowed_cidrs: Vec::new(),
            ..ResidencyConfig::default()
        };
        let guard = Arc::new(ResidencyGuard::from_config(&cfg).unwrap());
        let target = testutil::HttpsServer::start(dir.path(), 200, None).await;
        let denied = format!("https://127.0.0.1:{}/hook", target.port);
        let redirector = testutil::HttpsServer::start(dir.path(), 307, Some(denied)).await;
        let exporter = WebhookExporter::new(
            guard.clone(),
            &redirector.url("/hook"),
            Secret::new(SECRET.to_vec()),
            Some(&redirector.ca_file),
        )
        .unwrap();
        let err = exporter.send(&samples()).await.unwrap_err();
        assert!(err.to_string().contains("Australia"), "{err}");
        assert_eq!(redirector.requests.lock().unwrap().len(), 1);
        assert!(target.requests.lock().unwrap().is_empty());

        // An allowed redirect target is followed and still signed.
        let allowed =
            testutil::HttpsServer::start(dir.path(), 307, Some(target.url("/hook"))).await;
        let exporter = WebhookExporter::new(
            guard,
            &allowed.url("/hook"),
            Secret::new(SECRET.to_vec()),
            Some(&allowed.ca_file),
        )
        .unwrap();
        // Each test server has its own CA, so trust both through one bundle.
        let bundle = dir.path().join("bundle.pem");
        let mut pem = std::fs::read(&allowed.ca_file).unwrap();
        pem.extend(std::fs::read(&target.ca_file).unwrap());
        std::fs::write(&bundle, pem).unwrap();
        let exporter = WebhookExporter {
            client: tls::http_client(exporter.guard.clone(), Some(&bundle)).unwrap(),
            ..exporter
        };
        exporter.send(&samples()).await.unwrap();
        let req = target.requests.lock().unwrap().remove(0);
        let now = OffsetDateTime::now_utc().unix_timestamp();
        verify(
            SECRET,
            req.header(TIMESTAMP_HEADER).unwrap(),
            &req.body,
            req.header(SIGNATURE_HEADER).unwrap(),
            now,
        )
        .unwrap();
    }
}
