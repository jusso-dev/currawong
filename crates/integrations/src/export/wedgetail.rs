//! Wedgetail connector: OCSF events over HTTPS with a bearer token.
//!
//! Wedgetail's own ingest API was not available when this was written (see
//! `docs/VALIDATION.md`), so this follows the fallback in issue #42: a JSON
//! array of OCSF 1.3 events, `POST`ed to the configured URL.
use super::{tls, Event, EventKind, ExportError, Exporter};
use currawong_core::{ResidencyGuard, Secret};
use serde_json::{json, Value};
use std::{path::Path, sync::Arc};
use url::Url;

pub const OCSF_VERSION: &str = "1.3.0";
const EMAIL_ACTIVITY: u32 = 4009;
const EMAIL_URL_ACTIVITY: u32 = 4012;
const API_ACTIVITY: u32 = 6003;

pub struct WedgetailExporter {
    url: Url,
    token: Secret<String>,
    guard: Arc<ResidencyGuard>,
    client: reqwest::Client,
}

impl WedgetailExporter {
    pub fn new(
        guard: Arc<ResidencyGuard>,
        url: &str,
        token: Secret<String>,
        ca_file: Option<&Path>,
    ) -> Result<Self, ExportError> {
        let url = tls::checked_url(&guard, url)?;
        let client = tls::http_client(guard.clone(), ca_file)?;
        Ok(Self {
            url,
            token,
            guard,
            client,
        })
    }
}

#[async_trait::async_trait]
impl Exporter for WedgetailExporter {
    fn name(&self) -> &'static str {
        "wedgetail"
    }

    async fn send(&self, batch: &[Event]) -> Result<(), ExportError> {
        self.guard.check(&self.url)?;
        let body: Vec<Value> = batch.iter().map(ocsf).collect();
        let response = self
            .client
            .post(self.url.clone())
            .bearer_auth(self.token.expose())
            .header("content-type", "application/json")
            .body(serde_json::to_vec(&body).expect("OCSF serialises"))
            .send()
            .await
            .map_err(|err| ExportError::Transport(tls::error_chain(&err)))?;
        if !response.status().is_success() {
            return Err(ExportError::Transport(format!(
                "wedgetail returned {}",
                response.status()
            )));
        }
        Ok(())
    }
}

/// Map one event onto OCSF. The original event is kept under `unmapped.currawong`.
pub fn ocsf(event: &Event) -> Value {
    let (class_uid, activity_id, disposition_id, extra) = match &event.kind {
        EventKind::MessageVerdict {
            message_id,
            direction,
            mail_from,
            rcpt_to,
            verdict,
            ..
        } => (
            EMAIL_ACTIVITY,
            3, // Scan
            verdict_disposition(verdict),
            json!({
                "direction_id": if direction == "outbound" { 2 } else { 1 },
                "email": { "uid": message_id, "from": mail_from, "to": rcpt_to },
            }),
        ),
        EventKind::VerdictChanged { message_id, to, .. } => (
            EMAIL_ACTIVITY,
            99, // Other
            verdict_disposition(to),
            json!({ "email": { "uid": message_id } }),
        ),
        EventKind::QuarantineRelease {
            message_id,
            rcpt_to,
            ..
        } => (
            EMAIL_ACTIVITY,
            99,
            9, // Restored
            json!({ "email": { "uid": message_id, "to": rcpt_to } }),
        ),
        EventKind::UrlClick {
            message_id,
            url,
            action,
            ..
        } => (
            EMAIL_URL_ACTIVITY,
            3,
            if action == "blocked" { 2 } else { 1 },
            json!({ "email_uid": message_id, "url": { "url_string": url } }),
        ),
        EventKind::AdminAction { actor, action, .. } => (
            API_ACTIVITY,
            99,
            0,
            json!({ "actor": { "user": { "name": actor } }, "api": { "operation": action } }),
        ),
    };
    let mut out = json!({
        "class_uid": class_uid,
        "category_uid": class_uid / 1000,
        "activity_id": activity_id,
        "type_uid": class_uid * 100 + activity_id,
        "time": event.unix_millis() as i64,
        "severity_id": ocsf_severity(event.severity()),
        "disposition_id": disposition_id,
        "message": event.type_name(),
        "metadata": {
            "version": OCSF_VERSION,
            "uid": event.id,
            "tenant_uid": event.tenant_id,
            "product": {
                "name": "Currawong Gateway",
                "vendor_name": "Currawong",
                "version": env!("CARGO_PKG_VERSION"),
            },
        },
        "unmapped": { "currawong": event },
    });
    if let (Some(out), Some(extra)) = (out.as_object_mut(), extra.as_object()) {
        out.extend(extra.clone());
    }
    out
}

fn verdict_disposition(verdict: &str) -> u32 {
    match verdict {
        "deliver" => 1,    // Allowed
        "reject" => 2,     // Blocked
        "quarantine" => 3, // Quarantined
        "discard" => 6,    // Dropped
        "defer" => 14,     // Delayed
        _ => 0,
    }
}

/// CEF 0 to 10 onto OCSF severity_id 1 (informational) to 5 (critical).
fn ocsf_severity(cef: u8) -> u8 {
    match cef {
        0..=1 => 1,
        2..=3 => 2,
        4..=6 => 3,
        7..=8 => 4,
        _ => 5,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::export::{event::tests::samples, testutil};
    use currawong_core::config::ResidencyConfig;

    fn guard() -> Arc<ResidencyGuard> {
        Arc::new(ResidencyGuard::from_config(&ResidencyConfig::default()).unwrap())
    }

    #[test]
    fn export_ocsf_mapping_for_a_verdict() {
        let value = ocsf(&samples()[0]);
        assert_eq!(value["class_uid"], 4009);
        assert_eq!(value["category_uid"], 4);
        assert_eq!(value["type_uid"], 400903);
        assert_eq!(value["disposition_id"], 3);
        assert_eq!(value["direction_id"], 1);
        assert_eq!(value["email"]["from"], "billing@example.net");
        assert_eq!(value["metadata"]["version"], OCSF_VERSION);
        assert_eq!(value["unmapped"]["currawong"]["type"], "message_verdict");
    }

    #[tokio::test]
    async fn export_wedgetail_posts_ocsf_with_bearer_token() {
        let dir = tempfile::tempdir().unwrap();
        let server = testutil::HttpsServer::start(dir.path(), 202, None).await;
        let exporter = WedgetailExporter::new(
            guard(),
            &server.url("/api/ingest/ocsf"),
            Secret::new("wt-test-token".into()),
            Some(&server.ca_file),
        )
        .unwrap();
        exporter.send(&samples()).await.unwrap();
        let req = server.requests.lock().unwrap().remove(0);
        assert_eq!(req.path, "/api/ingest/ocsf");
        assert_eq!(req.header("authorization"), Some("Bearer wt-test-token"));
        let body: Vec<Value> = serde_json::from_slice(&req.body).unwrap();
        assert_eq!(body.len(), samples().len());
        assert_eq!(body[1]["class_uid"], 4012);
    }

    #[test]
    fn export_wedgetail_refuses_a_foreign_endpoint() {
        let err = WedgetailExporter::new(
            guard(),
            "https://wedgetail.example.com/api",
            Secret::new("t".into()),
            None,
        )
        .err()
        .unwrap();
        assert!(matches!(err, ExportError::Residency(_)), "{err}");
    }
}
