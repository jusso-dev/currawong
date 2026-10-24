//! Rspamd HTTP protocol: https://docs.rspamd.com/developers/protocol/.
use crate::service_http::{credential, EngineHttp, ServiceError};
use currawong_core::{
    config::RspamdConfig, residency::ResidencyGuard, RspamdResult, RspamdSymbol, Secret,
};
use serde::Deserialize;
use std::{collections::BTreeMap, sync::Arc, time::Duration};

const MAX_RESPONSE: usize = 1024 * 1024;
pub const MAX_SYMBOLS: usize = 256;

pub struct RspamdClient {
    scan: EngineHttp,
    controller: Option<EngineHttp>,
    password: Option<Secret<String>>,
    max_size: usize,
}

pub struct MessageMetadata<'a> {
    pub ip: &'a str,
    pub helo: &'a str,
    pub hostname: &'a str,
    pub from: &'a str,
    pub recipients: &'a [String],
    pub queue_id: &'a str,
    pub user: Option<&'a str>,
}

impl RspamdClient {
    pub fn new(cfg: &RspamdConfig, guard: Arc<ResidencyGuard>) -> Result<Self, String> {
        let timeout = Duration::from_secs(cfg.timeout_secs);
        Ok(Self {
            scan: EngineHttp::new(&cfg.url, guard.clone(), timeout, false)?,
            controller: if cfg.controller_url.is_empty() {
                None
            } else {
                Some(EngineHttp::new(&cfg.controller_url, guard, timeout, false)?)
            },
            password: credential(cfg.password_file.as_deref())?,
            max_size: cfg.max_size,
        })
    }
    fn headers(&self) -> Vec<(String, String)> {
        let mut headers = vec![("Content-Type".into(), "message/rfc822".into())];
        if let Some(password) = &self.password {
            headers.push(("Password".into(), password.expose().clone()));
        }
        headers
    }
    pub async fn scan_message(
        &self,
        raw: &[u8],
        meta: MessageMetadata<'_>,
    ) -> Result<RspamdResult, ServiceError> {
        if raw.len() > self.max_size {
            return Err(ServiceError::invalid("message exceeds Rspamd max_size"));
        }
        let mut headers = self.headers();
        for (name, value) in [
            ("IP", meta.ip),
            ("Helo", meta.helo),
            ("Hostname", meta.hostname),
            ("From", meta.from),
            ("Queue-Id", meta.queue_id),
        ] {
            headers.push((name.into(), value.into()));
        }
        for recipient in meta.recipients {
            headers.push(("Rcpt".into(), recipient.clone()));
        }
        if let Some(user) = meta.user {
            headers.push(("User".into(), user.into()));
        }
        let body = self
            .scan
            .send(
                reqwest::Method::POST,
                "checkv2",
                &headers,
                raw.to_vec(),
                MAX_RESPONSE,
            )
            .await?;
        parse(&body)
    }
    /// Optional controller learning. Never infer its port from the scan URL.
    pub async fn learn(&self, raw: &[u8], spam: bool) -> Result<(), ServiceError> {
        let Some(controller) = &self.controller else {
            return Ok(());
        };
        if raw.len() > self.max_size {
            return Err(ServiceError::invalid("message exceeds Rspamd max_size"));
        }
        let body = controller
            .send(
                reqwest::Method::POST,
                if spam { "learnspam" } else { "learnham" },
                &self.headers(),
                raw.to_vec(),
                MAX_RESPONSE,
            )
            .await?;
        let value: serde_json::Value = serde_json::from_slice(&body)
            .map_err(|_| ServiceError::invalid("invalid Rspamd learning JSON"))?;
        if value.get("success").and_then(|v| v.as_bool()) != Some(true) {
            return Err(ServiceError::invalid(
                "Rspamd learning was not acknowledged",
            ));
        }
        Ok(())
    }
    pub async fn ping(&self) -> Result<(), String> {
        let body = self
            .scan
            .send(
                reqwest::Method::GET,
                "ping",
                &self.headers(),
                Vec::new(),
                1024,
            )
            .await
            .map_err(|e| e.to_string())?;
        if body.starts_with(b"pong") {
            Ok(())
        } else {
            Err("Rspamd ping did not return pong".into())
        }
    }
}

#[derive(Deserialize)]
struct Response {
    score: f64,
    required_score: f64,
    action: String,
    symbols: BTreeMap<String, Symbol>,
    #[serde(default)]
    messages: serde_json::Value,
    #[serde(default)]
    is_skipped: bool,
}
#[derive(Deserialize)]
struct Symbol {
    score: f64,
    #[serde(default)]
    options: Vec<String>,
}
pub fn phishing_symbol(name: &str) -> bool {
    name.eq_ignore_ascii_case("PHISHING") || name.to_ascii_uppercase().starts_with("PHISHED_")
}
fn parse(bytes: &[u8]) -> Result<RspamdResult, ServiceError> {
    let response: Response = serde_json::from_slice(bytes)
        .map_err(|_| ServiceError::invalid("invalid Rspamd scan JSON"))?;
    if response.is_skipped {
        return Err(ServiceError::unavailable("Rspamd skipped scanning"));
    }
    if !response.score.is_finite()
        || !response.required_score.is_finite()
        || response.required_score < 0.0
    {
        return Err(ServiceError::invalid("invalid Rspamd scores"));
    }
    let action = response.action.replace(' ', "_").to_ascii_lowercase();
    if !matches!(
        action.as_str(),
        "reject" | "add_header" | "rewrite_subject" | "greylist" | "soft_reject" | "no_action"
    ) {
        return Err(ServiceError::invalid("unsupported Rspamd action"));
    }
    let mut symbols: Vec<_> = response
        .symbols
        .into_iter()
        .map(|(name, s)| RspamdSymbol {
            name,
            score: s.score,
            options: s.options,
        })
        .collect();
    // Retain phishing evidence even when an upstream configuration produces
    // more symbols than the bounded report/policy budget.
    symbols.sort_by_key(|s| (s.score <= 0.0, !phishing_symbol(&s.name), s.name.clone()));
    symbols.truncate(MAX_SYMBOLS);
    Ok(RspamdResult {
        score: response.score,
        required_score: response.required_score,
        action,
        symbols,
        messages: response.messages,
    })
}
