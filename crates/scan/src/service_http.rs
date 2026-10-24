//! Bounded, pinned HTTP for on-premises content engines. Never use an
//! environment proxy or follow redirects with message bytes or secrets.
use crate::EngineResult;
use currawong_core::{residency::ResidencyGuard, Secret};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use std::{io::Read, path::Path, sync::Arc, time::Duration};
use url::Url;

#[derive(Debug, Clone, thiserror::Error)]
#[error("{reason}")]
pub struct ServiceError {
    pub reason: String,
    pub unreachable: bool,
}

impl ServiceError {
    pub fn invalid(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
            unreachable: false,
        }
    }
    pub fn unavailable(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
            unreachable: true,
        }
    }
    pub fn engine_result(&self) -> EngineResult {
        EngineResult::Failed {
            reason: self.reason.clone(),
            unreachable: self.unreachable,
        }
    }
}

pub(crate) fn credential(path: Option<&Path>) -> Result<Option<Secret<String>>, String> {
    let Some(path) = path else { return Ok(None) };
    let file = std::fs::File::open(path).map_err(|_| "engine credential file cannot be read")?;
    let mut bytes = Vec::new();
    file.take(16 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "engine credential file cannot be read")?;
    if bytes.len() > 16 * 1024 {
        return Err("engine credential file is too large".into());
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| "engine credential must be UTF-8")?
        .trim();
    if text.is_empty() || !text.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
        return Err(
            "engine credential must be non-empty printable ASCII without whitespace".into(),
        );
    }
    Ok(Some(Secret::new(text.into())))
}

pub(crate) struct EngineHttp {
    base: Url,
    guard: Arc<ResidencyGuard>,
    timeout: Duration,
    on_premises: bool,
}

impl EngineHttp {
    pub fn new(
        base: &str,
        guard: Arc<ResidencyGuard>,
        timeout: Duration,
        on_premises: bool,
    ) -> Result<Self, String> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut base = Url::parse(base).map_err(|_| "invalid engine URL")?;
        if !matches!(base.scheme(), "http" | "https")
            || base.host_str().is_none()
            || !base.username().is_empty()
            || base.password().is_some()
            || base.query().is_some()
            || base.fragment().is_some()
        {
            return Err("engine URL must be HTTP(S) without credentials, query or fragment".into());
        }
        if !base.path().ends_with('/') {
            base.set_path(&format!("{}/", base.path()));
        }
        guard
            .check_request(&base)
            .map_err(|_| "engine endpoint denied by residency")?;
        Ok(Self {
            base,
            guard,
            timeout,
            on_premises,
        })
    }
    pub fn endpoint(&self, path: &str) -> Url {
        self.base.join(path).expect("static engine API path")
    }
    pub async fn send(
        &self,
        method: reqwest::Method,
        path: &str,
        headers: &[(String, String)],
        body: Vec<u8>,
        max_response: usize,
    ) -> Result<Vec<u8>, ServiceError> {
        tokio::time::timeout(
            self.timeout,
            self.send_inner(method, path, headers, body, max_response),
        )
        .await
        .map_err(|_| ServiceError::unavailable("engine request timed out"))?
    }
    async fn send_inner(
        &self,
        method: reqwest::Method,
        path: &str,
        headers: &[(String, String)],
        body: Vec<u8>,
        max_response: usize,
    ) -> Result<Vec<u8>, ServiceError> {
        let url = self.endpoint(path);
        self.guard
            .check_request(&url)
            .map_err(|_| ServiceError::invalid("engine request denied by residency"))?;
        let peer = self.guard.resolve(&url).await.map_err(|_| {
            ServiceError::unavailable("engine endpoint resolution failed or denied by residency")
        })?;
        if self.on_premises && !on_premises(peer.ip()) {
            return Err(ServiceError::invalid(
                "sandbox must resolve to an on-premises address",
            ));
        }
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .resolve(url.host_str().unwrap_or_default(), peer)
            .timeout(self.timeout)
            .build()
            .map_err(|_| ServiceError::invalid("engine HTTP client unavailable"))?;
        let mut map = HeaderMap::new();
        for (name, value) in headers {
            let key = HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| ServiceError::invalid("invalid engine header name"))?;
            let mut value = HeaderValue::from_str(value)
                .map_err(|_| ServiceError::invalid("invalid engine header value"))?;
            if key == "password" || key == "authorization" {
                value.set_sensitive(true);
            }
            map.append(key, value);
        }
        let mut response = client
            .request(method, url.clone())
            .headers(map)
            .body(body)
            .send()
            .await
            .map_err(|_| ServiceError::unavailable("engine HTTP request failed"))?;
        if response.status().is_redirection() {
            if let Some(location) = response
                .headers()
                .get("location")
                .and_then(|v| v.to_str().ok())
            {
                self.guard
                    .check_redirect(&url, location)
                    .map_err(|_| ServiceError::invalid("engine redirect denied by residency"))?;
            }
            return Err(ServiceError::invalid("engine redirects are disabled"));
        }
        if !response.status().is_success() {
            return Err(ServiceError::unavailable(format!(
                "engine HTTP status {}",
                response.status().as_u16()
            )));
        }
        if response
            .content_length()
            .is_some_and(|n| n > max_response as u64)
        {
            return Err(ServiceError::invalid("engine response exceeds size limit"));
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| ServiceError::unavailable("engine response interrupted"))?
        {
            if chunk.len() > max_response.saturating_sub(bytes.len()) {
                return Err(ServiceError::invalid("engine response exceeds size limit"));
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes)
    }
}

fn on_premises(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(ip) => ip.is_loopback() || ip.is_private() || ip.is_link_local(),
        std::net::IpAddr::V6(ip) => {
            ip.is_loopback()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
                || ip.to_ipv4_mapped().is_some_and(|ip| on_premises(ip.into()))
        }
    }
}
