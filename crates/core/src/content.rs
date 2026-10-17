//! Clients that carry message content off the gateway. Every request, and
//! every redirect hop, goes through the residency guard.
//!
//! A client is a [`GuardedClient`] over an [`HttpTransport`]. The transport
//! does the HTTP and TLS work and must never follow redirects itself;
//! [`GuardedClient::send`] follows them, checking each hop, and hands the
//! transport the address it pinned so a DNS change cannot move the connection.
//! Webhooks (#42), Graph (#41), the sandbox (#28) and the LLM classifier (#32)
//! build on this.
use crate::residency::{ResidencyError, ResidencyGuard};
use async_trait::async_trait;
use std::{net::SocketAddr, sync::Arc};
use url::Url;

/// Redirect hops followed before giving up.
pub const MAX_REDIRECTS: usize = 5;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest {
    pub method: String,
    pub url: Url,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpRequest {
    pub fn new(method: &str, url: Url) -> Self {
        Self {
            method: method.into(),
            url,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

#[async_trait]
pub trait HttpTransport: Send + Sync {
    /// Send exactly one request to `peer`. Use `request.url` for the Host
    /// header and the TLS server name. Never follow redirects; return 3xx
    /// responses as they are.
    async fn send_once(
        &self,
        peer: SocketAddr,
        request: &HttpRequest,
    ) -> Result<HttpResponse, String>;
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ContentError {
    #[error(transparent)]
    Residency(#[from] ResidencyError),
    #[error("transport: {0}")]
    Transport(String),
    #[error("more than {MAX_REDIRECTS} redirects")]
    TooManyRedirects,
}

pub struct GuardedClient {
    kind: &'static str,
    base: Url,
    guard: Arc<ResidencyGuard>,
    transport: Arc<dyn HttpTransport>,
}

impl GuardedClient {
    /// Fails when `base` is outside the residency rules.
    pub fn new(
        kind: &'static str,
        guard: Arc<ResidencyGuard>,
        base: &str,
        transport: Arc<dyn HttpTransport>,
    ) -> Result<Self, ResidencyError> {
        let base = Url::parse(base).map_err(|err| ResidencyError::Invalid(err.to_string()))?;
        guard.check_request(&base)?;
        Ok(Self {
            kind,
            base,
            guard,
            transport,
        })
    }

    pub fn kind(&self) -> &'static str {
        self.kind
    }

    pub fn endpoint(&self) -> &Url {
        &self.base
    }

    /// Check, resolve and pin, send, and follow redirects (each hop checked
    /// before it is resolved). 303, and 301/302 after a POST, continue as a
    /// GET without a body; 307 and 308 keep the method and body.
    pub async fn send(&self, mut request: HttpRequest) -> Result<HttpResponse, ContentError> {
        for _ in 0..=MAX_REDIRECTS {
            let peer = self.guard.resolve(&request.url).await?;
            let response = self
                .transport
                .send_once(peer, &request)
                .await
                .map_err(ContentError::Transport)?;
            let location = match (response.status, response.header("location")) {
                (301 | 302 | 303 | 307 | 308, Some(location)) => location.to_string(),
                _ => return Ok(response),
            };
            let next = self.guard.check_redirect(&request.url, &location)?;
            if response.status == 303
                || (matches!(response.status, 301 | 302) && request.method == "POST")
            {
                request.method = "GET".into();
                request.body.clear();
            }
            request.url = next;
        }
        Err(ContentError::TooManyRedirects)
    }
}

macro_rules! content_client {
    ($name:ident, $kind:literal) => {
        pub struct $name(GuardedClient);

        impl $name {
            pub fn new(
                guard: Arc<ResidencyGuard>,
                url: &str,
                transport: Arc<dyn HttpTransport>,
            ) -> Result<Self, ResidencyError> {
                GuardedClient::new($kind, guard, url, transport).map(Self)
            }
        }

        impl std::ops::Deref for $name {
            type Target = GuardedClient;

            fn deref(&self) -> &GuardedClient {
                &self.0
            }
        }
    };
}

content_client!(SandboxClient, "sandbox");
content_client!(LlmClient, "llm");
content_client!(ObjectStoreClient, "object-store");
content_client!(WebhookClient, "webhook");

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ResidencyConfig;
    use std::sync::Mutex;

    /// Answers from a script and records where each request went.
    struct Script {
        replies: Mutex<Vec<HttpResponse>>,
        sent: Mutex<Vec<(SocketAddr, String, String)>>,
    }

    impl Script {
        fn new(mut replies: Vec<HttpResponse>) -> Arc<Self> {
            replies.reverse();
            Arc::new(Self {
                replies: Mutex::new(replies),
                sent: Mutex::new(Vec::new()),
            })
        }

        fn sent(&self) -> Vec<(SocketAddr, String, String)> {
            self.sent.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl HttpTransport for Script {
        async fn send_once(
            &self,
            peer: SocketAddr,
            request: &HttpRequest,
        ) -> Result<HttpResponse, String> {
            self.sent
                .lock()
                .unwrap()
                .push((peer, request.method.clone(), request.url.to_string()));
            self.replies
                .lock()
                .unwrap()
                .pop()
                .ok_or_else(|| "no reply".to_string())
        }
    }

    fn redirect(status: u16, location: &str) -> HttpResponse {
        HttpResponse {
            status,
            headers: vec![("Location".into(), location.into())],
            body: Vec::new(),
        }
    }

    fn ok() -> HttpResponse {
        HttpResponse {
            status: 200,
            headers: Vec::new(),
            body: b"done".to_vec(),
        }
    }

    fn guard() -> Arc<ResidencyGuard> {
        Arc::new(ResidencyGuard::from_config(&ResidencyConfig::default()).unwrap())
    }

    #[test]
    fn content_clients_refuse_a_foreign_base() {
        let transport = Script::new(Vec::new());
        let err = ObjectStoreClient::new(
            guard(),
            "https://mail.s3.us-east-1.amazonaws.com/quarantine",
            transport.clone(),
        )
        .err()
        .expect("refused");
        assert!(matches!(err, ResidencyError::Denied(_)));
        let hook = WebhookClient::new(guard(), "https://10.4.5.6/siem", transport.clone()).unwrap();
        assert_eq!(hook.kind(), "webhook");
        assert!(LlmClient::new(guard(), "https://llm.example.com/v1", transport).is_err());
    }

    #[tokio::test]
    async fn a_redirect_to_a_foreign_host_is_not_followed() {
        let transport = Script::new(vec![
            redirect(302, "/v2/hook"),
            redirect(307, "https://mail.s3.us-east-1.amazonaws.com/steal"),
            ok(),
        ]);
        let client =
            WebhookClient::new(guard(), "https://10.4.5.6/hook", transport.clone()).unwrap();
        let mut request = HttpRequest::new("POST", client.endpoint().clone());
        request.body = b"message".to_vec();
        let err = client.send(request).await.unwrap_err();
        assert!(
            matches!(err, ContentError::Residency(ResidencyError::Denied(_))),
            "{err:?}"
        );
        let sent = transport.sent();
        assert_eq!(sent.len(), 2, "{sent:?}");
        assert_eq!(sent[0].0, "10.4.5.6:443".parse().unwrap());
        // 302 after POST continues as GET on the same pinned host.
        assert_eq!(sent[1].1, "GET");
        assert_eq!(sent[1].2, "https://10.4.5.6/v2/hook");
    }

    #[tokio::test]
    async fn allowed_redirects_are_followed_and_capped() {
        let transport = Script::new(vec![redirect(308, "https://10.4.5.7/b"), ok()]);
        let client = SandboxClient::new(guard(), "https://10.4.5.6/a", transport.clone()).unwrap();
        let response = client
            .send(HttpRequest::new("PUT", client.endpoint().clone()))
            .await
            .unwrap();
        assert_eq!(response.body, b"done");
        let sent = transport.sent();
        assert_eq!(sent[1].0, "10.4.5.7:443".parse().unwrap());
        assert_eq!(sent[1].1, "PUT");

        let looping = Script::new((0..=MAX_REDIRECTS).map(|_| redirect(302, "/a")).collect());
        let client = SandboxClient::new(guard(), "https://10.4.5.6/a", looping).unwrap();
        let err = client
            .send(HttpRequest::new("GET", client.endpoint().clone()))
            .await
            .unwrap_err();
        assert_eq!(err, ContentError::TooManyRedirects);
    }
}
