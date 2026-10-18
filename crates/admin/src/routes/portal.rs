//! Secure message portal. `GET /portal/{token}` shows the page, `POST
//! /portal/{token}/code` mails the recipient a six digit code and `POST
//! /portal/{token}/open` returns the message for the right code. Codes last
//! ten minutes and five wrong ones lock the message (see
//! `currawong_dlp::encrypt::portal`). Both POSTs are rate limited per client
//! address and per message. Plain HTTP: run it behind the TLS proxy that
//! serves `encrypt.portal.base_url`. The client address comes from
//! `X-Forwarded-For` only when the peer is one of `trusted_proxies`.
use async_trait::async_trait;
use axum::{
    extract::{ConnectInfo, Path, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Form, Router,
};
use currawong_dlp::encrypt::{Issued, PortalError, PortalStore};
use governor::{DefaultKeyedRateLimiter, Quota, RateLimiter};
use ipnet::IpNet;
use serde::Deserialize;
use std::{
    net::{IpAddr, SocketAddr},
    num::NonZeroU32,
    sync::Arc,
    time::Duration,
};

/// Sends the one-time code to the recipient, by mail, along the held
/// message's route.
#[async_trait]
pub trait CodeMailer: Send + Sync {
    async fn send_code(&self, issued: &Issued) -> Result<(), String>;
}

#[derive(Clone)]
pub struct PortalState {
    pub store: Arc<PortalStore>,
    pub mailer: Arc<dyn CodeMailer>,
    per_client: Arc<DefaultKeyedRateLimiter<IpAddr>>,
    per_message: Arc<DefaultKeyedRateLimiter<String>>,
    trusted_proxies: Arc<Vec<IpNet>>,
}

impl PortalState {
    /// `per_minute` applies to each client address and to each message.
    pub fn new(
        store: Arc<PortalStore>,
        mailer: Arc<dyn CodeMailer>,
        per_minute: u32,
        trusted_proxies: Vec<IpNet>,
    ) -> Self {
        let quota =
            Quota::per_minute(NonZeroU32::new(per_minute.max(1)).unwrap_or(NonZeroU32::MIN));
        Self {
            store,
            mailer,
            per_client: Arc::new(RateLimiter::keyed(quota)),
            per_message: Arc::new(RateLimiter::keyed(quota)),
            trusted_proxies: Arc::new(trusted_proxies),
        }
    }

    /// Forget clients and messages whose buckets have refilled.
    pub fn prune(&self) {
        self.per_client.retain_recent();
        self.per_client.shrink_to_fit();
        self.per_message.retain_recent();
        self.per_message.shrink_to_fit();
    }

    /// Entries held by the limiters, for tests and metrics.
    pub fn limiter_len(&self) -> usize {
        self.per_client.len() + self.per_message.len()
    }

    /// Charge one request to the client and to the message.
    fn allow(&self, peer: IpAddr, headers: &HeaderMap, token: &str) -> bool {
        let client = client_ip(peer, headers, &self.trusted_proxies);
        self.per_client.check_key(&client).is_ok()
            && self.per_message.check_key(&token.to_string()).is_ok()
    }
}

/// The client: the peer, or when the peer is a trusted proxy, the nearest
/// `X-Forwarded-For` entry that is not one. A malformed entry stops the walk
/// there, so a client cannot hide behind a forged list.
pub fn client_ip(peer: IpAddr, headers: &HeaderMap, trusted: &[IpNet]) -> IpAddr {
    let is_trusted = |ip: &IpAddr| trusted.iter().any(|net| net.contains(ip));
    if !is_trusted(&peer) {
        return peer;
    }
    let entries: Vec<&str> = headers
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .collect();
    let mut nearest = peer;
    for entry in entries.iter().rev() {
        match entry.trim().parse::<IpAddr>() {
            Ok(ip) if is_trusted(&ip) => nearest = ip,
            Ok(ip) => return ip,
            Err(_) => break,
        }
    }
    nearest
}

pub fn router(state: PortalState) -> Router {
    Router::new()
        .route("/portal/{token}", get(show))
        .route("/portal/{token}/code", post(request_code))
        .route("/portal/{token}/open", post(open))
        .layer(axum::middleware::map_response(harden))
        .with_state(state)
}

pub async fn serve(listener: tokio::net::TcpListener, state: PortalState) {
    let pruned = state.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        loop {
            tick.tick().await;
            pruned.prune();
        }
    });
    let app = router(state).into_make_service_with_connect_info::<SocketAddr>();
    if let Err(err) = axum::serve(listener, app).await {
        tracing::error!(%err, "portal stopped");
    }
}

#[derive(Deserialize)]
struct CodeForm {
    code: String,
}

async fn show(State(state): State<PortalState>, Path(token): Path<String>) -> Response {
    let found = blocking(&state, {
        let token = token.clone();
        move |store| store.recipient(&token, now())
    })
    .await;
    match found {
        Ok(recipient) => page(
            StatusCode::OK,
            &format!(
                "<p>A secure message is held for {}.</p>{}",
                escape(&mask(&recipient)),
                forms(&token)
            ),
        ),
        Err(err) => failure(err),
    }
}

async fn request_code(
    State(state): State<PortalState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(token): Path<String>,
) -> Response {
    if !state.allow(peer.ip(), &headers, &token) {
        return too_many();
    }
    let issued = blocking(&state, {
        let token = token.clone();
        move |store| store.issue_code(&token, now())
    })
    .await;
    let issued = match issued {
        Ok(issued) => issued,
        Err(err) => return failure(err),
    };
    if let Err(err) = state.mailer.send_code(&issued).await {
        tracing::error!(%err, "portal code not sent");
        return page(
            StatusCode::SERVICE_UNAVAILABLE,
            "<p>The code could not be sent. Try again shortly.</p>",
        );
    }
    page(
        StatusCode::OK,
        &format!(
            "<p>A code was sent to {}. It works for ten minutes.</p>{}",
            escape(&mask(&issued.recipient)),
            forms(&token)
        ),
    )
}

async fn open(
    State(state): State<PortalState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(token): Path<String>,
    Form(form): Form<CodeForm>,
) -> Response {
    if !state.allow(peer.ip(), &headers, &token) {
        return too_many();
    }
    let opened = blocking(&state, move |store| {
        store.open_message(&token, &form.code, now())
    })
    .await;
    match opened {
        Ok(message) => (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, "message/rfc822"),
                (
                    header::CONTENT_DISPOSITION,
                    "attachment; filename=\"message.eml\"",
                ),
            ],
            message,
        )
            .into_response(),
        Err(err) => failure(err),
    }
}

/// Store calls read and write files, so they run off the async workers.
async fn blocking<T: Send + 'static>(
    state: &PortalState,
    call: impl FnOnce(&PortalStore) -> Result<T, PortalError> + Send + 'static,
) -> Result<T, PortalError> {
    let store = Arc::clone(&state.store);
    tokio::task::spawn_blocking(move || call(&store))
        .await
        .unwrap_or_else(|err| Err(PortalError::Store(err.to_string())))
}

fn failure(err: PortalError) -> Response {
    let status = match &err {
        PortalError::NotFound => StatusCode::NOT_FOUND,
        PortalError::Expired => StatusCode::GONE,
        PortalError::Locked => StatusCode::LOCKED,
        PortalError::WrongCode { .. } => StatusCode::FORBIDDEN,
        PortalError::NoCode => StatusCode::BAD_REQUEST,
        PortalError::RateLimited { .. } => StatusCode::TOO_MANY_REQUESTS,
        PortalError::Store(detail) => {
            tracing::error!(%detail, "portal store failed");
            return page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "<p>Something went wrong. Try again later.</p>",
            );
        }
    };
    page(
        status,
        &format!("<p>{}.</p>", escape(&capitalise(&err.to_string()))),
    )
}

fn too_many() -> Response {
    page(
        StatusCode::TOO_MANY_REQUESTS,
        "<p>Too many requests. Wait a minute and try again.</p>",
    )
}

fn forms(token: &str) -> String {
    let token = escape(token);
    format!(
        "<form method=\"post\" action=\"/portal/{token}/code\"><button>Email me a code</button></form>\
         <form method=\"post\" action=\"/portal/{token}/open\">\
         <label>Code <input name=\"code\" inputmode=\"numeric\" autocomplete=\"one-time-code\" maxlength=\"6\" required></label>\
         <button>Open message</button></form>"
    )
}

fn page(status: StatusCode, body: &str) -> Response {
    let html = format!(
        "<!doctype html><html lang=\"en-AU\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width\"><title>Secure message</title></head>\
         <body><h1>Secure message</h1>{body}</body></html>"
    );
    (
        status,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        html,
    )
        .into_response()
}

/// The token is in the URL: never send it on as a referrer, never cache.
async fn harden(mut response: Response) -> Response {
    let headers = response.headers_mut();
    for (name, value) in [
        (header::REFERRER_POLICY, "no-referrer"),
        (header::CACHE_CONTROL, "no-store"),
        (header::X_FRAME_OPTIONS, "DENY"),
        (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        (
            header::CONTENT_SECURITY_POLICY,
            "default-src 'none'; form-action 'self'; frame-ancestors 'none'",
        ),
    ] {
        headers.insert(name, HeaderValue::from_static(value));
    }
    response
}

/// `p•••@example.com.au`: enough to recognise, not to harvest.
fn mask(address: &str) -> String {
    match address.split_once('@') {
        Some((local, domain)) => {
            let first: String = local.chars().take(1).collect();
            format!("{first}•••@{domain}")
        }
        None => "•••".into(),
    }
}

fn capitalise(text: &str) -> String {
    let mut chars = text.chars();
    chars
        .next()
        .map(|c| c.to_uppercase().chain(chars).collect())
        .unwrap_or_default()
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use std::sync::Mutex;
    use tower::ServiceExt;

    use currawong_dlp::encrypt::Route;

    #[derive(Default)]
    struct Outbox(Mutex<Vec<(String, String)>>);

    #[async_trait]
    impl CodeMailer for Outbox {
        async fn send_code(&self, issued: &Issued) -> Result<(), String> {
            self.0
                .lock()
                .unwrap()
                .push((issued.recipient.clone(), issued.code.clone()));
            Ok(())
        }
    }

    const CLIENT: [u8; 4] = [203, 0, 113, 9];

    const MESSAGE: &[u8] = b"Subject: Payroll\r\n\r\nTFN 123 456 782\r\n";

    struct Portal {
        _dir: tempfile::TempDir,
        app: Router,
        state: PortalState,
        outbox: Arc<Outbox>,
        token: String,
        /// A second held message.
        other: String,
    }

    fn portal(per_minute: u32) -> Portal {
        let dir = tempfile::tempdir().unwrap();
        let store =
            PortalStore::open(&dir.path().join("held"), &dir.path().join("key"), 30).unwrap();
        let held = |rcpt: &str| {
            store
                .store(rcpt, MESSAGE, &Route::default(), now())
                .unwrap()
        };
        let token = held("partner@partner.example.com.au");
        let other = held("other@partner.example.com.au");
        let outbox = Arc::new(Outbox::default());
        let proxies = vec!["127.0.0.1/32".parse().unwrap()];
        let state = PortalState::new(Arc::new(store), outbox.clone(), per_minute, proxies);
        Portal {
            _dir: dir,
            app: router(state.clone()),
            state,
            outbox,
            token,
            other,
        }
    }

    impl Portal {
        async fn call(
            &self,
            method: &str,
            path: &str,
            form: &str,
        ) -> (StatusCode, Vec<u8>, Response) {
            self.call_from(method, path, form, CLIENT, None).await
        }

        async fn call_from(
            &self,
            method: &str,
            path: &str,
            form: &str,
            peer: [u8; 4],
            forwarded: Option<&str>,
        ) -> (StatusCode, Vec<u8>, Response) {
            let mut request = Request::builder()
                .method(method)
                .uri(path)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
            if let Some(forwarded) = forwarded {
                request = request.header("x-forwarded-for", forwarded);
            }
            let mut request = request.body(Body::from(form.to_string())).unwrap();
            request
                .extensions_mut()
                .insert(ConnectInfo(SocketAddr::from((peer, 4000))));
            let response = self.app.clone().oneshot(request).await.unwrap();
            let status = response.status();
            let (parts, body) = response.into_parts();
            let bytes = to_bytes(body, usize::MAX).await.unwrap().to_vec();
            (
                status,
                bytes.clone(),
                Response::from_parts(parts, Body::from(bytes)),
            )
        }

        async fn code(&self) -> String {
            let (status, _, _) = self
                .call("POST", &format!("/portal/{}/code", self.token), "")
                .await;
            assert_eq!(status, StatusCode::OK);
            self.outbox.0.lock().unwrap().last().unwrap().1.clone()
        }

        async fn open(&self, code: &str) -> (StatusCode, Vec<u8>, Response) {
            self.call(
                "POST",
                &format!("/portal/{}/open", self.token),
                &format!("code={code}"),
            )
            .await
        }
    }

    fn wrong(code: &str) -> String {
        format!("{:06}", (code.parse::<u32>().unwrap() + 1) % 1_000_000)
    }

    #[tokio::test]
    async fn portal_opens_with_the_mailed_code_only() {
        let portal = portal(100);
        let (status, page, response) = portal
            .call("GET", &format!("/portal/{}", portal.token), "")
            .await;
        assert_eq!(status, StatusCode::OK);
        let page = String::from_utf8(page).unwrap();
        assert!(page.contains("p•••@partner.example.com.au"), "{page}");
        assert!(!page.contains("123 456 782"));
        assert_eq!(response.headers()[header::REFERRER_POLICY], "no-referrer");
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");

        let code = portal.code().await;
        assert_eq!(
            portal.outbox.0.lock().unwrap()[0].0,
            "partner@partner.example.com.au"
        );
        let (status, body, _) = portal.open(&wrong(&code)).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(String::from_utf8(body).unwrap().contains("4 attempts left"));
        let (status, body, response) = portal.open(&code).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, MESSAGE);
        assert_eq!(response.headers()[header::CONTENT_TYPE], "message/rfc822");

        let (status, _, _) = portal
            .call("GET", &format!("/portal/{}", "a".repeat(64)), "")
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn portal_locks_after_five_wrong_codes() {
        let portal = portal(100);
        let code = portal.code().await;
        for _ in 0..4 {
            assert_eq!(portal.open(&wrong(&code)).await.0, StatusCode::FORBIDDEN);
        }
        assert_eq!(portal.open(&wrong(&code)).await.0, StatusCode::LOCKED);
        assert_eq!(portal.open(&code).await.0, StatusCode::LOCKED);
    }

    #[tokio::test]
    async fn portal_rate_limits_each_client() {
        let portal = portal(3);
        let code = portal.code().await;
        assert_eq!(portal.open(&wrong(&code)).await.0, StatusCode::FORBIDDEN);
        assert_eq!(portal.open(&wrong(&code)).await.0, StatusCode::FORBIDDEN);
        // The fourth request this minute is refused before the store sees it,
        // so it does not count towards the lock either.
        assert_eq!(portal.open(&code).await.0, StatusCode::TOO_MANY_REQUESTS);
    }

    #[test]
    fn portal_client_address_comes_from_trusted_proxies_only() {
        let trusted: Vec<IpNet> = vec![
            "127.0.0.1/32".parse().unwrap(),
            "10.0.0.0/8".parse().unwrap(),
        ];
        let headers = |value: &str| {
            let mut map = HeaderMap::new();
            map.insert("x-forwarded-for", value.parse().unwrap());
            map
        };
        let proxy: IpAddr = "127.0.0.1".parse().unwrap();
        let outsider: IpAddr = "198.51.100.7".parse().unwrap();
        // The nearest untrusted hop wins; a forged entry further left is ignored.
        let chain = headers("192.0.2.66, 198.51.100.1, 10.1.2.3");
        assert_eq!(
            client_ip(proxy, &chain, &trusted),
            "198.51.100.1".parse::<IpAddr>().unwrap()
        );
        // From an untrusted peer the header means nothing.
        assert_eq!(client_ip(outsider, &chain, &trusted), outsider);
        // A malformed entry stops the walk at the last trusted hop.
        assert_eq!(
            client_ip(proxy, &headers("192.0.2.66, junk"), &trusted),
            proxy
        );
        assert_eq!(client_ip(proxy, &HeaderMap::new(), &trusted), proxy);
    }

    #[tokio::test]
    async fn portal_clients_behind_the_proxy_have_their_own_limits() {
        let portal = portal(2);
        let proxy = [127, 0, 0, 1];
        let code = |token: &str| format!("/portal/{token}/code");
        let first = portal
            .call_from(
                "POST",
                &code(&portal.token),
                "",
                proxy,
                Some("198.51.100.1"),
            )
            .await
            .0;
        assert_eq!(first, StatusCode::OK);
        let again = portal
            .call_from(
                "POST",
                &code(&portal.token),
                "",
                proxy,
                Some("198.51.100.1"),
            )
            .await
            .0;
        assert_eq!(
            again,
            StatusCode::TOO_MANY_REQUESTS,
            "store limits a second code a minute"
        );
        let third = portal
            .call_from(
                "POST",
                &code(&portal.other),
                "",
                proxy,
                Some("198.51.100.1"),
            )
            .await
            .0;
        assert_eq!(
            third,
            StatusCode::TOO_MANY_REQUESTS,
            "client spent its two requests"
        );
        // Another client behind the same proxy is not starved.
        let other = portal
            .call_from(
                "POST",
                &code(&portal.other),
                "",
                proxy,
                Some("198.51.100.2"),
            )
            .await
            .0;
        assert_eq!(other, StatusCode::OK);
        // An untrusted peer cannot borrow a fresh address with the header:
        // its second request, for a fresh message, is still its second.
        let portal = self::portal(1);
        let open = |token: &str| format!("/portal/{token}/open");
        let mut forged = Vec::new();
        for (token, address) in [
            (&portal.token, "198.51.100.3"),
            (&portal.other, "198.51.100.4"),
        ] {
            let status = portal
                .call_from("POST", &open(token), "code=000000", CLIENT, Some(address))
                .await
                .0;
            forged.push(status);
        }
        assert_eq!(
            forged,
            [StatusCode::BAD_REQUEST, StatusCode::TOO_MANY_REQUESTS]
        );
    }

    #[tokio::test]
    async fn portal_limits_each_message_across_clients() {
        let portal = portal(2);
        let open = format!("/portal/{}/open", portal.token);
        for (i, expected) in [
            StatusCode::BAD_REQUEST,
            StatusCode::BAD_REQUEST,
            StatusCode::TOO_MANY_REQUESTS,
        ]
        .into_iter()
        .enumerate()
        {
            let client = [198, 51, 100, i as u8 + 1];
            let status = portal
                .call_from("POST", &open, "code=000000", client, None)
                .await
                .0;
            assert_eq!(status, expected, "client {i}");
        }
    }

    #[tokio::test]
    async fn portal_limiters_are_pruned() {
        let portal = portal(6000);
        for i in 0..5u8 {
            portal
                .call_from(
                    "GET",
                    &format!("/portal/{}", portal.token),
                    "",
                    [198, 51, 100, i],
                    None,
                )
                .await;
            portal
                .call_from(
                    "POST",
                    &format!("/portal/{}/open", portal.token),
                    "code=1",
                    [198, 51, 100, i],
                    None,
                )
                .await;
        }
        assert_eq!(portal.state.limiter_len(), 6);
        // 6000 a minute refills one request in 10 ms.
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        portal.state.prune();
        assert_eq!(portal.state.limiter_len(), 0);
    }
}
