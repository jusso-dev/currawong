//! Secure message portal. `GET /portal/{token}` shows the page, `POST
//! /portal/{token}/code` mails the recipient a six digit code and `POST
//! /portal/{token}/open` returns the message for the right code. Codes last
//! ten minutes and five wrong ones lock the message (see
//! `currawong_dlp::encrypt::portal`). Both POSTs are rate limited per client
//! address. Plain HTTP: run it behind the TLS proxy that serves
//! `encrypt.portal.base_url`; behind a proxy every client shares its address.
use async_trait::async_trait;
use axum::{
    extract::{ConnectInfo, Path, State},
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Form, Router,
};
use currawong_dlp::encrypt::{PortalError, PortalStore};
use governor::{DefaultKeyedRateLimiter, Quota, RateLimiter};
use serde::Deserialize;
use std::{
    net::{IpAddr, SocketAddr},
    num::NonZeroU32,
    sync::Arc,
};

/// Sends the one-time code to the recipient, by mail.
#[async_trait]
pub trait CodeMailer: Send + Sync {
    async fn send_code(&self, recipient: &str, code: &str) -> Result<(), String>;
}

#[derive(Clone)]
pub struct PortalState {
    pub store: Arc<PortalStore>,
    pub mailer: Arc<dyn CodeMailer>,
    limiter: Arc<DefaultKeyedRateLimiter<IpAddr>>,
}

impl PortalState {
    pub fn new(store: Arc<PortalStore>, mailer: Arc<dyn CodeMailer>, per_minute: u32) -> Self {
        let quota =
            Quota::per_minute(NonZeroU32::new(per_minute.max(1)).unwrap_or(NonZeroU32::MIN));
        Self {
            store,
            mailer,
            limiter: Arc::new(RateLimiter::keyed(quota)),
        }
    }
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
    ConnectInfo(client): ConnectInfo<SocketAddr>,
    Path(token): Path<String>,
) -> Response {
    if state.limiter.check_key(&client.ip()).is_err() {
        return too_many();
    }
    let issued = blocking(&state, {
        let token = token.clone();
        move |store| store.issue_code(&token, now())
    })
    .await;
    let (recipient, code) = match issued {
        Ok(issued) => issued,
        Err(err) => return failure(err),
    };
    if let Err(err) = state.mailer.send_code(&recipient, &code).await {
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
            escape(&mask(&recipient)),
            forms(&token)
        ),
    )
}

async fn open(
    State(state): State<PortalState>,
    ConnectInfo(client): ConnectInfo<SocketAddr>,
    Path(token): Path<String>,
    Form(form): Form<CodeForm>,
) -> Response {
    if state.limiter.check_key(&client.ip()).is_err() {
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

    #[derive(Default)]
    struct Outbox(Mutex<Vec<(String, String)>>);

    #[async_trait]
    impl CodeMailer for Outbox {
        async fn send_code(&self, recipient: &str, code: &str) -> Result<(), String> {
            self.0.lock().unwrap().push((recipient.into(), code.into()));
            Ok(())
        }
    }

    const MESSAGE: &[u8] = b"Subject: Payroll\r\n\r\nTFN 123 456 782\r\n";

    struct Portal {
        _dir: tempfile::TempDir,
        app: Router,
        outbox: Arc<Outbox>,
        token: String,
    }

    fn portal(per_minute: u32) -> Portal {
        let dir = tempfile::tempdir().unwrap();
        let store =
            PortalStore::open(&dir.path().join("held"), &dir.path().join("key"), 30).unwrap();
        let token = store
            .store("partner@partner.example.com.au", MESSAGE, now())
            .unwrap();
        let outbox = Arc::new(Outbox::default());
        let state = PortalState::new(Arc::new(store), outbox.clone(), per_minute);
        Portal {
            _dir: dir,
            app: router(state),
            outbox,
            token,
        }
    }

    impl Portal {
        async fn call(
            &self,
            method: &str,
            path: &str,
            form: &str,
        ) -> (StatusCode, Vec<u8>, Response) {
            let mut request = Request::builder()
                .method(method)
                .uri(path)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(form.to_string()))
                .unwrap();
            request
                .extensions_mut()
                .insert(ConnectInfo(SocketAddr::from(([203, 0, 113, 9], 4000))));
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
}
