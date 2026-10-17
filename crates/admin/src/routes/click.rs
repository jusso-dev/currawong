//! Click service: `GET /u/<token>` checks the link again at click time,
//! then redirects to it or shows the block page. Every verified click is
//! recorded. Plain HTTP: run it behind the TLS proxy that serves `base_url`.
use axum::{
    extract::{Path, State},
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use currawong_scan::urls::{Reputation, TokenError, UrlReputation, UrlSigner};
use serde::{Deserialize, Serialize};
use std::{
    io::Write,
    sync::{Arc, Mutex},
};

#[derive(Clone)]
pub struct ClickState {
    pub signer: UrlSigner,
    pub reputation: Arc<dyn UrlReputation>,
    pub log: Arc<ClickLog>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClickAction {
    Redirected,
    Blocked,
}

/// One click. No client address or user agent is kept.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClickEvent {
    /// Unix seconds.
    pub at: u64,
    pub message_id: String,
    pub url: String,
    pub action: ClickAction,
    pub reason: String,
}

/// Append-only JSON lines file of click events.
pub struct ClickLog {
    file: Mutex<std::fs::File>,
}

impl ClickLog {
    pub fn open(path: &std::path::Path) -> std::io::Result<Self> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        Ok(Self {
            file: Mutex::new(file),
        })
    }

    pub fn record(&self, event: &ClickEvent) {
        tracing::info!(
            id = %event.message_id,
            action = ?event.action,
            reason = %event.reason,
            "link clicked"
        );
        let mut line = serde_json::to_vec(event).expect("event serialises");
        line.push(b'\n');
        let mut file = self.file.lock().unwrap_or_else(|p| p.into_inner());
        if let Err(err) = file.write_all(&line) {
            tracing::error!(%err, "click event not recorded");
        }
    }
}

pub fn router(state: ClickState) -> Router {
    Router::new()
        .route("/u/{token}", get(click))
        .with_state(state)
}

pub async fn serve(listener: tokio::net::TcpListener, state: ClickState) {
    if let Err(err) = axum::serve(listener, router(state)).await {
        tracing::error!(%err, "click service stopped");
    }
}

async fn click(State(state): State<ClickState>, Path(token): Path<String>) -> Response {
    let now = now();
    let claims = match state.signer.verify(&token, now) {
        Ok(claims) => claims,
        Err(TokenError::Expired) => {
            return page(
                StatusCode::GONE,
                "This link has expired",
                "Links in email stop working after a while. Ask the sender to send it again.",
            )
        }
        Err(err) => {
            tracing::warn!(%err, "click with a bad token");
            return page(
                StatusCode::BAD_REQUEST,
                "This link is not valid",
                "The link was changed or damaged after it was delivered.",
            );
        }
    };
    let verdict = state.reputation.check(&claims.u).await;
    let (action, reason) = match &verdict {
        Reputation::Clean => (ClickAction::Redirected, String::new()),
        Reputation::Blocked { reason } => (ClickAction::Blocked, reason.clone()),
    };
    state.log.record(&ClickEvent {
        at: now,
        message_id: claims.m,
        url: claims.u.clone(),
        action,
        reason: reason.clone(),
    });
    if action == ClickAction::Blocked {
        let detail = format!(
            "Currawong stopped this link because it is now known to be unsafe ({}). The link was <code>{}</code>. If you think this is a mistake, contact your IT team.",
            escape(&reason),
            escape(&claims.u)
        );
        return page(StatusCode::FORBIDDEN, "This link has been blocked", &detail);
    }
    match HeaderValue::from_str(&claims.u) {
        Ok(location) => (
            StatusCode::FOUND,
            [
                (header::LOCATION, location),
                (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
                (
                    header::REFERRER_POLICY,
                    HeaderValue::from_static("no-referrer"),
                ),
            ],
        )
            .into_response(),
        Err(_) => page(
            StatusCode::BAD_REQUEST,
            "This link is not valid",
            "The link cannot be followed.",
        ),
    }
}

/// `detail` is HTML: callers escape anything that came from a message.
fn page(status: StatusCode, title: &str, detail: &str) -> Response {
    let body = format!(
        "<!doctype html>\n<html lang=\"en-AU\"><head><meta charset=\"utf-8\"><meta name=\"robots\" content=\"noindex\"><title>{title}</title></head>\n<body><h1>{title}</h1>\n<p>{detail}</p></body></html>\n"
    );
    (
        status,
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/html; charset=utf-8"),
            ),
            (
                header::CONTENT_SECURITY_POLICY,
                HeaderValue::from_static("default-src 'none'"),
            ),
            (
                header::X_CONTENT_TYPE_OPTIONS,
                HeaderValue::from_static("nosniff"),
            ),
            (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
            (
                header::REFERRER_POLICY,
                HeaderValue::from_static("no-referrer"),
            ),
        ],
        body,
    )
        .into_response()
}

fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}
