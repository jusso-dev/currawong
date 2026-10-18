//! Click service: `GET /u/<token>` checks the link again at click time,
//! then redirects to it, shows the warning page or shows the block page.
//! Every verified click is recorded and sent to the event bus as
//! `url_click`. `HEAD` (link previews and prefetchers) is answered without
//! checking or recording; a prefetcher that sends `GET` is counted as a
//! click. Plain HTTP: run it behind the TLS proxy that serves `base_url`.
use axum::{
    extract::{ConnectInfo, Path, Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use currawong_integrations::export::{self, Event, EventKind};
use currawong_scan::urls::{Reputation, TokenError, UrlReputation, UrlSigner};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    hash::Hash,
    io::Write,
    net::{IpAddr, SocketAddr},
    path::{Path as FsPath, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

/// A token with no recipient list was sent to more than fit in it.
const UNLISTED_RECIPIENTS: u32 = 50;
/// Each limiter forgets idle keys once it holds this many.
const MAX_KEYS: usize = 50_000;

/// Click rate limits. Only clicks on verified tokens count, so junk tokens
/// cannot use up anyone's allowance.
#[derive(Debug, Clone)]
pub struct ClickLimits {
    /// Clicks per minute from one client address.
    pub per_client: u32,
    /// Clicks per minute on one link per recipient of its message.
    pub per_link: u32,
    /// Peers whose `X-Forwarded-For` is believed: the TLS proxy in front.
    pub trusted_proxies: Vec<ipnet::IpNet>,
}

impl Default for ClickLimits {
    fn default() -> Self {
        Self {
            per_client: 600,
            per_link: 30,
            trusted_proxies: Vec::new(),
        }
    }
}

/// Fixed one-minute windows per key.
struct Windows<K> {
    hits: Mutex<HashMap<K, (Instant, u32)>>,
}

impl<K: Eq + Hash> Windows<K> {
    fn new() -> Self {
        Self {
            hits: Mutex::new(HashMap::new()),
        }
    }

    fn hit(&self, key: K, limit: u32) -> bool {
        let mut hits = self.hits.lock().unwrap_or_else(|p| p.into_inner());
        if hits.len() > MAX_KEYS {
            hits.retain(|_, (start, _)| start.elapsed() < WINDOW);
        }
        let entry = hits.entry(key).or_insert((Instant::now(), 0));
        if entry.0.elapsed() >= WINDOW {
            *entry = (Instant::now(), 0);
        }
        entry.1 = entry.1.saturating_add(1);
        entry.1 <= limit
    }
}

const WINDOW: Duration = Duration::from_secs(60);

#[derive(Clone)]
pub struct ClickState {
    pub signer: UrlSigner,
    pub reputation: Arc<dyn UrlReputation>,
    pub log: Arc<ClickLog>,
    limits: Arc<ClickLimits>,
    windows: Arc<(Windows<IpAddr>, Windows<[u8; 32]>)>,
}

impl ClickState {
    pub fn new(
        signer: UrlSigner,
        reputation: Arc<dyn UrlReputation>,
        log: ClickLog,
        limits: ClickLimits,
    ) -> Self {
        Self {
            signer,
            reputation,
            log: Arc::new(log),
            limits: Arc::new(limits),
            windows: Arc::new((Windows::new(), Windows::new())),
        }
    }

    /// One verified click from `client` on `token`, whose message went to
    /// `recipients` (comma separated, empty when there were too many).
    fn allowed(&self, client: IpAddr, token: &str, recipients: &str) -> bool {
        let (per_client, per_link) = &*self.windows;
        let share = match recipients {
            "" => UNLISTED_RECIPIENTS,
            list => list.split(',').count().min(u32::MAX as usize) as u32,
        };
        let key: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        let client_ok = per_client.hit(client, self.limits.per_client);
        let link_ok = per_link.hit(key, self.limits.per_link.saturating_mul(share));
        client_ok && link_ok
    }

    /// The clicking client: the peer, or when the peer is a trusted proxy,
    /// the nearest untrusted address in `X-Forwarded-For`.
    fn client(&self, peer: IpAddr, headers: &HeaderMap) -> IpAddr {
        let trusted = |ip: &IpAddr| {
            self.limits
                .trusted_proxies
                .iter()
                .any(|net| net.contains(ip))
        };
        if !trusted(&peer) {
            return peer;
        }
        let chain: Vec<IpAddr> = headers
            .get_all("x-forwarded-for")
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|value| value.split(','))
            .filter_map(|hop| hop.trim().parse().ok())
            .collect();
        chain
            .iter()
            .rev()
            .find(|ip| !trusted(ip))
            .or(chain.first())
            .copied()
            .unwrap_or(peer)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClickAction {
    Redirected,
    Warned,
    Blocked,
}

/// One click. No client address or user agent is kept.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClickEvent {
    /// Unix seconds.
    pub at: u64,
    pub message_id: String,
    #[serde(default)]
    pub recipient: String,
    pub url: String,
    pub action: ClickAction,
    pub reason: String,
}

/// Append-only JSON lines file of click events, mode 0600. When it passes
/// `max_bytes` it is renamed to `<name>.1` (replacing the previous one) and
/// a new file is started.
pub struct ClickLog {
    path: PathBuf,
    max_bytes: u64,
    file: Mutex<std::fs::File>,
}

impl ClickLog {
    pub fn open(path: &FsPath, max_bytes: u64) -> std::io::Result<Self> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        Ok(Self {
            path: path.to_path_buf(),
            max_bytes,
            file: Mutex::new(open_log(path)?),
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
        let full = file
            .metadata()
            .is_ok_and(|meta| meta.len() + line.len() as u64 > self.max_bytes);
        if full {
            let mut rotated = self.path.clone().into_os_string();
            rotated.push(".1");
            match std::fs::rename(&self.path, &rotated).and_then(|_| open_log(&self.path)) {
                Ok(fresh) => *file = fresh,
                Err(err) => tracing::error!(%err, "click log not rotated"),
            }
        }
        if let Err(err) = file.write_all(&line) {
            tracing::error!(%err, "click event not recorded");
        }
    }
}

fn open_log(path: &FsPath) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options.open(path)
}

pub fn router(state: ClickState) -> Router {
    Router::new()
        .route("/u/{token}", get(click).head(preview))
        .with_state(state)
}

pub async fn serve(listener: tokio::net::TcpListener, state: ClickState) {
    let app = router(state).into_make_service_with_connect_info::<SocketAddr>();
    if let Err(err) = axum::serve(listener, app).await {
        tracing::error!(%err, "click service stopped");
    }
}

async fn preview() -> Response {
    (
        StatusCode::OK,
        [(header::CACHE_CONTROL, HeaderValue::from_static("no-store"))],
    )
        .into_response()
}

#[derive(Deserialize)]
struct ClickQuery {
    /// Set by the warning page's continue link.
    #[serde(default)]
    proceed: Option<String>,
}

async fn click(
    State(state): State<ClickState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(token): Path<String>,
    Query(query): Query<ClickQuery>,
) -> Response {
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
    let client = state.client(peer.ip(), &headers);
    if !state.allowed(client, &token, &claims.r) {
        return page(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many clicks",
            "Wait a minute and try the link again.",
        );
    }
    let proceed = query.proceed.is_some();
    let (action, reason) = match state.reputation.check(&claims.u).await {
        Reputation::Clean => (ClickAction::Redirected, String::new()),
        Reputation::Warn { reason } if proceed => (
            ClickAction::Redirected,
            format!("continued past a warning: {reason}"),
        ),
        Reputation::Warn { reason } => (ClickAction::Warned, reason),
        Reputation::Blocked { reason } => (ClickAction::Blocked, reason),
    };
    let event = ClickEvent {
        at: now,
        message_id: claims.m,
        recipient: claims.r,
        url: claims.u,
        action,
        reason,
    };
    state.log.record(&event);
    export::emit(Event::new(
        None,
        EventKind::UrlClick {
            message_id: event.message_id.clone(),
            recipient: event.recipient.clone(),
            url: event.url.clone(),
            action: match action {
                ClickAction::Redirected => "allowed",
                ClickAction::Warned => "warned",
                ClickAction::Blocked => "blocked",
            }
            .into(),
        },
    ));
    let link = escape(&event.url);
    let reason = escape(&event.reason);
    match action {
        ClickAction::Blocked => page(
            StatusCode::FORBIDDEN,
            "This link has been blocked",
            &format!("Currawong stopped this link because it is now known to be unsafe ({reason}). The link was <code>{link}</code>. If you think this is a mistake, contact your IT team."),
        ),
        ClickAction::Warned => page(
            StatusCode::OK,
            "Check this link before you continue",
            &format!("Currawong has not confirmed this link is safe ({reason}). It goes to <code>{link}</code>. Continue only if you expected it. <a href=\"/u/{token}?proceed=1\" rel=\"noreferrer\">Continue to the site</a>"),
        ),
        ClickAction::Redirected => match HeaderValue::from_str(&event.url) {
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
        },
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
                HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'"),
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
