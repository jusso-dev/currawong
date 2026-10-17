//! JSON logs, Prometheus metrics and the health endpoints.
use crate::config::LogConfig;
use async_trait::async_trait;
use axum::{extract::State, http::StatusCode, routing::get, Router};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use std::{
    net::SocketAddr,
    sync::{Arc, OnceLock},
    time::Duration,
};
use tracing_subscriber::{fmt::MakeWriter, util::SubscriberInitExt, EnvFilter};

pub const SMTP_CONNECTIONS_TOTAL: &str = "currawong_smtp_connections_total";
pub const MESSAGES_ACCEPTED_TOTAL: &str = "currawong_messages_accepted_total";
pub const MESSAGES_REJECTED_TOTAL: &str = "currawong_messages_rejected_total";
pub const SPOOL_DEPTH: &str = "currawong_spool_depth";
pub const SCAN_DURATION_SECONDS: &str = "currawong_scan_duration_seconds";
pub const RESIDENCY_REPORT_FAILURES_TOTAL: &str = "currawong_residency_report_failures_total";

/// Each readiness check gets this long before `/readyz` reports it as failed.
pub const READY_TIMEOUT: Duration = Duration::from_secs(2);

#[async_trait]
pub trait ReadinessCheck: Send + Sync {
    fn name(&self) -> &'static str;
    async fn check(&self) -> Result<(), String>;
}

#[derive(Clone)]
struct HealthState {
    checks: Arc<Vec<Arc<dyn ReadinessCheck>>>,
    /// Caps `/readyz` evaluations in flight; extra callers get 503 at once.
    slots: Arc<tokio::sync::Semaphore>,
}

/// `/readyz` evaluations allowed at the same time.
pub const MAX_READYZ: usize = 4;

static RECORDER: OnceLock<PrometheusHandle> = OnceLock::new();

/// `RUST_LOG`, when set and valid, wins over `log.level`.
fn env_filter(cfg: &LogConfig, rust_log: Option<&str>) -> EnvFilter {
    rust_log
        .and_then(|value| EnvFilter::try_new(value).ok())
        .or_else(|| EnvFilter::try_new(&cfg.level).ok())
        .unwrap_or_else(|| EnvFilter::new("info"))
}

/// The subscriber `init_tracing` installs, writing to `writer`.
pub fn subscriber<W>(
    cfg: &LogConfig,
    rust_log: Option<&str>,
    writer: W,
) -> Box<dyn tracing::Subscriber + Send + Sync>
where
    W: for<'a> MakeWriter<'a> + Send + Sync + 'static,
{
    let builder = tracing_subscriber::fmt()
        .with_env_filter(env_filter(cfg, rust_log))
        .with_ansi(false)
        .with_target(true)
        .with_writer(writer);
    match cfg.format.as_str() {
        "pretty" => Box::new(builder.pretty().finish()),
        _ => Box::new(builder.json().finish()),
    }
}

pub fn init_tracing(cfg: &LogConfig) {
    let rust_log = std::env::var("RUST_LOG").ok();
    if let Err(err) = subscriber(cfg, rust_log.as_deref(), std::io::stdout).try_init() {
        eprintln!("currawongd: tracing already initialised: {err}");
    }
}

fn install_recorder() -> PrometheusHandle {
    RECORDER
        .get_or_init(|| {
            let handle = PrometheusBuilder::new()
                .install_recorder()
                .expect("install prometheus recorder");
            describe_metrics();
            handle
        })
        .clone()
}

/// Describe and register every metric so `/metrics` lists them from startup,
/// before the first connection or message.
fn describe_metrics() {
    metrics::describe_counter!(
        SMTP_CONNECTIONS_TOTAL,
        "SMTP connections accepted by the gateway"
    );
    metrics::describe_counter!(MESSAGES_ACCEPTED_TOTAL, "Messages accepted after DATA");
    metrics::describe_counter!(MESSAGES_REJECTED_TOTAL, "Messages rejected before accept");
    metrics::describe_gauge!(SPOOL_DEPTH, "Messages waiting in the spool");
    metrics::describe_histogram!(
        SCAN_DURATION_SECONDS,
        "Time spent scanning one message, in seconds"
    );
    metrics::describe_counter!(
        RESIDENCY_REPORT_FAILURES_TOTAL,
        "Signed residency reports that could not be written"
    );
    for name in [
        SMTP_CONNECTIONS_TOTAL,
        MESSAGES_ACCEPTED_TOTAL,
        MESSAGES_REJECTED_TOTAL,
        RESIDENCY_REPORT_FAILURES_TOTAL,
    ] {
        metrics::counter!(name).increment(0);
    }
    metrics::gauge!(SPOOL_DEPTH).increment(0.0);
}

pub fn metrics_body() -> String {
    install_recorder().render()
}

pub fn router(checks: Vec<Arc<dyn ReadinessCheck>>) -> Router {
    let _ = install_recorder();
    let state = HealthState {
        checks: Arc::new(checks),
        slots: Arc::new(tokio::sync::Semaphore::new(MAX_READYZ)),
    };
    Router::new()
        .route("/metrics", get(|| async { metrics_body() }))
        .route("/healthz", get(|| async { (StatusCode::OK, "ok") }))
        .route("/readyz", get(readyz))
        .with_state(state)
}

/// Run every check at once, each under [`READY_TIMEOUT`]. The response names
/// failed checks only. Details (paths, peer errors) go to the log, not to an
/// unauthenticated caller.
async fn readyz(State(state): State<HealthState>) -> (StatusCode, String) {
    let Ok(_slot) = Arc::clone(&state.slots).try_acquire_owned() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "not ready: busy".into());
    };
    let mut set = tokio::task::JoinSet::new();
    for check in state.checks.iter() {
        let check = Arc::clone(check);
        set.spawn(async move {
            let result = tokio::time::timeout(READY_TIMEOUT, check.check()).await;
            (check.name(), result)
        });
    }
    let mut failed = Vec::new();
    while let Some(joined) = set.join_next().await {
        match joined {
            Ok((_, Ok(Ok(())))) => {}
            Ok((name, Ok(Err(err)))) => {
                tracing::warn!(check = name, %err, "readiness check failed");
                failed.push(name);
            }
            Ok((name, Err(_))) => {
                tracing::warn!(check = name, "readiness check timed out");
                failed.push(name);
            }
            Err(err) => {
                tracing::warn!(%err, "readiness check panicked");
                failed.push("check");
            }
        }
    }
    if failed.is_empty() {
        return (StatusCode::OK, "ready".into());
    }
    failed.sort_unstable();
    (
        StatusCode::SERVICE_UNAVAILABLE,
        format!("not ready: {}", failed.join(", ")),
    )
}

/// Bind the metrics and health server. Port `0` selects an ephemeral port.
pub fn init_metrics(addr: SocketAddr) -> std::io::Result<SocketAddr> {
    serve(addr, Vec::new())
}

pub fn serve(
    addr: SocketAddr,
    checks: Vec<Arc<dyn ReadinessCheck>>,
) -> std::io::Result<SocketAddr> {
    let app = router(checks);
    let listener = std::net::TcpListener::bind(addr)?;
    listener.set_nonblocking(true)?;
    let bound = listener.local_addr()?;
    let run = async move {
        let tokio_listener = match tokio::net::TcpListener::from_std(listener) {
            Ok(listener) => listener,
            Err(err) => {
                tracing::error!(%err, "observability listener failed");
                return;
            }
        };
        if let Err(err) = axum::serve(tokio_listener, app).await {
            tracing::error!(%err, "observability server stopped");
        }
    };
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        handle.spawn(run);
    } else {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        std::thread::spawn(move || rt.block_on(run));
    }
    Ok(bound)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::{
        io::{self, Write},
        sync::{Arc, Mutex},
    };

    #[derive(Clone)]
    struct MemWriter(Arc<Mutex<Vec<u8>>>);

    impl MemWriter {
        fn new() -> Self {
            Self(Arc::new(Mutex::new(Vec::new())))
        }

        fn text(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    impl Write for MemWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().expect("lock").extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for MemWriter {
        type Writer = MemWriter;

        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    fn log_cfg(format: &str, level: &str) -> LogConfig {
        LogConfig {
            format: format.into(),
            level: level.into(),
        }
    }

    #[test]
    fn json_mode_writes_one_json_object_per_line_with_the_message_span() {
        let buf = MemWriter::new();
        let sub = subscriber(&log_cfg("json", "info"), None, buf.clone());
        tracing::subscriber::with_default(sub, || {
            let span = tracing::info_span!("message", message_id = "01ARZ3NDEKTSV4RRFFQ69G5FAV");
            let _entered = span.enter();
            tracing::info!(verdict = "deliver", "evaluated");
            tracing::warn!("second line");
        });
        let text = buf.text();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2, "{text}");
        for line in &lines {
            let value: Value = serde_json::from_str(line).expect("json line");
            assert_eq!(
                value["span"]["message_id"], "01ARZ3NDEKTSV4RRFFQ69G5FAV",
                "{line}"
            );
        }
        let first: Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(first["fields"]["verdict"], "deliver");
        assert_eq!(first["level"], "INFO");
    }

    #[test]
    fn pretty_mode_is_not_json() {
        let buf = MemWriter::new();
        let sub = subscriber(&log_cfg("pretty", "info"), None, buf.clone());
        tracing::subscriber::with_default(sub, || tracing::info!("hello"));
        let text = buf.text();
        assert!(text.contains("hello"), "{text}");
        assert!(serde_json::from_str::<Value>(text.lines().next().unwrap()).is_err());
    }

    #[test]
    fn rust_log_overrides_the_configured_level() {
        let quiet = MemWriter::new();
        let sub = subscriber(&log_cfg("json", "warn"), None, quiet.clone());
        tracing::subscriber::with_default(sub, || tracing::debug!("detail"));
        assert!(quiet.text().is_empty());
        let loud = MemWriter::new();
        let sub = subscriber(&log_cfg("json", "warn"), Some("debug"), loud.clone());
        tracing::subscriber::with_default(sub, || tracing::debug!("detail"));
        assert!(loud.text().contains("detail"));
    }

    async fn get(addr: SocketAddr, path: &str) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let request =
            format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        client.write_all(request.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        client.read_to_end(&mut buf).await.unwrap();
        String::from_utf8_lossy(&buf).into_owned()
    }

    #[tokio::test]
    async fn metrics_and_healthz() {
        let _ = install_recorder();
        metrics::counter!(SMTP_CONNECTIONS_TOTAL).increment(1);
        let body = metrics_body();
        assert!(
            body.contains(SMTP_CONNECTIONS_TOTAL),
            "metrics render missing counter:\n{body}"
        );
        let addr = init_metrics(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
        let text = get(addr, "/healthz").await;
        assert!(text.contains("200"), "{text}");
        assert!(text.contains("ok"));
    }

    #[tokio::test]
    async fn serve_reports_a_bind_failure_instead_of_panicking() {
        let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = taken.local_addr().unwrap();
        assert!(serve(addr, Vec::new()).is_err());
    }

    struct Hangs;

    #[async_trait]
    impl ReadinessCheck for Hangs {
        fn name(&self) -> &'static str {
            "hangs"
        }

        async fn check(&self) -> Result<(), String> {
            std::future::pending().await
        }
    }

    #[tokio::test]
    async fn readyz_work_is_capped() {
        let addr = serve(SocketAddr::from(([127, 0, 0, 1], 0)), vec![Arc::new(Hangs)]).unwrap();
        let mut set = tokio::task::JoinSet::new();
        for _ in 0..MAX_READYZ + 2 {
            set.spawn(get(addr, "/readyz"));
        }
        let mut busy = 0;
        while let Some(text) = set.join_next().await {
            let text = text.unwrap();
            assert!(text.contains("503"), "{text}");
            busy += usize::from(text.contains("not ready: busy"));
        }
        assert!(busy >= 2, "{busy}");
    }

    struct Leaks;

    #[async_trait]
    impl ReadinessCheck for Leaks {
        fn name(&self) -> &'static str {
            "leaks"
        }

        async fn check(&self) -> Result<(), String> {
            Err("open /srv/secret-spool-path: permission denied".into())
        }
    }

    #[tokio::test]
    async fn readyz_times_out_a_hung_check_and_hides_error_details() {
        let addr = serve(
            SocketAddr::from(([127, 0, 0, 1], 0)),
            vec![Arc::new(Hangs), Arc::new(Leaks)],
        )
        .unwrap();
        let started = std::time::Instant::now();
        let text = tokio::time::timeout(Duration::from_secs(10), get(addr, "/readyz"))
            .await
            .expect("readyz returned");
        assert!(
            started.elapsed() < READY_TIMEOUT * 3,
            "{:?}",
            started.elapsed()
        );
        assert!(text.contains("503"), "{text}");
        assert!(text.contains("not ready: hangs, leaks"), "{text}");
        assert!(!text.contains("secret-spool-path"), "{text}");
    }
}
