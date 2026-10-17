//! JSON logs, Prometheus metrics and the health endpoints.
use crate::config::LogConfig;
use async_trait::async_trait;
use axum::{extract::State, http::StatusCode, routing::get, Router};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use std::{
    net::SocketAddr,
    sync::{Arc, OnceLock},
};
use tracing_subscriber::EnvFilter;

pub const SMTP_CONNECTIONS_TOTAL: &str = "currawong_smtp_connections_total";
pub const MESSAGES_ACCEPTED_TOTAL: &str = "currawong_messages_accepted_total";
pub const MESSAGES_REJECTED_TOTAL: &str = "currawong_messages_rejected_total";
pub const SPOOL_DEPTH: &str = "currawong_spool_depth";
pub const SCAN_DURATION_SECONDS: &str = "currawong_scan_duration_seconds";

#[async_trait]
pub trait ReadinessCheck: Send + Sync {
    fn name(&self) -> &'static str;
    async fn check(&self) -> Result<(), String>;
}

#[derive(Clone)]
struct HealthState {
    checks: Arc<Vec<Arc<dyn ReadinessCheck>>>,
}

static RECORDER: OnceLock<PrometheusHandle> = OnceLock::new();

pub fn init_tracing(cfg: &LogConfig) {
    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(&cfg.level))
        .unwrap_or_else(|_| EnvFilter::new("info"));
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(false)
        .with_target(true);
    match cfg.format.as_str() {
        "pretty" => builder.pretty().init(),
        _ => builder.json().init(),
    }
}

fn install_recorder() -> PrometheusHandle {
    RECORDER
        .get_or_init(|| {
            describe_metrics();
            PrometheusBuilder::new()
                .install_recorder()
                .expect("install prometheus recorder")
        })
        .clone()
}

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
}

pub fn metrics_body() -> String {
    install_recorder().render()
}

pub fn router(checks: Vec<Arc<dyn ReadinessCheck>>) -> Router {
    let _ = install_recorder();
    let state = HealthState {
        checks: Arc::new(checks),
    };
    Router::new()
        .route("/metrics", get(|| async { metrics_body() }))
        .route("/healthz", get(|| async { (StatusCode::OK, "ok") }))
        .route("/readyz", get(readyz))
        .with_state(state)
}

async fn readyz(
    State(state): State<HealthState>,
) -> Result<(StatusCode, String), (StatusCode, String)> {
    for check in state.checks.iter() {
        if let Err(err) = check.check().await {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                format!("{}: {err}", check.name()),
            ));
        }
    }
    Ok((StatusCode::OK, "ready".into()))
}

/// Bind the metrics and health server. Port `0` selects an ephemeral port.
pub fn init_metrics(addr: SocketAddr) -> SocketAddr {
    serve(addr, Vec::new())
}

pub fn serve(addr: SocketAddr, checks: Vec<Arc<dyn ReadinessCheck>>) -> SocketAddr {
    let app = router(checks);
    let listener = std::net::TcpListener::bind(addr).expect("bind observability");
    listener.set_nonblocking(true).expect("nonblocking");
    let bound = listener.local_addr().expect("local addr");
    let tokio_listener = tokio::net::TcpListener::from_std(listener).expect("tokio listener");
    let run = async move {
        if let Err(err) = axum::serve(tokio_listener, app).await {
            tracing::error!(%err, "observability server stopped");
        }
    };
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        handle.spawn(run);
    } else {
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("observability runtime");
            rt.block_on(run);
        });
    }
    bound
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::{
        io::{self, Write},
        sync::{Arc, Mutex},
    };
    use tracing_subscriber::fmt::MakeWriter;

    #[derive(Clone)]
    struct MemWriter(Arc<Mutex<Vec<u8>>>);

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

    #[test]
    fn json_log_line_is_json() {
        let buf = MemWriter(Arc::new(Mutex::new(Vec::new())));
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_ansi(false)
            .with_writer(buf.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(message_id = "01ARZ3NDEKTSV4RRFFQ69G5FAV", "accepted");
        });
        let text = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
        let line = text.lines().next().expect("log line");
        let value: Value = serde_json::from_str(line).expect("json");
        assert!(value.get("message_id").is_some() || line.contains("message_id"));
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
        let addr = init_metrics(SocketAddr::from(([127, 0, 0, 1], 0)));
        let url = format!("http://{addr}/healthz");
        let client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (mut read, mut write) = tokio::io::split(client);
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        write
            .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut buf = Vec::new();
        read.read_to_end(&mut buf).await.unwrap();
        let text = String::from_utf8_lossy(&buf);
        assert!(text.contains("200"), "{text} from {url}");
        assert!(text.contains("ok"));
    }
}
