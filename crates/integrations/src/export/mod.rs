//! Event export to SIEMs: syslog (RFC 5424, CEF or JSON), signed webhooks and Wedgetail.
//! See `docs/events.md` for the `currawong.event.v1` schema.
//!
//! Every outbound connection is checked against the residency guard: the
//! configured URL at start-up and on every send, and every HTTP redirect target.
pub mod bus;
pub mod cef;
pub mod event;
pub mod syslog;
mod tls;
pub mod webhook;
pub mod wedgetail;

#[cfg(test)]
mod testutil;

pub use bus::{BusOptions, EventBus};
pub use currawong_core::config::EventsConfig;
pub use event::{Event, EventKind, SCHEMA};

use currawong_core::{ResidencyError, ResidencyGuard, Secret};
use std::{
    path::Path,
    sync::{Arc, OnceLock},
    time::Duration,
};

#[derive(Debug, thiserror::Error)]
pub enum ExportError {
    #[error("export config: {0}")]
    Config(String),
    #[error(transparent)]
    Residency(#[from] ResidencyError),
    #[error("export transport: {0}")]
    Transport(String),
}

#[async_trait::async_trait]
pub trait Exporter: Send + Sync {
    fn name(&self) -> &'static str;
    async fn send(&self, batch: &[Event]) -> Result<(), ExportError>;
}

fn read_secret(path: &Path) -> Result<Secret<String>, ExportError> {
    let text = std::fs::read_to_string(path)
        .map_err(|err| ExportError::Config(format!("{}: {err}", path.display())))?;
    Ok(Secret::new(text.trim_end_matches(['\r', '\n']).to_string()))
}

impl EventBus {
    /// Build the configured exporters and start their workers. `hostname` is
    /// the gateway name written into syslog headers.
    pub fn from_config(
        cfg: &EventsConfig,
        guard: Arc<ResidencyGuard>,
        hostname: &str,
        overflow_dir: &Path,
    ) -> Result<Self, ExportError> {
        let mut exporters: Vec<Arc<dyn Exporter>> = Vec::new();
        if let Some(s) = &cfg.syslog {
            exporters.push(Arc::new(syslog::SyslogExporter::new(
                guard.clone(),
                &s.address,
                s.tls,
                s.ca_file.as_deref(),
                hostname,
                s.payload,
            )?));
        }
        if let Some(w) = &cfg.webhook {
            let secret = read_secret(&w.secret_file)?;
            exporters.push(Arc::new(webhook::WebhookExporter::new(
                guard.clone(),
                &w.url,
                Secret::new(secret.expose().as_bytes().to_vec()),
                w.ca_file.as_deref(),
            )?));
        }
        if let Some(w) = &cfg.wedgetail {
            exporters.push(Arc::new(wedgetail::WedgetailExporter::new(
                guard.clone(),
                &w.url,
                read_secret(&w.token_file)?,
                w.ca_file.as_deref(),
            )?));
        }
        let opts = BusOptions {
            queue_capacity: cfg.queue_capacity,
            batch_size: cfg.batch_size,
            overflow_dir: overflow_dir.to_path_buf(),
            overflow_max_files: cfg.overflow_max_files,
            retry_initial: Duration::from_secs(1),
            retry_max: Duration::from_secs(60),
        };
        EventBus::start(exporters, &opts)
            .map_err(|err| ExportError::Config(format!("event overflow: {err}")))
    }
}

static BUS: OnceLock<EventBus> = OnceLock::new();

/// Make `bus` the process-wide event bus. Fails if one is already installed.
pub fn install(bus: EventBus) -> Result<(), EventBus> {
    BUS.set(bus)
}

/// Queue an event on the installed bus. A no-op until [`install`] runs. Never waits.
pub fn emit(event: Event) {
    if let Some(bus) = BUS.get() {
        bus.emit(event);
    }
}

/// On shutdown: stop sending and move queued events to the overflow, which is
/// sent on the next start. See [`EventBus::flush`].
pub async fn flush(timeout: Duration) -> bool {
    match BUS.get() {
        Some(bus) => bus.flush(timeout).await,
        None => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use currawong_core::config::ResidencyConfig;

    #[tokio::test]
    async fn export_config_builds_a_bus_that_signs_webhooks() {
        let dir = tempfile::tempdir().unwrap();
        let server = testutil::HttpsServer::start(dir.path(), 204, None).await;
        let secret_file = dir.path().join("hook.key");
        std::fs::write(&secret_file, "0123456789abcdef-secret\n").unwrap();
        let toml_text = format!(
            "queue_capacity = 8\n[webhook]\nurl = {:?}\nsecret_file = {:?}\nca_file = {:?}\n",
            server.url("/events"),
            secret_file,
            server.ca_file,
        );
        let cfg: EventsConfig = toml::from_str(&toml_text).unwrap();
        let guard = Arc::new(ResidencyGuard::from_config(&ResidencyConfig::default()).unwrap());
        let bus = EventBus::from_config(&cfg, guard, "gw1", &dir.path().join("overflow")).unwrap();
        install(bus).ok().expect("first install");
        emit(event::tests::samples().remove(0));
        for _ in 0..500 {
            if !server.requests.lock().unwrap().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let req = server.requests.lock().unwrap().remove(0);
        webhook::verify(
            b"0123456789abcdef-secret",
            req.header(webhook::TIMESTAMP_HEADER).unwrap(),
            &req.body,
            req.header(webhook::SIGNATURE_HEADER).unwrap(),
            time::OffsetDateTime::now_utc().unix_timestamp(),
        )
        .unwrap();
    }

    #[test]
    fn export_config_defaults_have_no_exporters() {
        let cfg: EventsConfig = toml::from_str("").unwrap();
        assert!(cfg.syslog.is_none() && cfg.webhook.is_none() && cfg.wedgetail.is_none());
        assert_eq!(cfg.queue_capacity, 1024);
    }
}
