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
pub use event::{Event, EventKind, SCHEMA};

use currawong_core::{ResidencyError, ResidencyGuard, Secret};
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
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

/// `[events]` settings. Exporters are off unless configured.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ExportConfig {
    /// Events held in memory per exporter before overflowing to disk.
    pub queue_capacity: usize,
    pub batch_size: usize,
    pub overflow_dir: PathBuf,
    /// Events held on disk per exporter before new events are dropped.
    pub overflow_max_files: usize,
    pub syslog: Option<SyslogConfig>,
    pub webhook: Option<WebhookConfig>,
    pub wedgetail: Option<WedgetailConfig>,
}

impl Default for ExportConfig {
    fn default() -> Self {
        Self {
            queue_capacity: 1024,
            batch_size: 100,
            overflow_dir: PathBuf::from("/var/lib/currawong/events"),
            overflow_max_files: 100_000,
            syslog: None,
            webhook: None,
            wedgetail: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyslogConfig {
    /// `host:port`, for example `siem.corp.example:6514`.
    pub address: String,
    #[serde(default = "default_true")]
    pub tls: bool,
    /// PEM bundle for a private CA. Public roots are always trusted.
    #[serde(default)]
    pub ca_file: Option<PathBuf>,
    #[serde(default)]
    pub payload: syslog::Payload,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebhookConfig {
    pub url: String,
    /// File holding the HMAC key (at least 16 bytes, trailing newline ignored).
    pub secret_file: PathBuf,
    #[serde(default)]
    pub ca_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WedgetailConfig {
    pub url: String,
    pub token_file: PathBuf,
    #[serde(default)]
    pub ca_file: Option<PathBuf>,
}

fn default_true() -> bool {
    true
}

fn read_secret(path: &Path) -> Result<Secret<String>, ExportError> {
    let text = std::fs::read_to_string(path)
        .map_err(|err| ExportError::Config(format!("{}: {err}", path.display())))?;
    Ok(Secret::new(text.trim_end_matches(['\r', '\n']).to_string()))
}

impl EventBus {
    /// Build the configured exporters and start their workers.
    /// `hostname` is the gateway name written into syslog headers.
    pub fn from_config(
        cfg: &ExportConfig,
        guard: Arc<ResidencyGuard>,
        hostname: &str,
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
            overflow_dir: cfg.overflow_dir.clone(),
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
            "queue_capacity = 8\noverflow_dir = {:?}\n[webhook]\nurl = {:?}\nsecret_file = {:?}\nca_file = {:?}\n",
            dir.path().join("overflow"),
            server.url("/events"),
            secret_file,
            server.ca_file,
        );
        let cfg: ExportConfig = toml::from_str(&toml_text).unwrap();
        let guard = Arc::new(ResidencyGuard::from_config(&ResidencyConfig::default()).unwrap());
        let bus = EventBus::from_config(&cfg, guard, "gw1").unwrap();
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
        let cfg: ExportConfig = toml::from_str("").unwrap();
        assert!(cfg.syslog.is_none() && cfg.webhook.is_none() && cfg.wedgetail.is_none());
        assert_eq!(cfg.queue_capacity, 1024);
    }
}
