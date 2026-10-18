//! TLS client settings for Exchange on-premises routes. Built from the
//! route's CA file and client certificate, and cached until one of those
//! files changes, so a renewed certificate is picked up without a restart.
use super::OutboundTls;
use currawong_core::config::{Config, MailboxPlatform};
use rustls::ClientConfig;
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::SystemTime,
};

/// The files one Exchange route's TLS client settings are built from.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ExchangeTlsFiles {
    pub ca_file: Option<PathBuf>,
    /// Certificate and key presented to Exchange, for a domain secure
    /// (mutual TLS) Receive connector.
    pub client: Option<(PathBuf, PathBuf)>,
}

impl ExchangeTlsFiles {
    /// The TLS files for an Exchange route; `None` for any other platform.
    pub fn from_platform(platform: &MailboxPlatform) -> Option<Self> {
        let MailboxPlatform::ExchangeOnPrem { ca_file, .. } = platform else {
            return None;
        };
        Some(Self {
            ca_file: ca_file.clone(),
            client: platform
                .client_identity()
                .map(|(cert, key)| (cert.to_path_buf(), key.to_path_buf())),
        })
    }

    fn paths(&self) -> impl Iterator<Item = &PathBuf> {
        self.ca_file
            .iter()
            .chain(self.client.iter().flat_map(|(cert, key)| [cert, key]))
    }
}

type Stamps = Vec<SystemTime>;

#[derive(Default)]
pub struct ExchangeTlsCache {
    entries: Mutex<HashMap<ExchangeTlsFiles, (Stamps, Arc<ClientConfig>)>>,
}

impl ExchangeTlsCache {
    /// WebPKI roots plus the CA file, and the client certificate when set.
    /// Certificates are always verified.
    pub async fn config(
        &self,
        tls: &OutboundTls,
        files: &ExchangeTlsFiles,
    ) -> Result<Arc<ClientConfig>, String> {
        let mut stamps = Vec::new();
        for path in files.paths() {
            let modified = tokio::fs::metadata(path)
                .await
                .and_then(|meta| meta.modified())
                .map_err(|err| format!("4.7.5 {}: {err}", path.display()))?;
            stamps.push(modified);
        }
        if let Some((seen, config)) = self.lock().get(files) {
            if *seen == stamps {
                return Ok(Arc::clone(config));
            }
        }
        let (tls, owned) = (tls.clone(), files.clone());
        let config = tokio::task::spawn_blocking(move || build(&tls, &owned))
            .await
            .map_err(|err| format!("4.7.5 TLS settings: {err}"))??;
        self.lock()
            .insert(files.clone(), (stamps, Arc::clone(&config)));
        Ok(config)
    }

    fn lock(
        &self,
    ) -> std::sync::MutexGuard<'_, HashMap<ExchangeTlsFiles, (Stamps, Arc<ClientConfig>)>> {
        self.entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// Parse the files and build the client settings. Fails on an unreadable or
/// empty CA file, a bad certificate or key, or a key that does not match its
/// certificate.
fn build(tls: &OutboundTls, files: &ExchangeTlsFiles) -> Result<Arc<ClientConfig>, String> {
    let tls = match &files.ca_file {
        Some(path) => tls.with_ca_file(path)?,
        None => tls.clone(),
    };
    match &files.client {
        Some((cert, key)) => tls.webpki_client_config(cert, key),
        None => tls.webpki_config(),
    }
}

/// Build every Exchange route's TLS settings once at startup and in
/// `--check-config`, so a bad file is reported then rather than deferring
/// the domain's mail.
pub fn check_exchange_tls(cfg: &Config) -> Result<(), String> {
    let tls = OutboundTls::webpki();
    for route in &cfg.domains.routes {
        let Some(files) = route
            .platform
            .as_ref()
            .and_then(ExchangeTlsFiles::from_platform)
        else {
            continue;
        };
        build(&tls, &files).map_err(|err| format!("route {}: {err}", route.domain))?;
    }
    Ok(())
}
