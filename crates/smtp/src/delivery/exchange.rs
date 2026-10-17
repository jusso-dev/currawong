//! TLS client settings for Exchange on-premises routes. Built from the
//! route's CA file and client certificate, and cached until one of those
//! files changes, so a renewed certificate is picked up without a restart.
use super::OutboundTls;
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
        let config = tokio::task::spawn_blocking(move || {
            let tls = match &owned.ca_file {
                Some(path) => tls.with_ca_file(path)?,
                None => tls,
            };
            match &owned.client {
                Some((cert, key)) => tls.webpki_client_config(cert, key),
                None => tls.webpki_config(),
            }
        })
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
