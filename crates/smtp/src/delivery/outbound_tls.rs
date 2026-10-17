//! TLS client settings for outbound SMTP and policy fetches. Certificates are
//! always verified: against WebPKI roots, or against DANE TLSA records.
use super::dane::DaneVerifier;
use crate::dns::Tlsa;
use rustls::{
    crypto::CryptoProvider,
    pki_types::ServerName,
    version::{TLS12, TLS13},
    ClientConfig, RootCertStore,
};
use std::{sync::Arc, time::Duration};

#[derive(Clone)]
pub struct OutboundTls {
    roots: Arc<RootCertStore>,
    provider: Arc<CryptoProvider>,
}

impl OutboundTls {
    /// The Mozilla root programme, as shipped in `webpki-roots`.
    pub fn webpki() -> Self {
        Self::with_roots(RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        })
    }

    /// A different trust store, for private PKI or tests.
    pub fn with_roots(roots: RootCertStore) -> Self {
        Self {
            roots: Arc::new(roots),
            provider: Arc::new(rustls::crypto::ring::default_provider()),
        }
    }

    /// WebPKI: the chain must lead to a trusted root and name the host.
    pub fn webpki_config(&self) -> Result<Arc<ClientConfig>, String> {
        let config = ClientConfig::builder_with_provider(Arc::clone(&self.provider))
            .with_protocol_versions(&[&TLS13, &TLS12])
            .map_err(|err| err.to_string())?
            .with_root_certificates(Arc::clone(&self.roots))
            .with_no_client_auth();
        Ok(Arc::new(config))
    }

    /// DANE: the chain must match one of `records` (already filtered to the
    /// usable ones).
    pub fn dane_config(
        &self,
        records: Vec<Tlsa>,
        names: Vec<ServerName<'static>>,
    ) -> Result<Arc<ClientConfig>, String> {
        let verifier = DaneVerifier::new(records, names, Arc::clone(&self.provider));
        let config = ClientConfig::builder_with_provider(Arc::clone(&self.provider))
            .with_protocol_versions(&[&TLS13, &TLS12])
            .map_err(|err| err.to_string())?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth();
        Ok(Arc::new(config))
    }

    /// HTTPS client for MTA-STS policies and TLS-RPT uploads. No redirects
    /// (RFC 8461 section 3.3) and the same WebPKI roots.
    pub fn http_client(&self) -> Result<reqwest::Client, String> {
        let mut config = (*self.webpki_config()?).clone();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        reqwest::Client::builder()
            .use_preconfigured_tls(config)
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(30))
            .timeout(Duration::from_secs(60))
            .build()
            .map_err(|err| err.to_string())
    }
}
