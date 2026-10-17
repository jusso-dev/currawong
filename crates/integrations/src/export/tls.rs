//! Verifying TLS clients for exporters. There is no option to turn verification off.
use super::ExportError;
use currawong_core::ResidencyGuard;
use rustls::{ClientConfig, RootCertStore};
use std::{path::Path, sync::Arc, time::Duration};
use url::Url;

/// Public web roots plus an optional private CA (PEM), common for on-premises SIEMs.
pub fn client_config(ca_file: Option<&Path>) -> Result<ClientConfig, ExportError> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(path) = ca_file {
        let pem = std::fs::read(path)
            .map_err(|err| ExportError::Config(format!("{}: {err}", path.display())))?;
        for cert in rustls_pemfile::certs(&mut pem.as_slice()) {
            let cert =
                cert.map_err(|err| ExportError::Config(format!("{}: {err}", path.display())))?;
            roots
                .add(cert)
                .map_err(|err| ExportError::Config(format!("{}: {err}", path.display())))?;
        }
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|err| ExportError::Config(err.to_string()))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(config)
}

/// HTTPS only, no proxies, and every redirect target goes through the residency guard.
pub fn http_client(
    guard: Arc<ResidencyGuard>,
    ca_file: Option<&Path>,
) -> Result<reqwest::Client, ExportError> {
    let mut tls = client_config(ca_file)?;
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    let policy = reqwest::redirect::Policy::custom(move |attempt| {
        if attempt.previous().len() > 5 {
            return attempt.error("too many redirects");
        }
        match guard.check(attempt.url()) {
            Ok(()) => attempt.follow(),
            Err(err) => attempt.error(err),
        }
    });
    reqwest::Client::builder()
        .tls_backend_preconfigured(tls)
        .https_only(true)
        .no_proxy()
        .redirect(policy)
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|err| ExportError::Config(err.to_string()))
}

/// Parse an exporter URL, require HTTPS and check it against the residency guard.
pub fn checked_url(guard: &ResidencyGuard, url: &str) -> Result<Url, ExportError> {
    let parsed = Url::parse(url).map_err(|err| ExportError::Config(format!("{url}: {err}")))?;
    if parsed.scheme() != "https" {
        return Err(ExportError::Config(format!(
            "{url}: exporters require https"
        )));
    }
    guard.check(&parsed)?;
    Ok(parsed)
}

/// The full cause chain, so a residency refusal inside a redirect is visible.
pub fn error_chain(err: &dyn std::error::Error) -> String {
    let mut out = err.to_string();
    let mut source = err.source();
    while let Some(cause) = source {
        out.push_str(": ");
        out.push_str(&cause.to_string());
        source = cause.source();
    }
    out
}
