//! TLS 1.2 and 1.3 only, with certificate reload.
use arc_swap::ArcSwap;
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer},
    server::ServerConfig,
    version::{TLS12, TLS13},
};
use std::{fs::File, io::BufReader, path::Path, sync::Arc};
use tokio_rustls::TlsAcceptor;

#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("tls i/o: {0}")]
    Io(#[from] std::io::Error),
    #[error("tls: {0}")]
    Rustls(#[from] rustls::Error),
    #[error("no private key in {0}")]
    NoKey(String),
}

pub struct TlsManager {
    acceptor: ArcSwap<TlsAcceptor>,
    cert_path: std::path::PathBuf,
    key_path: std::path::PathBuf,
}

impl TlsManager {
    pub fn load(cert: &Path, key: &Path) -> Result<Self, TlsError> {
        let acceptor = build_acceptor(cert, key)?;
        Ok(Self {
            acceptor: ArcSwap::from_pointee(acceptor),
            cert_path: cert.to_path_buf(),
            key_path: key.to_path_buf(),
        })
    }

    pub fn reload(&self) -> Result<(), TlsError> {
        let acceptor = build_acceptor(&self.cert_path, &self.key_path)?;
        self.acceptor.store(Arc::new(acceptor));
        Ok(())
    }

    /// Reload from explicit paths. Used by SIGHUP and by tests.
    pub fn reload_from(&self, cert: &Path, key: &Path) -> Result<(), TlsError> {
        let acceptor = build_acceptor(cert, key)?;
        self.acceptor.store(Arc::new(acceptor));
        Ok(())
    }

    pub fn acceptor(&self) -> Arc<TlsAcceptor> {
        self.acceptor.load_full()
    }
}

pub fn build_server_config(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<ServerConfig, TlsError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&TLS13, &TLS12])?
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    Ok(config)
}

fn build_acceptor(cert: &Path, key: &Path) -> Result<TlsAcceptor, TlsError> {
    let certs = load_certs(cert)?;
    let key = load_key(key)?;
    let config = build_server_config(certs, key)?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

pub fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(TlsError::Io)
}

pub fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>, TlsError> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    rustls_pemfile::private_key(&mut reader)?
        .ok_or_else(|| TlsError::NoKey(path.display().to_string()))
}

pub fn tls_labels(conn: &rustls::ServerConnection) -> (String, String) {
    let version = conn
        .protocol_version()
        .map(|v| format!("{v:?}"))
        .unwrap_or_else(|| "unknown".into());
    let cipher = conn
        .negotiated_cipher_suite()
        .map(|suite| format!("{:?}", suite.suite()))
        .unwrap_or_else(|| "unknown".into());
    (version, cipher)
}
