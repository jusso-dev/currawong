//! Optional ACME (RFC 8555) certificates, validated with HTTP-01.
//!
//! The account key, certificate and private key live in `tls.acme.cache_dir`.
//! The daemon loads them through `TlsManager`, so a renewal swaps the
//! certificate the same way SIGHUP does, without closing a listener. The CA
//! sees the domain names and a CSR only; no mail leaves the host.
use crate::{
    delivery::outbound_tls::OutboundTls,
    tls::{build_server_config, load_certs, load_key, TlsManager},
};
use bytes::Bytes;
use currawong_core::config::AcmeConfig;
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, BodyWrapper, BytesResponse, ChallengeType,
    HttpClient, Identifier, NewAccount, NewOrder, OrderStatus, RetryPolicy,
};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    future::Future,
    io::Write,
    path::{Path, PathBuf},
    pin::Pin,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Semaphore,
};
use tokio_util::sync::CancellationToken;

pub const CERT_FILE: &str = "cert.pem";
pub const KEY_FILE: &str = "key.pem";
/// How often the certificate's remaining lifetime is checked.
pub const RENEW_CHECK: Duration = Duration::from_secs(12 * 3600);
/// How long the CA gets to validate the challenges and to issue.
const ORDER_TIMEOUT: Duration = Duration::from_secs(120);
/// Concurrent HTTP-01 requests. Port 80 is open to the internet.
const HTTP_CONNECTIONS: usize = 64;
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);
const HTTP_MAX_REQUEST: usize = 8 * 1024;
const CHALLENGE_PATH: &str = "/.well-known/acme-challenge/";

#[derive(Debug, thiserror::Error)]
pub enum AcmeError {
    #[error("acme: {0}")]
    Protocol(#[from] instant_acme::Error),
    #[error("acme i/o: {0}")]
    Io(#[from] std::io::Error),
    #[error("acme: {0}")]
    Other(String),
}

pub struct Acme {
    cfg: AcmeConfig,
    http: Arc<dyn HttpClient>,
    /// HTTP-01 answers while an order is open: token to key authorisation.
    challenges: Mutex<HashMap<String, String>>,
}

impl Acme {
    /// Talk to the CA over HTTPS with the WebPKI roots.
    pub fn new(cfg: AcmeConfig) -> Result<Self, AcmeError> {
        let client = OutboundTls::webpki()
            .http_client(true)
            .map_err(AcmeError::Other)?;
        Self::with_client(cfg, Arc::new(Reqwest(client)))
    }

    /// Use another HTTP client, for a private CA or tests.
    pub fn with_client(cfg: AcmeConfig, http: Arc<dyn HttpClient>) -> Result<Self, AcmeError> {
        create_private_dir(&cfg.cache_dir)?;
        Ok(Self {
            cfg,
            http,
            challenges: Mutex::new(HashMap::new()),
        })
    }

    pub fn cert_path(&self) -> PathBuf {
        self.cfg.cache_dir.join(CERT_FILE)
    }

    pub fn key_path(&self) -> PathBuf {
        self.cfg.cache_dir.join(KEY_FILE)
    }

    /// Keep the cached certificate if it loads and is not due for renewal,
    /// otherwise obtain a new one. True when a new certificate was written.
    /// A failed renewal keeps a cached pair that still loads, even an expired
    /// one, so an unreachable CA never stops mail; only a missing or broken
    /// pair is an error.
    pub async fn ensure(&self) -> Result<bool, AcmeError> {
        let loads = load_certs(&self.cert_path())
            .and_then(|certs| build_server_config(certs, load_key(&self.key_path())?))
            .is_ok();
        if !loads {
            self.issue().await?;
            return Ok(true);
        }
        let due = std::fs::read(self.cert_path())
            .map_err(AcmeError::from)
            .and_then(|pem| renewal_due(&pem, SystemTime::now()))
            .unwrap_or(true);
        if !due {
            return Ok(false);
        }
        match self.issue().await {
            Ok(()) => Ok(true),
            Err(err) => {
                tracing::warn!(%err, "ACME renewal failed; keeping the cached certificate");
                Ok(false)
            }
        }
    }

    /// Run one order for `domains` and write the certificate and key.
    pub async fn issue(&self) -> Result<(), AcmeError> {
        let result = self.order().await;
        self.challenges.lock().expect("challenge lock").clear();
        let (chain, key) = result?;
        // Refuse a pair rustls cannot serve before it replaces a good one.
        build_server_config(
            rustls_pemfile::certs(&mut chain.as_bytes()).collect::<Result<Vec<_>, _>>()?,
            rustls_pemfile::private_key(&mut key.as_bytes())?
                .ok_or_else(|| AcmeError::Other("the new private key did not parse".into()))?,
        )
        .map_err(|err| AcmeError::Other(err.to_string()))?;
        write_private(&self.key_path(), key.as_bytes())?;
        write_private(&self.cert_path(), chain.as_bytes())?;
        tracing::info!(domains = ?self.cfg.domains, "ACME certificate issued");
        Ok(())
    }

    async fn order(&self) -> Result<(String, String), AcmeError> {
        let account = self.account().await?;
        let identifiers: Vec<Identifier> = self
            .cfg
            .domains
            .iter()
            .cloned()
            .map(Identifier::Dns)
            .collect();
        let mut order = account.new_order(&NewOrder::new(&identifiers)).await?;
        let mut authorizations = order.authorizations();
        while let Some(authz) = authorizations.next().await {
            let mut authz = authz?;
            match authz.status {
                AuthorizationStatus::Pending => {}
                AuthorizationStatus::Valid => continue,
                status => {
                    return Err(AcmeError::Other(format!(
                        "authorisation for {} is {status:?}",
                        authz.identifier()
                    )))
                }
            }
            let mut challenge = authz
                .challenge(ChallengeType::Http01)
                .ok_or_else(|| AcmeError::Other("the CA offered no http-01 challenge".into()))?;
            let answer = challenge.key_authorization().as_str().to_string();
            self.challenges
                .lock()
                .expect("challenge lock")
                .insert(challenge.token.clone(), answer);
            challenge.set_ready().await?;
        }
        let retries = RetryPolicy::default().timeout(ORDER_TIMEOUT);
        let status = order.poll_ready(&retries).await?;
        if status != OrderStatus::Ready {
            return Err(AcmeError::Other(format!("order is {status:?}")));
        }
        let key = order.finalize().await?;
        let chain = order.poll_certificate(&retries).await?;
        Ok((chain, key))
    }

    /// The account for this directory, created on first use. The file name
    /// carries a hash of the directory URL, so moving from a staging CA to
    /// production does not reuse the wrong account.
    async fn account(&self) -> Result<Account, AcmeError> {
        let id = hex::encode(&Sha256::digest(self.cfg.directory_url.as_bytes())[..8]);
        let path = self.cfg.cache_dir.join(format!("account-{id}.json"));
        let builder = Account::builder_with_http(Box::new(Shared(Arc::clone(&self.http))));
        match std::fs::read(&path) {
            Ok(bytes) => {
                let credentials: AccountCredentials = serde_json::from_slice(&bytes)
                    .map_err(|err| AcmeError::Other(format!("{}: {err}", path.display())))?;
                Ok(builder.from_credentials(credentials).await?)
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                let contact = [self.cfg.contact.as_str()];
                let (account, credentials) = builder
                    .create(
                        &NewAccount {
                            contact: &contact,
                            terms_of_service_agreed: true,
                            only_return_existing: false,
                        },
                        self.cfg.directory_url.clone(),
                        None,
                    )
                    .await?;
                let bytes = serde_json::to_vec(&credentials)
                    .map_err(|err| AcmeError::Other(err.to_string()))?;
                write_private(&path, &bytes)?;
                Ok(account)
            }
            Err(err) => Err(err.into()),
        }
    }

    /// Answer HTTP-01 requests until shutdown. Anything else gets a 404.
    pub async fn serve_http01(self: Arc<Self>, listener: TcpListener, shutdown: CancellationToken) {
        let slots = Arc::new(Semaphore::new(HTTP_CONNECTIONS));
        loop {
            let accepted = tokio::select! {
                _ = shutdown.cancelled() => return,
                accepted = listener.accept() => accepted,
            };
            let sock = match accepted {
                Ok((sock, _)) => sock,
                Err(err) => {
                    tracing::warn!(%err, "acme http-01 accept failed; retrying");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };
            let Ok(slot) = Arc::clone(&slots).try_acquire_owned() else {
                continue;
            };
            let acme = Arc::clone(&self);
            tokio::spawn(async move {
                let _slot = slot;
                let _ = tokio::time::timeout(HTTP_TIMEOUT, acme.answer(sock)).await;
            });
        }
    }

    async fn answer(&self, mut sock: TcpStream) -> std::io::Result<()> {
        let mut request = Vec::with_capacity(1024);
        let mut chunk = [0u8; 1024];
        while !request.windows(4).any(|w| w == b"\r\n\r\n") && request.len() < HTTP_MAX_REQUEST {
            let read = sock.read(&mut chunk).await?;
            if read == 0 {
                break;
            }
            request.extend_from_slice(&chunk[..read]);
        }
        let line = request.split(|&b| b == b'\n').next().unwrap_or_default();
        let line = String::from_utf8_lossy(line);
        let mut parts = line.split_whitespace();
        let answer = match (parts.next(), parts.next()) {
            (Some("GET"), Some(path)) => path.strip_prefix(CHALLENGE_PATH).and_then(|token| {
                self.challenges
                    .lock()
                    .expect("challenge lock")
                    .get(token)
                    .cloned()
            }),
            _ => None,
        };
        let response = match answer {
            Some(body) => format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            ),
            None => "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                .to_string(),
        };
        sock.write_all(response.as_bytes()).await?;
        sock.shutdown().await
    }

    /// Check every `RENEW_CHECK` and swap a renewed certificate into `tls`.
    pub async fn renew(self: Arc<Self>, tls: Arc<TlsManager>, shutdown: CancellationToken) {
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => return,
                _ = tokio::time::sleep(RENEW_CHECK) => {}
            }
            match self.ensure().await {
                Ok(true) => match tls.reload() {
                    Ok(()) => tracing::info!("loaded the renewed ACME certificate"),
                    Err(err) => tracing::error!(%err, "renewed ACME certificate did not load"),
                },
                Ok(false) => {}
                Err(err) => tracing::warn!(%err, "ACME renewal failed; trying again later"),
            }
        }
    }
}

/// Renew once a third of the leaf's lifetime is left: 30 days of a 90-day
/// certificate, and proportionally less for short-lived ones.
pub fn renewal_due(chain_pem: &[u8], now: SystemTime) -> Result<bool, AcmeError> {
    let (_, pem) = x509_parser::pem::parse_x509_pem(chain_pem)
        .map_err(|err| AcmeError::Other(format!("certificate PEM: {err}")))?;
    let cert = pem
        .parse_x509()
        .map_err(|err| AcmeError::Other(format!("certificate: {err}")))?;
    let not_before = cert.validity().not_before.timestamp();
    let not_after = cert.validity().not_after.timestamp();
    let now = now
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or_default();
    Ok(now >= not_after - (not_after - not_before) / 3)
}

fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Write through a temporary file and rename, so a reader never sees half a
/// file. Owner read and write only.
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&tmp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    std::fs::rename(&tmp, path)
}

type Pending = Pin<Box<dyn Future<Output = Result<BytesResponse, instant_acme::Error>> + Send>>;

/// One `HttpClient` shared by every `Account` this process builds.
struct Shared(Arc<dyn HttpClient>);

impl HttpClient for Shared {
    fn request(&self, req: http::Request<BodyWrapper<Bytes>>) -> Pending {
        self.0.request(req)
    }
}

/// The workspace's reqwest client, so ACME uses the same rustls set-up as
/// MTA-STS and TLS-RPT.
struct Reqwest(reqwest::Client);

impl HttpClient for Reqwest {
    fn request(&self, req: http::Request<BodyWrapper<Bytes>>) -> Pending {
        let client = self.0.clone();
        Box::pin(async move {
            let req = reqwest::Request::try_from(req.map(reqwest::Body::wrap))
                .map_err(|err| instant_acme::Error::Other(Box::new(err)))?;
            let rsp = client
                .execute(req)
                .await
                .map_err(|err| instant_acme::Error::Other(Box::new(err)))?;
            Ok(BytesResponse::from(http::Response::from(rsp)))
        })
    }
}
