//! ACME against an in-process CA. The fake speaks enough RFC 8555 for
//! instant-acme (directory, nonces, account, order, authorisation, HTTP-01,
//! finalise, certificate), fetches the HTTP-01 answer from our responder
//! over loopback and signs the CSR with a generated root. No internet.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use bytes::Bytes;
use currawong_core::config::AcmeConfig;
use currawong_smtp::{
    acme::{renewal_due, Acme},
    tls::TlsManager,
};
use instant_acme::{BodyWrapper, BytesResponse, HttpClient};
use rcgen::{BasicConstraints, CertificateParams, CertificateSigningRequestParams, IsCa, KeyPair};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    future::Future,
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex},
    time::SystemTime,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio_util::sync::CancellationToken;

const CA: &str = "https://ca.test";
const DOMAIN: &str = "mx.example.test";

struct Root {
    cert: rcgen::Certificate,
    key: KeyPair,
}

#[derive(Default)]
struct State {
    nonce: u64,
    thumbprint: String,
    contact: Vec<String>,
    accounts: usize,
    orders: usize,
    domains: Vec<String>,
    valid: Vec<bool>,
    issued: Option<String>,
    /// Lifetime left on issued certificates (of 90 days). Default 89.
    days_left: Option<i64>,
    /// Fail every challenge, like a CA that cannot reach port 80.
    refuse: bool,
}

struct FakeCa {
    root: Root,
    http01: SocketAddr,
    state: Mutex<State>,
}

#[derive(Clone)]
struct Client(Arc<FakeCa>);

impl HttpClient for Client {
    fn request(
        &self,
        req: http::Request<BodyWrapper<Bytes>>,
    ) -> Pin<Box<dyn Future<Output = Result<BytesResponse, instant_acme::Error>> + Send>> {
        let ca = Arc::clone(&self.0);
        Box::pin(async move { Ok(ca.handle(req).await) })
    }
}

impl FakeCa {
    fn new(http01: SocketAddr) -> Arc<Self> {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let cert = params.self_signed(&key).unwrap();
        Arc::new(Self {
            root: Root { cert, key },
            http01,
            state: Mutex::new(State::default()),
        })
    }

    fn root_der(&self) -> Vec<u8> {
        self.root.cert.der().to_vec()
    }

    async fn handle(&self, req: http::Request<BodyWrapper<Bytes>>) -> BytesResponse {
        let path = req.uri().path().to_string();
        let method = req.method().clone();
        // BodyWrapper is an http_body::Body; BytesResponse knows how to drain one.
        let mut body = BytesResponse::from(http::Response::new(req.into_body())).body;
        let body = body.into_bytes().await.unwrap();
        if path == "/directory" {
            return self.reply(
                200,
                None,
                json!({
                    "newNonce": format!("{CA}/nonce"),
                    "newAccount": format!("{CA}/account"),
                    "newOrder": format!("{CA}/order"),
                }),
            );
        }
        if method == http::Method::HEAD {
            return self.reply(200, None, Value::Null);
        }
        let jws: Value = serde_json::from_slice(&body).unwrap();
        let protected: Value = serde_json::from_slice(&decode(&jws["protected"])).unwrap();
        let payload = decode(&jws["payload"]);
        let payload: Value = if payload.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&payload).unwrap()
        };
        let mut parts = path.trim_start_matches('/').split('/');
        match (parts.next().unwrap(), parts.next()) {
            ("account", None) => {
                let jwk = &protected["jwk"];
                let canonical = format!(
                    r#"{{"crv":"{}","kty":"{}","x":"{}","y":"{}"}}"#,
                    jwk["crv"].as_str().unwrap(),
                    jwk["kty"].as_str().unwrap(),
                    jwk["x"].as_str().unwrap(),
                    jwk["y"].as_str().unwrap(),
                );
                let mut state = self.state.lock().unwrap();
                state.thumbprint = URL_SAFE_NO_PAD.encode(Sha256::digest(canonical));
                state.contact = serde_json::from_value(payload["contact"].clone()).unwrap();
                state.accounts += 1;
                drop(state);
                self.reply(
                    201,
                    Some(format!("{CA}/acct/1")),
                    json!({"status": "valid"}),
                )
            }
            ("order", None) => {
                let mut state = self.state.lock().unwrap();
                state.domains = payload["identifiers"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|id| id["value"].as_str().unwrap().to_string())
                    .collect();
                state.valid = vec![false; state.domains.len()];
                state.issued = None;
                state.orders += 1;
                drop(state);
                self.reply(201, Some(format!("{CA}/order/1")), self.order())
            }
            ("order", Some(_)) => self.reply(200, None, self.order()),
            ("authz", Some(index)) => {
                let index: usize = index.parse().unwrap();
                self.reply(200, None, self.authz(index))
            }
            ("chall", Some(index)) => {
                let index: usize = index.parse().unwrap();
                let expected = format!("token-{index}.{}", self.state.lock().unwrap().thumbprint);
                let answer = http_get(self.http01, &format!("token-{index}")).await;
                let refuse = self.state.lock().unwrap().refuse;
                if !refuse && answer.as_deref() == Some(expected.as_str()) {
                    self.state.lock().unwrap().valid[index] = true;
                    self.reply(200, None, challenge(index, "valid"))
                } else {
                    let mut body = challenge(index, "invalid");
                    body["error"] = json!({
                        "type": "urn:ietf:params:acme:error:unauthorized",
                        "detail": format!("expected {expected}, got {answer:?}"),
                    });
                    self.reply(200, None, body)
                }
            }
            ("finalize", Some(_)) => {
                let csr = URL_SAFE_NO_PAD
                    .decode(payload["csr"].as_str().unwrap())
                    .unwrap();
                let mut csr = CertificateSigningRequestParams::from_der(&csr.into()).unwrap();
                let days_left = self.state.lock().unwrap().days_left.unwrap_or(89);
                let now = time::OffsetDateTime::now_utc();
                csr.params.not_after = now + time::Duration::days(days_left);
                csr.params.not_before = csr.params.not_after - time::Duration::days(90);
                let leaf = csr.signed_by(&self.root.cert, &self.root.key).unwrap();
                self.state.lock().unwrap().issued =
                    Some(format!("{}{}", leaf.pem(), self.root.cert.pem()));
                self.reply(200, None, self.order())
            }
            ("cert", Some(_)) => {
                let pem = self.state.lock().unwrap().issued.clone().unwrap();
                let mut rsp = self.reply(200, None, Value::Null);
                rsp.body = Box::new(Bytes::from(pem));
                rsp
            }
            other => panic!("unexpected ACME request {method} {other:?}"),
        }
    }

    fn order(&self) -> Value {
        let state = self.state.lock().unwrap();
        let status = if state.issued.is_some() {
            "valid"
        } else if state.valid.iter().all(|valid| *valid) {
            "ready"
        } else {
            "pending"
        };
        let authorizations: Vec<String> = (0..state.domains.len())
            .map(|index| format!("{CA}/authz/{index}"))
            .collect();
        let mut order = json!({
            "status": status,
            "authorizations": authorizations,
            "finalize": format!("{CA}/finalize/1"),
        });
        if state.issued.is_some() {
            order["certificate"] = json!(format!("{CA}/cert/1"));
        }
        order
    }

    fn authz(&self, index: usize) -> Value {
        let state = self.state.lock().unwrap();
        let status = if state.valid[index] {
            "valid"
        } else {
            "pending"
        };
        json!({
            "identifier": {"type": "dns", "value": state.domains[index]},
            "status": status,
            "challenges": [challenge(index, status)],
        })
    }

    fn reply(&self, status: u16, location: Option<String>, body: Value) -> BytesResponse {
        let nonce = {
            let mut state = self.state.lock().unwrap();
            state.nonce += 1;
            format!("nonce-{}", state.nonce)
        };
        let mut rsp = http::Response::builder()
            .status(status)
            .header("Replay-Nonce", nonce)
            .header("Content-Type", "application/json");
        if let Some(location) = location {
            rsp = rsp.header("Location", location);
        }
        let bytes = if body.is_null() {
            Vec::new()
        } else {
            serde_json::to_vec(&body).unwrap()
        };
        BytesResponse::from(rsp.body(BodyWrapper::from(bytes)).unwrap())
    }
}

fn challenge(index: usize, status: &str) -> Value {
    json!({
        "type": "http-01",
        "url": format!("{CA}/chall/{index}"),
        "token": format!("token-{index}"),
        "status": status,
    })
}

fn decode(value: &Value) -> Vec<u8> {
    URL_SAFE_NO_PAD.decode(value.as_str().unwrap()).unwrap()
}

/// What a CA does for HTTP-01: GET the token and read the body.
async fn http_get(addr: SocketAddr, token: &str) -> Option<String> {
    let response = raw_get(addr, &format!("/.well-known/acme-challenge/{token}")).await?;
    let (head, body) = response.split_once("\r\n\r\n")?;
    head.starts_with("HTTP/1.1 200").then(|| body.to_string())
}

async fn raw_get(addr: SocketAddr, path: &str) -> Option<String> {
    let mut sock = TcpStream::connect(addr).await.ok()?;
    let request = format!("GET {path} HTTP/1.1\r\nHost: {DOMAIN}\r\nConnection: close\r\n\r\n");
    sock.write_all(request.as_bytes()).await.ok()?;
    let mut response = String::new();
    sock.read_to_string(&mut response).await.ok()?;
    Some(response)
}

fn config(dir: &std::path::Path, http01: SocketAddr) -> AcmeConfig {
    AcmeConfig {
        directory_url: format!("{CA}/directory"),
        domains: vec![DOMAIN.into()],
        contact: "mailto:ops@example.test".into(),
        cache_dir: dir.join("acme"),
        http_bind: http01.to_string(),
    }
}

/// A TLS listener that keeps running for the whole test, so a reload is
/// seen by the next handshake on the same socket.
async fn tls_listener(manager: Arc<TlsManager>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((sock, _)) = listener.accept().await {
            let acceptor = manager.acceptor();
            tokio::spawn(async move {
                if let Ok(mut tls) = acceptor.accept(sock).await {
                    let _ = tls.read(&mut [0u8; 1]).await;
                }
            });
        }
    });
    addr
}

/// Handshake as `DOMAIN`, trusting only the fake CA's root. Returns the
/// leaf the server presented.
async fn leaf_from(addr: SocketAddr, root: &[u8]) -> Vec<u8> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(root.to_vec().into()).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let sock = TcpStream::connect(addr).await.unwrap();
    let tls = tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(
            rustls::pki_types::ServerName::try_from(DOMAIN).unwrap(),
            sock,
        )
        .await
        .expect("handshake against the ACME certificate");
    tls.get_ref().1.peer_certificates().unwrap()[0].to_vec()
}

#[tokio::test]
async fn acme_issues_over_http01_and_renewal_swaps_the_listener_certificate() {
    let dir = tempfile::tempdir().unwrap();
    let http = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http01 = http.local_addr().unwrap();
    let ca = FakeCa::new(http01);
    let acme = Arc::new(
        Acme::with_client(
            config(dir.path(), http01),
            Arc::new(Client(Arc::clone(&ca))),
        )
        .unwrap(),
    );
    let shutdown = CancellationToken::new();
    tokio::spawn(Arc::clone(&acme).serve_http01(http, shutdown.clone()));

    assert!(acme.ensure().await.unwrap(), "first start issues");
    assert_eq!(
        ca.state.lock().unwrap().contact,
        vec!["mailto:ops@example.test"]
    );
    #[cfg(unix)]
    for path in [acme.key_path(), acme.cert_path()] {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "{}", path.display());
    }

    // The issued pair is what the SMTP listeners serve, through TlsManager.
    let manager = Arc::new(TlsManager::load(&acme.cert_path(), &acme.key_path()).unwrap());
    let addr = tls_listener(Arc::clone(&manager)).await;
    let first = leaf_from(addr, &ca.root_der()).await;

    // A current certificate is kept: no new order.
    assert!(!acme.ensure().await.unwrap());
    assert_eq!(ca.state.lock().unwrap().orders, 1);

    // Renewal writes a new pair and the reload hook swaps it in place.
    acme.issue().await.unwrap();
    manager.reload().unwrap();
    let second = leaf_from(addr, &ca.root_der()).await;
    assert_ne!(first, second, "the renewed certificate is served");
    let counts = {
        let state = ca.state.lock().unwrap();
        (state.accounts, state.orders)
    };
    assert_eq!(counts, (1, 2), "the account is reused");

    // Outside an order the responder knows no tokens.
    let response = raw_get(http01, "/.well-known/acme-challenge/token-0")
        .await
        .unwrap();
    assert!(response.starts_with("HTTP/1.1 404"), "{response}");
    let response = raw_get(http01, "/").await.unwrap();
    assert!(response.starts_with("HTTP/1.1 404"), "{response}");
    shutdown.cancel();
}

#[tokio::test]
async fn failed_challenge_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    // Nothing answers HTTP-01 on this address.
    let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http01 = closed.local_addr().unwrap();
    drop(closed);
    let ca = FakeCa::new(http01);
    let acme = Acme::with_client(config(dir.path(), http01), Arc::new(Client(ca))).unwrap();
    let err = acme.ensure().await.unwrap_err().to_string();
    assert!(err.contains("expected token-0"), "{err}");
    assert!(!acme.cert_path().exists());
    assert!(!acme.key_path().exists());
}

#[tokio::test]
async fn due_certificate_is_renewed_and_a_failed_renewal_keeps_it() {
    let dir = tempfile::tempdir().unwrap();
    let http = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http01 = http.local_addr().unwrap();
    let ca = FakeCa::new(http01);
    ca.state.lock().unwrap().days_left = Some(10);
    let client = Arc::new(Client(Arc::clone(&ca)));
    let acme = Arc::new(Acme::with_client(config(dir.path(), http01), client).unwrap());
    let shutdown = CancellationToken::new();
    tokio::spawn(Arc::clone(&acme).serve_http01(http, shutdown.clone()));

    assert!(acme.ensure().await.unwrap());
    assert!(
        acme.ensure().await.unwrap(),
        "10 days of 90 left is in the renewal window"
    );
    assert_eq!(ca.state.lock().unwrap().orders, 2);

    // The CA can no longer validate us: keep serving what we have.
    ca.state.lock().unwrap().refuse = true;
    let before = std::fs::read(acme.cert_path()).unwrap();
    assert!(!acme.ensure().await.unwrap());
    assert_eq!(ca.state.lock().unwrap().orders, 3);
    assert_eq!(std::fs::read(acme.cert_path()).unwrap(), before);
    TlsManager::load(&acme.cert_path(), &acme.key_path()).unwrap();
    shutdown.cancel();
}

#[test]
fn renewal_is_due_in_the_last_third_of_the_lifetime() {
    let pem = |days_left: i64| {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec![DOMAIN.to_string()]).unwrap();
        let now = time::OffsetDateTime::now_utc();
        params.not_after = now + time::Duration::days(days_left);
        params.not_before = params.not_after - time::Duration::days(90);
        params.self_signed(&key).unwrap().pem()
    };
    let now = SystemTime::now();
    assert!(!renewal_due(pem(31).as_bytes(), now).unwrap());
    assert!(renewal_due(pem(29).as_bytes(), now).unwrap());
    assert!(renewal_due(pem(-1).as_bytes(), now).unwrap());
    assert!(renewal_due(b"not a certificate", now).is_err());
}
