//! In-process gateway for integration tests. Listeners bind port 0.
//!
//! The gateway runs the daemon's SMTP server, check stack and spool, and
//! [`TestGateway::run_pipeline`] runs the daemon's scan pipeline
//! (`currawongd::classify_pending`) over the spool. Outbound delivery is not
//! started: it needs DNS and a downstream MX.
use currawong_auth::AuthChecker;
use currawong_core::config::{Config, ListenerConfig, ListenerMode, ListenerRole};
use currawong_quarantine::QuarantineStore;
use currawong_smtp::{
    checks::CheckStack, dns::MapDns, relay::Relay, server::SmtpServer, session::SessionContext,
};
use currawong_spool::{Spool, SpoolState};
use currawongd::{classify_pending, Pipeline};
use mail_send::SmtpClientBuilder;
use std::{net::SocketAddr, sync::Arc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Mutex,
};
use tokio_util::sync::CancellationToken;

pub struct TestGateway {
    pub addr: SocketAddr,
    pub spool: Arc<Spool>,
    pub cfg: Arc<Config>,
    pub quarantine: QuarantineStore,
    pipeline: Mutex<Pipeline>,
    shutdown: CancellationToken,
    _dir: tempfile::TempDir,
}

/// Dropping the gateway stops its SMTP server.
impl Drop for TestGateway {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}

impl TestGateway {
    pub async fn shutdown(self) {
        self.shutdown.cancel();
    }

    /// The quarantine reason of every quarantined message.
    pub async fn quarantine_reasons(&self) -> Vec<String> {
        let mut out = Vec::new();
        for env in self.spool.list(SpoolState::Done).await.expect("list spool") {
            if env.pipeline == "quarantine" {
                out.push(self.quarantine.reason(env.id.as_str()).expect("reason"));
            }
        }
        out
    }

    /// One pass of the daemon's scan pipeline over everything spooled.
    pub async fn run_pipeline(&self) -> Result<(), String> {
        let mut pipeline = self.pipeline.lock().await;
        classify_pending(&self.spool, &mut pipeline, &self.quarantine).await
    }

    /// The pipeline label of every spooled message: `pending`, `deliver`,
    /// `quarantine` or `scan_defer`.
    pub async fn outcomes(&self) -> Vec<String> {
        let mut out = Vec::new();
        for state in [
            SpoolState::Incoming,
            SpoolState::Active,
            SpoolState::Deferred,
            SpoolState::Done,
        ] {
            for env in self.spool.list(state).await.expect("list spool") {
                out.push(env.pipeline);
            }
        }
        out
    }
}

pub async fn spawn_gateway(overrides: impl FnOnce(&mut Config)) -> TestGateway {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut cfg = Config::default();
    cfg.spool.dir = dir.path().join("spool");
    cfg.checks.dnsbl_enabled = false;
    cfg.checks.ratelimit_enabled = false;
    cfg.checks.greylist_enabled = false;
    cfg.checks.reputation_enabled = false;
    cfg.checks.greylist_database = dir.path().join("greylist.sqlite");
    cfg.relay.database = dir.path().join("relay.sqlite");
    cfg.domains.accept = vec!["example.test".into()];
    cfg.gateway.hostname = "mx.example.test".into();
    cfg.scanner.clamd.address.clear();
    cfg.scanner.worker_binary = None;
    cfg.listeners = vec![ListenerConfig {
        name: "test".into(),
        bind: "127.0.0.1:0".into(),
        mode: ListenerMode::Plain,
        role: ListenerRole::Inbound,
    }];
    overrides(&mut cfg);
    let listener_cfg = cfg.listeners.first().expect("a listener").clone();
    let listener = TcpListener::bind(&listener_cfg.bind)
        .await
        .expect("bind test listener");
    let addr = listener.local_addr().expect("local addr");
    let spool = Arc::new(Spool::open(&cfg.spool.dir).await.expect("spool"));
    let checks =
        CheckStack::from_checks(&cfg.checks, Arc::new(MapDns::new())).expect("check stack");
    let relay = Relay::open(&cfg.relay.database, &cfg.relay.tenants).expect("relay");
    let quarantine = QuarantineStore::open(cfg.spool.dir.join("quarantine")).expect("quarantine");
    let cfg = Arc::new(cfg);
    let auth = AuthChecker::offline(&cfg.auth.authserv_id).expect("auth");
    let pipeline = Pipeline::new(Arc::clone(&cfg), auth);
    let ctx = Arc::new(SessionContext {
        cfg: Arc::clone(&cfg),
        spool: Arc::clone(&spool),
        tls: None,
        checks: Arc::new(checks),
        relay: Arc::new(relay),
        role: listener_cfg.role.clone(),
    });
    let shutdown = CancellationToken::new();
    let token = shutdown.clone();
    tokio::spawn(async move {
        SmtpServer::new(ctx)
            .run(listener, token, listener_cfg.mode)
            .await;
    });
    TestGateway {
        addr,
        spool,
        cfg,
        quarantine,
        pipeline: Mutex::new(pipeline),
        shutdown,
        _dir: dir,
    }
}

/// The last SMTP reply of a transaction. `code` 0 means no reply (I/O error).
#[derive(Debug)]
pub struct SmtpResult {
    pub code: u16,
    pub message: String,
}

impl SmtpResult {
    pub fn accepted(&self) -> bool {
        self.code == 250
    }
}

/// Turn a `mail-send` reply, or its error, into an [`SmtpResult`].
macro_rules! reply {
    ($result:expr) => {
        match $result {
            Ok(response) => SmtpResult {
                code: response.code,
                message: response.message,
            },
            Err(mail_send::Error::UnexpectedReply(response)) => SmtpResult {
                code: response.code,
                message: response.message,
            },
            Err(err) => SmtpResult {
                code: 0,
                message: err.to_string(),
            },
        }
    };
}

/// Send one message and return the server's real reply: the first refusal
/// (MAIL, RCPT or DATA), or the final reply after the message body.
pub async fn send_eml(addr: SocketAddr, from: &str, to: &[&str], eml: &[u8]) -> SmtpResult {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
    let mut client = match SmtpClientBuilder::new(addr.ip().to_string(), addr.port())
        .implicit_tls(false)
        .helo_host("client.outside.test")
        .connect_plain()
        .await
    {
        Ok(client) => client,
        Err(mail_send::Error::UnexpectedReply(response)) => {
            return SmtpResult {
                code: response.code,
                message: response.message,
            }
        }
        Err(err) => {
            return SmtpResult {
                code: 0,
                message: err.to_string(),
            }
        }
    };
    let result = reply!(client.cmd(format!("MAIL FROM:<{from}>\r\n")).await);
    if result.code != 250 {
        return result;
    }
    for rcpt in to {
        let result = reply!(client.cmd(format!("RCPT TO:<{rcpt}>\r\n")).await);
        if !matches!(result.code, 250 | 251) {
            return result;
        }
    }
    let result = reply!(client.cmd(b"DATA\r\n").await);
    if result.code != 354 {
        return result;
    }
    if let Err(err) = client.write_message(eml).await {
        return SmtpResult {
            code: 0,
            message: err.to_string(),
        };
    }
    let result = reply!(client.read().await);
    let _ = client.quit().await;
    result
}

pub async fn read_banner(addr: SocketAddr) -> String {
    use tokio::io::{AsyncBufReadExt, BufReader};
    let mut sock = TcpStream::connect(addr).await.expect("connect");
    let (read, mut write) = sock.split();
    let mut read = BufReader::new(read);
    let mut line = String::new();
    read.read_line(&mut line).await.expect("banner");
    write.shutdown().await.ok();
    line
}

/// The EICAR test file, decoded at run time from XOR bytes (as in
/// `crates/scan/build.rs`). The contiguous string is never stored in the
/// repository.
pub fn eicar() -> Vec<u8> {
    const ENCODED: [u8; 68] = [
        114, 31, 101, 11, 122, 15, 106, 107, 122, 113, 30, 118, 122, 112, 114, 31, 30, 2, 122, 116,
        3, 29, 105, 105, 3, 29, 87, 14, 111, 99, 105, 107, 120, 7, 121, 126, 107, 100, 110, 107,
        120, 110, 7, 107, 100, 126, 99, 124, 99, 120, 127, 121, 7, 126, 111, 121, 126, 7, 108, 99,
        102, 111, 11, 14, 98, 1, 98, 0,
    ];
    let key = std::hint::black_box(0x2a);
    ENCODED.iter().map(|byte| byte ^ key).collect()
}

/// A message carrying EICAR as a plain text attachment, built at run time.
pub fn eicar_message() -> Vec<u8> {
    let mut eml = b"From: sender@outside.test\r\nTo: user@example.test\r\nSubject: EICAR test\r\nDate: Wed, 14 Oct 2026 01:00:00 +0000\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"b1\"\r\n\r\n--b1\r\nContent-Type: text/plain\r\n\r\nSee the attachment.\r\n--b1\r\nContent-Type: text/plain; name=\"eicar.txt\"\r\nContent-Disposition: attachment; filename=\"eicar.txt\"\r\n\r\n".to_vec();
    eml.extend_from_slice(&eicar());
    eml.extend_from_slice(b"\r\n--b1--\r\n");
    eml
}

/// A minimal clamd that speaks `zPING` and `zINSTREAM` and reports EICAR.
pub async fn spawn_fake_clamd() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind clamd");
    let addr = listener.local_addr().expect("clamd addr");
    let sample = Arc::new(eicar());
    tokio::spawn(async move {
        while let Ok((sock, _)) = listener.accept().await {
            tokio::spawn(serve_clamd(sock, Arc::clone(&sample)));
        }
    });
    addr
}

async fn serve_clamd(mut sock: TcpStream, sample: Arc<Vec<u8>>) -> std::io::Result<()> {
    let mut command = Vec::new();
    loop {
        let byte = sock.read_u8().await?;
        if byte == 0 {
            break;
        }
        command.push(byte);
        if command.len() > 64 {
            return Ok(());
        }
    }
    match command.as_slice() {
        b"zPING" => sock.write_all(b"PONG\0").await,
        b"zINSTREAM" => {
            let mut data = Vec::new();
            loop {
                let len = sock.read_u32().await? as usize;
                if len == 0 {
                    break;
                }
                let mut chunk = vec![0; len];
                sock.read_exact(&mut chunk).await?;
                data.extend_from_slice(&chunk);
            }
            let infected = data
                .windows(sample.len())
                .any(|window| window == &sample[..]);
            let reply: &[u8] = if infected {
                b"stream: Eicar-Test-Signature FOUND\0"
            } else {
                b"stream: OK\0"
            };
            sock.write_all(reply).await
        }
        _ => sock.write_all(b"UNKNOWN COMMAND\0").await,
    }
}
