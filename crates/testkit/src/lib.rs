//! In-process gateway for integration tests. Listeners bind port 0.
use currawong_core::config::{Config, ListenerConfig, ListenerMode, ListenerRole};
use currawong_smtp::{
    checks::CheckStack, relay::Relay, server::SmtpServer, session::SessionContext,
};
use currawong_spool::Spool;
use mail_send::SmtpClientBuilder;
use std::{net::SocketAddr, sync::Arc};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

pub struct TestGateway {
    pub addr: SocketAddr,
    pub spool: Arc<Spool>,
    shutdown: CancellationToken,
    _dir: tempfile::TempDir,
}

impl TestGateway {
    pub async fn shutdown(self) {
        self.shutdown.cancel();
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
    cfg.domains.accept = vec!["example.test".into()];
    cfg.gateway.hostname = "mx.example.test".into();
    cfg.listeners = vec![ListenerConfig {
        name: "test".into(),
        bind: "127.0.0.1:2525".into(),
        mode: ListenerMode::Plain,
        role: ListenerRole::Inbound,
    }];
    overrides(&mut cfg);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind port 0");
    let addr = listener.local_addr().expect("local addr");
    let spool = Arc::new(Spool::open(&cfg.spool.dir).await.expect("spool"));
    let cfg = Arc::new(cfg);
    let ctx = Arc::new(SessionContext {
        cfg,
        spool: Arc::clone(&spool),
        tls: None,
        checks: Arc::new(CheckStack::disabled()),
        relay: Arc::new(Relay::empty()),
        role: ListenerRole::Inbound,
    });
    let shutdown = CancellationToken::new();
    let token = shutdown.clone();
    tokio::spawn(async move {
        SmtpServer::new(ctx)
            .run(listener, token, ListenerMode::Plain)
            .await;
    });
    TestGateway {
        addr,
        spool,
        shutdown,
        _dir: dir,
    }
}

#[derive(Debug)]
pub struct SmtpResult {
    pub code: u16,
    pub message: String,
}

pub async fn send_eml(addr: SocketAddr, from: &str, to: &[&str], eml: &[u8]) -> SmtpResult {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
    let mut client = SmtpClientBuilder::new(addr.ip().to_string(), addr.port())
        .implicit_tls(false)
        .connect_plain()
        .await
        .expect("smtp connect");
    let params = mail_send::smtp::message::Parameters::default();
    client.mail_from(from, &params).await.expect("mail from");
    for rcpt in to {
        client.rcpt_to(rcpt, &params).await.expect("rcpt to");
    }
    client.data(eml).await.expect("data");
    SmtpResult {
        code: 250,
        message: "accepted".into(),
    }
}

pub async fn read_banner(addr: SocketAddr) -> String {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let mut sock = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let (read, mut write) = sock.split();
    let mut read = BufReader::new(read);
    let mut line = String::new();
    read.read_line(&mut line).await.expect("banner");
    write.shutdown().await.ok();
    line
}
