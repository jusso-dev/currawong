//! SMTP session, TLS, connection checks and submission (#14, #15, #18, #19).
//! Sessions run over `tokio::io::duplex`; listener tests bind 127.0.0.1:0.
use currawong_core::{
    config::{
        ChecksConfig, Config, DnsblListing, DnsblZone, ListenerMode, ListenerRole, TenantConfig,
    },
    Direction,
};
use currawong_smtp::{
    checks::{CheckStack, ConnCtx, GreylistCheck, MailCtx, VerdictSignal},
    dns::MapDns,
    limits::ConnectionLimits,
    relay::Relay,
    run_session,
    server::{Accept, SmtpServer},
    session::SessionContext,
    stream::BoxIo,
    tls::TlsManager,
};
use currawong_spool::{Spool, SpoolState};
use rcgen::generate_simple_self_signed;
use std::{
    future::Future,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicI64, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
    time::timeout,
};
use tokio_util::sync::CancellationToken;

const WAIT: Duration = Duration::from_secs(10);

// ---------------------------------------------------------------- harness

struct Harness {
    cfg: Config,
    spool: Arc<Spool>,
    dir: tempfile::TempDir,
}

async fn harness() -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::default();
    cfg.spool.dir = dir.path().join("spool");
    cfg.checks.ratelimit_enabled = false;
    cfg.checks.greylist_enabled = false;
    cfg.checks.reputation_enabled = false;
    cfg.checks.dnsbl_enabled = false;
    cfg.domains.accept = vec!["example.test".into()];
    cfg.gateway.hostname = "mx.example.test".into();
    let spool = Arc::new(Spool::open(&cfg.spool.dir).await.unwrap());
    Harness { cfg, spool, dir }
}

impl Harness {
    fn ctx(&self, role: ListenerRole) -> SessionContext {
        SessionContext {
            cfg: Arc::new(self.cfg.clone()),
            spool: Arc::clone(&self.spool),
            tls: None,
            checks: Arc::new(CheckStack::disabled()),
            relay: Arc::new(Relay::empty()),
            role,
        }
    }

    async fn incoming(&self) -> Vec<currawong_spool::Envelope> {
        self.spool.list(SpoolState::Incoming).await.unwrap()
    }

    /// Every file in `incoming/`, including temporary bodies.
    fn incoming_files(&self) -> Vec<String> {
        std::fs::read_dir(self.cfg.spool.dir.join("incoming"))
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().to_string())
            .collect()
    }
}

struct Client<S> {
    read: BufReader<tokio::io::ReadHalf<S>>,
    write: tokio::io::WriteHalf<S>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Client<S> {
    fn new(stream: S) -> Self {
        let (read, write) = tokio::io::split(stream);
        Self {
            read: BufReader::new(read),
            write,
        }
    }

    fn into_inner(self) -> S {
        self.read.into_inner().unsplit(self.write)
    }

    /// One complete, possibly multi-line, reply. Panics on a timeout and
    /// returns an empty string if the server closed the connection.
    async fn reply(&mut self) -> String {
        let mut all = String::new();
        loop {
            let mut line = Vec::new();
            let n = timeout(WAIT, self.read.read_until(b'\n', &mut line))
                .await
                .expect("timed out waiting for a reply")
                .unwrap_or(0);
            if n == 0 {
                return all;
            }
            let text = String::from_utf8_lossy(&line).to_string();
            all.push_str(&text);
            if text.len() < 4 || text.as_bytes()[3] == b' ' {
                return all;
            }
        }
    }

    async fn send(&mut self, bytes: &[u8]) {
        self.write.write_all(bytes).await.unwrap();
        self.write.flush().await.unwrap();
    }

    async fn cmd(&mut self, line: &str) -> String {
        self.send(format!("{line}\r\n").as_bytes()).await;
        self.reply().await
    }

    /// True if the server closes the connection within the wait.
    async fn closed(&mut self) -> bool {
        let mut buf = [0u8; 256];
        loop {
            match timeout(WAIT, self.read.read(&mut buf)).await {
                Ok(Ok(0)) | Ok(Err(_)) => return true,
                Ok(Ok(_)) => continue,
                Err(_) => return false,
            }
        }
    }
}

fn code(reply: &str) -> &str {
    reply.get(..3).unwrap_or("")
}

fn peer(octets: [u8; 4]) -> SocketAddr {
    SocketAddr::from((octets, 2525))
}

type Session = (
    Client<tokio::io::DuplexStream>,
    JoinHandle<()>,
    CancellationToken,
);

fn start_with(
    ctx: Arc<SessionContext>,
    peer: SocketAddr,
    buffer: usize,
    tls_info: Option<(String, String)>,
) -> Session {
    let (client, server) = tokio::io::duplex(buffer);
    let shutdown = CancellationToken::new();
    let token = shutdown.clone();
    let task = tokio::spawn(async move {
        run_session(BoxIo::new(server), peer, ctx, token, tls_info).await;
    });
    (Client::new(client), task, shutdown)
}

async fn start(
    ctx: SessionContext,
    peer: SocketAddr,
) -> (
    Client<tokio::io::DuplexStream>,
    JoinHandle<()>,
    CancellationToken,
) {
    let (mut client, task, shutdown) = start_with(Arc::new(ctx), peer, 1 << 20, None);
    let banner = client.reply().await;
    assert!(banner.starts_with("220 mx.example.test"), "{banner}");
    (client, task, shutdown)
}

async fn begin_transaction<S: AsyncRead + AsyncWrite + Unpin>(client: &mut Client<S>) {
    assert_eq!(code(&client.cmd("EHLO client.test").await), "250");
    assert_eq!(code(&client.cmd("MAIL FROM:<a@outside.test>").await), "250");
    assert_eq!(code(&client.cmd("RCPT TO:<b@example.test>").await), "250");
    assert_eq!(code(&client.cmd("DATA").await), "354");
}

// ------------------------------------------------------------ #14 session

#[tokio::test]
async fn session_local_mail_is_spooled_and_relay_is_denied() {
    let h = harness().await;
    let (mut c, _, _) = start(h.ctx(ListenerRole::Inbound), peer([203, 0, 113, 10])).await;
    let ehlo = c.cmd("EHLO client.test").await;
    let lines: Vec<&str> = ehlo.lines().collect();
    assert_eq!(lines.first(), Some(&"250-mx.example.test"), "{ehlo}");
    assert!(lines.last().unwrap().starts_with("250 "), "{ehlo}");
    for keyword in [
        "SIZE 52428800",
        "8BITMIME",
        "PIPELINING",
        "ENHANCEDSTATUSCODES",
        "SMTPUTF8",
    ] {
        assert!(
            lines.iter().any(|line| line[4..] == *keyword),
            "{keyword} missing: {ehlo}"
        );
    }
    assert_eq!(
        c.cmd("MAIL FROM:<a@outside.test>").await,
        "250 2.1.0 OK\r\n"
    );
    assert_eq!(
        c.cmd("RCPT TO:<b@other.test>").await,
        "550 5.7.1 Relaying denied\r\n"
    );
    assert_eq!(c.cmd("RCPT TO:<b@example.test>").await, "250 2.1.5 OK\r\n");
    assert_eq!(code(&c.cmd("DATA").await), "354");
    let done = c.cmd("Subject: hi\r\n\r\nhello\r\n.").await;
    assert!(done.starts_with("250 2.0.0 OK "), "{done}");
    assert_eq!(c.cmd("QUIT").await, "221 2.0.0 goodbye\r\n");
    let incoming = h.incoming().await;
    assert_eq!(incoming.len(), 1);
    assert_eq!(incoming[0].rcpt_to, vec!["b@example.test".to_string()]);
    assert_eq!(incoming[0].direction, Direction::Inbound);
    assert_eq!(
        h.spool.read_body(&incoming[0].id).await.unwrap(),
        b"Subject: hi\r\n\r\nhello\r\n"
    );
}

#[tokio::test]
async fn session_8bit_body_and_dot_stuffing_are_kept_byte_for_byte() {
    let h = harness().await;
    let (mut c, _, _) = start(h.ctx(ListenerRole::Inbound), peer([203, 0, 113, 11])).await;
    begin_transaction(&mut c).await;
    c.send(b"Subject: caf\xc3\xa9\r\n\r\nraw \xe9\xff\x80 octets\r\n..leading dot\r\n.\r\n")
        .await;
    let done = c.reply().await;
    assert!(done.starts_with("250 2.0.0"), "{done}");
    let incoming = h.incoming().await;
    assert_eq!(incoming.len(), 1);
    assert_eq!(
        h.spool.read_body(&incoming[0].id).await.unwrap(),
        b"Subject: caf\xc3\xa9\r\n\r\nraw \xe9\xff\x80 octets\r\n.leading dot\r\n"
    );
}

#[tokio::test]
async fn session_bare_lf_smuggling_is_refused_and_nothing_is_spooled() {
    let h = harness().await;
    for payload in [
        &b"line1\n.\nMAIL FROM:<evil@x.test>\r\nRCPT TO:<b@example.test>\r\nDATA\r\nsmuggled\r\n.\r\n"[..],
        &b"line1\r\n.\rMAIL FROM:<evil@x.test>\r\n.\r\n"[..],
    ] {
        let (mut c, _, _) = start(h.ctx(ListenerRole::Inbound), peer([203, 0, 113, 12])).await;
        begin_transaction(&mut c).await;
        c.send(payload).await;
        let reply = c.reply().await;
        assert!(reply.starts_with("554 5.5.2"), "{reply}");
        assert!(c.closed().await, "session must close after a bare newline");
    }
    assert!(h.incoming().await.is_empty());
    assert!(h.incoming_files().is_empty(), "{:?}", h.incoming_files());
}

#[tokio::test]
async fn session_line_limits_count_the_crlf() {
    let h = harness().await;
    let (mut c, _, _) = start(h.ctx(ListenerRole::Inbound), peer([203, 0, 113, 13])).await;
    let long = "A".repeat(1001);
    assert_eq!(c.cmd(&long).await, "500 5.5.2 line too long\r\n");
    assert!(c.closed().await);

    let (mut c, _, _) = start(h.ctx(ListenerRole::Inbound), peer([203, 0, 113, 13])).await;
    begin_transaction(&mut c).await;
    c.send(format!("{}\r\n", "x".repeat(998)).as_bytes()).await;
    c.send(format!("{}\r\n", "y".repeat(999)).as_bytes()).await;
    assert_eq!(c.reply().await, "500 5.5.2 line too long\r\n");
    assert!(c.closed().await);
    assert!(h.incoming().await.is_empty());
    assert!(h.incoming_files().is_empty(), "{:?}", h.incoming_files());
}

#[tokio::test]
async fn session_oversize_is_552_and_spools_nothing() {
    let mut h = harness().await;
    h.cfg.limits.max_message_bytes = 64;
    let (mut c, _, _) = start(h.ctx(ListenerRole::Inbound), peer([203, 0, 113, 14])).await;
    assert_eq!(code(&c.cmd("EHLO c.test").await), "250");
    assert_eq!(
        c.cmd("MAIL FROM:<a@x.test> SIZE=65").await,
        "552 5.3.4 message size exceeds limit\r\n"
    );
    assert_eq!(code(&c.cmd("MAIL FROM:<a@x.test> SIZE=64").await), "250");
    assert_eq!(code(&c.cmd("RCPT TO:<b@example.test>").await), "250");
    assert_eq!(code(&c.cmd("DATA").await), "354");
    let blob = "B".repeat(200);
    let reply = c.cmd(&format!("Subject: x\r\n\r\n{blob}\r\n.")).await;
    assert_eq!(reply, "552 5.3.4 message size exceeds limit\r\n");
    assert_eq!(
        code(&c.cmd("NOOP").await),
        "250",
        "session continues after 552"
    );
    assert!(h.incoming().await.is_empty());
    assert!(h.incoming_files().is_empty(), "{:?}", h.incoming_files());
}

#[tokio::test]
async fn session_body_streams_to_the_spool_before_the_final_dot() {
    let h = harness().await;
    let (mut c, _, _) = start(h.ctx(ListenerRole::Inbound), peer([203, 0, 113, 15])).await;
    begin_transaction(&mut c).await;
    let line = format!("{}\r\n", "z".repeat(900));
    for _ in 0..300 {
        c.send(line.as_bytes()).await;
    }
    let tmp_dir = h.cfg.spool.dir.join("incoming");
    let streamed = timeout(WAIT, async {
        loop {
            let big = std::fs::read_dir(&tmp_dir).unwrap().any(|entry| {
                let entry = entry.unwrap();
                entry.file_name().to_string_lossy().ends_with(".eml.tmp")
                    && entry.metadata().unwrap().len() > 200 * 1024
            });
            if big {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(
        streamed.is_ok(),
        "body was not written to the spool while DATA was open"
    );
    c.send(b".\r\n").await;
    assert!(c.reply().await.starts_with("250 2.0.0"));
    let files = h.incoming_files();
    assert!(
        files.iter().all(|name| !name.ends_with(".tmp")),
        "{files:?}"
    );
    let incoming = h.incoming().await;
    assert_eq!(
        h.spool.read_body(&incoming[0].id).await.unwrap().len(),
        300 * 902
    );
}

#[tokio::test]
async fn session_state_machine_and_parameter_errors() {
    let h = harness().await;
    let (mut c, _, _) = start(h.ctx(ListenerRole::Inbound), peer([203, 0, 113, 16])).await;
    assert_eq!(
        c.cmd("MAIL FROM:<a@x.test>").await,
        "503 5.5.1 send EHLO first\r\n"
    );
    assert_eq!(c.cmd("AUTH PLAIN").await, "503 5.5.1 send EHLO first\r\n");
    assert_eq!(code(&c.cmd("EHLO").await), "501", "EHLO needs a domain");
    assert_eq!(c.cmd("HELO client.test").await, "250 mx.example.test\r\n");
    assert_eq!(
        c.cmd("RCPT TO:<b@example.test>").await,
        "503 5.5.1 need MAIL first\r\n"
    );
    assert_eq!(c.cmd("DATA").await, "503 5.5.1 need RCPT first\r\n");
    assert_eq!(code(&c.cmd("MAIL FROM:<a@x.test> SIZE=abc").await), "501");
    assert_eq!(code(&c.cmd("MAIL FROM:<a@x.test> BODY=FOO").await), "501");
    assert_eq!(code(&c.cmd("MAIL FROM:<a@x.test> FROB=1").await), "555");
    assert_eq!(code(&c.cmd("MAIL FROM:junk<a@x.test>").await), "500");
    assert_eq!(
        code(&c.cmd("MAIL FROM:<a@x.test> BODY=8BITMIME SMTPUTF8").await),
        "250"
    );
    assert_eq!(
        c.cmd("MAIL FROM:<c@x.test>").await,
        "503 5.5.1 nested MAIL command\r\n"
    );
    assert_eq!(c.cmd("DATA").await, "503 5.5.1 need RCPT first\r\n");
    assert_eq!(
        code(&c.cmd("RCPT TO:<b@example.test> NOTIFY=NEVER").await),
        "555"
    );
    // A CR inside the path must not split the line into a second command.
    assert_eq!(
        code(&c.cmd("RCPT TO:<b@example.test\rQUIT\r>").await),
        "500"
    );
    assert_eq!(code(&c.cmd("RCPT TO:<b@example.test\0>").await), "500");
    assert_eq!(code(&c.cmd("RCPT TO:<postmaster>").await), "250");
    assert_eq!(code(&c.cmd("DATA").await), "354");
    assert!(c.cmd("Subject: pm\r\n\r\nhi\r\n.").await.starts_with("250"));
    let incoming = h.incoming().await;
    assert_eq!(
        incoming[0].rcpt_to,
        vec!["postmaster@example.test".to_string()]
    );
}

#[tokio::test]
async fn session_max_recipients_is_452() {
    let mut h = harness().await;
    h.cfg.limits.max_recipients = 2;
    let (mut c, _, _) = start(h.ctx(ListenerRole::Inbound), peer([203, 0, 113, 17])).await;
    assert_eq!(code(&c.cmd("EHLO c.test").await), "250");
    assert_eq!(code(&c.cmd("MAIL FROM:<a@x.test>").await), "250");
    assert_eq!(code(&c.cmd("RCPT TO:<one@example.test>").await), "250");
    assert_eq!(code(&c.cmd("RCPT TO:<two@example.test>").await), "250");
    assert_eq!(
        c.cmd("RCPT TO:<three@example.test>").await,
        "452 4.5.3 too many recipients\r\n"
    );
    assert_eq!(code(&c.cmd("DATA").await), "354");
    assert!(c.cmd("Subject: x\r\n\r\nx\r\n.").await.starts_with("250"));
    assert_eq!(h.incoming().await[0].rcpt_to.len(), 2);
}

#[tokio::test]
async fn session_idle_and_stalled_writers_time_out() {
    let mut h = harness().await;
    h.cfg.limits.smtp_command_timeout_secs = 1;
    let (mut c, _, _) = start(h.ctx(ListenerRole::Inbound), peer([203, 0, 113, 18])).await;
    let reply = c.reply().await;
    assert!(reply.starts_with("421 4.4.2"), "{reply}");
    assert!(c.closed().await);

    // A client that sends EHLO and never reads must not pin the session.
    let (mut c, task, _) = start_with(
        Arc::new(h.ctx(ListenerRole::Inbound)),
        peer([203, 0, 113, 18]),
        64,
        None,
    );
    c.send(b"EHLO client.test\r\n").await;
    timeout(WAIT, task)
        .await
        .expect("session stuck on a blocked write")
        .unwrap();
}

#[tokio::test]
async fn session_shutdown_lets_an_open_transaction_finish() {
    let h = harness().await;
    let (mut c, _, shutdown) = start(h.ctx(ListenerRole::Inbound), peer([203, 0, 113, 19])).await;
    begin_transaction(&mut c).await;
    c.send(b"Subject: drain\r\n\r\nfirst half\r\n").await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    shutdown.cancel();
    tokio::time::sleep(Duration::from_millis(50)).await;
    c.send(b"second half\r\n.\r\n").await;
    let done = c.reply().await;
    assert!(done.starts_with("250 2.0.0"), "{done}");
    assert!(c.reply().await.starts_with("421 4.3.2"));
    assert!(c.closed().await);
    let incoming = h.incoming().await;
    assert_eq!(
        h.spool.read_body(&incoming[0].id).await.unwrap(),
        b"Subject: drain\r\n\r\nfirst half\r\nsecond half\r\n"
    );

    // Shutdown between RCPT and DATA: the transaction may still complete.
    let (mut c, _, shutdown) = start(h.ctx(ListenerRole::Inbound), peer([203, 0, 113, 19])).await;
    assert_eq!(code(&c.cmd("EHLO client.test").await), "250");
    assert_eq!(code(&c.cmd("MAIL FROM:<a@outside.test>").await), "250");
    assert_eq!(code(&c.cmd("RCPT TO:<b@example.test>").await), "250");
    shutdown.cancel();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(code(&c.cmd("DATA").await), "354");
    assert!(c
        .cmd("Subject: late\r\n\r\nx\r\n.")
        .await
        .starts_with("250"));
    assert!(c.reply().await.starts_with("421 4.3.2"));
    assert_eq!(h.incoming().await.len(), 2);

    let (mut idle, _, shutdown) =
        start(h.ctx(ListenerRole::Inbound), peer([203, 0, 113, 19])).await;
    shutdown.cancel();
    assert!(idle.reply().await.starts_with("421 4.3.2"));
}

// ----------------------------------------------------------------- #15 TLS

fn write_cert(dir: &Path, name: &str) -> (PathBuf, PathBuf, Vec<u8>) {
    let rcgen::CertifiedKey { cert, key_pair } =
        generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_path = dir.join(format!("{name}.pem"));
    let key_path = dir.join(format!("{name}.key"));
    std::fs::write(&cert_path, cert.pem()).unwrap();
    std::fs::write(&key_path, key_pair.serialize_pem()).unwrap();
    (cert_path, key_path, cert.der().to_vec())
}

fn client_config(
    der: &[u8],
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(der.to_vec().into()).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    Arc::new(
        rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(versions)
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

fn tls_harness(h: &Harness) -> (Arc<TlsManager>, Vec<u8>) {
    let (cert, key, der) = write_cert(h.dir.path(), "a");
    (Arc::new(TlsManager::load(&cert, &key).unwrap()), der)
}

async fn starttls<S>(
    mut client: Client<S>,
    der: &[u8],
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> Client<tokio_rustls::client::TlsStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let ehlo = client.cmd("EHLO client.test").await;
    assert!(ehlo.contains("STARTTLS"), "{ehlo}");
    assert!(
        !ehlo.contains("AUTH"),
        "AUTH must not be offered in clear text: {ehlo}"
    );
    assert_eq!(
        client.cmd("STARTTLS").await,
        "220 2.0.0 Ready to start TLS\r\n"
    );
    let connector = tokio_rustls::TlsConnector::from(client_config(der, versions));
    let tls = connector
        .connect(
            rustls::pki_types::ServerName::try_from("localhost").unwrap(),
            client.into_inner(),
        )
        .await
        .unwrap();
    Client::new(tls)
}

fn negotiated<S>(
    client: Client<tokio_rustls::client::TlsStream<S>>,
) -> (
    Client<tokio_rustls::client::TlsStream<S>>,
    Option<rustls::ProtocolVersion>,
)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let stream = client.into_inner();
    let version = stream.get_ref().1.protocol_version();
    (Client::new(stream), version)
}

#[tokio::test]
async fn tls_starttls_negotiates_tls13_and_requires_a_fresh_ehlo() {
    let h = harness().await;
    let (manager, der) = tls_harness(&h);
    let mut ctx = h.ctx(ListenerRole::Inbound);
    ctx.tls = Some(manager);
    let (mut c, _, _) = start_with(Arc::new(ctx), peer([203, 0, 113, 21]), 1 << 20, None);
    assert!(c.reply().await.starts_with("220"));
    let tls = starttls(c, &der, &[&rustls::version::TLS13, &rustls::version::TLS12]).await;
    let (mut tls, version) = negotiated(tls);
    assert_eq!(version, Some(rustls::ProtocolVersion::TLSv1_3));
    assert_eq!(
        tls.cmd("MAIL FROM:<a@outside.test>").await,
        "503 5.5.1 send EHLO first\r\n"
    );
    let ehlo = tls.cmd("EHLO client.test").await;
    assert!(!ehlo.contains("STARTTLS"), "{ehlo}");
    assert!(ehlo.contains("AUTH PLAIN LOGIN"), "{ehlo}");
    assert_eq!(code(&tls.cmd("STARTTLS").await), "503");
    assert_eq!(code(&tls.cmd("MAIL FROM:<a@outside.test>").await), "250");
    assert_eq!(code(&tls.cmd("RCPT TO:<b@example.test>").await), "250");
    assert_eq!(code(&tls.cmd("DATA").await), "354");
    assert!(tls
        .cmd("Subject: tls\r\n\r\nx\r\n.")
        .await
        .starts_with("250"));
    let env = &h.incoming().await[0];
    assert_eq!(env.tls_version.as_deref(), Some("TLSv1_3"));
    assert!(
        env.tls_cipher.as_deref().unwrap().starts_with("TLS13_"),
        "{env:?}"
    );
}

#[tokio::test]
async fn tls_12_is_accepted_and_11_is_refused_with_an_alert() {
    let h = harness().await;
    let (manager, der) = tls_harness(&h);
    let mut ctx = h.ctx(ListenerRole::Inbound);
    ctx.tls = Some(Arc::clone(&manager));
    let (mut c, _, _) = start_with(Arc::new(ctx), peer([203, 0, 113, 22]), 1 << 20, None);
    assert!(c.reply().await.starts_with("220"));
    let (_, version) = negotiated(starttls(c, &der, &[&rustls::version::TLS12]).await);
    assert_eq!(version, Some(rustls::ProtocolVersion::TLSv1_2));

    let (addr, _stop) = listen(&h, Some(manager), ListenerMode::Implicit, None).await;
    let mut sock = TcpStream::connect(addr).await.unwrap();
    sock.write_all(&tls11_client_hello()).await.unwrap();
    let mut buf = [0u8; 7];
    timeout(WAIT, sock.read_exact(&mut buf))
        .await
        .expect("no reply to a TLS 1.1 ClientHello")
        .expect("server closed without a TLS alert");
    assert_eq!(buf[0], 0x15, "expected an alert record, got {buf:02x?}");
    assert_eq!(buf[5], 2, "alert must be fatal: {buf:02x?}");
    // rustls answers with handshake_failure (40); protocol_version (70) is also correct.
    assert!(matches!(buf[6], 40 | 70), "unexpected alert: {buf:02x?}");
}

#[tokio::test]
async fn tls_handshakes_that_stall_are_dropped() {
    let mut h = harness().await;
    h.cfg.limits.tls_handshake_timeout_secs = 1;
    let (manager, _) = tls_harness(&h);

    let (addr, _stop) = listen(&h, Some(Arc::clone(&manager)), ListenerMode::Implicit, None).await;
    let mut sock = TcpStream::connect(addr).await.unwrap();
    let mut buf = [0u8; 16];
    let read = timeout(WAIT, sock.read(&mut buf)).await;
    assert!(
        matches!(read, Ok(Ok(0)) | Ok(Err(_))),
        "implicit TLS slot was held: {read:?}"
    );

    let mut ctx = h.ctx(ListenerRole::Inbound);
    ctx.tls = Some(manager);
    let (mut c, task, _) = start_with(Arc::new(ctx), peer([203, 0, 113, 23]), 1 << 20, None);
    assert!(c.reply().await.starts_with("220"));
    assert_eq!(code(&c.cmd("EHLO c.test").await), "250");
    assert_eq!(code(&c.cmd("STARTTLS").await), "220");
    timeout(WAIT, task)
        .await
        .expect("STARTTLS handshake never timed out")
        .unwrap();
}

#[tokio::test]
async fn tls_certificate_reload_is_visible_to_the_next_handshake() {
    let h = harness().await;
    let (cert_a, key_a, der_a) = write_cert(h.dir.path(), "a");
    let (cert_b, key_b, der_b) = write_cert(h.dir.path(), "b");
    let manager = Arc::new(TlsManager::load(&cert_a, &key_a).unwrap());
    let (addr, _stop) = listen(&h, Some(Arc::clone(&manager)), ListenerMode::Implicit, None).await;
    let first = tls_connect(addr, &der_a).await;
    manager.reload_from(&cert_b, &key_b).unwrap();
    let second = tls_connect(addr, &der_b).await;
    assert_eq!(peer_der(&first), der_a);
    assert_eq!(peer_der(&second), der_b);
}

fn peer_der(stream: &tokio_rustls::client::TlsStream<TcpStream>) -> Vec<u8> {
    stream
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|certs| certs.first())
        .map(|cert| cert.as_ref().to_vec())
        .unwrap_or_default()
}

async fn tls_connect(addr: SocketAddr, der: &[u8]) -> tokio_rustls::client::TlsStream<TcpStream> {
    let sock = TcpStream::connect(addr).await.unwrap();
    let connector = tokio_rustls::TlsConnector::from(client_config(
        der,
        &[&rustls::version::TLS13, &rustls::version::TLS12],
    ));
    connector
        .connect(
            rustls::pki_types::ServerName::try_from("localhost").unwrap(),
            sock,
        )
        .await
        .unwrap()
}

fn tls11_client_hello() -> Vec<u8> {
    let mut hello = vec![
        0x01, 0x00, 0x00, 0x00, // handshake type, length fixed below
        0x03, 0x02, // client version TLS 1.1
    ];
    hello.extend_from_slice(&[0x11; 32]); // random
    hello.push(0x00); // session id
    hello.extend_from_slice(&[0x00, 0x02, 0x00, 0x2f]); // one cipher
    hello.extend_from_slice(&[0x01, 0x00]); // null compression
    let hs_len = (hello.len() - 4) as u16;
    hello[2] = (hs_len >> 8) as u8;
    hello[3] = hs_len as u8;
    let mut record = vec![0x16, 0x03, 0x02, 0x00, hello.len() as u8];
    record.extend(hello);
    record
}

// --------------------------------------------------------- listener limits

struct Stop(CancellationToken);

impl Drop for Stop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

async fn listen(
    h: &Harness,
    tls: Option<Arc<TlsManager>>,
    mode: ListenerMode,
    limits: Option<Arc<ConnectionLimits>>,
) -> (SocketAddr, Stop) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mut ctx = h.ctx(ListenerRole::Inbound);
    ctx.tls = tls;
    let ctx = Arc::new(ctx);
    let server = match limits {
        Some(limits) => SmtpServer::with_limits(ctx, limits),
        None => SmtpServer::new(ctx),
    };
    let shutdown = CancellationToken::new();
    let token = shutdown.clone();
    tokio::spawn(async move { server.run(listener, token, mode).await });
    (addr, Stop(shutdown))
}

async fn banner(addr: SocketAddr) -> (Client<TcpStream>, String) {
    let mut client = Client::new(TcpStream::connect(addr).await.unwrap());
    let reply = client.reply().await;
    (client, reply)
}

#[tokio::test]
async fn limits_per_ip_cap_holds_through_the_server_and_across_listeners() {
    let mut h = harness().await;
    h.cfg.limits.max_connections_per_ip = 1;
    let (addr, _stop) = listen(&h, None, ListenerMode::Plain, None).await;
    let (_held, first) = banner(addr).await;
    assert!(first.starts_with("220"), "{first}");
    let (_, second) = banner(addr).await;
    assert_eq!(second, "421 4.7.0 too many connections\r\n");

    let shared = ConnectionLimits::new(100, 1);
    let (port25, _a) = listen(&h, None, ListenerMode::Plain, Some(Arc::clone(&shared))).await;
    let (port587, _b) = listen(&h, None, ListenerMode::Plain, Some(shared)).await;
    let (mut held, first) = banner(port25).await;
    assert!(first.starts_with("220"), "{first}");
    let (_, other) = banner(port587).await;
    assert_eq!(other, "421 4.7.0 too many connections\r\n");
    assert_eq!(code(&held.cmd("QUIT").await), "221");
    assert!(held.closed().await);
    let (_, again) = timeout(WAIT, async {
        loop {
            let (client, reply) = banner(port587).await;
            if reply.starts_with("220") {
                return (client, reply);
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("slot was not released");
    assert!(again.starts_with("220"));
}

/// Fails the first `accept()` the way EMFILE would, then behaves.
struct FlakyListener {
    inner: TcpListener,
    failed: AtomicBool,
}

impl Accept for FlakyListener {
    fn accept(&self) -> impl Future<Output = std::io::Result<(TcpStream, SocketAddr)>> + Send {
        let fail = !self.failed.swap(true, Ordering::SeqCst);
        async move {
            if fail {
                return Err(std::io::Error::other("Too many open files"));
            }
            self.inner.accept().await
        }
    }
}

#[tokio::test]
async fn limits_accept_errors_do_not_stop_the_listener() {
    let h = harness().await;
    let inner = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = inner.local_addr().unwrap();
    let listener = FlakyListener {
        inner,
        failed: AtomicBool::new(false),
    };
    let server = SmtpServer::new(Arc::new(h.ctx(ListenerRole::Inbound)));
    let shutdown = CancellationToken::new();
    let _stop = Stop(shutdown.clone());
    tokio::spawn(async move { server.run(listener, shutdown, ListenerMode::Plain).await });
    let (_, reply) = banner(addr).await;
    assert!(
        reply.starts_with("220"),
        "listener stopped after an accept error: {reply:?}"
    );
}

// --------------------------------------------------------------- #18 checks

fn checks_cfg(dir: &Path) -> ChecksConfig {
    ChecksConfig {
        dnsbl_enabled: false,
        ratelimit_enabled: false,
        greylist_enabled: false,
        reputation_enabled: false,
        greylist_database: dir.join("grey.sqlite"),
        rate_per_minute_ip: 1000,
        rate_per_minute_net: 1000,
        rate_per_minute_sender: 1000,
        ..ChecksConfig::default()
    }
}

fn listed(ip: IpAddr) -> (DnsblZone, Arc<MapDns>) {
    let zone = DnsblZone {
        zone: "zen.example.test".into(),
        dqs_key: None,
        listings: vec![DnsblListing {
            code: "127.0.0.2".into(),
            reason: "listed by zen.example.test".into(),
        }],
    };
    let mut map = MapDns::new();
    let name = currawong_smtp::checks::DnsblCheck::query_name(ip, &zone).unwrap();
    map.ips.insert(name, vec!["127.0.0.2".parse().unwrap()]);
    (zone, Arc::new(map))
}

fn with_checks_arc(h: &Harness, checks: Arc<CheckStack>) -> SessionContext {
    let mut ctx = h.ctx(ListenerRole::Inbound);
    ctx.checks = checks;
    ctx
}

fn with_checks(h: &Harness, checks: CheckStack, role: ListenerRole) -> SessionContext {
    let mut ctx = h.ctx(role);
    ctx.checks = Arc::new(checks);
    ctx
}

#[tokio::test]
async fn checks_dnsbl_listing_is_554_at_connect_for_mapped_ipv4() {
    let h = harness().await;
    let ip: IpAddr = "203.0.113.9".parse().unwrap();
    let (zone, dns) = listed(ip);
    let cfg = ChecksConfig {
        dnsbl_enabled: true,
        dnsbl: vec![zone],
        ..checks_cfg(h.dir.path())
    };
    let ctx = Arc::new(with_checks(
        &h,
        CheckStack::from_checks(&cfg, dns).unwrap(),
        ListenerRole::Inbound,
    ));
    let mapped: IpAddr = "::ffff:203.0.113.9".parse().unwrap();
    let (mut c, _, _) = start_with(ctx, SocketAddr::new(mapped, 2525), 1 << 20, None);
    assert_eq!(c.reply().await, "554 5.7.1 listed by zen.example.test\r\n");
    assert!(c.closed().await);
}

#[tokio::test]
async fn checks_rate_limit_is_421_and_allow_list_comes_first() {
    let h = harness().await;
    let cfg = ChecksConfig {
        ratelimit_enabled: true,
        rate_per_minute_ip: 1,
        allow_cidrs: vec!["198.51.100.0/24".into()],
        ..checks_cfg(h.dir.path())
    };
    let ctx = Arc::new(with_checks(
        &h,
        CheckStack::from_checks(&cfg, Arc::new(MapDns::new())).unwrap(),
        ListenerRole::Inbound,
    ));
    let (mut first, _, _) = start_with(Arc::clone(&ctx), peer([203, 0, 113, 30]), 1 << 20, None);
    assert!(first.reply().await.starts_with("220"));
    let (mut second, _, _) = start_with(Arc::clone(&ctx), peer([203, 0, 113, 30]), 1 << 20, None);
    assert_eq!(
        second.reply().await,
        "421 4.7.0 rate limit exceeded, try again later\r\n"
    );
    assert!(second.closed().await);
    for _ in 0..3 {
        let (mut allowed, _, _) =
            start_with(Arc::clone(&ctx), peer([198, 51, 100, 4]), 1 << 20, None);
        assert!(
            allowed.reply().await.starts_with("220"),
            "allow-listed network was rate limited"
        );
    }
}

#[tokio::test]
async fn checks_sender_rate_limit_is_keyed_on_network_and_domain() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = ChecksConfig {
        ratelimit_enabled: true,
        rate_per_minute_sender: 1,
        ..checks_cfg(dir.path())
    };
    let stack = CheckStack::from_checks(&cfg, Arc::new(MapDns::new())).unwrap();
    let mail = |ip: [u8; 4]| MailCtx {
        ip: IpAddr::from(ip),
        mail_from: "ceo@bigcorp.test".into(),
    };
    assert_eq!(
        stack.on_mail(&mail([203, 0, 113, 1])).await,
        currawong_smtp::checks::CheckResult::Pass
    );
    assert!(matches!(
        stack.on_mail(&mail([203, 0, 113, 2])).await,
        currawong_smtp::checks::CheckResult::TempFail(line) if line.starts_with("421 4.7.0")
    ));
    assert_eq!(
        stack.on_mail(&mail([198, 51, 100, 1])).await,
        currawong_smtp::checks::CheckResult::Pass,
        "a forger on one network must not use up the domain's budget elsewhere"
    );
}

#[tokio::test]
async fn checks_421_from_mail_closes_the_session() {
    let h = harness().await;
    let cfg = ChecksConfig {
        ratelimit_enabled: true,
        rate_per_minute_sender: 1,
        ..checks_cfg(h.dir.path())
    };
    let stack = CheckStack::from_checks(&cfg, Arc::new(MapDns::new())).unwrap();
    let (mut c, _, _) = start(
        with_checks(&h, stack, ListenerRole::Inbound),
        peer([203, 0, 113, 31]),
    )
    .await;
    assert_eq!(code(&c.cmd("EHLO c.test").await), "250");
    assert_eq!(code(&c.cmd("MAIL FROM:<a@sender.test>").await), "250");
    assert_eq!(code(&c.cmd("RSET").await), "250");
    let reply = c.cmd("MAIL FROM:<a@sender.test>").await;
    assert!(reply.starts_with("421 4.7.0"), "{reply}");
    assert!(c.closed().await, "a 421 reply must close the connection");
}

fn clocked_greylist(path: &Path) -> (GreylistCheck, Arc<AtomicI64>) {
    let clock = Arc::new(AtomicI64::new(
        time::OffsetDateTime::now_utc().unix_timestamp(),
    ));
    let reader = Arc::clone(&clock);
    let check = GreylistCheck::open(path, 300)
        .unwrap()
        .with_clock(Arc::new(move || reader.load(Ordering::SeqCst)));
    (check, clock)
}

#[tokio::test]
async fn checks_greylist_is_451_then_250_after_the_delay() {
    let h = harness().await;
    let mut stack =
        CheckStack::from_checks(&checks_cfg(h.dir.path()), Arc::new(MapDns::new())).unwrap();
    let (grey, clock) = clocked_greylist(&h.dir.path().join("grey.sqlite"));
    stack.greylist = Some(grey);
    let ctx = Arc::new(with_checks(&h, stack, ListenerRole::Inbound));
    let attempt = |ctx: Arc<SessionContext>| async move {
        let (mut c, _, _) = start_with(ctx, peer([203, 0, 113, 40]), 1 << 20, None);
        assert!(c.reply().await.starts_with("220"));
        assert_eq!(code(&c.cmd("EHLO sender.test").await), "250");
        assert_eq!(code(&c.cmd("MAIL FROM:<a@sender.test>").await), "250");
        c.cmd("RCPT TO:<b@example.test>").await
    };
    assert_eq!(
        attempt(Arc::clone(&ctx)).await,
        "451 4.7.1 greylisted, try again later\r\n"
    );
    clock.fetch_add(60, Ordering::SeqCst);
    assert_eq!(
        code(&attempt(Arc::clone(&ctx)).await),
        "451",
        "retry before the delay"
    );
    clock.fetch_add(241, Ordering::SeqCst);
    assert_eq!(attempt(Arc::clone(&ctx)).await, "250 2.1.5 OK\r\n");
}

#[tokio::test]
async fn checks_trusted_and_authenticated_senders_skip_connection_checks() {
    let mut h = harness().await;
    h.cfg.relay.tenants = vec![TenantConfig {
        id: "acme".into(),
        domains: vec!["acme.test".into()],
        trusted_cidrs: vec!["10.0.0.0/8".into()],
    }];
    let trusted_ip: IpAddr = "10.1.2.3".parse().unwrap();
    let (zone, dns) = listed(trusted_ip);
    let cfg = ChecksConfig {
        dnsbl_enabled: true,
        dnsbl: vec![zone],
        ratelimit_enabled: true,
        rate_per_minute_ip: 1,
        rate_per_minute_sender: 1,
        greylist_enabled: true,
        ..checks_cfg(h.dir.path())
    };
    let relay =
        Arc::new(Relay::open(&h.dir.path().join("relay.sqlite"), &h.cfg.relay.tenants).unwrap());
    relay
        .upsert_credential("acme", "app", "s3cret-pass")
        .unwrap();
    relay.add_sender_address("app", "app@acme.test").unwrap();
    let mut ctx = with_checks(
        &h,
        CheckStack::from_checks(&cfg, dns).unwrap(),
        ListenerRole::Submission,
    );
    ctx.relay = Arc::clone(&relay);
    let (manager, der) = tls_harness(&h);
    ctx.tls = Some(manager);
    let ctx = Arc::new(ctx);
    for _ in 0..2 {
        let (mut c, _, _) = start_with(
            Arc::clone(&ctx),
            SocketAddr::new(trusted_ip, 2525),
            1 << 20,
            None,
        );
        assert!(
            c.reply().await.starts_with("220"),
            "trusted host hit DNSBL or rate limit"
        );
        assert_eq!(code(&c.cmd("EHLO app.acme.test").await), "250");
        assert_eq!(code(&c.cmd("MAIL FROM:<app@acme.test>").await), "250");
        assert_eq!(
            c.cmd("RCPT TO:<x@example.test>").await,
            "250 2.1.5 OK\r\n",
            "trusted host was greylisted"
        );
    }
    // Authenticated submission from an untrusted address skips greylisting
    // and the per-sender limit.
    let (mut c, _, _) = start_with(Arc::clone(&ctx), peer([203, 0, 113, 77]), 1 << 20, None);
    assert!(c.reply().await.starts_with("220"));
    let mut tls = starttls(c, &der, &[&rustls::version::TLS13]).await;
    assert_eq!(code(&tls.cmd("EHLO laptop").await), "250");
    let token = base64_plain("app", "s3cret-pass");
    assert_eq!(code(&tls.cmd(&format!("AUTH PLAIN {token}")).await), "235");
    for n in 0..2 {
        assert_eq!(
            code(&tls.cmd("MAIL FROM:<app@acme.test>").await),
            "250",
            "round {n}"
        );
        assert_eq!(
            code(&tls.cmd("RCPT TO:<y@example.test>").await),
            "250",
            "round {n}"
        );
        assert_eq!(code(&tls.cmd("RSET").await), "250");
    }
}

#[tokio::test]
async fn checks_reputation_learns_from_malware_not_from_dmarc_quarantines() {
    let h = harness().await;
    let cfg = ChecksConfig {
        reputation_enabled: true,
        reputation_reject_score: 20.0,
        reputation_half_life_secs: 3600,
        ..checks_cfg(h.dir.path())
    };
    let stack = Arc::new(CheckStack::from_checks(&cfg, Arc::new(MapDns::new())).unwrap());
    let clock = Arc::new(AtomicI64::new(1_000_000));
    let reader = Arc::clone(&clock);
    stack
        .reputation
        .as_ref()
        .unwrap()
        .set_clock(Arc::new(move || reader.load(Ordering::SeqCst)));
    let ctx = Arc::new(with_checks_arc(&h, Arc::clone(&stack)));
    let connect = |ip: IpAddr| {
        let ctx = Arc::clone(&ctx);
        async move {
            let (mut c, _, _) = start_with(ctx, SocketAddr::new(ip, 2525), 1 << 20, None);
            c.reply().await
        }
    };
    // A list server whose mail fails DMARC is quarantined, not blacklisted.
    let forwarder: IpAddr = "198.51.100.60".parse().unwrap();
    for _ in 0..20 {
        stack.record_verdict(forwarder, "list@lists.test", VerdictSignal::Neutral);
    }
    assert!(connect(forwarder).await.starts_with("220"));

    let ip: IpAddr = "203.0.113.50".parse().unwrap();
    stack.record_verdict(ip, "a@spam.test", VerdictSignal::Malware);
    assert!(
        connect(ip).await.starts_with("220"),
        "one bad message is not enough"
    );
    stack.record_verdict(ip, "a@spam.test", VerdictSignal::Malware);
    let reply = connect(ip).await;
    assert!(reply.starts_with("554 5.7.1 reputation"), "{reply}");

    // The score is capped, so a burst decays back in a bounded time.
    for _ in 0..100 {
        stack.record_verdict(ip, "a@spam.test", VerdictSignal::Malware);
    }
    let score = stack.reputation.as_ref().unwrap().score(ip);
    assert!(score <= 40.0, "score {score} not capped");
    clock.fetch_add(2 * 3600 + 60, Ordering::SeqCst);
    assert!(
        connect(ip).await.starts_with("220"),
        "capped score did not decay"
    );
    stack.record_verdict(ip, "a@spam.test", VerdictSignal::Spam);
    stack.record_verdict(
        ip,
        "a@spam.test",
        VerdictSignal::Delivered { dmarc_pass: false },
    );
    assert!(stack.reputation.as_ref().unwrap().score(ip) < 20.0);
}

#[tokio::test(start_paused = true)]
async fn checks_housekeeping_runs_on_its_own_task() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = ChecksConfig {
        reputation_enabled: true,
        reputation_half_life_secs: 1,
        ..checks_cfg(dir.path())
    };
    let stack = Arc::new(CheckStack::from_checks(&cfg, Arc::new(MapDns::new())).unwrap());
    let clock = Arc::new(AtomicI64::new(1_000_000));
    let reader = Arc::clone(&clock);
    let rep = stack.reputation.as_ref().unwrap();
    rep.set_clock(Arc::new(move || reader.load(Ordering::SeqCst)));
    stack.record_verdict(
        "203.0.113.1".parse().unwrap(),
        "a@x.test",
        VerdictSignal::Malware,
    );
    assert_eq!(rep.tracked(), 1);
    let task = stack.spawn_housekeeping();
    clock.fetch_add(3600, Ordering::SeqCst);
    // Nothing on the connect path prunes any more; only the timer does.
    stack
        .on_connect(&ConnCtx {
            ip: "203.0.113.2".parse().unwrap(),
            helo: String::new(),
        })
        .await;
    assert_eq!(rep.tracked(), 1);
    tokio::time::sleep(Duration::from_secs(61)).await;
    assert_eq!(rep.tracked(), 0);
    task.abort();
}

#[tokio::test]
async fn checks_dmarc_pass_skips_greylisting_only_from_that_network() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = ChecksConfig {
        greylist_enabled: true,
        ..checks_cfg(dir.path())
    };
    let stack = CheckStack::from_checks(&cfg, Arc::new(MapDns::new())).unwrap();
    let home: IpAddr = "198.51.100.20".parse().unwrap();
    stack.record_verdict(
        home,
        "news@bigcorp.test",
        VerdictSignal::Delivered { dmarc_pass: true },
    );
    let grey = stack.greylist.as_ref().unwrap();
    assert_eq!(
        grey.decide(
            "198.51.100.21".parse().unwrap(),
            "ceo@bigcorp.test",
            "a@example.test"
        )
        .unwrap(),
        currawong_smtp::checks::GreylistDecision::Pass
    );
    assert_eq!(
        grey.decide(
            "203.0.113.99".parse().unwrap(),
            "ceo@bigcorp.test",
            "a@example.test"
        )
        .unwrap(),
        currawong_smtp::checks::GreylistDecision::Delay
    );
}

#[tokio::test]
async fn checks_each_check_can_be_disabled() {
    let dir = tempfile::tempdir().unwrap();
    let ip: IpAddr = "203.0.113.60".parse().unwrap();
    let (zone, dns) = listed(ip);
    let connect = ConnCtx {
        ip,
        helo: String::new(),
    };
    let rcpt = currawong_smtp::checks::RcptCtx {
        ip,
        mail_from: "a@sender.test".into(),
        recipient: "b@example.test".into(),
    };
    let all_on = ChecksConfig {
        dnsbl_enabled: true,
        dnsbl: vec![zone],
        ratelimit_enabled: true,
        rate_per_minute_ip: 1,
        greylist_enabled: true,
        reputation_enabled: true,
        reputation_reject_score: 10.0,
        ..checks_cfg(dir.path())
    };
    use currawong_smtp::checks::CheckResult::{Pass, Reject, TempFail};

    let dnsbl_only = ChecksConfig {
        ratelimit_enabled: false,
        greylist_enabled: false,
        reputation_enabled: false,
        ..all_on.clone()
    };
    let on = CheckStack::from_checks(&dnsbl_only, dns.clone()).unwrap();
    assert!(matches!(on.on_connect(&connect).await, Reject(line) if line.starts_with("554")));
    let off = CheckStack::from_checks(
        &ChecksConfig {
            dnsbl_enabled: false,
            ..dnsbl_only
        },
        dns.clone(),
    )
    .unwrap();
    assert!(off.dnsbl.is_none());
    assert_eq!(off.on_connect(&connect).await, Pass);

    let rate_only = ChecksConfig {
        dnsbl_enabled: false,
        greylist_enabled: false,
        reputation_enabled: false,
        ..all_on.clone()
    };
    let on = CheckStack::from_checks(&rate_only, dns.clone()).unwrap();
    assert_eq!(on.on_connect(&connect).await, Pass);
    assert!(matches!(on.on_connect(&connect).await, TempFail(line) if line.starts_with("421")));
    let off = CheckStack::from_checks(
        &ChecksConfig {
            ratelimit_enabled: false,
            ..rate_only
        },
        dns.clone(),
    )
    .unwrap();
    assert!(off.rate.is_none());
    assert_eq!(off.on_connect(&connect).await, Pass);
    assert_eq!(off.on_connect(&connect).await, Pass);

    let grey_only = ChecksConfig {
        dnsbl_enabled: false,
        ratelimit_enabled: false,
        reputation_enabled: false,
        ..all_on.clone()
    };
    let on = CheckStack::from_checks(&grey_only, dns.clone()).unwrap();
    assert!(matches!(on.on_rcpt(&rcpt).await, TempFail(line) if line.starts_with("451")));
    let off = CheckStack::from_checks(
        &ChecksConfig {
            greylist_enabled: false,
            ..grey_only
        },
        dns.clone(),
    )
    .unwrap();
    assert!(off.greylist.is_none());
    assert_eq!(off.on_rcpt(&rcpt).await, Pass);

    let rep_only = ChecksConfig {
        dnsbl_enabled: false,
        ratelimit_enabled: false,
        greylist_enabled: false,
        ..all_on
    };
    let blocked = VerdictSignal::Malware;
    let on = CheckStack::from_checks(&rep_only, dns.clone()).unwrap();
    on.record_verdict(ip, "a@x.test", blocked);
    assert!(matches!(on.on_connect(&connect).await, Reject(line) if line.contains("reputation")));
    let off = CheckStack::from_checks(
        &ChecksConfig {
            reputation_enabled: false,
            ..rep_only
        },
        dns,
    )
    .unwrap();
    off.record_verdict(ip, "a@x.test", blocked);
    assert!(off.reputation.is_none());
    assert_eq!(off.on_connect(&connect).await, Pass);
}

#[tokio::test]
async fn checks_housekeeping_forgets_stale_keys() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = ChecksConfig {
        ratelimit_enabled: true,
        rate_per_minute_ip: 600,
        rate_per_minute_net: 600,
        rate_per_minute_sender: 600,
        reputation_enabled: true,
        reputation_half_life_secs: 60,
        ..checks_cfg(dir.path())
    };
    let stack = CheckStack::from_checks(&cfg, Arc::new(MapDns::new())).unwrap();
    let clock = Arc::new(AtomicI64::new(1_000_000));
    let reader = Arc::clone(&clock);
    stack
        .reputation
        .as_ref()
        .unwrap()
        .set_clock(Arc::new(move || reader.load(Ordering::SeqCst)));
    for n in 0..200u16 {
        let ip = IpAddr::from([0x2001, 0xdb8, n, 0, 0, 0, 0, 1]);
        stack
            .on_connect(&ConnCtx {
                ip,
                helo: String::new(),
            })
            .await;
        stack.record_verdict(ip, "a@x.test", VerdictSignal::Malware);
    }
    let rate = stack.rate.as_ref().unwrap();
    let rep = stack.reputation.as_ref().unwrap();
    assert_eq!(rate.tracked_keys(), 400);
    assert_eq!(rep.tracked(), 200);
    // 600 per minute refills a cell every 100 ms.
    tokio::time::sleep(Duration::from_millis(300)).await;
    clock.fetch_add(60 * 10, Ordering::SeqCst);
    stack.housekeeping();
    assert_eq!(rate.tracked_keys(), 0);
    assert_eq!(rep.tracked(), 0);
}

// ----------------------------------------------------------- #19 submission

fn base64_plain(user: &str, pass: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(format!("\0{user}\0{pass}"))
}

fn b64(text: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(text)
}

struct Tenants {
    h: Harness,
    relay: Arc<Relay>,
    der: Vec<u8>,
    manager: Arc<TlsManager>,
}

/// Tenant `acme` owns acme.test and 10.0.0.0/8. Tenant `globex` owns
/// globex.test and 192.0.2.0/24. Both have SMTP AUTH users.
async fn tenants() -> Tenants {
    let mut h = harness().await;
    h.cfg.domains.accept = vec![
        "example.test".into(),
        "acme.test".into(),
        "globex.test".into(),
    ];
    h.cfg.relay.tenants = vec![
        TenantConfig {
            id: "acme".into(),
            domains: vec!["acme.test".into()],
            trusted_cidrs: vec!["10.0.0.0/8".into()],
        },
        TenantConfig {
            id: "globex".into(),
            domains: vec!["globex.test".into()],
            trusted_cidrs: vec!["192.0.2.0/24".into()],
        },
    ];
    let relay =
        Arc::new(Relay::open(&h.dir.path().join("relay.sqlite"), &h.cfg.relay.tenants).unwrap());
    // ada logs in with her address; hank has a plain login and one alias.
    relay
        .upsert_credential("acme", "ada@acme.test", "correct horse")
        .unwrap();
    relay
        .upsert_credential("globex", "hank", "battery staple")
        .unwrap();
    relay
        .add_sender_address("hank", "hank@globex.test")
        .unwrap();
    let (manager, der) = tls_harness(&h);
    Tenants {
        h,
        relay,
        der,
        manager,
    }
}

impl Tenants {
    fn ctx(&self) -> Arc<SessionContext> {
        let mut ctx = self.h.ctx(ListenerRole::Submission);
        ctx.relay = Arc::clone(&self.relay);
        ctx.tls = Some(Arc::clone(&self.manager));
        Arc::new(ctx)
    }

    async fn plain(&self, ip: [u8; 4]) -> Client<tokio::io::DuplexStream> {
        let (mut c, _, _) = start_with(self.ctx(), peer(ip), 1 << 20, None);
        assert!(c.reply().await.starts_with("220"));
        c
    }

    async fn tls(
        &self,
        ip: [u8; 4],
    ) -> Client<tokio_rustls::client::TlsStream<tokio::io::DuplexStream>> {
        let c = self.plain(ip).await;
        let mut tls = starttls(c, &self.der, &[&rustls::version::TLS13]).await;
        assert_eq!(code(&tls.cmd("EHLO laptop.test").await), "250");
        tls
    }
}

#[tokio::test]
async fn submission_trusted_cidr_relays_out_and_is_marked_outbound() {
    let t = tenants().await;
    let mut c = t.plain([10, 1, 2, 3]).await;
    assert_eq!(code(&c.cmd("EHLO app.acme.test").await), "250");
    assert_eq!(code(&c.cmd("MAIL FROM:<app@acme.test>").await), "250");
    assert_eq!(code(&c.cmd("RCPT TO:<bob@outside.test>").await), "250");
    assert_eq!(code(&c.cmd("DATA").await), "354");
    assert!(c
        .cmd("Subject: out\r\n\r\nout\r\n.")
        .await
        .starts_with("250"));
    // Internal mail from a trusted host is still outbound, so outbound DLP applies.
    assert_eq!(code(&c.cmd("MAIL FROM:<app@acme.test>").await), "250");
    assert_eq!(code(&c.cmd("RCPT TO:<carol@example.test>").await), "250");
    assert_eq!(code(&c.cmd("DATA").await), "354");
    assert!(c.cmd("Subject: in\r\n\r\nin\r\n.").await.starts_with("250"));
    let stored = t.h.incoming().await;
    assert_eq!(stored.len(), 2);
    for env in &stored {
        assert_eq!(env.direction, Direction::Outbound, "{env:?}");
        assert_eq!(env.tenant_id.as_deref(), Some("acme"));
    }
}

#[tokio::test]
async fn submission_spoofing_another_tenants_domain_is_refused() {
    let t = tenants().await;
    let mut c = t.plain([10, 1, 2, 4]).await;
    assert_eq!(code(&c.cmd("EHLO app.acme.test").await), "250");
    assert_eq!(
        c.cmd("MAIL FROM:<ceo@globex.test>").await,
        "550 5.7.1 sender domain is not owned by this tenant\r\n"
    );
    assert_eq!(code(&c.cmd("MAIL FROM:<ceo@acme.test>").await), "250");

    // Authenticated as globex, sending as acme.
    let mut tls = t.tls([203, 0, 113, 80]).await;
    assert_eq!(
        code(
            &tls.cmd(&format!(
                "AUTH PLAIN {}",
                base64_plain("hank", "battery staple")
            ))
            .await
        ),
        "235"
    );
    assert_eq!(
        tls.cmd("MAIL FROM:<ada@acme.test>").await,
        "550 5.7.1 sender domain is not owned by this tenant\r\n"
    );
    assert_eq!(code(&tls.cmd("MAIL FROM:<hank@globex.test>").await), "250");
}

#[tokio::test]
async fn submission_auth_plain_and_login_succeed_over_tls() {
    let t = tenants().await;
    let mut c = t.plain([203, 0, 113, 81]).await;
    assert_eq!(code(&c.cmd("EHLO laptop").await), "250");
    assert_eq!(
        c.cmd("MAIL FROM:<ada@acme.test>").await,
        "530 5.7.0 authentication required\r\n"
    );
    let refused = c
        .cmd(&format!(
            "AUTH PLAIN {}",
            base64_plain("ada@acme.test", "correct horse")
        ))
        .await;
    assert!(refused.starts_with("538 5.7.11"), "{refused}");

    let mut tls = t.tls([203, 0, 113, 81]).await;
    assert_eq!(
        tls.cmd(&format!(
            "AUTH PLAIN {}",
            base64_plain("ada@acme.test", "correct horse")
        ))
        .await,
        "235 2.7.0 authentication succeeded\r\n"
    );
    assert_eq!(code(&tls.cmd("AUTH PLAIN").await), "503", "second AUTH");
    assert_eq!(code(&tls.cmd("MAIL FROM:<ada@acme.test>").await), "250");
    assert_eq!(code(&tls.cmd("RCPT TO:<friend@outside.test>").await), "250");
    assert_eq!(code(&tls.cmd("DATA").await), "354");
    assert!(tls
        .cmd("Subject: hi\r\n\r\nhi\r\n.")
        .await
        .starts_with("250"));
    let env = &t.h.incoming().await[0];
    assert_eq!(env.tenant_id.as_deref(), Some("acme"));
    assert_eq!(env.authenticated_as.as_deref(), Some("ada@acme.test"));
    assert_eq!(env.direction, Direction::Outbound);

    let mut login = t.tls([203, 0, 113, 82]).await;
    assert_eq!(
        login.cmd(&format!("AUTH LOGIN {}", b64("hank"))).await,
        "334 UGFzc3dvcmQ6\r\n"
    );
    assert_eq!(code(&login.cmd(&b64("battery staple")).await), "235");
    assert_eq!(
        code(&login.cmd("MAIL FROM:<hank@globex.test>").await),
        "250"
    );
    assert_eq!(code(&login.cmd("RCPT TO:<x@outside.test>").await), "250");
    assert_eq!(
        login
            .cmd(&format!(
                "AUTH PLAIN {}",
                base64_plain("ada@acme.test", "correct horse")
            ))
            .await,
        "503 5.5.1 AUTH is not permitted during a mail transaction\r\n"
    );
}

#[tokio::test]
async fn submission_bad_credentials_fail_and_repeated_failures_close() {
    let t = tenants().await;
    let mut tls = t.tls([203, 0, 113, 83]).await;
    assert_eq!(
        tls.cmd(&format!(
            "AUTH PLAIN {}",
            base64_plain("ada@acme.test", "wrong")
        ))
        .await,
        "535 5.7.8 authentication failed\r\n"
    );
    assert_eq!(
        tls.cmd(&format!(
            "AUTH PLAIN {}",
            base64_plain("nobody", "correct horse")
        ))
        .await,
        "535 5.7.8 authentication failed\r\n"
    );
    assert_eq!(code(&tls.cmd("MAIL FROM:<ada@acme.test>").await), "530");
    let last = tls
        .cmd(&format!(
            "AUTH PLAIN {}",
            base64_plain("ada@acme.test", "nope")
        ))
        .await;
    assert!(last.starts_with("535"), "{last}");
    assert!(tls.reply().await.starts_with("421 4.7.0"));
    assert!(tls.closed().await);
}

#[tokio::test]
async fn submission_login_may_only_send_as_its_own_address_or_alias() {
    let t = tenants().await;
    let mut tls = t.tls([203, 0, 113, 84]).await;
    assert_eq!(
        code(
            &tls.cmd(&format!(
                "AUTH PLAIN {}",
                base64_plain("ada@acme.test", "correct horse")
            ))
            .await
        ),
        "235"
    );
    // Same tenant domain, different user: refused.
    assert_eq!(
        tls.cmd("MAIL FROM:<ceo@acme.test>").await,
        "553 5.7.1 sender address is not authorised for this login\r\n"
    );
    assert_eq!(code(&tls.cmd("MAIL FROM:<>").await), "553");
    assert_eq!(code(&tls.cmd("MAIL FROM:<ADA@acme.test>").await), "250");
    assert_eq!(code(&tls.cmd("RSET").await), "250");

    let mut alias = t.tls([203, 0, 113, 85]).await;
    assert_eq!(
        code(
            &alias
                .cmd(&format!(
                    "AUTH PLAIN {}",
                    base64_plain("hank", "battery staple")
                ))
                .await
        ),
        "235"
    );
    assert_eq!(
        code(&alias.cmd("MAIL FROM:<boss@globex.test>").await),
        "553"
    );
    assert_eq!(
        code(&alias.cmd("MAIL FROM:<hank@globex.test>").await),
        "250"
    );
    assert_eq!(code(&alias.cmd("RCPT TO:<x@outside.test>").await), "250");
    assert_eq!(code(&alias.cmd("DATA").await), "354");
    assert!(alias
        .cmd("Subject: a\r\n\r\na\r\n.")
        .await
        .starts_with("250"));
    let env = &t.h.incoming().await[0];
    assert_eq!(env.authenticated_as.as_deref(), Some("hank"));

    // A trusted network is not a login: no identity is recorded.
    let mut trusted = t.plain([10, 9, 9, 9]).await;
    assert_eq!(code(&trusted.cmd("EHLO app.acme.test").await), "250");
    assert_eq!(code(&trusted.cmd("MAIL FROM:<ceo@acme.test>").await), "250");
    assert_eq!(code(&trusted.cmd("RCPT TO:<x@outside.test>").await), "250");
    assert_eq!(code(&trusted.cmd("DATA").await), "354");
    assert!(trusted
        .cmd("Subject: t\r\n\r\nt\r\n.")
        .await
        .starts_with("250"));
    let stored = t.h.incoming().await;
    assert!(stored
        .iter()
        .any(|env| env.mail_from == "ceo@acme.test" && env.authenticated_as.is_none()));
}

// ------------------------------------------------------------ round two

#[tokio::test]
async fn submission_from_a_dnsbl_listed_address_can_still_authenticate() {
    let t = tenants().await;
    let ip: IpAddr = "203.0.113.90".parse().unwrap();
    let (zone, dns) = listed(ip);
    let cfg = ChecksConfig {
        dnsbl_enabled: true,
        dnsbl: vec![zone],
        ratelimit_enabled: true,
        rate_per_minute_ip: 1,
        ..checks_cfg(t.h.dir.path())
    };
    let checks = Arc::new(CheckStack::from_checks(&cfg, dns).unwrap());
    let mut inbound = t.h.ctx(ListenerRole::Inbound);
    inbound.checks = Arc::clone(&checks);
    let (mut c, _, _) = start_with(Arc::new(inbound), SocketAddr::new(ip, 2525), 1 << 20, None);
    assert!(c.reply().await.starts_with("554"), "port 25 still checks");

    let mut submission = t.h.ctx(ListenerRole::Submission);
    submission.relay = Arc::clone(&t.relay);
    submission.tls = Some(Arc::clone(&t.manager));
    submission.checks = checks;
    let ctx = Arc::new(submission);
    for _ in 0..2 {
        let (mut c, _, _) = start_with(Arc::clone(&ctx), SocketAddr::new(ip, 2525), 1 << 20, None);
        assert!(
            c.reply().await.starts_with("220"),
            "listed user locked out of submission"
        );
        let mut tls = starttls(c, &t.der, &[&rustls::version::TLS13]).await;
        assert_eq!(code(&tls.cmd("EHLO laptop").await), "250");
        let auth = tls
            .cmd(&format!(
                "AUTH PLAIN {}",
                base64_plain("ada@acme.test", "correct horse")
            ))
            .await;
        assert_eq!(code(&auth), "235");
    }
}

#[tokio::test]
async fn data_low_spool_space_is_452_before_354() {
    let mut h = harness().await;
    h.cfg.limits.spool_min_free_bytes = u64::MAX;
    let (mut c, _, _) = start(h.ctx(ListenerRole::Inbound), peer([203, 0, 113, 91])).await;
    assert_eq!(code(&c.cmd("EHLO c.test").await), "250");
    assert_eq!(code(&c.cmd("MAIL FROM:<a@x.test>").await), "250");
    assert_eq!(code(&c.cmd("RCPT TO:<b@example.test>").await), "250");
    assert_eq!(
        c.cmd("DATA").await,
        "452 4.3.1 insufficient system storage\r\n"
    );
    assert!(h.incoming_files().is_empty());
}

#[tokio::test]
async fn data_slow_drip_hits_the_overall_deadline() {
    let mut h = harness().await;
    h.cfg.limits.data_timeout_secs = 1;
    let (mut c, task, _) = start(h.ctx(ListenerRole::Inbound), peer([203, 0, 113, 92])).await;
    begin_transaction(&mut c).await;
    let started = std::time::Instant::now();
    let reply = loop {
        c.send(b"drip\r\n").await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        let mut buf = [0u8; 128];
        if let Ok(Ok(n)) = timeout(Duration::from_millis(10), c.read.read(&mut buf)).await {
            break String::from_utf8_lossy(&buf[..n]).to_string();
        }
        assert!(started.elapsed() < WAIT, "per-line activity kept DATA open");
    };
    assert!(reply.starts_with("421 4.4.2"), "{reply}");
    timeout(WAIT, task).await.unwrap().unwrap();
    assert!(h.incoming_files().is_empty());
}

#[tokio::test]
async fn data_oversize_drain_is_bounded() {
    let mut h = harness().await;
    h.cfg.limits.max_message_bytes = 64;
    let (mut c, task, _) = start(h.ctx(ListenerRole::Inbound), peer([203, 0, 113, 93])).await;
    begin_transaction(&mut c).await;
    let line = format!("{}\r\n", "D".repeat(900));
    let mut sent = 0usize;
    let mut reply = String::new();
    while sent < 4 * 1024 * 1024 {
        if c.write.write_all(line.as_bytes()).await.is_err() {
            break;
        }
        sent += line.len();
        let mut buf = [0u8; 128];
        if let Ok(Ok(n)) = timeout(Duration::from_millis(0), c.read.read(&mut buf)).await {
            reply = String::from_utf8_lossy(&buf[..n]).to_string();
            break;
        }
    }
    if reply.is_empty() {
        reply = c.reply().await;
    }
    assert!(reply.starts_with("552 5.3.4"), "{reply}");
    assert!(
        sent < 3 * 1024 * 1024,
        "drained {sent} bytes before giving up"
    );
    timeout(WAIT, task).await.unwrap().unwrap();
    assert!(h.incoming_files().is_empty());
}

#[tokio::test]
async fn data_250_is_sent_only_after_the_spool_fsyncs() {
    let h = harness().await;
    let (mut c, _, _) = start(h.ctx(ListenerRole::Inbound), peer([203, 0, 113, 94])).await;
    begin_transaction(&mut c).await;
    let before = h.spool.commit_syncs();
    c.send(b"Subject: sync\r\n\r\nx\r\n.\r\n").await;
    let reply = c.reply().await;
    let synced = h.spool.commit_syncs() - before;
    assert!(reply.starts_with("250"), "{reply}");
    assert!(
        synced >= 3,
        "250 before body, JSON and directory fsyncs ({synced})"
    );
    let id = reply.split_whitespace().nth(3).unwrap();
    let files = h.incoming_files();
    assert!(files.contains(&format!("{id}.eml")) && files.contains(&format!("{id}.json")));
}

#[tokio::test]
async fn tls_starttls_discards_plaintext_sent_after_the_command() {
    let h = harness().await;
    let (manager, der) = tls_harness(&h);
    let mut ctx = h.ctx(ListenerRole::Inbound);
    ctx.tls = Some(manager);
    let (mut c, _, _) = start_with(Arc::new(ctx), peer([203, 0, 113, 95]), 1 << 20, None);
    assert!(c.reply().await.starts_with("220"));
    assert_eq!(code(&c.cmd("EHLO client.test").await), "250");
    // An attacker on the wire appends commands to STARTTLS in clear text.
    c.send(b"STARTTLS\r\nEHLO injected.test\r\nMAIL FROM:<evil@x.test>\r\n")
        .await;
    assert_eq!(c.reply().await, "220 2.0.0 Ready to start TLS\r\n");
    let connector =
        tokio_rustls::TlsConnector::from(client_config(&der, &[&rustls::version::TLS13]));
    let tls = connector
        .connect(
            rustls::pki_types::ServerName::try_from("localhost").unwrap(),
            c.into_inner(),
        )
        .await
        .expect("injected bytes must not reach the TLS layer");
    let mut tls = Client::new(tls);
    assert_eq!(
        tls.cmd("RCPT TO:<b@example.test>").await,
        "503 5.5.1 need MAIL first\r\n",
        "plaintext commands from before the handshake were run"
    );
    assert_eq!(
        code(&tls.cmd("MAIL FROM:<a@x.test>").await),
        "503",
        "needs a fresh EHLO"
    );
}

/// Forged Authentication-Results are removed while the body streams, folded
/// lines included, and nothing after the header section is touched.
#[tokio::test]
async fn data_strips_folded_forged_authentication_results_while_streaming() {
    let h = harness().await;
    let id = h.cfg.auth.authserv_id.clone();
    let (mut c, _, _) = start(h.ctx(ListenerRole::Inbound), peer([203, 0, 113, 96])).await;
    begin_transaction(&mut c).await;
    let data = format!(
        "Received: from x\r\n\tby y\r\nAuthentication-Results: {id};\r\n\tdkim=pass\r\n\theader.d=bank.test\r\nSubject: hi\r\n\r\nAuthentication-Results: {id}; body text stays\r\n.\r\n"
    );
    c.send(data.as_bytes()).await;
    assert!(c.reply().await.starts_with("250"));
    let stored = h.incoming().await;
    let body = h.spool.read_body(&stored[0].id).await.unwrap();
    assert_eq!(
        String::from_utf8(body).unwrap(),
        format!(
            "Received: from x\r\n\tby y\r\nSubject: hi\r\n\r\nAuthentication-Results: {id}; body text stays\r\n"
        )
    );
}
