//! SMTP session, TLS, checks, submission and delivery. Nothing binds port 25.
use currawong_core::{
    config::{Config, DnsblListing, DnsblZone, DomainRoute, ListenerRole, TenantConfig},
    Direction, Secret,
};
use currawong_smtp::{
    checks::{CheckStack, ConnCtx, MailCtx, RcptCtx},
    delivery::Deliverer,
    dns::MapDns,
    relay::Relay,
    run_session,
    server::SmtpServer,
    session::SessionContext,
    stream::BoxIo,
    tls::TlsManager,
};
use currawong_spool::{Envelope, Spool, SpoolState};
use rcgen::generate_simple_self_signed;
use std::{
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpListener,
    time::timeout,
};

struct Harness {
    cfg: Arc<Config>,
    spool: Arc<Spool>,
    _dir: tempfile::TempDir,
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
    Harness {
        cfg: Arc::new(cfg),
        spool,
        _dir: dir,
    }
}

fn context(
    h: &Harness,
    role: ListenerRole,
    tls: Option<Arc<TlsManager>>,
    relay: Arc<Relay>,
) -> Arc<SessionContext> {
    Arc::new(SessionContext {
        cfg: Arc::clone(&h.cfg),
        spool: Arc::clone(&h.spool),
        tls,
        checks: Arc::new(CheckStack::disabled()),
        relay,
        role,
    })
}

async fn talk(ctx: Arc<SessionContext>, peer: SocketAddr, script: &[&str]) -> String {
    let (client, server) = tokio::io::duplex(1024 * 1024);
    let shutdown = tokio_util::sync::CancellationToken::new();
    tokio::spawn(async move {
        run_session(BoxIo::new(server), peer, ctx, shutdown, None).await;
    });
    let (read, mut write) = tokio::io::split(client);
    let mut read = BufReader::new(read);
    let mut out = String::new();
    out.push_str(&read_smtp(&mut read).await);
    for line in script {
        write.write_all(line.as_bytes()).await.unwrap();
        if !line.ends_with("\r\n") && !line.ends_with('\n') {
            write.write_all(b"\r\n").await.unwrap();
        }
        write.flush().await.unwrap();
        if line.starts_with("QUIT") {
            let rest = read_smtp(&mut read).await;
            out.push_str(&rest);
            break;
        }
        let reply = timeout(Duration::from_secs(2), read_smtp(&mut read))
            .await
            .unwrap_or_else(|_| String::new());
        out.push_str(&reply);
        if reply.starts_with("354") {
            continue;
        }
    }
    out
}

async fn read_smtp(read: &mut BufReader<tokio::io::ReadHalf<tokio::io::DuplexStream>>) -> String {
    let mut all = String::new();
    let mut line = String::new();
    loop {
        line.clear();
        let n = timeout(Duration::from_secs(2), read.read_line(&mut line))
            .await
            .ok()
            .and_then(|r| r.ok())
            .unwrap_or(0);
        if n == 0 {
            break;
        }
        all.push_str(&line);
        let trimmed = line.trim_end();
        if trimmed.len() >= 4 && trimmed.as_bytes()[3] == b' ' {
            break;
        }
        if trimmed.len() == 3 {
            break;
        }
    }
    all
}

fn peer(octets: [u8; 4]) -> SocketAddr {
    SocketAddr::from((octets, 2525))
}

#[tokio::test]
async fn session_relays_denied_and_local_mail_is_spooled() {
    let h = await_harness().await;
    let ctx = context(&h, ListenerRole::Inbound, None, Arc::new(Relay::empty()));
    let transcript = talk(
        ctx,
        peer([203, 0, 113, 10]),
        &[
            "EHLO client.test",
            "MAIL FROM:<a@outside.test>",
            "RCPT TO:<b@other.test>",
            "RSET",
            "MAIL FROM:<a@outside.test>",
            "RCPT TO:<b@example.test>",
            "DATA",
            "Subject: hi\r\n\r\nhello\r\n.",
            "QUIT",
        ],
    )
    .await;
    assert!(
        transcript.contains("550 5.7.1 Relaying denied"),
        "{transcript}"
    );
    assert!(transcript.contains("250 2.0.0 OK"), "{transcript}");
    let incoming = h.spool.list(SpoolState::Incoming).await.unwrap();
    assert_eq!(incoming.len(), 1);
    let body = h.spool.read_body(&incoming[0].id).await.unwrap();
    assert!(body.windows(5).any(|w| w == b"hello"));
}

/// #20: the spooled copy (what is quarantined and delivered) carries no
/// Authentication-Results claiming our authserv-id.
#[tokio::test]
async fn session_strips_forged_authentication_results_before_spooling() {
    let h = await_harness().await;
    let id = h.cfg.auth.authserv_id.clone();
    let ctx = context(&h, ListenerRole::Inbound, None, Arc::new(Relay::empty()));
    let data = format!(
        "Authentication-Results : (forged) {id}.; dkim=pass\r\nAuthentication-Results: other.example; spf=pass\r\nSubject: hi\r\n\r\nhello\r\n."
    );
    let transcript = talk(
        ctx,
        peer([203, 0, 113, 10]),
        &[
            "EHLO client.test",
            "MAIL FROM:<a@outside.test>",
            "RCPT TO:<b@example.test>",
            "DATA",
            &data,
            "QUIT",
        ],
    )
    .await;
    assert!(transcript.contains("250 2.0.0 OK"), "{transcript}");
    let incoming = h.spool.list(SpoolState::Incoming).await.unwrap();
    let body = h.spool.read_body(&incoming[0].id).await.unwrap();
    let text = String::from_utf8(body).unwrap();
    assert!(!text.contains("dkim=pass"), "{text}");
    assert!(text.contains("other.example; spf=pass"), "{text}");
}

#[tokio::test]
async fn session_1001_byte_line_is_500() {
    let h = await_harness().await;
    let ctx = context(&h, ListenerRole::Inbound, None, Arc::new(Relay::empty()));
    let long = "A".repeat(1001);
    let transcript = talk(ctx, peer([203, 0, 113, 11]), &[&long]).await;
    assert!(
        transcript.contains("500 5.5.2 line too long"),
        "{transcript}"
    );
}

#[tokio::test]
async fn session_oversize_is_552_and_spools_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::default();
    cfg.spool.dir = dir.path().join("spool");
    cfg.limits.max_message_bytes = 64;
    cfg.checks.ratelimit_enabled = false;
    cfg.checks.greylist_enabled = false;
    cfg.checks.reputation_enabled = false;
    let spool = Arc::new(Spool::open(&cfg.spool.dir).await.unwrap());
    let ctx = Arc::new(SessionContext {
        cfg: Arc::new(cfg),
        spool: Arc::clone(&spool),
        tls: None,
        checks: Arc::new(CheckStack::disabled()),
        relay: Arc::new(Relay::empty()),
        role: ListenerRole::Inbound,
    });
    let blob = "B".repeat(200);
    let data = format!("Subject: x\r\n\r\n{blob}\r\n.");
    let transcript = talk(
        ctx,
        peer([203, 0, 113, 12]),
        &[
            "EHLO c",
            "MAIL FROM:<a@x.test>",
            "RCPT TO:<b@example.test>",
            "DATA",
            &data,
            "QUIT",
        ],
    )
    .await;
    assert!(transcript.contains("552"), "{transcript}");
    assert!(spool.list(SpoolState::Incoming).await.unwrap().is_empty());
}

fn write_cert(dir: &Path, name: &str) -> (PathBuf, PathBuf, Vec<u8>) {
    let rcgen::CertifiedKey { cert, key_pair } =
        generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_path = dir.join(format!("{name}.pem"));
    let key_path = dir.join(format!("{name}.key"));
    std::fs::write(&cert_path, cert.pem()).unwrap();
    std::fs::write(&key_path, key_pair.serialize_pem()).unwrap();
    (cert_path, key_path, cert.der().to_vec())
}

fn client_config(der: &[u8]) -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(der.to_vec().into()).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    Arc::new(
        rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

#[tokio::test]
async fn tls_13_handshake_and_mail_before_ehlo_is_503() {
    let h = await_harness().await;
    let (cert, key, der) = write_cert(h._dir.path(), "a");
    let manager = Arc::new(TlsManager::load(&cert, &key).unwrap());
    let ctx = context(
        &h,
        ListenerRole::Inbound,
        Some(manager),
        Arc::new(Relay::empty()),
    );
    let (client, server) = tokio::io::duplex(1024 * 1024);
    let shutdown = tokio_util::sync::CancellationToken::new();
    tokio::spawn(async move {
        run_session(
            BoxIo::new(server),
            peer([203, 0, 113, 21]),
            ctx,
            shutdown,
            None,
        )
        .await;
    });
    let tls = smtp_starttls(client, &der).await;
    let (mut read, mut write) = tokio::io::split(tls);
    write
        .write_all(b"MAIL FROM:<a@example.test>\r\n")
        .await
        .unwrap();
    let mut buf = vec![0u8; 128];
    let n = timeout(Duration::from_secs(2), read.read(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let text = String::from_utf8_lossy(&buf[..n]);
    assert!(text.contains("503"), "{text}");
}

#[tokio::test]
async fn tls_11_client_hello_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let (cert, key, _) = write_cert(dir.path(), "a");
    let manager = Arc::new(TlsManager::load(&cert, &key).unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let shutdown = tokio_util::sync::CancellationToken::new();
    let cfg = Arc::new(Config::default());
    let spool = Arc::new(Spool::open(dir.path().join("spool")).await.unwrap());
    let ctx = Arc::new(SessionContext {
        cfg,
        spool,
        tls: Some(manager),
        checks: Arc::new(CheckStack::disabled()),
        relay: Arc::new(Relay::empty()),
        role: ListenerRole::Submission,
    });
    let server = SmtpServer::new(ctx);
    let stop = shutdown.clone();
    tokio::spawn(async move {
        server
            .run(
                listener,
                stop,
                currawong_core::config::ListenerMode::Implicit,
            )
            .await;
    });
    let mut sock = tokio::net::TcpStream::connect(addr).await.unwrap();
    // TLS 1.1 ClientHello, one cipher, no supported_versions extension.
    let hello = tls11_client_hello();
    sock.write_all(&hello).await.unwrap();
    let mut buf = [0u8; 64];
    let n = timeout(Duration::from_secs(2), sock.read(&mut buf))
        .await
        .unwrap()
        .unwrap_or(0);
    assert!(
        n == 0 || buf[0] == 0x15,
        "expected a TLS alert or close, got {n} bytes {:02x?}",
        &buf[..n]
    );
    shutdown.cancel();
}

#[tokio::test]
async fn tls_certificate_reload_is_visible_to_the_next_handshake() {
    let dir = tempfile::tempdir().unwrap();
    let (cert_a, key_a, der_a) = write_cert(dir.path(), "a");
    let (cert_b, key_b, der_b) = write_cert(dir.path(), "b");
    assert_ne!(der_a, der_b);
    let manager = Arc::new(TlsManager::load(&cert_a, &key_a).unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let spool = Arc::new(Spool::open(dir.path().join("spool")).await.unwrap());
    let ctx = Arc::new(SessionContext {
        cfg: Arc::new(Config::default()),
        spool,
        tls: Some(Arc::clone(&manager)),
        checks: Arc::new(CheckStack::disabled()),
        relay: Arc::new(Relay::empty()),
        role: ListenerRole::Inbound,
    });
    let server = SmtpServer::new(ctx);
    let shutdown = tokio_util::sync::CancellationToken::new();
    let stop = shutdown.clone();
    tokio::spawn(async move {
        server
            .run(
                listener,
                stop,
                currawong_core::config::ListenerMode::Implicit,
            )
            .await;
    });
    let first = tls_connect(addr, &der_a).await;
    manager.reload_from(&cert_b, &key_b).unwrap();
    let second = tls_connect(addr, &der_b).await;
    assert_eq!(peer_der(&first), der_a);
    assert_eq!(peer_der(&second), der_b);
    shutdown.cancel();
}

fn peer_der(stream: &tokio_rustls::client::TlsStream<tokio::net::TcpStream>) -> Vec<u8> {
    stream
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|certs| certs.first())
        .map(|cert| cert.as_ref().to_vec())
        .unwrap_or_default()
}

async fn tls_connect(
    addr: SocketAddr,
    der: &[u8],
) -> tokio_rustls::client::TlsStream<tokio::net::TcpStream> {
    let sock = tokio::net::TcpStream::connect(addr).await.unwrap();
    let connector = tokio_rustls::TlsConnector::from(client_config(der));
    connector
        .connect(
            rustls::pki_types::ServerName::try_from("localhost").unwrap(),
            sock,
        )
        .await
        .unwrap()
}

async fn smtp_starttls(
    client: tokio::io::DuplexStream,
    der: &[u8],
) -> tokio_rustls::client::TlsStream<tokio::io::DuplexStream> {
    let (read, mut write) = tokio::io::split(client);
    let mut read = BufReader::new(read);
    let _ = read_smtp(&mut read).await;
    write
        .write_all(b"EHLO client.test\r\nSTARTTLS\r\n")
        .await
        .unwrap();
    let mut saw_ready = false;
    for _ in 0..8 {
        let reply = read_smtp(&mut read).await;
        if reply.starts_with("220") && reply.contains("Ready") {
            saw_ready = true;
            break;
        }
    }
    assert!(saw_ready, "STARTTLS was not accepted");
    let client = read.into_inner().unsplit(write);
    let connector = tokio_rustls::TlsConnector::from(client_config(der));
    connector
        .connect(
            rustls::pki_types::ServerName::try_from("localhost").unwrap(),
            client,
        )
        .await
        .unwrap()
}

fn tls11_client_hello() -> Vec<u8> {
    let mut hello = vec![
        0x01, 0x00, 0x00, 0x2d, // handshake type + length placeholder, fixed below
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

async fn await_harness() -> Harness {
    harness().await
}

#[tokio::test]
async fn checks_dnsbl_rate_greylist_and_allow_cidr() {
    let mut map = MapDns::new();
    let ip: IpAddr = "203.0.113.9".parse().unwrap();
    let zone = DnsblZone {
        zone: "zen.example.test".into(),
        dqs_key: Some(Secret::new("secret-key".into())),
        listings: vec![DnsblListing {
            code: "127.0.0.2".into(),
            reason: "listed".into(),
        }],
    };
    let name = currawong_smtp::checks::DnsblCheck::query_name(ip, &zone).unwrap();
    assert!(name.starts_with("secret-key."), "{name}");
    assert!(!format!("{zone:?}").contains("secret-key"));
    map.ips.insert(name, vec!["127.0.0.2".parse().unwrap()]);
    let dns = Arc::new(map);
    let mut cfg = currawong_core::config::ChecksConfig {
        dnsbl_enabled: true,
        ratelimit_enabled: false,
        greylist_enabled: false,
        reputation_enabled: false,
        dnsbl: vec![zone],
        ..currawong_core::config::ChecksConfig::default()
    };
    let stack = CheckStack::from_checks(&cfg, dns.clone()).unwrap();
    let hit = stack
        .on_connect(&ConnCtx {
            ip,
            helo: "bad".into(),
        })
        .await;
    assert!(
        matches!(hit, currawong_smtp::checks::CheckResult::Reject(line) if line.contains("554"))
    );

    cfg.allow_cidrs = vec!["203.0.113.0/24".into()];
    let allowed = CheckStack::from_checks(&cfg, dns.clone()).unwrap();
    let skipped = allowed
        .on_connect(&ConnCtx {
            ip,
            helo: "ok".into(),
        })
        .await;
    assert!(matches!(skipped, currawong_smtp::checks::CheckResult::Pass));

    cfg.dnsbl_enabled = false;
    cfg.allow_cidrs.clear();
    cfg.ratelimit_enabled = true;
    cfg.rate_per_minute_ip = 1;
    cfg.rate_per_minute_net = 1000;
    cfg.rate_per_minute_sender = 1000;
    let limited = CheckStack::from_checks(&cfg, dns.clone()).unwrap();
    let ctx = ConnCtx {
        ip,
        helo: "x".into(),
    };
    assert!(matches!(
        limited.on_connect(&ctx).await,
        currawong_smtp::checks::CheckResult::Pass
    ));
    let second = limited.on_connect(&ctx).await;
    assert!(
        matches!(second, currawong_smtp::checks::CheckResult::TempFail(line) if line.starts_with("421"))
    );

    let dir = tempfile::tempdir().unwrap();
    cfg.ratelimit_enabled = false;
    cfg.greylist_enabled = true;
    cfg.greylist_delay_secs = 300;
    cfg.greylist_database = dir.path().join("grey.sqlite");
    let grey = CheckStack::from_checks(&cfg, dns).unwrap();
    let rcpt = RcptCtx {
        ip,
        mail_from: "a@sender.test".into(),
        recipient: "b@example.test".into(),
    };
    let first = grey.on_rcpt(&rcpt).await;
    assert!(
        matches!(first, currawong_smtp::checks::CheckResult::TempFail(line) if line.starts_with("451"))
    );
    let mut direct =
        currawong_smtp::checks::GreylistCheck::open(&cfg.greylist_database, 300).unwrap();
    direct = direct.with_clock(Arc::new(|| {
        time::OffsetDateTime::now_utc().unix_timestamp() + 600
    }));
    let again = direct
        .decide(ip, "a@sender.test", "b@example.test")
        .unwrap();
    assert_eq!(again, currawong_smtp::checks::GreylistDecision::Pass);

    cfg.greylist_enabled = false;
    cfg.dnsbl_enabled = false;
    cfg.ratelimit_enabled = false;
    cfg.reputation_enabled = false;
    let off = CheckStack::from_checks(&cfg, Arc::new(MapDns::new())).unwrap();
    assert!(matches!(
        off.on_connect(&ConnCtx {
            ip,
            helo: String::new()
        })
        .await,
        currawong_smtp::checks::CheckResult::Pass
    ));
    assert!(matches!(
        off.on_mail(&MailCtx {
            ip,
            mail_from: "a@b.test".into()
        })
        .await,
        currawong_smtp::checks::CheckResult::Pass
    ));
    let _ = first;
}

#[tokio::test]
async fn submission_trusted_cidr_spoof_and_plaintext_auth() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::default();
    cfg.spool.dir = dir.path().join("spool");
    cfg.checks.ratelimit_enabled = false;
    cfg.checks.greylist_enabled = false;
    cfg.checks.reputation_enabled = false;
    cfg.domains.accept = vec!["example.test".into()];
    let spool = Arc::new(Spool::open(&cfg.spool.dir).await.unwrap());
    let relay = Arc::new(
        Relay::open(
            &dir.path().join("relay.sqlite"),
            &[TenantConfig {
                id: "ten".into(),
                domains: vec!["example.test".into()],
                trusted_cidrs: vec!["10.0.0.0/8".into()],
            }],
        )
        .unwrap(),
    );
    let hcfg = Arc::new(cfg);
    let ctx = Arc::new(SessionContext {
        cfg: Arc::clone(&hcfg),
        spool: Arc::clone(&spool),
        tls: None,
        checks: Arc::new(CheckStack::disabled()),
        relay: Arc::clone(&relay),
        role: ListenerRole::Submission,
    });
    let trusted = talk(
        Arc::clone(&ctx),
        peer([10, 1, 2, 3]),
        &[
            "EHLO app.example.test",
            "MAIL FROM:<user@example.test>",
            "RCPT TO:<bob@outside.test>",
            "DATA",
            "Subject: out\r\n\r\nout\r\n.",
            "QUIT",
        ],
    )
    .await;
    assert!(trusted.contains("250 2.0.0 OK"), "{trusted}");
    let stored = spool.list(SpoolState::Incoming).await.unwrap();
    assert_eq!(stored[0].direction, Direction::Outbound);

    let spoof = talk(
        Arc::clone(&ctx),
        peer([10, 1, 2, 4]),
        &[
            "EHLO app.example.test",
            "MAIL FROM:<user@other.test>",
            "QUIT",
        ],
    )
    .await;
    assert!(spoof.contains("550 5.7.1"), "{spoof}");

    let plain = talk(
        ctx,
        peer([203, 0, 113, 50]),
        &["EHLO client.test", "AUTH PLAIN AHVzZXIAc2VjcmV0", "QUIT"],
    )
    .await;
    assert!(plain.contains("538 5.7.11"), "{plain}");
}

async fn sink(
    reply: &'static [u8],
    hits: Arc<AtomicUsize>,
    captured: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((sock, _)) = listener.accept().await else {
                break;
            };
            let hits = Arc::clone(&hits);
            let captured = captured.clone();
            tokio::spawn(async move {
                hits.fetch_add(1, Ordering::SeqCst);
                let (read, mut write) = sock.into_split();
                let mut read = BufReader::new(read);
                let _ = write.write_all(b"220 sink ESMTP\r\n").await;
                let mut line = String::new();
                let mut data = Vec::new();
                loop {
                    line.clear();
                    if read.read_line(&mut line).await.unwrap_or(0) == 0 {
                        break;
                    }
                    let verb = line
                        .split_whitespace()
                        .next()
                        .unwrap_or("")
                        .to_ascii_uppercase();
                    match verb.as_str() {
                        "DATA" => {
                            let _ = write.write_all(b"354 go\r\n").await;
                            data.clear();
                            loop {
                                line.clear();
                                if read.read_line(&mut line).await.unwrap_or(0) == 0 {
                                    break;
                                }
                                if line.trim() == "." {
                                    break;
                                }
                                data.extend_from_slice(line.as_bytes());
                            }
                            let _ = captured.send(data.clone());
                            let _ = write.write_all(b"250 OK\r\n").await;
                        }
                        "QUIT" => {
                            let _ = write.write_all(b"221 bye\r\n").await;
                            break;
                        }
                        "RCPT" => {
                            let _ = write.write_all(reply).await;
                        }
                        "EHLO" | "HELO" => {
                            let _ = write.write_all(b"250-sink\r\n250 OK\r\n").await;
                        }
                        _ => {
                            let _ = write.write_all(b"250 OK\r\n").await;
                        }
                    }
                }
            });
        }
    });
    addr
}

async fn queued(spool: &Spool, from: &str, to: &str, body: &[u8]) -> Envelope {
    let env = Envelope {
        id: Envelope::new_id(),
        tenant_id: None,
        authenticated_as: None,
        mail_from: from.into(),
        rcpt_to: vec![to.into()],
        received_at: time::OffsetDateTime::now_utc(),
        remote_ip: "203.0.113.8".parse().unwrap(),
        helo: "client.test".into(),
        attempts: 0,
        next_attempt_at: None,
        state: SpoolState::Incoming,
        direction: Direction::Outbound,
        tls_version: None,
        tls_cipher: None,
        rcpt_status: Vec::new(),
        prepend_headers: Vec::new(),
        dsn_sent: false,
        tls: Default::default(),
        pipeline: "deliver".into(),
    };
    spool
        .accept(env.clone(), std::io::Cursor::new(body.to_vec()))
        .await
        .unwrap();
    env
}

#[tokio::test]
async fn delivery_adds_received_header() {
    let h = await_harness().await;
    let hits = Arc::new(AtomicUsize::new(0));
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let addr = sink(b"250 OK\r\n", hits, tx).await;
    let mut cfg = (*h.cfg).clone();
    cfg.domains.routes = vec![DomainRoute {
        domain: "example.test".into(),
        next_hop: addr.to_string(),
    }];
    let env = queued(
        &h.spool,
        "a@outside.test",
        "b@example.test",
        b"Subject: hi\r\n\r\nhello\r\n",
    )
    .await;
    let deliverer = Deliverer::new(Arc::clone(&h.spool), Arc::new(cfg), Arc::new(MapDns::new()));
    let outcome = deliverer.deliver(&env.id).await.unwrap();
    assert!(
        matches!(
            outcome,
            currawong_smtp::delivery::DeliveryOutcome::Delivered
        ),
        "{outcome:?}"
    );
    let data = timeout(Duration::from_secs(2), rx.recv())
        .await
        .unwrap()
        .unwrap();
    let text = String::from_utf8_lossy(&data);
    assert!(text.contains("Received:"), "{text}");
    assert!(text.contains("hello"));
}

#[tokio::test(start_paused = true)]
async fn delivery_4xx_retries_on_schedule() {
    let h = await_harness().await;
    let hits = Arc::new(AtomicUsize::new(0));
    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
    let addr = sink(b"450 busy\r\n", Arc::clone(&hits), tx).await;
    let mut cfg = (*h.cfg).clone();
    cfg.domains.routes = vec![DomainRoute {
        domain: "example.test".into(),
        next_hop: addr.to_string(),
    }];
    let env = queued(
        &h.spool,
        "a@outside.test",
        "b@example.test",
        b"Subject: hi\r\n\r\nhello\r\n",
    )
    .await;
    let deliverer = Deliverer::new(Arc::clone(&h.spool), Arc::new(cfg), Arc::new(MapDns::new()));
    let outcome = deliverer.deliver(&env.id).await.unwrap();
    assert!(
        matches!(
            outcome,
            currawong_smtp::delivery::DeliveryOutcome::TempFail(_)
        ),
        "{outcome:?}"
    );
    tokio::task::yield_now().await;
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    deliverer.poll_due().await.unwrap();
    tokio::task::yield_now().await;
    assert_eq!(hits.load(Ordering::SeqCst), 1, "not due yet");
    tokio::time::advance(Duration::from_secs(5 * 60 + 1)).await;
    deliverer.poll_due().await.unwrap();
    tokio::task::yield_now().await;
    assert_eq!(hits.load(Ordering::SeqCst), 2);
    let stored = h.spool.load(&env.id).await.unwrap();
    assert_eq!(stored.attempts, 2);
}

#[tokio::test]
async fn delivery_5xx_one_dsn_and_null_sender_none() {
    let h = await_harness().await;
    let hits = Arc::new(AtomicUsize::new(0));
    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
    let addr = sink(b"550 no such user\r\n", hits, tx).await;
    let mut cfg = (*h.cfg).clone();
    cfg.domains.routes = vec![DomainRoute {
        domain: "example.test".into(),
        next_hop: addr.to_string(),
    }];
    let env = queued(
        &h.spool,
        "sender@example.test",
        "b@example.test",
        b"Subject: hi\r\n\r\nhello\r\n",
    )
    .await;
    let deliverer = Deliverer::new(
        Arc::clone(&h.spool),
        Arc::new(cfg.clone()),
        Arc::new(MapDns::new()),
    );
    let outcome = deliverer.deliver(&env.id).await.unwrap();
    assert!(
        matches!(
            outcome,
            currawong_smtp::delivery::DeliveryOutcome::PermFail(_)
        ),
        "{outcome:?}"
    );
    let all = all_messages(&h.spool).await;
    let dsns: Vec<_> = all
        .iter()
        .filter(|item| item.mail_from.is_empty())
        .collect();
    assert_eq!(dsns.len(), 1, "{all:?}");
    let dsn_body = h.spool.read_body(&dsns[0].id).await.unwrap();
    assert!(
        dsn_body.windows(12).any(|w| w == b"Auto-Submitted")
            || String::from_utf8_lossy(&dsn_body).contains("Delivery")
    );

    let null = queued(
        &h.spool,
        "",
        "b@example.test",
        b"Subject: bounce\r\n\r\nno\r\n",
    )
    .await;
    let _ = deliverer.deliver(&null.id).await.unwrap();
    let after = all_messages(&h.spool).await;
    let extra = after
        .iter()
        .filter(|item| item.id != null.id && item.mail_from.is_empty())
        .count();
    assert_eq!(extra, 1, "null sender must not create another DSN");
}

async fn all_messages(spool: &Spool) -> Vec<Envelope> {
    let mut out = Vec::new();
    for state in [
        SpoolState::Incoming,
        SpoolState::Active,
        SpoolState::Deferred,
        SpoolState::Done,
    ] {
        out.extend(spool.list(state).await.unwrap());
    }
    out
}
