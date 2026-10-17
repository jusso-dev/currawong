//! Outbound delivery through `Deliverer::poll_due` and `deliver`, the calls
//! the daemon makes, against scripted in-process SMTP sinks.
use async_trait::async_trait;
use currawong_core::config::{Config, DomainRoute};
use currawong_smtp::{
    delivery::{Deliverer, DeliveryOutcome},
    dns::{Answer, DnsLookup, LookupError, MapDns},
};
use currawong_spool::{Envelope, RcptStatus, Spool, SpoolState};
use std::{
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::TcpListener,
    sync::mpsc,
};

type RcptReply = Arc<dyn Fn(&str) -> Vec<u8> + Send + Sync>;

#[derive(Clone)]
struct Script {
    /// `None` accepts the connection and never greets.
    greeting: Option<Vec<u8>>,
    rcpt: RcptReply,
}

impl Script {
    fn ok() -> Self {
        Self {
            greeting: Some(b"220 sink ESMTP\r\n".to_vec()),
            rcpt: Arc::new(|_| b"250 2.1.5 ok\r\n".to_vec()),
        }
    }

    fn rcpt(reply: impl Fn(&str) -> Vec<u8> + Send + Sync + 'static) -> Self {
        Self {
            rcpt: Arc::new(reply),
            ..Self::ok()
        }
    }
}

#[derive(Debug, Default)]
struct Session {
    commands: Vec<String>,
    data: Vec<u8>,
}

struct Sink {
    addr: SocketAddr,
    hits: Arc<AtomicUsize>,
    sessions: mpsc::UnboundedReceiver<Session>,
}

async fn sink(script: Script) -> Sink {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let (tx, sessions) = mpsc::unbounded_channel();
    let counter = Arc::clone(&hits);
    tokio::spawn(async move {
        while let Ok((sock, _)) = listener.accept().await {
            counter.fetch_add(1, Ordering::SeqCst);
            let script = script.clone();
            let tx = tx.clone();
            tokio::spawn(async move {
                let (read, mut write) = sock.into_split();
                let mut read = BufReader::new(read);
                let Some(greeting) = script.greeting.clone() else {
                    // Tarpit: hold the socket open and say nothing.
                    let mut line = Vec::new();
                    let _ = read.read_until(b'\n', &mut line).await;
                    tokio::time::sleep(Duration::from_secs(86_400)).await;
                    return;
                };
                let _ = write.write_all(&greeting).await;
                let mut session = Session::default();
                loop {
                    let mut line = Vec::new();
                    if read.read_until(b'\n', &mut line).await.unwrap_or(0) == 0 {
                        break;
                    }
                    let text = String::from_utf8_lossy(&line).into_owned();
                    session.commands.push(text.clone());
                    let verb = text
                        .split([' ', ':', '\r', '\n'])
                        .next()
                        .unwrap_or("")
                        .to_ascii_uppercase();
                    let reply: Vec<u8> = match verb.as_str() {
                        "EHLO" | "HELO" => b"250-sink\r\n250 8BITMIME\r\n".to_vec(),
                        "MAIL" | "RSET" => b"250 2.1.0 ok\r\n".to_vec(),
                        "RCPT" => {
                            let addr = text
                                .split_once('<')
                                .and_then(|(_, rest)| rest.split_once('>'))
                                .map(|(addr, _)| addr.to_string())
                                .unwrap_or_default();
                            (script.rcpt)(&addr)
                        }
                        "DATA" => {
                            let _ = write.write_all(b"354 go\r\n").await;
                            loop {
                                let mut line = Vec::new();
                                if read.read_until(b'\n', &mut line).await.unwrap_or(0) == 0 {
                                    break;
                                }
                                if line == b".\r\n" {
                                    break;
                                }
                                session.data.extend_from_slice(&line);
                            }
                            b"250 2.0.0 queued\r\n".to_vec()
                        }
                        "QUIT" => {
                            let _ = write.write_all(b"221 bye\r\n").await;
                            break;
                        }
                        _ => b"500 what\r\n".to_vec(),
                    };
                    let _ = write.write_all(&reply).await;
                }
                let _ = tx.send(session);
            });
        }
    });
    Sink {
        addr,
        hits,
        sessions,
    }
}

struct Harness {
    cfg: Config,
    spool: Arc<Spool>,
    _dir: tempfile::TempDir,
}

async fn harness() -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::default();
    cfg.spool.dir = dir.path().join("spool");
    cfg.gateway.hostname = "mx.example.test".into();
    cfg.delivery.tls_database = dir.path().join("tls.sqlite");
    let spool = Arc::new(Spool::open(&cfg.spool.dir).await.unwrap());
    Harness {
        cfg,
        spool,
        _dir: dir,
    }
}

fn route(cfg: &mut Config, domain: &str, addr: SocketAddr) {
    cfg.domains.routes.push(DomainRoute {
        domain: domain.into(),
        next_hop: addr.to_string(),
    });
}

fn envelope(from: &str, rcpts: &[&str]) -> Envelope {
    Envelope {
        id: Envelope::new_id(),
        tenant_id: None,
        mail_from: from.into(),
        rcpt_to: rcpts.iter().map(|rcpt| rcpt.to_string()).collect(),
        received_at: time::OffsetDateTime::now_utc(),
        remote_ip: "203.0.113.8".parse().unwrap(),
        helo: "client.test".into(),
        attempts: 0,
        next_attempt_at: None,
        state: SpoolState::Incoming,
        direction: currawong_core::Direction::Inbound,
        tls_version: None,
        tls_cipher: None,
        rcpt_status: Vec::new(),
        prepend_headers: Vec::new(),
        dsn_sent: false,
        pipeline: "deliver".into(),
    }
}

const BODY: &[u8] = b"Subject: hi\r\n\r\nhello\r\n";

async fn queue(spool: &Spool, env: Envelope) -> Envelope {
    spool
        .accept(env.clone(), std::io::Cursor::new(BODY.to_vec()))
        .await
        .unwrap();
    env
}

async fn dsns(spool: &Spool) -> Vec<(Envelope, String)> {
    let mut out = Vec::new();
    for state in [
        SpoolState::Incoming,
        SpoolState::Active,
        SpoolState::Deferred,
        SpoolState::Done,
    ] {
        for env in spool.list(state).await.unwrap() {
            if env.mail_from.is_empty() {
                let body = spool.read_body(&env.id).await.unwrap();
                out.push((env, String::from_utf8_lossy(&body).into_owned()));
            }
        }
    }
    out
}

fn status<'a>(env: &'a Envelope, rcpt: &str) -> &'a RcptStatus {
    env.rcpt_status
        .iter()
        .find(|status| status.address == rcpt)
        .unwrap()
}

#[tokio::test]
async fn poll_due_honours_next_attempt_and_skips_unscanned() {
    let h = harness().await;
    let busy = sink(Script::rcpt(|_| b"450 4.2.0 busy\r\n".to_vec())).await;
    let mut cfg = h.cfg.clone();
    route(&mut cfg, "example.test", busy.addr);
    let env = queue(&h.spool, envelope("a@outside.test", &["b@example.test"])).await;
    let mut unscanned = envelope("a@outside.test", &["c@example.test"]);
    unscanned.pipeline = "pending".into();
    let unscanned = queue(&h.spool, unscanned).await;
    let deliverer = Deliverer::new(Arc::clone(&h.spool), Arc::new(cfg), Arc::new(MapDns::new()));

    deliverer.poll_due().await.unwrap();
    assert_eq!(busy.hits.load(Ordering::SeqCst), 1);
    let mut stored = h.spool.load(&env.id).await.unwrap();
    assert_eq!(stored.state, SpoolState::Deferred);
    assert_eq!(stored.attempts, 1);
    let wait = stored.next_attempt_at.unwrap() - time::OffsetDateTime::now_utc();
    assert!(wait > time::Duration::minutes(4), "{wait}");

    deliverer.poll_due().await.unwrap();
    assert_eq!(busy.hits.load(Ordering::SeqCst), 1, "not due yet");

    // The retry time passes.
    stored.next_attempt_at = Some(time::OffsetDateTime::now_utc() - time::Duration::seconds(1));
    h.spool.update(&stored).await.unwrap();
    deliverer.poll_due().await.unwrap();
    assert_eq!(busy.hits.load(Ordering::SeqCst), 2);
    assert_eq!(h.spool.load(&env.id).await.unwrap().attempts, 2);
    let untouched = h.spool.load(&unscanned.id).await.unwrap();
    assert_eq!(untouched.state, SpoolState::Incoming);
    assert!(
        untouched.rcpt_status.is_empty(),
        "unscanned mail was delivered"
    );
}

/// Panics for one domain, otherwise answers from the map.
struct PanicDns(MapDns);

#[async_trait]
impl DnsLookup for PanicDns {
    async fn lookup_ips(&self, name: &str) -> Result<Vec<IpAddr>, String> {
        self.0.lookup_ips(name).await
    }

    async fn lookup_mx(&self, name: &str) -> Result<Vec<(u16, String)>, String> {
        self.0.lookup_mx(name).await
    }

    async fn resolve_mx(&self, name: &str) -> Result<Answer<Vec<(u16, String)>>, LookupError> {
        assert_ne!(name, "boom.test", "injected failure");
        self.0.resolve_mx(name).await
    }
}

#[tokio::test]
async fn one_bad_message_does_not_stop_the_pass() {
    let h = harness().await;
    let weird = sink(Script::rcpt(|_| "250\u{e9} ok\r\n".as_bytes().to_vec())).await;
    let mut good = sink(Script::ok()).await;
    let mut cfg = h.cfg.clone();
    route(&mut cfg, "weird.test", weird.addr);
    route(&mut cfg, "example.test", good.addr);
    let boom = queue(&h.spool, envelope("a@outside.test", &["x@boom.test"])).await;
    let odd = queue(&h.spool, envelope("a@outside.test", &["x@weird.test"])).await;
    let fine = queue(&h.spool, envelope("a@outside.test", &["x@example.test"])).await;
    let deliverer = Deliverer::new(
        Arc::clone(&h.spool),
        Arc::new(cfg),
        Arc::new(PanicDns(MapDns::new())),
    );
    deliverer.poll_due().await.unwrap();
    assert!(good.sessions.recv().await.is_some());
    assert_eq!(
        h.spool.load(&fine.id).await.unwrap().state,
        SpoolState::Done
    );
    let odd = h.spool.load(&odd.id).await.unwrap();
    assert_eq!(odd.state, SpoolState::Deferred);
    assert!(status(&odd, "x@weird.test").detail.contains("bad reply"));
    assert_eq!(
        h.spool.load(&boom.id).await.unwrap().state,
        SpoolState::Incoming
    );
}

#[tokio::test(start_paused = true)]
async fn silent_host_times_out() {
    let h = harness().await;
    let tarpit = sink(Script {
        greeting: None,
        ..Script::ok()
    })
    .await;
    let mut cfg = h.cfg.clone();
    route(&mut cfg, "example.test", tarpit.addr);
    let env = queue(&h.spool, envelope("a@outside.test", &["b@example.test"])).await;
    let deliverer = Deliverer::new(Arc::clone(&h.spool), Arc::new(cfg), Arc::new(MapDns::new()));
    let outcome = deliverer.deliver(&env.id).await.unwrap();
    assert!(
        matches!(&outcome, DeliveryOutcome::TempFail(detail) if detail.contains("timed out")),
        "{outcome:?}"
    );
}

#[tokio::test]
async fn oversized_reply_is_refused() {
    let h = harness().await;
    let mut huge = b"220 ".to_vec();
    huge.extend(std::iter::repeat_n(b'a', 1 << 20));
    let flood = sink(Script {
        greeting: Some(huge),
        ..Script::ok()
    })
    .await;
    let mut cfg = h.cfg.clone();
    route(&mut cfg, "example.test", flood.addr);
    let env = queue(&h.spool, envelope("a@outside.test", &["b@example.test"])).await;
    let deliverer = Deliverer::new(Arc::clone(&h.spool), Arc::new(cfg), Arc::new(MapDns::new()));
    let outcome = deliverer.deliver(&env.id).await.unwrap();
    assert!(
        matches!(&outcome, DeliveryOutcome::TempFail(detail) if detail.contains("too long")),
        "{outcome:?}"
    );
}

#[tokio::test]
async fn recipients_are_judged_one_by_one() {
    let h = harness().await;
    let later = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&later);
    let mut mx = sink(Script::rcpt(move |rcpt| match rcpt {
        "gone@example.test" => b"550 5.1.1 no such user\r\n".to_vec(),
        "busy@example.test" if !flag.load(Ordering::SeqCst) => b"450 4.2.0 busy\r\n".to_vec(),
        _ => b"250 2.1.5 ok\r\n".to_vec(),
    }))
    .await;
    let mut cfg = h.cfg.clone();
    route(&mut cfg, "example.test", mx.addr);
    let env = queue(
        &h.spool,
        envelope(
            "sender@outside.test",
            &["ok@example.test", "gone@example.test", "busy@example.test"],
        ),
    )
    .await;
    let deliverer = Deliverer::new(Arc::clone(&h.spool), Arc::new(cfg), Arc::new(MapDns::new()));

    let outcome = deliverer.deliver(&env.id).await.unwrap();
    assert!(
        matches!(outcome, DeliveryOutcome::TempFail(_)),
        "{outcome:?}"
    );
    let first = mx.sessions.recv().await.unwrap();
    assert!(
        first.commands.iter().any(|cmd| cmd.starts_with("DATA")),
        "DATA must follow one accepted RCPT: {first:?}"
    );
    let stored = h.spool.load(&env.id).await.unwrap();
    assert_eq!(stored.state, SpoolState::Deferred);
    assert_eq!(status(&stored, "ok@example.test").status, "delivered");
    assert_eq!(status(&stored, "gone@example.test").status, "bounced");
    assert_eq!(status(&stored, "busy@example.test").status, "temp");

    let bounces = dsns(&h.spool).await;
    assert_eq!(bounces.len(), 1, "perm recipient bounced at once");
    let (dsn_env, dsn) = &bounces[0];
    assert_eq!(dsn_env.rcpt_to, vec!["sender@outside.test".to_string()]);
    assert!(dsn.contains("multipart/report"), "{dsn}");
    assert!(dsn.contains("delivery-status"), "{dsn}");
    assert!(
        dsn.contains("Final-Recipient: rfc822; gone@example.test"),
        "{dsn}"
    );
    assert!(dsn.contains("Status: 5.1.1"), "{dsn}");
    assert!(!dsn.contains("Final-Recipient: rfc822; busy@"), "{dsn}");
    assert!(!dsn.contains("Final-Recipient: rfc822; ok@"), "{dsn}");

    later.store(true, Ordering::SeqCst);
    let outcome = deliverer.deliver(&env.id).await.unwrap();
    assert_eq!(outcome, DeliveryOutcome::Delivered);
    let second = mx.sessions.recv().await.unwrap();
    let rcpts: Vec<_> = second
        .commands
        .iter()
        .filter(|cmd| cmd.starts_with("RCPT"))
        .collect();
    assert_eq!(rcpts.len(), 1, "only the deferred recipient is retried");
    assert!(rcpts[0].contains("busy@example.test"));
    assert_eq!(h.spool.load(&env.id).await.unwrap().state, SpoolState::Done);
    assert_eq!(dsns(&h.spool).await.len(), 1, "no second DSN");
}

#[tokio::test]
async fn expired_message_bounces_every_pending_recipient() {
    let h = harness().await;
    let mx = sink(Script::ok()).await;
    let mut cfg = h.cfg.clone();
    route(&mut cfg, "example.test", mx.addr);
    let mut env = envelope("sender@outside.test", &["late@example.test"]);
    env.received_at -= time::Duration::days(6);
    env.rcpt_status.push(RcptStatus {
        address: "late@example.test".into(),
        status: "temp".into(),
        detail: "450 busy".into(),
    });
    let env = queue(&h.spool, env).await;
    let deliverer = Deliverer::new(Arc::clone(&h.spool), Arc::new(cfg), Arc::new(MapDns::new()));
    let outcome = deliverer.deliver(&env.id).await.unwrap();
    assert!(
        matches!(outcome, DeliveryOutcome::PermFail(_)),
        "{outcome:?}"
    );
    assert_eq!(mx.hits.load(Ordering::SeqCst), 0);
    let bounces = dsns(&h.spool).await;
    assert_eq!(bounces.len(), 1);
    let dsn = &bounces[0].1;
    assert!(
        dsn.contains("Final-Recipient: rfc822; late@example.test"),
        "{dsn}"
    );
    assert!(dsn.contains("Status: 4.4.7"), "{dsn}");
    assert!(dsn.contains("450 busy"), "{dsn}");
}

#[tokio::test]
async fn dsn_is_not_duplicated_after_a_crash() {
    let h = harness().await;
    let mx = sink(Script::rcpt(|_| b"550 5.1.1 no such user\r\n".to_vec())).await;
    let mut cfg = h.cfg.clone();
    route(&mut cfg, "example.test", mx.addr);
    let env = queue(
        &h.spool,
        envelope("sender@outside.test", &["gone@example.test"]),
    )
    .await;
    let deliverer = Deliverer::new(Arc::clone(&h.spool), Arc::new(cfg), Arc::new(MapDns::new()));
    deliverer.deliver(&env.id).await.unwrap();
    assert_eq!(dsns(&h.spool).await.len(), 1);
    // A crash after the DSN was spooled but before the bounce was recorded.
    let mut stored = h.spool.load(&env.id).await.unwrap();
    stored.rcpt_status[0].status = "perm".into();
    h.spool.update(&stored).await.unwrap();
    deliverer.deliver(&env.id).await.unwrap();
    assert_eq!(dsns(&h.spool).await.len(), 1);
}

#[tokio::test]
async fn control_bytes_in_a_recipient_never_reach_the_wire() {
    let h = harness().await;
    let mut mx = sink(Script::ok()).await;
    let mut cfg = h.cfg.clone();
    route(&mut cfg, "example.test", mx.addr);
    let evil = "evil\r\nRSET\r\nRCPT TO:<x@y.test>@example.test";
    let env = queue(
        &h.spool,
        envelope("sender@outside.test", &["ok@example.test", evil]),
    )
    .await;
    let deliverer = Deliverer::new(Arc::clone(&h.spool), Arc::new(cfg), Arc::new(MapDns::new()));
    deliverer.deliver(&env.id).await.unwrap();
    let session = mx.sessions.recv().await.unwrap();
    assert!(
        !session.commands.iter().any(|cmd| cmd.starts_with("RSET")),
        "{session:?}"
    );
    let rcpts = session
        .commands
        .iter()
        .filter(|cmd| cmd.starts_with("RCPT"))
        .count();
    assert_eq!(rcpts, 1, "{session:?}");
    let stored = h.spool.load(&env.id).await.unwrap();
    assert!(status(&stored, evil).detail.contains("5.1.3"));
    let dsn = &dsns(&h.spool).await[0].1;
    assert!(!dsn.contains("\r\nRSET"), "{dsn}");
}

#[tokio::test]
async fn message_ends_with_a_single_terminator() {
    let h = harness().await;
    let mut mx = sink(Script::ok()).await;
    let mut cfg = h.cfg.clone();
    route(&mut cfg, "example.test", mx.addr);
    let env = queue(&h.spool, envelope("a@outside.test", &["b@example.test"])).await;
    let deliverer = Deliverer::new(Arc::clone(&h.spool), Arc::new(cfg), Arc::new(MapDns::new()));
    deliverer.deliver(&env.id).await.unwrap();
    let data = mx.sessions.recv().await.unwrap().data;
    assert!(data.ends_with(b"\r\n\r\nhello\r\n"), "{data:?}");
    assert!(data.starts_with(b"Received: "));
}

#[tokio::test]
async fn nxdomain_and_null_mx_bounce() {
    let h = harness().await;
    let mut dns = MapDns::new();
    dns.nxdomain.insert("gone.test".into());
    dns.mx.insert("null.test".into(), vec![(0, ".".into())]);
    let deliverer = Deliverer::new(Arc::clone(&h.spool), Arc::new(h.cfg.clone()), Arc::new(dns));
    let gone = queue(&h.spool, envelope("a@outside.test", &["x@gone.test"])).await;
    let outcome = deliverer.deliver(&gone.id).await.unwrap();
    assert!(
        matches!(&outcome, DeliveryOutcome::PermFail(detail) if detail.starts_with("5.1.2")),
        "{outcome:?}"
    );
    let null = queue(&h.spool, envelope("a@outside.test", &["x@null.test"])).await;
    let outcome = deliverer.deliver(&null.id).await.unwrap();
    assert!(
        matches!(&outcome, DeliveryOutcome::PermFail(detail) if detail.starts_with("5.1.10")),
        "{outcome:?}"
    );
}

#[tokio::test]
async fn mx_pointing_inward_is_refused_unless_allowed() {
    let h = harness().await;
    let mx = sink(Script::ok()).await;
    let mut dns = MapDns::new();
    dns.mx
        .insert("example.test".into(), vec![(10, "mx.example.test".into())]);
    dns.ips.insert("mx.example.test".into(), vec![mx.addr.ip()]);
    let dns = Arc::new(dns);
    let env = queue(&h.spool, envelope("a@outside.test", &["b@example.test"])).await;
    let mut deliverer = Deliverer::new(
        Arc::clone(&h.spool),
        Arc::new(h.cfg.clone()),
        Arc::clone(&dns),
    );
    deliverer.mx_port = mx.addr.port();
    let outcome = deliverer.deliver(&env.id).await.unwrap();
    assert!(
        matches!(outcome, DeliveryOutcome::TempFail(_)),
        "{outcome:?}"
    );
    assert_eq!(mx.hits.load(Ordering::SeqCst), 0);

    let mut cfg = h.cfg.clone();
    cfg.delivery.allow_private_mx = true;
    let mut deliverer = Deliverer::new(Arc::clone(&h.spool), Arc::new(cfg), dns);
    deliverer.mx_port = mx.addr.port();
    let outcome = deliverer.deliver(&env.id).await.unwrap();
    assert_eq!(outcome, DeliveryOutcome::Delivered);
}
