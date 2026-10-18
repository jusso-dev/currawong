//! #47: mail Exchange on-premises relays through Currawong from its Send
//! connector is outbound mail. It is accepted only from the Exchange source
//! addresses (the tenant's trusted relay CIDRs), DLP scanned and DKIM signed.
//! Exchange is an in-process SMTP client here, not a real server.
use currawong_auth::{generate, seed_txt, AuthChecker, KeyStore};
use currawong_core::{
    config::{Config, DomainRoute, ExchangeVersion, ListenerRole, MailboxPlatform, TenantConfig},
    Direction, DlpKind,
};
use currawong_quarantine::QuarantineStore;
use currawong_smtp::{
    checks::CheckStack, delivery::outbound_bytes, relay::Relay, run_session,
    session::SessionContext, stream::BoxIo,
};
use currawong_spool::{Spool, SpoolState};
use currawongd::{classify_pending, Pipeline};
use std::{net::SocketAddr, path::Path, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    time::timeout,
};

const ID: &str = "currawong.example.test";
/// The Exchange Mailbox servers' source addresses (documentation range).
const EXCH01: [u8; 4] = [192, 0, 2, 25];

fn config(dir: &Path) -> Config {
    let mut cfg = Config::default();
    cfg.spool.dir = dir.join("spool");
    cfg.scanner.enabled = false;
    cfg.auth.authserv_id = ID.into();
    cfg.dkim.database = dir.join("dkim.sqlite");
    cfg.dkim.kek_path = dir.join("dkim.kek");
    cfg.checks.ratelimit_enabled = false;
    cfg.checks.greylist_enabled = false;
    cfg.checks.reputation_enabled = false;
    cfg.domains.accept = vec!["agency.example".into()];
    cfg.domains.routes = vec![DomainRoute {
        domain: "agency.example".into(),
        next_hop: String::new(),
        platform: Some(MailboxPlatform::ExchangeOnPrem {
            version: ExchangeVersion::Ex2019,
            mailbox_hosts: vec!["exch01.agency.example".into()],
            tls_cert_name: "mail.agency.example".into(),
            ca_file: None,
            client_cert: None,
            client_key: None,
        }),
    }];
    cfg.relay.tenants = vec![TenantConfig {
        id: "agency".into(),
        domains: vec!["agency.example".into()],
        trusted_cidrs: vec!["192.0.2.25/32".into(), "192.0.2.26/32".into()],
    }];
    cfg
}

/// The Exchange Send connector's side of one SMTP transaction on port 25.
async fn relay_from(ctx: Arc<SessionContext>, ip: [u8; 4], data: &str) -> String {
    let (client, server) = tokio::io::duplex(1024 * 1024);
    let peer = SocketAddr::from((ip, 41_000));
    tokio::spawn(async move {
        let shutdown = tokio_util::sync::CancellationToken::new();
        run_session(BoxIo::new(server), peer, ctx, shutdown, None).await;
    });
    let (read, mut write) = tokio::io::split(client);
    let mut read = BufReader::new(read);
    let mut transcript = String::new();
    let script = [
        "EHLO exch01.agency.example\r\n".to_string(),
        "MAIL FROM:<payroll@agency.example>\r\n".to_string(),
        "RCPT TO:<agent@partner.test>\r\n".to_string(),
        "DATA\r\n".to_string(),
        format!("{data}\r\n.\r\n"),
        "QUIT\r\n".to_string(),
    ];
    transcript.push_str(&reply(&mut read).await);
    for line in script {
        write.write_all(line.as_bytes()).await.unwrap();
        let answer = reply(&mut read).await;
        transcript.push_str(&answer);
        if answer.starts_with('5') {
            break;
        }
    }
    transcript
}

async fn reply<R: tokio::io::AsyncRead + Unpin>(read: &mut BufReader<R>) -> String {
    let mut all = String::new();
    loop {
        let mut line = String::new();
        let n = timeout(Duration::from_secs(5), read.read_line(&mut line))
            .await
            .ok()
            .and_then(Result::ok)
            .unwrap_or(0);
        all.push_str(&line);
        if n == 0 || line.as_bytes().get(3) != Some(&b'-') {
            return all;
        }
    }
}

fn message() -> String {
    // The ATO's published sample TFN.
    "From: payroll@agency.example\r\nTo: agent@partner.test\r\nSubject: staff\r\n\
     Date: Wed, 14 Oct 2026 01:00:00 +0000\r\nMessage-ID: <47@agency.example>\r\n\r\n\
     TFN: 123 456 782\r\n"
        .into()
}

#[tokio::test]
async fn exchange_relay_is_outbound_dlp_scanned_and_dkim_signed() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = Arc::new(config(dir.path()));
    let spool = Arc::new(Spool::open(&cfg.spool.dir).await.unwrap());
    let relay =
        Arc::new(Relay::open(&dir.path().join("relay.sqlite"), &cfg.relay.tenants).unwrap());
    let ctx = Arc::new(SessionContext {
        cfg: Arc::clone(&cfg),
        spool: Arc::clone(&spool),
        tls: None,
        checks: Arc::new(CheckStack::disabled()),
        relay,
        role: ListenerRole::Inbound,
    });

    // Anyone else trying to relay through the same listener is refused.
    let stranger = relay_from(Arc::clone(&ctx), [198, 51, 100, 7], &message()).await;
    assert!(stranger.contains("\r\n5"), "{stranger}");
    assert!(spool.list(SpoolState::Incoming).await.unwrap().is_empty());

    let transcript = relay_from(Arc::clone(&ctx), EXCH01, &message()).await;
    assert!(transcript.contains("250 2.0.0 OK"), "{transcript}");
    let stored = spool.list(SpoolState::Incoming).await.unwrap();
    assert_eq!(stored.len(), 1);
    let env = stored[0].clone();
    assert_eq!(env.direction, Direction::Outbound);
    assert_eq!(env.tenant_id.as_deref(), Some("agency"));

    let store = KeyStore::open(&cfg.dkim.database, &cfg.dkim.kek_path).unwrap();
    let mut key = generate("agency", "agency.example", "s1", "ed25519").unwrap();
    key.active = true;
    store.insert(&key).unwrap();
    let auth = AuthChecker::offline(ID).unwrap();
    seed_txt(auth.cache(), "agency.example", "v=spf1 ip4:192.0.2.25 -all").unwrap();
    let mut pipeline = Pipeline::new(Arc::clone(&cfg), auth).with_keys(store);

    // DLP runs on it as outbound mail.
    let body = spool.read_body(&env.id).await.unwrap();
    let (report, _) = pipeline.evaluate(&env, &body, None).await;
    let dlp = report.dlp.expect("outbound mail is DLP scanned");
    assert_eq!(dlp.counts.get(&DlpKind::Tfn), Some(&1), "{dlp:?}");

    // The classified message carries the tenant's DKIM signature on the wire.
    let quarantine = QuarantineStore::open(dir.path().join("held")).unwrap();
    classify_pending(&spool, &mut pipeline, &quarantine)
        .await
        .unwrap();
    let mut all = spool.list(SpoolState::Incoming).await.unwrap();
    all.extend(spool.list(SpoolState::Deferred).await.unwrap());
    let env = all.into_iter().find(|item| item.id == env.id).unwrap();
    let wire = outbound_bytes(&env, &body, ID);
    let text = String::from_utf8_lossy(&wire);
    assert!(text.contains("DKIM-Signature:"), "{text}");
    assert!(text.contains("d=agency.example"), "{text}");
    let verifier = AuthChecker::offline("mx.partner.test").unwrap();
    seed_txt(verifier.cache(), &key.dns_name(), &key.public_txt).unwrap();
    let mut far = env.clone();
    far.direction = Direction::Inbound;
    far.tenant_id = None;
    let results = verifier.check(&wire, &far).await;
    assert_eq!(
        results.dkim.first().map(|item| item.result.as_str()),
        Some("pass"),
        "{}",
        results.header
    );
}
