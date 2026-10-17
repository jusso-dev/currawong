//! Link rewriting in the real pipeline: the delivered copy carries the
//! rewritten links and an ARC seal over them, and a link blocked after
//! delivery is refused by the click service built from the same config.
use currawong_auth::{generate, seed_txt, AuthChecker, KeyStore, GATEWAY_TENANT};
use currawong_core::{config::Config, Direction, MessageId};
use currawong_quarantine::QuarantineStore;
use currawong_spool::{Envelope, Spool, SpoolState};
use currawongd::{classify_pending, url_protection, Pipeline};
use std::{io::Cursor, net::SocketAddr, sync::Arc};
use time::OffsetDateTime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const ID: &str = "currawong.example.test";
const BASE: &str = "https://links.example.com.au";

fn envelope(id: &str, direction: Direction) -> Envelope {
    Envelope {
        id: MessageId(id.into()),
        tenant_id: None,
        mail_from: "user@example.test".into(),
        rcpt_to: vec!["dest@example.test".into()],
        received_at: OffsetDateTime::now_utc(),
        remote_ip: "203.0.113.8".parse().unwrap(),
        helo: "client.example.test".into(),
        attempts: 0,
        next_attempt_at: None,
        state: SpoolState::Incoming,
        direction,
        tls_version: None,
        tls_cipher: None,
        rcpt_status: Vec::new(),
        prepend_headers: Vec::new(),
        dsn_sent: false,
        pipeline: "pending".into(),
    }
}

const MESSAGE: &[u8] = b"From: user@example.test\r\nTo: dest@example.test\r\nSubject: invoice\r\nDate: Wed, 14 Oct 2026 01:00:00 +0000\r\nMessage-ID: <29@example.test>\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nPay at https://pay.example.net/invoice/29 today.\r\n";

async fn get(addr: SocketAddr, path: &str) -> (u16, String) {
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let request = format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut raw = String::new();
    stream.read_to_string(&mut raw).await.unwrap();
    let status = raw.split(' ').nth(1).unwrap().parse().unwrap();
    (status, raw)
}

#[tokio::test]
async fn urls_delivered_copy_is_rewritten_sealed_and_blockable_after_delivery() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::default();
    cfg.spool.dir = dir.path().join("spool");
    cfg.scanner.enabled = false;
    cfg.auth.authserv_id = ID.into();
    cfg.dkim.database = dir.path().join("dkim.sqlite");
    cfg.dkim.kek_path = dir.path().join("dkim.kek");
    cfg.url_rewrite.enabled = true;
    cfg.url_rewrite.base_url = BASE.into();
    cfg.url_rewrite.key_file = dir.path().join("url.key");
    cfg.url_rewrite.blocklist = Some(dir.path().join("blocklist.txt"));
    cfg.url_rewrite.click_log = dir.path().join("clicks.jsonl");
    std::fs::write(&cfg.url_rewrite.key_file, [0x29u8; 32]).unwrap();

    let store = KeyStore::open(&cfg.dkim.database, &cfg.dkim.kek_path).unwrap();
    let mut sealer = generate(GATEWAY_TENANT, ID, "arc1", "rsa").unwrap();
    sealer.active = true;
    store.insert(&sealer).unwrap();
    let auth = AuthChecker::offline(ID).unwrap();
    seed_txt(auth.cache(), "example.test", "v=spf1 +all").unwrap();
    let (rewriter, clicks) = url_protection(&cfg).unwrap();
    let mut pipeline = Pipeline::new(Arc::new(cfg), auth)
        .with_keys(store)
        .with_url_rewriter(rewriter);

    let spool = Spool::open(&dir.path().join("spool")).await.unwrap();
    let inbound = envelope("01ARZ3NDEKTSV4RRFFQ69G5FAV", Direction::Inbound);
    let outbound = envelope("01ARZ3NDEKTSV4RRFFQ69G5FAW", Direction::Outbound);
    for env in [&inbound, &outbound] {
        spool
            .accept(env.clone(), Cursor::new(MESSAGE.to_vec()))
            .await
            .unwrap();
    }
    let quarantine = QuarantineStore::open(dir.path().join("held")).unwrap();
    classify_pending(&spool, &mut pipeline, &quarantine)
        .await
        .unwrap();

    // Outbound mail is never rewritten.
    let body = spool.read_body(&outbound.id).await.unwrap();
    assert_eq!(body, MESSAGE);

    let env = spool.load(&inbound.id).await.unwrap();
    assert_eq!(env.pipeline, "deliver");
    let body = String::from_utf8(spool.read_body(&inbound.id).await.unwrap()).unwrap();
    assert!(!body.contains("pay.example.net"), "{body}");
    let at = body.find(&format!("{BASE}/u/")).expect("rewritten link");
    let token: String = body[at + BASE.len() + 3..]
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        .collect();
    let path = format!("/u/{}", token.trim_end_matches('.'));

    // Rewriting set ScanReport.modified, so the delivered copy is ARC sealed
    // and the seal holds over the rewritten body.
    let headers = env.prepend_headers.concat();
    assert!(headers.contains("ARC-Seal: i=1;"), "{headers}");
    let wire = [headers.as_bytes(), body.as_bytes()].concat();
    let next = AuthChecker::offline("mx.receiver.test").unwrap();
    seed_txt(next.cache(), &sealer.dns_name(), &sealer.public_txt).unwrap();
    assert_eq!(next.check(&wire, &env).await.arc.result, "pass");

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(currawong_admin::routes::click::serve(listener, clicks));
    let (status, reply) = get(addr, &path).await;
    assert_eq!(status, 302, "{reply}");
    assert!(reply.contains("location: https://pay.example.net/invoice/29\r\n"));

    std::fs::write(dir.path().join("blocklist.txt"), "pay.example.net\n").unwrap();
    let (status, reply) = get(addr, &path).await;
    assert_eq!(status, 403);
    assert!(reply.contains("This link has been blocked"), "{reply}");
    let log = std::fs::read_to_string(dir.path().join("clicks.jsonl")).unwrap();
    assert_eq!(log.lines().count(), 2);
    assert!(log.contains("\"action\":\"blocked\""));
    assert!(log.contains("01ARZ3NDEKTSV4RRFFQ69G5FAV"));
}
