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
        authenticated_as: None,
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

struct Gateway {
    _dir: tempfile::TempDir,
    root: std::path::PathBuf,
    spool: Spool,
    pipeline: Pipeline,
    sealer: currawong_auth::StoredKey,
    quarantine: QuarantineStore,
}

/// A gateway with link rewriting and an ARC key. `seed` adds DNS answers.
async fn gateway(seed: impl FnOnce(&AuthChecker)) -> Gateway {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().to_path_buf();
    let mut cfg = Config::default();
    cfg.spool.dir = root.join("spool");
    cfg.scanner.enabled = false;
    cfg.auth.authserv_id = ID.into();
    cfg.dkim.database = root.join("dkim.sqlite");
    cfg.dkim.kek_path = root.join("dkim.kek");
    cfg.url_rewrite.enabled = true;
    cfg.url_rewrite.base_url = BASE.into();
    cfg.url_rewrite.key_file = root.join("url.key");
    cfg.url_rewrite.click_log = root.join("clicks.jsonl");
    std::fs::write(&cfg.url_rewrite.key_file, [0x29u8; 32]).unwrap();
    let store = KeyStore::open(&cfg.dkim.database, &cfg.dkim.kek_path).unwrap();
    let mut sealer = generate(GATEWAY_TENANT, ID, "arc1", "rsa").unwrap();
    sealer.active = true;
    store.insert(&sealer).unwrap();
    let auth = AuthChecker::offline(ID).unwrap();
    seed(&auth);
    let (rewriter, _) = url_protection(&cfg).unwrap();
    let pipeline = Pipeline::new(Arc::new(cfg), auth)
        .with_keys(store)
        .with_url_rewriter(rewriter);
    Gateway {
        spool: Spool::open(&root.join("spool")).await.unwrap(),
        quarantine: QuarantineStore::open(root.join("held")).unwrap(),
        root,
        _dir: dir,
        pipeline,
        sealer,
    }
}

impl Gateway {
    async fn classify(&mut self, env: &Envelope, raw: &[u8]) -> (Envelope, String) {
        self.spool
            .accept(env.clone(), Cursor::new(raw.to_vec()))
            .await
            .unwrap();
        classify_pending(&self.spool, &mut self.pipeline, &self.quarantine)
            .await
            .unwrap();
        let env = self.spool.load(&env.id).await.unwrap();
        let body = String::from_utf8(self.spool.read_body(&env.id).await.unwrap()).unwrap();
        (env, body)
    }
}

/// Review finding 1: a DKIM pass on the arriving message stays a pass in
/// our Authentication-Results and in the ARC set, though the body changed.
#[tokio::test]
async fn urls_dkim_pass_survives_rewriting_in_results_and_seal() {
    let dir = tempfile::tempdir().unwrap();
    let sender_store = KeyStore::open(
        &dir.path().join("sender.sqlite"),
        &dir.path().join("sender.kek"),
    )
    .unwrap();
    let mut dkim = generate("sender", "example.test", "s1", "ed25519").unwrap();
    dkim.active = true;
    sender_store.insert(&dkim).unwrap();
    let signature = currawong_auth::sign_outbound(&sender_store, MESSAGE, "sender").unwrap();
    let signed = [signature.as_bytes(), MESSAGE].concat();
    let (name, txt) = (dkim.dns_name(), dkim.public_txt.clone());
    let mut gw = gateway(|auth| {
        // SPF fails, so DMARC passes only through the DKIM signature.
        seed_txt(auth.cache(), "example.test", "v=spf1 -all").unwrap();
        seed_txt(auth.cache(), "_dmarc.example.test", "v=DMARC1; p=reject").unwrap();
        seed_txt(auth.cache(), &name, &txt).unwrap();
    })
    .await;
    let env = envelope("01ARZ3NDEKTSV4RRFFQ69G5FAV", Direction::Inbound);
    let (env, body) = gw.classify(&env, &signed).await;
    assert_eq!(env.pipeline, "deliver");
    assert!(body.contains(&format!("{BASE}/u/")), "{body}");
    let headers = env.prepend_headers.concat();
    let unfolded = headers.replace("\r\n\t", " ").replace("\r\n ", " ");
    let field = |name: &str| {
        unfolded
            .lines()
            .find(|line| line.starts_with(name))
            .unwrap_or_else(|| panic!("{name} missing: {headers}"))
            .to_string()
    };
    for name in ["Authentication-Results:", "ARC-Authentication-Results:"] {
        let value = field(name);
        assert!(
            value.contains("dkim=pass") && value.contains("dmarc=pass"),
            "{value}"
        );
    }
    let wire = [headers.as_bytes(), body.as_bytes()].concat();
    let next = AuthChecker::offline("mx.receiver.test").unwrap();
    seed_txt(next.cache(), &gw.sealer.dns_name(), &gw.sealer.public_txt).unwrap();
    assert_eq!(next.check(&wire, &env).await.arc.result, "pass");
}

/// Review finding 6: a crash after the rewritten body was stored but before
/// the envelope said so classifies the arrival bytes again, not our output.
#[tokio::test]
async fn urls_crash_between_body_and_envelope_reclassifies_the_original() {
    let mut gw = gateway(|auth| {
        seed_txt(auth.cache(), "example.test", "v=spf1 +all").unwrap();
    })
    .await;
    let env = envelope("01ARZ3NDEKTSV4RRFFQ69G5FAV", Direction::Inbound);
    // What the crash left: our rewritten body in place, the original saved.
    let saved = gw.root.join("spool").join("rewrite");
    std::fs::create_dir_all(&saved).unwrap();
    std::fs::write(saved.join(format!("{}.eml", env.id)), MESSAGE).unwrap();
    let ours = String::from_utf8_lossy(MESSAGE).replace(
        "https://pay.example.net/invoice/29",
        &format!("{BASE}/u/stale"),
    );
    let (env, body) = gw.classify(&env, ours.as_bytes()).await;
    assert_eq!(env.pipeline, "deliver");
    assert!(!body.contains("/u/stale"), "{body}");
    assert_eq!(body.matches(&format!("{BASE}/u/")).count(), 1, "{body}");
    assert!(env.prepend_headers.concat().contains("ARC-Seal: i=1;"));
    assert!(!saved.join(format!("{}.eml", env.id)).exists());
}

/// Review finding 5: links left as they were raise `url_rewrite.skipped`,
/// which the default pack turns into a header.
#[tokio::test]
async fn urls_skipped_links_are_flagged_for_policy() {
    let mut gw = gateway(|auth| {
        seed_txt(auth.cache(), "example.test", "v=spf1 +all").unwrap();
    })
    .await;
    let signed = "From: user@example.test\r\nTo: dest@example.test\r\nSubject: s\r\nMIME-Version: 1.0\r\nContent-Type: multipart/signed; protocol=\"application/pkcs7-signature\"; boundary=s\r\n\r\n--s\r\nContent-Type: text/plain\r\n\r\nhttps://pay.example.net/signed\r\n--s\r\nContent-Type: application/pkcs7-signature\r\nContent-Transfer-Encoding: base64\r\n\r\nAAAA\r\n--s--\r\n";
    let env = envelope("01ARZ3NDEKTSV4RRFFQ69G5FAV", Direction::Inbound);
    let (env, body) = gw.classify(&env, signed.as_bytes()).await;
    assert_eq!(env.pipeline, "deliver");
    assert!(body.contains("https://pay.example.net/signed"));
    assert!(
        env.prepend_headers
            .iter()
            .any(|h| h.starts_with("X-Currawong-Links: not-rewritten")),
        "{:?}",
        env.prepend_headers
    );
}
