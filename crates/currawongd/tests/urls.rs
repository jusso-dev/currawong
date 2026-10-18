//! Link rewriting in the real pipeline: the delivered copy carries the
//! rewritten links and an ARC seal over them, and a link blocked after
//! delivery is refused by the click service built from the same config.
use currawong_auth::{generate, seed_txt, AuthChecker, KeyStore, GATEWAY_TENANT};
use currawong_core::{config::Config, Direction, MessageId, TlsRequirement};
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
        tls: TlsRequirement::None,
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

/// A multipart/signed message whose signature part is a well-formed (not
/// verified) CMS structure, so its link is left alone.
fn signed_message() -> String {
    "From: user@example.test\r\nTo: dest@example.test\r\nSubject: s\r\nMIME-Version: 1.0\r\nContent-Type: multipart/signed; protocol=\"application/pkcs7-signature\"; boundary=s\r\n\r\n--s\r\nContent-Type: text/plain\r\n\r\nhttps://pay.example.net/signed\r\n--s\r\nContent-Type: application/pkcs7-signature\r\nContent-Transfer-Encoding: base64\r\n\r\nMIIAIAYJKoZIhvcNAQcCoBMBAgMEBQYHCAkKCwwNDg8QERIT\r\n--s--\r\n".into()
}

/// Links left as they were raise `url_rewrite.skipped`. The default pack
/// tags the mail, warns when DMARC did not pass, and holds it when DMARC
/// failed.
#[tokio::test]
async fn urls_skipped_links_are_flagged_for_policy() {
    let mut gw = gateway(|auth| {
        seed_txt(auth.cache(), "example.test", "v=spf1 +all").unwrap();
    })
    .await;
    let env = envelope("01ARZ3NDEKTSV4RRFFQ69G5FAV", Direction::Inbound);
    let (env, body) = gw.classify(&env, signed_message().as_bytes()).await;
    assert_eq!(env.pipeline, "deliver");
    assert!(body.contains("https://pay.example.net/signed"));
    let headers = env.prepend_headers.concat();
    assert!(
        headers.contains("X-Currawong-Links: not-rewritten"),
        "{headers}"
    );
    // No DMARC record: not a pass, so the visible warning too.
    assert!(
        headers
            .contains("X-Currawong-Warning: links from an unauthenticated sender were not checked"),
        "{headers}"
    );

    // A junk signature exempts nothing.
    let junk = signed_message().replace("MIIAIAYJKoZIhvcNAQcCoBMBAgMEBQYHCAkKCwwNDg8QERIT", "AAAA");
    let env = envelope("01ARZ3NDEKTSV4RRFFQ69G5FAW", Direction::Inbound);
    let (env, body) = gw.classify(&env, junk.as_bytes()).await;
    assert_eq!(env.pipeline, "deliver");
    assert!(!body.contains("pay.example.net"), "{body}");
    assert!(!env.prepend_headers.concat().contains("X-Currawong-Links"));

    // DMARC fails (p=none, so the dmarc-reject policy does not apply).
    let mut gw = gateway(|auth| {
        seed_txt(auth.cache(), "example.test", "v=spf1 -all").unwrap();
        seed_txt(auth.cache(), "_dmarc.example.test", "v=DMARC1; p=none").unwrap();
    })
    .await;
    let env = envelope("01ARZ3NDEKTSV4RRFFQ69G5FAV", Direction::Inbound);
    let (env, _) = gw.classify(&env, signed_message().as_bytes()).await;
    assert_eq!(env.pipeline, "quarantine");
}

/// Round 2 finding 2: nesting deep enough to overflow `mail-parser` is not
/// parsed in the daemon. The message is classified, flagged and kept whole.
#[tokio::test]
async fn urls_deeply_nested_mail_does_not_reach_the_parser() {
    let mut gw = gateway(|auth| {
        seed_txt(auth.cache(), "example.test", "v=spf1 +all").unwrap();
    })
    .await;
    let mut raw = String::from("From: user@example.test\r\nTo: dest@example.test\r\nSubject: deep\r\nMIME-Version: 1.0\r\n");
    for n in 0..2_000 {
        raw.push_str(&format!(
            "Content-Type: multipart/mixed; boundary=b{n}\r\n\r\n--b{n}\r\n"
        ));
    }
    raw.push_str("Content-Type: text/plain\r\n\r\nhttps://pay.example.net/deep\r\n");
    let env = envelope("01ARZ3NDEKTSV4RRFFQ69G5FAV", Direction::Inbound);
    let (report, _, rewritten) = gw
        .pipeline
        .assess_for_delivery(&env, raw.as_bytes(), None)
        .await;
    assert!(rewritten.is_none());
    assert!(
        report.flags.iter().any(|f| f == "url_rewrite.skipped"),
        "{report:?}"
    );
    // Through the scheduler: decided (the nesting also fails other stages
    // closed, so it is held), the bytes untouched, the daemon still running.
    let (env, body) = gw.classify(&env, raw.as_bytes()).await;
    assert_ne!(env.pipeline, "pending");
    assert_eq!(body, raw);
}

/// Round 2 finding 4: a split copy left behind by a crash before it was
/// acted on is finished from the plan, not classified on its own bytes.
#[tokio::test]
async fn urls_a_split_copy_left_by_a_crash_is_finished_from_the_plan() {
    use sha2::{Digest, Sha256};
    let mut gw = gateway(|auth| {
        seed_txt(auth.cache(), "example.test", "v=spf1 +all").unwrap();
    })
    .await;
    gw.pipeline.policies = currawong_policy::PolicySet::from_toml(
        "[[policy]]\nid = \"hold-one\"\nconditions = [{ recipient = \"held@example.test\" }]\nactions = [{ quarantine = \"review\" }]\n",
    )
    .unwrap();
    let id = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
    let mut env = envelope(id, Direction::Inbound);
    env.rcpt_to = vec!["a@example.test".into(), "held@example.test".into()];
    let copy_id =
        hex::encode_upper(Sha256::digest(format!("{id}\nheld@example.test")))[..26].to_string();
    // Writing the copy fails, as a crash would, after the plan is saved.
    let blocker = gw
        .root
        .join("spool")
        .join(SpoolState::Incoming.dir_name())
        .join(format!("{copy_id}.eml.tmp"));
    std::fs::create_dir_all(&blocker).unwrap();
    gw.spool
        .accept(env.clone(), Cursor::new(MESSAGE.to_vec()))
        .await
        .unwrap();
    classify_pending(&gw.spool, &mut gw.pipeline, &gw.quarantine)
        .await
        .unwrap();
    assert_eq!(gw.spool.load(&env.id).await.unwrap().pipeline, "pending");
    // What a crash between making the copy and acting on it leaves.
    std::fs::remove_dir(&blocker).unwrap();
    let mut copy = env.clone();
    copy.id = MessageId(copy_id.clone());
    copy.rcpt_to = vec!["held@example.test".into()];
    copy.pipeline = "split".into();
    gw.spool
        .accept(copy, Cursor::new(b"not the original".to_vec()))
        .await
        .unwrap();
    classify_pending(&gw.spool, &mut gw.pipeline, &gw.quarantine)
        .await
        .unwrap();
    let copy = gw.spool.load(&MessageId(copy_id.clone())).await.unwrap();
    assert_eq!(copy.pipeline, "quarantine");
    assert_eq!(
        gw.quarantine.reason(&copy_id).unwrap(),
        "hold-one (queue review)"
    );
    let original = gw.spool.load(&env.id).await.unwrap();
    assert_eq!(original.pipeline, "deliver");
    assert_eq!(original.rcpt_to, ["a@example.test"]);
    let body = String::from_utf8(gw.spool.read_body(&env.id).await.unwrap()).unwrap();
    assert!(body.contains(&format!("{BASE}/u/")), "{body}");
}

/// A link found in a QR code cannot be rewritten (it is in an image): it is
/// noted, not flagged as skipped, and the text links are still rewritten.
#[tokio::test]
async fn urls_qr_code_links_are_noted_not_rewritten() {
    let gw = gateway(|_| {}).await;
    let env = envelope("01ARZ3NDEKTSV4RRFFQ69G5FAV", Direction::Inbound);
    let mut report = currawong_core::ScanReport::new(env.id.clone());
    report.url_sources.push(currawong_core::FoundUrl {
        url: "https://qr.example.net/login".into(),
        source: currawong_core::UrlSource::Qr,
    });
    let body = gw
        .pipeline
        .rewrite_urls(&env, MESSAGE, &mut report)
        .await
        .expect("text link rewritten");
    assert!(!String::from_utf8(body).unwrap().contains("pay.example.net"));
    assert!(
        report
            .notes
            .iter()
            .any(|n| n == "1 QR code links not rewritten: no click-time check"),
        "{:?}",
        report.notes
    );
    assert!(!report.flags.iter().any(|f| f == "url_rewrite.skipped"));
}
