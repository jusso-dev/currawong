use currawong_auth::{seed_txt, AuthChecker};
use currawong_core::{config::Config, Direction, Verdict};
use currawong_quarantine::QuarantineStore;
use currawong_spool::{Envelope, Spool, SpoolState};
use currawongd::{check_config, classify_pending, pending_scan, ready_to_deliver, Pipeline};
use std::{io::Cursor, sync::Arc};
use time::OffsetDateTime;

fn envelope(from: &str) -> Envelope {
    Envelope {
        id: currawong_core::MessageId("01ARZ3NDEKTSV4RRFFQ69G5FAV".into()),
        tenant_id: None,
        authenticated_as: None,
        mail_from: from.into(),
        rcpt_to: vec!["dest@example.test".into()],
        received_at: OffsetDateTime::now_utc(),
        remote_ip: "203.0.113.8".parse().unwrap(),
        helo: "client.example.test".into(),
        attempts: 0,
        next_attempt_at: None,
        state: SpoolState::Incoming,
        direction: Direction::Inbound,
        tls_version: None,
        tls_cipher: None,
        rcpt_status: Vec::new(),
        prepend_headers: Vec::new(),
        dsn_sent: false,
        pipeline: "pending".into(),
    }
}

fn text_message() -> Vec<u8> {
    b"From: user@example.test\r\nTo: dest@example.test\r\nSubject: hi\r\nDate: Wed, 14 Oct 2026 01:00:00 +0000\r\n\r\nhello\r\n".to_vec()
}

#[tokio::test]
async fn dmarc_reject_is_quarantined_and_clean_mail_stays_deliverable() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::default();
    cfg.spool.dir = dir.path().join("spool");
    cfg.scanner.clamd.address.clear();
    cfg.scanner.worker_binary = None;
    let _spool = Spool::open(&cfg.spool.dir).await.unwrap();
    let auth = AuthChecker::offline("currawong.example.test").unwrap();
    seed_txt(auth.cache(), "attacker.test", "v=spf1 -all").unwrap();
    seed_txt(auth.cache(), "_dmarc.example.test", "v=DMARC1; p=reject").unwrap();
    let mut pipeline = Pipeline::new(Arc::new(cfg), auth);
    let env = envelope("spoof@attacker.test");
    let (_report, verdict) = pipeline.evaluate(&env, &text_message(), None).await;
    assert!(matches!(verdict, Verdict::Quarantine { .. }), "{verdict:?}");

    seed_txt(pipeline.auth.cache(), "example.test", "v=spf1 +all").unwrap();
    let mut clean = envelope("user@example.test");
    clean.id = currawong_core::MessageId("01ARZ3NDEKTSV4RRFFQ69G5FAW".into());
    let (_report, verdict) = pipeline.evaluate(&clean, &text_message(), None).await;
    assert!(matches!(verdict, Verdict::Deliver), "{verdict:?}");
    assert!(pending_scan(&env));
    assert!(!ready_to_deliver(&env));
}

#[tokio::test]
async fn renamed_executable_is_quarantined_without_clamav() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::default();
    cfg.spool.dir = dir.path().join("spool");
    cfg.scanner.clamd.address.clear();
    let auth = AuthChecker::offline("currawong.example.test").unwrap();
    let mut pipeline = Pipeline::new(Arc::new(cfg), auth);
    let mut pe = vec![0u8; 0x80];
    pe[0] = b'M';
    pe[1] = b'Z';
    pe[0x3c] = 0x40;
    pe[0x40] = b'P';
    pe[0x41] = b'E';
    let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &pe);
    let raw = format!(
        "From: a@example.test\r\nTo: b@example.test\r\nSubject: invoice\r\nMIME-Version: 1.0\r\nContent-Type: application/pdf; name=\"invoice.pdf\"\r\nContent-Disposition: attachment; filename=\"invoice.pdf\"\r\nContent-Transfer-Encoding: base64\r\n\r\n{encoded}\r\n"
    );
    let env = envelope("a@example.test");
    let (report, verdict) = pipeline.evaluate(&env, raw.as_bytes(), None).await;
    assert!(report.active_content, "{report:?}");
    assert!(matches!(verdict, Verdict::Quarantine { .. }), "{verdict:?}");
    let _ = Cursor::new(pe);
}

#[tokio::test]
async fn pending_mail_is_not_marked_deliver_before_the_pipeline() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::default();
    cfg.spool.dir = dir.path().join("spool");
    cfg.scanner.clamd.address.clear();
    let spool = Arc::new(Spool::open(&cfg.spool.dir).await.unwrap());
    let env = envelope("user@example.test");
    spool
        .accept(env, Cursor::new(text_message()))
        .await
        .unwrap();
    let listed = spool.list(SpoolState::Incoming).await.unwrap();
    assert!(listed.iter().all(pending_scan));
    assert!(listed.iter().all(|env| !ready_to_deliver(env)));
    let auth = AuthChecker::offline("currawong.example.test").unwrap();
    let mut pipeline = Pipeline::new(Arc::new(cfg), auth);
    let quarantine = QuarantineStore::open(dir.path().join("held")).unwrap();
    classify_pending(&spool, &mut pipeline, &quarantine)
        .await
        .unwrap();
    let listed = spool.list(SpoolState::Incoming).await.unwrap();
    assert!(listed.iter().all(ready_to_deliver), "{listed:?}");
}

#[test]
fn example_config_checks_and_foreign_bucket_fails() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../config/currawong.example.toml");
    check_config(&root).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bad.toml");
    std::fs::write(
        &path,
        r#"
[spool]
dir = "/var/spool/currawong"
[[listeners]]
name = "in"
bind = "127.0.0.1:2525"
mode = "plain"
role = "inbound"
[residency]
content_endpoints = ["https://mail.s3.us-east-1.amazonaws.com/box"]
"#,
    )
    .unwrap();
    let err = check_config(&path).unwrap_err();
    assert!(
        err.contains("Australia") || err.contains("us-east-1") || err.contains("not an allowed"),
        "{err}"
    );
}

#[tokio::test]
async fn verdicts_feed_reputation_and_dmarc_pass_skips_greylisting() {
    use currawong_smtp::{
        checks::{CheckStack, GreylistDecision},
        dns::MapDns,
    };
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::default();
    cfg.spool.dir = dir.path().join("spool");
    cfg.scanner.clamd.address.clear();
    cfg.scanner.worker_binary = None;
    cfg.checks.dnsbl_enabled = false;
    cfg.checks.ratelimit_enabled = false;
    cfg.checks.greylist_enabled = true;
    cfg.checks.reputation_enabled = true;
    cfg.checks.greylist_database = dir.path().join("grey.sqlite");
    let checks = Arc::new(CheckStack::from_checks(&cfg.checks, Arc::new(MapDns::new())).unwrap());
    let auth = AuthChecker::offline("currawong.example.test").unwrap();
    seed_txt(auth.cache(), "attacker.test", "v=spf1 -all").unwrap();
    seed_txt(auth.cache(), "_dmarc.example.test", "v=DMARC1; p=reject").unwrap();
    seed_txt(auth.cache(), "example.test", "v=spf1 +all").unwrap();
    let mut pipeline = Pipeline::new(Arc::new(cfg), auth).with_checks(Arc::clone(&checks));

    let spoof = envelope("spoof@attacker.test");
    let (_, verdict) = pipeline.evaluate(&spoof, &text_message(), None).await;
    assert!(matches!(verdict, Verdict::Quarantine { .. }), "{verdict:?}");
    let reputation = checks.reputation.as_ref().unwrap();
    assert!(
        reputation.score(spoof.remote_ip) > 0.0,
        "a blocked verdict must raise the score"
    );

    let mut clean = envelope("user@example.test");
    clean.remote_ip = "198.51.100.30".parse().unwrap();
    let (report, verdict) = pipeline.evaluate(&clean, &text_message(), None).await;
    assert!(matches!(verdict, Verdict::Deliver), "{verdict:?}");
    assert_eq!(report.auth.unwrap().dmarc.result, "pass");
    let greylist = checks.greylist.as_ref().unwrap();
    assert_eq!(
        greylist
            .decide(
                "198.51.100.31".parse().unwrap(),
                "other@example.test",
                "x@example.test"
            )
            .unwrap(),
        GreylistDecision::Pass,
        "aligned DMARC pass lets the domain skip greylisting from that network"
    );
    assert_eq!(
        greylist
            .decide(
                "203.0.113.200".parse().unwrap(),
                "other@example.test",
                "x@example.test"
            )
            .unwrap(),
        GreylistDecision::Delay
    );
}
