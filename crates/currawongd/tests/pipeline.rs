use currawong_auth::{seed_txt, AuthChecker};
use currawong_classify::{spam::Feedback, TenantContext};
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
async fn classify_puts_spam_and_lookalike_scores_on_the_report() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::default();
    cfg.spool.dir = dir.path().join("spool");
    cfg.scanner.clamd.address.clear();
    cfg.classify.bayes_database = dir.path().join("bayes.sqlite");
    let auth = AuthChecker::offline("currawong.example.test").unwrap();
    let mut pipeline = Pipeline::new(Arc::new(cfg), auth);
    let raw = b"From: Refunds <refunds@c0mmbank.com.au>\r\nReply-To: pay@examp1e.test\r\nTo: dest@example.test\r\nSubject: WINNER\r\nDate: Wed, 14 Oct 2026 01:00:00 +0000\r\n\r\nAct now at https://rnygov.au/claim\r\n";
    let env = envelope("bounce@c0mmbank.com.au");
    let (report, _verdict) = pipeline.evaluate(&env, raw, None).await;
    let spam = report.spam.as_ref().expect("spam report");
    let rules: Vec<&str> = spam.rules_hit.iter().map(|hit| hit.name.as_str()).collect();
    assert!(rules.contains(&"subject_shouting"), "{rules:?}");
    assert!(rules.contains(&"body_urgency"), "{rules:?}");
    assert!(spam.total > 0.0);
    let found: Vec<(&str, &str)> = report
        .lookalikes
        .iter()
        .map(|f| (f.source.as_str(), f.target.as_str()))
        .collect();
    for expected in [
        ("from", "commbank.com.au"),
        ("reply-to", "example.test"),
        ("envelope", "commbank.com.au"),
        ("url", "mygov.au"),
    ] {
        assert!(found.contains(&expected), "{expected:?} in {found:?}");
    }

    let (clean, _verdict) = pipeline
        .evaluate(&envelope("user@example.test"), &text_message(), None)
        .await;
    assert!(clean.lookalikes.is_empty(), "{:?}", clean.lookalikes);
    assert!(clean.spam.unwrap().rules_hit.is_empty());
}

#[tokio::test]
async fn classify_uses_the_recipient_tenant_for_bayes_and_protected_domains() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::default();
    cfg.spool.dir = dir.path().join("spool");
    cfg.scanner.clamd.address.clear();
    cfg.classify.bayes_database = dir.path().join("bayes.sqlite");
    cfg.domains.accept = vec![
        "alphafreight.com.au".into(),
        "bravodental.com.au".into(),
        "default.test".into(),
    ];
    for (id, domain) in [
        ("alpha", "alphafreight.com.au"),
        ("bravo", "bravodental.com.au"),
    ] {
        cfg.relay
            .tenants
            .push(currawong_core::config::TenantConfig {
                id: id.into(),
                domains: vec![domain.into()],
                trusted_cidrs: Vec::new(),
            });
    }
    let auth = AuthChecker::offline("currawong.example.test").unwrap();
    let mut pipeline = Pipeline::new(Arc::new(cfg), auth);
    let classifier = pipeline.classifier.clone().expect("classifier");
    let bravo = TenantContext::tenant("bravo", &["bravodental.com.au".to_string()]);
    let spam = b"From: promo@casino.example\r\nSubject: casino bonus jackpot\r\n\r\ncasino bonus jackpot cash\r\n";
    let ham = b"From: staff@bravodental.com.au\r\nSubject: roster\r\n\r\nroster for the clinic\r\n";
    for i in 0..5 {
        classifier
            .learn(&bravo, &format!("s{i}"), spam, Feedback::ReportedSpam)
            .unwrap();
        classifier
            .learn(&bravo, &format!("h{i}"), ham, Feedback::Released)
            .unwrap();
    }
    let raw = b"From: accounts@a1phafreight.com.au\r\nSubject: casino bonus jackpot\r\n\r\ncasino bonus jackpot cash\r\n";
    let to = |rcpt: &str| {
        let mut env = envelope("bounce@casino.example");
        env.rcpt_to = vec![rcpt.into()];
        env
    };
    let (for_bravo, _) = pipeline
        .evaluate(&to("dr@bravodental.com.au"), raw, None)
        .await;
    assert!(
        for_bravo.spam.as_ref().unwrap().bayes > 0.9,
        "{for_bravo:?}"
    );
    // Alpha's domain is not named in Bravo's report.
    assert!(
        for_bravo.lookalikes.is_empty(),
        "{:?}",
        for_bravo.lookalikes
    );

    let (for_alpha, _) = pipeline
        .evaluate(&to("ap@alphafreight.com.au"), raw, None)
        .await;
    assert_eq!(for_alpha.spam.as_ref().unwrap().bayes, 0.5);
    let targets: Vec<&str> = for_alpha
        .lookalikes
        .iter()
        .map(|f| f.target.as_str())
        .collect();
    assert_eq!(targets, vec!["alphafreight.com.au"]);

    // An accepted domain without a tenant gets its own store, separate from
    // a tenant that is literally called "default".
    let named_default = TenantContext::tenant("default", &[]);
    for i in 0..5 {
        classifier
            .learn(
                &named_default,
                &format!("s{i}"),
                spam,
                Feedback::ReportedSpam,
            )
            .unwrap();
        classifier
            .learn(&named_default, &format!("h{i}"), ham, Feedback::Released)
            .unwrap();
    }
    let (unclaimed, _) = pipeline.evaluate(&to("x@default.test"), raw, None).await;
    assert_eq!(unclaimed.spam.as_ref().unwrap().bayes, 0.5);
}

fn classify_pipeline(dir: &std::path::Path, scanner: bool) -> Pipeline {
    let mut cfg = Config::default();
    cfg.spool.dir = dir.join("spool");
    cfg.scanner.enabled = scanner;
    cfg.scanner.clamd.address.clear();
    cfg.scanner.worker_binary = None;
    cfg.classify.bayes_database = dir.join("bayes.sqlite");
    let auth = AuthChecker::offline("currawong.example.test").unwrap();
    Pipeline::new(Arc::new(cfg), auth)
}

#[tokio::test]
async fn default_pack_quarantines_and_tags_on_the_spam_score() {
    let dir = tempfile::tempdir().unwrap();
    let mut pipeline = classify_pipeline(dir.path(), true);
    // Rules: shouting 1.5, prize 1.5, bulk mailer 1, urgency 1, crypto 2,
    // IP literal 2, shortener 1 = 10, over the pack's quarantine line of 8.
    let spam = b"From: promo@promo.example\r\nTo: dest@example.test\r\nSubject: WINNER WINNER\r\nX-Mailer: BulkMail Pro\r\n\r\nAct now: Bitcoin with guaranteed returns at http://192.0.2.10/claim or https://bit.ly/x\r\n";
    let (report, decision) = pipeline
        .assess(&envelope("promo@promo.example"), spam, None)
        .await;
    assert!(report.spam.as_ref().unwrap().total >= 8.0, "{report:?}");
    assert_eq!(decision.decisions[0].queue(), Some("spam"), "{decision:?}");
    assert!(matches!(decision.verdict(), Verdict::Quarantine { .. }));

    // Shouting, prize and crypto = 5: delivered with the [SPAM] header.
    let tagged = b"From: promo@promo.example\r\nTo: dest@example.test\r\nSubject: WINNER WINNER\r\n\r\nBitcoin with guaranteed returns\r\n";
    let (report, decision) = pipeline
        .assess(&envelope("promo@promo.example"), tagged, None)
        .await;
    let total = report.spam.as_ref().unwrap().total;
    assert!((5.0..8.0).contains(&total), "{total}");
    assert!(
        matches!(decision.verdict(), Verdict::Deliver),
        "{decision:?}"
    );
    assert!(decision.decisions[0].actions.iter().any(|action| matches!(
        action,
        currawong_policy::Action::AddHeader { name, value }
            if name == "X-Currawong-Spam" && value == "[SPAM]"
    )));
}

#[tokio::test]
async fn lookalike_and_classify_flags_reach_policy_signals() {
    let dir = tempfile::tempdir().unwrap();
    let mut pipeline = classify_pipeline(dir.path(), true);
    let raw = b"From: Refunds <refunds@c0mmbank.com.au>\r\nTo: dest@example.test\r\nSubject: refund\r\n\r\nhello\r\n";
    let (report, _) = pipeline
        .evaluate(&envelope("bounce@c0mmbank.com.au"), raw, None)
        .await;
    let signals = currawong_policy::Signals::from_report(&report);
    assert!(signals.flags.contains("lookalike"), "{signals:?}");
    assert_eq!(signals.scores.get("lookalike"), Some(&0.95));
    assert!(signals.scores.contains_key("spam"));

    let mut body = String::new();
    for i in 0..600 {
        body.push_str(&format!("https://site{i}.example.test/\r\n"));
    }
    let raw =
        format!("From: a@example.test\r\nTo: dest@example.test\r\nSubject: links\r\n\r\n{body}");
    let (report, _) = pipeline
        .evaluate(&envelope("a@example.test"), raw.as_bytes(), None)
        .await;
    let signals = currawong_policy::Signals::from_report(&report);
    assert!(signals.flags.contains("link_scan_truncated"), "{signals:?}");
}

#[tokio::test]
async fn deeply_nested_message_is_held_without_crashing_the_classifier() {
    let dir = tempfile::tempdir().unwrap();
    // The scanner is off so only the classifier parses the message here.
    let mut pipeline = classify_pipeline(dir.path(), false);
    let mut raw = b"From: a@example.test\r\nTo: dest@example.test\r\nSubject: nest\r\n".to_vec();
    for _ in 0..50_000 {
        raw.extend_from_slice(b"Content-Type: message/rfc822\r\n\r\n");
    }
    raw.extend_from_slice(b"Subject: inner\r\n\r\nhello\r\n");
    let (report, verdict) = pipeline
        .evaluate(&envelope("a@example.test"), &raw, None)
        .await;
    assert!(report.fail_closed, "{:?}", report.notes);
    assert!(report.flags.contains(&"classify_skipped".to_string()));
    assert!(report.spam.is_none());
    assert!(matches!(verdict, Verdict::Quarantine { .. }), "{verdict:?}");
}

#[test]
fn check_config_opens_the_bayes_store_when_its_directory_exists() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = currawong_core::config::ClassifyConfig {
        bayes_database: dir.path().join("bayes.sqlite"),
        ..Default::default()
    };
    currawong_classify::check_config(&cfg).unwrap();
    assert!(cfg.bayes_database.exists());
    // A path that is not a database fails the check.
    std::fs::write(dir.path().join("junk.sqlite"), vec![0xffu8; 4096]).unwrap();
    cfg.bayes_database = dir.path().join("junk.sqlite");
    assert!(currawong_classify::check_config(&cfg).is_err());
    // A missing directory is left to the daemon, which scores rules only.
    cfg.bayes_database = dir.path().join("missing/bayes.sqlite");
    currawong_classify::check_config(&cfg).unwrap();
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
