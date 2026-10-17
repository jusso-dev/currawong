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
        tls: Default::default(),
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

#[tokio::test]
async fn one_unreadable_message_does_not_block_the_rest() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::default();
    cfg.spool.dir = dir.path().join("spool");
    cfg.scanner.clamd.address.clear();
    let spool = Arc::new(Spool::open(&cfg.spool.dir).await.unwrap());
    // Eight unreadable and eight good messages, interleaved by id. Stopping
    // at the first failure could only classify every good one if the spool
    // happened to list all eight before all the bad ones (1 order in 12,870),
    // so the result does not rest on directory order.
    let mut good = Vec::new();
    for n in 0..16 {
        let mut env = envelope("user@example.test");
        env.id = currawong_core::MessageId(format!("01ARZ3NDEKTSV4RRFFQ69G5F{n:02}"));
        spool
            .accept(env.clone(), Cursor::new(text_message()))
            .await
            .unwrap();
        if n % 2 == 0 {
            // The body vanishes, so reading it fails for this message.
            let eml = spool
                .root()
                .join("incoming")
                .join(format!("{}.eml", env.id));
            std::fs::remove_file(eml).unwrap();
        } else {
            good.push(env.id);
        }
    }
    let auth = AuthChecker::offline("currawong.example.test").unwrap();
    let mut pipeline = Pipeline::new(Arc::new(cfg), auth);
    let quarantine = QuarantineStore::open(dir.path().join("held")).unwrap();
    classify_pending(&spool, &mut pipeline, &quarantine)
        .await
        .unwrap();
    for id in good {
        assert!(ready_to_deliver(&spool.load(&id).await.unwrap()), "{id}");
    }
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

/// Captures formatted log lines so the test can check what was logged.
#[derive(Clone, Default)]
struct LogBuffer(Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for LogBuffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// The ATO's published sample `123456782`, then checksum-valid values
/// derived at run time by counting its leading digits down. Only the
/// published sample is committed.
fn sample_tfns() -> Vec<String> {
    let mut out = vec!["123456782".to_string()];
    let mut prefix = 12_345_678u32;
    while out.len() < 5 {
        prefix -= 1;
        if let Some(t) = (0..10)
            .map(|d| format!("{prefix}{d}"))
            .find(|t| currawong_dlp::detectors::tfn::validate(t))
        {
            out.push(t);
        }
    }
    out
}

fn tfn_message(tfns: &[String]) -> Vec<u8> {
    let lines: Vec<String> = tfns.iter().map(|t| format!("TFN: {t}")).collect();
    format!(
        "From: payroll@example.test\r\nTo: agent@external.test\r\nSubject: staff\r\nDate: Wed, 14 Oct 2026 01:00:00 +0000\r\n\r\n{}\r\n",
        lines.join("\r\n")
    )
    .into_bytes()
}

#[tokio::test]
async fn five_tfns_outbound_are_held_for_review_and_logs_are_redacted() {
    let logs = LogBuffer::default();
    let writer = logs.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .with_ansi(false)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let mut cfg = Config::default();
    cfg.scanner.clamd.address.clear();
    cfg.scanner.worker_binary = None;
    let auth = AuthChecker::offline("currawong.example.test").unwrap();
    seed_txt(auth.cache(), "example.test", "v=spf1 +all").unwrap();
    let mut pipeline = Pipeline::new(Arc::new(cfg), auth);
    let mut env = envelope("payroll@example.test");
    env.direction = Direction::Outbound;
    env.rcpt_to = vec!["agent@external.test".into()];

    let tfns = sample_tfns();
    let (held, verdict) = pipeline.evaluate(&env, &tfn_message(&tfns), None).await;
    let Verdict::Quarantine { reason } = verdict else {
        panic!("{verdict:?}");
    };
    // The default pack's outbound TFN policy.
    assert_eq!(reason, "dlp-tfn");
    let dlp = held.dlp.as_ref().unwrap();
    assert_eq!(dlp.counts.get(&currawong_core::DlpKind::Tfn), Some(&5));

    // Four is under the default threshold. Inbound is not scanned by default.
    let (_, verdict) = pipeline
        .evaluate(&env, &tfn_message(&tfns[..4]), None)
        .await;
    assert!(matches!(verdict, Verdict::Deliver), "{verdict:?}");
    // Five checksum-valid numbers that are only invoice references.
    let invoices: Vec<String> = tfns.iter().map(|t| format!("Invoice {t}")).collect();
    let raw = format!(
        "From: payroll@example.test\r\nTo: agent@external.test\r\nSubject: invoices\r\nDate: Wed, 14 Oct 2026 01:00:00 +0000\r\n\r\n{}\r\n",
        invoices.join("\r\n")
    );
    let (report, verdict) = pipeline.evaluate(&env, raw.as_bytes(), None).await;
    assert!(report.dlp.as_ref().unwrap().counts.is_empty(), "{report:?}");
    assert!(matches!(verdict, Verdict::Deliver), "{verdict:?}");
    let mut inbound = env.clone();
    inbound.direction = Direction::Inbound;
    let (report, verdict) = pipeline.evaluate(&inbound, &tfn_message(&tfns), None).await;
    assert!(report.dlp.is_none());
    assert!(matches!(verdict, Verdict::Deliver), "{verdict:?}");

    let logged = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    assert!(logged.contains("dlp findings"), "{logged}");
    let event = serde_json::to_string(&held).unwrap();
    for tfn in &tfns {
        for haystack in [&logged, &event, &reason] {
            assert!(!haystack.contains(tfn), "{tfn} leaked: {haystack}");
            assert!(!haystack.contains(&tfn[3..]), "{tfn} leaked: {haystack}");
        }
    }
    assert!(event.contains("123 *** ***"), "{event}");
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
    assert_eq!(
        reputation.score(spoof.remote_ip),
        0.0,
        "a DMARC quarantine says nothing about the connecting host"
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

#[tokio::test]
async fn yara_matches_reach_the_report_and_policy() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::default();
    cfg.spool.dir = dir.path().join("spool");
    cfg.scanner.clamd.address.clear();
    cfg.scanner.yara.rules_dir =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../rules/yara");
    let auth = AuthChecker::offline("currawong.example.test").unwrap();
    let mut pipeline = Pipeline::new(Arc::new(cfg), auth);
    assert!(pipeline.yara.is_some());

    let encoded = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        currawong_scan::eicar(),
    );
    let raw = format!(
        "From: a@example.test\r\nTo: b@example.test\r\nSubject: test\r\nMIME-Version: 1.0\r\nContent-Type: application/octet-stream; name=\"eicar.com\"\r\nContent-Disposition: attachment; filename=\"eicar.com\"\r\nContent-Transfer-Encoding: base64\r\n\r\n{encoded}\r\n"
    );
    let env = envelope("a@example.test");
    let (report, verdict) = pipeline.evaluate(&env, raw.as_bytes(), None).await;
    assert!(
        report
            .yara
            .iter()
            .any(|hit| hit.rule == "Currawong_EICAR_Test_File" && hit.part == "eicar.com"),
        "{report:?}"
    );
    assert!(report.malware);
    assert!(report.engines.iter().any(|f| f.engine == "yara"));
    assert!(matches!(verdict, Verdict::Quarantine { reason } if reason == "malware"));

    // A `bec` match is recorded for policy and does not quarantine by itself.
    let bec = b"From: a@example.test\r\nTo: b@example.test\r\nSubject: invoice\r\n\r\nPlease note our change of bank details. BSB 000-000.\r\n";
    let (report, verdict) = pipeline.evaluate(&env, bec, None).await;
    let hit = report
        .yara
        .iter()
        .find(|hit| hit.rule == "Currawong_Bank_Detail_Change")
        .expect("bec rule matched");
    assert_eq!(hit.tags, vec!["bec".to_string()]);
    assert!(!report.malware && !report.active_content, "{report:?}");
    assert!(matches!(verdict, Verdict::Deliver), "{verdict:?}");
}

#[test]
fn yara_broken_rules_fail_check_config() {
    let dir = tempfile::tempdir().unwrap();
    let rules = dir.path().join("yara");
    std::fs::create_dir(&rules).unwrap();
    std::fs::write(rules.join("broken.yar"), "rule Broken { condition: }").unwrap();
    let path = dir.path().join("cfg.toml");
    std::fs::write(
        &path,
        format!(
            "[spool]\ndir = \"/var/spool/currawong\"\n[scanner.yara]\nrules_dir = \"{}\"\n",
            rules.display()
        ),
    )
    .unwrap();
    let err = check_config(&path).unwrap_err();
    assert!(err.contains("broken.yar"), "{err}");
}

/// See `crates/scan/tests/yara.rs`: built by `cargo test --workspace`.
fn worker_binary() -> std::path::PathBuf {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let target = std::env::var_os("CARGO_TARGET_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| root.join("target"));
    let bin = target.join("debug/currawong-parser-worker");
    assert!(
        bin.is_file(),
        "parser worker missing at {}: run `cargo build -p currawong-parser-worker`",
        bin.display()
    );
    bin
}

#[tokio::test]
async fn yara_matches_through_the_isolated_worker() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::default();
    cfg.spool.dir = dir.path().join("spool");
    cfg.scanner.clamd.address.clear();
    cfg.scanner.worker_binary = Some(worker_binary());
    cfg.scanner.yara.rules_dir =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../rules/yara");
    let auth = AuthChecker::offline("currawong.example.test").unwrap();
    let mut pipeline = Pipeline::new(Arc::new(cfg), auth);
    assert!(pipeline.pool.is_some());

    let encoded = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        currawong_scan::eicar(),
    );
    let raw = format!(
        "From: a@example.test\r\nTo: b@example.test\r\nSubject: test\r\nMIME-Version: 1.0\r\nContent-Type: application/octet-stream; name=\"eicar.com\"\r\nContent-Disposition: attachment; filename=\"eicar.com\"\r\nContent-Transfer-Encoding: base64\r\n\r\n{encoded}\r\n"
    );
    let body = dir.path().join("body.eml");
    std::fs::write(&body, &raw).unwrap();
    let env = envelope("a@example.test");
    let (report, verdict) = pipeline.evaluate(&env, raw.as_bytes(), Some(&body)).await;
    assert!(
        report
            .yara
            .iter()
            .any(|hit| hit.rule == "Currawong_EICAR_Test_File" && hit.part == "eicar.com"),
        "{report:?}"
    );
    assert!(matches!(verdict, Verdict::Quarantine { reason } if reason == "malware"));
}

#[tokio::test]
async fn yara_rules_that_cannot_load_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    let rules = dir.path().join("yara");
    std::fs::create_dir(&rules).unwrap();
    std::fs::write(rules.join("broken.yar"), "rule Broken { condition: }").unwrap();
    let mut cfg = Config::default();
    cfg.spool.dir = dir.path().join("spool");
    cfg.scanner.clamd.address.clear();
    cfg.scanner.yara.rules_dir = rules;
    let auth = AuthChecker::offline("currawong.example.test").unwrap();
    let mut pipeline = Pipeline::new(Arc::new(cfg), auth);
    assert!(pipeline.yara.is_none());
    assert!(pipeline.yara_error.is_some());
    let env = envelope("user@example.test");
    let (report, verdict) = pipeline.evaluate(&env, &text_message(), None).await;
    assert!(report.fail_closed, "{report:?}");
    assert!(
        report
            .notes
            .iter()
            .any(|note| note.contains("rules unavailable")),
        "{report:?}"
    );
    assert!(matches!(verdict, Verdict::Quarantine { .. }), "{verdict:?}");
}

/// An outbound user-scoped policy follows the SMTP AUTH login recorded on the
/// envelope, not the MAIL FROM, and never matches unauthenticated relay.
#[tokio::test]
async fn outbound_user_policy_matches_only_the_logged_in_user() {
    use currawong_policy::{Action, Policy, PolicySet, Scope};
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::default();
    cfg.spool.dir = dir.path().join("spool");
    cfg.scanner.clamd.address.clear();
    cfg.scanner.worker_binary = None;
    cfg.relay.tenants = vec![currawong_core::config::TenantConfig {
        id: "t1".into(),
        domains: vec!["acme.test".into()],
        trusted_cidrs: Vec::new(),
    }];
    let auth = AuthChecker::offline("currawong.example.test").unwrap();
    let mut pipeline = Pipeline::new(Arc::new(cfg), auth);
    pipeline.policies = PolicySet {
        policies: vec![Policy {
            id: "hold-ada".into(),
            tenant_id: Some("t1".into()),
            scope: Scope::User("ada@acme.test".into()),
            priority: 10,
            enabled: true,
            dry_run: false,
            mandatory: false,
            override_floor: Vec::new(),
            conditions: Vec::new(),
            actions: vec![Action::Quarantine("held".into())],
        }],
        ..Default::default()
    };
    let mut hits = Vec::new();
    for login in [Some("ada@acme.test"), Some("bob@acme.test"), None] {
        let mut env = envelope("ada@acme.test");
        env.tenant_id = Some("t1".into());
        env.direction = Direction::Outbound;
        env.rcpt_to = vec!["someone@outside.test".into()];
        env.authenticated_as = login.map(str::to_string);
        let (_, decision) = pipeline.assess(&env, &text_message(), None).await;
        hits.push(
            decision.decisions[0]
                .matched
                .iter()
                .any(|m| m.id == "hold-ada"),
        );
    }
    assert_eq!(
        hits,
        vec![true, false, false],
        "only ada's login matches; bob sending as ada and trusted relay do not"
    );
}
