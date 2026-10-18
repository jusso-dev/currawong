use currawong_auth::{seed_txt, AuthChecker};
use currawong_classify::{spam::Feedback, TenantContext};
use currawong_core::{config::Config, Direction, Verdict};
use currawong_quarantine::{ListQuery, Principal, QuarantineStore, Role};
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

/// `cargo test --workspace` builds the worker binary next to the tests.
fn worker_bin() -> std::path::PathBuf {
    let exe = std::env::current_exe().unwrap();
    let candidate = exe
        .parent()
        .and_then(|deps| deps.parent())
        .map(|dir| dir.join("currawong-parser-worker"))
        .unwrap();
    assert!(
        candidate.is_file(),
        "parser worker binary: run cargo build -p currawong-parser-worker"
    );
    candidate
}

/// A scanning config without ClamAV.
fn scan_config(dir: &tempfile::TempDir) -> Config {
    let mut cfg = Config::default();
    cfg.spool.dir = dir.path().join("spool");
    cfg.scanner.clamd.address.clear();
    cfg.scanner.clamd.required = false;
    cfg.scanner.worker_binary = Some(worker_bin());
    cfg
}

fn with_attachment(name: &str, content_type: &str, bytes: &[u8]) -> Vec<u8> {
    let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, bytes);
    format!(
        "From: a@example.test\r\nTo: b@example.test\r\nSubject: t\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"b\"\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nsee attached\r\n--b\r\nContent-Type: {content_type}; name=\"{name}\"\r\nContent-Disposition: attachment; filename=\"{name}\"\r\nContent-Transfer-Encoding: base64\r\n\r\n{encoded}\r\n--b--\r\n"
    )
    .into_bytes()
}

fn text_message() -> Vec<u8> {
    b"From: user@example.test\r\nTo: dest@example.test\r\nSubject: hi\r\nDate: Wed, 14 Oct 2026 01:00:00 +0000\r\n\r\nhello\r\n".to_vec()
}

#[tokio::test]
async fn dmarc_reject_is_quarantined_and_clean_mail_stays_deliverable() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = scan_config(&dir);
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
    let cfg = scan_config(&dir);
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
    let cfg = scan_config(&dir);
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
[scanner.clamd]
required = false
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

async fn verdict_for(cfg: Config, raw: &[u8]) -> (currawong_core::ScanReport, Verdict) {
    let auth = AuthChecker::offline("currawong.example.test").unwrap();
    let mut pipeline = Pipeline::new(Arc::new(cfg), auth);
    pipeline
        .evaluate(&envelope("a@example.test"), raw, None)
        .await
}

/// No in-daemon fallback: without a worker the message is not parsed. That
/// is an infrastructure fault, so it is deferred rather than judged.
#[tokio::test]
async fn missing_worker_defers() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = scan_config(&dir);
    cfg.scanner.worker_binary = Some(dir.path().join("no-such-worker"));
    let (report, verdict) = verdict_for(cfg, &text_message()).await;
    assert!(report.defer && !report.fail_closed, "{report:?}");
    assert!(matches!(verdict, Verdict::Defer { .. }), "{verdict:?}");
}

/// A message the scanner keeps deferring is quarantined after the cap.
#[tokio::test]
async fn repeated_scan_deferrals_end_in_quarantine() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = scan_config(&dir);
    cfg.scanner.worker_binary = Some(dir.path().join("no-such-worker"));
    cfg.scanner.max_scan_deferrals = 2;
    let spool = Spool::open(&cfg.spool.dir).await.unwrap();
    let mut env = envelope("a@example.test");
    env.attempts = 2;
    spool
        .accept(env.clone(), Cursor::new(text_message()))
        .await
        .unwrap();
    let auth = AuthChecker::offline("currawong.example.test").unwrap();
    let mut pipeline = Pipeline::new(Arc::new(cfg), auth);
    let held = QuarantineStore::open(dir.path().join("held")).unwrap();
    classify_pending(&spool, &mut pipeline, &held)
        .await
        .unwrap();
    let env = spool.load(&env.id).await.unwrap();
    assert_eq!(env.pipeline, "quarantine", "{env:?}");
    let admin = Principal {
        actor: "root".into(),
        role: Role::PlatformAdmin,
        tenant_id: None,
    };
    let items = held.list(&admin, &ListQuery::default()).unwrap().items;
    assert_eq!(items.len(), 1, "{items:?}");
    assert_eq!(items[0].queue, "scan-failed");
}

/// Windows ignores trailing dots and spaces; the block list must too.
#[tokio::test]
async fn blocked_extension_with_trailing_dot_is_caught() {
    let dir = tempfile::tempdir().unwrap();
    let raw = with_attachment("run.js.", "text/plain", b"plain text");
    let (report, verdict) = verdict_for(scan_config(&dir), &raw).await;
    assert!(matches!(verdict, Verdict::Quarantine { .. }), "{verdict:?}");
    assert!(report.notes.iter().any(|n| n.contains("executable")));
}

/// Control characters in attacker-chosen names do not reach notes or logs.
#[tokio::test]
async fn attachment_names_are_sanitised_in_notes() {
    let dir = tempfile::tempdir().unwrap();
    let raw = with_attachment("a\u{1b}[31mb.exe", "application/octet-stream", b"x");
    let (report, _) = verdict_for(scan_config(&dir), &raw).await;
    assert!(
        report
            .notes
            .iter()
            .all(|n| !n.chars().any(char::is_control)),
        "{:?}",
        report.notes
    );
}

#[tokio::test]
async fn worker_readiness_runs_a_real_job() {
    use currawong_core::telemetry::ReadinessCheck;
    let dir = tempfile::tempdir().unwrap();
    let cfg = scan_config(&dir);
    let ready = currawongd::WorkerReady { cfg: cfg.clone() };
    ready.check().await.unwrap();
    let mut broken = cfg;
    broken.scanner.worker_binary = Some(dir.path().join("no-such-worker"));
    assert!(currawongd::WorkerReady { cfg: broken }
        .check()
        .await
        .is_err());
}

/// Scratch from an earlier run is removed when the pipeline starts.
#[tokio::test]
async fn leftover_scan_directories_are_swept() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = scan_config(&dir);
    let stale = cfg.spool.dir.join("parts").join("scan-old");
    std::fs::create_dir_all(stale.join("parts")).unwrap();
    std::fs::write(stale.join("parts/0000.part"), b"old mail").unwrap();
    let auth = AuthChecker::offline("currawong.example.test").unwrap();
    let _pipeline = Pipeline::new(Arc::new(cfg), auth);
    assert!(!stale.exists());
}

/// The default build requires clamd. With no address it defers and fails
/// readiness instead of delivering unscanned mail.
#[tokio::test]
async fn required_clamd_without_an_address_defers_and_is_not_ready() {
    use currawong_core::telemetry::ReadinessCheck;
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = scan_config(&dir);
    cfg.scanner.clamd.required = true;
    let (_report, verdict) = verdict_for(cfg, &text_message()).await;
    assert!(matches!(verdict, Verdict::Defer { .. }), "{verdict:?}");
    let ready = currawongd::ClamdReady {
        address: String::new(),
        required: true,
    };
    assert!(ready.check().await.is_err());
}

#[tokio::test]
async fn inspection_flags_quarantine() {
    let dir = tempfile::tempdir().unwrap();
    let mut zip = std::io::Cursor::new(Vec::new());
    {
        use std::io::Write;
        let mut writer = zip::ZipWriter::new(&mut zip);
        writer
            .start_file("a.txt", zip::write::SimpleFileOptions::default())
            .unwrap();
        writer.write_all(b"hello").unwrap();
        writer.finish().unwrap();
    }
    let zip = zip.into_inner();
    let cases: Vec<(&str, Vec<u8>)> = vec![
        (
            "embedded OLE object",
            with_attachment(
                "note.rtf",
                "application/rtf",
                b"{\\rtf1{\\object\\objemb{\\*\\objdata 01}}}",
            ),
        ),
        (
            "type does not match name",
            with_attachment("statement.pdf", "application/pdf", &zip),
        ),
        (
            "could not inspect",
            with_attachment("a.rar", "application/vnd.rar", b"Rar!\x1a\x07\x01\x00rest"),
        ),
    ];
    for (note, raw) in cases {
        let (report, verdict) = verdict_for(scan_config(&dir), &raw).await;
        assert!(
            matches!(verdict, Verdict::Quarantine { .. }),
            "{note}: {verdict:?} {report:?}"
        );
        assert!(
            report.notes.iter().any(|n| n.contains(note)),
            "{note}: {:?}",
            report.notes
        );
    }
}

#[tokio::test]
async fn encrypted_archive_is_quarantined() {
    let dir = tempfile::tempdir().unwrap();
    let mut writer = sevenz_rust2::ArchiveWriter::new(Cursor::new(Vec::new())).unwrap();
    writer.set_content_methods(vec![
        sevenz_rust2::encoder_options::AesEncoderOptions::new("not-in-the-body".into()).into(),
        sevenz_rust2::EncoderMethod::LZMA2.into(),
    ]);
    writer
        .push_archive_entry(
            sevenz_rust2::ArchiveEntry::new_file("report.txt"),
            Some(&b"quarterly"[..]),
        )
        .unwrap();
    let archive = writer.finish().unwrap().into_inner();
    let raw = with_attachment("report.7z", "application/x-7z-compressed", &archive);
    let (report, verdict) = verdict_for(scan_config(&dir), &raw).await;
    assert!(matches!(verdict, Verdict::Quarantine { .. }), "{verdict:?}");
    assert!(report.notes.iter().any(|n| n.contains("encrypted archive")));
}

#[tokio::test]
async fn blocked_extensions_come_from_config() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = scan_config(&dir);
    cfg.scanner.blocked_extensions = vec!["xyz".into()];
    let raw = with_attachment("notes.xyz", "text/plain", b"plain text");
    let (_report, verdict) = verdict_for(cfg.clone(), &raw).await;
    assert!(matches!(verdict, Verdict::Quarantine { .. }), "{verdict:?}");
    // js is on the default list but not on this one.
    let raw = with_attachment("run.js", "text/plain", b"plain text");
    let (_report, verdict) = verdict_for(cfg, &raw).await;
    assert!(matches!(verdict, Verdict::Deliver), "{verdict:?}");
}

/// Issue #23: killing a worker mid-job does not take the daemon down, the
/// message is quarantined, and the next message gets a fresh worker.
#[tokio::test]
async fn worker_killed_mid_job_quarantines_and_recovers() {
    use std::io::Write;
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = scan_config(&dir);
    cfg.scanner.job_timeout_secs = 60;
    cfg.scanner.worker_pool_size = 1;
    cfg.scanner.extract.max_uncompressed_bytes = 2 * 1024 * 1024 * 1024;
    cfg.scanner.extract.max_ratio = u32::MAX;
    let auth = AuthChecker::offline("currawong.example.test").unwrap();
    let mut pipeline = Pipeline::new(Arc::new(cfg), auth);
    let env = envelope("a@example.test");
    let (_report, verdict) = pipeline.evaluate(&env, &text_message(), None).await;
    assert!(matches!(verdict, Verdict::Deliver), "{verdict:?}");
    let pid = pipeline.pool.as_ref().unwrap().worker_pids()[0];

    // About 1 GiB of zeros: far more work than the 300 ms before the kill.
    let member = {
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
        enc.write_all(&vec![0u8; 1024 * 1024]).unwrap();
        enc.finish().unwrap()
    };
    let bomb: Vec<u8> = std::iter::repeat_n(member, 1024).flatten().collect();
    let raw = with_attachment("zeros.gz", "application/gzip", &bomb);
    let killer = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(300));
        std::process::Command::new("kill")
            .args(["-9", &pid.to_string()])
            .status()
            .unwrap()
    });
    let (report, verdict) = pipeline.evaluate(&env, &raw, None).await;
    assert!(killer.join().unwrap().success());
    assert!(matches!(verdict, Verdict::Quarantine { .. }), "{verdict:?}");
    assert!(
        report
            .notes
            .iter()
            .any(|n| n.contains("parser worker failed")),
        "{:?}",
        report.notes
    );
    let (_report, verdict) = pipeline.evaluate(&env, &text_message(), None).await;
    assert!(matches!(verdict, Verdict::Deliver), "{verdict:?}");
}

#[tokio::test]
async fn yara_matches_reach_the_report_and_policy() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::default();
    cfg.spool.dir = dir.path().join("spool");
    cfg.scanner.clamd.address.clear();
    cfg.scanner.clamd.required = false;
    cfg.scanner.worker_binary = Some(worker_binary());
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

    // A `bec` YARA match is recorded for policy and is not malware. The BEC
    // classifier (not the YARA tag) holds this bank-detail change.
    let bec = b"From: a@example.test\r\nTo: b@example.test\r\nSubject: invoice\r\n\r\nPlease note our change of bank details. BSB 000-000.\r\n";
    let (report, verdict) = pipeline.evaluate(&env, bec, None).await;
    let hit = report
        .yara
        .iter()
        .find(|hit| hit.rule == "Currawong_Bank_Detail_Change")
        .expect("bec rule matched");
    assert_eq!(hit.tags, vec!["bec".to_string()]);
    assert!(!report.malware && !report.active_content, "{report:?}");
    assert!(
        matches!(&verdict, Verdict::Quarantine { reason } if reason == "bec-quarantine"),
        "{verdict:?}"
    );
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
            "[spool]\ndir = \"/var/spool/currawong\"\n[scanner.clamd]\nrequired = false\n[scanner.yara]\nrules_dir = \"{}\"\n",
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
    cfg.scanner.clamd.required = false;
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
    cfg.scanner.clamd.required = false;
    cfg.scanner.worker_binary = Some(worker_binary());
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

#[tokio::test]
async fn classify_puts_spam_and_lookalike_scores_on_the_report() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::default();
    cfg.spool.dir = dir.path().join("spool");
    cfg.scanner.clamd.address.clear();
    cfg.scanner.clamd.required = false;
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
    cfg.scanner.clamd.required = false;
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
    cfg.scanner.clamd.required = false;
    cfg.scanner.worker_binary = Some(worker_binary());
    cfg.classify.bayes_database = dir.join("bayes.sqlite");
    let auth = AuthChecker::offline("currawong.example.test").unwrap();
    Pipeline::new(Arc::new(cfg), auth)
}

#[tokio::test]
async fn default_pack_quarantines_and_tags_on_the_spam_score() {
    let dir = tempfile::tempdir().unwrap();
    let pipeline = classify_pipeline(dir.path(), true);
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

fn attachment(name: &str, content_type: &str, bytes: &[u8]) -> String {
    let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, bytes);
    let lines: Vec<&str> = encoded
        .as_bytes()
        .chunks(76)
        .map(|line| std::str::from_utf8(line).unwrap())
        .collect();
    format!(
        "--b\r\nContent-Type: {content_type}; name=\"{name}\"\r\nContent-Disposition: attachment; filename=\"{name}\"\r\nContent-Transfer-Encoding: base64\r\n\r\n{}\r\n",
        lines.join("\r\n")
    )
}

#[tokio::test]
async fn qr_urls_feed_link_analysis_and_smuggling_reaches_policy() {
    let dir = tempfile::tempdir().unwrap();
    let pipeline = classify_pipeline(dir.path(), true);
    let code = qrcode::QrCode::new(b"https://c0mmbank.com.au/login").unwrap();
    let mut png = Cursor::new(Vec::new());
    code.render::<image::Luma<u8>>()
        .min_dimensions(240, 240)
        .build()
        .write_to(&mut png, image::ImageFormat::Png)
        .unwrap();
    let blob = "QUJD".repeat(16 * 1024);
    let html = format!(
        "<script>var b = new Blob([atob(\"{blob}\")]); var a = document.createElement('a'); a.href = URL.createObjectURL(b); a.download = 'x.iso';</script>"
    );
    let png = png.into_inner();
    let message = |attachments: &[String]| {
        format!(
            "From: a@example.test\r\nTo: dest@example.test\r\nSubject: verify\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"b\"\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nScan the code.\r\n{}--b--\r\n",
            attachments.concat()
        )
    };

    // A QR code alone is delivered, tagged by the default pack.
    let raw = message(&[attachment("code.png", "image/png", &png)]);
    let (report, decision) = pipeline
        .assess(&envelope("a@example.test"), raw.as_bytes(), None)
        .await;
    assert!(
        report.url_sources.contains(&currawong_core::FoundUrl {
            url: "https://c0mmbank.com.au/login".into(),
            source: currawong_core::UrlSource::Qr,
        }),
        "{:?}",
        report.url_sources
    );
    let signals = currawong_policy::Signals::from_report(&report);
    assert!(signals.flags.contains("qr_url"), "{signals:?}");
    assert_eq!(signals.counts.get("qr_urls"), Some(&1));
    assert!(
        matches!(decision.verdict(), Verdict::Deliver),
        "{decision:?}"
    );
    assert!(decision.decisions[0].actions.iter().any(|action| matches!(
        action,
        currawong_policy::Action::AddHeader { name, value }
            if name == "X-Currawong-QR-Code" && value == "present"
    )));

    // With an HTML smuggling attachment the default pack quarantines it.
    let raw = message(&[
        attachment("code.png", "image/png", &png),
        attachment("statement.html", "text/html", html.as_bytes()),
    ]);
    let (report, decision) = pipeline
        .assess(&envelope("a@example.test"), raw.as_bytes(), None)
        .await;
    assert_eq!(
        decision.decisions[0].queue(),
        Some("phishing"),
        "{decision:?}"
    );
    assert!(
        report
            .urls
            .contains(&"https://c0mmbank.com.au/login".to_string()),
        "{:?}",
        report.urls
    );
    // The link exists only inside the image, so this finding came from the QR code.
    assert!(
        report
            .lookalikes
            .iter()
            .any(|found| found.source == "url" && found.domain == "c0mmbank.com.au"),
        "{:?}",
        report.lookalikes
    );
    let signals = currawong_policy::Signals::from_report(&report);
    assert!(signals.flags.contains("qr_code"), "{signals:?}");
    assert!(signals.flags.contains("html_smuggling"), "{signals:?}");
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
async fn one_unreadable_message_does_not_block_the_rest() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::default();
    cfg.spool.dir = dir.path().join("spool");
    cfg.scanner.clamd.address.clear();
    cfg.scanner.clamd.required = false;
    cfg.scanner.worker_binary = Some(worker_bin());
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

    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::default();
    cfg.spool.dir = dir.path().join("spool");
    cfg.scanner.clamd.address.clear();
    cfg.scanner.clamd.required = false;
    cfg.scanner.worker_binary = Some(worker_binary());
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
    cfg.scanner.clamd.required = false;
    cfg.scanner.worker_binary = Some(worker_binary());
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

/// An outbound user-scoped policy follows the SMTP AUTH login recorded on the
/// envelope, not the MAIL FROM, and never matches unauthenticated relay.
#[tokio::test]
async fn outbound_user_policy_matches_only_the_logged_in_user() {
    use currawong_policy::{Action, Policy, PolicySet, Scope};
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::default();
    cfg.spool.dir = dir.path().join("spool");
    cfg.scanner.clamd.address.clear();
    cfg.scanner.clamd.required = false;
    cfg.scanner.worker_binary = Some(worker_binary());
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

/// A config without a clamd address while clamd is required (the default)
/// fails --check-config with a message that says how to fix it.
#[test]
fn check_config_requires_a_clamd_address_when_clamd_is_required() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("c.toml");
    std::fs::write(&path, "[spool]\ndir = \"/var/spool/currawong\"\n").unwrap();
    let err = check_config(&path).unwrap_err();
    assert!(
        err.contains("scanner.clamd.address") && err.contains("required = false"),
        "{err}"
    );
    std::fs::write(
        &path,
        "[spool]\ndir = \"/var/spool/currawong\"\n[scanner.clamd]\nrequired = false\n",
    )
    .unwrap();
    check_config(&path).unwrap();
}

fn marked_message(header: Option<&str>, subject: &str, to: &str) -> Vec<u8> {
    let header = header
        .map(|value| format!("X-Protective-Marking: {value}\r\n"))
        .unwrap_or_default();
    format!(
        "From: officer@agency.gov.au\r\nTo: {to}\r\n{header}Subject: {subject}\r\nDate: Wed, 14 Oct 2026 01:00:00 +0000\r\n\r\nbriefing\r\n"
    )
    .into_bytes()
}

#[tokio::test]
async fn pspf_outbound_protected_to_gmail_is_blocked_under_the_government_pack() {
    let mut cfg = Config::default();
    let spool_tmp = tempfile::tempdir().unwrap();
    cfg.spool.dir = spool_tmp.path().join("spool");
    cfg.scanner.clamd.address.clear();
    cfg.scanner.clamd.required = false;
    cfg.scanner.worker_binary = Some(worker_bin());
    cfg.policy.pack = Some(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../config/policies/government.toml"),
    );
    let auth = AuthChecker::offline("currawong.example.test").unwrap();
    seed_txt(auth.cache(), "agency.gov.au", "v=spf1 +all").unwrap();
    let mut pipeline = Pipeline::new(Arc::new(cfg.clone()), auth);
    pipeline.policies = currawong_policy::load_pack(&cfg.policy).unwrap();
    let protected = "VER=2018.6, NS=gov.au, SEC=PROTECTED, ORIGIN=officer@agency.gov.au";
    let send = |to: &str| {
        let mut env = envelope("officer@agency.gov.au");
        env.direction = Direction::Outbound;
        env.rcpt_to = vec![to.into()];
        env
    };

    let to_gmail = send("someone@gmail.com");
    let raw = marked_message(
        Some(protected),
        "Brief [SEC=PROTECTED]",
        "someone@gmail.com",
    );
    let (report, verdict) = pipeline.evaluate(&to_gmail, &raw, None).await;
    let marking = report.marking.as_ref().unwrap();
    assert_eq!(
        marking.classification,
        Some(currawong_core::Classification::Protected)
    );
    assert!(
        matches!(&verdict, Verdict::Reject { reason, .. } if reason == "pspf-protected-external"),
        "{verdict:?}"
    );

    // The same message to a government domain is delivered.
    let to_gov = send("officer@finance.gov.au");
    let raw = marked_message(
        Some(protected),
        "Brief [SEC=PROTECTED]",
        "officer@finance.gov.au",
    );
    let (_, verdict) = pipeline.evaluate(&to_gov, &raw, None).await;
    assert!(matches!(verdict, Verdict::Deliver), "{verdict:?}");

    // A PROTECTED header under an OFFICIAL subject is a mismatch and held.
    let raw = marked_message(
        Some(protected),
        "Brief [SEC=OFFICIAL]",
        "officer@finance.gov.au",
    );
    let (report, verdict) = pipeline.evaluate(&to_gov, &raw, None).await;
    assert!(report.marking.as_ref().unwrap().mismatch);
    assert!(
        matches!(&verdict, Verdict::Quarantine { reason } if reason == "pspf-mismatch"),
        "{verdict:?}"
    );

    // Subject-only PROTECTED marking still blocks external mail.
    let raw = marked_message(None, "Brief [SEC=PROTECTED]", "someone@gmail.com");
    let (_, verdict) = pipeline.evaluate(&to_gmail, &raw, None).await;
    assert!(matches!(verdict, Verdict::Reject { .. }), "{verdict:?}");

    // Government tenants must mark outbound mail: unmarked mail is held.
    let raw = marked_message(None, "Lunch", "someone@gmail.com");
    let (_, verdict) = pipeline.evaluate(&to_gmail, &raw, None).await;
    assert!(
        matches!(&verdict, Verdict::Quarantine { reason } if reason == "pspf-required"),
        "{verdict:?}"
    );

    // Mixed recipients are decided one by one: gov.au delivers, gmail is refused.
    let mut mixed = send("officer@finance.gov.au");
    mixed.rcpt_to.push("someone@gmail.com".into());
    let raw = marked_message(
        Some(protected),
        "Brief [SEC=PROTECTED]",
        "officer@finance.gov.au",
    );
    let (_, decision) = pipeline.assess(&mixed, &raw, None).await;
    let verdicts: Vec<(String, bool)> = decision
        .decisions
        .iter()
        .map(|d| (d.recipient.clone(), matches!(d.verdict, Verdict::Deliver)))
        .collect();
    assert!(
        verdicts.contains(&("officer@finance.gov.au".into(), true)),
        "{verdicts:?}"
    );
    assert!(
        verdicts.contains(&("someone@gmail.com".into(), false)),
        "{verdicts:?}"
    );
}

#[tokio::test]
async fn bec_inbound_spoof_is_quarantined_and_a_weak_one_marked_through_the_pipeline() {
    let dir = tempfile::tempdir().unwrap();
    let directory = dir.path().join("directory.csv");
    std::fs::write(
        &directory,
        "email,name,vip\njane.smith@acme.test,Jane Smith,true\nbob@acme.test,Bob Jones,false\n",
    )
    .unwrap();
    let mut cfg = Config::default();
    cfg.spool.dir = dir.path().join("spool");
    cfg.scanner.clamd.address.clear();
    cfg.scanner.enabled = false;
    cfg.classify.bayes_database = dir.path().join("bayes.sqlite");
    cfg.classify.history_database = dir.path().join("history.sqlite");
    cfg.classify.directory_csv = Some(directory);
    cfg.domains.accept = vec!["acme.test".into()];
    cfg.relay
        .tenants
        .push(currawong_core::config::TenantConfig {
            id: "acme".into(),
            domains: vec!["acme.test".into()],
            trusted_cidrs: Vec::new(),
        });
    let auth = AuthChecker::offline("currawong.example.test").unwrap();
    let mut pipeline = Pipeline::new(Arc::new(cfg), auth);
    let mut env = envelope("someone@gmail.com");
    env.rcpt_to = vec!["finance@acme.test".into()];

    let raw = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../testdata/bec/ceo-gift-cards.eml"
    ))
    .unwrap();
    let (report, verdict) = pipeline.evaluate(&env, &raw, None).await;
    let bec = report.bec.as_ref().expect("inbound mail is scored");
    assert!(bec
        .reasons
        .contains(&currawong_core::BecReason::DisplayNameSpoof));
    assert!(
        matches!(&verdict, Verdict::Quarantine { reason } if reason == "bec-quarantine"),
        "{verdict:?}"
    );

    // A non-VIP colleague's name with no request is marked, not held.
    let raw = b"From: \"Bob Jones\" <bob.jones.home@gmail.com>\r\nTo: finance@acme.test\r\nSubject: hi\r\n\r\nSee you soon.\r\n";
    let (_, decision) = pipeline.assess(&env, raw, None).await;
    let d = &decision.decisions[0];
    assert!(matches!(d.verdict, Verdict::Deliver), "{:?}", d.verdict);
    assert!(
        d.actions.iter().any(|a| matches!(a, currawong_policy::Action::AddHeader { name, .. } if name == "X-Currawong-Warning")),
        "{:?}",
        d.actions
    );

    // Unauthenticated mail is never remembered as a known sender.
    assert_eq!(pipeline.history_sender(&env, raw, &report), None);

    // Outbound mail is not BEC-scored.
    let mut outbound = env.clone();
    outbound.direction = Direction::Outbound;
    let (report, _) = pipeline.evaluate(&outbound, raw, None).await;
    assert!(report.bec.is_none());
}
