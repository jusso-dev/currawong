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

#[test]
fn clamd_by_host_name_must_pass_residency() {
    let dir = tempfile::tempdir().unwrap();
    let write = |address: &str| {
        let path = dir.path().join("c.toml");
        std::fs::write(
            &path,
            format!(
                "[spool]\ndir = \"/var/spool/currawong\"\n[scanner.clamd]\naddress = \"{address}\"\n[residency]\nallowed_names = [\"clamd.internal\"]\n"
            ),
        )
        .unwrap();
        path
    };
    check_config(&write("tcp:clamd.internal:3310")).unwrap();
    let err = check_config(&write("tcp:clamd.example.com:3310")).unwrap_err();
    assert!(err.contains("scanner.clamd.address"), "{err}");
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
