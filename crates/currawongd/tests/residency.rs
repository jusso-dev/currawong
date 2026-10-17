use currawong_core::{
    config::{Config, LogConfig},
    residency::{
        load_or_create_signing_key, verify_report, verifying_key_from_hex, ResidencyGuard,
        SignedReport,
    },
    telemetry::subscriber,
};
use currawongd::{check_config, report_due, report_signing_key, write_report};
use std::{
    io::{self, Write},
    sync::{Arc, Mutex},
};
use time::macros::datetime;
use tracing_subscriber::fmt::MakeWriter;

#[derive(Clone)]
struct MemWriter(Arc<Mutex<Vec<u8>>>);

impl Write for MemWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for MemWriter {
    type Writer = MemWriter;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

#[test]
fn reports_are_due_at_startup_and_each_new_month() {
    let now = datetime!(2026-10-17 03:15:00 UTC);
    assert!(report_due(None, now));
    assert!(!report_due(Some(datetime!(2026-10-01 00:00:00 UTC)), now));
    assert!(report_due(Some(datetime!(2026-09-30 23:59:59 UTC)), now));
    assert!(report_due(Some(datetime!(2025-10-17 03:15:00 UTC)), now));
}

#[test]
fn report_is_dated_private_and_verifies_against_the_published_key() {
    let dir = tempfile::tempdir().unwrap();
    let key = load_or_create_signing_key(&dir.path().join("keys/report.key")).unwrap();
    let mut cfg = Config::default();
    cfg.scanner.clamd.address = "tcp:127.0.0.1:3310".into();
    cfg.residency.content_endpoints =
        vec!["https://mail.s3.ap-southeast-2.amazonaws.com/box".into()];
    let guard = ResidencyGuard::from_config(&cfg.residency).unwrap();
    let reports = dir.path().join("reports");
    let path = write_report(
        &reports,
        &guard,
        &cfg,
        &key,
        datetime!(2026-10-17 03:15:00 UTC),
    )
    .unwrap();
    assert_eq!(
        path.file_name().unwrap(),
        "residency-report-2026-10-17T031500Z.json"
    );
    let second = write_report(
        &reports,
        &guard,
        &cfg,
        &key,
        datetime!(2026-11-01 00:00:00 UTC),
    )
    .unwrap();
    assert_ne!(
        path, second,
        "a new month must not overwrite the old report"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    let signed: SignedReport = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(signed.report.generated_at, "2026-10-17T03:15:00Z");
    assert_eq!(signed.report.endpoints.len(), 2, "{:?}", signed.report);
    assert!(signed.report.endpoints[0].url.starts_with("clamd:"));
    let pinned = std::fs::read_to_string(reports.join("residency-signing.pub")).unwrap();
    verify_report(&signed, &verifying_key_from_hex(&pinned).unwrap()).unwrap();
    assert!(!std::fs::read_dir(&reports)
        .unwrap()
        .any(|entry| entry.unwrap().path().extension() == Some("tmp".as_ref())));
}

#[test]
fn missing_signing_key_is_logged() {
    let buf = MemWriter(Arc::new(Mutex::new(Vec::new())));
    let log = LogConfig {
        format: "json".into(),
        level: "info".into(),
    };
    let cfg = Config::default();
    let key = tracing::subscriber::with_default(subscriber(&log, None, buf.clone()), || {
        report_signing_key(&cfg)
    });
    assert!(key.unwrap().is_none());
    let text = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
    assert!(text.contains("signing_key_path is not set"), "{text}");
    assert!(text.contains("WARN"), "{text}");
}

#[test]
fn check_config_refuses_a_foreign_clamd() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("clamd.toml");
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
address = "tcp:8.8.8.8:3310"
"#,
    )
    .unwrap();
    let err = check_config(&path).unwrap_err();
    assert!(err.contains("clamd") && err.contains("8.8.8.8"), "{err}");
}
