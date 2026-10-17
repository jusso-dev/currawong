use currawong_core::telemetry::{metrics_body, ReadinessCheck};
use currawong_core::{
    config::{Config, LogConfig},
    residency::{
        load_or_create_signing_key, verify_report, verifying_key_from_hex, ResidencyGuard,
        SignedReport,
    },
    telemetry::subscriber,
};
use currawongd::{
    check_config, config_digest, report_due, report_signing_key, report_tick, residency_reports,
    write_report, LastReport, ReportHealth,
};
use std::{
    io::{self, Write},
    sync::{Arc, Mutex},
};
use std::{sync::atomic::AtomicUsize, time::Duration};
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
fn reports_are_due_each_new_month_and_after_a_config_change() {
    let now = datetime!(2026-10-17 03:15:00 UTC);
    let last = |month: &str, digest: &str| LastReport {
        month: month.into(),
        config_sha256: digest.into(),
    };
    assert!(report_due(None, now, "d1"));
    assert!(!report_due(Some(&last("2026-10", "d1")), now, "d1"));
    assert!(report_due(Some(&last("2026-09", "d1")), now, "d1"));
    assert!(report_due(Some(&last("2025-10", "d1")), now, "d1"));
    assert!(report_due(Some(&last("2026-10", "d0")), now, "d1"));
}

fn report_fixture(
    dir: &std::path::Path,
) -> (
    Config,
    ResidencyGuard,
    currawong_core::residency::SigningKey,
) {
    let key = load_or_create_signing_key(&dir.join("keys/report.key")).unwrap();
    let mut cfg = Config::default();
    cfg.residency.report_dir = dir.join("reports");
    let guard = ResidencyGuard::from_config(&cfg.residency).unwrap();
    (cfg, guard, key)
}

fn reports_in(dir: &std::path::Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with("residency-report-"))
        .collect();
    names.sort();
    names
}

#[test]
fn ticks_follow_the_month_survive_a_restart_and_prune_old_reports() {
    let dir = tempfile::tempdir().unwrap();
    let (mut cfg, guard, key) = report_fixture(dir.path());
    let health = ReportHealth::default();
    let t0 = datetime!(2025-01-10 00:00:00 UTC);
    assert!(report_tick(&cfg, &guard, &key, &health, t0).is_some());
    assert!(report_tick(&cfg, &guard, &key, &health, t0 + time::Duration::days(1)).is_none());
    // A restart reads last-report.json, so the same month does not report again.
    let restarted = ReportHealth::default();
    assert!(report_tick(&cfg, &guard, &key, &restarted, t0 + time::Duration::days(2)).is_none());
    // A residency config change reports again at once.
    cfg.residency.content_endpoints = vec!["https://10.1.2.3/box".into()];
    assert!(report_tick(&cfg, &guard, &key, &restarted, t0 + time::Duration::days(3)).is_some());
    let feb = datetime!(2025-02-01 00:00:00 UTC);
    assert!(report_tick(&cfg, &guard, &key, &health, feb).is_some());
    assert_eq!(reports_in(&cfg.residency.report_dir).len(), 3);
    // 400 days after February, January's two reports are pruned.
    let later = feb + time::Duration::days(400) - time::Duration::hours(1);
    assert!(report_tick(&cfg, &guard, &key, &health, later).is_some());
    let names = reports_in(&cfg.residency.report_dir);
    assert_eq!(names.len(), 2, "{names:?}");
    assert!(
        names[0].starts_with("residency-report-2025-02-01"),
        "{names:?}"
    );
    assert_eq!(config_digest(&cfg).len(), 64);
}

#[tokio::test]
async fn a_failed_report_shows_on_readiness_and_in_metrics() {
    let dir = tempfile::tempdir().unwrap();
    let (mut cfg, guard, key) = report_fixture(dir.path());
    // A file where the report directory should be.
    std::fs::write(dir.path().join("blocked"), b"x").unwrap();
    cfg.residency.report_dir = dir.path().join("blocked");
    let _ = metrics_body();
    let health = ReportHealth::default();
    assert!(report_tick(
        &cfg,
        &guard,
        &key,
        &health,
        datetime!(2026-10-17 00:00:00 UTC)
    )
    .is_none());
    assert!(health
        .check()
        .await
        .unwrap_err()
        .contains("residency report"));
    assert!(metrics_body()
        .lines()
        .any(|line| line == "currawong_residency_report_failures_total 1"));
    cfg.residency.report_dir = dir.path().join("reports");
    assert!(report_tick(
        &cfg,
        &guard,
        &key,
        &health,
        datetime!(2026-10-17 00:00:00 UTC)
    )
    .is_some());
    health.check().await.unwrap();
}

#[tokio::test]
async fn the_report_loop_runs_on_a_fake_clock() {
    let dir = tempfile::tempdir().unwrap();
    let (cfg, guard, key) = report_fixture(dir.path());
    let reports = cfg.residency.report_dir.clone();
    let times = [
        datetime!(2026-08-31 23:00:00 UTC),
        datetime!(2026-08-31 23:30:00 UTC),
        datetime!(2026-09-01 00:00:00 UTC),
        datetime!(2026-09-15 00:00:00 UTC),
        datetime!(2026-10-01 00:00:00 UTC),
    ];
    let calls = Arc::new(AtomicUsize::new(0));
    let shutdown = tokio_util::sync::CancellationToken::new();
    let clock_calls = Arc::clone(&calls);
    let stop = shutdown.clone();
    let task = tokio::spawn(residency_reports(
        Arc::new(cfg),
        Arc::new(guard),
        key,
        ReportHealth::default(),
        shutdown.clone(),
        move || {
            let n = clock_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if n + 1 >= times.len() {
                stop.cancel();
            }
            times[n.min(times.len() - 1)]
        },
        Duration::from_millis(1),
    ));
    tokio::time::timeout(Duration::from_secs(10), task)
        .await
        .unwrap()
        .unwrap();
    let names = reports_in(&reports);
    assert_eq!(names.len(), 3, "{names:?}");
    assert!(names[0].contains("2026-08-31T230000Z"));
    assert!(names[1].contains("2026-09-01T000000Z"));
    assert!(names[2].contains("2026-10-01T000000Z"));
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
