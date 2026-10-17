//! Background tasks beside the delivery loop: the signed residency report and
//! the spool depth gauge.
//!
//! A report is written once per UTC calendar month, and again at startup when
//! the residency-relevant configuration changed since the last one. The last
//! report's month and configuration digest are kept in `last-report.json` so
//! a restart does not reset the cadence. Reports older than
//! `residency.report_retention_days` are deleted. A failed write shows on
//! `/readyz` and in `currawong_residency_report_failures_total`.
use async_trait::async_trait;
use currawong_core::{
    config::Config,
    residency::{load_or_create_signing_key, sign_report, ResidencyGuard, SigningKey},
    telemetry::{ReadinessCheck, RESIDENCY_REPORT_FAILURES_TOTAL, SPOOL_DEPTH},
};
use currawong_spool::{Spool, SpoolState};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};
use time::{
    format_description::well_known::Rfc3339, macros::format_description, OffsetDateTime,
    PrimitiveDateTime,
};
use tokio_util::sync::CancellationToken;

/// How often the report task checks whether a report is due.
pub const REPORT_CHECK: Duration = Duration::from_secs(3600);

const LAST_REPORT: &str = "last-report.json";

/// What the last report covered. Stored next to the reports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LastReport {
    /// `YYYY-MM`, UTC.
    pub month: String,
    pub config_sha256: String,
}

fn month_of(now: OffsetDateTime) -> String {
    let now = now.to_offset(time::UtcOffset::UTC);
    format!("{:04}-{:02}", now.year(), u8::from(now.month()))
}

/// Digest of everything the report describes: the residency section and the
/// clamd destination.
pub fn config_digest(cfg: &Config) -> String {
    let material = serde_json::to_vec(&(&cfg.residency, &cfg.scanner.clamd.address))
        .expect("residency config serialises");
    hex::encode(Sha256::digest(material))
}

/// Due when nothing was reported yet, the UTC month changed, or the
/// configuration the report describes changed.
pub fn report_due(last: Option<&LastReport>, now: OffsetDateTime, digest: &str) -> bool {
    match last {
        None => true,
        Some(last) => last.month != month_of(now) || last.config_sha256 != digest,
    }
}

/// Load the report key. Without `residency.signing_key_path` there is no
/// signed report, and that is logged rather than silent.
pub fn report_signing_key(cfg: &Config) -> Result<Option<SigningKey>, String> {
    match &cfg.residency.signing_key_path {
        Some(path) => load_or_create_signing_key(path)
            .map(Some)
            .map_err(|err| format!("residency signing key {}: {err}", path.display())),
        None => {
            tracing::warn!(
                "residency.signing_key_path is not set, so no signed residency report will be written"
            );
            Ok(None)
        }
    }
}

/// Write `residency-report-<UTC time>.json` and `residency-signing.pub` (the
/// hex public key auditors pin). Files are mode 0600 and replaced atomically.
pub fn write_report(
    dir: &Path,
    guard: &ResidencyGuard,
    cfg: &Config,
    key: &SigningKey,
    now: OffsetDateTime,
) -> std::io::Result<PathBuf> {
    let now = now.to_offset(time::UtcOffset::UTC);
    let generated_at = now.format(&Rfc3339).map_err(std::io::Error::other)?;
    let stamp = now
        .format(format_description!(
            "[year]-[month]-[day]T[hour][minute][second]Z"
        ))
        .map_err(std::io::Error::other)?;
    let signed = sign_report(guard.report(&generated_at, cfg), key);
    fs::create_dir_all(dir)?;
    let path = dir.join(format!("residency-report-{stamp}.json"));
    write_private(&path, &serde_json::to_vec_pretty(&signed)?)?;
    write_private(
        &dir.join("residency-signing.pub"),
        format!("{}\n", signed.public_key_hex).as_bytes(),
    )?;
    Ok(path)
}

fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    let _ = fs::remove_file(&tmp);
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&tmp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(&tmp, path)?;
    if let Some(parent) = path.parent() {
        fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

fn read_last(dir: &Path) -> Option<LastReport> {
    serde_json::from_slice(&fs::read(dir.join(LAST_REPORT)).ok()?).ok()
}

/// Delete reports whose file-name timestamp is older than `retention_days`.
/// Returns how many were removed.
pub fn prune_reports(
    dir: &Path,
    now: OffsetDateTime,
    retention_days: u64,
) -> std::io::Result<usize> {
    let cutoff = now - time::Duration::days(retention_days.min(i64::MAX as u64) as i64);
    let mut removed = 0;
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(err) => return Err(err),
    };
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(stamp) = name
            .strip_prefix("residency-report-")
            .and_then(|rest| rest.strip_suffix(".json"))
        else {
            continue;
        };
        let Ok(at) = PrimitiveDateTime::parse(
            stamp,
            format_description!("[year]-[month]-[day]T[hour][minute][second]Z"),
        ) else {
            continue;
        };
        if at.assume_utc() < cutoff {
            fs::remove_file(entry.path())?;
            removed += 1;
        }
    }
    Ok(removed)
}

/// Last report error, read by `/readyz`.
#[derive(Clone, Default)]
pub struct ReportHealth(Arc<Mutex<Option<String>>>);

impl ReportHealth {
    fn set(&self, error: Option<String>) {
        *self.0.lock().expect("report health lock") = error;
    }
}

#[async_trait]
impl ReadinessCheck for ReportHealth {
    fn name(&self) -> &'static str {
        "residency-report"
    }

    async fn check(&self) -> Result<(), String> {
        match self.0.lock().expect("report health lock").clone() {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }
}

/// One pass of the report task: write a report if one is due, then prune.
/// Returns the report written, if any.
pub fn report_tick(
    cfg: &Config,
    guard: &ResidencyGuard,
    key: &SigningKey,
    health: &ReportHealth,
    now: OffsetDateTime,
) -> Option<PathBuf> {
    let dir = &cfg.residency.report_dir;
    let digest = config_digest(cfg);
    let mut written = None;
    if report_due(read_last(dir).as_ref(), now, &digest) {
        let last = LastReport {
            month: month_of(now),
            config_sha256: digest,
        };
        let result = write_report(dir, guard, cfg, key, now).and_then(|path| {
            write_private(&dir.join(LAST_REPORT), &serde_json::to_vec(&last)?)?;
            Ok(path)
        });
        match result {
            Ok(path) => {
                tracing::info!(path = %path.display(), "wrote signed residency report");
                health.set(None);
                written = Some(path);
            }
            Err(err) => {
                tracing::error!(%err, "residency report failed");
                metrics::counter!(RESIDENCY_REPORT_FAILURES_TOTAL).increment(1);
                health.set(Some(format!("residency report: {err}")));
                return None;
            }
        }
    }
    if let Err(err) = prune_reports(dir, now, cfg.residency.report_retention_days) {
        tracing::warn!(%err, "old residency reports not pruned");
    }
    written
}

/// Run [`report_tick`] every `every`, reading time from `clock`.
pub async fn residency_reports(
    cfg: Arc<Config>,
    guard: Arc<ResidencyGuard>,
    key: SigningKey,
    health: ReportHealth,
    shutdown: CancellationToken,
    clock: impl Fn() -> OffsetDateTime,
    every: Duration,
) {
    loop {
        report_tick(&cfg, &guard, &key, &health, clock());
        tokio::select! {
            _ = shutdown.cancelled() => break,
            _ = tokio::time::sleep(every) => {}
        }
    }
}

/// Count messages not yet done and publish `currawong_spool_depth`. Counts
/// `.eml` files in the live state directories; nothing is parsed.
pub async fn record_spool_depth(spool: &Spool) -> Result<usize, String> {
    let mut depth = 0;
    for state in [
        SpoolState::Incoming,
        SpoolState::Active,
        SpoolState::Deferred,
    ] {
        let dir = spool.root().join(state.dir_name());
        let mut entries = match tokio::fs::read_dir(&dir).await {
            Ok(entries) => entries,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(err) => return Err(format!("{}: {err}", dir.display())),
        };
        while let Some(entry) = entries.next_entry().await.map_err(|err| err.to_string())? {
            if entry.file_name().to_string_lossy().ends_with(".eml") {
                depth += 1;
            }
        }
    }
    metrics::gauge!(SPOOL_DEPTH).set(depth as f64);
    Ok(depth)
}

pub async fn spool_depth(spool: Arc<Spool>, every: Duration, shutdown: CancellationToken) {
    loop {
        if let Err(err) = record_spool_depth(&spool).await {
            tracing::warn!(%err, "spool depth not updated");
        }
        tokio::select! {
            _ = shutdown.cancelled() => break,
            _ = tokio::time::sleep(every) => {}
        }
    }
}
