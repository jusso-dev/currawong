//! Background tasks beside the delivery loop: the signed residency report (at
//! startup and again in each new calendar month) and the spool depth gauge.
use currawong_core::{
    config::Config,
    residency::{load_or_create_signing_key, sign_report, ResidencyGuard, SigningKey},
    telemetry::SPOOL_DEPTH,
};
use currawong_spool::{Spool, SpoolState};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use time::{format_description::well_known::Rfc3339, macros::format_description, OffsetDateTime};
use tokio_util::sync::CancellationToken;

/// How often the report task checks whether a new month has started.
const REPORT_CHECK: Duration = Duration::from_secs(3600);

/// A report is due at startup and whenever the UTC calendar month changes.
pub fn report_due(last: Option<OffsetDateTime>, now: OffsetDateTime) -> bool {
    match last {
        None => true,
        Some(last) => (last.year(), last.month()) != (now.year(), now.month()),
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

pub async fn residency_reports(
    cfg: Arc<Config>,
    guard: Arc<ResidencyGuard>,
    key: SigningKey,
    shutdown: CancellationToken,
) {
    let mut last = None;
    loop {
        let now = OffsetDateTime::now_utc();
        if report_due(last, now) {
            match write_report(&cfg.residency.report_dir, &guard, &cfg, &key, now) {
                Ok(path) => {
                    tracing::info!(path = %path.display(), "wrote signed residency report");
                    last = Some(now);
                }
                Err(err) => tracing::error!(%err, "residency report failed"),
            }
        }
        tokio::select! {
            _ = shutdown.cancelled() => break,
            _ = tokio::time::sleep(REPORT_CHECK) => {}
        }
    }
}

/// Count messages not yet done and publish `currawong_spool_depth`.
pub async fn record_spool_depth(spool: &Spool) -> Result<usize, String> {
    let mut depth = 0;
    for state in [
        SpoolState::Incoming,
        SpoolState::Active,
        SpoolState::Deferred,
    ] {
        depth += spool
            .list(state)
            .await
            .map_err(|err| err.to_string())?
            .len();
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
