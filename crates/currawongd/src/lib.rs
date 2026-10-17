//! Gateway daemon library. The binary is `currawongd`.
pub mod dkim;
mod dmarc;
mod encrypt;
mod health;
mod periodic;
mod pipeline;
mod scheduler;

pub use dmarc::{is_public, send_dmarc_reports, supervise, BimiJob, BimiWorker, BIMI_QUEUE};
pub use encrypt::SpoolMailer;

pub use health::{
    checks_for, reload_certificates, ClamdReady, SignaturesReady, SpoolWritable, WorkerReady,
};
pub use periodic::{
    config_digest, prune_reports, record_spool_depth, report_due, report_signing_key, report_tick,
    residency_reports, spool_depth, write_report, LastReport, ReportHealth, REPORT_CHECK,
};
pub use pipeline::{worker_binary, worker_pool, Pipeline};
pub use scheduler::{classify_pending, pending_scan, ready_to_deliver};

use currawong_core::{config::Config, residency::ResidencyGuard, Config as CoreConfig};
use currawong_scan::engines::yara::{compile_dir, RuleSummary};
use std::{path::Path, sync::Arc};

/// Load and validate. Validation includes the residency check on clamd and
/// every content endpoint.
pub fn check_config(path: &Path) -> Result<CoreConfig, String> {
    let cfg = Config::load(path).map_err(|err| err.to_string())?;
    cfg.validate().map_err(|err| err.to_string())?;
    cfg.check_clamd().map_err(|err| err.to_string())?;
    if cfg.classify.enabled {
        currawong_classify::check_config(&cfg.classify).map_err(|err| err.to_string())?;
    }
    currawong_policy::load_pack(&cfg.policy).map_err(|err| err.to_string())?;
    let guard = ResidencyGuard::from_config(&cfg.residency).map_err(|err| err.to_string())?;
    // The guard checks HTTP URLs; a syslog collector is checked as
    // https://host:port, as the exporter does.
    let sinks: Vec<String> = cfg
        .events
        .destinations()
        .into_iter()
        .map(|sink| match sink.split_once("://") {
            Some(("syslog" | "syslog-tls", rest)) => format!("https://{rest}"),
            _ => sink,
        })
        .collect();
    guard
        .enforce_startup(&sinks)
        .map_err(|err| format!("events: {err}"))?;
    yara_summary(&cfg)?;
    Ok(cfg)
}

/// Compile the configured YARA rules. `--check-config` prints the summary:
/// rule and tag counts and compiler warnings.
pub fn yara_summary(cfg: &CoreConfig) -> Result<Option<RuleSummary>, String> {
    if cfg.scanner.yara.rules_dir.as_os_str().is_empty() {
        return Ok(None);
    }
    compile_dir(&cfg.scanner.yara.rules_dir).map(|(_, summary)| Some(summary))
}

/// Build the `[events]` sinks and install the process-wide event bus. Does
/// nothing when no sink is configured. Must run inside the Tokio runtime.
pub fn start_events(cfg: &CoreConfig, guard: Arc<ResidencyGuard>) -> Result<(), String> {
    let events = &cfg.events;
    if events.destinations().is_empty() {
        return Ok(());
    }
    let overflow = events
        .overflow_dir
        .clone()
        .unwrap_or_else(|| cfg.spool.dir.join("events"));
    let bus = currawong_integrations::export::EventBus::from_config(
        events,
        guard,
        &cfg.gateway.hostname,
        &overflow,
    )
    .map_err(|err| format!("events: {err}"))?;
    if currawong_integrations::export::install(bus).is_err() {
        return Err("events: an event bus is already installed".into());
    }
    tracing::info!(sinks = ?events.destinations(), "event export started");
    Ok(())
}

pub fn install_tracing(cfg: &CoreConfig) {
    currawong_core::telemetry::init_tracing(&cfg.log);
}
