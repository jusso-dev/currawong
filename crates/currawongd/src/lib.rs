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

pub use health::{checks_for, reload_certificates, ClamdReady, SignaturesReady, SpoolWritable};
pub use periodic::{
    config_digest, prune_reports, record_spool_depth, report_due, report_signing_key, report_tick,
    residency_reports, spool_depth, write_report, LastReport, ReportHealth, REPORT_CHECK,
};
pub use pipeline::Pipeline;
pub use scheduler::{classify_pending, pending_scan, ready_to_deliver};

use currawong_core::{config::Config, Config as CoreConfig};
use currawong_scan::engines::yara::{compile_dir, RuleSummary};
use std::path::Path;

/// Load and validate. Validation includes the residency check on clamd and
/// every content endpoint.
pub fn check_config(path: &Path) -> Result<CoreConfig, String> {
    let cfg = Config::load(path).map_err(|err| err.to_string())?;
    cfg.validate().map_err(|err| err.to_string())?;
    if cfg.classify.enabled {
        currawong_classify::check_config(&cfg.classify).map_err(|err| err.to_string())?;
    }
    currawong_policy::load_pack(&cfg.policy).map_err(|err| err.to_string())?;
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

pub fn install_tracing(cfg: &CoreConfig) {
    currawong_core::telemetry::init_tracing(&cfg.log);
}
