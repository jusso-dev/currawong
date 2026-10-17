//! Gateway daemon library. The binary is `currawongd`.
mod health;
mod periodic;
mod pipeline;
mod scheduler;

pub use health::{checks_for, reload_certificates, ClamdReady, SignaturesReady, SpoolWritable};
pub use periodic::{
    record_spool_depth, report_due, report_signing_key, residency_reports, spool_depth,
    write_report,
};
pub use pipeline::Pipeline;
pub use scheduler::{classify_pending, pending_scan, ready_to_deliver};

use currawong_core::{config::Config, Config as CoreConfig};
use std::path::Path;

/// Load and validate. Validation includes the residency check on clamd and
/// every content endpoint.
pub fn check_config(path: &Path) -> Result<CoreConfig, String> {
    let cfg = Config::load(path).map_err(|err| err.to_string())?;
    cfg.validate().map_err(|err| err.to_string())?;
    currawong_policy::load_pack(&cfg.policy).map_err(|err| err.to_string())?;
    Ok(cfg)
}

pub fn install_tracing(cfg: &CoreConfig) {
    currawong_core::telemetry::init_tracing(&cfg.log);
}
