//! Gateway daemon library. The binary is `currawongd`.
mod dmarc;
mod health;
mod pipeline;
mod scheduler;

pub use dmarc::{annotate_bimi, send_dmarc_reports};

pub use health::{checks_for, reload_certificates, ClamdReady, SignaturesReady, SpoolWritable};
pub use pipeline::Pipeline;
pub use scheduler::{classify_pending, pending_scan, ready_to_deliver};

use currawong_core::{config::Config, residency::ResidencyGuard, Config as CoreConfig};
use std::path::Path;

pub fn check_config(path: &Path) -> Result<CoreConfig, String> {
    let cfg = Config::load(path).map_err(|err| err.to_string())?;
    cfg.validate().map_err(|err| err.to_string())?;
    let guard = ResidencyGuard::from_config(&cfg.residency).map_err(|err| err.to_string())?;
    guard
        .enforce_startup(&cfg.residency.content_endpoints)
        .map_err(|err| err.to_string())?;
    for endpoint in &cfg.residency.content_endpoints {
        currawong_core::content::ObjectStoreClient::new(&guard, endpoint)
            .map_err(|err| err.to_string())?;
    }
    Ok(cfg)
}

pub fn install_tracing(cfg: &CoreConfig) {
    currawong_core::telemetry::init_tracing(&cfg.log);
}
