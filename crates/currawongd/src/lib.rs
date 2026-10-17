//! Gateway daemon library. The binary is `currawongd`.
pub mod dkim;
mod dmarc;
mod health;
mod pipeline;
mod scheduler;

pub use dmarc::{is_public, send_dmarc_reports, supervise, BimiJob, BimiWorker, BIMI_QUEUE};

pub use health::{
    checks_for, reload_certificates, ClamdReady, SignaturesReady, SpoolWritable, WorkerReady,
};
pub use pipeline::{worker_binary, worker_pool, Pipeline};
pub use scheduler::{classify_pending, pending_scan, ready_to_deliver};

use currawong_core::{config::Config, residency::ResidencyGuard, Config as CoreConfig};
use currawong_scan::engines::yara::{compile_dir, RuleSummary};
use std::path::Path;

pub fn check_config(path: &Path) -> Result<CoreConfig, String> {
    let cfg = Config::load(path).map_err(|err| err.to_string())?;
    cfg.validate().map_err(|err| err.to_string())?;
    currawong_policy::load_pack(&cfg.policy).map_err(|err| err.to_string())?;
    let guard = ResidencyGuard::from_config(&cfg.residency).map_err(|err| err.to_string())?;
    guard
        .enforce_startup(&cfg.residency.content_endpoints)
        .map_err(|err| err.to_string())?;
    for endpoint in &cfg.residency.content_endpoints {
        currawong_core::content::ObjectStoreClient::new(&guard, endpoint)
            .map_err(|err| err.to_string())?;
    }
    // Mail goes to clamd, so a clamd named by host must be an allowed endpoint.
    if let Ok(address) = currawong_scan::ClamdAddress::parse(&cfg.scanner.clamd.address) {
        if let Some(host) = address
            .host()
            .filter(|h| h.parse::<std::net::IpAddr>().is_err())
        {
            let url = url::Url::parse(&format!("clamd://{host}"))
                .map_err(|err| format!("scanner.clamd.address: {err}"))?;
            guard
                .check(&url)
                .map_err(|err| format!("scanner.clamd.address: {err}"))?;
        }
    }
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
