//! Gateway daemon library. The binary is `currawongd`.
mod health;
mod pipeline;
mod scheduler;

pub use health::{
    checks_for, reload_certificates, ClamdReady, SignaturesReady, SpoolWritable, WorkerReady,
};
pub use pipeline::{worker_binary, worker_pool, Pipeline};
pub use scheduler::{classify_pending, pending_scan, ready_to_deliver};

use currawong_core::{config::Config, residency::ResidencyGuard, Config as CoreConfig};
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
    Ok(cfg)
}

pub fn install_tracing(cfg: &CoreConfig) {
    currawong_core::telemetry::init_tracing(&cfg.log);
}
