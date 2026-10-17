//! Gateway daemon library. The binary is `currawongd`.
pub mod dkim;
mod dmarc;
mod health;
mod periodic;
mod pipeline;
mod scheduler;

pub use dmarc::{is_public, send_dmarc_reports, supervise, BimiJob, BimiWorker, BIMI_QUEUE};

pub use health::{checks_for, reload_certificates, ClamdReady, SignaturesReady, SpoolWritable};
pub use periodic::{
    config_digest, prune_reports, record_spool_depth, report_due, report_signing_key, report_tick,
    residency_reports, spool_depth, write_report, LastReport, ReportHealth, REPORT_CHECK,
};
pub use pipeline::Pipeline;
pub use scheduler::{classify_pending, pending_scan, ready_to_deliver};

use currawong_admin::routes::click::{ClickLog, ClickState};
use currawong_core::{config::Config, Config as CoreConfig};
use currawong_scan::engines::yara::{compile_dir, RuleSummary};
use currawong_scan::urls::{LocalBlocklist, UrlReputation, UrlRewriter, UrlSigner};
use std::{path::Path, sync::Arc};

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
    if cfg.url_rewrite.enabled {
        url_rewriter(&cfg)?;
    }
    Ok(cfg)
}

fn url_rewriter(cfg: &CoreConfig) -> Result<UrlRewriter, String> {
    let urls = &cfg.url_rewrite;
    UrlRewriter::new(
        UrlSigner::from_file(&urls.key_file)?,
        &urls.base_url,
        &urls.allow_domains,
        urls.ttl_days.saturating_mul(86_400),
        urls.max_message_bytes,
    )
}

/// The link rewriter and the click service state for `url_rewrite`.
pub fn url_protection(cfg: &CoreConfig) -> Result<(UrlRewriter, ClickState), String> {
    let urls = &cfg.url_rewrite;
    let rewriter = url_rewriter(cfg)?;
    let signer = rewriter.signer().clone();
    let reputation: Arc<dyn UrlReputation> = match &urls.blocklist {
        Some(path) => Arc::new(LocalBlocklist::from_file(path)),
        None => Arc::new(LocalBlocklist::from_entries("")),
    };
    let log = ClickLog::open(&urls.click_log)
        .map_err(|err| format!("click log {}: {err}", urls.click_log.display()))?;
    Ok((
        rewriter,
        ClickState {
            signer,
            reputation,
            log: Arc::new(log),
        },
    ))
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
