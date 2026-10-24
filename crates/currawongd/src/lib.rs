//! Gateway daemon library. The binary is `currawongd`.
pub mod dkim;
mod dmarc;
mod encrypt;
mod health;
pub mod intel;
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

use currawong_admin::routes::click::{ClickLimits, ClickLog, ClickState};
use currawong_core::{config::Config, residency::ResidencyGuard, Config as CoreConfig};
use currawong_scan::engines::yara::{compile_dir, RuleSummary};
use currawong_scan::urls::{LocalBlocklist, UrlReputation, UrlRewriter, UrlSigner};
use std::{path::Path, sync::Arc};

/// Load and validate. Validation includes the residency check on clamd and
/// every content endpoint.
pub fn check_config(path: &Path) -> Result<CoreConfig, String> {
    let cfg = Config::load(path).map_err(|err| err.to_string())?;
    cfg.validate().map_err(|err| err.to_string())?;
    cfg.check_clamd().map_err(|err| err.to_string())?;
    currawong_smtp::delivery::check_exchange_tls(&cfg)?;
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
    if !cfg.scanner.rspamd.url.is_empty() {
        currawong_scan::rspamd::RspamdClient::new(
            &cfg.scanner.rspamd,
            Arc::new(ResidencyGuard::from_config(&cfg.residency).map_err(|err| err.to_string())?),
        )?;
    }
    if !cfg.scanner.sandbox.url.is_empty() {
        currawong_scan::sandbox::cape::Cape::new(
            &cfg.scanner.sandbox,
            Arc::new(ResidencyGuard::from_config(&cfg.residency).map_err(|err| err.to_string())?),
        )?;
    }
    yara_summary(&cfg)?;
    if cfg.intel.enabled {
        currawong_intel::sync::http_client(cfg.intel.ca_file.as_deref(), cfg.intel.timeout_secs)
            .map_err(|err| format!("intel.ca_file: {err}"))?;
        let dqs = &cfg.intel.dqs;
        if dqs.enabled {
            currawong_intel::read_key(dqs.key_env.as_deref(), dqs.key_file.as_deref())
                .map_err(|err| format!("intel.dqs key: {err}"))?;
        }
    }
    if cfg.url_rewrite.enabled {
        url_rewriter(&cfg)?;
        click_limits(&cfg)?;
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
    let list = match &urls.blocklist {
        Some(path) => LocalBlocklist::from_file(path),
        None => LocalBlocklist::from_entries(""),
    };
    let mut reputation: Arc<dyn UrlReputation> =
        Arc::new(list.with_warn_unknown(urls.warn_unknown));
    if cfg.intel.enabled && cfg.intel.check_clicks {
        let store = Arc::new(intel::open_store(cfg)?);
        reputation = Arc::new(intel::ChainedReputation(vec![
            reputation,
            Arc::new(intel::IntelReputation { store }),
        ]));
    }
    let log = ClickLog::open(&urls.click_log, urls.click_log_max_bytes)
        .map_err(|err| format!("click log {}: {err}", urls.click_log.display()))?;
    Ok((
        rewriter,
        ClickState::new(signer, reputation, log, click_limits(cfg)?),
    ))
}

fn click_limits(cfg: &CoreConfig) -> Result<ClickLimits, String> {
    let urls = &cfg.url_rewrite;
    let trusted_proxies = urls
        .trusted_proxies
        .iter()
        .map(|entry| {
            entry
                .parse::<ipnet::IpNet>()
                .or_else(|_| entry.parse::<std::net::IpAddr>().map(ipnet::IpNet::from))
                .map_err(|_| {
                    format!("url_rewrite.trusted_proxies: {entry:?} is not an address or CIDR")
                })
        })
        .collect::<Result<_, _>>()?;
    Ok(ClickLimits {
        per_client: urls.clicks_per_minute_per_client,
        per_link: urls.clicks_per_minute_per_link,
        trusted_proxies,
    })
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
