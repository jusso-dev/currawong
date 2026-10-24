//! Threat-intel feeds in the daemon (ADR 0006): the store and DQS for the
//! pipeline, click-time reputation, the readiness check, and
//! `currawongd intel ...`.
use async_trait::async_trait;
use clap::Subcommand;
use currawong_core::{config::Config, telemetry::ReadinessCheck};
use currawong_intel::{guess_kind, url_candidates, Dqs, DqsResolver, Intel, Kind, Store, Syncer};
use currawong_scan::urls::{Reputation, UrlReputation};
use currawong_smtp::dns::{DnsLookup, HickoryDns, LookupError};
use std::{net::IpAddr, sync::Arc};

#[derive(Debug, Subcommand)]
pub enum IntelCommand {
    /// Download every enabled feed now. Without `--once`, keep syncing
    /// feeds as they fall due, as the daemon does.
    Sync {
        #[arg(long)]
        once: bool,
    },
    /// Check a SHA-256 hash, URL, domain or address against the local
    /// store, and Spamhaus DQS when it is enabled.
    Lookup { value: String },
}

/// The store, and DQS when `intel.dqs.enabled`. `None` when `intel` is off.
pub fn open_intel(cfg: &Config) -> Result<Option<Arc<Intel>>, String> {
    let intel = &cfg.intel;
    if !intel.enabled {
        return Ok(None);
    }
    let mut engine = Intel::new(Arc::new(open_store(cfg)?), intel);
    let dqs = &intel.dqs;
    if dqs.enabled {
        let key = currawong_intel::read_key(dqs.key_env.as_deref(), dqs.key_file.as_deref())
            .map_err(|err| format!("intel.dqs key: {err}"))?
            .ok_or("intel.dqs needs key_env or key_file")?;
        let dns = HickoryDns::system().map_err(|err| format!("intel.dqs resolver: {err}"))?;
        let resolver: Arc<dyn DqsResolver> = Arc::new(DqsDns(Arc::new(dns)));
        engine = engine.with_dqs(
            Dqs::new(
                &key,
                dqs.dbl,
                dqs.hbl,
                dqs.max_queries_per_message,
                resolver,
            )
            .map_err(|err| format!("intel.dqs: {err}"))?,
        );
    }
    Ok(Some(Arc::new(engine)))
}

pub fn open_store(cfg: &Config) -> Result<Store, String> {
    let days = cfg.intel.expire_after_days.min(36_500) as i64;
    Store::open(&cfg.intel.database, days * 86_400)
}

/// DQS through the gateway's resolver. NXDOMAIN is "not listed".
pub struct DqsDns(pub Arc<dyn DnsLookup>);

#[async_trait]
impl DqsResolver for DqsDns {
    async fn lookup_a(&self, name: &str) -> Result<Vec<IpAddr>, String> {
        match self.0.resolve_ips(name).await {
            Ok(answer) => Ok(answer.records),
            Err(LookupError::NxDomain) => Ok(Vec::new()),
            Err(err) => Err(err.to_string()),
        }
    }
}

/// Click-time check against the local store: a link, its domain or its
/// address on a feed is blocked.
pub struct IntelReputation {
    pub store: Arc<Store>,
}

#[async_trait]
impl UrlReputation for IntelReputation {
    async fn check(&self, url: &str) -> Reputation {
        let candidates = url_candidates(url);
        if candidates.is_empty() {
            return Reputation::Clean;
        }
        let store = Arc::clone(&self.store);
        let found = tokio::task::spawn_blocking(move || {
            store.lookup_many(&candidates, currawong_intel::now())
        })
        .await;
        match found {
            Ok(Ok(hits)) => match hits.first() {
                Some(hit) => Reputation::Blocked {
                    reason: format!("this {} is on the {} threat feed", hit.kind, hit.source),
                },
                None => Reputation::Clean,
            },
            // The store is a second opinion on top of the block list; a
            // failed read is logged and the other checks decide.
            Ok(Err(err)) => {
                tracing::error!(%err, "intel click lookup failed");
                Reputation::Clean
            }
            Err(err) => {
                tracing::error!(%err, "intel click lookup failed");
                Reputation::Clean
            }
        }
    }
}

/// Every check runs; a block from any of them wins over a warning.
pub struct ChainedReputation(pub Vec<Arc<dyn UrlReputation>>);

#[async_trait]
impl UrlReputation for ChainedReputation {
    async fn check(&self, url: &str) -> Reputation {
        let mut verdict = Reputation::Clean;
        for check in &self.0 {
            match check.check(url).await {
                blocked @ Reputation::Blocked { .. } => return blocked,
                warn @ Reputation::Warn { .. } if verdict == Reputation::Clean => verdict = warn,
                _ => {}
            }
        }
        verdict
    }
}

/// Stale feeds are a warning in the log and the
/// `currawong_intel_stale_feeds` gauge; with `intel.required` they also
/// fail `/readyz`.
pub struct IntelReady {
    pub syncer: Arc<Syncer>,
    pub required: bool,
}

pub const INTEL_STALE_FEEDS: &str = "currawong_intel_stale_feeds";

#[async_trait]
impl ReadinessCheck for IntelReady {
    fn name(&self) -> &'static str {
        "intel"
    }

    async fn check(&self) -> Result<(), String> {
        let syncer = Arc::clone(&self.syncer);
        let stale = tokio::task::spawn_blocking(move || syncer.stale_feeds(currawong_intel::now()))
            .await
            .map_err(|err| err.to_string())?;
        if stale.is_empty() || !self.required {
            return Ok(());
        }
        let names: Vec<&str> = stale.iter().map(|(name, _)| name.as_str()).collect();
        Err(format!("stale intel feeds: {}", names.join(", ")))
    }
}

/// One background pass: sync due feeds, then report stale ones.
pub async fn sync_pass(syncer: &Syncer) -> Result<(), String> {
    syncer.sync_due(false).await;
    let stale = syncer.stale_feeds(currawong_intel::now());
    metrics::gauge!(INTEL_STALE_FEEDS).set(stale.len() as f64);
    for (feed, last) in &stale {
        tracing::warn!(feed = %feed, last_success = ?last, "intel feed is stale");
    }
    Ok(())
}

pub fn syncer(cfg: &Config) -> Result<Syncer, String> {
    Syncer::new(&cfg.intel, Arc::new(open_store(cfg)?))
}

/// Runs the command and returns what to print.
pub async fn run(cfg: &Config, command: IntelCommand) -> Result<String, String> {
    if !cfg.intel.enabled {
        return Err("intel.enabled is false".into());
    }
    match command {
        IntelCommand::Sync { once: true } => {
            let syncer = syncer(cfg)?;
            let mut out = String::new();
            let mut failed = 0;
            for (feed, result) in syncer.sync_due(true).await {
                match result {
                    Ok(outcome) => out.push_str(&format!("{feed}: {outcome:?}\n")),
                    Err(err) => {
                        failed += 1;
                        out.push_str(&format!("{feed}: failed: {err}\n"));
                    }
                }
            }
            if failed > 0 {
                return Err(format!("{out}{failed} feeds failed"));
            }
            Ok(out)
        }
        IntelCommand::Sync { once: false } => {
            let syncer = syncer(cfg)?;
            loop {
                sync_pass(&syncer).await?;
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            }
        }
        IntelCommand::Lookup { value } => {
            let intel = open_intel(cfg)?.ok_or("intel.enabled is false")?;
            let (hashes, urls) = match guess_kind(&value) {
                Some(Kind::Sha256) => (vec![value.clone()], Vec::new()),
                Some(Kind::Url) => (Vec::new(), vec![value.clone()]),
                Some(Kind::Domain | Kind::Ip) => {
                    let host = value.trim().trim_end_matches('.');
                    let host = match host.parse::<std::net::Ipv6Addr>() {
                        Ok(_) => format!("[{host}]"),
                        Err(_) => host.to_string(),
                    };
                    (Vec::new(), vec![format!("http://{host}/")])
                }
                None => return Err("nothing to look up".into()),
            };
            let checked = intel.check(&hashes, &urls).await;
            let mut out = String::new();
            for hit in &checked.hits {
                if hit.kind == "url" && !value.contains("://") {
                    continue;
                }
                out.push_str(&format!(
                    "{} {} {} {}\n",
                    hit.kind, hit.value, hit.source, hit.threat
                ));
            }
            for flag in &checked.flags {
                out.push_str(&format!("flag {flag}\n"));
            }
            for note in checked
                .notes
                .iter()
                .filter(|n| !n.contains(" is listed by "))
            {
                out.push_str(&format!("note {note}\n"));
            }
            if out.is_empty() {
                out.push_str("not listed\n");
            }
            Ok(out)
        }
    }
}
