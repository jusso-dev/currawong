//! Threat-intelligence indicators (ADR 0006).
//!
//! Feeds (abuse.ch, OpenPhish, PhishTank, STIX 2.1 over TAXII 2.1 for ACSC
//! CTIS or MISP) are downloaded into a local SQLite store. Messages and
//! clicks are checked against the store on the box. Only the opt-in Spamhaus
//! DQS lookups leave it, and they carry a domain or a file hash.
pub mod dqs;
pub mod formats;
pub mod normalise;
pub mod store;
pub mod sync;

pub use dqs::{Dqs, DqsResolver};
pub use normalise::{guess_kind, normalise, url_candidates};
pub use store::{FeedStatus, Store};
pub use sync::{SyncOutcome, Syncer};

use currawong_core::{config::IntelConfig, IntelHit};
use std::{path::Path, sync::Arc};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Kind {
    Sha256,
    Url,
    Domain,
    Ip,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
            Self::Url => "url",
            Self::Domain => "domain",
            Self::Ip => "ip",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        Some(match text {
            "sha256" => Self::Sha256,
            "url" => Self::Url,
            "domain" => Self::Domain,
            "ip" => Self::Ip,
            _ => return None,
        })
    }
}

/// One normalised indicator from a feed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Indicator {
    pub kind: Kind,
    pub value: String,
    pub threat: String,
    /// Unix seconds. The sync time when the feed does not say.
    pub first_seen: Option<i64>,
    /// Unix seconds, when the feed limits the indicator's validity.
    pub expires: Option<i64>,
}

/// Read a key from the named environment variable or file. Never log it.
pub fn read_key(env: Option<&str>, file: Option<&Path>) -> Result<Option<String>, String> {
    let key = match (env, file) {
        (Some(name), _) => {
            std::env::var(name).map_err(|_| format!("environment variable {name} is not set"))?
        }
        (None, Some(path)) => std::fs::read_to_string(path)
            .map_err(|err| format!("key file {}: {err}", path.display()))?,
        (None, None) => return Ok(None),
    };
    let key = key.trim().to_string();
    if key.is_empty() {
        return Err("key is empty".into());
    }
    Ok(Some(key))
}

pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or_default()
}

/// What checking one message found.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Checked {
    pub hits: Vec<IntelHit>,
    /// Report flags, for example `intel.dbl_low_reputation`.
    pub flags: Vec<String>,
    pub notes: Vec<String>,
}

/// The local store plus, when configured, Spamhaus DQS.
pub struct Intel {
    pub store: Arc<Store>,
    pub dqs: Option<Dqs>,
    max_urls: usize,
}

impl Intel {
    pub fn new(store: Arc<Store>, cfg: &IntelConfig) -> Self {
        Self {
            store,
            dqs: None,
            max_urls: cfg.max_urls_per_message,
        }
    }

    pub fn with_dqs(mut self, dqs: Dqs) -> Self {
        self.dqs = Some(dqs);
        self
    }

    /// Check part hashes, then at most `max_urls_per_message` links and
    /// their domains. Store lookups run off the async workers.
    pub async fn check(&self, hashes: &[String], urls: &[String]) -> Checked {
        let mut checked = Checked::default();
        let mut hashes: Vec<String> = hashes
            .iter()
            .filter_map(|hash| normalise(Kind::Sha256, hash))
            .collect();
        hashes.sort();
        hashes.dedup();
        let mut unique: Vec<&String> = Vec::new();
        for url in urls {
            if !unique.contains(&url) {
                unique.push(url);
            }
        }
        if unique.len() > self.max_urls {
            checked.notes.push(format!(
                "intel: {} of {} links not checked against threat feeds",
                unique.len() - self.max_urls,
                unique.len()
            ));
            unique.truncate(self.max_urls);
        }
        let urls: Vec<String> = unique.into_iter().cloned().collect();
        let mut candidates: Vec<(Kind, String)> =
            hashes.iter().map(|h| (Kind::Sha256, h.clone())).collect();
        for url in &urls {
            for candidate in url_candidates(url) {
                if !candidates.contains(&candidate) {
                    candidates.push(candidate);
                }
            }
        }
        let store = Arc::clone(&self.store);
        let looked_up =
            tokio::task::spawn_blocking(move || store.lookup_many(&candidates, now())).await;
        match looked_up {
            Ok(Ok(hits)) => checked.hits = hits,
            Ok(Err(err)) => checked.notes.push(format!("intel lookup failed: {err}")),
            Err(err) => checked.notes.push(format!("intel lookup failed: {err}")),
        }
        if let Some(dqs) = &self.dqs {
            let domains: Vec<String> = urls
                .iter()
                .filter_map(|url| url::Url::parse(url).ok())
                .filter_map(|url| match url.host() {
                    Some(url::Host::Domain(host)) => Some(host.to_ascii_lowercase()),
                    _ => None,
                })
                .collect();
            let found = dqs.check(&domains, &hashes).await;
            checked.hits.extend(found.hits);
            checked.flags.extend(found.flags);
            checked.notes.extend(found.notes);
        }
        for hit in &checked.hits {
            checked.notes.push(format!(
                "intel: {} {} is listed by {} ({})",
                hit.kind, hit.value, hit.source, hit.threat
            ));
        }
        checked
    }
}
