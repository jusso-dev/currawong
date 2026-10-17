//! Policy engine: `ScanReport` -> `Signals` -> built-in floor and layered
//! policies -> one `Decision` per recipient, with an explanation of which
//! policies matched.
pub mod eval;
pub mod model;
pub mod signals;
pub mod store;

pub use eval::{
    evaluate, evaluate_message, evaluate_signals, Context, Decision, Matched, MessageDecision,
};
pub use model::{
    canonical_address, canonical_domain, canonical_pattern, valid_name, valid_tenant, Action,
    Condition, Flow, Policy, PolicyError, PolicySet, Scope, FLOOR_RULES,
};
pub use signals::Signals;
pub use store::PolicyStore;

use currawong_core::{config::PolicyConfig, Direction, ScanReport, Verdict};
use std::{sync::OnceLock, time::SystemTime};

pub const DEFAULT_PACK: &str = include_str!("../../../config/policies/default.toml");

pub fn default_pack() -> &'static PolicySet {
    static PACK: OnceLock<PolicySet> = OnceLock::new();
    PACK.get_or_init(|| PolicySet::from_toml(DEFAULT_PACK).expect("default policy pack is valid"))
}

/// The configured pack file, or the default pack. Does not touch the database.
pub fn load_pack(cfg: &PolicyConfig) -> Result<PolicySet, PolicyError> {
    match &cfg.pack {
        Some(path) => {
            let text = std::fs::read_to_string(path)
                .map_err(|err| PolicyError::Toml(format!("{}: {err}", path.display())))?;
            PolicySet::from_toml(&text)
        }
        None => Ok(default_pack().clone()),
    }
}

/// Policies for the running gateway: the database when configured (seeded
/// from the pack the first time only), otherwise the pack. Once the database
/// is seeded the pack file is not read, so a bad pack cannot block it.
pub fn load(cfg: &PolicyConfig) -> Result<PolicySet, PolicyError> {
    let Some(path) = &cfg.database else {
        return load_pack(cfg);
    };
    let mut store = PolicyStore::open(path)?;
    if !store.seeded()? {
        store.seed(&load_pack(cfg)?)?;
    }
    store.load()
}

/// Changes whenever the configured policy source might have: the pack file's
/// modification time and size, and the database revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stamp {
    pack: Option<(SystemTime, u64)>,
    revision: Option<i64>,
}

pub fn stamp(cfg: &PolicyConfig) -> Result<Stamp, PolicyError> {
    // A configured database is the source; the pack only seeds it once.
    if let Some(path) = &cfg.database {
        return Ok(Stamp {
            pack: None,
            revision: Some(PolicyStore::open(path)?.revision()?),
        });
    }
    let pack = match &cfg.pack {
        Some(path) => {
            let meta = std::fs::metadata(path)
                .map_err(|err| PolicyError::Toml(format!("{}: {err}", path.display())))?;
            Some((
                meta.modified().unwrap_or(SystemTime::UNIX_EPOCH),
                meta.len(),
            ))
        }
        None => None,
    };
    Ok(Stamp {
        pack,
        revision: None,
    })
}

/// The default pack with no envelope context. Kept for callers that only have a report.
pub fn decide(report: &ScanReport) -> Verdict {
    let ctx = Context {
        tenant_id: None,
        direction: Direction::Inbound,
        sender: "",
        sender_identity: None,
        recipient: "",
    };
    evaluate_message(report, &[ctx], default_pack()).verdict()
}
