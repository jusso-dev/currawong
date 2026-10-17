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
    canonical_address, canonical_domain, Action, Condition, Flow, Policy, PolicyError, PolicySet,
    Scope,
};
pub use signals::Signals;
pub use store::PolicyStore;

use currawong_core::{config::PolicyConfig, Direction, ScanReport, Verdict};
use std::sync::OnceLock;

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
/// from the pack the first time only), otherwise the pack.
pub fn load(cfg: &PolicyConfig) -> Result<PolicySet, PolicyError> {
    let pack = load_pack(cfg)?;
    let Some(path) = &cfg.database else {
        return Ok(pack);
    };
    let mut store = PolicyStore::open(path)?;
    store.seed(&pack)?;
    store.load()
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
