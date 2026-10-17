//! Shared types for Currawong: identifiers, verdicts, configuration and reports.
pub mod config;
pub mod content;
pub mod report;
pub mod residency;
pub mod secret;
pub mod telemetry;

pub use config::{Config, ConfigError};
pub use report::{
    AuthMethodResult, AuthResults, DlpKind, DlpReport, DlpSample, EngineFinding, LookalikeFinding,
    LookalikeTechnique, PartFlag, PartInfo, RuleHit, ScanReport, SpamReport, YaraMatch,
};
pub use residency::{ResidencyError, ResidencyGuard, SignedReport};
pub use secret::Secret;

use serde::{Deserialize, Serialize};

/// Unique identifier for a message in the spool (ULID).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MessageId(pub String);

impl MessageId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for MessageId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Direction of mail flow through the gateway.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum Direction {
    #[default]
    Inbound,
    Outbound,
}

/// Final decision produced by the policy engine for one message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verdict {
    Deliver,
    Quarantine {
        reason: String,
    },
    Reject {
        code: u16,
        reason: String,
    },
    Discard,
    /// Temporary failure. The message stays in the spool and is retried.
    Defer {
        reason: String,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("not implemented: {0}")]
    NotImplemented(&'static str),
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Residency(#[from] ResidencyError),
}
