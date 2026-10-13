//! Shared types for Currawong: message identifiers, verdicts and errors.
use serde::{Deserialize, Serialize};

/// Unique identifier for a message in the spool (ULID string once M1 lands).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MessageId(pub String);

/// Direction of mail flow through the gateway.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Direction { Inbound, Outbound }

/// Final decision produced by the policy engine for one message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verdict { Deliver, Quarantine { reason: String }, Reject { code: u16, reason: String }, Discard }

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("not implemented: {0}")]
    NotImplemented(&'static str),
}
