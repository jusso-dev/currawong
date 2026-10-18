//! currawong-admin: see docs/ARCHITECTURE.md. Implementation tracked in GitHub issues.
//! TODO: every audited admin action and verdict change emits
//! `currawong_integrations::export::EventKind::{AdminAction, VerdictChanged}`.
pub mod routes;

pub use currawong_core::Error;
