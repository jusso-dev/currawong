//! Scan report shared by the pipeline, policy engine and SIEM export.
use crate::MessageId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthMethodResult {
    pub result: String,
    pub detail: String,
}

impl AuthMethodResult {
    pub fn none() -> Self {
        Self {
            result: "none".into(),
            detail: String::new(),
        }
    }
}

/// SPF, DKIM, DMARC and ARC results plus the RFC 8601 header we add.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthResults {
    pub spf: AuthMethodResult,
    pub dkim: Vec<AuthMethodResult>,
    pub dmarc: AuthMethodResult,
    pub arc: AuthMethodResult,
    /// `p=none`, `p=quarantine` or `p=reject` when a DMARC record was found.
    pub dmarc_policy: String,
    pub header: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PartFlag {
    ExtMismatch,
    Encrypted,
    HasMacro,
    HasOleObject,
    Executable,
    LimitExceeded,
}

impl PartFlag {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ExtMismatch => "ExtMismatch",
            Self::Encrypted => "Encrypted",
            Self::HasMacro => "HasMacro",
            Self::HasOleObject => "HasOleObject",
            Self::Executable => "Executable",
            Self::LimitExceeded => "LimitExceeded",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartInfo {
    pub content_type: String,
    pub filename: Option<String>,
    pub size: u64,
    pub sha256: String,
    pub flags: Vec<PartFlag>,
    /// Path of the extracted bytes, when the parser worker wrote them to disk.
    pub path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineFinding {
    pub engine: String,
    pub result: String,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanReport {
    pub message_id: MessageId,
    pub auth: Option<AuthResults>,
    pub parts: Vec<PartInfo>,
    pub urls: Vec<String>,
    pub engines: Vec<EngineFinding>,
    pub malware: bool,
    pub active_content: bool,
    /// Parser crash, limit or a hard scanner error. Policy quarantines.
    pub fail_closed: bool,
    /// Required engine configured but unreachable. Do not deliver; retry.
    pub defer: bool,
    pub notes: Vec<String>,
    /// A stage changed the message (for example URL rewriting). Only
    /// modified inbound mail is ARC sealed.
    #[serde(default)]
    pub modified: bool,
}

impl ScanReport {
    pub fn new(message_id: MessageId) -> Self {
        Self {
            message_id,
            auth: None,
            parts: Vec::new(),
            urls: Vec::new(),
            engines: Vec::new(),
            malware: false,
            active_content: false,
            fail_closed: false,
            defer: false,
            notes: Vec::new(),
            modified: false,
        }
    }
}
