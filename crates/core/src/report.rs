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

/// How a domain imitates a protected one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LookalikeTechnique {
    /// Same UTS 39 confusable skeleton, for example `c0mmbank` or Cyrillic `а`.
    Homoglyph,
    /// Same label under another public suffix, for example `.net.au`.
    SuffixSwap,
    EditDistance,
    /// Embeds the protected name, for example `ato-refunds.com`.
    Cousin,
}

/// A sender or link domain that imitates a tenant domain or a brand.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LookalikeFinding {
    /// `from`, `reply-to`, `envelope` or `url`.
    pub source: String,
    pub domain: String,
    pub target: String,
    pub technique: LookalikeTechnique,
    /// 0 to 1. Higher is a closer imitation.
    pub score: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuleHit {
    pub name: String,
    pub score: f64,
}

/// Spam score from the classify stage. `bayes` is the Robinson-Fisher
/// probability (0.5 when the tenant has not trained it). `total` is Bayes
/// points plus rule scores. Policy chooses the threshold.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SpamReport {
    pub bayes: f64,
    pub rules_hit: Vec<RuleHit>,
    pub total: f64,
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
    /// Set by the classify stage when it runs.
    #[serde(default)]
    pub spam: Option<SpamReport>,
    #[serde(default)]
    pub lookalikes: Vec<LookalikeFinding>,
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
            spam: None,
            lookalikes: Vec::new(),
        }
    }
}
