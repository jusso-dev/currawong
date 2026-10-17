//! Length-prefixed JSON frames shared by the worker and the supervisor.
use crate::text::DlpText;
use currawong_core::config::ExtractLimits;
use currawong_core::{PartInfo, YaraMatch};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParseRequest {
    pub id: String,
    pub raw_path: PathBuf,
    pub limits: ExtractLimits,
    /// Generation of the YARA rules the worker must have loaded through
    /// [`LoadRules`]. None skips YARA. A mismatch fails the job closed.
    #[serde(default)]
    pub yara_generation: Option<u64>,
}

/// Serialised YARA rules, sent on stdin after spawn and whenever the rules
/// change. Never a path: the worker only trusts bytes from the supervisor.
/// The reply is a [`ParseResponse`] with id [`LoadRules::REPLY_ID`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoadRules {
    pub generation: u64,
    /// Base64 of `yara_x::Rules::serialize`.
    pub yara_rules: String,
}

impl LoadRules {
    pub const REPLY_ID: &'static str = "yara-load";

    /// Load frames can be far larger than a parse request.
    pub const MAX_FRAME_BYTES: usize = 256 * 1024 * 1024;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParseResponse {
    pub id: String,
    pub parts: Vec<PartInfo>,
    pub urls: Vec<String>,
    pub error: Option<String>,
    /// Extracted text for DLP, bounded by `text::MAX_TEXT_BYTES`.
    #[serde(default)]
    pub dlp: DlpText,
    #[serde(default)]
    pub yara: Vec<YaraMatch>,
}

impl ParseResponse {
    pub fn failed(id: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            parts: Vec::new(),
            urls: Vec::new(),
            error: Some(reason.into()),
            dlp: DlpText::default(),
            yara: Vec::new(),
        }
    }
}
