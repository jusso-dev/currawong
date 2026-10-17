//! Length-prefixed JSON frames shared by the worker and the supervisor.
use currawong_core::config::ExtractLimits;
use currawong_core::{PartInfo, YaraMatch};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParseRequest {
    pub id: String,
    pub raw_path: PathBuf,
    pub limits: ExtractLimits,
    /// Serialised YARA rules written by the supervisor. None skips YARA.
    #[serde(default)]
    pub yara_rules: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParseResponse {
    pub id: String,
    pub parts: Vec<PartInfo>,
    pub urls: Vec<String>,
    pub error: Option<String>,
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
            yara: Vec::new(),
        }
    }
}
