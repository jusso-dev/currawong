//! Length-prefixed JSON frames shared by the worker and the supervisor.
use crate::text::DlpText;
use currawong_core::config::ExtractLimits;
use currawong_core::PartInfo;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParseRequest {
    pub id: String,
    pub raw_path: PathBuf,
    pub limits: ExtractLimits,
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
}

impl ParseResponse {
    pub fn failed(id: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            parts: Vec::new(),
            urls: Vec::new(),
            error: Some(reason.into()),
            dlp: DlpText::default(),
        }
    }
}
