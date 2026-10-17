//! Length-prefixed JSON frames shared by the worker and the supervisor.
use currawong_core::config::ExtractLimits;
use currawong_core::PartInfo;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tokio_util::codec::LengthDelimitedCodec;

/// Largest frame either side accepts. A response that would be bigger is
/// replaced by a failure so the worker never dies writing it.
pub const MAX_FRAME: usize = 8 * 1024 * 1024;

pub fn codec() -> LengthDelimitedCodec {
    LengthDelimitedCodec::builder()
        .max_frame_length(MAX_FRAME)
        .new_codec()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParseRequest {
    pub id: String,
    pub raw_path: PathBuf,
    pub limits: ExtractLimits,
    /// When set, the worker writes each part's decoded bytes here and records
    /// the file in `PartInfo::path`, so the supervisor can send it to clamd.
    #[serde(default)]
    pub out_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParseResponse {
    pub id: String,
    pub parts: Vec<PartInfo>,
    pub urls: Vec<String>,
    pub error: Option<String>,
    /// Sandbox warnings, sent once in the `ready` frame.
    #[serde(default)]
    pub warnings: Vec<String>,
}

/// Id of the frame a worker sends once its sandbox is in place, and of the
/// failure it sends instead when it could not install it.
pub const READY_ID: &str = "ready";
pub const STARTUP_ID: &str = "startup";

impl ParseResponse {
    pub fn failed(id: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            parts: Vec::new(),
            urls: Vec::new(),
            error: Some(reason.into()),
            warnings: Vec::new(),
        }
    }
}
