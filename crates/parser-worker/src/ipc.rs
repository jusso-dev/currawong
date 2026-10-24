//! Length-prefixed JSON frames shared by the worker and the supervisor.
use crate::text::DlpText;
use currawong_core::config::ExtractLimits;
pub use currawong_core::{FoundUrl, UrlSource};
use currawong_core::{PartInfo, YaraMatch};
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
    /// Every distinct URL, QR codes included, for link analysis.
    pub urls: Vec<String>,
    /// The same URLs with where each was found. A URL found in two places
    /// is listed once per source.
    #[serde(default)]
    pub url_sources: Vec<FoundUrl>,
    pub error: Option<String>,
    /// Sandbox warnings, sent once in the `ready` frame.
    #[serde(default)]
    pub warnings: Vec<String>,
    /// Extracted text for DLP, bounded by `text::MAX_TEXT_BYTES`.
    #[serde(default)]
    pub dlp: DlpText,
    /// Decoded message bodies only, at most 64 KiB, for campaign digests.
    #[serde(default)]
    pub campaign_body: Box<DlpText>,
    #[serde(default)]
    pub yara: Vec<YaraMatch>,
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
            url_sources: Vec::new(),
            error: Some(reason.into()),
            warnings: Vec::new(),
            dlp: DlpText::default(),
            campaign_body: Box::default(),
            yara: Vec::new(),
        }
    }
}
