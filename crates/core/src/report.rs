//! Scan report shared by the pipeline, policy engine and SIEM export.
use crate::MessageId;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

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

/// A YARA rule that matched the raw message, a MIME part or an archive member.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct YaraMatch {
    pub rule: String,
    pub namespace: String,
    pub tags: Vec<String>,
    /// File name, content type, or `message` for the raw message.
    pub part: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanReport {
    pub message_id: MessageId,
    pub auth: Option<AuthResults>,
    pub parts: Vec<PartInfo>,
    pub urls: Vec<String>,
    pub engines: Vec<EngineFinding>,
    /// Every YARA rule match, for policy to act on by rule name or tag.
    #[serde(default)]
    pub yara: Vec<YaraMatch>,
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
    /// Australian identifier findings. `None` when DLP did not run.
    #[serde(default)]
    pub dlp: Option<DlpReport>,
    /// PSPF protective marking read from the `X-Protective-Marking` header
    /// and the subject. `None` when markings were not inspected.
    #[serde(default)]
    pub marking: Option<MarkingReport>,
}

/// PSPF security classifications, lowest first, so `Ord` compares levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Classification {
    Unofficial,
    Official,
    OfficialSensitive,
    Protected,
    Secret,
    TopSecret,
}

impl Classification {
    /// The form the Email Protective Marking Standard writes after `SEC=`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unofficial => "UNOFFICIAL",
            Self::Official => "OFFICIAL",
            Self::OfficialSensitive => "OFFICIAL:Sensitive",
            Self::Protected => "PROTECTED",
            Self::Secret => "SECRET",
            Self::TopSecret => "TOP-SECRET",
        }
    }

    /// Case-insensitive. Accepts `OFFICIAL:Sensitive`, `OFFICIAL Sensitive`,
    /// `OFFICIAL-Sensitive`, `TOP-SECRET` and `TOP SECRET`.
    pub fn parse(value: &str) -> Option<Self> {
        let canonical: String = value
            .trim()
            .chars()
            .map(|c| {
                if matches!(c, ' ' | '-' | '_') {
                    ':'
                } else {
                    c.to_ascii_uppercase()
                }
            })
            .collect();
        Some(match canonical.as_str() {
            "UNOFFICIAL" => Self::Unofficial,
            "OFFICIAL" => Self::Official,
            "OFFICIAL:SENSITIVE" => Self::OfficialSensitive,
            "PROTECTED" => Self::Protected,
            "SECRET" => Self::Secret,
            "TOP:SECRET" => Self::TopSecret,
            _ => return None,
        })
    }
}

/// What the gateway found in a message's protective markings.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MarkingReport {
    /// The effective classification: the header's when it is valid,
    /// otherwise the subject's.
    pub classification: Option<Classification>,
    pub header: Option<Classification>,
    pub subject: Option<Classification>,
    pub caveats: Vec<String>,
    pub access: Vec<String>,
    /// A marking was present but did not follow the standard.
    pub invalid: bool,
    /// Header and subject both carry a marking and they disagree.
    pub mismatch: bool,
    /// Parse errors, for the explanation and the audit trail.
    pub errors: Vec<String>,
}

/// Identifier kinds found by `currawong-dlp`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DlpKind {
    Tfn,
    Medicare,
    Abn,
    Acn,
    DriverLicence,
    Card,
}

impl DlpKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tfn => "tfn",
            Self::Medicare => "medicare",
            Self::Abn => "abn",
            Self::Acn => "acn",
            Self::DriverLicence => "driver_licence",
            Self::Card => "card",
        }
    }
}

/// A redacted sample such as `123 *** ***`. The full value is never stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DlpSample {
    pub kind: DlpKind,
    pub redacted: String,
    pub confidence: u8,
}

/// Counts and redacted samples only, so the report is safe to log and export.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DlpReport {
    /// Distinct identifiers per kind at or above the profile's confidence.
    pub counts: BTreeMap<DlpKind, u32>,
    pub samples: Vec<DlpSample>,
    /// Some text was not scanned (size limit, or a document that could not
    /// be extracted). The default policy pack holds the message.
    #[serde(default)]
    pub incomplete: bool,
}

impl ScanReport {
    pub fn new(message_id: MessageId) -> Self {
        Self {
            message_id,
            auth: None,
            parts: Vec::new(),
            urls: Vec::new(),
            engines: Vec::new(),
            yara: Vec::new(),
            malware: false,
            active_content: false,
            fail_closed: false,
            defer: false,
            notes: Vec::new(),
            dlp: None,
            marking: None,
            modified: false,
        }
    }
}
