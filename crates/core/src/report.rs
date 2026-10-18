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
    /// RFC 5322 From domain the DMARC result applies to, from the verifier
    /// rather than reparsed header text. Empty when DMARC was not evaluated.
    #[serde(default)]
    pub dmarc_domain: String,
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
    /// HTML that builds a file in the browser from an inline payload.
    HtmlSmuggling,
    /// An image or PDF page with a readable QR code.
    QrCode,
    /// Not checked for QR codes: the message's QR budget was used up.
    QrSkipped,
    /// An archive or document that could not be opened (unsupported format,
    /// corrupt, RAR). Treated as a fail-closed scan.
    Unscannable,
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
            Self::HtmlSmuggling => "HtmlSmuggling",
            Self::QrCode => "QrCode",
            Self::QrSkipped => "QrSkipped",
            Self::Unscannable => "Unscannable",
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

/// Why a message looks like business email compromise.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum BecReason {
    /// The display name is a directory person's, but the address is not theirs
    /// and is outside the tenant.
    DisplayNameSpoof,
    /// The From or Reply-To domain imitates a protected domain.
    LookalikeSender,
    /// Replies go to free mail or another domain than the sender's.
    ReplyToMismatch,
    /// Asks to change bank or payment details, or quotes BSB and account numbers.
    PaymentChange,
    /// Asks for gift cards or vouchers.
    GiftCard,
    Urgency,
    Secrecy,
    /// No earlier delivered mail from this sender to the tenant.
    FirstTimeSender,
    /// DMARC failed for the From domain.
    AuthFailure,
}

impl BecReason {
    /// Policy flag suffix, `bec.<name>`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DisplayNameSpoof => "display_name_spoof",
            Self::LookalikeSender => "lookalike_sender",
            Self::ReplyToMismatch => "reply_to_mismatch",
            Self::PaymentChange => "payment_change",
            Self::GiftCard => "gift_card",
            Self::Urgency => "urgency",
            Self::Secrecy => "secrecy",
            Self::FirstTimeSender => "first_time_sender",
            Self::AuthFailure => "auth_failure",
        }
    }
}

/// Score from 0 to 1 with the reasons that added to it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BecReport {
    pub score: f64,
    pub reasons: Vec<BecReason>,
    /// Human-readable explanation per reason, without message content.
    pub explanation: Vec<String>,
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

/// Where the parser found a URL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UrlSource {
    /// The raw message or a decoded MIME part.
    Text,
    /// A QR code in an image or a PDF page.
    Qr,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct FoundUrl {
    pub url: String,
    pub source: UrlSource,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanReport {
    pub message_id: MessageId,
    pub auth: Option<AuthResults>,
    pub parts: Vec<PartInfo>,
    pub urls: Vec<String>,
    /// The parser's URLs with where each was found, for example a QR code.
    #[serde(default)]
    pub url_sources: Vec<FoundUrl>,
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
    /// Set by the classify stage when it runs.
    #[serde(default)]
    pub spam: Option<SpamReport>,
    #[serde(default)]
    pub lookalikes: Vec<LookalikeFinding>,
    /// Business email compromise score and reasons, for inbound mail.
    #[serde(default)]
    pub bec: Option<BecReport>,
    /// Named conditions from later stages, exposed to policy as flags, for
    /// example `classify_skipped` or `link_scan_truncated`.
    #[serde(default)]
    pub flags: Vec<String>,
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
            url_sources: Vec::new(),
            engines: Vec::new(),
            yara: Vec::new(),
            malware: false,
            active_content: false,
            fail_closed: false,
            defer: false,
            notes: Vec::new(),
            dlp: None,
            spam: None,
            lookalikes: Vec::new(),
            bec: None,
            flags: Vec::new(),
            marking: None,
            modified: false,
        }
    }
}
