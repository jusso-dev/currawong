//! The engine reads named signals, not report fields. A new stage (spam, BEC,
//! DLP, markings) plugs in by adding its report field to `Signals::from_report`
//! under a stable name; policies can then use it with no engine change.
//!
//! Names produced today:
//! - flags: `malware`, `active_content`, `fail_closed`, `defer`, plus part
//!   flags `ext_mismatch`, `encrypted`, `has_macro`, `has_ole_object`,
//!   `executable`, `limit_exceeded`, `html_smuggling`, `qr_code`,
//!   `qr.skipped` (images not checked once the QR budget ran out),
//!   `svg_active`, `external_template`, `dde_field`, `protocol_handler`,
//!   `onenote_embedded`, `shortcut`, `disk_image`, `pdf_javascript`,
//!   `pdf_launch`, `pdf_embedded_file`, `pdf_auto_action`, `pdf_form` and
//!   `pdf_remote_action` (document and file-type checks); `qr_url`
//!   when a QR code held a link; `yara` when any YARA rule matched and
//!   `yara.<tag>` for each tag on a matching rule (for example `yara.bec`);
//!   `dlp.incomplete` when some text could not be scanned for identifiers;
//!   `pspf.invalid` (a protective marking that breaks the standard),
//!   `pspf.mismatch` (header and subject markings disagree) and
//!   `pspf.missing` (no protective marking at all), `pspf.caveat` and
//!   `pspf.caveat.<caveat>` (for example `pspf.caveat.sh:cabinet`), and
//!   `pspf.access.<marker>` (for example `pspf.access.legal-privilege`).
//!   Classify adds `lookalike` when a sender or link domain imitates a
//!   protected one, and passes on report flags such as `classify_skipped`
//!   and `link_scan_truncated`. Link rewriting adds `url_rewrite.skipped`
//!   when some links were left without a click-time check.
//!   Threat-intel feeds add `intel.hash`, `intel.url`, `intel.domain` and
//!   `intel.ip` by indicator kind, and `intel.<source>` per feed (for example
//!   `intel.urlhaus` or `intel.spamhaus-dbl`); `intel.dbl_low_reputation`
//!   when Spamhaus DBL lists a link domain only as low reputation.
//! - marking: the PSPF classification (`PROTECTED`, `OFFICIAL:Sensitive`...),
//!   for the `marking` and `marking_at_least` conditions.
//! - counts: `parts`, `urls`, `yara` (matches), `intel_hits`, and distinct identifiers
//!   found by DLP as `dlp.tfn`, `dlp.medicare`, `dlp.abn`, `dlp.acn`,
//!   `dlp.driver_licence`, `dlp.card` (present only when found).
//! - scores: `spam` (the classify total: Bayes points plus rule scores) and
//!   `lookalike` (the strongest finding, 0 to 1); `bec` (0 to 1, inbound only)
//!   with flags `bec.<reason>` such as `bec.display_name_spoof` and
//!   `bec.payment_change`.
//!
//! HTTP engines add `rspamd` (raw score), `rspamd.ratio`,
//! `rspamd.action.<action>`, positive `rspamd.<symbol>` (lower case, 256 max),
//! `rspamd.phishing` (PHISHING/PHISHED_*), `sandbox` (maximum score, 0..1),
//! `sandbox.malicious`, `sandbox.pending` and `sandbox.timeout`.
use currawong_core::{AuthResults, PartFlag, ScanReport, UrlSource};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Signals {
    pub flags: BTreeSet<String>,
    pub scores: BTreeMap<String, f64>,
    pub counts: BTreeMap<String, u64>,
    pub auth: Option<AuthResults>,
    pub marking: Option<String>,
}

impl Signals {
    pub fn from_report(report: &ScanReport) -> Self {
        let mut signals = Self {
            auth: report.auth.clone(),
            ..Self::default()
        };
        for (name, set) in [
            ("malware", report.malware),
            ("active_content", report.active_content),
            ("fail_closed", report.fail_closed),
            ("defer", report.defer),
        ] {
            if set {
                signals.flag(name);
            }
        }
        for flag in report.parts.iter().flat_map(|part| &part.flags) {
            signals.flag(part_flag(*flag));
        }
        for flag in &report.flags {
            signals.flag(flag);
        }
        if let Some(spam) = &report.spam {
            signals.score("spam", spam.total);
        }
        if let Some(rspamd) = &report.rspamd {
            signals.score("rspamd", rspamd.score);
            if rspamd.required_score > 0.0 {
                let ratio = rspamd.score / rspamd.required_score;
                if ratio.is_finite() {
                    signals.score("rspamd.ratio", ratio);
                }
            }
            signals.flag(&format!("rspamd.action.{}", rspamd.action));
            for symbol in rspamd.symbols.iter().filter(|s| s.score > 0.0).take(256) {
                let name = symbol.name.to_ascii_lowercase();
                // Restrict names to a single symbol namespace.
                if name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_') {
                    signals.flag(&format!("rspamd.{name}"));
                    if name == "phishing" || name.starts_with("phished_") {
                        signals.flag("rspamd.phishing");
                    }
                }
            }
        }
        if !report.sandbox.is_empty() {
            signals.score(
                "sandbox",
                report.sandbox.iter().map(|r| r.score).fold(0.0, f64::max),
            );
            for result in &report.sandbox {
                if result.malicious {
                    signals.flag("sandbox.malicious");
                }
                if result.status == "pending" {
                    signals.flag("sandbox.pending");
                }
                if result.status == "timeout" {
                    signals.flag("sandbox.timeout");
                }
            }
        }
        if let Some(bec) = &report.bec {
            signals.score("bec", bec.score);
            for reason in &bec.reasons {
                signals.flag(&format!("bec.{}", reason.as_str()));
            }
        }
        if let Some(strongest) = report.lookalikes.iter().map(|f| f.score).reduce(f64::max) {
            signals.flag("lookalike");
            signals.score("lookalike", strongest);
        }
        signals.count("parts", report.parts.len() as u64);
        signals.count("urls", report.urls.len() as u64);
        let qr_urls = report
            .url_sources
            .iter()
            .filter(|found| found.source == UrlSource::Qr)
            .count();
        if qr_urls > 0 {
            signals.flag("qr_url");
            signals.count("qr_urls", qr_urls as u64);
        }
        if let Some(dlp) = &report.dlp {
            for (kind, count) in &dlp.counts {
                signals.count(&format!("dlp.{}", kind.as_str()), u64::from(*count));
            }
            if dlp.incomplete {
                signals.flag("dlp.incomplete");
            }
        }
        if let Some(marking) = &report.marking {
            signals.marking = marking.classification.map(|c| c.as_str().to_string());
            for (name, set) in [
                ("pspf.invalid", marking.invalid),
                ("pspf.mismatch", marking.mismatch),
                ("pspf.missing", marking.classification.is_none()),
            ] {
                if set {
                    signals.flag(name);
                }
            }
            for caveat in &marking.caveats {
                signals.flag("pspf.caveat");
                signals.flag(&format!("pspf.caveat.{}", caveat.to_ascii_lowercase()));
            }
            for access in &marking.access {
                signals.flag(&format!("pspf.access.{}", access.to_ascii_lowercase()));
            }
        }
        if !report.yara.is_empty() {
            signals.flag("yara");
            signals.count("yara", report.yara.len() as u64);
        }
        for tag in report.yara.iter().flat_map(|hit| &hit.tags) {
            signals.flag(&format!("yara.{tag}"));
        }
        for hit in &report.intel {
            let kind = match hit.kind.as_str() {
                "sha256" => "hash",
                other => other,
            };
            signals.flag(&format!("intel.{kind}"));
            signals.flag(&format!("intel.{}", hit.source));
        }
        if !report.intel.is_empty() {
            signals.count("intel_hits", report.intel.len() as u64);
        }
        signals
    }

    pub fn flag(&mut self, name: &str) {
        self.flags.insert(name.to_string());
    }

    pub fn score(&mut self, name: &str, value: f64) {
        self.scores.insert(name.to_string(), value);
    }

    pub fn count(&mut self, name: &str, value: u64) {
        self.counts.insert(name.to_string(), value);
    }

    /// Result for one auth method, lower case. DKIM passes if any signature passes.
    pub fn auth_result(&self, method: &str) -> Vec<String> {
        let Some(auth) = &self.auth else {
            return vec!["none".into()];
        };
        let results: Vec<&str> = match method {
            "spf" => vec![&auth.spf.result],
            "dkim" if auth.dkim.is_empty() => vec!["none"],
            "dkim" => auth.dkim.iter().map(|r| r.result.as_str()).collect(),
            "dmarc" => vec![&auth.dmarc.result],
            "arc" => vec![&auth.arc.result],
            "dmarc_policy" if auth.dmarc_policy.is_empty() => vec!["none"],
            "dmarc_policy" => vec![&auth.dmarc_policy],
            _ => Vec::new(),
        };
        results.into_iter().map(str::to_ascii_lowercase).collect()
    }
}

fn part_flag(flag: PartFlag) -> &'static str {
    match flag {
        PartFlag::ExtMismatch => "ext_mismatch",
        PartFlag::Encrypted => "encrypted",
        PartFlag::HasMacro => "has_macro",
        PartFlag::HasOleObject => "has_ole_object",
        PartFlag::Executable => "executable",
        PartFlag::LimitExceeded => "limit_exceeded",
        PartFlag::HtmlSmuggling => "html_smuggling",
        PartFlag::QrCode => "qr_code",
        PartFlag::QrSkipped => "qr.skipped",
        PartFlag::Unscannable => "unscannable",
        PartFlag::SvgActive => "svg_active",
        PartFlag::ExternalTemplate => "external_template",
        PartFlag::DdeField => "dde_field",
        PartFlag::ProtocolHandler => "protocol_handler",
        PartFlag::OneNoteEmbedded => "onenote_embedded",
        PartFlag::Shortcut => "shortcut",
        PartFlag::DiskImage => "disk_image",
        PartFlag::PdfJavaScript => "pdf_javascript",
        PartFlag::PdfLaunch => "pdf_launch",
        PartFlag::PdfEmbeddedFile => "pdf_embedded_file",
        PartFlag::PdfAutoAction => "pdf_auto_action",
        PartFlag::PdfForm => "pdf_form",
        PartFlag::PdfRemoteAction => "pdf_remote_action",
    }
}
