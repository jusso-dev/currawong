//! The engine reads named signals, not report fields. A new stage (spam, BEC,
//! DLP, markings) plugs in by adding its report field to `Signals::from_report`
//! under a stable name; policies can then use it with no engine change.
//!
//! Names produced today:
//! - flags: `malware`, `active_content`, `fail_closed`, `defer`, plus part
//!   flags `ext_mismatch`, `encrypted`, `has_macro`, `has_ole_object`,
//!   `executable`, `limit_exceeded`; `yara` when any YARA rule matched and
//!   `yara.<tag>` for each tag on a matching rule (for example `yara.bec`).
//! - counts: `parts`, `urls`, `yara` (matches).
//! - scores: none yet. Reserved: `spam`, `bec`, `lookalike`. DLP counts use `dlp.<kind>`.
use currawong_core::{AuthResults, PartFlag, ScanReport};
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
        signals.count("parts", report.parts.len() as u64);
        signals.count("urls", report.urls.len() as u64);
        if !report.yara.is_empty() {
            signals.flag("yara");
            signals.count("yara", report.yara.len() as u64);
        }
        for tag in report.yara.iter().flat_map(|hit| &hit.tags) {
            signals.flag(&format!("yara.{tag}"));
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
    }
}
