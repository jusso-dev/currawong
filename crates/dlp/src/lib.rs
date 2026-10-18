//! Australian identifier detection with checksum validation, and the
//! PSPF protective-marking parser (`pspf`).
//!
//! `scan` returns counts and redacted samples only. Full identifiers stay in
//! memory for the length of the scan and are never logged or stored.
//!
//! `encrypt` carries out the policy encryption actions: S/MIME to a known
//! recipient certificate, or the secure pull portal.
pub mod detectors;
pub mod encrypt;
pub mod pspf;

pub use currawong_core::config::DlpProfile;
use currawong_core::Classification;
pub use currawong_core::{DlpKind, DlpReport, DlpSample, Error};
pub use detectors::{Match, Scan};
pub use pspf::ProtectiveMarking;

use std::collections::{BTreeMap, HashSet};

/// Text beyond this is not scanned and the report is marked incomplete.
/// The parser bounds extraction to less than this.
pub const MAX_SCAN_BYTES: usize = 2 * 1024 * 1024;
const MAX_SAMPLES_PER_KIND: usize = 5;

/// The classification in an `X-Protective-Marking` value, or a bare
/// classification word such as `OFFICIAL: Sensitive`.
pub fn parse_pspf(value: &str) -> Option<Classification> {
    match pspf::parse_header(value) {
        Ok(marking) => Some(marking.sec),
        Err(_) => Classification::parse(
            value
                .trim()
                .trim_start_matches("X-Protective-Marking:")
                .trim()
                .replace(": ", ":")
                .as_str(),
        ),
    }
}

/// Every detector. Where two matches overlap the higher confidence wins, and
/// on a tie the checksum types win over licences (earlier in this list).
pub fn find_all(text: &str) -> Vec<Match> {
    let scan = Scan::new(bounded(text));
    let rules = detectors::checksum_rules();
    let mut all = detectors::find_rules(&scan, &rules);
    all.extend(
        detectors::licence::find_in(&scan)
            .into_iter()
            .map(|m| (rules.len(), m)),
    );
    all.sort_by_key(|(rank, m)| (std::cmp::Reverse(m.confidence), *rank, m.start));
    // Kept spans never overlap, so the one starting closest before `end` is
    // the only one that can collide.
    let mut kept: BTreeMap<usize, Match> = BTreeMap::new();
    for (_, m) in all {
        let clash = kept
            .range(..m.end)
            .next_back()
            .is_some_and(|(_, k)| k.end > m.start);
        if !clash {
            kept.insert(m.start, m);
        }
    }
    kept.into_values().collect()
}

pub fn scan(text: &str, profile: &DlpProfile) -> DlpReport {
    let mut report = DlpReport {
        incomplete: text.len() > MAX_SCAN_BYTES,
        ..DlpReport::default()
    };
    let text = bounded(text);
    let mut seen = HashSet::new();
    for m in find_all(text) {
        if m.confidence < profile.min_confidence {
            continue;
        }
        let value = normalised(&text[m.start..m.end]);
        // The same identifier in the text and HTML parts counts once.
        if !seen.insert((m.kind, value)) {
            continue;
        }
        *report.counts.entry(m.kind).or_default() += 1;
        if report.samples.iter().filter(|s| s.kind == m.kind).count() < MAX_SAMPLES_PER_KIND {
            report.samples.push(DlpSample {
                kind: m.kind,
                redacted: redact(m.kind, &text[m.start..m.end]),
                confidence: m.confidence,
            });
        }
    }
    report
}

/// Shows at most a third of the value, and at most three characters, then
/// masks the rest in groups of three: `123 456 782` becomes `123 *** ***`.
/// Licences have no structure worth showing and are fully masked.
pub fn redact(kind: DlpKind, value: &str) -> String {
    let chars: Vec<char> = normalised(value).chars().collect();
    let shown = if kind == DlpKind::DriverLicence {
        0
    } else {
        (chars.len() / 3).min(3)
    };
    let mut out: String = chars.iter().take(shown).collect();
    for i in 0..chars.len() - shown {
        if i % 3 == 0 && !out.is_empty() {
            out.push(' ');
        }
        out.push('*');
    }
    out
}

/// ASCII letters and digits only, with Unicode digits mapped to ASCII.
fn normalised(value: &str) -> String {
    value
        .chars()
        .filter_map(|c| {
            if c.is_ascii_alphanumeric() {
                Some(c)
            } else {
                detectors::digit_value(c).map(|d| char::from(b'0' + d))
            }
        })
        .collect()
}

fn bounded(text: &str) -> &str {
    let mut end = text.len().min(MAX_SCAN_BYTES);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

pub fn fuzz_scan(data: &[u8]) {
    let end = data.len().min(64 * 1024);
    let text = String::from_utf8_lossy(&data[..end]);
    let _ = scan(&text, &DlpProfile::default());
    let _ = parse_pspf(&text);
    let _ = pspf::parse_subject(&text);
    let _ = pspf::inspect(&data[..end]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn published_tfn_sample_is_redacted_and_pspf_values_parse() {
        let report = scan("TFN 123 456 782 only", &DlpProfile::default());
        assert_eq!(report.counts.get(&DlpKind::Tfn), Some(&1));
        assert_eq!(report.samples[0].redacted, "123 *** ***");
        assert_eq!(
            parse_pspf("OFFICIAL: Sensitive"),
            Some(Classification::OfficialSensitive)
        );
        assert_eq!(parse_pspf("PROTECTED"), Some(Classification::Protected));
        assert_eq!(parse_pspf("CONFIDENTIAL"), None);
        assert_eq!(
            parse_pspf("VER=2018.6, NS=gov.au, SEC=SECRET"),
            Some(Classification::Secret)
        );
    }
}
