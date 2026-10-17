//! Australian identifier detection with checksum validation, and the
//! protective-marking parser used by the fuzzer.
//!
//! `scan` returns counts and redacted samples only. Full identifiers stay in
//! memory for the length of the scan and are never logged or stored.
pub mod detectors;

pub use currawong_core::config::DlpProfile;
pub use currawong_core::{DlpKind, DlpReport, DlpSample, Error};
pub use detectors::Match;

use std::collections::HashSet;

/// Text beyond this is not scanned. The parser bounds extraction too.
pub const MAX_SCAN_BYTES: usize = 4 * 1024 * 1024;
const MAX_SAMPLES_PER_KIND: usize = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectiveMarking {
    Official,
    OfficialSensitive,
    Protected,
}

pub fn parse_pspf(value: &str) -> Option<ProtectiveMarking> {
    let value = value.trim();
    let value = value
        .strip_prefix("X-Protective-Marking:")
        .unwrap_or(value)
        .trim();
    match value.to_ascii_lowercase().as_str() {
        "official" => Some(ProtectiveMarking::Official),
        "official: sensitive" | "official:sensitive" => Some(ProtectiveMarking::OfficialSensitive),
        "protected" => Some(ProtectiveMarking::Protected),
        _ => None,
    }
}

/// Every detector. Where two matches overlap the higher confidence wins, and
/// on a tie the checksum types win over licences (earlier in this list).
pub fn find_all(text: &str) -> Vec<Match> {
    let text = bounded(text);
    let mut all: Vec<(usize, Match)> = [
        detectors::card::find(text),
        detectors::abn::find(text),
        detectors::medicare::find(text),
        detectors::tfn::find(text),
        detectors::acn::find(text),
        detectors::licence::find(text),
    ]
    .into_iter()
    .enumerate()
    .flat_map(|(rank, found)| found.into_iter().map(move |m| (rank, m)))
    .collect();
    all.sort_by_key(|(rank, m)| (std::cmp::Reverse(m.confidence), *rank, m.start));
    let mut kept: Vec<Match> = Vec::new();
    for (_, m) in all {
        if kept.iter().all(|k| m.end <= k.start || m.start >= k.end) {
            kept.push(m);
        }
    }
    kept.sort_by_key(|m| m.start);
    kept
}

pub fn scan(text: &str, profile: &DlpProfile) -> DlpReport {
    let text = bounded(text);
    let mut report = DlpReport::default();
    let mut seen = HashSet::new();
    for m in find_all(text) {
        if m.confidence < profile.min_confidence {
            continue;
        }
        let value: String = text[m.start..m.end]
            .chars()
            .filter(char::is_ascii_alphanumeric)
            .collect();
        // The same identifier in the text and HTML parts counts once.
        if !seen.insert((m.kind, value)) {
            continue;
        }
        *report.counts.entry(m.kind).or_default() += 1;
        if report.samples.iter().filter(|s| s.kind == m.kind).count() < MAX_SAMPLES_PER_KIND {
            report.samples.push(DlpSample {
                kind: m.kind,
                redacted: redact(&text[m.start..m.end]),
                confidence: m.confidence,
            });
        }
    }
    report.review = report
        .counts
        .iter()
        .filter(|(kind, count)| {
            let threshold = profile.review_thresholds.get(**kind);
            threshold > 0 && **count >= threshold
        })
        .map(|(kind, _)| *kind)
        .collect();
    report
}

/// Keeps the first three characters and masks the rest in groups of three:
/// `123 456 782` becomes `123 *** ***`.
pub fn redact(value: &str) -> String {
    let chars: Vec<char> = value.chars().filter(char::is_ascii_alphanumeric).collect();
    let mut out: String = chars.iter().take(3).collect();
    for i in 0..chars.len().saturating_sub(3) {
        if i % 3 == 0 {
            out.push(' ');
        }
        out.push('*');
    }
    out
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
            Some(ProtectiveMarking::OfficialSensitive)
        );
        assert_eq!(parse_pspf("PROTECTED"), Some(ProtectiveMarking::Protected));
        assert_eq!(parse_pspf("SECRET"), None);
    }
}
