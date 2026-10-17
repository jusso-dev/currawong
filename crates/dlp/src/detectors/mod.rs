//! One module per identifier. Each has `find` over text and `validate` over
//! the bare digits. A `Match` holds offsets, never the identifier itself.
pub mod abn;
pub mod acn;
pub mod card;
pub mod licence;
pub mod medicare;
pub mod tfn;

pub use currawong_core::DlpKind;

/// Added to a match when a context word is close by.
pub const CONTEXT_BOOST: u8 = 30;
const CONTEXT_BEFORE: usize = 60;
const CONTEXT_AFTER: usize = 30;

/// Byte offsets into the scanned text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Match {
    pub kind: DlpKind,
    pub start: usize,
    pub end: usize,
    /// 0 to 100.
    pub confidence: u8,
}

/// Digit groups joined by single spaces or hyphens. `123 456-782` gives
/// digits `123456782`.
pub(crate) struct Candidate {
    pub start: usize,
    pub end: usize,
    pub digits: String,
}

/// Candidate lengths: TFNs and ACNs are 9 digits, cards at most 19.
const MIN_DIGITS: usize = 9;
const MAX_DIGITS: usize = 19;
/// Bounds work on hostile input such as `1 1 1 1 ...`.
const MAX_CANDIDATES: usize = 50_000;

/// Every run of consecutive digit groups up to `MAX_DIGITS`, so that
/// `123456782 876543210` yields both numbers as well as the joined run.
/// Groups glued to letters (`INV123`) are not used.
pub(crate) fn digit_runs(text: &str) -> Vec<Candidate> {
    let b = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if !b[i].is_ascii_digit() {
            i += 1;
            continue;
        }
        let mut groups = Vec::new();
        loop {
            let start = i;
            while i < b.len() && b[i].is_ascii_digit() {
                i += 1;
            }
            groups.push((start, i));
            let joined = i + 1 < b.len() && (b[i] == b' ' || b[i] == b'-');
            if !(joined && b[i + 1].is_ascii_digit()) {
                break;
            }
            i += 1;
        }
        let first = usize::from(groups[0].0 > 0 && b[groups[0].0 - 1].is_ascii_alphabetic());
        let last_end = groups[groups.len() - 1].1;
        let glued_after = b.get(last_end).is_some_and(u8::is_ascii_alphabetic);
        for from in first..groups.len() {
            let mut digits = String::new();
            for (to, (start, end)) in groups.iter().enumerate().skip(from) {
                if digits.len() + (end - start) > MAX_DIGITS {
                    break;
                }
                digits.push_str(&text[*start..*end]);
                if to == groups.len() - 1 && glued_after {
                    break;
                }
                if digits.len() < MIN_DIGITS {
                    continue;
                }
                if out.len() >= MAX_CANDIDATES {
                    return out;
                }
                out.push(Candidate {
                    start: groups[from].0,
                    end: *end,
                    digits: digits.clone(),
                });
            }
        }
    }
    out
}

/// Builds a match, boosting confidence when a context word is near.
pub(crate) fn scored(
    kind: DlpKind,
    text: &str,
    start: usize,
    end: usize,
    base: u8,
    words: &[&str],
) -> Match {
    let confidence = if has_context(text, start, end, words) {
        base.saturating_add(CONTEXT_BOOST).min(100)
    } else {
        base
    };
    Match {
        kind,
        start,
        end,
        confidence,
    }
}

/// True when one of `words` appears as a whole word shortly before or after.
pub(crate) fn has_context(text: &str, start: usize, end: usize, words: &[&str]) -> bool {
    let b = text.as_bytes();
    let window = &b[start.saturating_sub(CONTEXT_BEFORE)..(end + CONTEXT_AFTER).min(b.len())];
    words
        .iter()
        .any(|word| contains_word(window, word.as_bytes()))
}

fn contains_word(hay: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || hay.len() < needle.len() {
        return false;
    }
    (0..=hay.len() - needle.len()).any(|pos| {
        hay[pos..pos + needle.len()].eq_ignore_ascii_case(needle)
            && (pos == 0 || !hay[pos - 1].is_ascii_alphanumeric())
            && hay
                .get(pos + needle.len())
                .is_none_or(|b| !b.is_ascii_alphanumeric())
    })
}

/// Weighted digit sum, or `None` unless `digits` is exactly `weights.len()`
/// ASCII digits.
pub(crate) fn weighted_sum(digits: &str, weights: &[u32]) -> Option<u32> {
    if digits.len() != weights.len() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(
        digits
            .bytes()
            .zip(weights)
            .map(|(b, w)| u32::from(b - b'0') * w)
            .sum(),
    )
}

/// Digit-run detector shared by the checksum types.
pub(crate) fn find_runs(
    text: &str,
    kind: DlpKind,
    base: u8,
    words: &[&str],
    validate: fn(&str) -> bool,
) -> Vec<Match> {
    digit_runs(text)
        .into_iter()
        .filter(|c| validate(&c.digits))
        .map(|c| scored(kind, text, c.start, c.end, base, words))
        .collect()
}
