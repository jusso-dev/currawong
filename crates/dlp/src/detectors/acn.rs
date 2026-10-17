//! Australian Company Numbers: nine digits, check = (10 - weighted sum mod 10)
//! mod 10. A one-in-ten check, so a bare ACN needs a context word to count
//! at the default confidence.
use super::{find_runs, weighted_sum, DlpKind, Match};

const WEIGHTS: [u32; 8] = [8, 7, 6, 5, 4, 3, 2, 1];
const CONTEXT: &[&str] = &["acn", "arbn", "australian company number", "company number"];

pub fn find(text: &str) -> Vec<Match> {
    find_runs(text, DlpKind::Acn, 40, CONTEXT, validate)
}

pub fn validate(digits: &str) -> bool {
    let b = digits.as_bytes();
    if b.len() != 9 || b.iter().all(|d| *d == b'0') {
        return false;
    }
    weighted_sum(&digits[..8], &WEIGHTS)
        .is_some_and(|sum| b[8].is_ascii_digit() && (10 - sum % 10) % 10 == u32::from(b[8] - b'0'))
}
