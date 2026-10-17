//! Medicare card numbers: eight digits starting 2 to 6, a check digit, the
//! issue number, then an optional individual reference number (IRN, 1 to 9).
//! The check digit covers the first eight digits only.
use super::{find_runs, weighted_sum, DlpKind, Match};

const WEIGHTS: [u32; 8] = [1, 3, 7, 9, 1, 3, 7, 9];
const CONTEXT: &[&str] = &["medicare", "irn"];

pub fn find(text: &str) -> Vec<Match> {
    find_runs(text, DlpKind::Medicare, 60, CONTEXT, validate)
}

pub fn validate(digits: &str) -> bool {
    let b = digits.as_bytes();
    if !(b.len() == 10 || b.len() == 11) || !b.iter().all(u8::is_ascii_digit) {
        return false;
    }
    if !(b'2'..=b'6').contains(&b[0]) || (b.len() == 11 && b[10] == b'0') {
        return false;
    }
    weighted_sum(&digits[..8], &WEIGHTS).is_some_and(|sum| sum % 10 == u32::from(b[8] - b'0'))
}
