//! Medicare card numbers: eight digits starting 2 to 6, a check digit, the
//! issue number, then an optional individual reference number (IRN, 1 to 9).
//! The check digit covers the first eight digits only. As with TFNs, a bare
//! number needs "Medicare" nearby or in the same text to count.
use super::{find_rule, weighted_sum, DlpKind, Match, Rule, Scan};

const WEIGHTS: [u32; 8] = [1, 3, 7, 9, 1, 3, 7, 9];
const CONTEXT: &[&str] = &["medicare", "irn"];

pub fn find(text: &str) -> Vec<Match> {
    find_in(&Scan::new(text))
}

pub(crate) const RULE: Rule = Rule {
    kind: DlpKind::Medicare,
    lengths: 10..=11,
    base: 40,
    words: CONTEXT,
    validate,
};

pub fn find_in(scan: &Scan) -> Vec<Match> {
    find_rule(scan, &RULE)
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
