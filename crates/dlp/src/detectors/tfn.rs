//! Tax file numbers: nine digits with ATO weighted modulus 11, or the older
//! eight-digit form with its own weights. One random nine-digit number in
//! eleven passes, so a bare number does not count at the default
//! confidence: it needs "TFN" nearby or in the same text. Eight-digit TFNs
//! need the word nearby.
use super::{find_rules, weighted_sum, DlpKind, Match, Rule, Scan};

const WEIGHTS_9: [u32; 9] = [1, 4, 3, 7, 5, 8, 6, 9, 10];
const WEIGHTS_8: [u32; 8] = [10, 7, 8, 4, 6, 3, 5, 1];
const CONTEXT: &[&str] = &["tfn", "tfns", "tax file", "tax file number"];

pub(crate) const RULE_9: Rule = Rule {
    kind: DlpKind::Tfn,
    lengths: 9..=9,
    base: 40,
    words: CONTEXT,
    validate,
};
pub(crate) const RULE_8: Rule = Rule {
    kind: DlpKind::Tfn,
    lengths: 8..=8,
    base: 20,
    words: CONTEXT,
    validate,
};

pub fn find(text: &str) -> Vec<Match> {
    find_in(&Scan::new(text))
}

pub fn find_in(scan: &Scan) -> Vec<Match> {
    find_rules(scan, &[&RULE_9, &RULE_8])
        .into_iter()
        .map(|(_, m)| m)
        .collect()
}

pub fn validate(digits: &str) -> bool {
    // Every eight-digit repdigit passes the old check (weights sum to 44).
    // Repdigits are not issued, so none is accepted.
    if digits
        .bytes()
        .all(|b| Some(&b) == digits.as_bytes().first())
    {
        return false;
    }
    let sum = match digits.len() {
        9 => weighted_sum(digits, &WEIGHTS_9),
        8 => weighted_sum(digits, &WEIGHTS_8),
        _ => None,
    };
    sum.is_some_and(|sum| sum.is_multiple_of(11))
}
