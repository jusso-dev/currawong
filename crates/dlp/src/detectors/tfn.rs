//! Tax file numbers: nine digits, ATO weighted modulus 11.
use super::{find_runs, weighted_sum, DlpKind, Match};

const WEIGHTS: [u32; 9] = [1, 4, 3, 7, 5, 8, 6, 9, 10];
const CONTEXT: &[&str] = &["tfn", "tax file", "tax file number"];

pub fn find(text: &str) -> Vec<Match> {
    find_runs(text, DlpKind::Tfn, 60, CONTEXT, validate)
}

pub fn validate(digits: &str) -> bool {
    !digits.bytes().all(|b| b == b'0')
        && weighted_sum(digits, &WEIGHTS).is_some_and(|sum| sum.is_multiple_of(11))
}
