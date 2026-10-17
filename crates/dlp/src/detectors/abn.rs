//! Australian Business Numbers: subtract 1 from the first digit, then a
//! weighted sum modulus 89.
use super::{find_runs, weighted_sum, DlpKind, Match};

const WEIGHTS: [u32; 11] = [10, 1, 3, 5, 7, 9, 11, 13, 15, 17, 19];
const CONTEXT: &[&str] = &["abn", "australian business number"];

pub fn find(text: &str) -> Vec<Match> {
    find_runs(text, DlpKind::Abn, 65, CONTEXT, validate)
}

pub fn validate(digits: &str) -> bool {
    // A first digit of 0 cannot have 1 subtracted. Weight 10 is the first one.
    if !digits.starts_with(|c: char| ('1'..='9').contains(&c)) {
        return false;
    }
    weighted_sum(digits, &WEIGHTS).is_some_and(|sum| (sum - 10).is_multiple_of(89))
}
