//! Payment cards: Luhn plus the issuer (IIN) ranges and lengths of the main
//! schemes.
use super::{find_runs, DlpKind, Match};

const CONTEXT: &[&str] = &[
    "card",
    "credit",
    "debit",
    "visa",
    "mastercard",
    "amex",
    "expiry",
    "cvv",
    "ccv",
];

pub fn find(text: &str) -> Vec<Match> {
    find_runs(text, DlpKind::Card, 70, CONTEXT, validate)
}

pub fn validate(digits: &str) -> bool {
    (13..=19).contains(&digits.len())
        && digits.bytes().all(|b| b.is_ascii_digit())
        && known_iin(digits)
        && luhn(digits)
}

fn luhn(digits: &str) -> bool {
    let sum: u32 = digits
        .bytes()
        .rev()
        .enumerate()
        .map(|(i, b)| {
            let d = u32::from(b - b'0');
            if i % 2 == 1 {
                let doubled = d * 2;
                if doubled > 9 {
                    doubled - 9
                } else {
                    doubled
                }
            } else {
                d
            }
        })
        .sum();
    sum.is_multiple_of(10)
}

fn known_iin(d: &str) -> bool {
    let prefix = |n: usize| d[..n].parse::<u32>().unwrap_or(0);
    let len = d.len();
    if d.starts_with('4') {
        // Visa
        matches!(len, 13 | 16 | 19)
    } else if (51..=55).contains(&prefix(2)) || (2221..=2720).contains(&prefix(4)) {
        // Mastercard
        len == 16
    } else if matches!(prefix(2), 34 | 37) {
        // American Express
        len == 15
    } else if (300..=305).contains(&prefix(3)) || matches!(prefix(2), 36 | 38 | 39) {
        // Diners Club
        (14..=19).contains(&len)
    } else if prefix(4) == 6011 || prefix(2) == 65 || (644..=649).contains(&prefix(3)) {
        // Discover
        (16..=19).contains(&len)
    } else if (3528..=3589).contains(&prefix(4)) {
        // JCB
        (16..=19).contains(&len)
    } else if prefix(2) == 62 {
        // UnionPay
        (16..=19).contains(&len)
    } else {
        false
    }
}
