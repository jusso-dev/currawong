//! Payment cards: Luhn plus the issuer (IIN) ranges and lengths of the main
//! schemes.
use super::{find_rule, DlpKind, Match, Rule, Scan};

const CONTEXT: &[&str] = &[
    "card",
    "credit",
    "debit",
    "visa",
    "mastercard",
    "amex",
    "maestro",
    "expiry",
    "cvv",
    "ccv",
];

pub fn find(text: &str) -> Vec<Match> {
    find_in(&Scan::new(text))
}

pub(crate) const RULE: Rule = Rule {
    kind: DlpKind::Card,
    lengths: 12..=19,
    base: 70,
    words: CONTEXT,
    validate,
};

pub fn find_in(scan: &Scan) -> Vec<Match> {
    find_rule(scan, &RULE)
}

pub fn validate(digits: &str) -> bool {
    (12..=19).contains(&digits.len())
        && matches!(digits.as_bytes()[0], b'2'..=b'6')
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
    let prefix = |n: usize| {
        d.bytes()
            .take(n)
            .fold(0u32, |acc, b| acc * 10 + u32::from(b - b'0'))
    };
    let len = d.len();
    if d.starts_with('4') {
        // Visa
        matches!(len, 13 | 16 | 19)
    } else if (51..=55).contains(&prefix(2)) || (2221..=2720).contains(&prefix(4)) {
        // Mastercard
        len == 16
    } else if (2200..=2204).contains(&prefix(4)) {
        // Mir
        (16..=19).contains(&len)
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
        // UnionPay, and Discover's 622126 to 622925 range
        (16..=19).contains(&len)
    } else if prefix(4) == 5610 || (560221..=560225).contains(&prefix(6)) {
        // Australian Bankcard (withdrawn, numbers may still appear)
        len == 16
    } else if prefix(2) == 50
        || (56..=58).contains(&prefix(2))
        || matches!(prefix(4), 6304 | 6759)
        || matches!(prefix(6), 676770 | 676774)
    {
        // Maestro
        (12..=19).contains(&len)
    } else {
        false
    }
}
