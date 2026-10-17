//! State and territory driver's licences. There is no check digit and the
//! formats overlap (NSW, QLD, WA, VIC, NT and ACT are 5 to 10 digits; SA and
//! TAS may lead with letters), so a token only matches with a context word.
use super::{DlpKind, Match, Scan, CONTEXT_BOOST};

const CONTEXT: &[&str] = &[
    "licence", "license", "driver", "drivers", "driver's", "driving", "dl", "lic",
];

pub fn find(text: &str) -> Vec<Match> {
    find_in(&Scan::new(text))
}

pub fn find_in(scan: &Scan) -> Vec<Match> {
    let text = scan.text();
    let context = scan.context(CONTEXT);
    if !context.anywhere() {
        return Vec::new();
    }
    let mut out = Vec::new();
    let b = text.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if !b[i].is_ascii_alphanumeric() {
            i += 1;
            continue;
        }
        let start = i;
        while i < b.len() && b[i].is_ascii_alphanumeric() {
            i += 1;
        }
        if validate(&text[start..i]) && context.near(start, i) {
            out.push(Match {
                kind: DlpKind::DriverLicence,
                start,
                end: i,
                confidence: 30 + CONTEXT_BOOST,
            });
        }
    }
    out
}

/// Up to two leading letters, then digits, 6 to 10 characters in all.
pub fn validate(digits: &str) -> bool {
    let letters = digits
        .bytes()
        .take_while(|b| b.is_ascii_alphabetic())
        .count();
    letters <= 2
        && (6..=10).contains(&digits.len())
        && digits.len() - letters >= 5
        && digits.bytes().skip(letters).all(|b| b.is_ascii_digit())
}
