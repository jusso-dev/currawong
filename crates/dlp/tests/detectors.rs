//! Table tests. Literals are published samples only: the ATO's TFN
//! `123 456 782` and ABN `51 824 753 556`, ASIC's ACN examples, the common
//! Medicare sample `2123 45670 1` and card scheme test numbers. Where more
//! distinct valid values are needed they are generated at run time (see
//! `synthetic_tfns`) and never committed.
use currawong_dlp::detectors::{
    abn, acn, card, licence, medicare, tfn, CONTEXT_BOOST, DOCUMENT_BOOST,
};
use currawong_dlp::{find_all, redact, scan, DlpKind, DlpProfile, MAX_SCAN_BYTES};
use std::time::{Duration, Instant};

const TFN: &str = "123456782";
const MEDICARE: &[&str] = &["2123456701", "21234567011"];
const ABN: &str = "51824753556";
const ACNS: &[&str] = &[
    "000000019",
    "000250000",
    "004085616",
    "005499981",
    "010499966",
];
/// Visa, Mastercard, Mastercard 2-series, Amex, Discover, JCB, Diners, UnionPay.
const CARDS: &[&str] = &[
    "4111111111111111",
    "5555555555554444",
    "2223003122003222",
    "378282246310005",
    "6011111111111117",
    "3530111333300000",
    "36227206271667",
    "6200000000000005",
];

/// Checksum-valid TFNs of `len` digits (8 or 9), derived at run time:
/// count down from the published sample's leading digits and keep each
/// prefix whose check digit exists. These are test values, not records.
fn synthetic_tfns(n: usize, len: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut prefix: u64 = TFN[..len - 1].parse().unwrap();
    while out.len() < n {
        prefix -= 1;
        for last in 0..10 {
            let candidate = format!("{prefix:0width$}{last}", width = len - 1);
            if tfn::validate(&candidate) && candidate != TFN {
                out.push(candidate);
                break;
            }
        }
    }
    out
}

/// Appends the Luhn check digit.
fn with_luhn(body: &str) -> String {
    (0..10)
        .map(|d| format!("{body}{d}"))
        .find(|c| {
            let sum: u32 = c
                .bytes()
                .rev()
                .enumerate()
                .map(|(i, b)| {
                    let d = u32::from(b - b'0') * if i % 2 == 1 { 2 } else { 1 };
                    if d > 9 {
                        d - 9
                    } else {
                        d
                    }
                })
                .sum();
            sum.is_multiple_of(10)
        })
        .unwrap()
}

type Validate = fn(&str) -> bool;

fn mutations(value: &str) -> impl Iterator<Item = (usize, i32, String)> + '_ {
    (0..value.len()).flat_map(move |pos| {
        let original = value.as_bytes()[pos];
        (b'0'..=b'9').filter(move |d| *d != original).map(move |d| {
            let mut bytes = value.as_bytes().to_vec();
            bytes[pos] = d;
            (
                pos,
                i32::from(d) - i32::from(original),
                String::from_utf8(bytes).unwrap(),
            )
        })
    })
}

fn tfn_count(text: &str) -> u32 {
    *scan(text, &DlpProfile::default())
        .counts
        .get(&DlpKind::Tfn)
        .unwrap_or(&0)
}

#[test]
fn valid_samples_pass_and_every_single_digit_change_fails() {
    let mut tfns = vec![TFN.to_string()];
    tfns.extend(synthetic_tfns(3, 9));
    tfns.extend(synthetic_tfns(3, 8));
    let mut cards: Vec<String> = CARDS.iter().map(|c| c.to_string()).collect();
    // Maestro (12 and 16 digits), Mir and Bankcard ranges, generated.
    for body in [
        "50000000000",
        "675900000000000",
        "220000000000000",
        "561000000000000",
    ] {
        cards.push(with_luhn(body));
    }
    let strict: [(&str, Vec<String>, Validate); 3] = [
        ("tfn", tfns, tfn::validate),
        ("abn", vec![ABN.to_string()], abn::validate),
        ("card", cards, card::validate),
    ];
    for (name, samples, validate) in &strict {
        for sample in samples {
            assert!(validate(sample), "{name} {sample}");
            for (pos, _, mutated) in mutations(sample) {
                assert!(!validate(&mutated), "{name} {mutated} (position {pos})");
            }
        }
    }
}

#[test]
fn medicare_check_digit_covers_the_first_nine_digits() {
    for sample in MEDICARE {
        assert!(medicare::validate(sample), "{sample}");
        for (pos, _, mutated) in mutations(sample) {
            if pos < 9 {
                assert!(!medicare::validate(&mutated), "{mutated}");
            }
        }
    }
    // The issue number and IRN are outside the check digit. An IRN of 0 is invalid.
    assert!(medicare::validate("2123456702"));
    assert!(!medicare::validate("21234567010"));
    // First digit must be 2 to 6.
    assert!(!medicare::validate("7123456701"));
    assert!(!medicare::validate("212345670"));
}

/// ASIC's mod 10 check uses even weights (8, 6, 4, 2), so a change of 5 at
/// those positions keeps the same check digit. Those values are valid ACNs by
/// definition. Every other single-digit change is rejected.
#[test]
fn acn_rejects_every_change_the_check_digit_can_see() {
    const WEIGHTS: [i32; 8] = [8, 7, 6, 5, 4, 3, 2, 1];
    for sample in ACNS {
        assert!(acn::validate(sample), "{sample}");
        for (pos, delta, mutated) in mutations(sample) {
            if mutated.bytes().all(|b| b == b'0') {
                continue;
            }
            let invisible = pos < 8 && (WEIGHTS[pos] * delta).rem_euclid(10) == 0;
            assert_eq!(
                acn::validate(&mutated),
                invisible,
                "{mutated} (position {pos})"
            );
        }
    }
}

#[test]
fn checksum_validators_reject_bad_shapes() {
    assert!(!tfn::validate("000000000"));
    assert!(!tfn::validate("1234567"));
    assert!(!tfn::validate("12345678a"));
    assert!(!abn::validate("01824753556"));
    assert!(!acn::validate("000000000"));
    assert!(!card::validate("0000000000000000"));
    // Luhn-valid but not a known issuer range.
    assert!(!card::validate(&with_luhn("911111111111111")));
    // Visa range, wrong length.
    assert!(!card::validate("41111111111111"));
}

#[test]
fn context_sets_confidence() {
    let text = "Your TFN is 123 456 782 and the ABN is 51 824 753 556.";
    let found = find_all(text);
    let kinds: Vec<DlpKind> = found.iter().map(|m| m.kind).collect();
    assert_eq!(kinds, vec![DlpKind::Tfn, DlpKind::Abn]);
    assert_eq!(&text[found[0].start..found[0].end], "123 456 782");
    assert_eq!(found[0].confidence, 40 + CONTEXT_BOOST);

    assert_eq!(tfn::find("ref 123-456-782")[0].confidence, 40);
    // A context word elsewhere in the text, such as a column header.
    let far = format!("TFN{} 123456782", " x".repeat(100));
    assert_eq!(tfn::find(&far)[0].confidence, 40 + DOCUMENT_BOOST);
    // Glued to letters: lower, unless the letters are the context word.
    assert!(tfn::find("INV123456782")[0].confidence < 40);
    assert_eq!(tfn::find("TFN123456782")[0].confidence, 50);
    assert!(tfn::find("1234567821").is_empty());

    assert_eq!(medicare::find("Medicare 2123 45670 1").len(), 1);
    assert_eq!(card::find("card 4111 1111 1111 1111")[0].confidence, 100);
    assert_eq!(
        acn::find("ACN 004 085 616")[0].confidence,
        25 + CONTEXT_BOOST
    );
}

#[test]
fn separators_digit_scripts_and_invisible_characters_do_not_hide_tfns() {
    let spellings = [
        "123.456.782",
        "123/456/782",
        "123,456,782",
        "123\n456\n782",
        "123\r\n456\t782",
        "123 - 456 - 782",
        "123  456  782",
        "123\u{a0}456\u{a0}782",
        "123\u{2009}456\u{202f}782",
        "123\u{2013}456\u{2013}782",
        "1\u{200b}2\u{200b}3\u{200b}4\u{200b}5\u{200b}6\u{200b}7\u{200b}8\u{200b}2",
        "123\u{feff}456\u{ad}782",
        "\u{ff11}\u{ff12}\u{ff13}\u{ff14}\u{ff15}\u{ff16}\u{ff17}\u{ff18}\u{ff12}",
        "\u{661}\u{662}\u{663}\u{664}\u{665}\u{666}\u{667}\u{668}\u{662}",
    ];
    for spelling in spellings {
        let text = format!("TFN: {spelling}");
        let report = scan(&text, &DlpProfile::default());
        assert_eq!(
            report.counts.get(&DlpKind::Tfn),
            Some(&1),
            "{spelling:?} {report:?}"
        );
        assert_eq!(report.samples[0].redacted, "123 *** ***", "{spelling:?}");
    }
    // Several TFNs in one line or one column are each found.
    let mut list = vec![TFN.to_string()];
    list.extend(synthetic_tfns(4, 9));
    assert_eq!(tfn_count(&format!("TFNs: {}", list.join(" "))), 5);
    assert_eq!(tfn_count(&format!("TFN\n{}", list.join("\n"))), 5);
}

#[test]
fn padding_before_tfns_does_not_exhaust_detection() {
    let pads = [
        "1 ".repeat(60_000),
        "0412345678\n".repeat(60_000),
        "999999999 ".repeat(60_000),
    ];
    for pad in pads {
        assert_eq!(tfn_count(&format!("{pad}\nTFN 123 456 782")), 1);
    }
}

#[test]
fn hostile_input_scans_in_linear_time() {
    // The dev profile builds this crate at opt-level 2 (root Cargo.toml).
    let limit = if cfg!(debug_assertions) {
        Duration::from_secs(2)
    } else {
        Duration::from_secs(1)
    };
    let mib = 1024 * 1024;
    for unit in ["1 ", "123456782 ", "licence 12345678 ", "1.1-1/1,"] {
        let text = unit.repeat(mib / unit.len());
        // Best of three, so a busy build machine does not fail the test.
        let elapsed = (0..3)
            .map(|_| {
                let started = Instant::now();
                let _ = scan(&text, &DlpProfile::default());
                started.elapsed()
            })
            .min()
            .unwrap();
        assert!(elapsed < limit, "{unit:?} took {elapsed:?}");
    }
}

#[test]
fn bare_numbers_without_context_do_not_trigger_review() {
    let profile = DlpProfile::default();
    let mut values = vec![TFN.to_string()];
    values.extend(synthetic_tfns(4, 9));
    let invoices: Vec<String> = values.iter().map(|v| format!("Invoice {v}")).collect();
    let report = scan(&invoices.join("\n"), &profile);
    assert!(report.review.is_empty(), "{report:?}");
    // The same numbers under a TFN heading count.
    let report = scan(&format!("Name, TFN\n{}", values.join("\n")), &profile);
    assert_eq!(report.review, vec![DlpKind::Tfn], "{report:?}");
}

#[test]
fn eight_digit_tfns_need_nearby_context() {
    let old = &synthetic_tfns(1, 8)[0];
    assert_eq!(tfn_count(&format!("TFN {old}")), 1);
    assert_eq!(tfn_count(&format!("ref {old}")), 0);
}

#[test]
fn licences_need_a_context_word() {
    assert!(licence::find("order 12345678 shipped").is_empty());
    let found = licence::find("Driver licence no: 12345678");
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].kind, DlpKind::DriverLicence);
    assert_eq!(licence::find("SA licence S12345").len(), 1);
    assert!(licence::validate("AB123456"));
    assert!(!licence::validate("ABC12345"));
    assert!(!licence::validate("12345"));
    assert!(!licence::validate("licence"));
}

#[test]
fn overlapping_matches_keep_the_most_confident() {
    // 123456782 is a valid TFN; near "licence" it is also licence-shaped.
    let found = find_all("licence 123456782 TFN");
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].kind, DlpKind::Tfn);
    // The ABN contains a nine-digit tail that passes as an ACN.
    let found = find_all("ABN 51 824 753 556");
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].kind, DlpKind::Abn);
}

#[test]
fn scan_counts_distinct_values_and_flags_review() {
    let profile = DlpProfile::default();
    let mut values = vec![TFN.to_string()];
    values.extend(synthetic_tfns(4, 9));
    let body = values
        .iter()
        .map(|t| format!("TFN {t}"))
        .collect::<Vec<_>>()
        .join("\n");
    let report = scan(&format!("{body}\n{body}"), &profile);
    assert_eq!(report.counts.get(&DlpKind::Tfn), Some(&5));
    assert_eq!(report.review, vec![DlpKind::Tfn]);
    let four = scan(&body[..body.rfind('\n').unwrap()], &profile);
    assert!(four.review.is_empty(), "{four:?}");
    // ABNs are public and never trigger review by default.
    let abns = scan(&format!("ABN {ABN}\n").repeat(6), &profile);
    assert_eq!(abns.counts.get(&DlpKind::Abn), Some(&1));
    assert!(abns.review.is_empty());
}

#[test]
fn oversized_text_is_marked_incomplete() {
    let profile = DlpProfile::default();
    assert!(!scan("TFN 123456782", &profile).incomplete);
    let big = format!("{}TFN 123456782", " ".repeat(MAX_SCAN_BYTES));
    let report = scan(&big, &profile);
    assert!(report.incomplete);
    assert!(report.counts.is_empty());
}

#[test]
fn reports_hold_redacted_samples_only() {
    let mut values = vec![TFN.to_string()];
    values.extend(synthetic_tfns(4, 9));
    let text = format!(
        "TFN: {}. Card 4111 1111 1111 1111. Driver licence S12345",
        values.join(" ; ")
    );
    let report = scan(&text, &DlpProfile::default());
    assert_eq!(report.counts.get(&DlpKind::DriverLicence), Some(&1));
    let json = serde_json::to_string(&report).unwrap();
    for value in values
        .iter()
        .map(String::as_str)
        .chain(["4111111111111111"])
    {
        assert!(!json.contains(value), "{json}");
        assert!(!json.contains(&value[3..]), "{json}");
    }
    assert!(!json.contains("S12"), "{json}");
    assert!(json.contains("123 *** ***"), "{json}");
    assert_eq!(
        redact(DlpKind::Card, "4111 1111 1111 1111"),
        "411 *** *** *** *** *"
    );
    assert_eq!(redact(DlpKind::DriverLicence, "S12345"), "*** ***");
    assert_eq!(redact(DlpKind::Tfn, "12345678"), "12 *** ***");
}
