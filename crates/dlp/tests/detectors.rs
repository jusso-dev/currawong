//! Table tests. Every value here is a published sample or test number, or a
//! synthetic value built to pass the checksum. None belongs to a person.
use currawong_dlp::detectors::{abn, acn, card, licence, medicare, tfn, CONTEXT_BOOST};
use currawong_dlp::{find_all, redact, scan, DlpKind, DlpProfile};

/// `123456782` is the ATO's published sample. The rest are synthetic.
const TFNS: &[&str] = &[
    "123456782",
    "876543210",
    "100000060",
    "200000010",
    "300000070",
];
/// `2123 45670 1` is the common published sample.
const MEDICARE: &[&str] = &["2123456701", "21234567011"];
/// The ATO's example ABN.
const ABNS: &[&str] = &["51824753556"];
/// ASIC's published ACN examples.
const ACNS: &[&str] = &[
    "000000019",
    "000250000",
    "004085616",
    "005499981",
    "010499966",
];
/// Published scheme test numbers (Visa, Mastercard, Mastercard 2-series,
/// Amex, Discover, JCB, Diners, UnionPay).
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

#[test]
fn valid_samples_pass_and_every_single_digit_change_fails() {
    let strict: &[(&str, &[&str], Validate)] = &[
        ("tfn", TFNS, tfn::validate),
        ("abn", ABNS, abn::validate),
        ("card", CARDS, card::validate),
    ];
    for (name, samples, validate) in strict {
        for sample in *samples {
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
    const WEIGHTS: [i32; 9] = [8, 7, 6, 5, 4, 3, 2, 1, 1];
    for sample in ACNS {
        assert!(acn::validate(sample), "{sample}");
        for (pos, delta, mutated) in mutations(sample) {
            let invisible = pos < 8 && (WEIGHTS[pos] * delta).rem_euclid(10) == 0;
            if mutated.bytes().all(|b| b == b'0') {
                continue;
            }
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
    assert!(!tfn::validate("12345678"));
    assert!(!tfn::validate("12345678a"));
    assert!(!abn::validate("01824753556"));
    assert!(!acn::validate("000000000"));
    assert!(!card::validate("0000000000000000"));
    // Luhn-valid but not a known issuer range.
    assert!(!card::validate("9111111111111111"));
    // Visa range, wrong length.
    assert!(!card::validate("41111111111111"));
}

#[test]
fn find_handles_grouping_boundaries_and_context() {
    let text = "Your TFN is 123 456 782 and the ABN is 51 824 753 556.";
    let found = find_all(text);
    let kinds: Vec<DlpKind> = found.iter().map(|m| m.kind).collect();
    assert_eq!(kinds, vec![DlpKind::Tfn, DlpKind::Abn]);
    assert_eq!(&text[found[0].start..found[0].end], "123 456 782");
    assert_eq!(found[0].confidence, 60 + CONTEXT_BOOST);

    let bare = tfn::find("ref 123-456-782");
    assert_eq!(bare.len(), 1);
    assert_eq!(bare[0].confidence, 60);

    // Glued to letters or part of a longer number: not an identifier.
    assert!(tfn::find("INV123456782").is_empty());
    assert!(tfn::find("1234567821").is_empty());
    // "attfn" is not the word "tfn".
    assert_eq!(tfn::find("attfn 123456782")[0].confidence, 60);

    assert_eq!(medicare::find("Medicare 2123 45670 1").len(), 1);
    assert_eq!(card::find("card 4111 1111 1111 1111")[0].confidence, 100);
    assert_eq!(
        acn::find("ACN 004 085 616")[0].confidence,
        40 + CONTEXT_BOOST
    );
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
    let found = find_all("licence 123456782");
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].kind, DlpKind::Tfn);
    // A bare ACN is below the default confidence, a bare TFN is not.
    let report = scan("004085616 123456782", &DlpProfile::default());
    assert_eq!(report.counts.get(&DlpKind::Acn), None);
    assert_eq!(report.counts.get(&DlpKind::Tfn), Some(&1));
}

#[test]
fn scan_counts_distinct_values_and_flags_review() {
    let profile = DlpProfile::default();
    let body = TFNS
        .iter()
        .map(|t| format!("TFN {t}"))
        .collect::<Vec<_>>()
        .join("\n");
    let report = scan(&format!("{body}\n{body}"), &profile);
    assert_eq!(report.counts.get(&DlpKind::Tfn), Some(&5));
    assert_eq!(report.review, vec![DlpKind::Tfn]);
    let four = scan(&TFNS[..4].join(", "), &profile);
    assert!(four.review.is_empty(), "{four:?}");
    // ABNs are public and never trigger review by default.
    let abns = scan(&format!("ABN {}\n", ABNS[0]).repeat(6), &profile);
    assert_eq!(abns.counts.get(&DlpKind::Abn), Some(&1));
    assert!(abns.review.is_empty());
}

#[test]
fn reports_hold_redacted_samples_only() {
    let text = format!("TFNs: {}. Card 4111 1111 1111 1111", TFNS.join(" ; "));
    let report = scan(&text, &DlpProfile::default());
    let json = serde_json::to_string(&report).unwrap();
    for value in TFNS.iter().chain(["4111111111111111"].iter()) {
        assert!(!json.contains(value), "{json}");
        assert!(!json.contains(&value[3..]), "{json}");
    }
    assert!(json.contains("123 *** ***"), "{json}");
    assert_eq!(redact("4111 1111 1111 1111"), "411 *** *** *** *** *");
}

#[test]
fn space_separated_lists_and_hostile_runs() {
    let report = scan(&TFNS.join(" "), &DlpProfile::default());
    assert_eq!(report.counts.get(&DlpKind::Tfn), Some(&5), "{report:?}");
    // Single-digit groups separated by spaces must not blow up.
    let started = std::time::Instant::now();
    let _ = scan(&"1 ".repeat(2 * 1024 * 1024), &DlpProfile::default());
    assert!(started.elapsed() < std::time::Duration::from_secs(20));
}
