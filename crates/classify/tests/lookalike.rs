use currawong_classify::{
    lookalike::{parse_brands, score, BRANDS_AU},
    spam::{RuleSet, SpamClassifier},
    Classifier,
};
use currawong_core::{config::Config, LookalikeTechnique};

fn protected() -> Vec<String> {
    let mut domains = parse_brands(BRANDS_AU);
    domains.push("example.test".into());
    domains.push("acmeplumbing.com.au".into());
    domains
}

#[test]
fn lookalike_domains_are_flagged_against_their_targets() {
    use LookalikeTechnique::*;
    let cases = [
        ("c0mmbank.com.au", "commbank.com.au", Homoglyph),
        ("rnygov.au", "mygov.au", Homoglyph),
        // Cyrillic small a (U+0430) in place of the Latin a.
        ("\u{0430}to.gov.au", "ato.gov.au", Homoglyph),
        // The same name as punycode, as it arrives in a URL host.
        ("xn--to-6kc.gov.au", "ato.gov.au", Homoglyph),
        ("examp1e.test", "example.test", Homoglyph),
        ("commbank.net.au", "commbank.com.au", SuffixSwap),
        ("westpac.au", "westpac.com.au", SuffixSwap),
        ("acmeplumbing.au", "acmeplumbing.com.au", SuffixSwap),
        ("westpak.com.au", "westpac.com.au", EditDistance),
        ("acmeplumbimg.com.au", "acmeplumbing.com.au", EditDistance),
        ("auspost-delivery.com", "auspost.com.au", Cousin),
        ("ato-refunds.com", "ato.gov.au", Cousin),
        ("ato.gov.au.secure-login.net", "ato.gov.au", Cousin),
    ];
    let protected = protected();
    for (candidate, target, technique) in cases {
        let hit = score(candidate, &protected)
            .unwrap_or_else(|| panic!("{candidate} should imitate {target}"));
        assert_eq!(hit.target, target, "{candidate}");
        assert_eq!(hit.technique, technique, "{candidate}");
        assert!(hit.score > 0.0 && hit.score <= 1.0, "{candidate}");
    }
}

#[test]
fn lookalike_skips_exact_tenant_and_brand_domains() {
    let protected = protected();
    for candidate in [
        "example.test",
        "EXAMPLE.TEST",
        "example.test.",
        "mail.example.test",
        "acmeplumbing.com.au",
        "ato.gov.au",
        "my.gov.au",
        "online.commbank.com.au",
        "anz.com",
        "telstra.com",
        // Unrelated domains.
        "gmail.com",
        "outlook.com",
        "atlassian.com",
        "abc.net.au",
        "bom.gov.au",
        "com.au",
        "",
    ] {
        assert_eq!(score(candidate, &protected), None, "{candidate}");
    }
}

#[test]
fn lookalike_checks_from_reply_to_envelope_and_links() {
    let mut cfg = Config::default();
    cfg.domains.accept = vec!["example.test".into()];
    let classifier = Classifier::new(
        {
            let mut domains = parse_brands(BRANDS_AU);
            domains.extend(cfg.domains.accept.clone());
            domains
        },
        SpamClassifier {
            bayes: None,
            rules: RuleSet::builtin().unwrap(),
        },
    );
    let raw = "From: ATO <notice@\u{0430}to.gov.au>\r\nReply-To: refunds@examp1e.test\r\nTo: staff@example.test\r\nSubject: Refund\r\n\r\nLog in at https://c0mmbank.com.au/login or https://example.test/ok\r\n";
    let result = classifier.classify(
        "example",
        raw.as_bytes(),
        "bounce@rnygov.au",
        &["https://westpak.com.au/x".to_string()],
    );
    let found: Vec<(&str, &str)> = result
        .lookalikes
        .iter()
        .map(|f| (f.source.as_str(), f.target.as_str()))
        .collect();
    assert!(found.contains(&("from", "ato.gov.au")), "{found:?}");
    assert!(found.contains(&("reply-to", "example.test")), "{found:?}");
    assert!(found.contains(&("envelope", "mygov.au")), "{found:?}");
    assert!(found.contains(&("url", "commbank.com.au")), "{found:?}");
    assert!(found.contains(&("url", "westpac.com.au")), "{found:?}");
    assert_eq!(
        found.len(),
        5,
        "the real tenant link is not flagged: {found:?}"
    );
}

#[test]
fn lookalike_config_protects_accepted_and_tenant_domains() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::default();
    cfg.classify.bayes_database = dir.path().join("bayes.sqlite");
    cfg.domains.accept = vec!["example.test".into()];
    cfg.classify.protected_domains = vec!["partner.com.au".into()];
    let classifier = Classifier::from_config(&cfg).unwrap();
    let raw = b"From: a@partner.net.au\r\nSubject: hi\r\n\r\nhello\r\n";
    let result = classifier.classify("example", raw, "b@exarnple.test", &[]);
    let targets: Vec<&str> = result
        .lookalikes
        .iter()
        .map(|f| f.target.as_str())
        .collect();
    assert_eq!(targets, vec!["partner.com.au", "example.test"]);
}
