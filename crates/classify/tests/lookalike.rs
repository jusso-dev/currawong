use currawong_classify::{
    lookalike::{parse_brands, score, BRANDS_AU},
    spam::{RuleSet, SpamClassifier},
    Classifier, TenantContext,
};
use currawong_core::{config::Config, LookalikeTechnique};
use std::time::{Duration, Instant};

fn protected() -> Vec<String> {
    let mut domains = parse_brands(BRANDS_AU);
    domains.push("example.test".into());
    domains.push("acmeplumbing.com.au".into());
    domains
}

fn classifier() -> Classifier {
    Classifier::new(
        &parse_brands(BRANDS_AU),
        SpamClassifier {
            bayes: None,
            rules: RuleSet::builtin().unwrap(),
        },
    )
}

fn targets(classifier: &Classifier, tenant: &TenantContext, raw: &str) -> Vec<(String, String)> {
    classifier
        .classify(tenant, raw.as_bytes(), "", &[])
        .lookalikes
        .into_iter()
        .map(|found| (found.source, found.target))
        .collect()
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
        // Cyrillic small o (U+043E) in the suffix: `gоv.au` is not a public suffix.
        ("ato.g\u{043e}v.au", "ato.gov.au", Homoglyph),
        ("login.ato.g\u{043e}v.au", "ato.gov.au", Homoglyph),
        ("examp1e.test", "example.test", Homoglyph),
        ("commbank.net.au", "commbank.com.au", SuffixSwap),
        ("westpac.au", "westpac.com.au", SuffixSwap),
        ("acmeplumbing.au", "acmeplumbing.com.au", SuffixSwap),
        ("ato.com.au", "ato.gov.au", SuffixSwap),
        ("westpak.com.au", "westpac.com.au", EditDistance),
        ("acmeplumbimg.com.au", "acmeplumbing.com.au", EditDistance),
        ("auspost-delivery.com", "auspost.com.au", Cousin),
        ("ato-refunds.com", "ato.gov.au", Cousin),
        ("ato.gov.au.secure-login.net", "ato.gov.au", Cousin),
        ("login-ato.gov.au.secure-login.net", "ato.gov.au", Cousin),
        ("ato.gov.au-secure.com", "ato.gov.au", Cousin),
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
        // Short labels under foreign suffixes, and names that merely contain a brand.
        "my.com",
        "anz.co.nz",
        "cba.org",
        "nab.co.uk",
        "dentalmedicare.com.au",
        "plato.gov.au.mirror.net",
    ] {
        assert_eq!(score(candidate, &protected), None, "{candidate}");
    }
}

#[test]
fn lookalike_long_labels_are_bounded_in_time() {
    let protected = protected();
    let long = format!("{}.com.au", "a".repeat(16_000));
    let started = Instant::now();
    assert_eq!(score(&long, &protected), None);
    let at_limit = format!("{}.com.au", "c0mmbank".repeat(7));
    for _ in 0..100 {
        score(&at_limit, &protected);
    }
    let raw = format!(
        "From: x@{long}\r\nReply-To: y@{long}\r\nSubject: hi\r\n\r\nhttps://{long}/ https://b{long}/\r\n"
    );
    classifier().classify(
        &TenantContext::domain("example.test"),
        raw.as_bytes(),
        "",
        &[],
    );
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "took {:?}",
        started.elapsed()
    );
}

#[test]
fn lookalike_checks_from_reply_to_envelope_and_links() {
    let classifier = classifier();
    let raw = "From: ATO <notice@\u{0430}to.gov.au>\r\nReply-To: refunds@examp1e.test\r\nTo: staff@example.test\r\nSubject: Refund\r\n\r\nLog in at https://c0mmbank.com.au/login or https://example.test/ok\r\n";
    let result = classifier.classify(
        &TenantContext::domain("example.test"),
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
fn lookalike_link_after_many_others_is_checked() {
    let mut body = String::new();
    for i in 0..64 {
        body.push_str(&format!("https://example.test/news/{i}\r\n"));
    }
    body.push_str("https://c0mmbank.com.au/login\r\n");
    let raw = format!("From: a@example.test\r\nSubject: news\r\n\r\n{body}");
    let found = targets(&classifier(), &TenantContext::domain("example.test"), &raw);
    assert_eq!(
        found,
        vec![("url".to_string(), "commbank.com.au".to_string())]
    );
}

#[test]
fn lookalike_tenant_domains_stay_with_their_tenant() {
    let classifier = classifier();
    let alpha = TenantContext::tenant("alpha", &["alphafreight.com.au".to_string()]);
    let bravo = TenantContext::tenant("bravo", &["bravodental.com.au".to_string()]);
    let raw = "From: accounts@a1phafreight.com.au\r\nSubject: invoice\r\n\r\nhello\r\n";
    assert_eq!(
        targets(&classifier, &alpha, raw),
        vec![("from".to_string(), "alphafreight.com.au".to_string())]
    );
    // Bravo's report must not name Alpha's domain.
    assert!(targets(&classifier, &bravo, raw).is_empty());
}

#[test]
fn lookalike_config_protects_extra_domains_for_every_tenant() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::default();
    cfg.classify.bayes_database = dir.path().join("bayes.sqlite");
    cfg.classify.protected_domains = vec!["partner.com.au".into()];
    let classifier = Classifier::from_config(&cfg).unwrap();
    let raw = b"From: a@partner.net.au\r\nSubject: hi\r\n\r\nhello\r\n";
    let result = classifier.classify(
        &TenantContext::domain("example.test"),
        raw,
        "b@exarnple.test",
        &[],
    );
    let targets: Vec<&str> = result
        .lookalikes
        .iter()
        .map(|f| f.target.as_str())
        .collect();
    assert_eq!(targets, vec!["partner.com.au", "example.test"]);
    assert!(result.notes.is_empty(), "{:?}", result.notes);
}
