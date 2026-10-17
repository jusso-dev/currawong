use currawong_auth::{
    bimi::{author_domain, lookup, parse_record},
    Bimi, VmcStatus,
};
use currawong_core::{AuthMethodResult, AuthResults};
use std::collections::HashMap;

fn auth(dmarc: &str, policy: &str) -> AuthResults {
    AuthResults {
        spf: AuthMethodResult::none(),
        dkim: Vec::new(),
        dmarc: AuthMethodResult {
            result: dmarc.into(),
            detail: String::new(),
        },
        arc: AuthMethodResult::none(),
        dmarc_policy: policy.into(),
        header: String::new(),
    }
}

fn dns(records: &[&str]) -> HashMap<String, Vec<String>> {
    HashMap::from([(
        "default._bimi.example.test".to_string(),
        records.iter().map(|record| record.to_string()).collect(),
    )])
}

#[tokio::test]
async fn bimi_logo_with_authority_is_flagged_unverified() {
    let txt = dns(&["v=BIMI1; l=https://example.test/logo.svg; a=https://example.test/vmc.pem"]);
    let found = lookup(&txt, "example.test", &auth("pass", "reject")).await;
    assert_eq!(
        found,
        Some(Bimi {
            domain: "example.test".into(),
            logo: "https://example.test/logo.svg".into(),
            authority: Some("https://example.test/vmc.pem".into()),
            vmc: VmcStatus::Unverified,
        })
    );
    let json = serde_json::to_string(&found).unwrap();
    assert!(json.contains("\"vmc\":\"unverified\""), "{json}");
}

#[tokio::test]
async fn bimi_logo_without_authority_has_no_vmc() {
    let txt = dns(&["v=BIMI1; l=https://example.test/logo.svg;"]);
    let found = lookup(&txt, "example.test", &auth("pass", "quarantine"))
        .await
        .unwrap();
    assert_eq!(found.vmc, VmcStatus::Absent);
    assert_eq!(found.authority, None);
}

#[tokio::test]
async fn bimi_needs_dmarc_pass_at_enforcement() {
    let txt = dns(&["v=BIMI1; l=https://example.test/logo.svg"]);
    assert!(lookup(&txt, "example.test", &auth("pass", "none"))
        .await
        .is_none());
    assert!(lookup(&txt, "example.test", &auth("fail", "reject"))
        .await
        .is_none());
    assert!(lookup(&txt, "other.test", &auth("pass", "reject"))
        .await
        .is_none());
}

#[tokio::test]
async fn bimi_two_records_mean_no_bimi() {
    let txt = dns(&[
        "v=BIMI1; l=https://example.test/a.svg",
        "v=BIMI1; l=https://example.test/b.svg",
    ]);
    assert!(lookup(&txt, "example.test", &auth("pass", "reject"))
        .await
        .is_none());
}

#[test]
fn bimi_record_parsing() {
    assert_eq!(
        parse_record("v=BIMI1; l=https://example.test/logo.svg"),
        Some(("https://example.test/logo.svg".into(), None))
    );
    // Plain HTTP logos and an empty l= (declined) are not shown.
    assert_eq!(
        parse_record("v=BIMI1; l=http://example.test/logo.svg"),
        None
    );
    assert_eq!(parse_record("v=BIMI1; l=;"), None);
    assert_eq!(
        parse_record("l=https://example.test/logo.svg; v=BIMI1"),
        None
    );
    assert_eq!(
        parse_record("v=BIMI1; l=https://example.test/logo.svg; a=http://example.test/vmc.pem"),
        Some(("https://example.test/logo.svg".into(), None))
    );
}

#[test]
fn bimi_author_domain_from_header() {
    let raw = b"From: Brand <News@Example.TEST>\r\nSubject: hi\r\n\r\nbody\r\n";
    assert_eq!(author_domain(raw).as_deref(), Some("example.test"));
    assert_eq!(author_domain(b"Subject: hi\r\n\r\nbody\r\n"), None);
}
