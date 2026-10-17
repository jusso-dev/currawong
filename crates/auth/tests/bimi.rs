use currawong_auth::{
    bimi::{dmarc_domain, lookup, parse_record, safe_url},
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
        header: format!(
            "Authentication-Results: gateway.test;\r\n\tdkim=none header.from=other.test;\r\n\tdmarc={dmarc} header.from=example.test policy.dmarc={policy}\r\n"
        ),
    }
}

fn dns(dmarc: &str, bimi: &[&str]) -> HashMap<String, Vec<String>> {
    HashMap::from([
        ("_dmarc.example.test".to_string(), vec![dmarc.to_string()]),
        (
            "default._bimi.example.test".to_string(),
            bimi.iter().map(|record| record.to_string()).collect(),
        ),
    ])
}

const REJECT: &str = "v=DMARC1; p=reject";

#[tokio::test]
async fn bimi_logo_with_authority_is_flagged_unverified() {
    let txt = dns(
        REJECT,
        &["v=BIMI1; l=https://example.test/logo.svg; a=https://example.test/vmc.pem"],
    );
    let found = lookup(&txt, &auth("pass", "reject")).await;
    assert_eq!(
        found,
        Some(Bimi {
            domain: "example.test".into(),
            logo: "https://example.test/logo.svg".into(),
            authority: Some("https://example.test/vmc.pem".into()),
            vmc: VmcStatus::Unverified,
            displayable: false,
        })
    );
    let json = serde_json::to_string(&found).unwrap();
    assert!(json.contains("\"vmc\":\"unverified\""), "{json}");
    assert!(json.contains("\"displayable\":false"), "{json}");
}

#[tokio::test]
async fn bimi_logo_without_authority_has_no_vmc_and_is_not_displayable() {
    let txt = dns(REJECT, &["v=BIMI1; l=https://example.test/logo.svg;"]);
    let found = lookup(&txt, &auth("pass", "quarantine")).await.unwrap();
    assert_eq!(found.vmc, VmcStatus::Absent);
    assert_eq!(found.authority, None);
    assert!(!found.displayable);
}

#[tokio::test]
async fn bimi_needs_dmarc_pass_at_enforcement() {
    let txt = dns(REJECT, &["v=BIMI1; l=https://example.test/logo.svg"]);
    assert!(lookup(&txt, &auth("pass", "none")).await.is_none());
    assert!(lookup(&txt, &auth("fail", "reject")).await.is_none());
}

#[tokio::test]
async fn bimi_pct_below_100_or_sp_none_means_no_logo() {
    let logo = ["v=BIMI1; l=https://example.test/logo.svg"];
    for record in [
        "v=DMARC1; p=reject; pct=50",
        "v=DMARC1; p=quarantine; sp=none",
        "v=DMARC1; p=none",
    ] {
        let txt = dns(record, &logo);
        assert!(
            lookup(&txt, &auth("pass", "reject")).await.is_none(),
            "{record}"
        );
    }
    let txt = dns("v=DMARC1; p=reject; pct=100; sp=quarantine", &logo);
    assert!(lookup(&txt, &auth("pass", "reject")).await.is_some());
    // No published DMARC record at all.
    let mut txt = dns(REJECT, &logo);
    txt.remove("_dmarc.example.test");
    assert!(lookup(&txt, &auth("pass", "reject")).await.is_none());
}

#[tokio::test]
async fn bimi_uses_the_dmarc_domain_not_another_header() {
    let auth = auth("pass", "reject");
    assert_eq!(dmarc_domain(&auth).as_deref(), Some("example.test"));
    let mut forged = auth.clone();
    forged.header = "Authentication-Results: gateway.test; dkim=none".into();
    assert_eq!(dmarc_domain(&forged), None);
}

#[tokio::test]
async fn bimi_two_records_mean_no_bimi() {
    let txt = dns(
        REJECT,
        &[
            "v=BIMI1; l=https://example.test/a.svg",
            "v=BIMI1; l=https://example.test/b.svg",
        ],
    );
    assert!(lookup(&txt, &auth("pass", "reject")).await.is_none());
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
fn bimi_url_validation() {
    assert!(safe_url("https://brand.example.test/logo.svg"));
    let long = format!("https://example.test/{}", "a".repeat(3000));
    for bad in [
        "https://user:pw@example.test/logo.svg",
        "https://user@example.test/logo.svg",
        "https://10.0.0.1/logo.svg",
        "https://[::1]/logo.svg",
        "https://127.0.0.1/logo.svg",
        "https://localhost/logo.svg",
        "https://example.test/logo.svg\" onerror=\"x",
        "https://example.test/<script>",
        "https://example.test/a b.svg",
        "https://example.test/\u{1}.svg",
        "javascript:alert(1)",
        "http://example.test/logo.svg",
        long.as_str(),
    ] {
        assert!(!safe_url(bad), "{bad}");
    }
}
