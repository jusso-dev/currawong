//! Auth against a fake DNS server, so mail-auth's own cache inserts run.
#[path = "common/fakedns.rs"]
mod fakedns;

use currawong_auth::{generate, sign_message, AuthChecker};
use currawong_core::{Direction, MessageId};
use currawong_spool::{Envelope, SpoolState};
use fakedns::FakeDns;
use time::OffsetDateTime;

fn envelope(from: &str) -> Envelope {
    Envelope {
        id: MessageId("01ARZ3NDEKTSV4RRFFQ69G5FAV".into()),
        tenant_id: None,
        authenticated_as: None,
        mail_from: from.into(),
        rcpt_to: vec!["dest@example.test".into()],
        received_at: OffsetDateTime::now_utc(),
        remote_ip: "203.0.113.5".parse().unwrap(),
        helo: "client.attacker.test".into(),
        attempts: 0,
        next_attempt_at: None,
        state: SpoolState::Incoming,
        direction: Direction::Inbound,
        tls_version: None,
        tls_cipher: None,
        rcpt_status: Vec::new(),
        prepend_headers: Vec::new(),
        dsn_sent: false,
        tls: Default::default(),
        pipeline: "pending".into(),
    }
}

fn message(from: &str) -> Vec<u8> {
    format!(
        "From: {from}\r\nTo: dest@example.test\r\nSubject: wire the money\r\nDate: Wed, 14 Oct 2026 01:00:00 +0000\r\nMessage-ID: <1@victim.test>\r\n\r\npay now\r\n"
    )
    .into_bytes()
}

/// Re-review finding 1: an attacker SPF `include:` of the victim's DMARC
/// name made mail-auth cache a parse failure under `_dmarc.victim.test.`,
/// which the DMARC lookup then read as "no record" (p=reject bypassed).
#[tokio::test]
async fn spf_include_cannot_poison_the_dmarc_record() {
    let dns = FakeDns::start().await;
    dns.txt("attacker.test", "v=spf1 include:_dmarc.victim.test ?all");
    dns.txt("_dmarc.victim.test", "v=DMARC1; p=reject");
    let checker = AuthChecker::with_name_server("currawong.example.test", dns.addr).unwrap();
    for round in 0..2 {
        let results = checker
            .check(&message("ceo@victim.test"), &envelope("x@attacker.test"))
            .await;
        assert_eq!(
            results.dmarc.result, "fail",
            "round {round}: {}",
            results.header
        );
        assert_eq!(
            results.dmarc_policy, "reject",
            "round {round}: {}",
            results.header
        );
    }
}

/// Same trick against the victim's DKIM key: legitimate mail must still pass.
#[tokio::test]
async fn spf_include_cannot_poison_a_dkim_key() {
    let dns = FakeDns::start().await;
    let mut key = generate("victim", "victim.test", "sel", "ed25519").unwrap();
    key.active = true;
    dns.txt(&key.dns_name(), &key.public_txt);
    dns.txt(
        "attacker.test",
        "v=spf1 include:sel._domainkey.victim.test ?all",
    );
    dns.txt("victim.test", "v=spf1 -all");
    dns.txt("_dmarc.victim.test", "v=DMARC1; p=reject");
    let checker = AuthChecker::with_name_server("currawong.example.test", dns.addr).unwrap();
    let _ = checker
        .check(&message("ceo@victim.test"), &envelope("x@attacker.test"))
        .await;
    let signed = sign_message(&message("ceo@victim.test"), &key).unwrap();
    let results = checker
        .check(&signed, &envelope("bounce@victim.test"))
        .await;
    assert_eq!(
        results.dkim.first().map(|item| item.result.as_str()),
        Some("pass"),
        "{}",
        results.header
    );
    assert_eq!(results.dmarc.result, "pass", "{}", results.header);
}

/// A DNS failure fetching DMARC is a temporary error, not "no policy".
#[tokio::test]
async fn dmarc_servfail_is_temperror() {
    let dns = FakeDns::start().await;
    dns.txt("attacker.test", "v=spf1 ?all");
    dns.servfail("_dmarc.victim.test");
    let checker = AuthChecker::with_name_server("currawong.example.test", dns.addr).unwrap();
    let results = checker
        .check(&message("ceo@victim.test"), &envelope("x@attacker.test"))
        .await;
    assert_eq!(results.dmarc.result, "temperror", "{}", results.header);
}

/// Re-review finding 4: activation checks the TXT record really is served.
#[tokio::test]
async fn dkim_record_published_matches_the_public_key() {
    let key = generate("local", "example.test", "s1", "ed25519").unwrap();
    let other = generate("local", "example.test", "s2", "ed25519").unwrap();
    let dns = FakeDns::start().await;
    let checker = AuthChecker::with_name_server("currawong.example.test", dns.addr).unwrap();
    assert!(!checker.dkim_record_published(&key).await.unwrap_or(false));
    dns.txt(&key.dns_name(), &other.public_txt);
    assert!(!checker.dkim_record_published(&key).await.unwrap());

    let dns = FakeDns::start().await;
    dns.txt(&key.dns_name(), &key.public_txt.replace("; ", ";  "));
    let checker = AuthChecker::with_name_server("currawong.example.test", dns.addr).unwrap();
    assert!(checker.dkim_record_published(&key).await.unwrap());
}
