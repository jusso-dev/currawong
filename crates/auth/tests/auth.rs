use currawong_auth::{
    ed25519_key, publishable, rsa_key, seal_arc, seed_txt, sign_message, AuthChecker, KeyStore,
};
use currawong_core::{Direction, MessageId};
use currawong_spool::{Envelope, SpoolState};
use std::net::{IpAddr, Ipv4Addr};
use time::OffsetDateTime;

fn message() -> Vec<u8> {
    b"From: user@example.test\r\n\
To: dest@example.test\r\n\
Subject: hello\r\n\
Date: Wed, 14 Oct 2026 01:00:00 +0000\r\n\
Message-ID: <1@example.test>\r\n\
MIME-Version: 1.0\r\n\
Content-Type: text/plain; charset=utf-8\r\n\
\r\n\
hello\r\n"
        .to_vec()
}

fn envelope(from: &str) -> Envelope {
    Envelope {
        id: MessageId("01ARZ3NDEKTSV4RRFFQ69G5FAV".into()),
        tenant_id: Some("local".into()),
        mail_from: from.into(),
        rcpt_to: vec!["dest@example.test".into()],
        received_at: OffsetDateTime::now_utc(),
        remote_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)),
        helo: "client.example.test".into(),
        attempts: 0,
        next_attempt_at: None,
        state: SpoolState::Incoming,
        direction: Direction::Inbound,
        tls_version: None,
        tls_cipher: None,
        rcpt_status: Vec::new(),
        prepend_headers: Vec::new(),
        dsn_sent: false,
        pipeline: "pending".into(),
    }
}

#[tokio::test]
async fn signed_fixture_is_dkim_pass_and_dmarc_pass() {
    let key = ed25519_key().unwrap();
    let signed = sign_message(&message(), &key).unwrap();
    let checker = AuthChecker::offline("currawong.example.test").unwrap();
    seed_txt(
        checker.cache(),
        "ed._domainkey.example.test",
        &key.public_txt,
    )
    .unwrap();
    seed_txt(
        checker.cache(),
        "example.test",
        "v=spf1 ip4:203.0.113.5 -all",
    )
    .unwrap();
    seed_txt(
        checker.cache(),
        "_dmarc.example.test",
        "v=DMARC1; p=reject; adkim=r; aspf=r",
    )
    .unwrap();
    let results = checker.check(&signed, &envelope("user@example.test")).await;
    assert_eq!(
        results.dkim.first().map(|item| item.result.as_str()),
        Some("pass"),
        "{}",
        results.header
    );
    assert_eq!(results.dmarc.result, "pass", "{}", results.header);
    assert!(
        results.header.to_ascii_lowercase().contains("dkim=pass"),
        "{}",
        results.header
    );
}

#[tokio::test]
async fn spoofed_from_with_reject_policy_fails_dmarc() {
    let checker = AuthChecker::offline("currawong.example.test").unwrap();
    seed_txt(checker.cache(), "attacker.test", "v=spf1 -all").unwrap();
    seed_txt(checker.cache(), "_dmarc.example.test", "v=DMARC1; p=reject").unwrap();
    let results = checker
        .check(&message(), &envelope("spoof@attacker.test"))
        .await;
    assert_eq!(results.dmarc.result, "fail", "{}", results.header);
    assert_eq!(results.dmarc_policy, "reject", "{}", results.header);
}

#[tokio::test]
async fn sign_round_trip_rsa_and_ed25519() {
    for key in [ed25519_key().unwrap(), rsa_key(2048).unwrap()] {
        let signed = sign_message(&message(), &key).unwrap();
        assert!(signed
            .windows(14)
            .any(|window| window.eq_ignore_ascii_case(b"DKIM-Signature")));
        let checker = AuthChecker::offline("currawong.example.test").unwrap();
        let name = format!("{}._domainkey.example.test", key.selector);
        seed_txt(checker.cache(), &name, &key.public_txt).unwrap();
        seed_txt(checker.cache(), "example.test", "v=spf1 +all").unwrap();
        seed_txt(checker.cache(), "_dmarc.example.test", "v=DMARC1; p=none").unwrap();
        let results = checker.check(&signed, &envelope("user@example.test")).await;
        assert_eq!(
            results.dkim.first().map(|item| item.result.as_str()),
            Some("pass"),
            "{} {}",
            key.algorithm,
            results.header
        );
    }
}

#[tokio::test]
async fn sign_seals_arc_for_a_modified_message() {
    let key = ed25519_key().unwrap();
    let sealed = seal_arc(&message(), &key, "currawong.example.test").unwrap();
    let text = String::from_utf8_lossy(&sealed);
    assert!(text.contains("ARC-Seal:"), "{text}");
    assert!(text.contains("ARC-Message-Signature:"), "{text}");
    assert!(text.contains("ARC-Authentication-Results:"), "{text}");
}

#[test]
fn sign_retired_selector_stays_publishable_for_seven_days() {
    let dir = tempfile::tempdir().unwrap();
    let store = KeyStore::open(&dir.path().join("keys.sqlite"), &dir.path().join("kek")).unwrap();
    let mut key = ed25519_key().unwrap();
    key.id = "ed-1".into();
    key.created_at = 1_000;
    store.insert(&key).unwrap();
    let now = 2_000;
    store.retire(&key.id, now).unwrap();
    let day = 24 * 60 * 60;
    assert!(store
        .publishable_keys("example.test", now + 6 * day)
        .unwrap()
        .iter()
        .any(|item| item.selector == "ed"));
    assert!(store
        .signing_keys("example.test", now + 6 * day)
        .unwrap()
        .is_empty());
    assert!(store
        .publishable_keys("example.test", now + 8 * day)
        .unwrap()
        .is_empty());
    let mut retired = key.clone();
    retired.active = false;
    retired.retired_at = Some(now);
    assert!(publishable(&retired, now + 6 * day));
    assert!(!publishable(&retired, now + 8 * day));
    assert_eq!(key.algorithm, "ed25519");
}
