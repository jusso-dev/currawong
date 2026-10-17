use currawong_auth::{
    generate, publishable, seed_txt, sign, sign_message, sign_outbound, AuthChecker, KeyStore,
    StoredKey,
};
use currawong_core::{Direction, MessageId};
use currawong_spool::{Envelope, SpoolState};
use std::net::{IpAddr, Ipv4Addr};
use time::OffsetDateTime;

const DAY: u64 = 24 * 60 * 60;

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
        authenticated_as: None,
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
        tls: Default::default(),
        pipeline: "pending".into(),
    }
}

/// An activated key, as after `dkim activate`.
fn key(selector: &str, algorithm: &str) -> StoredKey {
    let mut key = generate("local", "example.test", selector, algorithm).unwrap();
    key.active = true;
    key
}

fn checker_with(keys: &[&StoredKey]) -> AuthChecker {
    let checker = AuthChecker::offline("currawong.example.test").unwrap();
    for key in keys {
        seed_txt(checker.cache(), &key.dns_name(), &key.public_txt).unwrap();
    }
    seed_txt(checker.cache(), "example.test", "v=spf1 +all").unwrap();
    seed_txt(checker.cache(), "_dmarc.example.test", "v=DMARC1; p=none").unwrap();
    checker
}

fn dkim_results(results: &currawong_core::AuthResults) -> Vec<&str> {
    results
        .dkim
        .iter()
        .map(|item| item.result.as_str())
        .collect()
}

#[tokio::test]
async fn signed_fixture_is_dkim_pass_and_dmarc_pass() {
    let key = key("ed", "ed25519");
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

/// Review finding 1: the attacker's MAIL FROM is echoed into our own header
/// as `smtp.mailfrom=`, so parsing the rendered header for `policy.dmarc=`
/// let `MAIL FROM:<policy.dmarc=none@attacker.test>` downgrade p=reject.
#[tokio::test]
async fn mail_from_cannot_spoof_the_dmarc_policy() {
    let checker = AuthChecker::offline("currawong.example.test").unwrap();
    seed_txt(checker.cache(), "attacker.test", "v=spf1 -all").unwrap();
    seed_txt(checker.cache(), "_dmarc.example.test", "v=DMARC1; p=reject").unwrap();
    let results = checker
        .check(&message(), &envelope("policy.dmarc=none@attacker.test"))
        .await;
    assert_eq!(results.dmarc.result, "fail", "{}", results.header);
    assert_eq!(results.dmarc_policy, "reject", "{}", results.header);
}

/// RFC 7208 section 2.4: bounces are SPF checked as postmaster@HELO.
#[tokio::test]
async fn null_sender_is_checked_against_the_helo_domain() {
    let checker = AuthChecker::offline("currawong.example.test").unwrap();
    seed_txt(
        checker.cache(),
        "client.example.test",
        "v=spf1 ip4:203.0.113.5 -all",
    )
    .unwrap();
    let results = checker.check(&message(), &envelope("")).await;
    assert_eq!(results.spf.result, "pass", "{}", results.header);
    assert!(
        results
            .header
            .contains("smtp.mailfrom=postmaster@client.example.test"),
        "{}",
        results.header
    );
}

#[tokio::test]
async fn sign_round_trip_rsa_and_ed25519() {
    for key in [key("ed", "ed25519"), key("currawong", "rsa")] {
        let signed = sign_message(&message(), &key).unwrap();
        assert!(signed
            .windows(14)
            .any(|window| window.eq_ignore_ascii_case(b"DKIM-Signature")));
        let checker = checker_with(&[&key]);
        let results = checker.check(&signed, &envelope("user@example.test")).await;
        assert_eq!(
            dkim_results(&results),
            vec!["pass"],
            "{} {}",
            key.algorithm,
            results.header
        );
    }
}

#[tokio::test]
async fn sign_dual_signs_with_rsa_and_ed25519() {
    let ed = key("ed", "ed25519");
    let rsa = key("rsa", "rsa");
    let headers = sign(&message(), &[rsa.clone(), ed.clone()]).unwrap();
    assert_eq!(headers.matches("DKIM-Signature:").count(), 2, "{headers}");
    let mut signed = headers.into_bytes();
    signed.extend_from_slice(&message());
    let results = checker_with(&[&ed, &rsa])
        .check(&signed, &envelope("user@example.test"))
        .await;
    assert_eq!(
        dkim_results(&results),
        vec!["pass", "pass"],
        "{}",
        results.header
    );
}

#[test]
fn sign_rsa_keys_are_2048_bit_and_names_are_per_domain() {
    use rsa::{pkcs8::DecodePrivateKey, traits::PublicKeyParts, RsaPrivateKey};
    let key = generate("tenant-a", "Example.Test.", "s1", "rsa").unwrap();
    let private = RsaPrivateKey::from_pkcs8_der(&key.private_key).unwrap();
    assert_eq!(private.size() * 8, 2048);
    assert_eq!(key.domain, "example.test");
    assert_eq!(key.tenant_id, "tenant-a");
    assert_eq!(key.dns_name(), "s1._domainkey.example.test");
    assert!(generate("t", "example.test", "bad selector", "ed25519").is_err());
    assert!(generate("t", "example.test", "s", "dsa").is_err());
}

#[test]
fn sign_debug_output_never_contains_the_private_key() {
    let key = key("ed", "ed25519");
    let printed = format!("{key:?}");
    assert!(printed.contains("<redacted>"), "{printed}");
    let der = format!("{:?}", key.private_key.as_slice());
    assert!(!printed.contains(&der[1..20]), "{printed}");
}

#[test]
fn sign_store_keeps_tenants_apart_and_rejects_duplicate_selectors() {
    let dir = tempfile::tempdir().unwrap();
    let store = KeyStore::open(&dir.path().join("keys.sqlite"), &dir.path().join("kek")).unwrap();
    store.insert(&key("s1", "ed25519")).unwrap();
    store.insert(&key("s2", "rsa")).unwrap();
    assert!(store.insert(&key("s1", "ed25519")).is_err());
    let now = currawong_auth_now();
    assert_eq!(
        store
            .signing_keys("local", "example.test", now)
            .unwrap()
            .len(),
        2
    );
    assert!(store
        .signing_keys("other", "example.test", now)
        .unwrap()
        .is_empty());
    let raw = message();
    assert!(sign_outbound(&store, &raw, "other").unwrap().is_empty());
    let headers = sign_outbound(&store, &raw, "local").unwrap();
    assert_eq!(headers.matches("DKIM-Signature:").count(), 2, "{headers}");
}

#[test]
fn sign_missing_kek_is_not_silently_regenerated() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("keys.sqlite");
    let kek = dir.path().join("kek");
    let store = KeyStore::open(&db, &kek).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&kek).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    store.insert(&key("s1", "ed25519")).unwrap();
    std::fs::remove_file(&kek).unwrap();
    let err = KeyStore::open(&db, &kek).err().expect("must refuse");
    assert!(err.contains("missing"), "{err}");
    assert!(!kek.exists());
}

/// Re-review finding 9: blobs are bound to their row, legacy blobs are
/// refused and the database is created 0600.
#[test]
fn sign_key_blobs_are_bound_to_their_row() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("keys.sqlite");
    let store = KeyStore::open(&db, &dir.path().join("kek")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&db).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    store.insert(&key("s1", "ed25519")).unwrap();
    store.insert(&key("s2", "ed25519")).unwrap();
    assert_eq!(
        store
            .publishable_keys("local", "example.test", 0)
            .unwrap()
            .len(),
        2
    );
    let conn = rusqlite::Connection::open(&db).unwrap();
    conn.execute(
        "UPDATE dkim_keys SET private_key_enc = (SELECT private_key_enc FROM dkim_keys WHERE selector = 's1') WHERE selector = 's2'",
        [],
    )
    .unwrap();
    let err = store
        .publishable_keys("local", "example.test", 0)
        .unwrap_err();
    assert!(err.contains("another row"), "{err}");
    conn.execute(
        "UPDATE dkim_keys SET private_key_enc = substr(private_key_enc, 5) WHERE selector = 's2'",
        [],
    )
    .unwrap();
    let err = store
        .publishable_keys("local", "example.test", 0)
        .unwrap_err();
    assert!(err.contains("legacy"), "{err}");
}

fn currawong_auth_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// #21: after rotation the new selector signs, and mail signed with the old
/// one still verifies against the records we publish for seven days.
#[tokio::test]
async fn sign_rotation_keeps_old_selector_valid_for_seven_days() {
    let dir = tempfile::tempdir().unwrap();
    let store = KeyStore::open(&dir.path().join("keys.sqlite"), &dir.path().join("kek")).unwrap();
    store.insert(&key("2026a", "ed25519")).unwrap();
    let raw = message();
    let mut before = sign_outbound(&store, &raw, "local").unwrap().into_bytes();
    before.extend_from_slice(&raw);
    assert!(String::from_utf8_lossy(&before).contains("s=2026a"));

    // A new selector is pending until activated: it is published, not used.
    let now = currawong_auth_now();
    let next = generate("local", "example.test", "2026b", "ed25519").unwrap();
    assert_eq!(next.state(), "pending");
    store.insert(&next).unwrap();
    let pending = sign_outbound(&store, &raw, "local").unwrap();
    assert!(
        pending.contains("s=2026a") && !pending.contains("s=2026b"),
        "{pending}"
    );
    assert!(store
        .publishable_keys("local", "example.test", now)
        .unwrap()
        .iter()
        .any(|item| item.selector == "2026b" && item.state() == "pending"));
    store.activate(&next.id, now).unwrap();
    // Activation clears the decrypted-key cache straight away.
    let after = sign_outbound(&store, &raw, "local").unwrap();
    assert!(
        after.contains("s=2026b") && !after.contains("s=2026a"),
        "{after}"
    );

    for (offset, old_valid) in [(6 * DAY, true), (8 * DAY, false)] {
        let published = store
            .publishable_keys("local", "example.test", now + offset)
            .unwrap();
        let refs: Vec<&StoredKey> = published.iter().collect();
        let results = checker_with(&refs)
            .check(&before, &envelope("user@example.test"))
            .await;
        let expected = if old_valid { "pass" } else { "permerror" };
        assert_eq!(
            dkim_results(&results).first().copied(),
            Some(expected),
            "day {} {}",
            offset / DAY,
            results.header
        );
        assert!(published.iter().any(|item| item.selector == "2026b"));
    }
}

#[test]
fn sign_retired_selector_stays_publishable_for_seven_days() {
    let dir = tempfile::tempdir().unwrap();
    let store = KeyStore::open(&dir.path().join("keys.sqlite"), &dir.path().join("kek")).unwrap();
    let mut key = key("ed", "ed25519");
    key.created_at = 1_000;
    store.insert(&key).unwrap();
    let now = 2_000;
    store.retire(&key.id, now).unwrap();
    assert!(store
        .publishable_keys("local", "example.test", now + 6 * DAY)
        .unwrap()
        .iter()
        .any(|item| item.selector == "ed"));
    assert!(store
        .signing_keys("local", "example.test", now + 6 * DAY)
        .unwrap()
        .is_empty());
    assert!(store
        .publishable_keys("local", "example.test", now + 8 * DAY)
        .unwrap()
        .is_empty());
    let mut retired = key.clone();
    retired.active = false;
    retired.retired_at = Some(now);
    assert!(publishable(&retired, now + 6 * DAY));
    assert!(!publishable(&retired, now + 8 * DAY));
}

/// ARC seal carries our real results and verifies; a second hop chains on
/// with i=2 and cv=pass.
#[tokio::test]
async fn sign_arc_seal_verifies_and_chains() {
    let sealer = generate("_gateway", "currawong.example.test", "arc", "rsa").unwrap();
    let gateway = checker_with(&[&sealer]);
    let raw = message();
    let first = gateway
        .check_and_seal(&raw, &envelope("user@example.test"), Some(&sealer))
        .await;
    assert!(first.header.contains("ARC-Seal: i=1;"), "{}", first.header);
    assert!(
        first
            .header
            .contains("ARC-Authentication-Results: i=1; currawong.example.test;")
            && first.header.contains("spf=pass"),
        "{}",
        first.header
    );
    let mut hop1 = first.header.into_bytes();
    hop1.extend_from_slice(&raw);

    let next = AuthChecker::offline("mx2.example.test").unwrap();
    seed_txt(next.cache(), &sealer.dns_name(), &sealer.public_txt).unwrap();
    seed_txt(next.cache(), "example.test", "v=spf1 +all").unwrap();
    let second = next
        .check_and_seal(&hop1, &envelope("user@example.test"), Some(&sealer))
        .await;
    assert_eq!(second.arc.result, "pass", "{}", second.header);
    assert!(
        second.header.contains("i=2;") && second.header.contains("cv=pass"),
        "{}",
        second.header
    );
    let mut hop2 = second.header.into_bytes();
    hop2.extend_from_slice(&hop1);
    let third = next.check(&hop2, &envelope("user@example.test")).await;
    assert_eq!(third.arc.result, "pass", "{}", third.header);
}

/// Re-review finding 11: headers added in transit (a second Subject, a Cc
/// or Reply-To that was absent at signing) break the signature.
#[tokio::test]
async fn sign_oversigned_headers_cannot_be_added_in_transit() {
    let key = key("ed", "ed25519");
    let signed = sign_message(&message(), &key).unwrap();
    for added in [
        "Subject: urgent: new bank details\r\n",
        "Reply-To: attacker@evil.test\r\n",
        "Cc: someone@evil.test\r\n",
    ] {
        let text = String::from_utf8(signed.clone()).unwrap();
        let split = text.find("From: user@example.test").unwrap();
        let tampered = format!("{}{added}{}", &text[..split], &text[split..]);
        let results = checker_with(&[&key])
            .check(tampered.as_bytes(), &envelope("user@example.test"))
            .await;
        assert_eq!(
            dkim_results(&results),
            vec!["fail"],
            "{added}: {}",
            results.header
        );
    }
}
