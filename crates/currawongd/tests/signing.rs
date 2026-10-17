//! Auth fixes from the M1 review: DMARC policy bypass, header stacking,
//! outbound DKIM, ARC sealing and the key CLI.
use currawong_auth::{generate, seed_txt, AuthChecker, KeyStore, GATEWAY_TENANT};
use currawong_core::{config::Config, Direction, MessageId, Verdict};
use currawong_quarantine::QuarantineStore;
use currawong_smtp::delivery::outbound_bytes;
use currawong_spool::{Envelope, Spool, SpoolState};
use currawongd::{classify_pending, dkim, Pipeline};
use std::{io::Cursor, path::Path, sync::Arc};
use time::OffsetDateTime;

const ID: &str = "currawong.example.test";

fn envelope(from: &str, direction: Direction) -> Envelope {
    Envelope {
        id: MessageId("01ARZ3NDEKTSV4RRFFQ69G5FAV".into()),
        tenant_id: Some("local".into()),
        mail_from: from.into(),
        rcpt_to: vec!["dest@example.test".into()],
        received_at: OffsetDateTime::now_utc(),
        remote_ip: "203.0.113.8".parse().unwrap(),
        helo: "client.example.test".into(),
        attempts: 0,
        next_attempt_at: None,
        state: SpoolState::Incoming,
        direction,
        tls_version: None,
        tls_cipher: None,
        rcpt_status: Vec::new(),
        prepend_headers: Vec::new(),
        dsn_sent: false,
        pipeline: "pending".into(),
    }
}

fn message() -> Vec<u8> {
    b"From: user@example.test\r\nTo: dest@example.test\r\nSubject: hi\r\nDate: Wed, 14 Oct 2026 01:00:00 +0000\r\nMessage-ID: <1@example.test>\r\n\r\nhello\r\n".to_vec()
}

fn config(dir: &Path) -> Config {
    let mut cfg = Config::default();
    cfg.spool.dir = dir.join("spool");
    cfg.scanner.enabled = false;
    cfg.auth.authserv_id = ID.into();
    cfg.dkim.database = dir.join("dkim.sqlite");
    cfg.dkim.kek_path = dir.join("dkim.kek");
    cfg
}

/// Spool one message, run the pipeline and return the classified envelope.
async fn classify(dir: &Path, cfg: Config, env: Envelope, keys: Option<KeyStore>) -> Envelope {
    let spool = Spool::open(&cfg.spool.dir).await.unwrap();
    spool.accept(env, Cursor::new(message())).await.unwrap();
    let auth = AuthChecker::offline(ID).unwrap();
    seed_txt(auth.cache(), "example.test", "v=spf1 +all").unwrap();
    let mut pipeline = Pipeline::new(Arc::new(cfg), auth);
    if let Some(keys) = keys {
        pipeline = pipeline.with_keys(keys);
    }
    let quarantine = QuarantineStore::open(dir.join("held")).unwrap();
    classify_pending(&spool, &mut pipeline, &quarantine)
        .await
        .unwrap();
    spool.list(SpoolState::Incoming).await.unwrap().remove(0)
}

/// Review finding 1, end to end: the exact one-command attack is quarantined.
#[tokio::test]
async fn mail_from_policy_injection_is_still_quarantined() {
    let dir = tempfile::tempdir().unwrap();
    let auth = AuthChecker::offline(ID).unwrap();
    seed_txt(auth.cache(), "attacker.test", "v=spf1 -all").unwrap();
    seed_txt(auth.cache(), "_dmarc.example.test", "v=DMARC1; p=reject").unwrap();
    let mut pipeline = Pipeline::new(Arc::new(config(dir.path())), auth);
    let env = envelope("policy.dmarc=none@attacker.test", Direction::Inbound);
    let (report, verdict) = pipeline.evaluate(&env, &message(), None).await;
    assert_eq!(report.auth.unwrap().dmarc_policy, "reject");
    assert!(matches!(verdict, Verdict::Quarantine { .. }), "{verdict:?}");
}

/// Review finding 15: re-evaluation replaces our headers instead of stacking.
#[tokio::test]
async fn reclassifying_replaces_previous_gateway_headers() {
    let dir = tempfile::tempdir().unwrap();
    let mut env = envelope("user@example.test", Direction::Inbound);
    env.prepend_headers = vec![format!("Authentication-Results: {ID}; stale\r\n")];
    let env = classify(dir.path(), config(dir.path()), env, None).await;
    let joined = env.prepend_headers.concat();
    assert_eq!(
        joined.matches("Authentication-Results:").count(),
        1,
        "{joined}"
    );
    assert!(!joined.contains("stale"), "{joined}");
}

/// Review finding 5 / #21: outbound tenant mail leaves DKIM signed and the
/// bytes the deliverer sends verify.
#[tokio::test]
async fn outbound_tenant_mail_is_dkim_signed_on_the_wire() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(dir.path());
    let store = KeyStore::open(&cfg.dkim.database, &cfg.dkim.kek_path).unwrap();
    let key = generate("local", "example.test", "s1", "ed25519").unwrap();
    store.insert(&key).unwrap();
    let env = classify(
        dir.path(),
        cfg,
        envelope("user@example.test", Direction::Outbound),
        Some(store),
    )
    .await;
    assert_eq!(env.pipeline, "deliver");
    let wire = outbound_bytes(&env, &message(), "mx.example.test");
    assert!(String::from_utf8_lossy(&wire).contains("DKIM-Signature:"));
    let verifier = AuthChecker::offline("mx.receiver.test").unwrap();
    seed_txt(verifier.cache(), &key.dns_name(), &key.public_txt).unwrap();
    let mut far = envelope("user@example.test", Direction::Inbound);
    far.tenant_id = None;
    let results = verifier.check(&wire, &far).await;
    assert_eq!(
        results.dkim.first().map(|item| item.result.as_str()),
        Some("pass"),
        "{}",
        results.header
    );
}

/// Inbound mail is not signed with a tenant key, and another tenant's key is
/// never used for this tenant's mail.
#[tokio::test]
async fn only_outbound_mail_with_the_tenants_own_key_is_signed() {
    for (direction, tenant) in [
        (Direction::Inbound, "local"),
        (Direction::Outbound, "other"),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let cfg = config(dir.path());
        let store = KeyStore::open(&cfg.dkim.database, &cfg.dkim.kek_path).unwrap();
        store
            .insert(&generate("local", "example.test", "s1", "ed25519").unwrap())
            .unwrap();
        let mut env = envelope("user@example.test", direction);
        env.tenant_id = Some(tenant.into());
        let env = classify(dir.path(), cfg, env, Some(store)).await;
        assert!(
            !env.prepend_headers.concat().contains("DKIM-Signature"),
            "{direction:?} {tenant}"
        );
    }
}

/// With `seal_arc` and a gateway key, delivered mail carries an ARC set the
/// next hop validates.
#[tokio::test]
async fn delivered_mail_is_arc_sealed_with_the_gateway_key() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(dir.path());
    let store = KeyStore::open(&cfg.dkim.database, &cfg.dkim.kek_path).unwrap();
    let sealer = generate(GATEWAY_TENANT, ID, "arc1", "rsa").unwrap();
    store.insert(&sealer).unwrap();
    let env = classify(
        dir.path(),
        cfg,
        envelope("user@example.test", Direction::Inbound),
        Some(store),
    )
    .await;
    let wire = outbound_bytes(&env, &message(), "mx.example.test");
    let text = String::from_utf8_lossy(&wire);
    assert!(text.contains("ARC-Seal: i=1;"), "{text}");
    let next = AuthChecker::offline("mx.receiver.test").unwrap();
    seed_txt(next.cache(), &sealer.dns_name(), &sealer.public_txt).unwrap();
    let results = next
        .check(&wire, &envelope("user@example.test", Direction::Inbound))
        .await;
    assert_eq!(results.arc.result, "pass", "{}", results.header);
}

#[test]
fn dkim_cli_generates_rotates_and_lists_records() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(dir.path());
    let out = dkim::run(
        &cfg,
        dkim::DkimCommand::Generate {
            tenant: "local".into(),
            domain: "example.test".into(),
            selector: "s1".into(),
            algorithm: "rsa".into(),
        },
    )
    .unwrap();
    assert!(
        out.starts_with("s1._domainkey.example.test. IN TXT \"v=DKIM1; k=rsa; p="),
        "{out}"
    );
    // RSA-2048 needs more than one 255-byte TXT string.
    assert!(out.contains("\" \""), "{out}");
    dkim::run(
        &cfg,
        dkim::DkimCommand::Rotate {
            tenant: "local".into(),
            domain: "example.test".into(),
            selector: "s2".into(),
            algorithm: "rsa".into(),
        },
    )
    .unwrap();
    let records = dkim::run(
        &cfg,
        dkim::DkimCommand::Records {
            tenant: "local".into(),
            domain: "example.test".into(),
        },
    )
    .unwrap();
    assert!(
        records.contains("s1._domainkey") && records.contains("; retired"),
        "{records}"
    );
    assert!(
        records.contains("s2._domainkey") && records.contains("; active"),
        "{records}"
    );
}
