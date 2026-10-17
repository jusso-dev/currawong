//! Auth fixes from the M1 reviews: DMARC policy bypass and temperror,
//! header stacking, outbound DKIM, ARC sealing, forged headers already in
//! the spool and the key CLI.
#[path = "../../auth/tests/common/fakedns.rs"]
mod fakedns;

use currawong_auth::{generate, seed_txt, AuthChecker, KeyStore, StoredKey, GATEWAY_TENANT};
use currawong_core::{config::Config, Direction, MessageId, Verdict};
use currawong_quarantine::QuarantineStore;
use currawong_smtp::delivery::outbound_bytes;
use currawong_spool::{Envelope, Spool, SpoolState};
use currawongd::{classify_pending, dkim, Pipeline};
use fakedns::FakeDns;
use std::{io::Cursor, path::Path, sync::Arc};
use time::OffsetDateTime;

const ID: &str = "currawong.example.test";

fn envelope(from: &str, direction: Direction) -> Envelope {
    Envelope {
        id: MessageId("01ARZ3NDEKTSV4RRFFQ69G5FAV".into()),
        tenant_id: Some("local".into()),
        authenticated_as: None,
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
        tls: Default::default(),
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

fn active(tenant: &str, domain: &str, selector: &str, algorithm: &str) -> StoredKey {
    let mut key = generate(tenant, domain, selector, algorithm).unwrap();
    key.active = true;
    key
}

fn checker() -> AuthChecker {
    let auth = AuthChecker::offline(ID).unwrap();
    seed_txt(auth.cache(), "example.test", "v=spf1 +all").unwrap();
    auth
}

/// Spool `raw`, run the pipeline and return the classified envelope and
/// the spooled body afterwards.
async fn classify_raw(
    dir: &Path,
    cfg: Config,
    env: Envelope,
    raw: Vec<u8>,
    keys: Option<KeyStore>,
) -> (Envelope, Vec<u8>) {
    let spool = Spool::open(&cfg.spool.dir).await.unwrap();
    spool.accept(env, Cursor::new(raw)).await.unwrap();
    let mut pipeline = Pipeline::new(Arc::new(cfg), checker());
    if let Some(keys) = keys {
        pipeline = pipeline.with_keys(keys);
    }
    let quarantine = QuarantineStore::open(dir.join("held")).unwrap();
    classify_pending(&spool, &mut pipeline, &quarantine)
        .await
        .unwrap();
    let mut all = spool.list(SpoolState::Incoming).await.unwrap();
    all.extend(spool.list(SpoolState::Deferred).await.unwrap());
    let env = all.remove(0);
    let body = spool.read_body(&env.id).await.unwrap();
    (env, body)
}

async fn classify(dir: &Path, cfg: Config, env: Envelope, keys: Option<KeyStore>) -> Envelope {
    classify_raw(dir, cfg, env, message(), keys).await.0
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

/// Re-review finding 1: a DMARC lookup that fails temporarily defers the
/// message instead of delivering it with an unknown policy.
#[tokio::test]
async fn dmarc_temperror_defers() {
    let dir = tempfile::tempdir().unwrap();
    let dns = FakeDns::start().await;
    dns.txt("attacker.test", "v=spf1 ?all");
    dns.servfail("_dmarc.example.test");
    let auth = AuthChecker::with_name_server(ID, dns.addr).unwrap();
    let mut pipeline = Pipeline::new(Arc::new(config(dir.path())), auth);
    let env = envelope("x@attacker.test", Direction::Inbound);
    let (_, verdict) = pipeline.evaluate(&env, &message(), None).await;
    assert!(matches!(verdict, Verdict::Defer { .. }), "{verdict:?}");

    // With scanning on, the scanners' result must not clear the defer.
    let mut cfg = config(dir.path());
    cfg.scanner.enabled = true;
    cfg.scanner.clamd.address.clear();
    let auth = AuthChecker::with_name_server(ID, dns.addr).unwrap();
    let mut pipeline = Pipeline::new(Arc::new(cfg), auth);
    let (report, verdict) = pipeline.evaluate(&env, &message(), None).await;
    assert!(report.defer, "{report:?}");
    assert!(matches!(verdict, Verdict::Defer { .. }), "{verdict:?}");
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

/// Re-review finding 7: forged results already in the spool (accepted
/// before the DATA strip existed) are removed before delivery.
#[tokio::test]
async fn forged_results_already_spooled_are_stripped_at_classification() {
    let dir = tempfile::tempdir().unwrap();
    let mut raw = format!("Authentication-Results: {ID}; dkim=pass dmarc=pass\r\n").into_bytes();
    raw.extend_from_slice(&message());
    let (env, body) = classify_raw(
        dir.path(),
        config(dir.path()),
        envelope("user@example.test", Direction::Inbound),
        raw,
        None,
    )
    .await;
    assert_eq!(env.pipeline, "deliver");
    let wire = String::from_utf8(outbound_bytes(&env, &body, "mx.example.test")).unwrap();
    assert!(!wire.contains("dmarc=pass"), "{wire}");
    assert_eq!(wire.matches("Authentication-Results:").count(), 1, "{wire}");
}

/// Review finding 5 / #21: outbound tenant mail leaves DKIM signed and the
/// bytes the deliverer sends verify. Re-review finding 2: no
/// Authentication-Results or ARC set goes out on outbound mail.
#[tokio::test]
async fn outbound_tenant_mail_is_dkim_signed_on_the_wire() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(dir.path());
    let store = KeyStore::open(&cfg.dkim.database, &cfg.dkim.kek_path).unwrap();
    let key = active("local", "example.test", "s1", "ed25519");
    store.insert(&key).unwrap();
    store
        .insert(&active(GATEWAY_TENANT, ID, "arc1", "ed25519"))
        .unwrap();
    let env = classify(
        dir.path(),
        cfg,
        envelope("user@example.test", Direction::Outbound),
        Some(store),
    )
    .await;
    assert_eq!(env.pipeline, "deliver");
    let wire = outbound_bytes(&env, &message(), "mx.example.test");
    let text = String::from_utf8_lossy(&wire);
    assert!(text.contains("DKIM-Signature:"), "{text}");
    assert!(!text.contains("Authentication-Results"), "{text}");
    assert!(!text.contains("ARC-Seal"), "{text}");
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

/// Inbound mail is not signed with a tenant key, another tenant's key is
/// never used, and a pending key does not sign.
#[tokio::test]
async fn only_outbound_mail_with_the_tenants_own_active_key_is_signed() {
    for (direction, tenant, activated) in [
        (Direction::Inbound, "local", true),
        (Direction::Outbound, "other", true),
        (Direction::Outbound, "local", false),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let cfg = config(dir.path());
        let store = KeyStore::open(&cfg.dkim.database, &cfg.dkim.kek_path).unwrap();
        let mut key = generate("local", "example.test", "s1", "ed25519").unwrap();
        key.active = activated;
        store.insert(&key).unwrap();
        let mut env = envelope("user@example.test", direction);
        env.tenant_id = Some(tenant.into());
        let env = classify(dir.path(), cfg, env, Some(store)).await;
        assert!(
            !env.prepend_headers.concat().contains("DKIM-Signature"),
            "{direction:?} {tenant} {activated}"
        );
    }
}

/// Re-review finding 3: a tenant with an active key whose signing fails is
/// deferred, never sent unsigned.
#[tokio::test]
async fn signing_failure_defers_instead_of_sending_unsigned() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(dir.path());
    let store = KeyStore::open(&cfg.dkim.database, &cfg.dkim.kek_path).unwrap();
    let mut broken = active("local", "example.test", "s1", "ed25519");
    broken.private_key = zeroize::Zeroizing::new(b"not a pkcs8 key".to_vec());
    store.insert(&broken).unwrap();
    let env = classify(
        dir.path(),
        cfg,
        envelope("user@example.test", Direction::Outbound),
        Some(store),
    )
    .await;
    assert_eq!(env.pipeline, "scan_defer", "{env:?}");
    assert_eq!(env.state, SpoolState::Deferred);
    assert!(env.prepend_headers.is_empty(), "{env:?}");
}

/// Re-review finding 2: ARC sealing happens only for inbound mail a stage
/// modified, and the next hop validates the seal.
#[tokio::test]
async fn only_modified_inbound_mail_is_arc_sealed() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(dir.path());
    let store = KeyStore::open(&cfg.dkim.database, &cfg.dkim.kek_path).unwrap();
    let sealer = active(GATEWAY_TENANT, ID, "arc1", "rsa");
    store.insert(&sealer).unwrap();
    let mut pipeline = Pipeline::new(Arc::new(cfg), checker()).with_keys(store);
    let env = envelope("user@example.test", Direction::Inbound);
    let (mut report, verdict) = pipeline.evaluate(&env, &message(), None).await;
    assert!(matches!(verdict, Verdict::Deliver));
    let plain = pipeline
        .delivery_headers(&env, &message(), &report)
        .await
        .unwrap()
        .concat();
    assert!(
        plain.contains("Authentication-Results") && !plain.contains("ARC-Seal"),
        "{plain}"
    );

    report.modified = true;
    let sealed = pipeline
        .delivery_headers(&env, &message(), &report)
        .await
        .unwrap()
        .concat();
    assert!(sealed.contains("ARC-Seal: i=1;"), "{sealed}");
    let mut wire = sealed.into_bytes();
    wire.extend_from_slice(&message());
    let next = AuthChecker::offline("mx.receiver.test").unwrap();
    seed_txt(next.cache(), &sealer.dns_name(), &sealer.public_txt).unwrap();
    let results = next.check(&wire, &env).await;
    assert_eq!(results.arc.result, "pass", "{}", results.header);

    let outbound = envelope("user@example.test", Direction::Outbound);
    let out = pipeline
        .delivery_headers(&outbound, &message(), &report)
        .await
        .unwrap()
        .concat();
    assert!(
        !out.contains("ARC-Seal") && !out.contains("Authentication-Results"),
        "{out}"
    );
}

/// Re-review finding 4: a generated key is pending, activation needs the
/// record in DNS, and activating the next selector retires the old one.
#[tokio::test]
async fn dkim_cli_activates_only_published_keys() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(dir.path());
    let dns = FakeDns::start().await;
    let resolver = AuthChecker::with_name_server(ID, dns.addr).unwrap();
    let generate_cmd = |selector: &str| dkim::DkimCommand::Generate {
        tenant: "local".into(),
        domain: "example.test".into(),
        selector: selector.into(),
        algorithm: "rsa".into(),
    };
    let activate_cmd = |selector: &str| dkim::DkimCommand::Activate {
        tenant: "local".into(),
        domain: "example.test".into(),
        selector: selector.into(),
    };
    let records_cmd = || dkim::DkimCommand::Records {
        tenant: "local".into(),
        domain: "example.test".into(),
    };
    let out = dkim::run(&cfg, generate_cmd("s1"), &resolver)
        .await
        .unwrap();
    assert!(
        out.starts_with("s1._domainkey.example.test. IN TXT \"v=DKIM1; k=rsa; p="),
        "{out}"
    );
    // RSA-2048 needs more than one 255-byte TXT string.
    assert!(out.contains("\" \"") && out.contains("; pending"), "{out}");

    let err = dkim::run(&cfg, activate_cmd("s1"), &resolver)
        .await
        .unwrap_err();
    assert!(
        err.contains("not published") || err.contains("does not serve"),
        "{err}"
    );

    let store = KeyStore::open(&cfg.dkim.database, &cfg.dkim.kek_path).unwrap();
    let s1 = store.find("local", "example.test", "s1").unwrap().unwrap();
    assert!(store
        .signing_keys("local", "example.test", 0)
        .unwrap()
        .is_empty());
    dns.txt(&s1.dns_name(), &s1.public_txt);
    dkim::run(&cfg, activate_cmd("s1"), &resolver)
        .await
        .unwrap();

    dkim::run(&cfg, generate_cmd("s2"), &resolver)
        .await
        .unwrap();
    let s2 = store.find("local", "example.test", "s2").unwrap().unwrap();
    dns.txt(&s2.dns_name(), &s2.public_txt);
    dkim::run(&cfg, activate_cmd("s2"), &resolver)
        .await
        .unwrap();

    let records = dkim::run(&cfg, records_cmd(), &resolver).await.unwrap();
    assert!(
        records.contains("s1._domainkey") && records.contains("; retired"),
        "{records}"
    );
    assert!(
        records.contains("s2._domainkey") && records.contains("; active"),
        "{records}"
    );
}
