use currawong_auth::AuthChecker;
use currawong_core::{
    config::{Config, TenantConfig},
    Direction, MessageId, Verdict,
};
use currawong_policy::{default_pack, Action, Condition, Policy, PolicySet, Scope};
use currawong_quarantine::QuarantineStore;
use currawong_spool::{Envelope, RcptStatus, Spool, SpoolState};
use currawongd::{classify_pending, Pipeline};
use std::{io::Cursor, path::PathBuf, sync::Arc};
use time::OffsetDateTime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const ID: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
const RAW: &[u8] =
    b"From: sender@example.test\r\nTo: a@example.test\r\nSubject: hi\r\n\r\nhello\r\n";

fn envelope(id: &str, rcpt: &[&str]) -> Envelope {
    Envelope {
        id: MessageId(id.into()),
        tenant_id: None,
        authenticated_as: None,
        mail_from: "sender@sender.test".into(),
        rcpt_to: rcpt.iter().map(|r| r.to_string()).collect(),
        received_at: OffsetDateTime::now_utc(),
        remote_ip: "203.0.113.8".parse().unwrap(),
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

fn policy(id: &str, tenant: Option<&str>, scope: Scope, actions: Vec<Action>) -> Policy {
    Policy {
        id: id.into(),
        tenant_id: tenant.map(str::to_string),
        scope,
        priority: 10,
        enabled: true,
        dry_run: false,
        mandatory: false,
        override_floor: Vec::new(),
        conditions: Vec::new(),
        actions,
    }
}

fn recipient_is(mut policy: Policy, rcpt: &str) -> Policy {
    policy.conditions.push(Condition::Recipient(rcpt.into()));
    policy
}

fn with(extra: Vec<Policy>) -> PolicySet {
    let mut set = default_pack().clone();
    set.policies.extend(extra);
    set
}

fn config(dir: &std::path::Path) -> Config {
    let mut cfg = Config::default();
    cfg.spool.dir = dir.join("spool");
    cfg.scanner.clamd.address.clear();
    cfg.scanner.worker_binary = None;
    cfg.relay.tenants = vec![
        TenantConfig {
            id: "t1".into(),
            domains: vec!["example.test".into()],
            trusted_cidrs: Vec::new(),
        },
        TenantConfig {
            id: "t2".into(),
            domains: vec!["other.test".into()],
            trusted_cidrs: Vec::new(),
        },
    ];
    cfg
}

fn pipeline(cfg: Config, policies: PolicySet) -> Pipeline {
    let auth = AuthChecker::offline("currawong.example.test").unwrap();
    Pipeline::new(Arc::new(cfg), auth).with_policies(policies)
}

/// Spool, pipeline and quarantine with one message accepted.
async fn harness(
    dir: &std::path::Path,
    cfg: Config,
    policies: PolicySet,
    env: Envelope,
    raw: &[u8],
) -> (Spool, Pipeline, QuarantineStore) {
    let spool = Spool::open(&cfg.spool.dir).await.unwrap();
    spool.accept(env, Cursor::new(raw.to_vec())).await.unwrap();
    let quarantine = QuarantineStore::open(dir.join("held")).unwrap();
    (spool, pipeline(cfg, policies), quarantine)
}

async fn all(spool: &Spool) -> Vec<Envelope> {
    let mut out = Vec::new();
    for state in [SpoolState::Incoming, SpoolState::Deferred, SpoolState::Done] {
        out.extend(spool.list(state).await.unwrap());
    }
    out
}

/// Minimal clamd: INSTREAM replies FOUND when the stream holds the EICAR bytes.
/// With `hang_up`, it closes the connection without a reply.
async fn fake_clamd(hang_up: bool) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut tmp = [0u8; 4096];
                loop {
                    let n = sock.read(&mut tmp).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                    if buf.starts_with(b"zINSTREAM\0") && buf.ends_with(&[0, 0, 0, 0]) {
                        if hang_up {
                            break;
                        }
                        let sample = currawong_scan::eicar();
                        let hit = buf.windows(sample.len()).any(|w| w == sample);
                        let reply: &[u8] = if hit {
                            b"stream: Eicar-Test-Signature FOUND\0"
                        } else {
                            b"stream: OK\0"
                        };
                        let _ = sock.write_all(reply).await;
                        break;
                    }
                }
            });
        }
    });
    format!("tcp:{addr}")
}

#[tokio::test]
async fn default_pack_matches_the_corpus_expectations() {
    let corpus = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/corpus");
    let expected: toml::Table =
        toml::from_str(&std::fs::read_to_string(corpus.join("expected.toml")).unwrap()).unwrap();
    let mut cfg = Config::default();
    cfg.scanner.worker_binary = None;
    cfg.scanner.clamd.address = fake_clamd(false).await;
    let mut pipeline = pipeline(cfg, default_pack().clone());
    assert!(expected.len() >= 6);
    for (name, entry) in &expected {
        let file = entry["file"].as_str().unwrap();
        let raw = if file == "generated-at-test-time" {
            let mut raw =
                b"From: a@example.test\r\nTo: dest@example.test\r\nSubject: test\r\n\r\n".to_vec();
            raw.extend_from_slice(currawong_scan::eicar());
            raw.extend_from_slice(b"\r\n");
            raw
        } else {
            std::fs::read(corpus.join(file)).unwrap()
        };
        let env = envelope(ID, &["dest@example.test"]);
        let (report, verdict) = pipeline.evaluate(&env, &raw, None).await;
        let got = match verdict {
            Verdict::Deliver => "deliver",
            Verdict::Quarantine { .. } => "quarantine",
            Verdict::Reject { .. } => "reject",
            Verdict::Discard => "discard",
            Verdict::Defer { .. } => "defer",
        };
        assert_eq!(
            got,
            entry["verdict"].as_str().unwrap(),
            "{name}: {report:?}"
        );
        assert_eq!(report.malware, file == "generated-at-test-time", "{name}");
    }
}

#[tokio::test]
async fn required_scanner_hang_up_defers_even_when_a_tenant_allows_everything() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = config(dir.path());
    cfg.scanner.clamd.address = fake_clamd(true).await;
    cfg.scanner.clamd.required = true;
    let allow = policy("allow", Some("t1"), Scope::Tenant, vec![Action::Deliver]);
    let mut pipeline = pipeline(cfg, with(vec![allow]));
    let (_, verdict) = pipeline
        .evaluate(&envelope(ID, &["a@example.test"]), RAW, None)
        .await;
    assert!(matches!(verdict, Verdict::Defer { .. }), "{verdict:?}");
}

#[tokio::test]
async fn inbound_tenant_comes_from_each_recipient_domain() {
    let dir = tempfile::tempdir().unwrap();
    let hold = policy(
        "t1-hold",
        Some("t1"),
        Scope::Tenant,
        vec![Action::Quarantine("t1".into())],
    );
    let mut pipeline = pipeline(config(dir.path()), with(vec![hold]));
    // MX mail: no tenant on the envelope.
    let env = envelope(ID, &["a@example.test", "b@other.test", "c@nobody.test"]);
    let (_, decision) = pipeline.assess(&env, RAW, None).await;
    let tenants: Vec<Option<&str>> = decision
        .decisions
        .iter()
        .map(|d| d.tenant_id.as_deref())
        .collect();
    assert_eq!(tenants, [Some("t1"), Some("t2"), None]);
    assert_eq!(
        decision.decisions[0].verdict,
        Verdict::Quarantine {
            reason: "t1-hold".into()
        }
    );
    assert_eq!(decision.decisions[1].verdict, Verdict::Deliver);
    assert!(decision.decisions[2]
        .explanation
        .iter()
        .any(|l| l.contains("no tenant")));
}

#[tokio::test]
async fn submitted_mail_to_a_local_mailbox_is_scoped_by_that_mailbox() {
    let dir = tempfile::tempdir().unwrap();
    let hold = policy(
        "colleague-hold",
        Some("t1"),
        Scope::User("colleague@example.test".into()),
        vec![Action::Quarantine("review".into())],
    );
    let mut pipeline = pipeline(config(dir.path()), with(vec![hold]));
    let mut env = envelope(ID, &["colleague@example.test", "partner@elsewhere.test"]);
    env.direction = Direction::Outbound;
    env.tenant_id = Some("t1".into());
    env.mail_from = "colleague@example.test".into();
    let (_, decision) = pipeline.assess(&env, RAW, None).await;
    assert!(matches!(
        decision.decisions[0].verdict,
        Verdict::Quarantine { .. }
    ));
    // Outbound user scope needs a login, and MAIL FROM alone is not one.
    assert_eq!(decision.decisions[1].verdict, Verdict::Deliver);
}

#[tokio::test]
async fn split_copies_are_decided_once_and_never_duplicated() {
    let dir = tempfile::tempdir().unwrap();
    let hold = recipient_is(
        policy(
            "hold-one",
            None,
            Scope::Global,
            vec![Action::Quarantine("review".into())],
        ),
        "held@example.test",
    );
    let tag = policy(
        "tag-all",
        None,
        Scope::Global,
        vec![Action::AddHeader {
            name: "X-Policy".into(),
            value: "seen".into(),
        }],
    );
    let rcpts = ["a@example.test", "held@example.test", "b@example.test"];
    let (spool, mut pipeline, quarantine) = harness(
        dir.path(),
        config(dir.path()),
        with(vec![hold, tag]),
        envelope(ID, &rcpts),
        RAW,
    )
    .await;
    classify_pending(&spool, &mut pipeline, &quarantine)
        .await
        .unwrap();

    let original = spool.load(&MessageId(ID.into())).await.unwrap();
    assert_eq!(original.rcpt_to, ["a@example.test", "b@example.test"]);
    assert_eq!(original.pipeline, "deliver");
    assert!(original
        .prepend_headers
        .iter()
        .any(|h| h == "X-Policy: seen\r\n"));
    // The copy was decided in the same pass, from the same scan.
    let copy = all(&spool)
        .await
        .into_iter()
        .find(|e| e.id.as_str() != ID)
        .unwrap();
    assert_eq!(copy.rcpt_to, ["held@example.test"]);
    assert_eq!(copy.state, SpoolState::Done);
    assert_eq!(
        quarantine.reason(copy.id.as_str()).unwrap(),
        "hold-one (queue review)"
    );

    // A crash before the original was narrowed: the retry finds the copy.
    let mut replay = original.clone();
    replay.rcpt_to = rcpts.iter().map(|r| r.to_string()).collect();
    replay.pipeline = "pending".into();
    replay.prepend_headers.clear();
    spool.update(&replay).await.unwrap();
    classify_pending(&spool, &mut pipeline, &quarantine)
        .await
        .unwrap();
    assert_eq!(all(&spool).await.len(), 2);
    let original = spool.load(&MessageId(ID.into())).await.unwrap();
    assert_eq!(original.rcpt_to, ["a@example.test", "b@example.test"]);
}

#[tokio::test]
async fn reject_bounces_only_verified_senders_once_and_discard_is_not_quarantined() {
    let dir = tempfile::tempdir().unwrap();
    let reject = recipient_is(
        policy(
            "no-entry",
            None,
            Scope::Global,
            vec![Action::Reject { code: 554 }],
        ),
        "reject@example.test",
    );
    let drop = recipient_is(
        policy("drop", None, Scope::Global, vec![Action::Discard]),
        "drop@example.test",
    );
    // Unverified MX sender: no backscatter.
    let (spool, mut pipeline, quarantine) = harness(
        dir.path(),
        config(dir.path()),
        with(vec![reject, drop]),
        envelope(ID, &["reject@example.test"]),
        RAW,
    )
    .await;
    // Authenticated submission: bounced.
    let submitted = "01ARZ3NDEKTSV4RRFFQ69G5FAW";
    let mut env = envelope(submitted, &["reject@example.test"]);
    env.tenant_id = Some("t1".into());
    spool.accept(env, Cursor::new(RAW.to_vec())).await.unwrap();
    // Authenticated but automatic: not bounced.
    let auto = "01ARZ3NDEKTSV4RRFFQ69G5FAX";
    let mut env = envelope(auto, &["reject@example.test"]);
    env.tenant_id = Some("t1".into());
    let mut raw = b"Auto-Submitted: auto-replied\r\n".to_vec();
    raw.extend_from_slice(RAW);
    spool.accept(env, Cursor::new(raw)).await.unwrap();
    let dropped = "01ARZ3NDEKTSV4RRFFQ69G5FAY";
    spool
        .accept(
            envelope(dropped, &["drop@example.test"]),
            Cursor::new(RAW.to_vec()),
        )
        .await
        .unwrap();
    classify_pending(&spool, &mut pipeline, &quarantine)
        .await
        .unwrap();

    let bounces = |all: Vec<Envelope>| {
        all.into_iter()
            .filter(|e| e.mail_from.is_empty())
            .collect::<Vec<_>>()
    };
    let dsns = bounces(all(&spool).await);
    assert_eq!(dsns.len(), 1, "{dsns:?}");
    let body = String::from_utf8(spool.read_body(&dsns[0].id).await.unwrap()).unwrap();
    assert!(body.contains("554"), "{body}");
    assert!(!body.contains("no-entry"), "policy id leaked: {body}");
    for id in [ID, auto] {
        let env = spool.load(&MessageId(id.into())).await.unwrap();
        assert_eq!(env.state, SpoolState::Done);
        assert_eq!(env.pipeline, "reject");
        assert!(!env.dsn_sent);
    }
    assert!(quarantine.reason(ID).is_err());

    // A retry after the envelope update was lost does not queue a second DSN.
    let mut replay = spool.load(&MessageId(submitted.into())).await.unwrap();
    assert!(replay.dsn_sent);
    replay.dsn_sent = false;
    replay.pipeline = "pending".into();
    replay.rcpt_status.clear();
    spool.update(&replay).await.unwrap();
    spool
        .transition(&replay.id, SpoolState::Incoming)
        .await
        .unwrap();
    classify_pending(&spool, &mut pipeline, &quarantine)
        .await
        .unwrap();
    assert_eq!(bounces(all(&spool).await).len(), 1);

    let discarded = spool.load(&MessageId(dropped.into())).await.unwrap();
    assert_eq!(discarded.state, SpoolState::Done);
    assert_eq!(discarded.pipeline, "discard");
    assert!(quarantine.reason(dropped).is_err());
}

#[tokio::test]
async fn redirect_and_bcc_stay_inside_allowed_domains_and_rcpt_status() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = config(dir.path());
    cfg.policy.forward_domains = vec!["archive.test".into()];
    let forward = policy(
        "forward",
        Some("t1"),
        Scope::Tenant,
        vec![
            Action::Bcc("audit@example.test".into()),
            Action::Redirect("desk@example.test".into()),
            Action::Bcc("spy@evil.test".into()),
            Action::Bcc("copy@other.test".into()),
            Action::Bcc("keep@archive.test".into()),
        ],
    );
    let mut env = envelope(ID, &["a@example.test"]);
    env.rcpt_status = vec![RcptStatus {
        address: "a@example.test".into(),
        status: "pending".into(),
        detail: String::new(),
    }];
    let (spool, mut pipeline, quarantine) =
        harness(dir.path(), cfg.clone(), with(vec![forward]), env, RAW).await;
    classify_pending(&spool, &mut pipeline, &quarantine)
        .await
        .unwrap();
    let env = spool.load(&MessageId(ID.into())).await.unwrap();
    // The bcc before the redirect survives; other tenants and unknown domains do not.
    assert_eq!(
        env.rcpt_to,
        [
            "desk@example.test",
            "audit@example.test",
            "keep@archive.test"
        ]
    );
    let status: Vec<&str> = env.rcpt_status.iter().map(|s| s.address.as_str()).collect();
    assert_eq!(status, env.rcpt_to);
}

#[tokio::test]
async fn forged_received_headers_do_not_stop_forwarding_and_loops_keep_mandatory_bcc() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(dir.path());
    let tenant_bcc = policy(
        "tenant-bcc",
        Some("t1"),
        Scope::Tenant,
        vec![Action::Bcc("audit@example.test".into())],
    );
    let mut journal = policy(
        "journal",
        None,
        Scope::Global,
        vec![Action::Bcc("journal@example.test".into())],
    );
    journal.mandatory = true;
    let mut forged = "Received: from hop by relay.attacker.test with ESMTP id x;\r\n\tdate\r\n"
        .repeat(30)
        .into_bytes();
    forged.extend_from_slice(RAW);
    let (spool, mut pipeline, quarantine) = harness(
        dir.path(),
        cfg.clone(),
        with(vec![tenant_bcc, journal]),
        envelope(ID, &["a@example.test"]),
        &forged,
    )
    .await;
    // Mail that has been through this gateway three times already.
    let looped = "01ARZ3NDEKTSV4RRFFQ69G5FAW";
    let ours = format!(
        "Received: from hop ([192.0.2.1]) by {} with ESMTP id y;\r\n\tdate\r\n",
        cfg.gateway.hostname
    );
    let mut raw = ours.repeat(3).into_bytes();
    raw.extend_from_slice(RAW);
    spool
        .accept(envelope(looped, &["a@example.test"]), Cursor::new(raw))
        .await
        .unwrap();
    classify_pending(&spool, &mut pipeline, &quarantine)
        .await
        .unwrap();
    let env = spool.load(&MessageId(ID.into())).await.unwrap();
    assert_eq!(
        env.rcpt_to,
        [
            "a@example.test",
            "audit@example.test",
            "journal@example.test"
        ]
    );
    let env = spool.load(&MessageId(looped.into())).await.unwrap();
    assert_eq!(env.rcpt_to, ["a@example.test", "journal@example.test"]);
}

#[tokio::test]
async fn an_interrupted_split_finishes_its_plan_after_a_policy_change() {
    use sha2::{Digest, Sha256};
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(dir.path());
    let hold = recipient_is(
        policy(
            "hold-one",
            None,
            Scope::Global,
            vec![Action::Quarantine("review".into())],
        ),
        "held@example.test",
    );
    let rcpts = ["a@example.test", "held@example.test"];
    let (spool, mut pipeline, quarantine) = harness(
        dir.path(),
        cfg.clone(),
        with(vec![hold]),
        envelope(ID, &rcpts),
        RAW,
    )
    .await;
    // Make writing the copy fail, as a crash would, after the plan is saved.
    let digest = Sha256::digest(format!("{ID}\nheld@example.test"));
    let copy_id = hex::encode_upper(digest)[..26].to_string();
    let blocker = spool
        .root()
        .join(SpoolState::Incoming.dir_name())
        .join(format!("{copy_id}.eml.tmp"));
    std::fs::create_dir_all(&blocker).unwrap();
    classify_pending(&spool, &mut pipeline, &quarantine)
        .await
        .unwrap();
    let original = spool.load(&MessageId(ID.into())).await.unwrap();
    assert_eq!(original.pipeline, "pending");
    assert_eq!(original.rcpt_to, rcpts);

    // The policy is removed before the retry; the saved plan still applies.
    pipeline.policies = default_pack().clone();
    std::fs::remove_dir(&blocker).unwrap();
    classify_pending(&spool, &mut pipeline, &quarantine)
        .await
        .unwrap();
    assert_eq!(
        quarantine.reason(&copy_id).unwrap(),
        "hold-one (queue review)"
    );
    let original = spool.load(&MessageId(ID.into())).await.unwrap();
    assert_eq!(original.rcpt_to, ["a@example.test"]);
    assert_eq!(original.pipeline, "deliver");
    assert!(!spool
        .root()
        .join("split")
        .join(format!("{ID}.json"))
        .exists());
}

#[tokio::test]
async fn policies_reload_when_the_source_changes() {
    let dir = tempfile::tempdir().unwrap();
    let pack = dir.path().join("pack.toml");
    std::fs::write(&pack, "[[policy]]\nid = \"one\"\nactions = [\"deliver\"]\n").unwrap();
    let mut cfg = config(dir.path());
    cfg.policy.pack = Some(pack.clone());
    let mut pipeline = pipeline(cfg.clone(), PolicySet::default());
    assert_eq!(pipeline.reload_policies().await, Ok(true));
    assert_eq!(pipeline.reload_policies().await, Ok(false));
    std::fs::write(&pack, "[[policy]]\nid = \"two\"\nactions = [\"discard\"]\n").unwrap();
    assert_eq!(pipeline.reload_policies().await, Ok(true));
    assert_eq!(pipeline.policies.policies[0].id, "two");
    std::fs::write(&pack, "[[policy]]\nid = \"\"\n").unwrap();
    assert!(pipeline.reload_policies().await.is_err());
    assert_eq!(pipeline.policies.policies[0].id, "two");

    // With a database, a broken pack does not block reloading the database.
    cfg.policy.database = Some(dir.path().join("policy.db"));
    std::fs::write(
        &pack,
        "[[policy]]\nid = \"seed\"\nactions = [\"deliver\"]\n",
    )
    .unwrap();
    let mut pipeline = self::pipeline(cfg.clone(), PolicySet::default());
    assert_eq!(pipeline.reload_policies().await, Ok(true));
    std::fs::write(&pack, "broken [").unwrap();
    let mut store =
        currawong_policy::PolicyStore::open(cfg.policy.database.as_ref().unwrap()).unwrap();
    store
        .upsert(
            None,
            &policy("added", None, Scope::Global, vec![Action::Discard]),
        )
        .unwrap();
    assert_eq!(pipeline.reload_policies().await, Ok(true));
    assert_eq!(pipeline.policies.policies.len(), 2);
}
