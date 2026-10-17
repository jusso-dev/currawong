use currawong_auth::AuthChecker;
use currawong_core::{config::Config, Direction, MessageId, Verdict};
use currawong_policy::{default_pack, Action, Condition, Policy, Scope};
use currawong_quarantine::QuarantineStore;
use currawong_spool::{Envelope, Spool, SpoolState};
use currawongd::{classify_pending, Pipeline};
use std::{io::Cursor, path::PathBuf, sync::Arc};
use time::OffsetDateTime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn envelope(id: &str, rcpt: &[&str]) -> Envelope {
    Envelope {
        id: MessageId(id.into()),
        tenant_id: None,
        mail_from: "sender@example.test".into(),
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

/// Minimal clamd: INSTREAM replies FOUND when the stream holds the EICAR bytes.
async fn fake_clamd() -> std::net::SocketAddr {
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
    addr
}

#[tokio::test]
async fn default_pack_matches_the_corpus_expectations() {
    let corpus = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/corpus");
    let expected: toml::Table =
        toml::from_str(&std::fs::read_to_string(corpus.join("expected.toml")).unwrap()).unwrap();
    let mut cfg = Config::default();
    cfg.scanner.worker_binary = None;
    cfg.scanner.clamd.address = format!("tcp:{}", fake_clamd().await);
    let auth = AuthChecker::offline("currawong.example.test").unwrap();
    let mut pipeline = Pipeline::new(Arc::new(cfg), auth).with_policies(default_pack().clone());
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
        let env = envelope("01ARZ3NDEKTSV4RRFFQ69G5FAV", &["dest@example.test"]);
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
async fn differing_recipients_are_split_and_actions_applied() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::default();
    cfg.spool.dir = dir.path().join("spool");
    cfg.scanner.clamd.address.clear();
    cfg.scanner.worker_binary = None;
    let spool = Spool::open(&cfg.spool.dir).await.unwrap();
    let raw = b"From: sender@example.test\r\nTo: a@example.test\r\nSubject: hi\r\n\r\nhello\r\n";
    let env = envelope(
        "01ARZ3NDEKTSV4RRFFQ69G5FAV",
        &["a@example.test", "held@example.test", "b@example.test"],
    );
    spool.accept(env, Cursor::new(raw.to_vec())).await.unwrap();

    let mut policies = default_pack().clone();
    policies.policies.push(Policy {
        id: "hold-one".into(),
        tenant_id: None,
        scope: Scope::Global,
        priority: 1,
        enabled: true,
        dry_run: false,
        conditions: vec![Condition::Recipient("held@example.test".into())],
        actions: vec![Action::Quarantine("review".into())],
    });
    policies.policies.push(Policy {
        id: "tag-all".into(),
        tenant_id: None,
        scope: Scope::Global,
        priority: 2,
        enabled: true,
        dry_run: false,
        conditions: Vec::new(),
        actions: vec![Action::AddHeader {
            name: "X-Policy".into(),
            value: "seen".into(),
        }],
    });
    let auth = AuthChecker::offline("currawong.example.test").unwrap();
    let mut pipeline = Pipeline::new(Arc::new(cfg), auth).with_policies(policies);
    let quarantine = QuarantineStore::open(dir.path().join("held")).unwrap();
    classify_pending(&spool, &mut pipeline, &quarantine)
        .await
        .unwrap();

    let incoming = spool.list(SpoolState::Incoming).await.unwrap();
    let original = incoming
        .iter()
        .find(|e| e.id.as_str() == "01ARZ3NDEKTSV4RRFFQ69G5FAV")
        .unwrap();
    assert_eq!(original.rcpt_to, ["a@example.test", "b@example.test"]);
    assert_eq!(original.pipeline, "deliver");
    assert!(original
        .prepend_headers
        .iter()
        .any(|h| h == "X-Policy: seen\r\n"));
    let split = incoming
        .iter()
        .find(|e| e.id.as_str() != "01ARZ3NDEKTSV4RRFFQ69G5FAV")
        .unwrap();
    assert_eq!(split.rcpt_to, ["held@example.test"]);
    assert_eq!(split.pipeline, "pending");

    // The split copy is decided on its own on the next pass.
    classify_pending(&spool, &mut pipeline, &quarantine)
        .await
        .unwrap();
    assert_eq!(quarantine.reason(split.id.as_str()).unwrap(), "hold-one");
    let done = spool.list(SpoolState::Done).await.unwrap();
    assert!(done.iter().any(|e| e.id == split.id));
}
