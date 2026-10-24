//! Offline outbreak tests, generated benign fixtures, real parser worker.
use currawong_auth::AuthChecker;
use currawong_core::{
    config::{Config, FeedFormat, IntelFeedConfig},
    Direction, ScanReport, Verdict,
};
use currawong_outbreak::{Content, Detection, Feature, Message, Remediation};
use currawong_spool::{Envelope, Spool, SpoolState};
use currawongd::{classify_pending, Pipeline};
use sha2::{Digest, Sha256};
use std::{
    io::Cursor,
    sync::{Arc, Mutex},
};
use time::OffsetDateTime;
fn envelope() -> Envelope {
    Envelope {
        id: currawong_core::MessageId("01ARZ3NDEKTSV4RRFFQ69G5FAV".into()),
        tenant_id: None,
        authenticated_as: None,
        mail_from: "a@example.test".into(),
        rcpt_to: vec!["dest@example.test".into()],
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
        tls: Default::default(),
        pipeline: "pending".into(),
    }
}

fn worker_bin() -> std::path::PathBuf {
    let exe = std::env::current_exe().unwrap();
    let candidate = exe
        .parent()
        .and_then(|deps| deps.parent())
        .map(|dir| dir.join("currawong-parser-worker"))
        .unwrap();
    assert!(
        candidate.is_file(),
        "parser worker binary: run cargo build -p currawong-parser-worker"
    );
    candidate
}

fn config(dir: &std::path::Path) -> Config {
    let mut cfg = Config::default();
    cfg.spool.dir = dir.join("spool");
    cfg.scanner.worker_binary = Some(worker_bin());
    cfg.scanner.clamd.address.clear();
    cfg.scanner.clamd.required = false;
    cfg.outbreak.enabled = true;
    cfg
}
fn message(bytes: &[u8], name: &str, kind: &str) -> Vec<u8> {
    let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, bytes);
    format!("From: sender@example.test\r\nTo: dest@example.test\r\nSubject: Test\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nPlease review attached document.\r\n--b\r\nContent-Type: {kind}; name=\"{name}\"\r\nContent-Disposition: attachment; filename=\"{name}\"\r\nContent-Transfer-Encoding: base64\r\n\r\n{encoded}\r\n--b--\r\n").into_bytes()
}
fn pipeline(cfg: Config) -> Pipeline {
    Pipeline::new(Arc::new(cfg), AuthChecker::offline("gw.test").unwrap())
}

#[tokio::test]
async fn outbreak_hold_then_release_with_injected_clock_and_allow_cache() {
    let dir = tempfile::tempdir().unwrap();
    let pipeline = pipeline(config(dir.path()));
    let raw = message(
        b"<html><body>Benign attachment for first seen delay</body></html>",
        "review.html",
        "text/html",
    );
    let env = envelope();
    let (report, decision) = pipeline.assess(&env, &raw, None).await;
    assert!(
        matches!(decision.verdict(), Verdict::Defer { .. }),
        "{report:?}"
    );
    assert!(report.outbreak.as_ref().unwrap().held);
    assert!(report.notes.iter().any(|n| n.contains("outbreak hold")));
    let now = currawong_intel::now();
    let mut retry = ScanReport::new(env.id.clone());
    retry.parts = report.parts.clone();
    // Parsed part files are scratch and already removed; clock-only check
    // retains the verified flags/hash but needs no bytes for similarity.
    for p in &mut retry.parts {
        p.path = None;
    }
    pipeline
        .check_outbreak_at(&env, "", &mut retry, now + 30 * 60)
        .await;
    assert!(!retry.defer);
    assert!(!retry.outbreak.unwrap().held);
    let store = pipeline.outbreak.as_ref().unwrap().as_ref().unwrap();
    for part in &report.parts {
        store.mark_clean(&part.sha256, now + 3600).unwrap();
    }
    let (report, decision) = pipeline.assess(&env, &raw, None).await;
    assert!(matches!(decision.verdict(), Verdict::Deliver), "{report:?}");
    assert!(!report.outbreak.unwrap().held);
}

#[tokio::test]
async fn outbreak_index_is_committed_on_scheduler_deliver() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(dir.path());
    let spool = Spool::open(cfg.spool.dir.clone()).await.unwrap();
    let quarantine =
        currawong_quarantine::QuarantineStore::open(dir.path().join("quarantine")).unwrap();
    let mut pipeline = pipeline(cfg);
    let env = envelope();
    let bytes = b"Benign delivered attachment indexed by SHA256";
    spool
        .accept(
            env.clone(),
            Cursor::new(message(bytes, "notes.txt", "text/plain")),
        )
        .await
        .unwrap();
    let store = Arc::clone(pipeline.outbreak.as_ref().unwrap().as_ref().unwrap());
    assert!(store.indicator_page(0).unwrap().is_empty());
    classify_pending(&spool, &mut pipeline, &quarantine)
        .await
        .unwrap();
    assert_eq!(spool.load(&env.id).await.unwrap().pipeline, "deliver");
    let hash = hex::encode(Sha256::digest(bytes));
    assert!(store
        .indicator_page(0)
        .unwrap()
        .iter()
        .any(|(_, kind, value)| kind == "sha256" && value == &hash));
}

#[tokio::test]
async fn outbreak_yara_generation_change_rescans_retained_parts() {
    let dir = tempfile::tempdir().unwrap();
    let rules = dir.path().join("rules");
    std::fs::create_dir(&rules).unwrap();
    std::fs::write(rules.join("test.yar"), "rule Initial { condition: false }").unwrap();
    let mut cfg = config(dir.path());
    cfg.outbreak.retain_parts_hours = 1;
    cfg.scanner.yara.rules_dir = rules.clone();
    let pipeline = pipeline(cfg);
    let env = envelope();
    let raw = message(b"currawong-retro-benign-marker", "notes.txt", "text/plain");
    let (_, decision) = pipeline.assess(&env, &raw, None).await;
    assert!(matches!(decision.verdict(), Verdict::Deliver));
    pipeline
        .index_delivered(env.id.as_str(), &env)
        .await
        .unwrap();
    pipeline.outbreak_tick().await.unwrap();
    pipeline.outbreak_tick().await.unwrap();
    std::fs::write(
        rules.join("test.yar"),
        "rule Retro : malware { strings: $a = \"currawong-retro-benign-marker\" condition: $a }",
    )
    .unwrap();
    pipeline.yara.as_ref().unwrap().reload().unwrap();
    for _ in 0..4 {
        pipeline.outbreak_tick().await.unwrap();
    }
    let conn = rusqlite::Connection::open(pipeline.cfg.spool.dir.join("outbreak.sqlite3")).unwrap();
    let source: String = conn
        .query_row(
            "SELECT source FROM detections WHERE source LIKE 'yara:%'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(source.contains("Retro"));
    assert_eq!(
        conn.query_row(
            "SELECT notified FROM detections WHERE source=?1",
            [source],
            |r| r.get::<_, u32>(0)
        )
        .unwrap(),
        1
    );
}

#[tokio::test]
async fn outbreak_campaign_header_has_size_without_blocking() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = config(dir.path());
    cfg.outbreak.campaign_threshold = 2;
    let pipeline = pipeline(cfg);
    let raw = message(
        b"Same benign attachment appears across this campaign",
        "notes.txt",
        "text/plain",
    );
    let mut env = envelope();
    pipeline.assess(&env, &raw, None).await;
    env.id = currawong_core::MessageId("second".into());
    let (report, decision) = pipeline.assess(&env, &raw, None).await;
    assert_eq!(report.outbreak.unwrap().messages, 2);
    assert!(matches!(decision.verdict(), Verdict::Deliver));
    assert!(decision.decisions.iter().flat_map(|d|&d.actions).any(|a|matches!(a,currawong_policy::Action::AddHeader{name,value} if name=="X-Currawong-Campaign" && value=="2")));
}

#[tokio::test]
async fn outbreak_fake_intel_sync_emits_event_and_calls_remediation() {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };
    let dir = tempfile::tempdir().unwrap();
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let ca = dir.path().join("ca.pem");
    std::fs::write(&ca, cert.pem()).unwrap();
    let tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![CertificateDer::from(cert.der().to_vec())],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der())),
    )
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let hash = hex::encode(Sha256::digest(b"benign delivered part"));
    let url = "https://phish.example.test/path";
    let body = format!("{hash}\n{url}\n");
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut tls = tokio_rustls::TlsAcceptor::from(Arc::new(tls))
            .accept(stream)
            .await
            .unwrap();
        let mut request = Vec::new();
        let mut chunk = [0; 1024];
        while !request.windows(4).any(|s| s == b"\r\n\r\n") {
            let n = tls.read(&mut chunk).await.unwrap();
            assert!(n > 0);
            request.extend_from_slice(&chunk[..n]);
        }
        let reply = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        tls.write_all(reply.as_bytes()).await.unwrap();
        tls.shutdown().await.unwrap();
    });
    let mut cfg = config(dir.path());
    cfg.intel.enabled = true;
    cfg.intel.database = dir.path().join("intel.db");
    cfg.intel.ca_file = Some(ca);
    cfg.intel.feeds.push(IntelFeedConfig {
        name: "fake".into(),
        format: FeedFormat::Lines,
        url: format!("https://localhost:{port}/feed"),
        key_env: None,
        key_file: None,
        auth_header: None,
        refresh_secs: 3600,
        enabled: true,
        kind: None,
        threat: Some("phishing".into()),
    });
    let intel = Arc::new(currawongd::intel::open_store(&cfg).unwrap());
    let store =
        currawong_outbreak::Store::open(&dir.path().join("outbreak.db"), cfg.outbreak.clone())
            .unwrap();
    let recipients = vec!["dest@example.test".into()];
    let msg = Message {
        id: "delivered",
        tenant: "tenant-a",
        sender: "sender@example.test",
        direction: Direction::Inbound,
        recipients: &recipients,
    };
    let content = Content {
        features: vec![
            Feature {
                kind: "sha256".into(),
                value: hash,
                content_type: "text/plain".into(),
                digest: None,
            },
            Feature {
                kind: "url".into(),
                value: url.into(),
                content_type: String::new(),
                digest: None,
            },
        ],
    };
    let now = currawong_intel::now();
    store.observe(&msg, &content, now).unwrap();
    store.deliver(msg.id, &msg, now).unwrap();
    let revision = intel.revision().unwrap();
    let syncer = currawong_intel::Syncer::new(&cfg.intel, Arc::clone(&intel)).unwrap();
    assert!(syncer.sync_due(true).await[0].1.is_ok());
    server.await.unwrap();
    assert_ne!(revision, intel.revision().unwrap());
    let mut cursor = 0;
    while let Some(next) =
        currawongd::outbreak::retro_intel_page(&store, &intel, cursor, now).unwrap()
    {
        cursor = next;
    }
    #[derive(Default)]
    struct Fake(Mutex<Vec<Detection>>);
    impl Remediation for Fake {
        fn remediate(&self, d: &Detection) -> Result<(), String> {
            self.0.lock().unwrap().push(d.clone());
            Ok(())
        }
    }
    let fake = Fake::default();
    let mut events = Vec::new();
    assert_eq!(
        store
            .notify(&fake, |d| events
                .push(currawongd::outbreak::detection_event(d)))
            .unwrap(),
        2
    );
    assert_eq!(fake.0.lock().unwrap().len(), 2);
    assert!(events.iter().all(|e|matches!(&e.kind,currawong_integrations::export::EventKind::VerdictChanged{from,to,..} if from=="deliver" && to=="retro_detection")));
    assert_eq!(
        store.notify(&fake, |_| panic!("duplicate event")).unwrap(),
        0
    );
}

#[tokio::test]
async fn outbreak_short_hold_retry_uses_window_deadline() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = config(dir.path());
    cfg.outbreak.hold_minutes = 1;
    let spool = Spool::open(cfg.spool.dir.clone()).await.unwrap();
    let quarantine =
        currawong_quarantine::QuarantineStore::open(dir.path().join("quarantine")).unwrap();
    let mut pipeline = pipeline(cfg);
    let env = envelope();
    let raw = message(
        b"<html><body>Plain benign review document</body></html>",
        "review.html",
        "text/html",
    );
    let start = currawong_intel::now();
    spool.accept(env.clone(), Cursor::new(raw)).await.unwrap();
    classify_pending(&spool, &mut pipeline, &quarantine)
        .await
        .unwrap();
    let saved = spool.load(&env.id).await.unwrap();
    assert_eq!(saved.pipeline, "scan_defer");
    let next = saved.next_attempt_at.unwrap().unix_timestamp();
    assert!(
        next >= start + 60 && next <= currawong_intel::now() + 60,
        "{next} vs {start}"
    );
}

#[tokio::test]
async fn outbreak_clamd_version_change_rescans_retained_parts() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = format!("tcp:{}", listener.local_addr().unwrap());
    let version = Arc::new(AtomicUsize::new(1));
    let current = Arc::clone(&version);
    let server = tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let mut command = Vec::new();
            loop {
                let byte = stream.read_u8().await.unwrap();
                command.push(byte);
                if byte == 0 {
                    break;
                }
            }
            let version = current.load(Ordering::SeqCst);
            if command == b"zVERSION\0" {
                stream
                    .write_all(format!("ClamAV test/{version}/today\0").as_bytes())
                    .await
                    .unwrap();
            } else {
                assert_eq!(command, b"zINSTREAM\0");
                let mut body = Vec::new();
                loop {
                    let size = stream.read_u32().await.unwrap();
                    if size == 0 {
                        break;
                    }
                    let mut buf = vec![0; size as usize];
                    stream.read_exact(&mut buf).await.unwrap();
                    body.extend_from_slice(&buf);
                }
                let reply = if version == 1
                    || !body
                        .windows(b"benign retained AV marker".len())
                        .any(|s| s == b"benign retained AV marker")
                {
                    b"stream: OK\0".as_slice()
                } else {
                    b"stream: BenignTestMarker FOUND\0".as_slice()
                };
                stream.write_all(reply).await.unwrap();
            }
        }
    });
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = config(dir.path());
    cfg.outbreak.retain_parts_hours = 1;
    // Stage with clamd disabled; only the retro path talks to this fake.
    let mut pipeline = pipeline(cfg);
    let env = envelope();
    pipeline
        .assess(
            &env,
            &message(b"benign retained AV marker", "notes.txt", "text/plain"),
            None,
        )
        .await;
    pipeline
        .index_delivered(env.id.as_str(), &env)
        .await
        .unwrap();
    Arc::get_mut(&mut pipeline.cfg)
        .unwrap()
        .scanner
        .clamd
        .address = address;
    pipeline.outbreak_tick().await.unwrap();
    pipeline.outbreak_tick().await.unwrap();
    version.store(2, Ordering::SeqCst);
    for _ in 0..4 {
        pipeline.outbreak_tick().await.unwrap();
    }
    let conn = rusqlite::Connection::open(pipeline.cfg.spool.dir.join("outbreak.sqlite3")).unwrap();
    assert_eq!(
        conn.query_row(
            "SELECT COUNT(*) FROM detections WHERE source='clamav:BenignTestMarker' AND notified=1",
            [],
            |r| r.get::<_, usize>(0)
        )
        .unwrap(),
        1
    );
    server.abort();
}

#[tokio::test]
async fn outbreak_multi_tenant_hold_and_redirect_keep_owner() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = config(dir.path());
    cfg.outbreak.min_tenants = 2;
    cfg.relay.tenants = [("a", "a.test"), ("b", "b.test")]
        .into_iter()
        .map(|(id, domain)| currawong_core::config::TenantConfig {
            id: id.into(),
            domains: vec![domain.into()],
            trusted_cidrs: vec![],
        })
        .collect();
    let pipeline = pipeline(cfg);
    let mut env = envelope();
    env.rcpt_to = vec!["first@a.test".into(), "second@b.test".into()];
    let payload = b"<html><body>Benign multi tenant attachment</body></html>";
    let raw = message(payload, "review.html", "text/html");
    let (report, decision) = pipeline.assess(&env, &raw, None).await;
    assert!(matches!(decision.verdict(), Verdict::Defer { .. }));
    let result = report.outbreak.unwrap();
    assert!(result.held);
    assert_eq!((result.messages, result.tenants), (1, 2));
    env.direction = Direction::Outbound;
    env.tenant_id = Some("a".into());
    let (report, _) = pipeline.assess(&env, &raw, None).await;
    assert!(!report.outbreak.unwrap().held);
    env.direction = Direction::Inbound;
    env.tenant_id = None;
    env.rcpt_to = vec!["redirect@external.test".into()];
    pipeline
        .index_delivered_for(env.id.as_str(), &env, Some("a"))
        .await
        .unwrap();
    let store = pipeline.outbreak.as_ref().unwrap().as_ref().unwrap();
    store
        .detect("sha256", &hex::encode(Sha256::digest(payload)), "test")
        .unwrap();
    struct Noop;
    impl Remediation for Noop {
        fn remediate(&self, _: &Detection) -> Result<(), String> {
            Ok(())
        }
    }
    let mut found = Vec::new();
    store.notify(&Noop, |d| found.push(d.clone())).unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].tenant, "a");
    assert_eq!(found[0].recipients, vec!["redirect@external.test"]);
}
