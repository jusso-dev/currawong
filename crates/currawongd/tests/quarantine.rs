//! Quarantine end to end: policy holds spam, the user's digest link releases
//! it, and the scheduler delivers it once without quarantining it again.
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use currawong_auth::AuthChecker;
use currawong_core::{
    config::{Config, DomainRoute},
    Direction, MessageId,
};
use currawong_policy::{default_pack, Action, Condition, Policy, Scope};
use currawong_quarantine::{
    digest::{send_digests, DigestSettings},
    http::{router, HttpState},
    LinkSigner, QuarantineStore,
};
use currawong_smtp::{
    delivery::{Deliverer, DeliveryOutcome},
    dns::MapDns,
};
use currawong_spool::{Envelope, Spool, SpoolState};
use currawongd::{classify_pending, ready_to_deliver, Pipeline};
use std::{io::Cursor, sync::Arc, time::Duration};
use time::OffsetDateTime;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::TcpListener,
};
use tower::ServiceExt;

const ID: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
const RAW: &[u8] =
    b"From: sender@outside.test\r\nTo: user@example.test\r\nSubject: Cheap pills\r\n\r\nbuy now\r\n";

/// Accepts every message and hands its DATA to the test.
async fn sink(captured: tokio::sync::mpsc::UnboundedSender<Vec<u8>>) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((sock, _)) = listener.accept().await {
            let captured = captured.clone();
            tokio::spawn(async move {
                let (read, mut write) = sock.into_split();
                let mut read = BufReader::new(read);
                let _ = write.write_all(b"220 sink ESMTP\r\n").await;
                let mut line = String::new();
                loop {
                    line.clear();
                    if read.read_line(&mut line).await.unwrap_or(0) == 0 {
                        break;
                    }
                    let verb = line.get(..4).unwrap_or("").to_ascii_uppercase();
                    let reply: &[u8] = match verb.as_str() {
                        "EHLO" | "HELO" => b"250-sink\r\n250 OK\r\n",
                        "DATA" => {
                            let _ = write.write_all(b"354 go\r\n").await;
                            let mut data = Vec::new();
                            loop {
                                line.clear();
                                if read.read_line(&mut line).await.unwrap_or(0) == 0
                                    || line.trim_end() == "."
                                {
                                    break;
                                }
                                data.extend_from_slice(line.as_bytes());
                            }
                            let _ = captured.send(data);
                            b"250 OK\r\n"
                        }
                        "QUIT" => {
                            let _ = write.write_all(b"221 bye\r\n").await;
                            break;
                        }
                        _ => b"250 OK\r\n",
                    };
                    let _ = write.write_all(reply).await;
                }
            });
        }
    });
    addr
}

#[tokio::test]
async fn spam_released_from_a_digest_link_is_delivered_and_audited() {
    let dir = tempfile::tempdir().unwrap();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let mx = sink(tx).await;
    let mut cfg = Config::default();
    cfg.spool.dir = dir.path().join("spool");
    // The quarantine comes from policy; scanning is not under test here.
    cfg.scanner.enabled = false;
    cfg.scanner.clamd.address.clear();
    cfg.scanner.clamd.required = false;
    cfg.gateway.hostname = "mx.example.test".into();
    cfg.domains.accept = vec!["example.test".into()];
    cfg.domains.routes = vec![DomainRoute {
        domain: "example.test".into(),
        next_hop: mx.to_string(),
        platform: None,
    }];
    cfg.quarantine.link_base_url = "https://quarantine.example.test".into();
    // Stands in for the spam score the classifier will report.
    let mut policies = default_pack().clone();
    policies.policies.push(Policy {
        id: "spam-test".into(),
        tenant_id: None,
        scope: Scope::Global,
        priority: 10,
        enabled: true,
        dry_run: false,
        mandatory: false,
        override_floor: Vec::new(),
        conditions: vec![Condition::Recipient("user@example.test".into())],
        actions: vec![Action::Quarantine("spam".into())],
    });
    let spool = Arc::new(Spool::open(&cfg.spool.dir).await.unwrap());
    let env = Envelope {
        id: MessageId(ID.into()),
        tenant_id: None,
        authenticated_as: None,
        mail_from: "sender@outside.test".into(),
        rcpt_to: vec!["user@example.test".into()],
        received_at: OffsetDateTime::now_utc(),
        remote_ip: "203.0.113.8".parse().unwrap(),
        helo: "client.outside.test".into(),
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
    };
    spool.accept(env, Cursor::new(RAW.to_vec())).await.unwrap();
    let auth = AuthChecker::offline("currawong.example.test").unwrap();
    let cfg = Arc::new(cfg);
    let mut pipeline = Pipeline::new(Arc::clone(&cfg), auth).with_policies(policies);
    let quarantine = QuarantineStore::open(cfg.quarantine_dir())
        .unwrap()
        .with_config(&cfg.quarantine);

    classify_pending(&spool, &mut pipeline, &quarantine)
        .await
        .unwrap();
    assert_eq!(quarantine.reason(ID).unwrap(), "spam-test (queue spam)");
    assert_eq!(
        spool.load(&MessageId(ID.into())).await.unwrap().state,
        SpoolState::Done
    );

    // The digest goes through the spool like any other mail.
    let links = LinkSigner::new(vec![3; 32]).unwrap();
    let now = OffsetDateTime::now_utc();
    let settings = DigestSettings::from_config(&cfg);
    assert_eq!(
        send_digests(&quarantine, &spool, &links, &settings, now)
            .await
            .unwrap(),
        1
    );
    let digest = spool
        .list(SpoolState::Incoming)
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert!(ready_to_deliver(&digest));
    let body = spool.read_body(&digest.id).await.unwrap();
    let text = mail_parser::MessageParser::default()
        .parse(&body[..])
        .unwrap()
        .body_text(0)
        .unwrap()
        .into_owned();
    let url = text
        .lines()
        .find_map(|line| line.strip_prefix("Release: "))
        .unwrap()
        .trim();
    let path = url.strip_prefix("https://quarantine.example.test").unwrap();

    let app = router(HttpState {
        store: quarantine.clone(),
        spool: Arc::clone(&spool),
        links,
    });
    let response = app
        .oneshot(Request::post(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let page = to_bytes(response.into_body(), 1 << 20).await.unwrap();
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&page));

    // The release skips policy (which would quarantine it again) and is
    // queued for delivery.
    classify_pending(&spool, &mut pipeline, &quarantine)
        .await
        .unwrap();
    let released = spool
        .list(SpoolState::Incoming)
        .await
        .unwrap()
        .into_iter()
        .find(|env| env.id != digest.id)
        .unwrap();
    assert!(ready_to_deliver(&released), "{}", released.pipeline);
    assert_eq!(released.rcpt_to, ["user@example.test"]);

    let deliverer = Deliverer::new(
        Arc::clone(&spool),
        Arc::clone(&cfg),
        Arc::new(MapDns::new()),
    );
    let outcome = deliverer.deliver(&released.id).await.unwrap();
    assert!(matches!(outcome, DeliveryOutcome::Delivered), "{outcome:?}");
    let data = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .unwrap()
        .unwrap();
    let delivered = String::from_utf8_lossy(&data);
    assert!(delivered.contains("Subject: Cheap pills"), "{delivered}");
    assert!(delivered.contains("buy now"), "{delivered}");

    let events = quarantine.audit_table().events().unwrap();
    let actions: Vec<&str> = events.iter().map(|e| e.action.as_str()).collect();
    assert_eq!(actions, ["release_started", "release"], "{events:?}");
    assert_eq!(events[1].actor, "user@example.test");
    assert_eq!(events[1].detail.as_deref(), Some(released.id.as_str()));
}
