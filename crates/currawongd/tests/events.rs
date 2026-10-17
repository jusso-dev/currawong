//! Verdict events leave the daemon through the configured `[events]` sinks.
use currawong_auth::{seed_txt, AuthChecker};
use currawong_core::{
    config::{Config, EventPayload, SyslogSinkConfig},
    residency::ResidencyGuard,
    Direction, MessageId,
};
use currawong_quarantine::QuarantineStore;
use currawong_spool::{Envelope, Spool, SpoolState};
use currawongd::{check_config, classify_pending, start_events, Pipeline};
use std::{io::Cursor, sync::Arc, time::Duration};
use time::OffsetDateTime;
use tokio::{io::AsyncReadExt, net::TcpListener};

const ID: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";

fn envelope() -> Envelope {
    Envelope {
        id: MessageId(ID.into()),
        tenant_id: None,
        authenticated_as: None,
        mail_from: "spoof@attacker.test".into(),
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

/// Reads octet-counted syslog frames until one carries a JSON event for `ID`.
async fn next_verdict(listener: TcpListener) -> serde_json::Value {
    let (mut tcp, _) = listener.accept().await.unwrap();
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = tcp.read(&mut chunk).await.unwrap();
        assert!(n > 0, "syslog connection closed without the verdict event");
        buf.extend_from_slice(&chunk[..n]);
        let mut rest = &buf[..];
        while let Some(space) = rest.iter().position(|b| *b == b' ') {
            let len: usize = std::str::from_utf8(&rest[..space])
                .unwrap()
                .parse()
                .unwrap();
            if rest.len() < space + 1 + len {
                break;
            }
            let line = std::str::from_utf8(&rest[space + 1..space + 1 + len]).unwrap();
            assert!(line.starts_with('<') && line.contains(">1 "), "{line}");
            let msg = line.splitn(8, ' ').nth(7).unwrap();
            let event: serde_json::Value = serde_json::from_str(msg).unwrap();
            if event["type"] == "message_verdict" && event["message_id"] == ID {
                return event;
            }
            rest = &rest[space + 1 + len..];
        }
    }
}

#[tokio::test]
async fn a_pipeline_verdict_reaches_the_syslog_sink() {
    let dir = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let receiver = tokio::spawn(next_verdict(listener));

    let mut cfg = Config::default();
    cfg.spool.dir = dir.path().join("spool");
    cfg.scanner.clamd.address.clear();
    cfg.scanner.worker_binary = None;
    cfg.events.syslog = Some(SyslogSinkConfig {
        address,
        tls: false,
        ca_file: None,
        payload: EventPayload::Json,
    });
    let guard = Arc::new(ResidencyGuard::from_config(&cfg.residency).unwrap());
    start_events(&cfg, guard).unwrap();

    let spool = Spool::open(&cfg.spool.dir).await.unwrap();
    spool
        .accept(
            envelope(),
            Cursor::new(
                b"From: user@example.test\r\nTo: dest@example.test\r\nSubject: hi\r\n\r\nhello\r\n"
                    .to_vec(),
            ),
        )
        .await
        .unwrap();
    let auth = AuthChecker::offline("currawong.example.test").unwrap();
    seed_txt(auth.cache(), "attacker.test", "v=spf1 -all").unwrap();
    seed_txt(auth.cache(), "_dmarc.example.test", "v=DMARC1; p=reject").unwrap();
    let mut pipeline = Pipeline::new(Arc::new(cfg), auth);
    let quarantine = QuarantineStore::open(dir.path().join("held")).unwrap();
    classify_pending(&spool, &mut pipeline, &quarantine)
        .await
        .unwrap();

    let event = tokio::time::timeout(Duration::from_secs(10), receiver)
        .await
        .expect("verdict event within 10 seconds")
        .unwrap();
    assert_eq!(event["schema"], "currawong.event.v1");
    assert_eq!(event["verdict"], "quarantine");
    assert_eq!(event["mail_from"], "spoof@attacker.test");
    assert_eq!(event["rcpt_to"][0], "dest@example.test");
    assert!(currawong_integrations::export::flush(Duration::from_secs(5)).await);
}

#[test]
fn check_config_refuses_a_foreign_event_sink() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("events.toml");
    let base = r#"
[spool]
dir = "/var/spool/currawong"
[[listeners]]
name = "in"
bind = "127.0.0.1:2525"
mode = "plain"
role = "inbound"
"#;
    std::fs::write(
        &path,
        format!("{base}[events.webhook]\nurl = \"https://siem.example.com/hook\"\nsecret_file = \"/etc/currawong/hook.key\"\n"),
    )
    .unwrap();
    let err = check_config(&path).unwrap_err();
    assert!(err.contains("events") && err.contains("Australia"), "{err}");

    std::fs::write(
        &path,
        format!("{base}[events.syslog]\naddress = \"siem.example.com:6514\"\n"),
    )
    .unwrap();
    assert!(check_config(&path).unwrap_err().contains("Australia"));

    std::fs::write(
        &path,
        format!("{base}[events.webhook]\nurl = \"http://10.0.0.5/hook\"\nsecret_file = \"/k\"\n"),
    )
    .unwrap();
    assert!(check_config(&path).unwrap_err().contains("https"));

    std::fs::write(
        &path,
        format!("{base}[events.syslog]\naddress = \"10.0.0.5:6514\"\n[events.webhook]\nurl = \"https://10.0.0.6/hook\"\nsecret_file = \"/k\"\n"),
    )
    .unwrap();
    check_config(&path).unwrap();
}
