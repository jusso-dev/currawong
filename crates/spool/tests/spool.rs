use currawong_core::{Direction, MessageId};
use currawong_spool::{next_retry, Envelope, Spool, SpoolState};
use std::io::Write;
use std::{net::IpAddr, time::Duration};
use time::OffsetDateTime;

fn envelope(id: &str) -> Envelope {
    Envelope {
        id: MessageId(id.to_string()),
        tenant_id: None,
        authenticated_as: None,
        mail_from: "sender@example.test".into(),
        rcpt_to: vec!["rcpt@example.test".into()],
        received_at: OffsetDateTime::UNIX_EPOCH,
        remote_ip: "203.0.113.5".parse::<IpAddr>().unwrap(),
        helo: "mail.example.test".into(),
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
async fn recover_keeps_accepted_mail_and_drops_tmp() {
    let dir = tempfile::tempdir().unwrap();
    let spool = Spool::open(dir.path()).await.unwrap();
    let env = envelope("01ARZ3NDEKTSV4RRFFQ69G5FAV");
    spool
        .accept(
            env.clone(),
            std::io::Cursor::new(b"Subject: hi\r\n\r\nbody"),
        )
        .await
        .unwrap();
    let stray = dir.path().join("incoming/ORPHAN.eml.tmp");
    tokio::fs::write(&stray, b"partial").await.unwrap();
    spool.transition(&env.id, SpoolState::Active).await.unwrap();
    drop(spool);

    let spool = Spool::open(dir.path()).await.unwrap();
    let recovered = spool.recover().await.unwrap();
    assert!(
        recovered.iter().any(|item| item.id == env.id),
        "accepted message was lost"
    );
    assert!(recovered
        .iter()
        .filter(|item| item.id == env.id)
        .all(|item| item.state == SpoolState::Incoming));
    let body = spool.read_body(&env.id).await.unwrap();
    assert_eq!(body, b"Subject: hi\r\n\r\nbody");

    let mut rd = tokio::fs::read_dir(dir.path().join("incoming"))
        .await
        .unwrap();
    while let Some(entry) = rd.next_entry().await.unwrap() {
        let name = entry.file_name().to_string_lossy().to_string();
        assert!(!name.ends_with(".tmp"), "tmp file remained: {name}");
    }
    let active = spool.list(SpoolState::Active).await.unwrap();
    assert!(active.is_empty());
}

#[test]
fn retry_schedule_matches_adr_0001() {
    let cases = [
        (1, 5 * 60),
        (2, 15 * 60),
        (3, 30 * 60),
        (4, 60 * 60),
        (10, 60 * 60),
    ];
    for (attempts, secs) in cases {
        assert_eq!(
            next_retry(attempts),
            Duration::from_secs(secs),
            "attempts {attempts}"
        );
    }
}

#[tokio::test]
async fn directory_sync_does_not_error() {
    let dir = tempfile::tempdir().unwrap();
    let spool = Spool::open(dir.path()).await.unwrap();
    let mut body = Vec::new();
    body.write_all(b"hello").unwrap();
    let env = envelope("01ARZ3NDEKTSV4RRFFQ69G5FB0");
    spool.accept(env, std::io::Cursor::new(body)).await.unwrap();
}
