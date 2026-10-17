use currawong_core::{Direction, MessageId};
use currawong_spool::{next_retry, Envelope, Spool, SpoolError, SpoolState};
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
        tls: Default::default(),
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

const ID: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
const BODY: &[u8] = b"Subject: hi\r\n\r\nbody";

fn names(dir: &std::path::Path) -> Vec<String> {
    let mut out: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    out.sort();
    out
}

fn write_json(path: std::path::PathBuf, env: &Envelope) {
    std::fs::write(path, serde_json::to_vec(env).unwrap()).unwrap();
}

/// An older spool moved the eml before the JSON, so a crash could leave the
/// eml in `active/` and its envelope in `incoming/`.
#[tokio::test]
async fn recover_rejoins_eml_with_envelope_left_in_another_directory() {
    let dir = tempfile::tempdir().unwrap();
    let spool = Spool::open(dir.path()).await.unwrap();
    let mut env = envelope(ID);
    env.attempts = 3;
    std::fs::write(dir.path().join(format!("active/{ID}.eml")), BODY).unwrap();
    write_json(dir.path().join(format!("incoming/{ID}.json")), &env);

    let recovered = spool.recover().await.unwrap();
    assert_eq!(recovered.len(), 1);
    assert_eq!(recovered[0], env);
    assert_eq!(
        names(&dir.path().join("incoming")),
        [format!("{ID}.eml"), format!("{ID}.json")]
    );
    assert!(names(&dir.path().join("active")).is_empty());
    assert_eq!(spool.read_body(&env.id).await.unwrap(), BODY);
}

/// A source JSON whose unlink was not made durable sits beside a newer pair.
#[tokio::test]
async fn stale_envelope_does_not_shadow_the_live_one() {
    let dir = tempfile::tempdir().unwrap();
    let spool = Spool::open(dir.path()).await.unwrap();
    let mut live = envelope(ID);
    live.state = SpoolState::Deferred;
    live.attempts = 4;
    std::fs::write(dir.path().join(format!("deferred/{ID}.eml")), BODY).unwrap();
    write_json(dir.path().join(format!("deferred/{ID}.json")), &live);
    write_json(
        dir.path().join(format!("incoming/{ID}.json")),
        &envelope(ID),
    );

    assert_eq!(spool.load(&live.id).await.unwrap(), live);
    assert!(spool.list(SpoolState::Incoming).await.unwrap().is_empty());
    let recovered = spool.recover().await.unwrap();
    assert_eq!(recovered, [live.clone()]);
    assert!(names(&dir.path().join("incoming")).is_empty());
    assert_eq!(spool.read_body(&live.id).await.unwrap(), BODY);
}

/// Bytes are never deleted: an eml with no envelope anywhere is set aside.
#[tokio::test]
async fn eml_without_any_envelope_is_quarantined_not_deleted() {
    let dir = tempfile::tempdir().unwrap();
    let spool = Spool::open(dir.path()).await.unwrap();
    std::fs::write(dir.path().join(format!("active/{ID}.eml")), BODY).unwrap();

    assert!(spool.recover().await.unwrap().is_empty());
    assert_eq!(names(&dir.path().join("bad")), [format!("{ID}.eml")]);
    assert!(names(&dir.path().join("active")).is_empty());
}

#[tokio::test]
async fn quarantine_never_overwrites_an_earlier_bad_file() {
    let dir = tempfile::tempdir().unwrap();
    let spool = Spool::open(dir.path()).await.unwrap();
    std::fs::write(dir.path().join(format!("bad/{ID}.eml")), b"earlier").unwrap();
    std::fs::write(dir.path().join(format!("active/{ID}.eml")), BODY).unwrap();

    spool.recover().await.unwrap();
    let bad = dir.path().join("bad");
    assert_eq!(names(&bad), [format!("{ID}.eml"), format!("{ID}.eml.1")]);
    assert_eq!(
        std::fs::read(bad.join(format!("{ID}.eml"))).unwrap(),
        b"earlier"
    );
    assert_eq!(
        std::fs::read(bad.join(format!("{ID}.eml.1"))).unwrap(),
        BODY
    );
}

#[tokio::test]
async fn envelope_naming_another_message_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let spool = Spool::open(dir.path()).await.unwrap();
    std::fs::write(dir.path().join(format!("incoming/{ID}.eml")), BODY).unwrap();
    write_json(
        dir.path().join(format!("incoming/{ID}.json")),
        &envelope("01ARZ3NDEKTSV4RRFFQ69G5FB9"),
    );

    assert!(matches!(
        spool.load(&MessageId(ID.into())).await,
        Err(SpoolError::IdMismatch { .. })
    ));
    assert!(spool.list(SpoolState::Incoming).await.unwrap().is_empty());
    assert!(spool.recover().await.unwrap().is_empty());
    assert_eq!(
        names(&dir.path().join("bad")),
        [format!("{ID}.eml"), format!("{ID}.json")]
    );
}

#[tokio::test]
async fn corrupt_envelope_does_not_block_startup_or_the_queue() {
    let dir = tempfile::tempdir().unwrap();
    let spool = Spool::open(dir.path()).await.unwrap();
    let good = envelope("01ARZ3NDEKTSV4RRFFQ69G5FB1");
    spool
        .accept(good.clone(), std::io::Cursor::new(BODY))
        .await
        .unwrap();
    std::fs::write(dir.path().join(format!("incoming/{ID}.eml")), BODY).unwrap();
    std::fs::write(dir.path().join(format!("incoming/{ID}.json")), b"{not json").unwrap();

    let listed = spool.list(SpoolState::Incoming).await.unwrap();
    assert_eq!(listed, std::slice::from_ref(&good));
    let recovered = spool.recover().await.unwrap();
    assert_eq!(recovered, [good]);
    assert_eq!(
        names(&dir.path().join("bad")),
        [format!("{ID}.eml"), format!("{ID}.json")]
    );
}

struct FailingBody;

impl tokio::io::AsyncRead for FailingBody {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        _buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Err(std::io::Error::other("client went away")))
    }
}

#[tokio::test]
async fn failed_accept_leaves_nothing_behind() {
    let dir = tempfile::tempdir().unwrap();
    let spool = Spool::open(dir.path()).await.unwrap();
    assert!(spool.accept(envelope(ID), FailingBody).await.is_err());
    assert!(names(&dir.path().join("incoming")).is_empty());
}

#[cfg(unix)]
#[tokio::test]
async fn spool_files_and_directories_are_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("spool");
    let spool = Spool::open(&root).await.unwrap();
    let env = envelope(ID);
    spool
        .accept(env.clone(), std::io::Cursor::new(BODY))
        .await
        .unwrap();
    spool
        .transition(&env.id, SpoolState::Deferred)
        .await
        .unwrap();
    let mode =
        |path: std::path::PathBuf| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(root.clone()), 0o700);
    for state in ["incoming", "active", "deferred", "done", "bad"] {
        assert_eq!(mode(root.join(state)), 0o700, "{state}");
    }
    assert_eq!(mode(root.join(format!("deferred/{ID}.eml"))), 0o600);
    assert_eq!(mode(root.join(format!("deferred/{ID}.json"))), 0o600);
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
