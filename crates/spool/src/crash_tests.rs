//! Crash injection: stop `accept`, `transition` and `recover` dead after every
//! durable step, then check `recover` leaves each accepted message exactly once,
//! with its envelope, somewhere the daemon picks it up.
use super::*;
use std::future::Future;
use std::sync::{atomic::AtomicUsize, Arc};

const ID: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
const BODY: &[u8] = b"Subject: crash\r\n\r\nbody\r\n";

fn envelope() -> Envelope {
    Envelope {
        id: MessageId(ID.into()),
        tenant_id: Some("tenant-a".into()),
        mail_from: "sender@example.test".into(),
        rcpt_to: vec!["rcpt@example.test".into()],
        received_at: OffsetDateTime::UNIX_EPOCH,
        remote_ip: "203.0.113.5".parse().unwrap(),
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

async fn spool_crashing_after(root: &Path, steps: usize) -> Spool {
    let mut spool = Spool::open(root).await.unwrap();
    spool.crash_after = Some(Arc::new(AtomicUsize::new(steps)));
    spool
}

/// Run `op` on its own task. Returns true if it hit the injected crash.
async fn crashed<F, Fut>(spool: Spool, op: F) -> bool
where
    F: FnOnce(Spool) -> Fut,
    Fut: Future<Output = Result<()>> + Send + 'static,
{
    match tokio::spawn(op(spool)).await {
        Ok(result) => {
            result.unwrap();
            false
        }
        Err(err) => {
            assert!(err.is_panic(), "task failed without the injected crash");
            true
        }
    }
}

/// Names of every file under `dir`.
fn files(dir: &Path) -> Vec<String> {
    std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect()
}

/// Active is not processed by the daemon; recovery hands it back to incoming.
fn after_recovery(state: SpoolState) -> SpoolState {
    match state {
        SpoolState::Active => SpoolState::Incoming,
        other => other,
    }
}

fn assert_clean(root: &Path) {
    for state in STATES {
        let names = files(&root.join(state.dir_name()));
        assert!(
            names.iter().all(|name| !name.ends_with(".tmp")),
            "tmp left in {}: {names:?}",
            state.dir_name()
        );
    }
    assert!(
        files(&root.join(BAD_DIR)).is_empty(),
        "nothing should be quarantined"
    );
}

/// The message is one eml and JSON pair in one allowed state, with the
/// expected envelope and body, and is handed back for processing unless done.
async fn assert_whole(
    spool: &Spool,
    recovered: &[Envelope],
    expected: &Envelope,
    allowed: &[SpoolState],
) {
    let root = spool.root();
    assert_clean(root);
    let holding = |suffix: &str| -> Vec<SpoolState> {
        STATES
            .into_iter()
            .filter(|state| files(&root.join(state.dir_name())).contains(&format!("{ID}{suffix}")))
            .collect()
    };
    let emls = holding(".eml");
    let jsons = holding(".json");
    assert_eq!(emls.len(), 1, "eml in {emls:?}");
    assert_eq!(jsons, emls, "JSON must sit beside the eml");
    let state = emls[0];
    assert!(
        allowed.contains(&state),
        "message in {state:?}, allowed {allowed:?}"
    );

    let env = spool.load(&expected.id).await.unwrap();
    let mut want = expected.clone();
    want.state = state;
    assert_eq!(env, want);
    assert_eq!(spool.read_body(&expected.id).await.unwrap(), BODY);

    let listed = recovered.iter().filter(|env| env.id == expected.id).count();
    let processed = matches!(state, SpoolState::Incoming | SpoolState::Deferred);
    assert_eq!(
        listed,
        usize::from(processed),
        "recover must return it once when not done"
    );
}

#[tokio::test]
async fn crash_at_every_step_of_accept() {
    let mut crash_points = 0;
    let mut kept = 0;
    for steps in 0.. {
        let dir = tempfile::tempdir().unwrap();
        let spool = spool_crashing_after(dir.path(), steps).await;
        let hit = crashed(spool, |spool| async move {
            spool
                .accept(envelope(), std::io::Cursor::new(BODY))
                .await
                .map(|_| ())
        })
        .await;
        if !hit {
            break;
        }
        crash_points += 1;

        let spool = Spool::open(dir.path()).await.unwrap();
        let recovered = spool.recover().await.unwrap();
        // No 250 was sent, so the message may be gone, but never half there.
        let present = STATES.into_iter().any(|state| {
            files(&dir.path().join(state.dir_name()))
                .iter()
                .any(|n| n.starts_with(ID))
        });
        if present {
            kept += 1;
            assert_whole(&spool, &recovered, &envelope(), &[SpoolState::Incoming]).await;
        } else {
            assert_clean(dir.path());
            assert!(recovered.is_empty());
        }
    }
    assert!(
        crash_points >= 7,
        "only {crash_points} crash points in accept"
    );
    assert!(
        kept >= 1,
        "a crash after the final rename must keep the message"
    );
}

async fn crash_transition(from: SpoolState, to: SpoolState) -> usize {
    let mut expected = envelope();
    expected.attempts = 2;
    expected.pipeline = "scan_defer".into();
    expected.prepend_headers = vec!["X-Test: kept".into()];
    for steps in 0.. {
        let dir = tempfile::tempdir().unwrap();
        let spool = Spool::open(dir.path()).await.unwrap();
        spool
            .accept(envelope(), std::io::Cursor::new(BODY))
            .await
            .unwrap();
        spool.transition(&expected.id, from).await.unwrap();
        let mut env = expected.clone();
        env.state = from;
        spool.update(&env).await.unwrap();

        let spool = spool_crashing_after(dir.path(), steps).await;
        let hit = crashed(spool, move |spool| async move {
            spool.transition(&MessageId(ID.into()), to).await
        })
        .await;
        if !hit {
            return steps;
        }
        let spool = Spool::open(dir.path()).await.unwrap();
        let recovered = spool.recover().await.unwrap();
        let allowed = [after_recovery(from), after_recovery(to)];
        assert_whole(&spool, &recovered, &expected, &allowed).await;
    }
    unreachable!()
}

#[tokio::test]
async fn crash_at_every_step_of_every_transition() {
    for from in STATES {
        for to in STATES {
            if from == to {
                continue;
            }
            let steps = crash_transition(from, to).await;
            assert!(
                steps >= 8,
                "{from:?} -> {to:?} only had {steps} crash points"
            );
        }
    }
}

/// Recovery itself can be interrupted: crash mid-transition, crash again at
/// every step of the first recovery, then recover once more.
#[tokio::test]
async fn crash_during_recovery_after_a_crashed_transition() {
    for (from, to) in [
        (SpoolState::Incoming, SpoolState::Deferred),
        (SpoolState::Active, SpoolState::Done),
    ] {
        for transition_steps in 0..8 {
            for recover_steps in 0.. {
                let dir = tempfile::tempdir().unwrap();
                let spool = Spool::open(dir.path()).await.unwrap();
                spool
                    .accept(envelope(), std::io::Cursor::new(BODY))
                    .await
                    .unwrap();
                spool.transition(&MessageId(ID.into()), from).await.unwrap();
                let spool = spool_crashing_after(dir.path(), transition_steps).await;
                assert!(
                    crashed(spool, move |spool| async move {
                        spool.transition(&MessageId(ID.into()), to).await
                    })
                    .await
                );
                let spool = spool_crashing_after(dir.path(), recover_steps).await;
                let hit = crashed(
                    spool,
                    |spool| async move { spool.recover().await.map(|_| ()) },
                )
                .await;

                let spool = Spool::open(dir.path()).await.unwrap();
                let recovered = spool.recover().await.unwrap();
                let allowed = [after_recovery(from), after_recovery(to)];
                assert_whole(&spool, &recovered, &envelope(), &allowed).await;
                if !hit {
                    break;
                }
            }
        }
    }
}
