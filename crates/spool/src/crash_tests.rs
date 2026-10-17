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
        authenticated_as: None,
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

fn assert_tmp_free(root: &Path) {
    for state in STATES {
        let names = files(&root.join(state.dir_name()));
        assert!(
            names.iter().all(|name| !name.ends_with(".tmp")),
            "tmp left in {}: {names:?}",
            state.dir_name()
        );
    }
}

fn assert_clean(root: &Path) {
    assert_tmp_free(root);
    assert!(
        files(&root.join(BAD_DIR)).is_empty(),
        "nothing should be quarantined"
    );
}

/// The message is one eml and JSON pair in one allowed state, with the
/// expected envelope and body, and is handed back for processing unless done.
/// Quarantine is checked by the caller.
async fn assert_whole(
    spool: &Spool,
    recovered: &[Envelope],
    expected: &Envelope,
    allowed: &[SpoolState],
) {
    let root = spool.root();
    assert_tmp_free(root);
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
            assert!(recovered.is_empty());
        }
        assert_clean(dir.path());
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
        assert_clean(dir.path());
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
#[tokio::test(flavor = "multi_thread")]
async fn crash_during_recovery_after_every_crashed_transition() {
    let mut pairs = tokio::task::JoinSet::new();
    for from in STATES {
        for to in STATES {
            if from != to {
                pairs.spawn(crash_recovery_after_transition(from, to));
            }
        }
    }
    while let Some(done) = pairs.join_next().await {
        done.unwrap();
    }
}

async fn crash_recovery_after_transition(from: SpoolState, to: SpoolState) {
    for transition_steps in 0.. {
        for recover_steps in 0.. {
            let dir = tempfile::tempdir().unwrap();
            let spool = Spool::open(dir.path()).await.unwrap();
            spool
                .accept(envelope(), std::io::Cursor::new(BODY))
                .await
                .unwrap();
            spool.transition(&MessageId(ID.into()), from).await.unwrap();
            let spool = spool_crashing_after(dir.path(), transition_steps).await;
            let transition_hit = crashed(spool, move |spool| async move {
                spool.transition(&MessageId(ID.into()), to).await
            })
            .await;
            if !transition_hit {
                return;
            }
            let spool = spool_crashing_after(dir.path(), recover_steps).await;
            let recover_hit = crashed(
                spool,
                |spool| async move { spool.recover().await.map(|_| ()) },
            )
            .await;

            let spool = Spool::open(dir.path()).await.unwrap();
            let recovered = spool.recover().await.unwrap();
            let allowed = [after_recovery(from), after_recovery(to)];
            assert_whole(&spool, &recovered, &envelope(), &allowed).await;
            assert_clean(dir.path());
            if !recover_hit {
                break;
            }
        }
    }
}

/// On-disk states only an older spool, a duplicate copy or corruption can
/// produce. Recovery quarantines or adopts, and must survive a crash at each
/// of those steps too.
#[derive(Debug, Clone, Copy)]
enum Damage {
    /// eml in `active/`, its envelope left in `incoming/`.
    Split,
    /// Unreadable envelope beside the eml, a good one in another directory.
    UnreadableBesideEml,
    /// Two complete copies of the message.
    Duplicate,
    /// A copy with an unreadable envelope ahead of a complete copy.
    DuplicateUnreadableFirst,
    /// The envelope names a different message.
    WrongId,
    /// An eml with no envelope anywhere.
    NoEnvelope,
}

impl Damage {
    const ALL: [Damage; 6] = [
        Damage::Split,
        Damage::UnreadableBesideEml,
        Damage::Duplicate,
        Damage::DuplicateUnreadableFirst,
        Damage::WrongId,
        Damage::NoEnvelope,
    ];

    fn with_attempts(attempts: u32) -> Envelope {
        let mut env = envelope();
        env.attempts = attempts;
        env
    }

    fn write(root: &Path, state: SpoolState, suffix: &str, bytes: &[u8]) {
        std::fs::write(
            root.join(state.dir_name()).join(format!("{ID}{suffix}")),
            bytes,
        )
        .unwrap();
    }

    fn write_env(root: &Path, state: SpoolState, env: &Envelope) {
        Self::write(root, state, ".json", &serde_json::to_vec(env).unwrap());
    }

    fn apply(self, root: &Path) {
        use SpoolState::*;
        match self {
            Damage::Split => {
                Self::write(root, Active, ".eml", BODY);
                Self::write_env(root, Incoming, &Self::with_attempts(3));
            }
            Damage::UnreadableBesideEml => {
                Self::write(root, Deferred, ".eml", BODY);
                Self::write(root, Deferred, ".json", b"{not json");
                Self::write_env(root, Incoming, &Self::with_attempts(3));
            }
            Damage::Duplicate => {
                Self::write(root, Incoming, ".eml", BODY);
                Self::write_env(root, Incoming, &Self::with_attempts(1));
                Self::write(root, Deferred, ".eml", BODY);
                Self::write_env(root, Deferred, &Self::with_attempts(9));
            }
            Damage::DuplicateUnreadableFirst => {
                Self::write(root, Incoming, ".eml", BODY);
                Self::write(root, Incoming, ".json", b"{not json");
                Self::write(root, Deferred, ".eml", BODY);
                Self::write_env(root, Deferred, &Self::with_attempts(9));
            }
            Damage::WrongId => {
                let mut env = envelope();
                env.id = MessageId("01ARZ3NDEKTSV4RRFFQ69G5FB9".into());
                Self::write(root, Incoming, ".eml", BODY);
                Self::write_env(root, Incoming, &env);
            }
            Damage::NoEnvelope => Self::write(root, Active, ".eml", BODY),
        }
    }

    /// Where the message ends up, with which envelope, and how many files
    /// are set aside in `bad/`.
    fn outcome(self) -> (Option<(SpoolState, Envelope)>, usize) {
        use SpoolState::*;
        match self {
            Damage::Split => (Some((Incoming, Self::with_attempts(3))), 0),
            Damage::UnreadableBesideEml => (Some((Deferred, Self::with_attempts(3))), 1),
            Damage::Duplicate => (Some((Incoming, Self::with_attempts(1))), 2),
            Damage::DuplicateUnreadableFirst => (Some((Deferred, Self::with_attempts(9))), 2),
            Damage::WrongId => (None, 2),
            Damage::NoEnvelope => (None, 1),
        }
    }
}

#[tokio::test]
async fn crash_at_every_step_of_repair() {
    for damage in Damage::ALL {
        let (want, bad) = damage.outcome();
        let mut crash_points = 0;
        for steps in 0.. {
            let dir = tempfile::tempdir().unwrap();
            Spool::open(dir.path()).await.unwrap();
            damage.apply(dir.path());
            let spool = spool_crashing_after(dir.path(), steps).await;
            let hit = crashed(
                spool,
                |spool| async move { spool.recover().await.map(|_| ()) },
            )
            .await;

            let spool = Spool::open(dir.path()).await.unwrap();
            let recovered = spool.recover().await.unwrap();
            assert_tmp_free(dir.path());
            let quarantined = files(&dir.path().join(BAD_DIR));
            assert_eq!(
                quarantined.len(),
                bad,
                "{damage:?} after {steps} steps: {quarantined:?}"
            );
            match &want {
                Some((state, env)) => {
                    assert_whole(&spool, &recovered, env, &[*state]).await;
                }
                None => {
                    for state in STATES {
                        assert!(files(&dir.path().join(state.dir_name())).is_empty());
                    }
                    assert!(recovered.is_empty());
                }
            }
            if !hit {
                break;
            }
            crash_points += 1;
        }
        assert!(
            crash_points >= bad.max(1),
            "{damage:?} only had {crash_points} crash points"
        );
    }
}

/// Stream a body in two writes, then commit.
async fn streamed(spool: Spool) -> Result<()> {
    let mut pending = spool.begin(&MessageId(ID.into())).await?;
    let (head, tail) = BODY.split_at(7);
    pending.write(head).await?;
    pending.write(tail).await?;
    spool.commit(pending, envelope()).await.map(|_| ())
}

#[tokio::test]
async fn crash_at_every_step_of_begin_and_commit() {
    let mut crash_points = 0;
    let mut kept = 0;
    for steps in 0.. {
        let dir = tempfile::tempdir().unwrap();
        let spool = spool_crashing_after(dir.path(), steps).await;
        let hit = crashed(spool, streamed).await;
        if !hit {
            break;
        }
        crash_points += 1;
        let incoming = files(&dir.path().join("incoming"));
        let renamed = incoming.contains(&format!("{ID}.eml"));

        let spool = Spool::open(dir.path()).await.unwrap();
        let recovered = spool.recover().await.unwrap();
        let present = STATES.into_iter().any(|state| {
            files(&dir.path().join(state.dir_name()))
                .iter()
                .any(|n| n.starts_with(ID))
        });
        // A body still in `.eml.tmp` was never acknowledged and must vanish.
        assert_eq!(present, renamed, "crash at step {steps}: {incoming:?}");
        if present {
            kept += 1;
            assert_whole(&spool, &recovered, &envelope(), &[SpoolState::Incoming]).await;
        } else {
            assert!(recovered.is_empty());
        }
        assert_clean(dir.path());
    }
    assert!(crash_points >= 6, "only {crash_points} crash points");
    assert!(kept >= 1, "a crash after the final rename must keep the message");
}

#[tokio::test]
async fn dropped_or_failed_commit_leaves_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let spool = Spool::open(dir.path()).await.unwrap();
    let mut pending = spool.begin(&MessageId(ID.into())).await.unwrap();
    pending.write(BODY).await.unwrap();
    drop(pending);
    assert!(files(&dir.path().join("incoming")).is_empty());

    // The JSON cannot be written: commit fails after the body was synced.
    let blocker = dir.path().join("incoming").join(format!("{ID}.json.tmp"));
    std::fs::create_dir(&blocker).unwrap();
    let mut pending = spool.begin(&MessageId(ID.into())).await.unwrap();
    pending.write(BODY).await.unwrap();
    assert!(spool.commit(pending, envelope()).await.is_err());
    std::fs::remove_dir(&blocker).unwrap();
    assert!(
        files(&dir.path().join("incoming")).is_empty(),
        "{:?}",
        files(&dir.path().join("incoming"))
    );

    let before = spool.commit_syncs();
    streamed(spool.clone()).await.unwrap();
    assert!(spool.commit_syncs() >= before + 3, "body, JSON and directory are synced");
}
