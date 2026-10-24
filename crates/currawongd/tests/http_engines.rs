#[path = "../../scan/tests/support/http.rs"]
mod http;
use currawong_auth::AuthChecker;
use currawong_core::{config::Config, Direction, Verdict};
use currawong_policy::Signals;
use currawong_quarantine::QuarantineStore;
use currawong_spool::{Envelope, Spool, SpoolState};
use currawongd::{classify_pending, Pipeline};
use http::{unavailable_url, Response, Server};
use serde_json::json;
use std::{
    io::Cursor,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
use time::OffsetDateTime;
fn envelope() -> Envelope {
    Envelope {
        id: currawong_core::MessageId("01ARZ3NDEKTSV4RRFFQ69G5FAV".into()),
        tenant_id: None,
        authenticated_as: None,
        mail_from: "a@example.test".into(),
        rcpt_to: vec!["b@example.test".into()],
        received_at: OffsetDateTime::now_utc(),
        remote_ip: "192.0.2.1".parse().unwrap(),
        helo: "client.example.test".into(),
        attempts: 0,
        next_attempt_at: None,
        state: SpoolState::Incoming,
        direction: Direction::Inbound,
        tls_version: None,
        tls_cipher: None,
        rcpt_status: vec![],
        prepend_headers: vec![],
        dsn_sent: false,
        tls: Default::default(),
        pipeline: "pending".into(),
    }
}
fn config(dir: &tempfile::TempDir) -> Config {
    let mut cfg = Config::default();
    cfg.spool.dir = dir.path().join("spool");
    cfg.scanner.clamd.required = false;
    cfg.scanner.clamd.address.clear();
    cfg.scanner.worker_binary = Some(
        std::env::current_exe()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("currawong-parser-worker"),
    );
    cfg.classify.enabled = false;
    cfg
}
fn pipeline(cfg: Config) -> Pipeline {
    Pipeline::new(Arc::new(cfg), AuthChecker::offline("gateway.test").unwrap())
}
fn raw() -> Vec<u8> {
    b"From: a@example.test\r\nTo: b@example.test\r\nSubject: harmless test\r\n\r\nhello\r\n"
        .to_vec()
}
fn pdf() -> Vec<u8> {
    let data = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        b"%PDF-1.4\n% benign synthetic test\n%%EOF",
    );
    format!("From: a@example.test\r\nTo: b@example.test\r\nSubject: harmless attachment\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=x\r\n\r\n--x\r\nContent-Type: text/plain\r\n\r\nhello\r\n--x\r\nContent-Type: application/pdf; name=fixture.pdf\r\nContent-Disposition: attachment; filename=fixture.pdf\r\nContent-Transfer-Encoding: base64\r\n\r\n{data}\r\n--x--\r\n").into_bytes()
}
#[tokio::test]
async fn rspamd_actions_symbols_and_spam_path_feed_policy() {
    for (action, symbol, queue) in [
        ("reject", "TEST", Some("spam")),
        ("add header", "TEST", None),
        ("rewrite subject", "TEST", None),
        ("no action", "TEST", None),
        ("no action", "PHISHED_TEST", Some("phishing")),
    ] {
        let value = json!({"score":9,"required_score":6,"action":action,"symbols":{symbol:{"score":1,"options":[]}}});
        let server = Server::start(move |_| Response::json(value.clone())).await;
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = config(&dir);
        cfg.scanner.rspamd.url = server.url.clone();
        let pipeline = pipeline(cfg);
        let (report, decision) = pipeline.assess(&envelope(), &raw(), None).await;
        assert!(!report.fail_closed, "{:?}", report.notes);
        let signals = Signals::from_report(&report);
        assert_eq!(signals.scores["rspamd"], 9.0);
        assert_eq!(signals.scores["rspamd.ratio"], 1.5);
        assert!(report
            .engines
            .iter()
            .find(|e| e.engine == "rspamd")
            .unwrap()
            .detail
            .contains("score=9"));
        let decision = &decision.decisions[0];
        if let Some(queue) = queue {
            assert!(matches!(decision.verdict, Verdict::Quarantine { .. }));
            assert_eq!(decision.queue(), Some(queue));
        } else {
            assert_eq!(decision.verdict, Verdict::Deliver);
            if action != "no action" {
                assert!(!decision.actions.is_empty());
            }
        }
    }
}
#[tokio::test]
async fn rspamd_unreachable_and_bad_json_fail_safely() {
    for required in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = config(&dir);
        cfg.scanner.rspamd.url = unavailable_url().await;
        cfg.scanner.rspamd.required = required;
        let (report, verdict) = pipeline(cfg).evaluate(&envelope(), &raw(), None).await;
        assert_eq!(report.defer, required);
        assert!(!report.notes.is_empty());
        assert_eq!(matches!(verdict, Verdict::Defer { .. }), required);
    }
    let server = Server::start(|_| Response::bytes(b"bad JSON".to_vec())).await;
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = config(&dir);
    cfg.scanner.rspamd.url = server.url.clone();
    let (report, verdict) = pipeline(cfg).evaluate(&envelope(), &raw(), None).await;
    assert!(report.fail_closed);
    assert!(matches!(verdict, Verdict::Quarantine { .. }));
}
#[tokio::test]
async fn rspamd_release_learning_runs_without_bayes() {
    let server = Server::start(|_| Response::json(json!({"success":true}))).await;
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = config(&dir);
    cfg.scanner.rspamd.url = server.url.clone();
    cfg.scanner.rspamd.controller_url = server.url.clone();
    pipeline(cfg).learn_released(&envelope(), &raw()).await;
    assert_eq!(server.requests()[0].path, "/learnham");
}
#[tokio::test]
async fn sandbox_spool_defers_then_malware_or_clean_and_cache_hit() {
    for malicious in [false, true] {
        let done = Arc::new(AtomicBool::new(false));
        let state = done.clone();
        let server=Server::start(move |r|match r.path.as_str(){
            "/apiv2/tasks/create/file/"=>Response::json(json!({"error":false,"data":{"task_ids":[1]}})),
            "/apiv2/tasks/status/1/"=>Response::json(json!({"error":false,"data":if state.load(Ordering::SeqCst){"reported"}else{"running"}})),
            "/apiv2/tasks/get/report/1/json/"=>Response::json(json!({"malscore":if malicious{9}else{0},"signatures":[]})),
            _=>panic!("unexpected path")}).await;
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = config(&dir);
        cfg.scanner.sandbox.url = server.url.clone();
        cfg.scanner.sandbox.poll_secs = 1;
        let spool = Spool::open(&cfg.spool.dir).await.unwrap();
        spool.accept(envelope(), Cursor::new(pdf())).await.unwrap();
        let quarantine = QuarantineStore::open(dir.path().join("held")).unwrap();
        let mut pipeline = pipeline(cfg);
        let before = OffsetDateTime::now_utc();
        classify_pending(&spool, &mut pipeline, &quarantine)
            .await
            .unwrap();
        let mut saved = spool.load(&envelope().id).await.unwrap();
        assert_eq!(saved.state, SpoolState::Deferred);
        assert_eq!(saved.pipeline, "scan_defer");
        assert!(saved.next_attempt_at.unwrap() <= before + time::Duration::seconds(10));
        assert_eq!(server.requests().len(), 1);
        // Explicitly age the SQLite task to test the real scheduler retry
        // without sleeping or needing any external sandbox.
        let db =
            rusqlite::Connection::open(pipeline.cfg.spool.dir.join("sandbox.sqlite3")).unwrap();
        db.execute("UPDATE sandbox_tasks SET polled=polled-2", [])
            .unwrap();
        done.store(true, Ordering::SeqCst);
        saved.next_attempt_at = Some(OffsetDateTime::now_utc() - time::Duration::seconds(1));
        spool.update(&saved).await.unwrap();
        classify_pending(&spool, &mut pipeline, &quarantine)
            .await
            .unwrap();
        let saved = spool.load(&envelope().id).await.unwrap();
        assert_eq!(
            saved.pipeline,
            if malicious { "quarantine" } else { "deliver" }
        );
        let requests = server.requests().len();
        let (report, verdict) = pipeline.evaluate(&envelope(), &pdf(), None).await;
        assert_eq!(server.requests().len(), requests);
        assert_eq!(report.malware, malicious);
        assert_eq!(report.sandbox[0].status, "done");
        assert_eq!(matches!(verdict, Verdict::Quarantine { .. }), malicious);
        if malicious {
            assert!(Signals::from_report(&report)
                .flags
                .contains("sandbox.malicious"));
        }
    }
}
#[tokio::test]
async fn sandbox_timeout_and_unreachable_pipeline_modes() {
    let server =
        Server::start(|_| Response::json(json!({"error":false,"data":{"task_ids":[1]}}))).await;
    for mode in ["quarantine", "deliver"] {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = config(&dir);
        cfg.scanner.sandbox.url = server.url.clone();
        cfg.scanner.sandbox.on_timeout = mode.into();
        let mut pipeline = pipeline(cfg);
        let (report, verdict) = pipeline.evaluate(&envelope(), &pdf(), None).await;
        assert!(report.defer);
        assert!(matches!(verdict, Verdict::Defer { .. }));
        assert!(Signals::from_report(&report)
            .flags
            .contains("sandbox.pending"));
        let db =
            rusqlite::Connection::open(pipeline.cfg.spool.dir.join("sandbox.sqlite3")).unwrap();
        db.execute("UPDATE sandbox_tasks SET submitted=submitted-1000", [])
            .unwrap();
        let (report, verdict) = pipeline.evaluate(&envelope(), &pdf(), None).await;
        assert!(Signals::from_report(&report)
            .flags
            .contains("sandbox.timeout"));
        assert_eq!(
            matches!(verdict, Verdict::Quarantine { .. }),
            mode == "quarantine"
        );
        assert!(!report.defer);
    }
    for required in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = config(&dir);
        cfg.scanner.sandbox.url = unavailable_url().await;
        cfg.scanner.sandbox.required = required;
        let (report, verdict) = pipeline(cfg).evaluate(&envelope(), &pdf(), None).await;
        assert_eq!(report.defer, required);
        assert_eq!(matches!(verdict, Verdict::Defer { .. }), required);
        assert!(!report.notes.is_empty());
    }
}
#[tokio::test]
async fn rspamd_required_readiness_uses_ping() {
    let server = Server::start(|r| {
        assert_eq!(r.path, "/ping");
        Response::bytes(b"pong".to_vec())
    })
    .await;
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = config(&dir);
    cfg.scanner.rspamd.url = server.url.clone();
    cfg.scanner.rspamd.required = true;
    let check = currawongd::checks_for(&cfg)
        .into_iter()
        .find(|c| c.name() == "rspamd")
        .unwrap();
    check.check().await.unwrap();
    drop(server);
    assert!(check.check().await.is_err());
    cfg.scanner.rspamd.required = false;
    assert!(currawongd::checks_for(&cfg)
        .iter()
        .all(|c| c.name() != "rspamd"));
}

#[tokio::test]
async fn rspamd_and_builtin_spam_both_keep_reports() {
    let server = Server::start(|_| {
        Response::json(json!({"score":0,"required_score":6,"action":"no action","symbols":{}}))
    })
    .await;
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = config(&dir);
    cfg.classify.enabled = true;
    cfg.classify.bayes_database = dir.path().join("bayes.db");
    cfg.classify.history_database = dir.path().join("history.db");
    cfg.scanner.rspamd.url = server.url.clone();
    let (report, _) = pipeline(cfg).evaluate(&envelope(), &raw(), None).await;
    assert!(report.rspamd.is_some());
    assert!(report.spam.is_some(), "{:?}", report.notes);
}

#[tokio::test]
async fn sandbox_unnamed_html_attachment_is_submitted_but_html_body_is_not() {
    let server =
        Server::start(|_| Response::json(json!({"error":false,"data":{"task_ids":[1]}}))).await;
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = config(&dir);
    cfg.scanner.sandbox.url = server.url.clone();
    let mut pipeline = pipeline(cfg);
    for attachment in [false, true] {
        let disposition = if attachment {
            "Content-Disposition: attachment\r\n"
        } else {
            ""
        };
        let raw = format!("From: a@example.test\r\nTo: b@example.test\r\nSubject: harmless HTML\r\nMIME-Version: 1.0\r\nContent-Type: text/html\r\n{disposition}\r\n<html><p>Harmless newsletter</p></html>");
        let (report, verdict) = pipeline.evaluate(&envelope(), raw.as_bytes(), None).await;
        assert_eq!(report.parts[0].is_attachment, attachment);
        assert_eq!(report.defer, attachment);
        assert_eq!(matches!(verdict, Verdict::Defer { .. }), attachment);
    }
    assert_eq!(server.requests().len(), 1);
}
