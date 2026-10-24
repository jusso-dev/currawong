mod support {
    pub mod http;
}
use currawong_core::{
    config::{Config, RspamdConfig, SandboxConfig},
    PartFlag, PartInfo, ResidencyGuard,
};
use currawong_scan::{
    combine,
    rspamd::{MessageMetadata, RspamdClient},
    sandbox::{cape::Cape, Sandbox, SandboxEngine, SandboxStatus},
    EngineOutput,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use support::http::{unavailable_url, Response, Server};

fn guard() -> Arc<ResidencyGuard> {
    Arc::new(ResidencyGuard::from_config(&Config::default().residency).unwrap())
}
fn metadata() -> MessageMetadata<'static> {
    MessageMetadata {
        ip: "192.0.2.1",
        helo: "client.test",
        hostname: "client.test",
        from: "a@test",
        recipients: &[],
        queue_id: "queue",
        user: None,
    }
}
fn scan_reply(action: &str) -> serde_json::Value {
    json!({"score": 9.0, "required_score": 6.0, "action":action, "symbols":{"TEST":{"score":1.0,"options":["option"]}},"messages":{"smtp_message":"test"}})
}
fn sandbox_config(url: &str) -> SandboxConfig {
    SandboxConfig {
        url: url.into(),
        poll_secs: 1,
        max_wait_secs: 10,
        cache_ttl_secs: 100,
        ..Default::default()
    }
}
fn part(dir: &tempfile::TempDir) -> PartInfo {
    let bytes = b"%PDF-1.4\nbenign synthetic sandbox fixture\n%%EOF";
    let path = dir.path().join("fixture.pdf");
    std::fs::write(&path, bytes).unwrap();
    PartInfo {
        is_attachment: true,
        content_type: "application/pdf".into(),
        filename: Some("fixture.pdf".into()),
        size: bytes.len() as u64,
        sha256: hex::encode(Sha256::digest(bytes)),
        flags: vec![],
        path: Some(path.to_str().unwrap().into()),
    }
}
async fn cape_server(done: Arc<AtomicBool>, score: f64) -> Server {
    Server::start(move |request| match request.path.as_str() {
        "/apiv2/tasks/create/file/" => Response::json(json!({"error":false,"data":{"task_ids":[7]}})),
        "/apiv2/tasks/status/7/" => Response::json(json!({"error":false,"data":if done.load(Ordering::SeqCst) {"reported"} else {"running"}})),
        "/apiv2/tasks/get/report/7/json/" => Response::json(json!({"malscore":score,"signatures":[{"name":"synthetic-test"}]})),
        _ => panic!("unexpected path {}",request.path),
    }).await
}

#[tokio::test]
async fn rspamd_protocol_actions_headers_and_learning() {
    for action in [
        "reject",
        "add header",
        "rewrite subject",
        "no action",
        "greylist",
        "soft reject",
    ] {
        let value = scan_reply(action);
        let server = Server::start(move |r| {
            if r.path == "/ping" {
                Response::bytes(b"pong\r\n".to_vec())
            } else if r.path == "/checkv2" {
                Response::json(value.clone())
            } else {
                Response::json(json!({"success":true}))
            }
        })
        .await;
        let dir = tempfile::tempdir().unwrap();
        let secret = dir.path().join("password");
        std::fs::write(&secret, "synthetic-test-secret\n").unwrap();
        let cfg = RspamdConfig {
            url: server.url.clone(),
            controller_url: server.url.clone(),
            password_file: Some(secret),
            ..Default::default()
        };
        let client = RspamdClient::new(&cfg, guard()).unwrap();
        let recipients = vec!["one@test".into(), "two@test".into()];
        let mut meta = metadata();
        meta.recipients = &recipients;
        meta.user = Some("test-user");
        let result = client.scan_message(b"benign mail", meta).await.unwrap();
        assert_eq!(result.action, action.replace(' ', "_"));
        assert_eq!(result.symbols[0].options, ["option"]);
        assert_eq!(result.messages["smtp_message"], "test");
        client.ping().await.unwrap();
        client.learn(b"ham", false).await.unwrap();
        client.learn(b"spam", true).await.unwrap();
        let requests = server.requests();
        let r = &requests[0];
        assert_eq!(r.path, "/checkv2");
        assert_eq!(r.body, b"benign mail");
        for (k, v) in [
            ("ip", "192.0.2.1"),
            ("helo", "client.test"),
            ("hostname", "client.test"),
            ("from", "a@test"),
            ("queue-id", "queue"),
            ("user", "test-user"),
            ("password", "synthetic-test-secret"),
            ("content-type", "message/rfc822"),
        ] {
            assert_eq!(r.header(k), Some(v));
        }
        assert_eq!(
            r.headers
                .iter()
                .filter(|(k, _)| k.eq_ignore_ascii_case("rcpt"))
                .count(),
            2
        );
        assert_eq!(requests[2].path, "/learnham");
        assert_eq!(requests[3].path, "/learnspam");
    }
}
#[tokio::test]
async fn rspamd_bad_json_size_limits_and_skipped() {
    for body in [b"invalid".to_vec(),serde_json::to_vec(&json!({"score":1,"required_score":1,"action":"no action","symbols":{},"is_skipped":true})).unwrap()] {
        let server=Server::start(move |_| Response::bytes(body.clone())).await;
        let cfg=RspamdConfig {url:server.url.clone(),..Default::default()};
        assert!(RspamdClient::new(&cfg,guard()).unwrap().scan_message(b"mail",metadata()).await.is_err());
    }
    let server = Server::start(|_| Response {
        status: 200,
        headers: vec![("Content-Length".into(), "1048577".into())],
        body: vec![],
    })
    .await;
    let mut cfg = RspamdConfig {
        url: server.url.clone(),
        ..Default::default()
    };
    let err = RspamdClient::new(&cfg, guard())
        .unwrap()
        .scan_message(b"mail", metadata())
        .await
        .unwrap_err();
    assert!(err.reason.contains("size limit"));
    assert!(!err.unreachable);
    cfg.max_size = 1;
    assert!(RspamdClient::new(&cfg, guard())
        .unwrap()
        .scan_message(b"mail", metadata())
        .await
        .unwrap_err()
        .reason
        .contains("max_size"));
    assert_eq!(server.requests().len(), 1);
}
#[tokio::test]
async fn rspamd_unreachable_required_and_optional() {
    let cfg = RspamdConfig {
        url: unavailable_url().await,
        ..Default::default()
    };
    let result = RspamdClient::new(&cfg, guard())
        .unwrap()
        .scan_message(b"mail", metadata())
        .await
        .unwrap_err();
    for required in [false, true] {
        let combined = combine(
            &[EngineOutput {
                name: "rspamd".into(),
                result: result.engine_result(),
                required,
            }],
            false,
        );
        assert_eq!(combined.defer, required);
        assert!(!combined.fail_closed);
        assert!(!combined.notes.is_empty());
    }
}
#[tokio::test]
async fn rspamd_redirects_and_foreign_endpoints_never_receive_content() {
    let sink = Server::start(|_| panic!("redirect followed")).await;
    for destination in [sink.url.clone(), "https://foreign.example/steal".into()] {
        let server = Server::start(move |_| Response {
            status: 307,
            headers: vec![("Location".into(), destination.clone())],
            body: vec![],
        })
        .await;
        let cfg = RspamdConfig {
            url: server.url.clone(),
            ..Default::default()
        };
        assert!(RspamdClient::new(&cfg, guard())
            .unwrap()
            .scan_message(b"mail", metadata())
            .await
            .unwrap_err()
            .reason
            .contains("redirect"));
        assert_eq!(server.requests().len(), 1);
    }
    assert!(sink.requests().is_empty());
    let cfg = RspamdConfig {
        url: "https://foreign.example".into(),
        ..Default::default()
    };
    assert!(RspamdClient::new(&cfg, guard()).is_err());
}
#[tokio::test]
async fn rspamd_learning_disabled_and_bad_credentials() {
    let server = Server::start(|_| panic!("learning disabled")).await;
    let mut cfg = RspamdConfig {
        url: server.url.clone(),
        ..Default::default()
    };
    RspamdClient::new(&cfg, guard())
        .unwrap()
        .learn(b"mail", false)
        .await
        .unwrap();
    assert!(server.requests().is_empty());
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("credential");
    std::fs::write(&path, "test\r\ninjected-header").unwrap();
    cfg.password_file = Some(path);
    let err = RspamdClient::new(&cfg, guard()).err().unwrap();
    assert!(!err.contains("injected-header"));
}
#[tokio::test]
async fn sandbox_submit_poll_done_and_cache_survives_restart() {
    for score in [0.0, 8.0] {
        let dir = tempfile::tempdir().unwrap();
        let part = part(&dir);
        let done = Arc::new(AtomicBool::new(false));
        let server = cape_server(done.clone(), score).await;
        let cfg = sandbox_config(&server.url);
        let db = dir.path().join("sandbox.db");
        let engine = SandboxEngine::new(&cfg, guard(), &db).unwrap();
        assert!(
            engine
                .assess_at(&[part.clone(), part.clone()], 100)
                .await
                .pending
        );
        assert!(
            engine
                .assess_at(std::slice::from_ref(&part), 100)
                .await
                .pending
        );
        assert_eq!(server.requests().len(), 1);
        assert!(
            engine
                .assess_at(std::slice::from_ref(&part), 101)
                .await
                .pending
        );
        done.store(true, Ordering::SeqCst);
        drop(engine);
        let engine = SandboxEngine::new(&cfg, guard(), &db).unwrap();
        let assessment = engine.assess_at(std::slice::from_ref(&part), 102).await;
        assert!(!assessment.pending);
        assert_eq!(assessment.results[0].malicious, score >= 5.0);
        assert_eq!(assessment.results[0].score, score / 10.0);
        assert_eq!(assessment.results[0].signatures, ["synthetic-test"]);
        assert_eq!(combine(&assessment.outputs, false).malware, score >= 5.0);
        assert_eq!(server.requests().len(), 4);
        engine.assess_at(std::slice::from_ref(&part), 103).await;
        assert_eq!(server.requests().len(), 4);
        assert!(engine.assess_at(&[part], 203).await.pending);
        assert_eq!(server.requests().len(), 5);
    }
}
#[tokio::test]
async fn cape_token_and_multipart_follow_v2_protocol() {
    let server = cape_server(Arc::new(AtomicBool::new(true)), 8.0).await;
    let dir = tempfile::tempdir().unwrap();
    let token = dir.path().join("token");
    std::fs::write(&token, "synthetic-cape-token").unwrap();
    let mut cfg = sandbox_config(&server.url);
    cfg.token_file = Some(token);
    let cape = Cape::new(&cfg, guard()).unwrap();
    let task = cape
        .submit(b"benign fixture", "note\"\r\n.txt", "text/plain")
        .await
        .unwrap();
    assert_eq!(task.0, "7");
    assert!(matches!(
        cape.status(&task).await.unwrap(),
        SandboxStatus::Done(_)
    ));
    let requests = server.requests();
    let request = &requests[0];
    assert_eq!(
        request.header("authorization"),
        Some("Token synthetic-cape-token")
    );
    let body = String::from_utf8(request.body.clone()).unwrap();
    assert!(body.contains("name=\"file\""));
    assert!(body.contains("benign fixture"));
    assert!(!body.contains("note\"\r\n"));
}
#[tokio::test]
async fn sandbox_timeout_both_modes_and_required_optional_unreachable() {
    let server = cape_server(Arc::new(AtomicBool::new(false)), 0.0).await;
    for mode in ["quarantine", "deliver"] {
        let dir = tempfile::tempdir().unwrap();
        let p = part(&dir);
        let mut cfg = sandbox_config(&server.url);
        cfg.on_timeout = mode.into();
        let engine = SandboxEngine::new(&cfg, guard(), &dir.path().join("db")).unwrap();
        assert!(
            engine
                .assess_at(std::slice::from_ref(&p), 100)
                .await
                .pending
        );
        let assessment = engine.assess_at(&[p], 110).await;
        assert!(assessment.timeout);
        assert!(!assessment.pending);
        assert_eq!(
            combine(&assessment.outputs, false).fail_closed,
            mode == "quarantine"
        );
    }
    for required in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = sandbox_config(&unavailable_url().await);
        cfg.required = required;
        let engine = SandboxEngine::new(&cfg, guard(), &dir.path().join("db")).unwrap();
        let assessment = engine.assess_at(&[part(&dir)], 100).await;
        assert_eq!(combine(&assessment.outputs, false).defer, required);
        assert!(!assessment.notes.is_empty());
    }
}
#[tokio::test]
async fn cape_errors_and_missing_scores_never_become_clean() {
    for value in [
        json!({"malscore":11,"signatures":[]}),
        json!({"signatures":[]}),
        json!({"malscore":0}),
        json!({"error":true}),
    ] {
        let server = Server::start(move |r| {
            if r.path.contains("status") {
                Response::json(json!({"error":false,"data":"reported"}))
            } else {
                Response::json(value.clone())
            }
        })
        .await;
        let cape = Cape::new(&sandbox_config(&server.url), guard()).unwrap();
        assert!(cape
            .status(&currawong_scan::sandbox::TaskId("1".into()))
            .await
            .is_err());
    }
    let server =
        Server::start(|_| Response::json(json!({"error":false,"data":"failed_analysis"}))).await;
    assert!(matches!(
        Cape::new(&sandbox_config(&server.url), guard())
            .unwrap()
            .status(&currawong_scan::sandbox::TaskId("1".into()))
            .await
            .unwrap(),
        SandboxStatus::Failed(_)
    ));
}
#[tokio::test]
async fn sandbox_selection_size_and_digest_bounds() {
    let server = Server::start(|_| panic!("no uploads expected")).await;
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = sandbox_config(&server.url);
    cfg.max_file_size = 1;
    let engine = SandboxEngine::new(&cfg, guard(), &dir.path().join("db")).unwrap();
    let mut p = part(&dir);
    assert!(combine(&engine.assess_at(&[p.clone()], 100).await.outputs, false).fail_closed);
    p.content_type = "text/plain".into();
    p.filename = Some("note.txt".into());
    assert!(engine.assess_at(&[p.clone()], 100).await.results.is_empty());
    for name in ["exe", "js", "docm", "iso", "html", "zip"] {
        p.filename = Some(format!("fixture.{name}"));
        p.flags = if name == "exe" {
            vec![PartFlag::Executable]
        } else if name == "docm" {
            vec![PartFlag::HasMacro]
        } else {
            vec![]
        };
        assert!(engine.selected(&p), "{name}");
    }
    cfg.max_file_size = 10000;
    let engine = SandboxEngine::new(&cfg, guard(), &dir.path().join("db2")).unwrap();
    p.sha256 = "wrong".into();
    assert!(combine(&engine.assess_at(&[p], 100).await.outputs, false).fail_closed);
    assert!(server.requests().is_empty());
}

#[tokio::test]
async fn sandbox_refuses_public_peer_even_with_residency_permission() {
    let mut config = Config::default();
    config.residency.allowed_cidrs.push("203.0.113.0/24".into());
    let guard = Arc::new(ResidencyGuard::from_config(&config.residency).unwrap());
    let cape = Cape::new(&sandbox_config("http://203.0.113.1:8000"), guard).unwrap();
    let error = cape
        .submit(b"benign", "fixture.txt", "text/plain")
        .await
        .unwrap_err();
    assert!(!error.unreachable);
    assert!(error.reason.contains("on-premises"));
}

#[tokio::test]
async fn sandbox_concurrent_attempts_and_failed_analysis_remain_fail_closed() {
    let server = Server::start(|request| {
        if request.path.contains("create") {
            Response::json(json!({"error":false,"data":{"task_ids":[7]}}))
        } else {
            Response::json(json!({"error":false,"data":"failed_analysis"}))
        }
    })
    .await;
    let dir = tempfile::tempdir().unwrap();
    let part = part(&dir);
    let mut cfg = sandbox_config(&server.url);
    cfg.required = true;
    cfg.on_timeout = "deliver".into();
    let db = dir.path().join("db");
    let first = SandboxEngine::new(&cfg, guard(), &db).unwrap();
    let second = SandboxEngine::new(&cfg, guard(), &db).unwrap();
    let parts = [part];
    let (a, b) = tokio::join!(first.assess_at(&parts, 100), second.assess_at(&parts, 100));
    assert!(a.pending && b.pending);
    assert_eq!(server.requests().len(), 1);
    let failure = first.assess_at(&parts, 101).await;
    assert!(combine(&failure.outputs, false).fail_closed);
    let retry = second.assess_at(&parts, 102).await;
    assert!(combine(&retry.outputs, false).fail_closed);
    let late = second.assess_at(&parts, 111).await;
    assert!(!late.timeout);
    assert!(combine(&late.outputs, false).fail_closed);
    assert_eq!(server.requests().len(), 2);
}

#[tokio::test]
async fn sandbox_ambiguous_upload_is_not_resubmitted_when_verdict_ttl_expires() {
    let server = Server::start(|_| Response {
        status: 503,
        headers: vec![],
        body: vec![],
    })
    .await;
    let dir = tempfile::tempdir().unwrap();
    let parts = [part(&dir)];
    let mut cfg = sandbox_config(&server.url);
    cfg.cache_ttl_secs = 1;
    let engine = SandboxEngine::new(&cfg, guard(), &dir.path().join("db")).unwrap();
    assert!(!engine.assess_at(&parts, 100).await.outputs.is_empty());
    let retry = engine.assess_at(&parts, 102).await;
    assert!(!retry.outputs.is_empty());
    assert_eq!(server.requests().len(), 1);
    assert!(engine.assess_at(&parts, 110).await.timeout);
    assert_eq!(server.requests().len(), 1);
}

#[tokio::test]
async fn sandbox_html_body_is_skipped_but_named_html_and_executable_are_selected() {
    let server = cape_server(Arc::new(AtomicBool::new(false)), 0.0).await;
    let dir = tempfile::tempdir().unwrap();
    let engine = SandboxEngine::new(
        &sandbox_config(&server.url),
        guard(),
        &dir.path().join("db"),
    )
    .unwrap();
    let mut part = part(&dir);
    let bytes = b"<html><p>Harmless newsletter</p></html>";
    std::fs::write(part.path.as_ref().unwrap(), bytes).unwrap();
    part.sha256 = hex::encode(Sha256::digest(bytes));
    part.size = bytes.len() as u64;
    part.content_type = "text/html".into();
    part.filename = None;
    part.is_attachment = false;
    assert!(engine
        .assess_at(std::slice::from_ref(&part), 100)
        .await
        .results
        .is_empty());
    assert!(server.requests().is_empty());
    part.filename = Some("newsletter.html".into());
    assert!(
        engine
            .assess_at(std::slice::from_ref(&part), 100)
            .await
            .pending
    );
    assert_eq!(server.requests().len(), 1);
    part.content_type = "application/octet-stream".into();
    part.filename = Some("program.com".into());
    part.flags.clear();
    assert!(engine.selected(&part));
}

#[tokio::test]
async fn sandbox_connect_failure_retries_after_recovery() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let dir = tempfile::tempdir().unwrap();
    let parts = [part(&dir)];
    let mut cfg = sandbox_config(&format!("http://{address}"));
    cfg.required = true;
    let db = dir.path().join("sandbox.db");
    let engine = SandboxEngine::new(&cfg, guard(), &db).unwrap();
    let failed = engine.assess_at(&parts, 100).await;
    assert!(combine(&failed.outputs, false).defer);
    drop(engine);
    let listener = tokio::net::TcpListener::bind(address).await.unwrap();
    let server = Server::with_listener(listener, |_| {
        Response::json(json!({"error":false,"data":{"task_ids":[7]}}))
    })
    .await;
    let engine = SandboxEngine::new(&cfg, guard(), &db).unwrap();
    assert!(engine.assess_at(&parts, 101).await.pending);
    assert_eq!(server.requests().len(), 1);
}
