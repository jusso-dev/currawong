use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    Router,
};
use currawong_core::{config::Config, Direction, MessageId};
use currawong_quarantine::{
    digest::{send_digests, DigestSettings},
    http::{router, HttpState},
    BlobStore, FsBlobStore, Hold, Link, LinkAction, LinkSigner, Principal, QuarantineStore, Role,
    RELEASE_PIPELINE,
};
use currawong_spool::{Spool, SpoolState};
use std::sync::Arc;
use time::{Duration, OffsetDateTime};
use tower::ServiceExt;

const SPAM_ID: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
const VIRUS_ID: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAW";
const RAW: &[u8] =
    b"From: sender@outside.test\r\nTo: user@example.test\r\nSubject: Cheap <b>pills</b>\r\n\r\nbuy now\r\n";

struct Setup {
    _dir: tempfile::TempDir,
    store: QuarantineStore,
    blobs: FsBlobStore,
    spool: Arc<Spool>,
    links: LinkSigner,
    app: Router,
}

async fn setup() -> Setup {
    let dir = tempfile::tempdir().unwrap();
    let blobs = FsBlobStore::open(dir.path().join("held/blobs")).unwrap();
    let store = QuarantineStore::open(dir.path().join("held"))
        .unwrap()
        .with_blobs(Arc::new(blobs.clone()));
    let spool = Arc::new(Spool::open(dir.path().join("spool")).await.unwrap());
    let links = LinkSigner::new(vec![9; 32]).unwrap();
    let app = router(HttpState {
        store: store.clone(),
        spool: Arc::clone(&spool),
        links: links.clone(),
    });
    Setup {
        _dir: dir,
        store,
        blobs,
        spool,
        links,
        app,
    }
}

fn hold(id: &str, queue: &str, tenant: Option<&str>) -> Hold {
    Hold {
        message_id: MessageId(id.into()),
        tenant_id: tenant.map(str::to_string),
        queue: queue.into(),
        reason: format!("{queue} (queue {queue})"),
        reasons: vec![format!("policy {queue} matched")],
        sender: "sender@outside.test".into(),
        recipients: vec!["user@example.test".into()],
        score: None,
        direction: Direction::Inbound,
        headers: vec!["Authentication-Results: currawong.example.test; spf=pass\r\n".into()],
    }
}

fn settings() -> DigestSettings {
    let mut cfg = Config::default();
    cfg.gateway.hostname = "mx.example.test".into();
    cfg.quarantine.link_base_url = "https://quarantine.example.test/".into();
    DigestSettings::from_config(&cfg)
}

async fn send(app: &Router, request: Request<Body>) -> (StatusCode, String) {
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), 1 << 20).await.unwrap();
    (status, String::from_utf8_lossy(&body).into_owned())
}

fn post(uri: &str, principal: Option<&Principal>, json: &str) -> Request<Body> {
    let mut request = Request::post(uri)
        .header("content-type", "application/json")
        .body(Body::from(json.to_string()))
        .unwrap();
    if let Some(principal) = principal {
        request.extensions_mut().insert(principal.clone());
    }
    request
}

/// Release link path from the digest's decoded text part.
fn release_path(digest: &[u8]) -> String {
    let message = mail_parser::MessageParser::default().parse(digest).unwrap();
    let text = message.body_text(0).unwrap().into_owned();
    let line = text
        .lines()
        .find(|line| line.starts_with("Release: "))
        .unwrap();
    let url = line.trim_start_matches("Release: ").trim();
    assert!(
        url.starts_with("https://quarantine.example.test/quarantine/link/"),
        "{url}"
    );
    url.trim_start_matches("https://quarantine.example.test")
        .to_string()
}

#[tokio::test]
async fn spam_released_from_a_digest_link_is_reinjected_and_audited() {
    let s = setup().await;
    let now = OffsetDateTime::now_utc();
    let ids = s
        .store
        .hold(&hold(SPAM_ID, "spam", Some("t1")), RAW, now)
        .await
        .unwrap();
    s.store
        .hold(&hold(VIRUS_ID, "malware", Some("t1")), RAW, now)
        .await
        .unwrap();

    assert_eq!(
        send_digests(&s.store, &s.spool, &s.links, &settings(), now)
            .await
            .unwrap(),
        1
    );
    // Not again within the interval.
    assert_eq!(
        send_digests(&s.store, &s.spool, &s.links, &settings(), now)
            .await
            .unwrap(),
        0
    );
    let digests = s.spool.list(SpoolState::Incoming).await.unwrap();
    assert_eq!(digests.len(), 1);
    let digest = &digests[0];
    assert_eq!(digest.rcpt_to, ["user@example.test"]);
    assert_eq!(digest.mail_from, "quarantine@mx.example.test");
    assert_eq!(digest.pipeline, "deliver");
    let body = s.spool.read_body(&digest.id).await.unwrap();
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("Auto-Submitted: auto-generated"), "{text}");
    let html = mail_parser::MessageParser::default()
        .parse(&body[..])
        .unwrap()
        .body_html(0)
        .unwrap()
        .into_owned();
    // Sender-controlled text is escaped, and only spam is offered to the user.
    assert!(
        html.contains("Cheap &#60;b&#62;pills") || html.contains("Cheap &lt;b&gt;pills"),
        "{html}"
    );
    assert_eq!(html.matches(">Release</a>").count(), 1, "{html}");
    let path = release_path(&body);

    // Following the link only asks for confirmation.
    let (status, page) = send(&s.app, Request::get(&path).body(Body::empty()).unwrap()).await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert!(page.contains("<form method=\"post\">"), "{page}");
    assert_eq!(s.spool.list(SpoolState::Incoming).await.unwrap().len(), 1);

    let (status, page) = send(&s.app, Request::post(&path).body(Body::empty()).unwrap()).await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert!(page.contains("released"), "{page}");

    // Re-injected for this recipient only, with the original bytes, marked to
    // skip policy.
    let released = s
        .spool
        .list(SpoolState::Incoming)
        .await
        .unwrap()
        .into_iter()
        .find(|env| env.pipeline == RELEASE_PIPELINE)
        .unwrap();
    assert_eq!(released.rcpt_to, ["user@example.test"]);
    assert_eq!(released.mail_from, "sender@outside.test");
    assert_eq!(released.tenant_id.as_deref(), Some("t1"));
    assert_eq!(
        released.prepend_headers,
        ["Authentication-Results: currawong.example.test; spf=pass\r\n"]
    );
    assert_eq!(s.spool.read_body(&released.id).await.unwrap(), RAW);
    let item = s.store.get(&ids[0]).unwrap().unwrap();
    assert_eq!(item.released_by.as_deref(), Some("user@example.test"));

    let events = s.store.audit_table().events().unwrap();
    let release = events.iter().find(|e| e.action == "release").unwrap();
    assert_eq!(release.actor, "user@example.test");
    assert_eq!(release.role, "end_user");
    assert_eq!(release.item_id, ids[0]);
    assert_eq!(release.detail.as_deref(), Some(released.id.as_str()));

    // The link works once.
    let (status, _) = send(&s.app, Request::post(&path).body(Body::empty()).unwrap()).await;
    assert_eq!(status, StatusCode::GONE);
    assert_eq!(
        s.spool
            .list(SpoolState::Incoming)
            .await
            .unwrap()
            .iter()
            .filter(|env| env.pipeline == RELEASE_PIPELINE)
            .count(),
        1
    );
}

#[tokio::test]
async fn end_users_get_403_on_virus_items() {
    let s = setup().await;
    let now = OffsetDateTime::now_utc();
    let ids = s
        .store
        .hold(&hold(VIRUS_ID, "malware", Some("t1")), RAW, now)
        .await
        .unwrap();
    let id = &ids[0];

    // Digests never link virus items, so forge a correctly signed one.
    let token = s.links.sign(&Link {
        item_id: id.clone(),
        recipient: "user@example.test".into(),
        action: LinkAction::Release,
        expires_at: now.unix_timestamp() + 3600,
    });
    let link = format!("/quarantine/link/{token}");
    let (status, page) = send(&s.app, Request::post(&link).body(Body::empty()).unwrap()).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{page}");

    let user = Principal {
        actor: "user@example.test".into(),
        role: Role::EndUser,
        tenant_id: Some("t1".into()),
    };
    let release = format!("/quarantine/items/{id}/release");
    let (status, _) = send(&s.app, post(&release, Some(&user), r#"{"reason":"mine"}"#)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let delete = format!("/quarantine/items/{id}/delete");
    let (status, _) = send(&s.app, post(&delete, Some(&user), "{}")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, list) = send(&s.app, {
        let mut request = Request::get("/quarantine/items")
            .body(Body::empty())
            .unwrap();
        request.extensions_mut().insert(user.clone());
        request
    })
    .await;
    assert_eq!((status, list.as_str()), (StatusCode::OK, "[]"));

    // No caller at all.
    let (status, _) = send(&s.app, post(&release, None, "{}")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // Auditors read only; another tenant's admin sees nothing.
    let auditor = Principal {
        actor: "audit".into(),
        role: Role::Auditor,
        tenant_id: Some("t1".into()),
    };
    let (status, _) = send(&s.app, post(&release, Some(&auditor), r#"{"reason":"x"}"#)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let other = Principal {
        actor: "admin@t2".into(),
        role: Role::TenantAdmin,
        tenant_id: Some("t2".into()),
    };
    let (status, _) = send(&s.app, post(&release, Some(&other), r#"{"reason":"x"}"#)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(s.spool.list(SpoolState::Incoming).await.unwrap().is_empty());

    // The tenant admin can, with a reason.
    let admin = Principal {
        actor: "admin@t1".into(),
        role: Role::TenantAdmin,
        tenant_id: Some("t1".into()),
    };
    let (status, _) = send(&s.app, post(&release, Some(&admin), "{}")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, body) = send(
        &s.app,
        post(
            &release,
            Some(&admin),
            r#"{"reason":"false positive, checked"}"#,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(s.spool.list(SpoolState::Incoming).await.unwrap().len(), 1);

    let events = s.store.audit_table().events().unwrap();
    let actions: Vec<(&str, &str)> = events
        .iter()
        .map(|e| (e.action.as_str(), e.role.as_str()))
        .collect();
    assert_eq!(
        actions,
        [
            ("denied:release", "end_user"),
            ("denied:release", "end_user"),
            ("denied:delete", "end_user"),
            ("denied:release", "auditor"),
            ("denied:release", "tenant_admin"),
            ("release", "tenant_admin"),
        ]
    );
    assert_eq!(
        events.last().unwrap().reason.as_deref(),
        Some("false positive, checked")
    );
}

#[tokio::test]
async fn expired_items_are_purged_from_db_and_blob_store() {
    let s = setup().await;
    let now = OffsetDateTime::now_utc();
    let old = s
        .store
        .hold(&hold(SPAM_ID, "spam", None), RAW, now - Duration::days(31))
        .await
        .unwrap();
    let fresh = s
        .store
        .hold(
            &hold(VIRUS_ID, "malware", None),
            RAW,
            now - Duration::days(1),
        )
        .await
        .unwrap();
    assert!(s.blobs.path(SPAM_ID).unwrap().exists());

    assert_eq!(s.store.purge(now).await.unwrap(), 1);
    assert!(s.store.get(&old[0]).unwrap().is_none());
    assert!(s.store.reason(SPAM_ID).is_err());
    assert!(!s.blobs.path(SPAM_ID).unwrap().exists());
    assert!(s.blobs.get(SPAM_ID).await.is_err());
    // Within retention: kept.
    assert!(s.store.get(&fresh[0]).unwrap().is_some());
    assert_eq!(s.blobs.get(VIRUS_ID).await.unwrap(), RAW);

    let events = s.store.audit_table().events().unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(
        (events[0].action.as_str(), events[0].actor.as_str()),
        ("purge", "system")
    );
    assert_eq!(s.store.purge(now).await.unwrap(), 0);
}

#[tokio::test]
async fn holding_again_after_a_crash_adds_nothing_and_retention_is_per_queue() {
    let s = setup().await;
    let mut cfg = Config::default();
    cfg.quarantine
        .queue_retention_days
        .insert("malware".into(), 90);
    let store = s.store.clone().with_config(&cfg.quarantine);
    let now = OffsetDateTime::now_utc();
    let mut two = hold(SPAM_ID, "malware", None);
    two.recipients.push("other@example.test".into());
    let first = store.hold(&two, RAW, now).await.unwrap();
    let again = store.hold(&two, RAW, now).await.unwrap();
    assert_eq!(first, again);
    let item = store.get(&first[0]).unwrap().unwrap();
    assert_eq!(item.expires_at - item.created_at, 90 * 86_400);
    assert_eq!(item.subject, "Cheap <b>pills</b>");
    let admin = Principal {
        actor: "root".into(),
        role: Role::PlatformAdmin,
        tenant_id: None,
    };
    assert_eq!(store.list(&admin, Some("malware")).unwrap().len(), 2);

    // Deleting one recipient's copy keeps the bytes for the other.
    store
        .act(&s.spool, &admin, &first[0], LinkAction::Delete, None, now)
        .await
        .unwrap();
    assert!(s.blobs.get(SPAM_ID).await.is_ok());
    store
        .act(&s.spool, &admin, &first[1], LinkAction::Delete, None, now)
        .await
        .unwrap();
    assert!(s.blobs.get(SPAM_ID).await.is_err());
}
