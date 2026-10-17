use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    Router,
};
use currawong_core::{config::Config, Direction, MessageId};
use currawong_quarantine::{
    digest::{send_digests, DigestSettings},
    http::{router, HttpState},
    AuditEvent, AuditSink, BlobStore, FsBlobStore, Hold, Link, LinkAction, LinkSigner, ListQuery,
    Principal, QuarantineError, QuarantineStore, Role, RELEASE_HAM_PIPELINE, RELEASE_PIPELINE,
};
use currawong_spool::{Spool, SpoolState};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
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
        .find(|env| env.pipeline == RELEASE_HAM_PIPELINE)
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
            .filter(|env| env.pipeline == RELEASE_HAM_PIPELINE)
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
    assert_eq!(
        (status, list.as_str()),
        (StatusCode::OK, r#"{"items":[],"next":null}"#)
    );

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
    let malware = ListQuery {
        queue: Some("Malware".into()),
        ..ListQuery::default()
    };
    assert_eq!(store.list(&admin, &malware).unwrap().items.len(), 2);

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

fn principal(actor: &str, role: Role, tenant: Option<&str>) -> Principal {
    Principal {
        actor: actor.into(),
        role,
        tenant_id: tenant.map(str::to_string),
    }
}

#[tokio::test]
async fn outbound_holds_notify_the_sender_and_never_the_external_recipient() {
    let s = setup().await;
    let now = OffsetDateTime::now_utc();
    let mut out = hold(SPAM_ID, "spam", Some("t1"));
    out.direction = Direction::Outbound;
    out.sender = "staff@example.test".into();
    out.recipients = vec!["victim@outside.test".into()];
    let ids = s.store.hold(&out, RAW, now).await.unwrap();

    assert_eq!(
        send_digests(&s.store, &s.spool, &s.links, &settings(), now)
            .await
            .unwrap(),
        1
    );
    let notices = s.spool.list(SpoolState::Incoming).await.unwrap();
    assert_eq!(notices.len(), 1);
    assert_eq!(notices[0].rcpt_to, ["staff@example.test"]);
    let body = s.spool.read_body(&notices[0].id).await.unwrap();
    let text = mail_parser::MessageParser::default()
        .parse(&body[..])
        .unwrap()
        .body_text(0)
        .unwrap()
        .into_owned();
    assert!(text.contains("To: victim@outside.test"), "{text}");
    assert!(!text.contains("/quarantine/link/"), "{text}");
    assert!(!String::from_utf8_lossy(&body).contains("/quarantine/link/"));

    // A correctly signed link for the external recipient is still refused,
    // and neither party sees the item as an end user.
    let token = s.links.sign(&Link {
        item_id: ids[0].clone(),
        recipient: "victim@outside.test".into(),
        action: LinkAction::Release,
        expires_at: now.unix_timestamp() + 3600,
    });
    let (status, _) = send(
        &s.app,
        Request::post(format!("/quarantine/link/{token}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    for actor in ["victim@outside.test", "staff@example.test"] {
        let user = principal(actor, Role::EndUser, Some("t1"));
        assert!(s
            .store
            .list(&user, &ListQuery::default())
            .unwrap()
            .items
            .is_empty());
        let err = s
            .store
            .act(&s.spool, &user, &ids[0], LinkAction::Release, None, now)
            .await
            .unwrap_err();
        assert!(matches!(err, QuarantineError::Forbidden), "{err:?}");
    }
    // An administrator can.
    let admin = principal("admin@t1", Role::TenantAdmin, Some("t1"));
    s.store
        .act(&s.spool, &admin, &ids[0], LinkAction::Release, None, now)
        .await
        .unwrap();
}

#[tokio::test]
async fn lists_are_scoped_in_the_query_searchable_and_paged() {
    let s = setup().await;
    let now = OffsetDateTime::now_utc();
    // Many newer items for another tenant must not crowd t1 out of a page.
    for n in 0..30u32 {
        let id = format!("01ARZ3NDEKTSV4RRFFQ69G{n:04}");
        let mut other = hold(&id, "spam", Some("t2"));
        other.recipients = vec![format!("u{n}@other.test")];
        s.store.hold(&other, RAW, now).await.unwrap();
    }
    let ids = [
        "01ARZ3NDEKTSV4RRFFQ69G5FA1",
        "01ARZ3NDEKTSV4RRFFQ69G5FA2",
        "01ARZ3NDEKTSV4RRFFQ69G5FA3",
    ];
    for (n, id) in ids.iter().enumerate() {
        let mut mine = hold(id, "spam", Some("t1"));
        mine.sender = format!("sender{n}@outside.test");
        let raw = format!("Subject: invoice {n}\r\n\r\nbody\r\n");
        let at = now - Duration::hours(10 + n as i64);
        s.store.hold(&mine, raw.as_bytes(), at).await.unwrap();
    }
    let admin = principal("admin@t1", Role::TenantAdmin, Some("t1"));
    let first = s
        .store
        .list(
            &admin,
            &ListQuery {
                limit: Some(2),
                ..ListQuery::default()
            },
        )
        .unwrap();
    assert_eq!(first.items.len(), 2);
    assert!(first
        .items
        .iter()
        .all(|i| i.tenant_id.as_deref() == Some("t1")));
    let second = s
        .store
        .list(
            &admin,
            &ListQuery {
                limit: Some(2),
                cursor: first.next.clone(),
                ..ListQuery::default()
            },
        )
        .unwrap();
    assert_eq!(second.items.len(), 1);
    assert_eq!(second.next, None);
    assert_ne!(second.items[0].id, first.items[0].id);

    let search = |query: ListQuery| s.store.list(&admin, &query).unwrap().items;
    let hit = search(ListQuery {
        subject: Some("voice 1".into()),
        ..ListQuery::default()
    });
    assert_eq!(hit.len(), 1);
    assert_eq!(hit[0].subject, "invoice 1");
    assert!(search(ListQuery {
        subject: Some("%".into()),
        ..ListQuery::default()
    })
    .is_empty());
    assert_eq!(
        search(ListQuery {
            sender: Some("SENDER2@outside.test".into()),
            ..ListQuery::default()
        })
        .len(),
        1
    );
    assert_eq!(
        search(ListQuery {
            since: Some((now - Duration::hours(11)).unix_timestamp()),
            ..ListQuery::default()
        })
        .len(),
        2
    );
    // An end user sees only their own inbound items.
    let user = principal("User@Example.test", Role::EndUser, Some("t1"));
    assert_eq!(
        s.store
            .list(&user, &ListQuery::default())
            .unwrap()
            .items
            .len(),
        3
    );
    let user = principal("u3@other.test", Role::EndUser, Some("t1"));
    assert!(s
        .store
        .list(&user, &ListQuery::default())
        .unwrap()
        .items
        .is_empty());
}

/// Fails while `fail` is set.
struct FlakyAudit {
    fail: AtomicBool,
    events: std::sync::Mutex<Vec<AuditEvent>>,
}

impl AuditSink for FlakyAudit {
    fn record(&self, event: &AuditEvent) -> Result<(), String> {
        if self.fail.load(Ordering::SeqCst) {
            return Err("audit store unavailable".into());
        }
        self.events.lock().unwrap().push(event.clone());
        Ok(())
    }
}

#[tokio::test]
async fn a_failed_audit_write_leaves_the_item_held_and_a_retry_completes() {
    let s = setup().await;
    let audit = Arc::new(FlakyAudit {
        fail: AtomicBool::new(true),
        events: std::sync::Mutex::new(Vec::new()),
    });
    let store = s.store.clone().with_audit(audit.clone());
    let now = OffsetDateTime::now_utc();
    let ids = store
        .hold(&hold(SPAM_ID, "spam", None), RAW, now)
        .await
        .unwrap();
    let admin = principal("root", Role::PlatformAdmin, None);
    for action in [LinkAction::Release, LinkAction::Delete] {
        let err = store
            .act(&s.spool, &admin, &ids[0], action, None, now)
            .await
            .unwrap_err();
        assert!(matches!(err, QuarantineError::Store(_)), "{err:?}");
        assert!(store.get(&ids[0]).unwrap().unwrap().held());
    }
    // Nothing was released without its audit row.
    assert!(s.spool.list(SpoolState::Incoming).await.unwrap().is_empty());
    assert!(s.blobs.get(SPAM_ID).await.is_ok());

    audit.fail.store(false, Ordering::SeqCst);
    let released = store
        .act(&s.spool, &admin, &ids[0], LinkAction::Release, None, now)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(s.spool.list(SpoolState::Incoming).await.unwrap().len(), 1);
    let events = audit.events.lock().unwrap().clone();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].action, "release");
    assert_eq!(events[0].detail.as_deref(), Some(released.as_str()));
}

/// File blobs whose delete fails for one key.
struct StuckBlob {
    inner: FsBlobStore,
    stuck: String,
}

#[async_trait::async_trait]
impl BlobStore for StuckBlob {
    async fn put(&self, key: &str, bytes: &[u8]) -> std::io::Result<()> {
        self.inner.put(key, bytes).await
    }
    async fn get(&self, key: &str) -> std::io::Result<Vec<u8>> {
        self.inner.get(key).await
    }
    async fn delete(&self, key: &str) -> std::io::Result<()> {
        if key == self.stuck {
            return Err(std::io::Error::other("bucket unavailable"));
        }
        self.inner.delete(key).await
    }
}

#[tokio::test]
async fn purge_continues_past_a_failing_item_and_expired_items_cannot_be_released() {
    let s = setup().await;
    let store = s.store.clone().with_blobs(Arc::new(StuckBlob {
        inner: s.blobs.clone(),
        stuck: SPAM_ID.into(),
    }));
    let now = OffsetDateTime::now_utc();
    let old = now - Duration::days(31);
    let stuck = store
        .hold(&hold(SPAM_ID, "spam", None), RAW, old)
        .await
        .unwrap();
    let gone = store
        .hold(&hold(VIRUS_ID, "virus", None), RAW, old)
        .await
        .unwrap();

    // Expired but not yet purged: nobody can release it.
    let admin = principal("root", Role::PlatformAdmin, None);
    let err = store
        .act(&s.spool, &admin, &stuck[0], LinkAction::Release, None, now)
        .await
        .unwrap_err();
    assert!(matches!(err, QuarantineError::NotFound), "{err:?}");

    assert_eq!(store.purge(now).await.unwrap(), 1);
    assert!(store.get(&gone[0]).unwrap().is_none());
    assert!(s.blobs.get(VIRUS_ID).await.is_err());
    // The failing item is kept, bytes and row, for the next pass.
    assert!(store.get(&stuck[0]).unwrap().is_some());
    assert!(s.blobs.get(SPAM_ID).await.is_ok());
    assert!(s.spool.list(SpoolState::Incoming).await.unwrap().is_empty());
}

#[tokio::test]
async fn the_blob_goes_when_the_last_recipient_is_released() {
    let s = setup().await;
    let now = OffsetDateTime::now_utc();
    let mut two = hold(SPAM_ID, "spam", None);
    two.recipients.push("other@example.test".into());
    let ids = s.store.hold(&two, RAW, now).await.unwrap();
    let admin = principal("root", Role::PlatformAdmin, None);
    s.store
        .act(&s.spool, &admin, &ids[0], LinkAction::Release, None, now)
        .await
        .unwrap();
    assert!(s.blobs.get(SPAM_ID).await.is_ok());
    s.store
        .act(&s.spool, &admin, &ids[1], LinkAction::Release, None, now)
        .await
        .unwrap();
    assert!(s.blobs.get(SPAM_ID).await.is_err());
    // Both re-injected copies carry the bytes.
    for env in s.spool.list(SpoolState::Incoming).await.unwrap() {
        assert_eq!(s.spool.read_body(&env.id).await.unwrap(), RAW);
        assert_eq!(env.pipeline, RELEASE_HAM_PIPELINE);
    }
}

#[tokio::test]
async fn queue_names_are_canonical_and_virus_and_pspf_need_an_admin() {
    let s = setup().await;
    let mut cfg = Config::default();
    cfg.quarantine.user_release_queues = vec!["SPAM".into()];
    cfg.quarantine
        .queue_retention_days
        .insert("Virus".into(), 90);
    let store = s.store.clone().with_config(&cfg.quarantine);
    let now = OffsetDateTime::now_utc();
    let mut score = hold("01ARZ3NDEKTSV4RRFFQ69G5FAX", "Spam ", None);
    score.score = Some(9.5);
    let spam = store.hold(&score, RAW, now).await.unwrap();
    let virus = store
        .hold(&hold(VIRUS_ID, " Virus", None), RAW, now)
        .await
        .unwrap();
    let pspf = store
        .hold(&hold(SPAM_ID, "PSPF", None), RAW, now)
        .await
        .unwrap();
    let item = store.get(&virus[0]).unwrap().unwrap();
    assert_eq!(item.queue, "virus");
    assert_eq!(item.expires_at - item.created_at, 90 * 86_400);
    assert_eq!(store.get(&spam[0]).unwrap().unwrap().score, Some(9.5));

    let user = principal("user@example.test", Role::EndUser, None);
    for id in [&virus[0], &pspf[0]] {
        let err = store
            .act(&s.spool, &user, id, LinkAction::Release, Some("mine"), now)
            .await
            .unwrap_err();
        assert!(matches!(err, QuarantineError::Forbidden), "{err:?}");
        let err = store
            .act(&s.spool, &user, id, LinkAction::Delete, None, now)
            .await
            .unwrap_err();
        assert!(matches!(err, QuarantineError::Forbidden), "{err:?}");
    }
    // "SPAM" in config matches the "spam" queue for end users.
    store
        .act(&s.spool, &user, &spam[0], LinkAction::Delete, None, now)
        .await
        .unwrap();
    let admin = principal("root", Role::PlatformAdmin, None);
    let err = store
        .act(&s.spool, &admin, &pspf[0], LinkAction::Release, None, now)
        .await
        .unwrap_err();
    assert!(matches!(err, QuarantineError::BadRequest(_)), "{err:?}");
    store
        .act(
            &s.spool,
            &admin,
            &pspf[0],
            LinkAction::Release,
            Some("cleared"),
            now,
        )
        .await
        .unwrap();
    // Not a spam release, so it does not train the classifier.
    let released = s.spool.list(SpoolState::Incoming).await.unwrap();
    assert_eq!(released.len(), 1);
    assert_eq!(released[0].pipeline, RELEASE_PIPELINE);
    let actions: Vec<String> = store
        .audit_table()
        .events()
        .unwrap()
        .into_iter()
        .map(|e| e.action)
        .collect();
    assert_eq!(
        actions,
        [
            "denied:release",
            "denied:delete",
            "denied:release",
            "denied:delete",
            "delete",
            "release"
        ]
    );
}
