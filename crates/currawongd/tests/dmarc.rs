use currawong_auth::TxtLookup;
use currawong_auth::{seed_txt, seed_txt_error, AuthChecker, DmarcEventStore};
use currawong_core::{
    config::{Config, DmarcReportConfig},
    AuthMethodResult, AuthResults, Direction, MessageId,
};
use currawong_quarantine::{Hold, QuarantineStore};
use currawong_smtp::dns::MapDns;
use currawong_spool::{Envelope, Spool, SpoolState};
use currawongd::{ready_to_deliver, send_dmarc_reports, supervise, BimiJob, BimiWorker, Pipeline};
use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use time::OffsetDateTime;
use tokio_util::sync::CancellationToken;

// Wed, 14 Oct 2026 01:00:00 UTC.
const RECEIVED: i64 = 1_791_939_600;
// The next day, after the one-hour grace period.
const DUE: i64 = RECEIVED - 3_600 + 86_400 + 2 * 3_600;

fn envelope(id: &str, direction: Direction) -> Envelope {
    Envelope {
        id: MessageId(id.into()),
        tenant_id: None,
        authenticated_as: None,
        mail_from: "user@example.test".into(),
        rcpt_to: vec!["dest@gateway.test".into()],
        received_at: OffsetDateTime::from_unix_timestamp(RECEIVED).unwrap(),
        remote_ip: "203.0.113.8".parse().unwrap(),
        helo: "client.example.test".into(),
        attempts: 0,
        next_attempt_at: None,
        state: SpoolState::Incoming,
        direction,
        tls_version: None,
        tls_cipher: None,
        rcpt_status: Vec::new(),
        prepend_headers: Vec::new(),
        dsn_sent: false,
        pipeline: "pending".into(),
    }
}

fn message() -> Vec<u8> {
    b"From: user@example.test\r\nTo: dest@gateway.test\r\nSubject: hi\r\nDate: Wed, 14 Oct 2026 01:00:00 +0000\r\n\r\nhello\r\n".to_vec()
}

struct Setup {
    _dir: tempfile::TempDir,
    cfg: Config,
    spool: Spool,
    store: DmarcEventStore,
    pipeline: Pipeline,
    dns: MapDns,
}

/// One inbound message from example.test whose record asks for `rua`.
async fn setup(rua: &str) -> Setup {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::default();
    cfg.spool.dir = dir.path().join("spool");
    cfg.scanner.enabled = false;
    cfg.domains.accept = vec!["gateway.test".into()];
    cfg.auth.dmarc_reports = DmarcReportConfig {
        enabled: true,
        email: "dmarc-reports@gateway.test".into(),
        database: dir.path().join("dmarc.sqlite"),
        ..DmarcReportConfig::default()
    };
    let spool = Spool::open(&cfg.spool.dir).await.unwrap();
    let auth = AuthChecker::offline("gateway.test").unwrap();
    seed_txt(auth.cache(), "example.test", "v=spf1 ip4:203.0.113.8 -all").unwrap();
    seed_txt(
        auth.cache(),
        "_dmarc.example.test",
        &format!("v=DMARC1; p=none; rua={rua}"),
    )
    .unwrap();
    let store = DmarcEventStore::open(&cfg.auth.dmarc_reports).unwrap();
    let mut pipeline = Pipeline::new(Arc::new(cfg.clone()), auth).with_dmarc_events(store.clone());
    pipeline
        .evaluate(
            &envelope("01ARZ3NDEKTSV4RRFFQ69G5FAV", Direction::Inbound),
            &message(),
            None,
        )
        .await;
    let mut dns = MapDns::new();
    for host in ["example.test", "victim.test"] {
        dns.mx.insert(host.into(), vec![(10, format!("mx.{host}"))]);
        dns.ips.insert(
            format!("mx.{host}"),
            vec!["203.0.113.25".parse::<IpAddr>().unwrap()],
        );
    }
    Setup {
        _dir: dir,
        cfg,
        spool,
        store,
        pipeline,
        dns,
    }
}

async fn pass(s: &Setup) -> usize {
    send_dmarc_reports(
        &s.spool,
        &s.pipeline.auth,
        &s.store,
        &s.cfg,
        &s.dns,
        OffsetDateTime::from_unix_timestamp(DUE).unwrap(),
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn dmarc_report_pipeline_records_inbound_and_spools_daily_report() {
    let mut s = setup("mailto:agg@example.test,mailto:other@victim.test").await;
    // Our own outbound mail is not reported back to its sender.
    s.pipeline
        .evaluate(
            &envelope("01ARZ3NDEKTSV4RRFFQ69G5FAW", Direction::Outbound),
            &message(),
            None,
        )
        .await;
    let early = OffsetDateTime::from_unix_timestamp(RECEIVED + 60).unwrap();
    assert_eq!(
        send_dmarc_reports(&s.spool, &s.pipeline.auth, &s.store, &s.cfg, &s.dns, early)
            .await
            .unwrap(),
        0
    );
    assert_eq!(pass(&s).await, 1);
    let queued = s.spool.list(SpoolState::Incoming).await.unwrap();
    assert_eq!(queued.len(), 1);
    let env = &queued[0];
    assert_eq!(env.rcpt_to, vec!["agg@example.test".to_string()]);
    assert_eq!(env.mail_from, "dmarc-reports@gateway.test");
    assert_eq!(env.direction, Direction::Outbound);
    assert!(ready_to_deliver(env));
    let body = String::from_utf8(s.spool.read_body(&env.id).await.unwrap()).unwrap();
    assert!(body.contains("application/gzip"), "{body}");
    assert!(!body.contains("victim.test"), "{body}");

    // The day is finished: nothing is sent twice.
    assert_eq!(pass(&s).await, 0);
    assert_eq!(s.spool.list(SpoolState::Incoming).await.unwrap().len(), 1);
}

#[tokio::test]
async fn dmarc_report_deferred_message_is_counted_once() {
    let mut s = setup("mailto:agg@example.test").await;
    // The same message classified again, as after a scan deferral.
    s.pipeline
        .evaluate(
            &envelope("01ARZ3NDEKTSV4RRFFQ69G5FAV", Direction::Inbound),
            &message(),
            None,
        )
        .await;
    let day = RECEIVED as u64 / 86_400;
    let data = s.store.load(day, "example.test").unwrap().unwrap();
    assert_eq!(data.rows.len(), 1);
    assert_eq!(data.rows[0].1, 1);
}

async fn pass_at(s: &Setup, at: i64) -> usize {
    send_dmarc_reports(
        &s.spool,
        &s.pipeline.auth,
        &s.store,
        &s.cfg,
        &s.dns,
        OffsetDateTime::from_unix_timestamp(at).unwrap(),
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn dmarc_report_dns_error_keeps_rows_and_retries() {
    let s = setup("mailto:collector@victim.test").await;
    seed_txt_error(
        s.pipeline.auth.cache(),
        "example.test._report._dmarc.victim.test",
    );
    assert_eq!(pass(&s).await, 0);
    let day = RECEIVED as u64 / 86_400;
    assert!(s.store.load(day, "example.test").unwrap().is_some());
    assert_eq!(
        s.store.ledger(day, "example.test").unwrap(),
        Some((1, false, false))
    );
    // Backing off: an immediate second pass leaves it alone.
    assert_eq!(pass(&s).await, 0);
    assert_eq!(
        s.store.ledger(day, "example.test").unwrap(),
        Some((1, false, false))
    );

    // DNS recovers and the destination has consented: the report goes out.
    seed_txt(
        s.pipeline.auth.cache(),
        "example.test._report._dmarc.victim.test",
        "v=DMARC1",
    )
    .unwrap();
    assert_eq!(pass_at(&s, DUE + 600).await, 1);
    let queued = s.spool.list(SpoolState::Incoming).await.unwrap();
    assert_eq!(queued[0].rcpt_to, vec!["collector@victim.test".to_string()]);
}

#[tokio::test]
async fn dmarc_report_one_failing_domain_does_not_hold_up_another() {
    let mut s = setup("mailto:agg@example.test").await;
    // A second sending domain whose consent lookup keeps failing.
    seed_txt(
        s.pipeline.auth.cache(),
        "slow.test",
        "v=spf1 ip4:203.0.113.8 -all",
    )
    .unwrap();
    seed_txt(
        s.pipeline.auth.cache(),
        "_dmarc.slow.test",
        "v=DMARC1; p=none; rua=mailto:collector@victim.test",
    )
    .unwrap();
    seed_txt_error(
        s.pipeline.auth.cache(),
        "slow.test._report._dmarc.victim.test",
    );
    let mut env = envelope("01ARZ3NDEKTSV4RRFFQ69G5FAX", Direction::Inbound);
    env.mail_from = "user@slow.test".into();
    let raw = b"From: user@slow.test\r\nTo: dest@gateway.test\r\nSubject: hi\r\n\r\nhello\r\n";
    s.pipeline.evaluate(&env, raw, None).await;

    assert_eq!(pass(&s).await, 1);
    let queued = s.spool.list(SpoolState::Incoming).await.unwrap();
    assert_eq!(queued.len(), 1);
    assert_eq!(queued[0].rcpt_to, vec!["agg@example.test".to_string()]);
    let day = RECEIVED as u64 / 86_400;
    assert!(s.store.load(day, "slow.test").unwrap().is_some());
    assert_eq!(
        s.store.ledger(day, "slow.test").unwrap(),
        Some((1, false, false))
    );
}

#[tokio::test]
async fn dmarc_report_spooled_before_a_crash_is_not_duplicated() {
    let s = setup("mailto:agg@example.test").await;
    let day = RECEIVED as u64 / 86_400;
    // A previous pass spooled the report and died before finishing the day.
    let id = s
        .store
        .claim(day, "example.test", Envelope::new_id().as_str())
        .unwrap();
    let mut env = envelope(&id, Direction::Outbound);
    env.pipeline = "deliver".into();
    s.spool.accept(env, &b"earlier report"[..]).await.unwrap();

    assert_eq!(pass(&s).await, 1);
    assert_eq!(s.spool.list(SpoolState::Incoming).await.unwrap().len(), 1);
    assert!(s.store.load(day, "example.test").unwrap().is_none());
    assert_eq!(pass(&s).await, 0);
}

#[tokio::test]
async fn dmarc_report_never_targets_internal_addresses() {
    // The policy domain's own rua needs no consent, but its MX points inside.
    let mut s = setup("mailto:agg@example.test").await;
    s.dns
        .ips
        .insert("mx.example.test".into(), vec!["127.0.0.1".parse().unwrap()]);
    assert_eq!(pass(&s).await, 0);
    assert!(s.spool.list(SpoolState::Incoming).await.unwrap().is_empty());

    for internal in [
        "10.1.2.3",
        "169.254.169.254",
        "100.64.0.1",
        "198.18.0.1",
        "192.0.0.8",
        "fd00::1",
        "fec0::1",
        "::ffff:192.168.0.1",
        "64:ff9b::a00:1",
        "2002:a00:1::1",
        "::10.0.0.1",
    ] {
        assert!(
            !currawongd::is_public(internal.parse().unwrap()),
            "{internal}"
        );
    }
    assert!(currawongd::is_public("203.0.113.25".parse().unwrap()));
    assert!(currawongd::is_public("2001:db8::25".parse().unwrap()));
}

#[tokio::test]
async fn dmarc_report_checks_every_mx_host() {
    // One public MX and one private one: refused.
    let mut s = setup("mailto:agg@example.test").await;
    s.dns.mx.insert(
        "example.test".into(),
        vec![
            (10, "mx.example.test".into()),
            (20, "backup.example.test".into()),
        ],
    );
    s.dns.ips.insert(
        "backup.example.test".into(),
        vec!["10.0.0.25".parse().unwrap()],
    );
    assert_eq!(pass(&s).await, 0);
    assert!(s.spool.list(SpoolState::Incoming).await.unwrap().is_empty());
}

#[tokio::test]
async fn dmarc_report_refuses_too_many_or_null_mx() {
    let mut many = setup("mailto:agg@example.test").await;
    let hosts: Vec<(u16, String)> = (0..11)
        .map(|n| (n, format!("mx{n}.example.test")))
        .collect();
    for (_, host) in &hosts {
        many.dns
            .ips
            .insert(host.clone(), vec!["203.0.113.25".parse().unwrap()]);
    }
    many.dns.mx.insert("example.test".into(), hosts);
    assert_eq!(pass(&many).await, 0);

    let mut null = setup("mailto:agg@example.test").await;
    null.dns
        .mx
        .insert("example.test".into(), vec![(0, ".".into())]);
    null.dns
        .ips
        .insert("example.test".into(), vec!["203.0.113.25".parse().unwrap()]);
    assert_eq!(pass(&null).await, 0);

    // No MX at all: the host's own address is checked and used.
    let mut bare = setup("mailto:agg@example.test").await;
    bare.dns.mx.remove("example.test");
    bare.dns
        .ips
        .insert("example.test".into(), vec!["203.0.113.26".parse().unwrap()]);
    assert_eq!(pass(&bare).await, 1);
}

#[tokio::test]
async fn dmarc_report_never_targets_local_or_literal_domains() {
    let mut s = setup("mailto:postmaster@gateway.test,mailto:agg@10.0.0.1").await;
    for host in ["gateway.test", "10.0.0.1"] {
        seed_txt(
            s.pipeline.auth.cache(),
            &format!("example.test._report._dmarc.{host}"),
            "v=DMARC1",
        )
        .unwrap();
        s.dns
            .ips
            .insert(host.into(), vec!["203.0.113.30".parse().unwrap()]);
    }
    assert_eq!(pass(&s).await, 0);
    assert!(s.spool.list(SpoolState::Incoming).await.unwrap().is_empty());
}

#[tokio::test]
async fn dmarc_report_task_restarts_after_a_panic() {
    let runs = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&runs);
    supervise(
        "test",
        CancellationToken::new(),
        Duration::from_millis(1),
        move || {
            let counter = Arc::clone(&counter);
            async move {
                if counter.fetch_add(1, Ordering::SeqCst) == 0 {
                    panic!("first run fails");
                }
            }
        },
    )
    .await;
    assert_eq!(runs.load(Ordering::SeqCst), 2);

    // Shutdown stops a task that would otherwise run for ever.
    let shutdown = CancellationToken::new();
    shutdown.cancel();
    supervise("test", shutdown, Duration::from_millis(1), || {
        std::future::pending::<()>()
    })
    .await;
}

/// Counts lookups so the cache can be checked.
struct Counting {
    records: HashMap<String, Vec<String>>,
    calls: AtomicUsize,
}

#[async_trait::async_trait]
impl TxtLookup for Counting {
    async fn txt(&self, name: &str) -> Result<Vec<String>, String> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.records.txt(name).await
    }
}

fn bimi_auth() -> AuthResults {
    AuthResults {
        spf: AuthMethodResult::none(),
        dkim: Vec::new(),
        dmarc: AuthMethodResult {
            result: "pass".into(),
            detail: String::new(),
        },
        arc: AuthMethodResult::none(),
        dmarc_policy: "reject".into(),
        dmarc_domain: "example.test".into(),
        header: String::new(),
    }
}

#[tokio::test]
async fn bimi_logo_is_stored_off_the_classify_loop_with_a_domain_cache() {
    let dir = tempfile::tempdir().unwrap();
    let quarantine = QuarantineStore::open(dir.path()).unwrap();
    let ids = ["01ARZ3NDEKTSV4RRFFQ69G5FAV", "01ARZ3NDEKTSV4RRFFQ69G5FAW"];
    for id in ids {
        let hold = Hold {
            message_id: MessageId(id.into()),
            tenant_id: None,
            queue: "spam".into(),
            reason: "spam".into(),
            reasons: Vec::new(),
            sender: "user@example.test".into(),
            recipients: vec!["dest@gateway.test".into()],
            score: None,
            direction: Direction::Inbound,
            headers: Vec::new(),
        };
        quarantine
            .hold(&hold, &message(), OffsetDateTime::now_utc())
            .await
            .unwrap();
    }
    let txt = Counting {
        records: HashMap::from([
            (
                "_dmarc.example.test".to_string(),
                vec!["v=DMARC1; p=reject".to_string()],
            ),
            (
                "default._bimi.example.test".to_string(),
                vec![
                    "v=BIMI1; l=https://example.test/logo.svg; a=https://example.test/vmc.pem"
                        .to_string(),
                ],
            ),
        ]),
        calls: AtomicUsize::new(0),
    };
    let mut worker = BimiWorker::default();
    for id in ids {
        let job = BimiJob {
            id: MessageId(id.into()),
            auth: bimi_auth(),
        };
        worker.handle(&txt, &quarantine, job).await;
    }
    // The second message for the same domain is served from the cache.
    assert_eq!(txt.calls.load(Ordering::SeqCst), 2);
    for id in ids {
        let json = quarantine.bimi(id).unwrap().unwrap();
        assert!(json.contains("https://example.test/logo.svg"), "{json}");
        assert!(json.contains("\"vmc\":\"unverified\""), "{json}");
    }
}

#[tokio::test]
async fn bimi_jobs_are_queued_not_awaited() {
    let s = setup("mailto:agg@example.test").await;
    let (jobs, mut queue) = tokio::sync::mpsc::channel(1);
    let pipeline = Pipeline::new(
        Arc::new(s.cfg.clone()),
        AuthChecker::offline("gateway.test").unwrap(),
    )
    .with_bimi(jobs);
    pipeline.queue_bimi(MessageId("01ARZ3NDEKTSV4RRFFQ69G5FAV".into()), bimi_auth());
    // Full queue: dropped without blocking.
    pipeline.queue_bimi(MessageId("01ARZ3NDEKTSV4RRFFQ69G5FAW".into()), bimi_auth());
    assert_eq!(
        queue.recv().await.unwrap().id.as_str(),
        "01ARZ3NDEKTSV4RRFFQ69G5FAV"
    );
    assert!(queue.try_recv().is_err());
}
