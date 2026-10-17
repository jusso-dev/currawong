use currawong_auth::{seed_txt, seed_txt_error, AuthChecker, DmarcEventStore};
use currawong_core::{
    config::{Config, DmarcReportConfig},
    AuthMethodResult, AuthResults, Direction, MessageId, ScanReport,
};
use currawong_quarantine::QuarantineStore;
use currawong_smtp::dns::MapDns;
use currawong_spool::{Envelope, Spool, SpoolState};
use currawongd::{annotate_bimi, ready_to_deliver, send_dmarc_reports, Pipeline};
use std::{collections::HashMap, net::IpAddr, sync::Arc};
use time::OffsetDateTime;

// Wed, 14 Oct 2026 01:00:00 UTC.
const RECEIVED: i64 = 1_791_939_600;
// The next day, after the one-hour grace period.
const DUE: i64 = RECEIVED - 3_600 + 86_400 + 2 * 3_600;

fn envelope(id: &str, direction: Direction) -> Envelope {
    Envelope {
        id: MessageId(id.into()),
        tenant_id: None,
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

    // DNS recovers and the destination has consented: the report goes out.
    seed_txt(
        s.pipeline.auth.cache(),
        "example.test._report._dmarc.victim.test",
        "v=DMARC1",
    )
    .unwrap();
    assert_eq!(pass(&s).await, 1);
    let queued = s.spool.list(SpoolState::Incoming).await.unwrap();
    assert_eq!(queued[0].rcpt_to, vec!["collector@victim.test".to_string()]);
}

#[tokio::test]
async fn dmarc_report_spooled_before_a_crash_is_not_duplicated() {
    let s = setup("mailto:agg@example.test").await;
    let day = RECEIVED as u64 / 86_400;
    // A previous pass spooled the report and died before finishing the day.
    let id = s
        .store
        .spool_id(day, "example.test", Envelope::new_id().as_str())
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
        "fd00::1",
        "::ffff:192.168.0.1",
    ] {
        assert!(
            !currawongd::is_public(internal.parse().unwrap()),
            "{internal}"
        );
    }
    assert!(currawongd::is_public("203.0.113.25".parse().unwrap()));
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
async fn bimi_logo_is_stored_with_the_quarantined_message() {
    let dir = tempfile::tempdir().unwrap();
    let quarantine = QuarantineStore::open(dir.path()).unwrap();
    let id = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
    quarantine.hold(id, "spam", &message()).unwrap();
    let mut report = ScanReport::new(MessageId(id.into()));
    report.auth = Some(AuthResults {
        spf: AuthMethodResult::none(),
        dkim: Vec::new(),
        dmarc: AuthMethodResult {
            result: "pass".into(),
            detail: String::new(),
        },
        arc: AuthMethodResult::none(),
        dmarc_policy: "reject".into(),
        header: "Authentication-Results: gateway.test;\r\n\tdmarc=pass header.from=example.test policy.dmarc=reject\r\n".into(),
    });
    let txt = HashMap::from([
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
    ]);
    annotate_bimi(&txt, &quarantine, &report).await;
    let json = quarantine.bimi(id).unwrap().unwrap();
    assert!(json.contains("https://example.test/logo.svg"), "{json}");
    assert!(json.contains("\"vmc\":\"unverified\""), "{json}");
}
