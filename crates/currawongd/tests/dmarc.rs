use currawong_auth::{seed_txt, AuthChecker, DmarcEventStore};
use currawong_core::{
    config::{Config, DmarcReportConfig},
    AuthMethodResult, AuthResults, Direction, MessageId, ScanReport,
};
use currawong_quarantine::QuarantineStore;
use currawong_spool::{Envelope, Spool, SpoolState};
use currawongd::{annotate_bimi, ready_to_deliver, send_dmarc_reports, Pipeline};
use std::{collections::HashMap, sync::Arc};
use time::OffsetDateTime;

const RECEIVED: i64 = 1_791_939_600;

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

#[tokio::test]
async fn dmarc_report_pipeline_records_inbound_and_spools_daily_report() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::default();
    cfg.spool.dir = dir.path().join("spool");
    cfg.scanner.enabled = false;
    let spool = Spool::open(&cfg.spool.dir).await.unwrap();
    let auth = AuthChecker::offline("gateway.test").unwrap();
    seed_txt(auth.cache(), "example.test", "v=spf1 ip4:203.0.113.8 -all").unwrap();
    seed_txt(
        auth.cache(),
        "_dmarc.example.test",
        "v=DMARC1; p=none; rua=mailto:agg@example.test,mailto:other@victim.test",
    )
    .unwrap();
    let store = DmarcEventStore::open(&dir.path().join("dmarc.sqlite")).unwrap();
    let mut pipeline = Pipeline::new(Arc::new(cfg), auth).with_dmarc_events(store.clone());
    let inbound = envelope("01ARZ3NDEKTSV4RRFFQ69G5FAV", Direction::Inbound);
    pipeline.evaluate(&inbound, &message(), None).await;
    // Our own outbound mail is not reported back to its sender.
    let outbound = envelope("01ARZ3NDEKTSV4RRFFQ69G5FAW", Direction::Outbound);
    pipeline.evaluate(&outbound, &message(), None).await;

    let settings = DmarcReportConfig {
        enabled: true,
        email: "dmarc-reports@gateway.test".into(),
        ..DmarcReportConfig::default()
    };
    let same_day = OffsetDateTime::from_unix_timestamp(RECEIVED + 60).unwrap();
    assert_eq!(
        send_dmarc_reports(&spool, &pipeline.auth, &store, &settings, same_day)
            .await
            .unwrap(),
        0
    );
    let next_day = OffsetDateTime::from_unix_timestamp(RECEIVED + 86_400).unwrap();
    assert_eq!(
        send_dmarc_reports(&spool, &pipeline.auth, &store, &settings, next_day)
            .await
            .unwrap(),
        1
    );
    let queued = spool.list(SpoolState::Incoming).await.unwrap();
    assert_eq!(queued.len(), 1);
    let env = &queued[0];
    assert_eq!(env.rcpt_to, vec!["agg@example.test".to_string()]);
    assert_eq!(env.mail_from, "dmarc-reports@gateway.test");
    assert_eq!(env.direction, Direction::Outbound);
    assert!(ready_to_deliver(env));
    let body = String::from_utf8(spool.read_body(&env.id).await.unwrap()).unwrap();
    assert!(body.contains("application/gzip"), "{body}");
    assert!(!body.contains("victim.test"), "{body}");

    // The day is finished: nothing is sent twice.
    assert_eq!(
        send_dmarc_reports(&spool, &pipeline.auth, &store, &settings, next_day)
            .await
            .unwrap(),
        0
    );
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
        header: String::new(),
    });
    let txt = HashMap::from([(
        "default._bimi.example.test".to_string(),
        vec![
            "v=BIMI1; l=https://example.test/logo.svg; a=https://example.test/vmc.pem".to_string(),
        ],
    )]);
    annotate_bimi(&txt, &quarantine, &report, &message()).await;
    let json = quarantine.bimi(id).unwrap().unwrap();
    assert!(json.contains("https://example.test/logo.svg"), "{json}");
    assert!(json.contains("\"vmc\":\"unverified\""), "{json}");
}
