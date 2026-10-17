use currawong_auth::{
    dmarc_report::{build_report, DAY_SECS},
    ed25519_key, seed_txt, sign_message, AuthChecker, DmarcEventStore,
};
use currawong_core::{config::DmarcReportConfig, Direction, MessageId};
use currawong_spool::{Envelope, SpoolState};
use mail_parser::MimeHeaders;
use std::{
    io::Read,
    net::{IpAddr, Ipv4Addr},
    path::Path,
    process::Command,
};
use time::OffsetDateTime;

// Wed, 14 Oct 2026 01:00:00 UTC.
const RECEIVED: i64 = 1_791_939_600;

fn message(from: &str) -> Vec<u8> {
    format!(
        "From: {from}\r\n\
To: dest@gateway.test\r\n\
Subject: hello\r\n\
Date: Wed, 14 Oct 2026 01:00:00 +0000\r\n\
Message-ID: <1@example.test>\r\n\
\r\n\
hello\r\n"
    )
    .into_bytes()
}

fn envelope(from: &str) -> Envelope {
    Envelope {
        id: MessageId("01ARZ3NDEKTSV4RRFFQ69G5FAV".into()),
        tenant_id: Some("local".into()),
        mail_from: from.into(),
        rcpt_to: vec!["dest@gateway.test".into()],
        received_at: OffsetDateTime::from_unix_timestamp(RECEIVED).unwrap(),
        remote_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)),
        helo: "client.example.test".into(),
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

fn settings() -> DmarcReportConfig {
    DmarcReportConfig {
        enabled: true,
        org_name: "Currawong Test".into(),
        email: "dmarc-reports@gateway.test".into(),
        ..DmarcReportConfig::default()
    }
}

fn rua_xsd() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/dmarc/rua.xsd")
}

/// Validate with libxml2. Fails, rather than skips, when xmllint is missing,
/// so a green run always means the schema check happened.
fn assert_valid_xml(xml: &str) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("report.xml");
    std::fs::write(&path, xml).unwrap();
    let output = Command::new("xmllint")
        .arg("--noout")
        .arg("--schema")
        .arg(rua_xsd())
        .arg(&path)
        .output()
        .expect("xmllint is required for the RUA schema check (libxml2-utils)");
    assert!(
        output.status.success(),
        "{}\n{xml}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Pull the gzip attachment out of a rendered report and inflate it.
fn attachment_xml(message: &[u8]) -> (String, String) {
    let parsed = mail_parser::MessageParser::default()
        .parse(message)
        .unwrap();
    let part = parsed.attachments().next().expect("report attachment");
    let name = part.attachment_name().unwrap_or_default().to_string();
    let mut xml = String::new();
    flate2::read::GzDecoder::new(part.contents())
        .read_to_string(&mut xml)
        .unwrap();
    (name, xml)
}

async fn checker_with_records(dmarc: &str) -> (AuthChecker, Vec<u8>) {
    let key = ed25519_key().unwrap();
    let signed = sign_message(&message("user@example.test"), &key).unwrap();
    let checker = AuthChecker::offline("gateway.test").unwrap();
    seed_txt(
        checker.cache(),
        "ed._domainkey.example.test",
        &key.public_txt,
    )
    .unwrap();
    seed_txt(
        checker.cache(),
        "example.test",
        "v=spf1 ip4:203.0.113.5 -all",
    )
    .unwrap();
    seed_txt(checker.cache(), "attacker.test", "v=spf1 -all").unwrap();
    seed_txt(checker.cache(), "_dmarc.example.test", dmarc).unwrap();
    (checker, signed)
}

fn store() -> (tempfile::TempDir, DmarcEventStore) {
    let dir = tempfile::tempdir().unwrap();
    let store = DmarcEventStore::open(&dir.path().join("dmarc.sqlite")).unwrap();
    (dir, store)
}

#[tokio::test]
async fn dmarc_report_xml_validates_against_rua_xsd() {
    let (checker, signed) =
        checker_with_records("v=DMARC1; p=reject; rua=mailto:agg@example.test").await;
    let (_dir, store) = store();
    let pass = checker
        .evaluate(&signed, &envelope("user@example.test"))
        .await;
    let fail = checker
        .evaluate(
            &message("user@example.test"),
            &envelope("spoof@attacker.test"),
        )
        .await;
    for event in [&pass, &fail, &pass] {
        store.record(event.dmarc_event.as_ref().unwrap()).unwrap();
    }
    let day = RECEIVED as u64 / DAY_SECS;
    assert!(store.pending_days(RECEIVED as u64).unwrap().is_empty());
    assert_eq!(
        store.pending_days(RECEIVED as u64 + DAY_SECS).unwrap(),
        vec![day]
    );

    let days = store.day(day).unwrap();
    assert_eq!(days.len(), 1);
    assert_eq!(days[0].domain, "example.test");
    // Two identical passes collapse into one row.
    let counts: Vec<u32> = days[0].rows.iter().map(|(_, count)| *count).collect();
    assert_eq!(counts, vec![2, 1]);
    assert_valid_xml(&build_report(&settings(), day, &days[0]).to_xml());

    // The bytes that would be sent: gzip attachment named per RFC 9990.
    let reports = checker
        .dmarc_reports(&store, &settings(), day)
        .await
        .unwrap();
    assert_eq!(reports.len(), 1);
    assert_eq!(reports[0].to, vec!["agg@example.test".to_string()]);
    let text = String::from_utf8_lossy(&reports[0].message);
    assert!(text.contains("application/gzip"), "{text}");
    let parsed = mail_parser::MessageParser::default()
        .parse(&reports[0].message)
        .unwrap();
    assert!(
        parsed
            .subject()
            .unwrap_or_default()
            .starts_with("Report Domain: example.test Submitter: gateway.test"),
        "{text}"
    );
    let (name, xml) = attachment_xml(&reports[0].message);
    let begin = day * DAY_SECS;
    assert_eq!(
        name,
        format!(
            "gateway.test!example.test!{begin}!{}.xml.gz",
            begin + DAY_SECS - 1
        )
    );
    assert!(xml.contains("<source_ip>203.0.113.5</source_ip>"), "{xml}");
    assert!(xml.contains("<disposition>reject</disposition>"), "{xml}");
    assert!(!xml.contains("ruf"), "{xml}");
    assert_valid_xml(&xml);

    store.finish_day(day).unwrap();
    assert!(store
        .pending_days(RECEIVED as u64 + DAY_SECS)
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn dmarc_report_unauthorised_cross_domain_rua_is_not_sent() {
    let (checker, signed) = checker_with_records(
        "v=DMARC1; p=none; rua=mailto:agg@example.test,mailto:collector@victim.test",
    )
    .await;
    let (_dir, store) = store();
    let event = checker
        .evaluate(&signed, &envelope("user@example.test"))
        .await
        .dmarc_event
        .unwrap();
    store.record(&event).unwrap();
    let day = RECEIVED as u64 / DAY_SECS;
    let reports = checker
        .dmarc_reports(&store, &settings(), day)
        .await
        .unwrap();
    assert_eq!(reports.len(), 1);
    assert_eq!(reports[0].to, vec!["agg@example.test".to_string()]);
    assert!(!String::from_utf8_lossy(&reports[0].message).contains("victim.test"));
}

#[tokio::test]
async fn dmarc_report_only_external_rua_without_authorisation_sends_nothing() {
    let (checker, signed) =
        checker_with_records("v=DMARC1; p=none; rua=mailto:collector@victim.test").await;
    let (_dir, store) = store();
    let event = checker
        .evaluate(&signed, &envelope("user@example.test"))
        .await
        .dmarc_event
        .unwrap();
    store.record(&event).unwrap();
    let day = RECEIVED as u64 / DAY_SECS;
    assert!(checker
        .dmarc_reports(&store, &settings(), day)
        .await
        .unwrap()
        .is_empty());

    // Once the destination publishes its consent record the report goes out.
    seed_txt(
        checker.cache(),
        "example.test._report._dmarc.victim.test",
        "v=DMARC1",
    )
    .unwrap();
    let reports = checker
        .dmarc_reports(&store, &settings(), day)
        .await
        .unwrap();
    assert_eq!(reports[0].to, vec!["collector@victim.test".to_string()]);
}

#[tokio::test]
async fn dmarc_report_policy_domain_follows_tree_walk() {
    let checker = AuthChecker::offline("gateway.test").unwrap();
    seed_txt(
        checker.cache(),
        "sub.example.test",
        "v=spf1 ip4:203.0.113.5 -all",
    )
    .unwrap();
    seed_txt(
        checker.cache(),
        "_dmarc.example.test",
        "v=DMARC1; p=quarantine; rua=mailto:agg@example.test",
    )
    .unwrap();
    let event = checker
        .evaluate(
            &message("user@sub.example.test"),
            &envelope("user@sub.example.test"),
        )
        .await
        .dmarc_event
        .unwrap();
    assert_eq!(event.policy_domain, "example.test");
    assert_eq!(event.policy.domain, "example.test");
    let (_dir, store) = store();
    store.record(&event).unwrap();
    let reports = checker
        .dmarc_reports(&store, &settings(), RECEIVED as u64 / DAY_SECS)
        .await
        .unwrap();
    assert_eq!(reports[0].domain, "example.test");
    assert_eq!(reports[0].to, vec!["agg@example.test".to_string()]);
}

#[tokio::test]
async fn dmarc_report_no_event_without_a_dmarc_record() {
    let checker = AuthChecker::offline("gateway.test").unwrap();
    seed_txt(checker.cache(), "example.test", "v=spf1 +all").unwrap();
    let evaluation = checker
        .evaluate(
            &message("user@example.test"),
            &envelope("user@example.test"),
        )
        .await;
    assert!(evaluation.dmarc_event.is_none());
}
