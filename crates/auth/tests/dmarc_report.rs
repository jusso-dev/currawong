use currawong_auth::{
    dmarc_report::{build_report, render_report, valid_address, DAY_SECS, GRACE_SECS},
    ed25519_key, seed_txt, seed_txt_error, sign_message, AuthChecker, DmarcEvent, DmarcEventStore,
};
use currawong_core::{config::DmarcReportConfig, Direction, MessageId};
use currawong_spool::{Envelope, SpoolState};
use mail_auth::{
    dmarc::URI,
    report::{ActionDisposition, DKIMAuthResult, DmarcResult, PolicyPublished, Record},
};
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
const DAY: u64 = RECEIVED as u64 / DAY_SECS;
const NEXT_DAY: u64 = (DAY + 1) * DAY_SECS + GRACE_SECS;

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

fn envelope(id: &str, from: &str) -> Envelope {
    Envelope {
        id: MessageId(id.into()),
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

fn uri(address: impl Into<String>, max_size: usize) -> URI {
    URI {
        uri: address.into(),
        max_size,
    }
}

fn local() -> Vec<String> {
    vec!["gateway.test".into()]
}

/// Validate with libxml2. Fails, rather than skips, when xmllint is missing,
/// so a green run always means the schema check happened.
fn assert_valid_xml(xml: &str) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("report.xml");
    std::fs::write(&path, xml).unwrap();
    let xsd = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/dmarc/rua.xsd");
    let output = Command::new("xmllint")
        .arg("--noout")
        .arg("--schema")
        .arg(xsd)
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

fn checker_with_records(dmarc: &str) -> (AuthChecker, Vec<u8>) {
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

fn store_with(cfg: &DmarcReportConfig) -> (tempfile::TempDir, DmarcEventStore) {
    let dir = tempfile::tempdir().unwrap();
    let store = DmarcEventStore::open_at(&dir.path().join("dmarc.sqlite"), cfg).unwrap();
    (dir, store)
}

fn store() -> (tempfile::TempDir, DmarcEventStore) {
    store_with(&settings())
}

/// A hand-built event for `domain`, `n` distinguishing the row.
fn event(id: &str, domain: &str, n: u8, received_at: u64) -> DmarcEvent {
    DmarcEvent {
        message_id: id.into(),
        tenant_id: None,
        policy_domain: domain.into(),
        received_at,
        policy: PolicyPublished {
            domain: domain.into(),
            ..PolicyPublished::default()
        },
        rua: vec![uri(format!("agg@{domain}"), 0)],
        record: Record::new()
            .with_source_ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, n)))
            .with_count(1)
            .with_envelope_from(domain)
            .with_header_from(domain)
            .with_action_disposition(ActionDisposition::None)
            .with_dmarc_dkim_result(DmarcResult::Fail)
            .with_dmarc_spf_result(DmarcResult::Pass),
    }
}

async fn evaluated(checker: &AuthChecker, raw: &[u8], env: &Envelope) -> DmarcEvent {
    checker
        .evaluate(raw, env, true)
        .await
        .dmarc_event
        .expect("dmarc event")
}

#[tokio::test]
async fn dmarc_report_xml_validates_against_rua_xsd() {
    let (checker, signed) = checker_with_records("v=DMARC1; p=reject; rua=mailto:agg@example.test");
    let (_dir, store) = store();
    let pass = evaluated(
        &checker,
        &signed,
        &envelope("01ARZ3NDEKTSV4RRFFQ69G5FA1", "user@example.test"),
    )
    .await;
    let pass2 = evaluated(
        &checker,
        &signed,
        &envelope("01ARZ3NDEKTSV4RRFFQ69G5FA2", "user@example.test"),
    )
    .await;
    let fail = evaluated(
        &checker,
        &message("user@example.test"),
        &envelope("01ARZ3NDEKTSV4RRFFQ69G5FA3", "spoof@attacker.test"),
    )
    .await;
    for event in [&pass, &fail, &pass2] {
        assert!(store.record(event).unwrap());
    }
    let data = store.load(DAY, "example.test").unwrap().unwrap();
    // Two identical passes collapse into one row, largest first.
    let counts: Vec<u32> = data.rows.iter().map(|(_, count)| *count).collect();
    assert_eq!(counts, vec![2, 1]);
    assert_valid_xml(&build_report(&settings(), &data).to_xml());

    let to = checker
        .authorised_rua("example.test", &data.rua, &local())
        .await
        .unwrap();
    let report = render_report(&settings(), &data, &to).unwrap().unwrap();
    assert_eq!(report.to, vec!["agg@example.test".to_string()]);
    let parsed = mail_parser::MessageParser::default()
        .parse(&report.message)
        .unwrap();
    assert!(parsed
        .subject()
        .unwrap_or_default()
        .starts_with("Report Domain: example.test Submitter: gateway.test"));
    let (name, xml) = attachment_xml(&report.message);
    let begin = DAY * DAY_SECS;
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
}

#[tokio::test]
async fn dmarc_report_hostile_characters_still_validate() {
    let (_dir, store) = store();
    let mut hostile = event(
        "01ARZ3NDEKTSV4RRFFQ69G5FA1",
        "example.test",
        1,
        RECEIVED as u64,
    );
    hostile.record = hostile
        .record
        .with_envelope_from("evil<&\u{1}\u{0}.test")
        .with_header_from("a\u{1b}b\"'.test")
        .with_dkim_auth_result(
            DKIMAuthResult::new()
                .with_domain("d<&>\u{7}.test")
                .with_selector("s<&\u{1}")
                .with_human_result("bad \u{0} signature \u{fffe}"),
        );
    assert!(store.record(&hostile).unwrap());
    let data = store.load(DAY, "example.test").unwrap().unwrap();
    let xml = build_report(&settings(), &data).to_xml();
    assert!(!xml.contains('\u{1}') && !xml.contains('\u{0}'), "{xml:?}");
    assert_valid_xml(&xml);
}

#[tokio::test]
async fn dmarc_report_unauthorised_cross_domain_rua_is_not_sent() {
    let (checker, signed) = checker_with_records(
        "v=DMARC1; p=none; rua=mailto:agg@example.test,mailto:collector@victim.test",
    );
    let event = evaluated(
        &checker,
        &signed,
        &envelope("01ARZ3NDEKTSV4RRFFQ69G5FA1", "user@example.test"),
    )
    .await;
    let to = checker
        .authorised_rua("example.test", &event.rua, &local())
        .await
        .unwrap();
    let to: Vec<&str> = to.iter().map(URI::uri).collect();
    assert_eq!(to, vec!["agg@example.test"]);

    // Consent from the destination makes it eligible.
    seed_txt(
        checker.cache(),
        "example.test._report._dmarc.victim.test",
        "v=DMARC1",
    )
    .unwrap();
    let to = checker
        .authorised_rua("example.test", &event.rua, &local())
        .await
        .unwrap();
    assert_eq!(to.len(), 2);
}

#[tokio::test]
async fn dmarc_report_dns_error_is_retry_not_refusal() {
    let (checker, _) = checker_with_records("v=DMARC1; p=none");
    seed_txt_error(checker.cache(), "example.test._report._dmarc.victim.test");
    let rua = vec![uri("collector@victim.test", 0)];
    assert_eq!(
        checker.authorised_rua("example.test", &rua, &local()).await,
        None
    );
}

#[tokio::test]
async fn dmarc_report_internal_ip_literal_and_local_rua_refused() {
    let (checker, _) = checker_with_records("v=DMARC1; p=none");
    // Consent is published for every host, so only the address checks refuse.
    for host in [
        "[10.0.0.1]",
        "10.0.0.1",
        "127.0.0.1",
        "gateway.test",
        "mx.gateway.test",
    ] {
        seed_txt(
            checker.cache(),
            &format!("example.test._report._dmarc.{host}"),
            "v=DMARC1",
        )
        .unwrap();
    }
    let rua = vec![
        uri("agg@[10.0.0.1]", 0),
        uri("agg@10.0.0.1", 0),
        uri("agg@127.0.0.1", 0),
        uri("postmaster@gateway.test", 0),
        uri("postmaster@mx.gateway.test", 0),
        uri("agg>@example.test", 0),
        uri("agg>\r\nRCPT TO:<x@example.test", 0),
        uri("agg@example.test", 0),
    ];
    let to = checker
        .authorised_rua("example.test", &rua, &local())
        .await
        .unwrap();
    let to: Vec<&str> = to.iter().map(URI::uri).collect();
    assert_eq!(to, vec!["agg@example.test"]);
}

#[test]
fn dmarc_report_address_validation() {
    assert!(valid_address("agg+dmarc@reports.example.test"));
    for bad in [
        "agg@localhost",
        "agg@[::1]",
        "a b@example.test",
        "agg@exa_mple.test",
        "<agg@example.test>",
        "agg@-example.test",
        "agg\u{0}@example.test",
        "@example.test",
        "agg@",
    ] {
        assert!(!valid_address(bad), "{bad:?}");
    }
}

#[tokio::test]
async fn dmarc_report_caps_rua_domains_rows_and_bytes() {
    let cfg = DmarcReportConfig {
        max_rua_per_record: 2,
        max_domains_per_day: 2,
        max_rows_per_report: 1,
        ..settings()
    };
    let (_dir, store) = store_with(&cfg);
    let mut many = event("01ARZ3NDEKTSV4RRFFQ69G5FA1", "a.test", 1, RECEIVED as u64);
    many.rua = (0..10).map(|n| uri(format!("agg{n}@a.test"), 0)).collect();
    assert!(store.record(&many).unwrap());
    assert!(store
        .record(&event(
            "01ARZ3NDEKTSV4RRFFQ69G5FA2",
            "a.test",
            2,
            RECEIVED as u64
        ))
        .unwrap());
    assert!(store
        .record(&event(
            "01ARZ3NDEKTSV4RRFFQ69G5FA3",
            "b.test",
            1,
            RECEIVED as u64
        ))
        .unwrap());
    // A third policy domain on the same day is over the cap.
    assert!(!store
        .record(&event(
            "01ARZ3NDEKTSV4RRFFQ69G5FA4",
            "c.test",
            1,
            RECEIVED as u64
        ))
        .unwrap());
    assert_eq!(store.domains(DAY).unwrap(), vec!["a.test", "b.test"]);

    let data = store.load(DAY, "a.test").unwrap().unwrap();
    assert_eq!(data.rows.len(), 1);
    assert_eq!((data.omitted_rows, data.omitted_messages), (1, 1));
    let xml = build_report(&cfg, &data).to_xml();
    assert!(xml.contains("1 rows covering 1 messages omitted"), "{xml}");
    assert_valid_xml(&xml);

    // Only the first two rua addresses of a record are kept.
    let (_other, alone) = store_with(&cfg);
    assert!(alone.record(&many).unwrap());
    let kept: Vec<String> = alone
        .load(DAY, "a.test")
        .unwrap()
        .unwrap()
        .rua
        .iter()
        .map(|uri| uri.uri().to_string())
        .collect();
    assert_eq!(kept, vec!["agg0@a.test", "agg1@a.test"]);

    let tiny = DmarcReportConfig {
        max_report_bytes: 512,
        ..cfg.clone()
    };
    assert!(render_report(&tiny, &data, &[uri("agg@a.test", 0)])
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn dmarc_report_size_limited_destination_leaves_to_header() {
    let (_dir, store) = store();
    store
        .record(&event(
            "01ARZ3NDEKTSV4RRFFQ69G5FA1",
            "example.test",
            1,
            RECEIVED as u64,
        ))
        .unwrap();
    let data = store.load(DAY, "example.test").unwrap().unwrap();
    let to = [uri("small@example.test", 100), uri("agg@example.test", 0)];
    let report = render_report(&settings(), &data, &to).unwrap().unwrap();
    assert_eq!(report.to, vec!["agg@example.test".to_string()]);
    let text = String::from_utf8_lossy(&report.message);
    assert!(!text.contains("small@example.test"), "{text}");
}

#[tokio::test]
async fn dmarc_report_same_message_is_counted_once() {
    let (_dir, store) = store();
    let first = event(
        "01ARZ3NDEKTSV4RRFFQ69G5FA1",
        "example.test",
        1,
        RECEIVED as u64,
    );
    assert!(store.record(&first).unwrap());
    // A deferred message classified again.
    assert!(!store.record(&first).unwrap());
    let data = store.load(DAY, "example.test").unwrap().unwrap();
    assert_eq!(data.rows[0].1, 1);
}

#[tokio::test]
async fn dmarc_report_grace_period_and_late_rows() {
    let (_dir, store) = store();
    let late_evening = (DAY + 1) * DAY_SECS - 60;
    store
        .record(&event(
            "01ARZ3NDEKTSV4RRFFQ69G5FA1",
            "example.test",
            1,
            late_evening,
        ))
        .unwrap();
    let after_midnight = (DAY + 1) * DAY_SECS + 600;
    assert!(store.pending_days(after_midnight).unwrap().is_empty());
    assert_eq!(store.pending_days(NEXT_DAY).unwrap(), vec![DAY]);
    store.finish(DAY, "example.test").unwrap();

    // Classified after the day was reported: dropped, not a second report.
    assert!(!store
        .record(&event(
            "01ARZ3NDEKTSV4RRFFQ69G5FA2",
            "example.test",
            2,
            late_evening
        ))
        .unwrap());
    assert!(store.pending_days(NEXT_DAY).unwrap().is_empty());
}

#[tokio::test]
async fn dmarc_report_corrupt_row_is_skipped() {
    let (dir, store) = store();
    store
        .record(&event(
            "01ARZ3NDEKTSV4RRFFQ69G5FA1",
            "example.test",
            1,
            RECEIVED as u64,
        ))
        .unwrap();
    let conn = rusqlite::Connection::open(dir.path().join("dmarc.sqlite")).unwrap();
    conn.execute(
        "INSERT INTO dmarc_events (message_id, policy_domain, day, received_at, policy_json, rua_json, record_json)
         VALUES ('bad', 'example.test', ?1, ?2, '{}', '[]', 'not json')",
        rusqlite::params![DAY as i64, RECEIVED],
    )
    .unwrap();
    let data = store.load(DAY, "example.test").unwrap().unwrap();
    assert_eq!(data.rows.len(), 1);
    assert_valid_xml(&build_report(&settings(), &data).to_xml());
}

#[tokio::test]
async fn dmarc_report_spool_id_is_stable() {
    let (_dir, store) = store();
    let first = store
        .spool_id(DAY, "example.test", "01ARZ3NDEKTSV4RRFFQ69G5FA1")
        .unwrap();
    let again = store
        .spool_id(DAY, "example.test", "01ARZ3NDEKTSV4RRFFQ69G5FA2")
        .unwrap();
    assert_eq!(first, again);
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
    let event = evaluated(
        &checker,
        &message("user@sub.example.test"),
        &envelope("01ARZ3NDEKTSV4RRFFQ69G5FA1", "user@sub.example.test"),
    )
    .await;
    assert_eq!(event.policy_domain, "example.test");
    assert_eq!(event.policy.domain, "example.test");
}

#[tokio::test]
async fn dmarc_report_event_only_when_asked_and_published() {
    let (checker, signed) = checker_with_records("v=DMARC1; p=none; rua=mailto:agg@example.test");
    let env = envelope("01ARZ3NDEKTSV4RRFFQ69G5FA1", "user@example.test");
    assert!(checker
        .evaluate(&signed, &env, false)
        .await
        .dmarc_event
        .is_none());
    let checker = AuthChecker::offline("gateway.test").unwrap();
    seed_txt(checker.cache(), "example.test", "v=spf1 +all").unwrap();
    assert!(checker
        .evaluate(&message("user@example.test"), &env, true)
        .await
        .dmarc_event
        .is_none());
}

#[tokio::test]
async fn dmarc_report_envelope_from_never_leaks_a_local_part() {
    let (checker, signed) = checker_with_records("v=DMARC1; p=none; rua=mailto:agg@example.test");
    let event = evaluated(
        &checker,
        &signed,
        &envelope("01ARZ3NDEKTSV4RRFFQ69G5FA1", "bare-local-part"),
    )
    .await;
    assert_eq!(event.record.identifiers.envelope_from, "");
    let event = evaluated(
        &checker,
        &signed,
        &envelope("01ARZ3NDEKTSV4RRFFQ69G5FA2", "user@example.test"),
    )
    .await;
    assert_eq!(event.record.identifiers.envelope_from, "example.test");
}
