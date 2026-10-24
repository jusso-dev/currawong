//! Threat-intel feeds end to end: a stored indicator quarantines mail
//! through the parser worker and the default pack, blocks clicks, and DQS
//! answers come through the gateway resolver. No network.
use currawong_auth::AuthChecker;
use currawong_core::{config::Config, Direction};
use currawong_intel::{Indicator, Kind};
use currawong_policy::Action;
use currawong_scan::urls::{LocalBlocklist, Reputation, UrlReputation};
use currawong_spool::{Envelope, SpoolState};
use currawongd::{
    intel::{ChainedReputation, DqsDns, IntelReputation},
    Pipeline,
};
use sha2::{Digest, Sha256};
use std::{io::Cursor, sync::Arc};
use time::OffsetDateTime;

fn envelope() -> Envelope {
    Envelope {
        id: currawong_core::MessageId("01ARZ3NDEKTSV4RRFFQ69G5FAV".into()),
        tenant_id: None,
        authenticated_as: None,
        mail_from: "a@example.test".into(),
        rcpt_to: vec!["dest@example.test".into()],
        received_at: OffsetDateTime::now_utc(),
        remote_ip: "203.0.113.8".parse().unwrap(),
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
        tls: Default::default(),
        pipeline: "pending".into(),
    }
}

fn worker_bin() -> std::path::PathBuf {
    let exe = std::env::current_exe().unwrap();
    let candidate = exe
        .parent()
        .and_then(|deps| deps.parent())
        .map(|dir| dir.join("currawong-parser-worker"))
        .unwrap();
    assert!(
        candidate.is_file(),
        "parser worker binary: run cargo build -p currawong-parser-worker"
    );
    candidate
}

fn intel_config(dir: &std::path::Path) -> Config {
    let mut cfg = Config::default();
    cfg.spool.dir = dir.join("spool");
    cfg.scanner.clamd.address.clear();
    cfg.scanner.clamd.required = false;
    cfg.scanner.worker_binary = Some(worker_bin());
    cfg.intel.enabled = true;
    cfg.intel.database = dir.join("intel.sqlite");
    cfg
}

fn indicator(kind: Kind, value: &str, threat: &str) -> Indicator {
    Indicator {
        kind,
        value: value.into(),
        threat: threat.into(),
        first_seen: None,
        expires: None,
    }
}

/// Store indicators as a feed sync would, before the pipeline opens the store.
fn seed(cfg: &Config, source: &str, indicators: &[Indicator]) {
    let store = currawongd::intel::open_store(cfg).unwrap();
    store
        .replace_source(source, indicators, currawong_intel::now(), None, None)
        .unwrap();
}

fn attachment(name: &str, content_type: &str, bytes: &[u8]) -> String {
    let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, bytes);
    let lines: Vec<&str> = encoded
        .as_bytes()
        .chunks(76)
        .map(|line| std::str::from_utf8(line).unwrap())
        .collect();
    format!(
        "--b\r\nContent-Type: {content_type}; name=\"{name}\"\r\nContent-Disposition: attachment; filename=\"{name}\"\r\nContent-Transfer-Encoding: base64\r\n\r\n{}\r\n",
        lines.join("\r\n")
    )
}

fn message(body: &str, attachments: &[String]) -> Vec<u8> {
    format!(
        "From: a@example.test\r\nTo: dest@example.test\r\nSubject: invoice\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"b\"\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\n{body}\r\n{}--b--\r\n",
        attachments.concat()
    )
    .into_bytes()
}

fn qr_png(text: &str) -> Vec<u8> {
    let code = qrcode::QrCode::new(text.as_bytes()).unwrap();
    let mut png = Cursor::new(Vec::new());
    code.render::<image::Luma<u8>>()
        .min_dimensions(240, 240)
        .build()
        .write_to(&mut png, image::ImageFormat::Png)
        .unwrap();
    png.into_inner()
}

/// The quarantine queue the decision chose, if any.
fn queue(decision: &currawong_policy::MessageDecision) -> Option<String> {
    decision.decisions[0]
        .actions
        .iter()
        .find_map(|action| match action {
            Action::Quarantine(queue) => Some(queue.clone()),
            _ => None,
        })
}

#[tokio::test]
async fn intel_part_hash_and_links_in_a_feed_quarantine_the_message() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = intel_config(dir.path());
    // A benign file: what matters is that its hash is on the feed.
    let payload = b"benign test attachment listed by a test feed\n";
    let hash = hex::encode(Sha256::digest(payload));
    seed(
        &cfg,
        "malwarebazaar",
        &[indicator(Kind::Sha256, &hash, "malware")],
    );
    seed(
        &cfg,
        "openphish",
        &[
            indicator(Kind::Url, "https://qr-phish.example/login", "phishing"),
            indicator(Kind::Domain, "text-phish.example", "phishing"),
        ],
    );
    let pipeline = Pipeline::new(Arc::new(cfg), AuthChecker::offline("gw.test").unwrap());
    assert!(pipeline.intel.is_some(), "{:?}", pipeline.intel_error);

    // The hash of an attachment: malware queue.
    let raw = message(
        "see attached",
        &[attachment("notes.txt", "text/plain", payload)],
    );
    let (report, decision) = pipeline.assess(&envelope(), &raw, None).await;
    assert_eq!(report.intel.len(), 1, "{report:?}");
    assert_eq!(report.intel[0].kind, "sha256");
    assert_eq!(report.intel[0].source, "malwarebazaar");
    assert!(report
        .notes
        .iter()
        .any(|n| n.contains("listed by malwarebazaar")));
    assert_eq!(queue(&decision).as_deref(), Some("malware"), "{decision:?}");

    // The same file inside a zip: archive members are hashed too.
    let mut zipped = zip::ZipWriter::new(Cursor::new(Vec::new()));
    zipped
        .start_file("inner/notes.txt", zip::write::SimpleFileOptions::default())
        .unwrap();
    std::io::Write::write_all(&mut zipped, payload).unwrap();
    let zipped = zipped.finish().unwrap().into_inner();
    let raw = message(
        "see attached",
        &[attachment("bundle.zip", "application/zip", &zipped)],
    );
    let (report, decision) = pipeline.assess(&envelope(), &raw, None).await;
    assert!(
        report.intel.iter().any(|hit| hit.value == hash),
        "{report:?}"
    );
    assert_eq!(queue(&decision).as_deref(), Some("malware"), "{decision:?}");

    // A link in a QR code, listed as a URL: phishing queue.
    let raw = message(
        "scan the code",
        &[attachment(
            "code.png",
            "image/png",
            &qr_png("https://QR-PHISH.example:443/login#ref"),
        )],
    );
    let (report, decision) = pipeline.assess(&envelope(), &raw, None).await;
    assert!(
        report
            .intel
            .iter()
            .any(|hit| hit.kind == "url" && hit.value == "https://qr-phish.example/login"),
        "{report:?}"
    );
    assert_eq!(
        queue(&decision).as_deref(),
        Some("phishing"),
        "{decision:?}"
    );

    // A text link on a subdomain of a listed domain: phishing queue.
    let raw = message("log in at https://www.text-phish.example/account now", &[]);
    let (report, decision) = pipeline.assess(&envelope(), &raw, None).await;
    assert!(
        report
            .intel
            .iter()
            .any(|hit| hit.kind == "domain" && hit.value == "text-phish.example"),
        "{report:?}"
    );
    assert_eq!(
        queue(&decision).as_deref(),
        Some("phishing"),
        "{decision:?}"
    );

    // Nothing listed: delivered.
    let raw = message(
        "see https://fine.example/ and attached",
        &[attachment("a.txt", "text/plain", b"other")],
    );
    let (report, decision) = pipeline.assess(&envelope(), &raw, None).await;
    assert!(report.intel.is_empty(), "{report:?}");
    assert_eq!(queue(&decision), None, "{decision:?}");
}

#[tokio::test]
async fn intel_caps_links_checked_per_message() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = intel_config(dir.path());
    cfg.intel.max_urls_per_message = 2;
    seed(
        &cfg,
        "list",
        &[indicator(Kind::Domain, "third.example", "phishing")],
    );
    let pipeline = Pipeline::new(Arc::new(cfg), AuthChecker::offline("gw.test").unwrap());
    let raw = message(
        "https://first.example/ https://second.example/ https://third.example/",
        &[],
    );
    let (report, _) = pipeline.assess(&envelope(), &raw, None).await;
    assert!(
        report
            .notes
            .iter()
            .any(|n| n.contains("1 of 3 links not checked")),
        "{:?}",
        report.notes
    );
}

#[tokio::test]
async fn intel_blocks_listed_links_at_click_time() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = intel_config(dir.path());
    seed(
        &cfg,
        "urlhaus",
        &[
            indicator(Kind::Url, "http://198.51.100.9/x.exe", "malware_download"),
            indicator(Kind::Domain, "evil.example", "phishing"),
        ],
    );
    let store = Arc::new(currawongd::intel::open_store(&cfg).unwrap());
    let intel = IntelReputation { store };
    assert!(matches!(
        intel.check("http://198.51.100.9:80/x.exe").await,
        Reputation::Blocked { reason } if reason.contains("urlhaus")
    ));
    assert!(matches!(
        intel.check("https://login.evil.example/").await,
        Reputation::Blocked { .. }
    ));
    assert_eq!(
        intel.check("https://fine.example/").await,
        Reputation::Clean
    );

    // Chained after the operator list: a block wins over a warning.
    let list = LocalBlocklist::from_entries("warn evil.example\nwarn odd.example\n");
    let chain = ChainedReputation(vec![Arc::new(list), Arc::new(intel)]);
    assert!(matches!(
        chain.check("https://evil.example/").await,
        Reputation::Blocked { .. }
    ));
    assert!(matches!(
        chain.check("https://odd.example/").await,
        Reputation::Warn { .. }
    ));
    assert_eq!(
        chain.check("https://fine.example/").await,
        Reputation::Clean
    );
}

#[tokio::test]
async fn intel_dqs_answers_come_through_the_gateway_resolver() {
    let mut dns = currawong_smtp::dns::MapDns::new();
    dns.ips.insert(
        "phish.example.testkey.dbl.dq.spamhaus.net".into(),
        vec!["127.0.1.4".parse().unwrap()],
    );
    dns.nxdomain
        .insert("clean.example.testkey.dbl.dq.spamhaus.net".into());
    let dqs =
        currawong_intel::Dqs::new("testkey", true, false, 10, Arc::new(DqsDns(Arc::new(dns))))
            .unwrap();
    let found = dqs
        .check(&["www.phish.example".into(), "clean.example".into()], &[])
        .await;
    assert_eq!(found.hits.len(), 1, "{found:?}");
    assert_eq!(found.hits[0].source, "spamhaus-dbl");
    assert!(found.notes.is_empty(), "{found:?}");
}

#[tokio::test]
async fn intel_lookup_command_reads_the_store() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = intel_config(dir.path());
    seed(
        &cfg,
        "threatfox",
        &[indicator(Kind::Domain, "c2.example", "botnet_cc")],
    );
    let lookup = |value: &str| currawongd::intel::IntelCommand::Lookup {
        value: value.into(),
    };
    let out = currawongd::intel::run(&cfg, lookup("api.c2.example"))
        .await
        .unwrap();
    assert_eq!(out, "domain c2.example threatfox botnet_cc\n");
    let out = currawongd::intel::run(&cfg, lookup("https://c2.example/gate.php"))
        .await
        .unwrap();
    assert_eq!(out, "domain c2.example threatfox botnet_cc\n");
    let out = currawongd::intel::run(&cfg, lookup(&"0".repeat(64)))
        .await
        .unwrap();
    assert_eq!(out, "not listed\n");
    let mut off = cfg.clone();
    off.intel.enabled = false;
    assert!(currawongd::intel::run(&off, lookup("x.example"))
        .await
        .is_err());
}

#[test]
fn intel_config_is_validated() {
    use currawong_core::config::{FeedFormat, IntelFeedConfig};
    let dir = tempfile::tempdir().unwrap();
    let feed = |name: &str, url: &str| IntelFeedConfig {
        name: name.into(),
        format: FeedFormat::Lines,
        url: url.into(),
        key_env: None,
        key_file: None,
        auth_header: None,
        refresh_secs: 3600,
        enabled: true,
        kind: None,
        threat: None,
    };
    let check = |feeds: Vec<IntelFeedConfig>| {
        let mut cfg = intel_config(dir.path());
        cfg.intel.feeds = feeds;
        cfg.validate().map_err(|err| err.to_string())
    };
    check(vec![feed("ok", "https://feeds.example/list.txt")]).unwrap();
    for (feeds, expected) in [
        (vec![feed("plain", "http://feeds.example/x")], "https URL"),
        (
            vec![feed("Bad Name", "https://feeds.example/x")],
            "lower case",
        ),
        (
            vec![feed("spamhaus-dbl", "https://feeds.example/x")],
            "reserved",
        ),
        (
            vec![
                feed("twice", "https://feeds.example/x"),
                feed("twice", "https://feeds.example/y"),
            ],
            "used twice",
        ),
        (
            vec![feed("keyed", "https://feeds.example/{key}/x")],
            "needs key_env or key_file",
        ),
    ] {
        let err = check(feeds).unwrap_err();
        assert!(err.contains(expected), "{err}");
    }
}

#[tokio::test]
async fn intel_checks_text_urls_with_scanner_disabled() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = intel_config(dir.path());
    cfg.scanner.enabled = false;
    seed(
        &cfg,
        "fixture",
        &[
            indicator(Kind::Url, "https://url.example/login", "phishing"),
            indicator(Kind::Domain, "domain.example", "phishing"),
        ],
    );
    let pipeline = Pipeline::new(Arc::new(cfg), AuthChecker::offline("gw.test").unwrap());
    for url in [
        "https://url.example/login",
        "https://sub.domain.example/path",
    ] {
        let raw = message(&format!("See {url}"), &[]);
        let (report, decision) = pipeline.assess(&envelope(), &raw, None).await;
        assert!(report.parts.is_empty());
        assert!(!report.intel.is_empty(), "{report:?}");
        assert_eq!(queue(&decision).as_deref(), Some("phishing"));
    }
    // MIME transfer encoding must be decoded before looking for links.
    let raw = b"From: a@example.test\r\nTo: dest@example.test\r\nContent-Type: text/plain\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nSee https://url.example/lo=\r\ngin";
    let (report, decision) = pipeline.assess(&envelope(), raw, None).await;
    assert!(!report.intel.is_empty(), "{report:?}");
    assert_eq!(queue(&decision).as_deref(), Some("phishing"));
    let raw = b"From: a@example.test\r\nTo: dest@example.test\r\nContent-Type: text/html\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n<a href=3D\"https://url.example/lo=\r\ngin\">Review</a>";
    let (report, decision) = pipeline.assess(&envelope(), raw, None).await;
    assert!(!report.intel.is_empty(), "{report:?}");
    assert_eq!(queue(&decision).as_deref(), Some("phishing"));
}
