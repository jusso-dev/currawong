//! Feed sync against an in-process HTTPS server with a self-signed
//! `localhost` certificate. No network.
use currawong_core::config::{FeedFormat, IntelConfig, IntelFeedConfig};
use currawong_intel::{Kind, Store, SyncOutcome, Syncer};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

#[derive(Debug, Clone)]
struct Request {
    path: String,
    headers: Vec<(String, String)>,
}

impl Request {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

struct Reply {
    status: u16,
    headers: Vec<(&'static str, String)>,
    body: Vec<u8>,
}

fn ok(body: impl Into<Vec<u8>>) -> Reply {
    Reply {
        status: 200,
        headers: Vec::new(),
        body: body.into(),
    }
}

type Handler = Arc<dyn Fn(&Request) -> Reply + Send + Sync>;

struct Server {
    port: u16,
    ca_file: PathBuf,
    requests: Arc<Mutex<Vec<Request>>>,
    handler: Arc<Mutex<Handler>>,
}

impl Server {
    async fn start(dir: &Path) -> Self {
        let rcgen::CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let ca_file = dir.join("ca.pem");
        std::fs::write(&ca_file, cert.pem()).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(cert.der().to_vec())],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der())),
            )
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let handler: Arc<Mutex<Handler>> = Arc::new(Mutex::new(Arc::new(|_: &Request| ok(""))));
        let (seen, current) = (Arc::clone(&requests), Arc::clone(&handler));
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let (acceptor, seen, current) =
                    (acceptor.clone(), Arc::clone(&seen), Arc::clone(&current));
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 4096];
                    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        match tls.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                    }
                    let head = String::from_utf8_lossy(&buf).to_string();
                    let mut lines = head.split("\r\n");
                    let path = lines
                        .next()
                        .and_then(|l| l.split(' ').nth(1))
                        .unwrap_or("")
                        .to_string();
                    let headers = lines
                        .filter_map(|l| l.split_once(':'))
                        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
                        .collect();
                    let request = Request { path, headers };
                    let handler = current.lock().unwrap().clone();
                    let reply = handler(&request);
                    seen.lock().unwrap().push(request);
                    let mut head = format!(
                        "HTTP/1.1 {} X\r\ncontent-length: {}\r\nconnection: close\r\n",
                        reply.status,
                        reply.body.len()
                    );
                    for (name, value) in &reply.headers {
                        head.push_str(&format!("{name}: {value}\r\n"));
                    }
                    head.push_str("\r\n");
                    let _ = tls.write_all(head.as_bytes()).await;
                    let _ = tls.write_all(&reply.body).await;
                    let _ = tls.shutdown().await;
                });
            }
        });
        Self {
            port,
            ca_file,
            requests,
            handler,
        }
    }

    fn reply(&self, handler: impl Fn(&Request) -> Reply + Send + Sync + 'static) {
        *self.handler.lock().unwrap() = Arc::new(handler);
    }

    fn url(&self, path: &str) -> String {
        format!("https://localhost:{}{path}", self.port)
    }

    fn last(&self) -> Request {
        self.requests.lock().unwrap().last().cloned().unwrap()
    }
}

fn feed(name: &str, format: FeedFormat, url: String) -> IntelFeedConfig {
    IntelFeedConfig {
        name: name.into(),
        format,
        url,
        key_env: None,
        key_file: None,
        auth_header: None,
        refresh_secs: 3600,
        enabled: true,
        kind: None,
        threat: None,
    }
}

fn setup(dir: &Path, server: &Server, feeds: Vec<IntelFeedConfig>) -> Syncer {
    let cfg = IntelConfig {
        enabled: true,
        database: dir.join("intel.sqlite"),
        ca_file: Some(server.ca_file.clone()),
        max_download_bytes: 4096,
        feeds,
        ..IntelConfig::default()
    };
    let store = Arc::new(Store::open(&cfg.database, 7 * 86_400).unwrap());
    Syncer::new(&cfg, store).unwrap()
}

fn listed(syncer: &Syncer, kind: Kind, value: &str) -> bool {
    !syncer
        .store()
        .lookup(kind, value, currawong_intel::now())
        .unwrap()
        .is_empty()
}

#[tokio::test]
async fn intel_sync_uses_etags_and_keeps_old_data_on_bad_downloads() {
    let dir = tempfile::tempdir().unwrap();
    let server = Server::start(dir.path()).await;
    let lines = feed("list", FeedFormat::Lines, server.url("/feed.txt"));
    let syncer = setup(dir.path(), &server, vec![lines.clone()]);
    server.reply(|_| Reply {
        status: 200,
        headers: vec![
            ("etag", "\"v1\"".into()),
            ("last-modified", "Wed, 21 Oct 2026 07:28:00 GMT".into()),
        ],
        body: b"# test feed\nevil.example\nhttps://phish.example/login\n".to_vec(),
    });
    let now = currawong_intel::now();
    assert_eq!(
        syncer.sync_feed(&lines, now).await,
        Ok(SyncOutcome::Updated {
            indicators: 2,
            rejected: 0
        })
    );
    assert!(listed(&syncer, Kind::Domain, "evil.example"));
    assert!(listed(&syncer, Kind::Url, "https://phish.example/login"));
    assert!(server
        .last()
        .header("user-agent")
        .unwrap()
        .starts_with("currawong/"));

    // Unchanged: a conditional GET answered 304.
    server.reply(|req| {
        assert_eq!(req.header("if-none-match"), Some("\"v1\""));
        assert_eq!(
            req.header("if-modified-since"),
            Some("Wed, 21 Oct 2026 07:28:00 GMT")
        );
        Reply {
            status: 304,
            headers: Vec::new(),
            body: Vec::new(),
        }
    });
    assert_eq!(
        syncer.sync_feed(&lines, now + 10).await,
        Ok(SyncOutcome::NotModified)
    );
    let status = syncer.store().status("list").unwrap().unwrap();
    assert_eq!(status.last_success, Some(now + 10));

    // Too big, an HTML error page, an empty body and a server error all
    // leave the last good list in place.
    server.reply(|_| ok(vec![b'a'; 5000]));
    let err = syncer.sync_feed(&lines, now + 20).await.unwrap_err();
    assert!(err.contains("larger than 4096"), "{err}");
    server.reply(|_| ok("<html>\n<body>Service unavailable</body>\n</html>\n"));
    let err = syncer.sync_feed(&lines, now + 30).await.unwrap_err();
    assert!(err.contains("not indicators"), "{err}");
    server.reply(|_| ok(""));
    let err = syncer.sync_feed(&lines, now + 40).await.unwrap_err();
    assert!(err.contains("no indicators"), "{err}");
    server.reply(|_| Reply {
        status: 503,
        headers: Vec::new(),
        body: Vec::new(),
    });
    assert!(syncer.sync_feed(&lines, now + 50).await.is_err());
    assert!(listed(&syncer, Kind::Domain, "evil.example"));
    let status = syncer.store().status("list").unwrap().unwrap();
    assert_eq!(status.last_success, Some(now + 10));
    assert!(status.last_error.unwrap().contains("503"));

    // A new list replaces the old one.
    server.reply(|_| ok("new.example\n"));
    syncer.sync_feed(&lines, now + 60).await.unwrap();
    assert!(!listed(&syncer, Kind::Domain, "evil.example"));
    assert!(listed(&syncer, Kind::Domain, "new.example"));
}

#[tokio::test]
async fn intel_sync_sends_keys_without_logging_them_and_refuses_http_redirects() {
    let dir = tempfile::tempdir().unwrap();
    let server = Server::start(dir.path()).await;
    let key_file = dir.path().join("abuse.key");
    std::fs::write(&key_file, "s3cretKEY123\n").unwrap();
    let mut keyed = feed(
        "urlhaus",
        FeedFormat::Csv,
        server.url("/v2/files/exports/{key}/online.csv"),
    );
    keyed.key_file = Some(key_file.clone());
    keyed.auth_header = Some("Auth-Key".into());
    let syncer = setup(dir.path(), &server, vec![keyed.clone()]);
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    std::io::Write::write_all(
        &mut gz,
        b"# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter\n\"1\",\"2026-10-01\",\"http://198.51.100.9/x.exe\",\"online\",\"\",\"malware_download\",\"exe\",\"\",\"r\"\n",
    )
    .unwrap();
    let gz = gz.finish().unwrap();
    server.reply(move |_| ok(gz.clone()));
    let now = currawong_intel::now();
    syncer.sync_feed(&keyed, now).await.unwrap();
    let request = server.last();
    assert_eq!(request.path, "/v2/files/exports/s3cretKEY123/online.csv");
    assert_eq!(request.header("auth-key"), Some("s3cretKEY123"));
    assert!(listed(&syncer, Kind::Url, "http://198.51.100.9/x.exe"));

    // Errors name neither the URL nor the key.
    let port = server.port;
    server.reply(move |_| Reply {
        status: 302,
        headers: vec![("location", format!("http://localhost:{port}/plain"))],
        body: Vec::new(),
    });
    let err = syncer.sync_feed(&keyed, now + 1).await.unwrap_err();
    assert!(!err.contains("s3cretKEY123"), "{err}");
    assert!(
        err.contains("non-https") || err.contains("redirect"),
        "{err}"
    );
    let stored = syncer.store().status("urlhaus").unwrap().unwrap();
    assert!(!stored.last_error.unwrap().contains("s3cretKEY123"));
    assert_eq!(server.requests.lock().unwrap().len(), 2);

    let mut missing = keyed.clone();
    missing.key_file = Some(dir.path().join("absent.key"));
    assert!(syncer
        .sync_feed(&missing, now + 2)
        .await
        .unwrap_err()
        .contains("feed key"));
}

#[tokio::test]
async fn intel_sync_follows_taxii_pages_and_reports_stale_feeds() {
    let dir = tempfile::tempdir().unwrap();
    let server = Server::start(dir.path()).await;
    let taxii = feed(
        "ctis",
        FeedFormat::Taxii,
        server.url("/api/collections/abc/objects/?match%5Btype%5D=indicator"),
    );
    let mut dead = feed("dead", FeedFormat::Lines, server.url("/dead.txt"));
    dead.refresh_secs = 60;
    let syncer = setup(dir.path(), &server, vec![taxii.clone(), dead.clone()]);
    server.reply(|req| {
        assert_eq!(
            req.header("accept"),
            Some("application/taxii+json;version=2.1")
        );
        if req.path.contains("dead") {
            return Reply {
                status: 404,
                headers: Vec::new(),
                body: Vec::new(),
            };
        }
        assert!(req.path.contains("match%5Btype%5D=indicator") || req.path.contains("match[type]=indicator"), "{}", req.path);
        let (more, value) = if req.path.contains("next=page2") {
            (false, "two.example")
        } else {
            (true, "one.example")
        };
        ok(format!(
            r#"{{"more": {more}, "next": "page2", "objects": [{{"type": "indicator", "pattern_type": "stix", "pattern": "[domain-name:value = '{value}']"}}]}}"#
        ))
    });
    let results = syncer.sync_due(false).await;
    assert_eq!(results.len(), 2);
    assert_eq!(
        results[0].1,
        Ok(SyncOutcome::Updated {
            indicators: 2,
            rejected: 0
        })
    );
    assert!(results[1].1.is_err());
    assert!(listed(&syncer, Kind::Domain, "one.example"));
    assert!(listed(&syncer, Kind::Domain, "two.example"));
    // Nothing is due straight after a sync, and a failed feed waits too.
    assert!(syncer.sync_due(false).await.is_empty());

    let now = currawong_intel::now();
    let stale = syncer.stale_feeds(now);
    assert_eq!(stale, vec![("dead".to_string(), None)]);
    let later = syncer.stale_feeds(now + 3 * 3600 + 1);
    assert_eq!(later.len(), 2);
}

#[tokio::test]
async fn intel_sync_redirects_stay_same_origin_without_referer() {
    let dir = tempfile::tempdir().unwrap();
    let server = Server::start(dir.path()).await;
    let key_file = dir.path().join("fixture.key");
    std::fs::write(&key_file, "synthetic-feed-key").unwrap();
    let mut keyed = feed("keyed", FeedFormat::Lines, server.url("/key/{key}"));
    keyed.key_file = Some(key_file);
    keyed.auth_header = Some("Auth-Key".into());
    let syncer = setup(dir.path(), &server, vec![keyed.clone()]);
    server.reply(|req| {
        if req.path.starts_with("/key/") {
            Reply {
                status: 302,
                headers: vec![("location", "/list".into())],
                body: vec![],
            }
        } else {
            assert_eq!(req.header("auth-key"), Some("synthetic-feed-key"));
            ok("old.example\n")
        }
    });
    let now = currawong_intel::now();
    syncer.sync_feed(&keyed, now).await.unwrap();
    assert!(server.last().header("referer").is_none());
}

#[tokio::test]
async fn intel_sync_refuses_cross_origin_authenticated_redirects() {
    let dir = tempfile::tempdir().unwrap();
    let server = Server::start(dir.path()).await;
    let other_dir = tempfile::tempdir().unwrap();
    let other = Server::start(other_dir.path()).await;
    // Trust both fake peers: TLS must not hide an unsafe redirect policy.
    let mut roots = std::fs::read(&server.ca_file).unwrap();
    roots.extend(std::fs::read(&other.ca_file).unwrap());
    std::fs::write(&server.ca_file, roots).unwrap();
    let key_file = dir.path().join("fixture.key");
    std::fs::write(&key_file, "synthetic-feed-key").unwrap();
    let mut keyed = feed("keyed", FeedFormat::Lines, server.url("/key/{key}"));
    keyed.key_file = Some(key_file);
    keyed.auth_header = Some("Auth-Key".into());
    let syncer = setup(dir.path(), &server, vec![keyed.clone()]);
    server.reply(|_| ok("old.example\n"));
    let now = currawong_intel::now();
    syncer.sync_feed(&keyed, now).await.unwrap();
    other.reply(|_| ok("other.example\n"));
    // Different port is a different origin, even on the same hostname.
    let location = other.url("/list");
    server.reply(move |_| Reply {
        status: 302,
        headers: vec![("location", location.clone())],
        body: vec![],
    });
    let err = syncer.sync_feed(&keyed, now + 1).await.unwrap_err();
    assert!(err.contains("cross-origin"), "{err}");
    assert!(!err.contains("synthetic-feed-key"));
    assert!(other.requests.lock().unwrap().is_empty());
    assert!(listed(&syncer, Kind::Domain, "old.example"));
}

#[tokio::test]
async fn intel_sync_incomplete_taxii_keeps_previous_collection() {
    let dir = tempfile::tempdir().unwrap();
    let server = Server::start(dir.path()).await;
    let taxii = feed("ctis", FeedFormat::Taxii, server.url("/objects"));
    let syncer = setup(dir.path(), &server, vec![taxii.clone()]);
    server.reply(|_| ok(r#"{"more":false,"objects":[{"type":"indicator","pattern":"[domain-name:value = 'old.example']"}]}"#));
    let now = currawong_intel::now();
    syncer.sync_feed(&taxii, now).await.unwrap();
    for next in [
        None,
        Some(serde_json::json!(null)),
        Some(serde_json::json!(42)),
        Some(serde_json::json!("")),
        Some(serde_json::json!("  ")),
    ] {
        let mut page = serde_json::json!({"more":true,"objects":[{"type":"indicator","pattern":"[domain-name:value = 'partial.example']"}]});
        if let Some(next) = next {
            page["next"] = next;
        }
        server.reply(move |_| ok(serde_json::to_vec(&page).unwrap()));
        assert!(syncer.sync_feed(&taxii, now + 1).await.is_err());
        assert!(listed(&syncer, Kind::Domain, "old.example"));
        assert!(!listed(&syncer, Kind::Domain, "partial.example"));
    }
}
