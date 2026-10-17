//! The click service over a real socket: round trip, tampering, and a link
//! blocked after delivery.
use currawong_admin::routes::click::{serve, ClickAction, ClickEvent, ClickLog, ClickState};
use currawong_scan::urls::{Claims, Delivery, LocalBlocklist, UrlRewriter, UrlSigner};
use std::{net::SocketAddr, path::Path, sync::Arc};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const BASE: &str = "https://links.example.com.au";

fn at(message_id: &str, issued_at: u64) -> Delivery<'_> {
    Delivery {
        message_id,
        recipient: "dest@example.test",
        issued_at,
    }
}

struct Reply {
    status: u16,
    location: Option<String>,
    body: String,
}

async fn get(addr: SocketAddr, path: &str) -> Reply {
    request(addr, "GET", path).await
}

async fn request(addr: SocketAddr, method: &str, path: &str) -> Reply {
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: links.example.com.au\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.unwrap();
    let text = String::from_utf8_lossy(&raw).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let status = head.split(' ').nth(1).unwrap().parse().unwrap();
    let location = head
        .lines()
        .find_map(|line| line.strip_prefix("location: "))
        .map(str::to_string);
    Reply {
        status,
        location,
        body: body.to_string(),
    }
}

fn signer() -> UrlSigner {
    UrlSigner::new(vec![0x42; 32]).unwrap()
}

fn rewriter() -> UrlRewriter {
    UrlRewriter::new(
        signer(),
        BASE,
        &["trusted.example".into()],
        30 * 86_400,
        1 << 20,
    )
    .unwrap()
}

async fn start(dir: &Path) -> SocketAddr {
    start_with(dir, false, 1 << 20).await
}

async fn start_with(dir: &Path, warn_unknown: bool, log_bytes: u64) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let list =
        LocalBlocklist::from_file(&dir.join("blocklist.txt")).with_warn_unknown(warn_unknown);
    let state = ClickState::new(
        signer(),
        Arc::new(list),
        ClickLog::open(&dir.join("clicks.jsonl"), log_bytes).unwrap(),
    );
    tokio::spawn(serve(listener, state));
    addr
}

fn claims(url: &str) -> Claims {
    Claims {
        u: url.into(),
        m: "m".into(),
        r: "dest@example.test".into(),
        t: 0,
        e: u64::MAX,
    }
}

fn events(dir: &Path) -> Vec<ClickEvent> {
    std::fs::read_to_string(dir.join("clicks.jsonl"))
        .unwrap_or_default()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

/// Rewritten `/u/<token>` paths in a message, in order.
fn click_paths(message: &[u8]) -> Vec<String> {
    let parsed = decoded(message);
    let marker = format!("{BASE}/u/");
    parsed
        .match_indices(&marker)
        .map(|(at, _)| {
            let token: String = parsed[at + marker.len()..]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
                .collect();
            format!("/u/{}", token.trim_end_matches('.'))
        })
        .collect()
}

/// Decoded text of every leaf part.
fn decoded(message: &[u8]) -> String {
    let parsed = mail_parser::MessageParser::default()
        .parse(message)
        .unwrap();
    parsed
        .parts
        .iter()
        .filter_map(|part| part.text_contents())
        .collect()
}

fn fixture() -> Vec<u8> {
    std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../testdata/urls/links.eml"
    ))
    .unwrap()
}

#[tokio::test]
async fn urls_every_fixture_link_round_trips_through_the_click_service() {
    let dir = tempfile::tempdir().unwrap();
    let addr = start(dir.path()).await;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let out = rewriter()
        .rewrite_message(&fixture(), &at("01ARZ3NDEKTSV4RRFFQ69G5FAV", now))
        .unwrap();
    let paths = click_paths(&out.message);
    assert_eq!(paths.len(), out.links);
    let mut landed = Vec::new();
    for path in &paths {
        let reply = get(addr, path).await;
        assert_eq!(reply.status, 302, "{path}: {}", reply.body);
        landed.push(reply.location.unwrap());
    }
    landed.sort();
    let mut expected = vec![
        "https://pay.example.net/invoice/42?ref=abc",
        "https://docs.example.net/a/very/long/path/that/needs/a/soft/line/break/in/quoted-printable",
        "https://shop.example.net/menu?a=1&b=2",
        "https://login.example.org/Reset",
        "http://maps.example.net/area",
        "http://plain.example.net/start",
        "https://plain.example.net/end",
    ];
    expected.sort();
    assert_eq!(landed, expected);
    let log = events(dir.path());
    assert_eq!(log.len(), expected.len());
    assert!(log.iter().all(
        |e| e.action == ClickAction::Redirected && e.message_id == "01ARZ3NDEKTSV4RRFFQ69G5FAV"
    ));
}

#[tokio::test]
async fn urls_tampered_tokens_return_400() {
    let dir = tempfile::tempdir().unwrap();
    let addr = start(dir.path()).await;
    let claims = claims("https://shop.example.net/");
    let token = signer().sign(&claims);
    assert_eq!(get(addr, &format!("/u/{token}")).await.status, 302);
    let (payload, tag) = token.split_once('.').unwrap();
    let flip = |s: &str, at: usize| {
        let mut b = s.as_bytes().to_vec();
        b[at] = if b[at] == b'A' { b'B' } else { b'A' };
        String::from_utf8(b).unwrap()
    };
    let other_key = UrlSigner::new(vec![0x43; 32]).unwrap().sign(&claims);
    let bad = [
        format!("{}.{tag}", flip(payload, 3)),
        format!("{payload}.{}", flip(tag, 5)),
        format!("{payload}.{}", &tag[..tag.len() - 2]),
        payload.to_string(),
        format!("{payload}.{tag}x"),
        "not-a-token".into(),
        other_key,
        "A".repeat(20_000),
    ];
    for token in bad {
        let reply = get(addr, &format!("/u/{token}")).await;
        assert_eq!(reply.status, 400, "{token}");
        assert!(reply.location.is_none());
    }
    let expired = signer().sign(&Claims { e: 1, ..claims });
    assert_eq!(get(addr, &format!("/u/{expired}")).await.status, 410);
    // Only verified clicks are recorded.
    assert_eq!(events(dir.path()).len(), 1);
}

#[tokio::test]
async fn urls_link_blocked_after_delivery_shows_the_block_page() {
    let dir = tempfile::tempdir().unwrap();
    let addr = start(dir.path()).await;
    let raw = b"From: a@example.org\r\nTo: b@example.test\r\nSubject: x\r\nContent-Type: text/plain\r\n\r\nInvoice: https://files.example.net/invoice.pdf\r\n";
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let delivered = rewriter()
        .rewrite_message(raw, &at("m-blocked", now))
        .unwrap();
    let paths = click_paths(&delivered.message);
    assert_eq!(paths.len(), 1);
    // Clean at delivery and at the first click.
    let first = get(addr, &paths[0]).await;
    assert_eq!(first.status, 302);
    assert_eq!(
        first.location.as_deref(),
        Some("https://files.example.net/invoice.pdf")
    );

    // The domain is weaponised and blocked after delivery.
    std::fs::write(
        dir.path().join("blocklist.txt"),
        "# feed\nfiles.example.net\n",
    )
    .unwrap();
    let second = get(addr, &paths[0]).await;
    assert_eq!(second.status, 403);
    assert!(second.location.is_none());
    assert!(
        second.body.contains("This link has been blocked"),
        "{}",
        second.body
    );
    assert!(second
        .body
        .contains("https://files.example.net/invoice.pdf"));
    assert!(second
        .body
        .contains("files.example.net is on the block list"));

    let log = events(dir.path());
    assert_eq!(log.len(), 2);
    assert_eq!(log[0].action, ClickAction::Redirected);
    assert_eq!(log[1].action, ClickAction::Blocked);
    assert_eq!(log[1].message_id, "m-blocked");
}

#[tokio::test]
async fn urls_block_page_escapes_the_link() {
    let dir = tempfile::tempdir().unwrap();
    let addr = start(dir.path()).await;
    std::fs::write(dir.path().join("blocklist.txt"), "evil.test\n").unwrap();
    let token = signer().sign(&claims("https://evil.test/?q=<script>alert(1)</script>\""));
    let reply = get(addr, &format!("/u/{token}")).await;
    assert_eq!(reply.status, 403);
    assert!(!reply.body.contains("<script>"), "{}", reply.body);
    assert!(reply.body.contains("&lt;script&gt;"));
}

#[tokio::test]
async fn urls_warning_page_lets_the_user_continue() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("blocklist.txt"),
        "allow known.example\nwarn odd.example\n",
    )
    .unwrap();
    let addr = start_with(dir.path(), true, 1 << 20).await;
    let known = signer().sign(&claims("https://known.example/a"));
    assert_eq!(get(addr, &format!("/u/{known}")).await.status, 302);
    for url in ["https://odd.example/b", "https://unknown.example/c"] {
        let token = signer().sign(&claims(url));
        let reply = get(addr, &format!("/u/{token}")).await;
        assert_eq!(reply.status, 200, "{url}");
        assert!(reply.body.contains("Check this link before you continue"));
        assert!(reply.body.contains(&format!("/u/{token}?proceed=1")));
        let reply = get(addr, &format!("/u/{token}?proceed=1")).await;
        assert_eq!(reply.status, 302);
        assert_eq!(reply.location.as_deref(), Some(url));
    }
    std::fs::write(dir.path().join("blocklist.txt"), "odd.example\n").unwrap();
    let token = signer().sign(&claims("https://odd.example/b"));
    // A block wins over a click-through.
    assert_eq!(
        get(addr, &format!("/u/{token}?proceed=1")).await.status,
        403
    );
    let actions: Vec<ClickAction> = events(dir.path()).iter().map(|e| e.action).collect();
    use ClickAction::*;
    assert_eq!(
        actions,
        [Redirected, Warned, Redirected, Warned, Redirected, Blocked]
    );
    assert!(events(dir.path())
        .iter()
        .all(|e| e.recipient == "dest@example.test"));
}

#[tokio::test]
async fn urls_head_previews_are_not_clicks_and_clicks_are_rate_limited() {
    let dir = tempfile::tempdir().unwrap();
    let addr = start(dir.path()).await;
    let token = signer().sign(&claims("https://shop.example.net/x"));
    let path = format!("/u/{token}");
    assert_eq!(request(addr, "HEAD", &path).await.status, 200);
    assert!(events(dir.path()).is_empty());
    let mut statuses = Vec::new();
    for _ in 0..31 {
        statuses.push(get(addr, &path).await.status);
    }
    assert!(statuses[..30].iter().all(|s| *s == 302), "{statuses:?}");
    assert_eq!(statuses[30], 429);
    // Other links are not held back by this one.
    let other = signer().sign(&claims("https://shop.example.net/y"));
    assert_eq!(get(addr, &format!("/u/{other}")).await.status, 302);
}

#[tokio::test]
async fn urls_click_log_is_private_and_rotates() {
    let dir = tempfile::tempdir().unwrap();
    let addr = start_with(dir.path(), false, 600).await;
    for n in 0..6 {
        let token = signer().sign(&claims(&format!("https://shop.example.net/{n}")));
        assert_eq!(get(addr, &format!("/u/{token}")).await.status, 302);
    }
    let log = dir.path().join("clicks.jsonl");
    assert!(std::fs::metadata(&log).unwrap().len() <= 600);
    assert!(dir.path().join("clicks.jsonl.1").exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&log).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
