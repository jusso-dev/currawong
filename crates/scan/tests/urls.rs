use currawong_scan::urls::{Claims, UrlRewriter, UrlSigner};
use mail_parser::{MessageParser, MimeHeaders};
use std::collections::BTreeSet;

const BASE: &str = "https://links.example.com.au";

fn fixture() -> Vec<u8> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata/urls/links.eml");
    std::fs::read(path).unwrap()
}

fn rewriter() -> UrlRewriter {
    UrlRewriter::new(
        UrlSigner::new(vec![3; 32]).unwrap(),
        BASE,
        &["trusted.example".into()],
        30 * 86_400,
        10 * 1024 * 1024,
    )
    .unwrap()
}

/// Every link the fixture's rewritable parts contain, as a browser parses it.
const LINKS: &[&str] = &[
    "https://pay.example.net/invoice/42?ref=abc",
    "https://docs.example.net/a/very/long/path/that/needs/a/soft/line/break/in/quoted-printable",
    "https://shop.example.net/menu?a=1&b=2",
    "https://login.example.org/Reset",
    "http://maps.example.net/area",
    "http://plain.example.net/start",
    "https://plain.example.net/end",
];

/// Links that must survive unchanged: allow-listed, signed, attached.
const KEPT: &[&str] = &[
    "https://trusted.example/x",
    "https://www.trusted.example/ok",
    "mailto:help@example.org",
    "https://signed.example.net/keep",
    "https://attached.example.net/keep",
];

/// Decoded bodies of every leaf part, in order.
fn bodies(raw: &[u8]) -> Vec<Vec<u8>> {
    let message = MessageParser::default().parse(raw).unwrap();
    message
        .parts
        .iter()
        .filter(|part| !part.is_multipart())
        .map(|part| match &part.body {
            mail_parser::PartType::Text(text) | mail_parser::PartType::Html(text) => {
                text.as_bytes().to_vec()
            }
            _ => part.contents().to_vec(),
        })
        .collect()
}

fn tokens(text: &str) -> Vec<String> {
    let marker = format!("{BASE}/u/");
    text.match_indices(&marker)
        .map(|(at, _)| {
            text[at + marker.len()..]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
                .collect::<String>()
                .trim_end_matches('.')
                .to_string()
        })
        .collect()
}

#[test]
fn urls_every_http_link_in_the_fixture_round_trips() {
    let raw = fixture();
    let rewriter = rewriter();
    let out = rewriter
        .rewrite_message(&raw, "01ARZ3NDEKTSV4RRFFQ69G5FAV", 1_000)
        .unwrap();
    assert_eq!(out.links, LINKS.len(), "{:?}", out.notes);
    let joined: String = bodies(&out.message)
        .iter()
        .map(|body| String::from_utf8_lossy(body).into_owned())
        .collect();
    let mut found = BTreeSet::new();
    for token in tokens(&joined) {
        let claims: Claims = rewriter.signer().verify(&token, 1_000).unwrap();
        assert_eq!(claims.m, "01ARZ3NDEKTSV4RRFFQ69G5FAV");
        assert_eq!(claims.e, 1_000 + 30 * 86_400);
        found.insert(claims.u);
    }
    let expected: BTreeSet<String> = LINKS.iter().map(|s| s.to_string()).collect();
    assert_eq!(found, expected);
    for link in LINKS.iter().filter(|l| !l.contains("Reset")) {
        assert!(!joined.contains(link), "{link} left in place");
    }
    for link in KEPT {
        assert!(joined.contains(link), "{link} was rewritten");
    }
}

#[test]
fn urls_rewrite_keeps_mime_structure_encodings_and_charsets() {
    let raw = fixture();
    let out = rewriter().rewrite_message(&raw, "m", 0).unwrap().message;
    let before = MessageParser::default().parse(&raw).unwrap();
    let after = MessageParser::default().parse(&out).unwrap();
    assert_eq!(before.parts.len(), after.parts.len());
    for (a, b) in before.parts.iter().zip(&after.parts) {
        let describe = |p: &mail_parser::MessagePart| {
            let ct = p.content_type().unwrap();
            (
                ct.ctype().to_string(),
                ct.subtype().map(str::to_string),
                ct.attribute("charset").map(str::to_string),
                p.content_transfer_encoding().map(str::to_string),
            )
        };
        if a.content_type().is_some() {
            assert_eq!(describe(a), describe(b));
        }
    }
    // Headers, the preamble, the signed part and the attachment are byte for byte.
    let text = String::from_utf8(out.clone()).unwrap();
    let raw_text = String::from_utf8(raw.clone()).unwrap();
    let header_end = raw_text.find("\r\n\r\n").unwrap();
    assert!(text.starts_with(&raw_text[..header_end + 4]));
    for kept in [
        &raw_text[raw_text
            .find("--outer\r\nContent-Type: multipart/signed")
            .unwrap()..],
        "This is a multi-part message in MIME format.\r\n--outer\r\n",
    ] {
        assert!(text.contains(kept));
    }
    // The ISO-8859-1 byte in the base64 HTML part is untouched.
    let html = &bodies(&out)[1];
    assert!(String::from_utf8_lossy(html).contains("Caf\u{e9}"));
    let html_part = after.parts.iter().find(|p| p.is_text_html()).unwrap();
    let raw_html = &out[html_part.offset_body as usize..html_part.offset_end as usize];
    assert!(raw_html.split(|b| *b == b'\n').all(|line| line.len() <= 78));
}

#[test]
fn urls_rewrite_is_deterministic_and_idempotent() {
    let raw = fixture();
    let rewriter = rewriter();
    let first = rewriter.rewrite_message(&raw, "m", 5).unwrap();
    let second = rewriter.rewrite_message(&raw, "m", 5).unwrap();
    assert_eq!(first.message, second.message);
    let again = rewriter.rewrite_message(&first.message, "m", 5).unwrap();
    assert_eq!(again.links, 0);
    assert_eq!(again.message, first.message);
}

#[test]
fn urls_long_link_in_a_7bit_part_moves_to_quoted_printable() {
    let link = format!("https://long.example.net/{}", "a".repeat(900));
    let raw = format!(
        "From: a@example.org\r\nTo: b@example.test\r\nSubject: long\r\nContent-Type: text/plain\r\nContent-Transfer-Encoding: 7bit\r\n\r\nGo {link} now\r\n"
    );
    let out = rewriter().rewrite_message(raw.as_bytes(), "m", 0).unwrap();
    assert_eq!(out.links, 1);
    let text = String::from_utf8(out.message.clone()).unwrap();
    assert!(text.contains("Content-Transfer-Encoding: quoted-printable\r\n\r\n"));
    assert!(!text.contains("7bit"));
    assert!(text.lines().all(|line| line.len() <= 998));
    let body = &bodies(&out.message)[0];
    let tokens = tokens(&String::from_utf8_lossy(body));
    let claims = rewriter().signer().verify(&tokens[0], 0).unwrap();
    assert_eq!(claims.u, link);
}

#[test]
fn urls_hostile_input_never_panics_and_is_bounded() {
    let rewriter = UrlRewriter::new(
        UrlSigner::new(vec![3; 32]).unwrap(),
        BASE,
        &[],
        60,
        64 * 1024,
    )
    .unwrap();
    let mut seed = 0x2545_f491_u32;
    let table = b"<a href=\"http://x.test/'>&#;\r\n=AZ\x00\xff";
    let mut noise = Vec::new();
    for _ in 0..20_000 {
        seed ^= seed << 13;
        seed ^= seed >> 17;
        seed ^= seed << 5;
        noise.push(table[seed as usize % table.len()]);
    }
    let header = "Content-Type: text/html; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n";
    let inputs = [
        format!("{header}{}", "<a href=".repeat(5_000)).into_bytes(),
        format!("{header}<a href=\"http://x.test/{}", "&#x".repeat(5_000)).into_bytes(),
        format!("{header}<select><xmp><script><a href=\"https://x.test/\">").into_bytes(),
        [header.as_bytes(), &noise].concat(),
        noise.clone(),
        b"Content-Type: multipart/mixed; boundary=a\r\n\r\n--a\r\n--a\r\n--a--".to_vec(),
        "Content-Type: text/html; charset=utf-16\r\n\r\n<a href=\"https://x.test/\">"
            .to_string()
            .into_bytes(),
    ];
    for input in &inputs {
        if let Ok(out) = rewriter.rewrite_message(input, "m", 0) {
            assert!(out.message.len() <= input.len() * 4 + 4096);
        }
    }
    let big = vec![b'a'; 64 * 1024 + 1];
    assert!(rewriter.rewrite_message(&big, "m", 0).is_err());
    let many = format!(
        "Content-Type: text/plain\r\n\r\n{}",
        "https://x.test/ ".repeat(currawong_scan::urls::rewrite::MAX_LINKS + 1)
    );
    let roomy = UrlRewriter::new(
        UrlSigner::new(vec![3; 32]).unwrap(),
        BASE,
        &[],
        60,
        usize::MAX,
    )
    .unwrap();
    assert!(roomy.rewrite_message(many.as_bytes(), "m", 0).is_err());
}
