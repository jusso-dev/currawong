use currawong_scan::urls::{Claims, Delivery, UrlRewriter, UrlSigner};
use mail_parser::{MessageParser, MimeHeaders};
use std::collections::BTreeSet;

const BASE: &str = "https://links.example.com.au";

fn at(message_id: &str, issued_at: u64) -> Delivery<'_> {
    Delivery {
        message_id,
        recipient: "dest@example.test",
        issued_at,
    }
}

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
        .rewrite_message(&raw, &at("01ARZ3NDEKTSV4RRFFQ69G5FAV", 1_000))
        .unwrap();
    assert_eq!(out.links, LINKS.len(), "{:?}", out.notes);
    // The S/MIME signed part keeps its link and is counted for policy.
    assert_eq!(out.skipped, 1, "{:?}", out.notes);
    let joined: String = bodies(&out.message)
        .iter()
        .map(|body| String::from_utf8_lossy(body).into_owned())
        .collect();
    let mut found = BTreeSet::new();
    for token in tokens(&joined) {
        let claims: Claims = rewriter.signer().verify(&token, 1_000).unwrap();
        assert_eq!(claims.m, "01ARZ3NDEKTSV4RRFFQ69G5FAV");
        assert_eq!(claims.r, "dest@example.test");
        assert_eq!(claims.t, 1_000);
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
    let out = rewriter()
        .rewrite_message(&raw, &at("m", 0))
        .unwrap()
        .message;
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
    let first = rewriter.rewrite_message(&raw, &at("m", 5)).unwrap();
    let second = rewriter.rewrite_message(&raw, &at("m", 5)).unwrap();
    assert_eq!(first.message, second.message);
    let again = rewriter
        .rewrite_message(&first.message, &at("m", 5))
        .unwrap();
    assert_eq!(again.links, 0);
    assert_eq!(again.message, first.message);
}

#[test]
fn urls_long_link_in_a_7bit_part_moves_to_quoted_printable() {
    let link = format!("https://long.example.net/{}", "a".repeat(900));
    let raw = format!(
        "From: a@example.org\r\nTo: b@example.test\r\nSubject: long\r\nContent-Type: text/plain\r\nContent-Transfer-Encoding: 7bit\r\n\r\nGo {link} now\r\n"
    );
    let out = rewriter()
        .rewrite_message(raw.as_bytes(), &at("m", 0))
        .unwrap();
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
        if let Ok(out) = rewriter.rewrite_message(input, &at("m", 0)) {
            assert!(out.message.len() <= input.len() * 4 + 4096);
        }
    }
    let big = vec![b'a'; 64 * 1024 + 1];
    assert!(rewriter.rewrite_message(&big, &at("m", 0)).is_err());
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
    assert!(roomy.rewrite_message(many.as_bytes(), &at("m", 0)).is_err());
}

fn message(content_type: &str, body: &str) -> Vec<u8> {
    format!("From: a@example.org\r\nTo: b@example.test\r\nSubject: x\r\nMIME-Version: 1.0\r\nContent-Type: {content_type}\r\n\r\n{body}").into_bytes()
}

/// Minimal well-formed CMS ContentInfo (signedData) and OpenPGP signature
/// packet, base64. Structure only: nothing here is a real signature.
const CMS: &str = "MIIAIAYJKoZIhvcNAQcCoBMBAgMEBQYHCAkKCwwNDg8QERIT";
const PGP_PACKET: &str = "iQAQAQIDBAUGBwgJCgsMDQ4PEA==";

fn signed(protocol: &str, sig_type: &str, signature: &str) -> Vec<u8> {
    let body = format!("--s\r\nContent-Type: text/plain\r\n\r\nhttps://evil.test/a\r\n--s\r\nContent-Type: {sig_type}\r\nContent-Transfer-Encoding: base64\r\n\r\n{signature}\r\n--s--\r\n");
    message(
        &format!("multipart/signed; protocol=\"{protocol}\"; boundary=s"),
        &body,
    )
}

#[test]
fn urls_bogus_signed_wrappers_do_not_exempt_links() {
    let rewriter = rewriter();
    let smime = "application/pkcs7-signature";
    let pgp = "application/pgp-signature";
    let armour = format!(
        "-----BEGIN PGP SIGNATURE-----\r\n\r\n{PGP_PACKET}\r\n=abcd\r\n-----END PGP SIGNATURE-----"
    );
    let armour_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &armour);
    for (raw, exempt) in [
        (
            message(
                "multipart/signed; boundary=s",
                "--s\r\nContent-Type: text/plain\r\n\r\nhttps://evil.test/a\r\n--s--\r\n",
            ),
            false,
        ),
        (signed("text/plain", "text/plain", CMS), false),
        (signed(smime, "application/octet-stream", CMS), false),
        // The right protocol and part type with junk for a signature.
        (signed(smime, smime, "AAAA"), false),
        (signed(pgp, pgp, "AAAA"), false),
        (signed(smime, smime, CMS), true),
        (signed(pgp, pgp, &armour_b64), true),
    ] {
        let out = rewriter.rewrite_message(&raw, &at("m", 0)).unwrap();
        let text = String::from_utf8_lossy(&raw).into_owned();
        assert_eq!(
            (out.links, out.skipped),
            if exempt { (0, 1) } else { (1, 0) },
            "{text}"
        );
    }
    let fake_pgp = "-----BEGIN PGP SIGNED MESSAGE-----\r\nhttps://evil.test/b\r\n";
    let out = rewriter
        .rewrite_message(&message("text/plain", fake_pgp), &at("m", 0))
        .unwrap();
    assert_eq!(out.links, 1);
    let junk_pgp = "-----BEGIN PGP SIGNED MESSAGE-----\r\nHash: SHA256\r\n\r\nhttps://evil.test/c\r\n-----BEGIN PGP SIGNATURE-----\r\n\r\nAAAA\r\n-----END PGP SIGNATURE-----\r\n";
    let out = rewriter
        .rewrite_message(&message("text/plain", junk_pgp), &at("m", 0))
        .unwrap();
    assert_eq!((out.links, out.skipped), (1, 0), "{:?}", out.notes);
    // Only the clear-signed span is exempt; links around it are rewritten.
    let real_pgp = format!("Before https://evil.test/before\r\n-----BEGIN PGP SIGNED MESSAGE-----\r\nHash: SHA256\r\n\r\nhttps://evil.test/c\r\n-----BEGIN PGP SIGNATURE-----\r\n\r\n{PGP_PACKET}\r\n=abcd\r\n-----END PGP SIGNATURE-----\r\nAfter https://evil.test/after\r\n");
    let out = rewriter
        .rewrite_message(&message("text/plain", &real_pgp), &at("m", 0))
        .unwrap();
    assert_eq!((out.links, out.skipped), (2, 1), "{:?}", out.notes);
    let text = String::from_utf8(out.message).unwrap();
    assert!(text.contains("https://evil.test/c\r\n"));
    assert!(!text.contains("evil.test/before") && !text.contains("evil.test/after"));
}

/// Nesting deep enough to overflow `mail-parser` is refused before parsing,
/// and nesting under the limit parses on a thread with the stack tokio gives
/// a blocking task (2 MiB).
#[test]
fn urls_deep_nesting_is_refused_without_crashing() {
    let nested = |depth: usize, multipart: bool| {
        let mut raw = String::from(
            "From: a@example.org\r\nTo: b@example.test\r\nSubject: x\r\nMIME-Version: 1.0\r\n",
        );
        for n in 0..depth {
            if multipart {
                raw.push_str(&format!(
                    "Content-Type: multipart/mixed; boundary=b{n}\r\n\r\n--b{n}\r\n"
                ));
            } else {
                raw.push_str("Content-Type: message/rfc822\r\n\r\nSubject: inner\r\n");
            }
        }
        raw.push_str("Content-Type: text/plain\r\n\r\nhttps://evil.test/deep\r\n");
        raw.into_bytes()
    };
    let rewriter = std::sync::Arc::new(rewriter());
    for (depth, multipart, refused) in [
        (513, true, true),
        (33, false, true),
        (500, true, false),
        (31, false, false),
    ] {
        let raw = nested(depth, multipart);
        let rw = std::sync::Arc::clone(&rewriter);
        let result = std::thread::Builder::new()
            .stack_size(2 * 1024 * 1024)
            .spawn(move || rw.rewrite_message(&raw, &at("m", 0)).map(|out| out.links))
            .unwrap()
            .join()
            .expect("no crash");
        if refused {
            assert_eq!(
                result,
                Err(currawong_scan::urls::RewriteError::TooNested),
                "{depth}"
            );
        } else {
            assert!(result.is_ok(), "{depth}: {result:?}");
        }
    }
}

#[test]
fn urls_unreadable_charsets_are_counted_and_amp_html_is_rewritten() {
    let rewriter = rewriter();
    let out = rewriter
        .rewrite_message(
            &message("text/html; charset=utf-16le", "<\0a\0"),
            &at("m", 0),
        )
        .unwrap();
    assert_eq!((out.links, out.skipped), (0, 1));
    let amp = message(
        "multipart/alternative; boundary=b",
        "--b\r\nContent-Type: text/x-amp-html; charset=utf-8\r\n\r\n<a href=\"https://evil.test/\">x</a>\r\n--b--\r\n",
    );
    assert_eq!(
        rewriter.rewrite_message(&amp, &at("m", 0)).unwrap().links,
        1
    );
}

#[test]
fn urls_lf_only_messages_keep_lf_line_endings() {
    let html = format!(
        "<p>{}<a href=\"https://evil.test/x\">x</a></p>\n",
        "y".repeat(300)
    );
    for cte in ["base64", "quoted-printable"] {
        let body = if cte == "base64" {
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &html)
        } else {
            html.clone()
        };
        let raw = format!(
            "From: a@example.org\nTo: b@example.test\nSubject: x\nMIME-Version: 1.0\nContent-Type: text/html\nContent-Transfer-Encoding: {cte}\n\n{body}\n"
        );
        let out = rewriter()
            .rewrite_message(raw.as_bytes(), &at("m", 0))
            .unwrap();
        assert_eq!(out.links, 1, "{cte}");
        assert!(!out.message.contains(&b'\r'), "{cte}");
    }
}
