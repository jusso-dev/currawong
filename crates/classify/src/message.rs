//! The parts of a message the classifiers read: decoded headers, sender
//! addresses, body text and links.
//!
//! This parses in the supervisor process, not in an isolated parser worker
//! (ADR 0002). Until extraction moves into the worker response, the input is
//! capped, deeply nested messages are refused before `mail-parser` sees them
//! (its recursion would overflow the stack and abort the process), and the
//! parse runs on its own thread with a large stack so a panic or a deep but
//! allowed message yields an empty view instead of taking down the pipeline.
use mail_parser::{HeaderValue, MessageParser};
use regex::{bytes::Regex as BytesRegex, Regex};
use std::{collections::HashSet, sync::OnceLock};

/// Bytes of the raw message that are parsed. Later bytes are not classified.
pub const MAX_RAW_BYTES: usize = 4 * 1024 * 1024;
/// Embedded messages and multiparts allowed before the message is refused.
pub const MAX_EMBEDDED_MESSAGES: usize = 32;
pub const MAX_MULTIPARTS: usize = 512;
const PARSER_STACK_BYTES: usize = 64 * 1024 * 1024;
/// Body text kept for tokens and rules. Longer bodies are cut, not rejected.
const MAX_BODY_CHARS: usize = 64 * 1024;
/// Decoded header value kept for tokens and rules.
const MAX_HEADER_CHARS: usize = 64 * 1024;
/// Links are found in all text and HTML, up to the raw cap. Every distinct
/// host up to `MAX_HOSTS` is kept; `MAX_URLS` distinct links go to the URI
/// rules; at most `MAX_LINKS_SCANNED` distinct links are examined.
const MAX_URLS: usize = 512;
const MAX_HOSTS: usize = 10_000;
const MAX_LINKS_SCANNED: usize = 100_000;

#[derive(Debug, Clone, Default)]
pub struct MessageView {
    /// Header names and decoded values (RFC 2047), in message order.
    pub headers: Vec<(String, String)>,
    pub from: Vec<String>,
    pub reply_to: Vec<String>,
    pub body: String,
    pub urls: Vec<String>,
    /// Hosts of every link in the text and HTML bodies, first seen first.
    pub hosts: Vec<String>,
    /// The message was longer than `MAX_RAW_BYTES`.
    pub truncated: bool,
    /// A link cap was reached, so some links were not checked.
    pub links_truncated: bool,
    /// Too deeply nested to parse safely. Nothing else is filled in.
    pub skipped: bool,
    /// The parser found no headers or panicked.
    pub failed: bool,
}

impl MessageView {
    pub fn parse(raw: &[u8]) -> Self {
        let truncated = raw.len() > MAX_RAW_BYTES;
        let raw = &raw[..raw.len().min(MAX_RAW_BYTES)];
        if too_nested(raw) {
            return Self {
                skipped: true,
                truncated,
                ..Self::default()
            };
        }
        let parsed = std::thread::scope(|scope| {
            std::thread::Builder::new()
                .name("classify-parse".into())
                .stack_size(PARSER_STACK_BYTES)
                .spawn_scoped(scope, || Self::parse_capped(raw))
                .ok()
                .and_then(|handle| handle.join().ok())
                .flatten()
        });
        let mut view = parsed.unwrap_or_else(|| Self {
            failed: true,
            ..Self::default()
        });
        view.truncated = truncated;
        view
    }

    fn parse_capped(raw: &[u8]) -> Option<Self> {
        let message = MessageParser::new()
            .with_minimal_headers()
            .default_header_text()
            .parse(raw)?;
        let headers = message
            .headers()
            .iter()
            .map(|header| {
                let mut value = match &header.value {
                    HeaderValue::Text(text) => text.to_string(),
                    HeaderValue::TextList(list) => list.join(" "),
                    HeaderValue::Address(address) => address
                        .iter()
                        .map(|addr| match (addr.name(), addr.address()) {
                            (Some(name), Some(address)) => format!("{name} <{address}>"),
                            (name, address) => name.or(address).unwrap_or_default().to_string(),
                        })
                        .collect::<Vec<_>>()
                        .join(", "),
                    _ => raw
                        .get(header.offset_start as usize..header.offset_end as usize)
                        .map(|bytes| {
                            String::from_utf8_lossy(bytes)
                                .trim()
                                .replace(['\r', '\n'], "")
                        })
                        .unwrap_or_default(),
                };
                truncate(&mut value, MAX_HEADER_CHARS);
                (header.name.as_str().to_string(), value)
            })
            .collect();
        let addresses = |list: Option<&mail_parser::Address>| -> Vec<String> {
            list.map(|list| {
                list.iter()
                    .filter_map(|addr| addr.address())
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default()
        };
        // Links come from every text part and the HTML markup (`body_text`
        // flattens HTML and drops href targets), up to the raw cap.
        let mut link_text = String::new();
        for pos in 0..message.text_body_count() {
            if let Some(text) = message.body_text(pos) {
                link_text.push_str(&text);
                link_text.push('\n');
            }
        }
        let mut body = link_text.clone();
        truncate(&mut body, MAX_BODY_CHARS);
        for part in message.html_bodies() {
            if let Some(text) = part.text_contents() {
                link_text.push_str(text);
                link_text.push('\n');
            }
        }
        let mut links_truncated = link_text.len() > MAX_RAW_BYTES;
        truncate(&mut link_text, MAX_RAW_BYTES);
        let (urls, hosts, capped) = links_in(&link_text);
        links_truncated |= capped;
        Some(Self {
            headers,
            from: addresses(message.from()),
            reply_to: addresses(message.reply_to()),
            body,
            urls,
            hosts,
            truncated: false,
            links_truncated,
            skipped: false,
            failed: false,
        })
    }

    /// Values of every header called `name`, compared case-insensitively.
    pub fn header<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.headers
            .iter()
            .filter(move |(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// The domain of an address, without a trailing `>` or dot.
pub fn address_domain(address: &str) -> Option<&str> {
    let (_, domain) = address.rsplit_once('@')?;
    let domain = domain.trim_end_matches(['>', '.']);
    (!domain.is_empty()).then_some(domain)
}

/// The lowercase host of an absolute http or https link.
pub fn url_host(link: &str) -> Option<String> {
    let url = url::Url::parse(link).ok()?;
    match url.host()? {
        url::Host::Domain(domain) => Some(domain.to_ascii_lowercase()),
        _ => None,
    }
}

/// Distinct links (capped for the URI rules), distinct hosts, and whether a cap hit.
fn links_in(text: &str) -> (Vec<String>, Vec<String>, bool) {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    let pattern =
        PATTERN.get_or_init(|| Regex::new(r#"(?i)https?://[^\s<>"'()\[\]]+"#).expect("url regex"));
    let mut urls = Vec::new();
    let mut seen_links = HashSet::new();
    let mut hosts = Vec::new();
    let mut seen_hosts = HashSet::new();
    let mut capped = false;
    for found in pattern.find_iter(text) {
        let link = found.as_str().trim_end_matches(['.', ',', ';']);
        if seen_links.contains(link) {
            continue;
        }
        if seen_links.len() >= MAX_LINKS_SCANNED {
            capped = true;
            break;
        }
        seen_links.insert(link.to_string());
        if urls.len() < MAX_URLS {
            urls.push(link.to_string());
        } else {
            capped = true;
        }
        if let Some(host) = url_host(link) {
            if !seen_hosts.contains(&host) {
                if hosts.len() < MAX_HOSTS {
                    seen_hosts.insert(host.clone());
                    hosts.push(host);
                } else {
                    capped = true;
                }
            }
        }
    }
    (urls, hosts, capped)
}

/// More embedded messages or multiparts than `mail-parser` can safely recurse into.
pub fn too_nested(raw: &[u8]) -> bool {
    static EMBEDDED: OnceLock<BytesRegex> = OnceLock::new();
    static MULTIPART: OnceLock<BytesRegex> = OnceLock::new();
    let embedded =
        EMBEDDED.get_or_init(|| BytesRegex::new(r"(?i)message/(rfc822|global)").expect("regex"));
    let multipart = MULTIPART.get_or_init(|| BytesRegex::new(r"(?i)multipart/").expect("regex"));
    embedded.find_iter(raw).nth(MAX_EMBEDDED_MESSAGES).is_some()
        || multipart.find_iter(raw).nth(MAX_MULTIPARTS).is_some()
}

fn truncate(text: &mut String, max: usize) {
    if text.len() > max {
        let mut end = max;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_senders_body_and_links() {
        let raw = b"From: Pay Desk <pay@c0mmbank.com.au>\r\nReply-To: refunds@example.test\r\nSubject: Refund\r\n\r\nClaim at https://c0mmbank.com.au/login. Thanks\r\n";
        let view = MessageView::parse(raw);
        assert_eq!(view.from, vec!["pay@c0mmbank.com.au"]);
        assert_eq!(view.reply_to, vec!["refunds@example.test"]);
        assert_eq!(view.header("subject").next(), Some("Refund"));
        assert_eq!(view.urls, vec!["https://c0mmbank.com.au/login"]);
        assert_eq!(view.hosts, vec!["c0mmbank.com.au"]);
        assert_eq!(address_domain("<a@ato.gov.au.>"), Some("ato.gov.au"));
    }

    #[test]
    fn encoded_headers_are_decoded() {
        // "You have won a prize" in base64 and quoted-printable encoded words.
        let raw = b"From: =?utf-8?q?Prize_Desk?= <a@example.test>\r\nSubject: =?utf-8?b?WW91IGhhdmUgd29uIGEgcHJpemU=?=\r\nX-Mailer: =?utf-8?q?Bulk_Mail?=\r\n\r\nhi\r\n";
        let view = MessageView::parse(raw);
        assert_eq!(view.header("Subject").next(), Some("You have won a prize"));
        assert_eq!(view.header("x-mailer").next(), Some("Bulk Mail"));
        assert_eq!(
            view.header("from").next(),
            Some("Prize Desk <a@example.test>")
        );
    }

    #[test]
    fn html_hrefs_and_the_sixty_fifth_link_are_kept() {
        let mut body = String::new();
        for i in 0..200 {
            body.push_str(&format!("https://example.test/news/{i}\r\n"));
        }
        let raw = format!(
            "From: a@example.test\r\nSubject: news\r\nMIME-Version: 1.0\r\nContent-Type: multipart/alternative; boundary=b\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\n{body}\r\n--b\r\nContent-Type: text/html\r\n\r\n<a href=\"https://c0mmbank.com.au/login\">Your bank</a>\r\n--b--\r\n"
        );
        let view = MessageView::parse(raw.as_bytes());
        assert!(
            view.hosts.contains(&"c0mmbank.com.au".to_string()),
            "{:?}",
            view.hosts
        );
        assert_eq!(view.hosts.len(), 2);
    }

    #[test]
    fn oversized_input_is_capped() {
        let mut raw = b"From: a@example.test\r\nSubject: big\r\n\r\n".to_vec();
        raw.resize(MAX_RAW_BYTES + 4096, b'a');
        let view = MessageView::parse(&raw);
        assert!(view.truncated && !view.failed);
        assert_eq!(view.header("subject").next(), Some("big"));
        assert!(view.body.len() <= MAX_BODY_CHARS);
    }

    #[test]
    fn deeply_nested_messages_are_refused_before_parsing() {
        // 50,000 levels of message/rfc822 would overflow mail-parser's recursion.
        let mut raw = b"From: a@example.test\r\n".to_vec();
        for _ in 0..50_000 {
            raw.extend_from_slice(b"Content-Type: message/rfc822\r\n\r\n");
        }
        raw.extend_from_slice(b"Subject: inner\r\n\r\nhello\r\n");
        let view = MessageView::parse(&raw);
        assert!(view.skipped && view.headers.is_empty());

        // A message at the bound still parses.
        let mut raw = b"From: a@example.test\r\n".to_vec();
        for _ in 0..MAX_EMBEDDED_MESSAGES {
            raw.extend_from_slice(b"Content-Type: message/rfc822\r\n\r\n");
        }
        raw.extend_from_slice(b"Subject: inner\r\n\r\nhello\r\n");
        assert!(!MessageView::parse(&raw).skipped);
    }

    #[test]
    fn every_host_and_late_links_are_checked() {
        let mut body = String::new();
        for i in 0..600 {
            body.push_str(&format!("https://site{i}.example.test/\r\n"));
        }
        body.push_str("https://c0mmbank.com.au/login\r\n");
        let filler = "x".repeat(300 * 1024);
        let raw = format!(
            "From: a@example.test\r\nSubject: news\r\nMIME-Version: 1.0\r\nContent-Type: multipart/alternative; boundary=b\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\n{body}\r\n--b\r\nContent-Type: text/html\r\n\r\n<p>{filler}</p><a href=\"https://westpak.com.au/x\">pay</a>\r\n--b--\r\n"
        );
        let view = MessageView::parse(raw.as_bytes());
        assert!(view.hosts.contains(&"c0mmbank.com.au".to_string()));
        assert!(view.hosts.contains(&"westpak.com.au".to_string()));
        assert_eq!(view.hosts.len(), 602);
        // More than MAX_URLS distinct links: the URI rules see a capped list.
        assert!(view.links_truncated);
    }

    #[test]
    fn long_header_values_are_capped() {
        let raw = format!(
            "From: a@example.test\r\nSubject: {}\r\n\r\nhi\r\n",
            "w ".repeat(100 * 1024)
        );
        let view = MessageView::parse(raw.as_bytes());
        let subject = view.header("subject").next().unwrap();
        assert!(subject.len() <= MAX_HEADER_CHARS && subject.len() > 1000);
    }
}
