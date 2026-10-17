//! The parts of a message the classifiers read: decoded headers, sender
//! addresses, body text and links.
//!
//! This parses in the supervisor process, not in an isolated parser worker
//! (ADR 0002). Until extraction moves into the worker response, the input is
//! capped and a parser panic yields an empty view instead of taking down the
//! pipeline.
use mail_parser::{HeaderValue, MessageParser};
use regex::Regex;
use std::{collections::HashSet, sync::OnceLock};

/// Bytes of the raw message that are parsed. Later bytes are not classified.
pub const MAX_RAW_BYTES: usize = 4 * 1024 * 1024;
/// Body text kept for scoring. Longer bodies are cut, not rejected.
const MAX_BODY_CHARS: usize = 64 * 1024;
/// HTML scanned for links, across all HTML parts.
const MAX_HTML_CHARS: usize = 256 * 1024;
/// Distinct links and distinct link hosts kept. Hosts are gathered from every
/// link found, so many links to one site cannot push another host out.
const MAX_URLS: usize = 512;
const MAX_HOSTS: usize = 512;

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
    /// The parser found no headers or panicked.
    pub failed: bool,
}

impl MessageView {
    pub fn parse(raw: &[u8]) -> Self {
        let truncated = raw.len() > MAX_RAW_BYTES;
        let raw = &raw[..raw.len().min(MAX_RAW_BYTES)];
        let parsed = std::panic::catch_unwind(|| Self::parse_capped(raw));
        let mut view = match parsed {
            Ok(Some(view)) => view,
            Ok(None) | Err(_) => Self {
                failed: true,
                ..Self::default()
            },
        };
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
                let value = match &header.value {
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
        let mut body = String::new();
        for pos in 0..message.text_body_count() {
            if let Some(text) = message.body_text(pos) {
                body.push_str(&text);
                body.push('\n');
            }
            if body.len() >= MAX_BODY_CHARS {
                break;
            }
        }
        truncate(&mut body, MAX_BODY_CHARS);
        // `body_text` flattens HTML and drops href targets, so scan the markup too.
        let mut html = String::new();
        for part in message.html_bodies() {
            if let Some(text) = part.text_contents() {
                html.push_str(text);
                html.push('\n');
            }
            if html.len() >= MAX_HTML_CHARS {
                break;
            }
        }
        truncate(&mut html, MAX_HTML_CHARS);
        let (urls, hosts) = links_in(&[&body, &html]);
        Some(Self {
            headers,
            from: addresses(message.from()),
            reply_to: addresses(message.reply_to()),
            body,
            urls,
            hosts,
            truncated: false,
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

fn links_in(texts: &[&str]) -> (Vec<String>, Vec<String>) {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    let pattern =
        PATTERN.get_or_init(|| Regex::new(r#"(?i)https?://[^\s<>"'()\[\]]+"#).expect("url regex"));
    let mut urls = Vec::new();
    let mut seen_urls = HashSet::new();
    let mut hosts = Vec::new();
    let mut seen_hosts = HashSet::new();
    for found in texts.iter().flat_map(|text| pattern.find_iter(text)) {
        let link = found.as_str().trim_end_matches(['.', ',', ';']);
        if urls.len() < MAX_URLS && seen_urls.insert(link.to_string()) {
            urls.push(link.to_string());
        }
        if hosts.len() < MAX_HOSTS {
            if let Some(host) = url_host(link) {
                if seen_hosts.insert(host.clone()) {
                    hosts.push(host);
                }
            }
        }
        if urls.len() >= MAX_URLS && hosts.len() >= MAX_HOSTS {
            break;
        }
    }
    (urls, hosts)
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
}
