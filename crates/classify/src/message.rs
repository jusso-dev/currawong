//! The parts of a message the classifiers read: headers, sender addresses,
//! body text and links. This parses headers and text bodies in-process;
//! attachments stay with the isolated parser worker.
use mail_parser::MessageParser;
use regex::Regex;
use std::sync::OnceLock;

/// Body text kept for scoring. Longer bodies are cut, not rejected.
const MAX_BODY_CHARS: usize = 64 * 1024;
const MAX_URLS: usize = 64;

#[derive(Debug, Clone, Default)]
pub struct MessageView {
    /// Header names and unfolded raw values, in message order.
    pub headers: Vec<(String, String)>,
    pub from: Vec<String>,
    pub reply_to: Vec<String>,
    pub body: String,
    pub urls: Vec<String>,
}

impl MessageView {
    pub fn parse(raw: &[u8]) -> Self {
        let Some(message) = MessageParser::default().parse(raw) else {
            return Self::default();
        };
        let headers = message
            .headers_raw()
            .map(|(name, value)| (name.to_string(), value.trim().replace(['\r', '\n'], "")))
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
        let urls = urls_in(&body);
        Self {
            headers,
            from: addresses(message.from()),
            reply_to: addresses(message.reply_to()),
            body,
            urls,
        }
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

/// The host of an absolute http or https link.
pub fn url_host(link: &str) -> Option<String> {
    let url = url::Url::parse(link).ok()?;
    match url.host()? {
        url::Host::Domain(domain) => Some(domain.to_string()),
        _ => None,
    }
}

fn urls_in(text: &str) -> Vec<String> {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    let pattern =
        PATTERN.get_or_init(|| Regex::new(r#"(?i)https?://[^\s<>"'()\[\]]+"#).expect("url regex"));
    let mut urls: Vec<String> = pattern
        .find_iter(text)
        .take(MAX_URLS)
        .map(|found| found.as_str().trim_end_matches(['.', ',', ';']).to_string())
        .collect();
    urls.sort();
    urls.dedup();
    urls
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
        assert_eq!(url_host(&view.urls[0]).as_deref(), Some("c0mmbank.com.au"));
        assert_eq!(address_domain("<a@ato.gov.au.>"), Some("ato.gov.au"));
    }
}
