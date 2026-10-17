//! Rewrite http(s) links in the text and HTML parts of a message to
//! `<base_url>/u/<token>`. Only the bytes of rewritten parts change: other
//! parts, boundaries, headers, charsets and transfer encodings are kept.
//! Signed (S/MIME, PGP) and encrypted parts, attachments and attached
//! messages are left alone.
use super::{
    reputation::host_matches,
    token::{Claims, UrlSigner},
    transfer,
};
use encoding_rs::Encoding;
use lol_html::{element, html_content::Element, AsciiCompatibleEncoding, HtmlRewriter};
use mail_parser::{MessageParser, MimeHeaders, PartType};
use std::cell::RefCell;

/// More links than this in one message and the message is left unchanged.
pub const MAX_LINKS: usize = 10_000;
/// Longer links are not rewritten (and counted in a note).
pub const MAX_URL_BYTES: usize = 8 * 1024;
/// Memory the HTML rewriter may use for one part.
const HTML_MEMORY: usize = 32 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RewriteError {
    #[error("message larger than the rewrite limit")]
    TooLarge,
    #[error("message could not be parsed for rewriting")]
    Unparsable,
    #[error("more than {MAX_LINKS} links")]
    TooManyLinks,
}

#[derive(Debug, Default)]
pub struct Rewritten {
    pub message: Vec<u8>,
    /// Links replaced. Zero means `message` equals the input.
    pub links: usize,
    pub notes: Vec<String>,
}

pub struct UrlRewriter {
    signer: UrlSigner,
    base: String,
    base_host: String,
    allow: Vec<String>,
    ttl_secs: u64,
    max_bytes: usize,
}

/// One message's token claims and counters.
struct Ctx<'a> {
    message_id: &'a str,
    expires: u64,
    links: usize,
    too_long: usize,
}

impl UrlRewriter {
    /// `base_url` is the public click service, for example
    /// `https://links.example.com.au`. Links to its host and to `allow`
    /// domains (and their subdomains) are not rewritten.
    pub fn new(
        signer: UrlSigner,
        base_url: &str,
        allow: &[String],
        ttl_secs: u64,
        max_bytes: usize,
    ) -> Result<Self, String> {
        let parsed = url::Url::parse(base_url).map_err(|err| format!("base_url: {err}"))?;
        let base_host = parsed
            .host_str()
            .ok_or("base_url has no host")?
            .to_ascii_lowercase();
        Ok(Self {
            signer,
            base: base_url.trim_end_matches('/').to_string(),
            base_host,
            allow: allow
                .iter()
                .map(|d| d.trim().trim_end_matches('.').to_ascii_lowercase())
                .filter(|d| !d.is_empty())
                .collect(),
            ttl_secs,
            max_bytes,
        })
    }

    pub fn signer(&self) -> &UrlSigner {
        &self.signer
    }

    /// Tokens expire `ttl_secs` after `issued_at` (Unix seconds). The same
    /// input, id and time always give the same bytes.
    pub fn rewrite_message(
        &self,
        raw: &[u8],
        message_id: &str,
        issued_at: u64,
    ) -> Result<Rewritten, RewriteError> {
        if raw.len() > self.max_bytes {
            return Err(RewriteError::TooLarge);
        }
        let message = MessageParser::default()
            .parse(raw)
            .ok_or(RewriteError::Unparsable)?;
        let mut ctx = Ctx {
            message_id,
            expires: issued_at.saturating_add(self.ttl_secs),
            links: 0,
            too_long: 0,
        };
        let mut notes = Vec::new();
        let mut edits: Vec<(usize, usize, Vec<u8>)> = Vec::new();
        let parts = &message.parts;
        let mut seen = vec![false; parts.len()];
        let mut stack = vec![(0usize, false)];
        while let Some((idx, signed)) = stack.pop() {
            let Some(part) = parts.get(idx) else {
                continue;
            };
            if std::mem::replace(&mut seen[idx], true) {
                continue;
            }
            let (ctype, subtype) = part
                .content_type()
                .map(|ct| {
                    (
                        ct.ctype().to_ascii_lowercase(),
                        ct.subtype().unwrap_or("").to_ascii_lowercase(),
                    )
                })
                .unwrap_or_else(|| ("text".into(), "plain".into()));
            let html = match &part.body {
                PartType::Multipart(children) => {
                    let protected =
                        ctype == "multipart" && matches!(subtype.as_str(), "signed" | "encrypted");
                    stack.extend(children.iter().map(|&c| (c as usize, signed || protected)));
                    continue;
                }
                PartType::Html(_) => true,
                PartType::Text(_) if subtype == "plain" => false,
                _ => continue,
            };
            if signed
                || part
                    .content_disposition()
                    .is_some_and(|d| d.is_attachment())
            {
                continue;
            }
            let (header, body, end) = (
                part.offset_header as usize,
                part.offset_body as usize,
                part.offset_end as usize,
            );
            if !(header <= body && body <= end && end <= raw.len()) {
                continue;
            }
            let label = part
                .content_type()
                .and_then(|ct| ct.attribute("charset"))
                .unwrap_or("utf-8");
            let encoding =
                Encoding::for_label(label.trim().as_bytes()).unwrap_or(encoding_rs::WINDOWS_1252);
            let Some(encoding) = AsciiCompatibleEncoding::new(encoding) else {
                notes.push(format!("links in a {label} part not rewritten"));
                continue;
            };
            let cte = part
                .content_transfer_encoding()
                .unwrap_or("7bit")
                .trim()
                .to_ascii_lowercase();
            match self.rewrite_part(
                &raw[header..body],
                &raw[body..end],
                &cte,
                html,
                encoding,
                &mut ctx,
            ) {
                Ok(Some((true, replacement))) => edits.push((header, end, replacement)),
                Ok(Some((false, replacement))) => edits.push((body, end, replacement)),
                Ok(None) => {}
                Err(note) => notes.push(note),
            }
            if ctx.links > MAX_LINKS {
                return Err(RewriteError::TooManyLinks);
            }
        }
        if ctx.too_long > 0 {
            notes.push(format!("{} links too long to rewrite", ctx.too_long));
        }
        if edits.is_empty() {
            return Ok(Rewritten {
                message: raw.to_vec(),
                links: 0,
                notes,
            });
        }
        edits.sort_by_key(|edit| edit.0);
        let mut out = Vec::with_capacity(raw.len() + raw.len() / 2);
        let mut at = 0;
        for (start, end, bytes) in edits {
            if start < at {
                continue;
            }
            out.extend_from_slice(&raw[at..start]);
            out.extend_from_slice(&bytes);
            at = end;
        }
        out.extend_from_slice(&raw[at..]);
        Ok(Rewritten {
            message: out,
            links: ctx.links,
            notes,
        })
    }

    /// The new body, or the new header block and body when the part had to
    /// move to quoted-printable (`true`). `None` when no link changed.
    fn rewrite_part(
        &self,
        headers: &[u8],
        body: &[u8],
        cte: &str,
        html: bool,
        encoding: AsciiCompatibleEncoding,
        ctx: &mut Ctx,
    ) -> Result<Option<(bool, Vec<u8>)>, String> {
        let before = ctx.links;
        let rewrite = |decoded: &[u8], ctx: &mut Ctx| {
            if html {
                self.rewrite_html(decoded, encoding, ctx)
            } else if decoded
                .windows(34)
                .any(|w| w == b"-----BEGIN PGP SIGNED MESSAGE-----")
            {
                Ok(decoded.to_vec())
            } else {
                Ok(self.rewrite_text(decoded, ctx))
            }
        };
        let out = match cte {
            "base64" => {
                let trimmed = body.trim_ascii_end();
                let decoded = transfer::decode_base64(trimmed)
                    .ok_or("undecodable base64 part, links not rewritten")?;
                let mut out = transfer::encode_base64(&rewrite(&decoded, ctx)?);
                out.extend_from_slice(&body[trimmed.len()..]);
                (false, out)
            }
            "quoted-printable" => (
                false,
                transfer::encode_qp(&rewrite(&transfer::decode_qp(body), ctx)?),
            ),
            _ => {
                let rewritten = rewrite(body, ctx)?;
                if transfer::longest_line(&rewritten) <= transfer::MAX_LINE {
                    (false, rewritten)
                } else {
                    // A long link made a line SMTP cannot carry.
                    let mut out = qp_headers(headers)
                        .ok_or("part headers not understood, links not rewritten")?;
                    out.extend_from_slice(&transfer::encode_qp(&rewritten));
                    (true, out)
                }
            }
        };
        Ok((ctx.links > before).then_some(out))
    }

    fn rewrite_html(
        &self,
        html: &[u8],
        encoding: AsciiCompatibleEncoding,
        ctx: &mut Ctx,
    ) -> Result<Vec<u8>, String> {
        let ctx = RefCell::new(ctx);
        let mut out = Vec::with_capacity(html.len() + html.len() / 4);
        let handle = |el: &mut Element| -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            if let Some(href) = el.get_attribute("href") {
                if let Some(link) = self.link(&decode_entities(&href), &mut ctx.borrow_mut()) {
                    el.set_attribute("href", &link)?;
                }
            }
            Ok(())
        };
        let settings = lol_html::Settings::new()
            .append_element_content_handler(element!("a[href]", handle))
            .append_element_content_handler(element!("area[href]", handle))
            .with_encoding(encoding)
            .with_strict(false)
            .with_memory_settings(
                lol_html::MemorySettings::new().with_max_allowed_memory_usage(HTML_MEMORY),
            );
        let mut rewriter = HtmlRewriter::new(settings, |chunk: &[u8]| {
            out.extend_from_slice(chunk);
        });
        let failed =
            |err: lol_html::errors::RewritingError| format!("HTML part not rewritten: {err}");
        rewriter.write(html).map_err(failed)?;
        rewriter.end().map_err(failed)?;
        Ok(out)
    }

    fn rewrite_text(&self, text: &[u8], ctx: &mut Ctx) -> Vec<u8> {
        let mut out = Vec::with_capacity(text.len());
        let (mut i, mut copied) = (0, 0);
        while i < text.len() {
            let Some(end) = link_end(text, i) else {
                i += 1;
                continue;
            };
            let found = std::str::from_utf8(&text[i..end]).ok();
            if let Some(link) = found.and_then(|url| self.link(url, ctx)) {
                out.extend_from_slice(&text[copied..i]);
                out.extend_from_slice(link.as_bytes());
                copied = end;
            }
            i = end;
        }
        out.extend_from_slice(&text[copied..]);
        out
    }

    /// The rewritten link, or `None` when this link is kept. Parsing is the
    /// WHATWG one browsers use, so tabs, newlines and case tricks in the
    /// scheme cannot hide a link.
    fn link(&self, href: &str, ctx: &mut Ctx) -> Option<String> {
        let url = url::Url::parse(href).ok()?;
        if !matches!(url.scheme(), "http" | "https") {
            return None;
        }
        let host = url.host_str()?.to_ascii_lowercase();
        if host == self.base_host || self.allow.iter().any(|d| host_matches(&host, d)) {
            return None;
        }
        if url.as_str().len() > MAX_URL_BYTES {
            ctx.too_long += 1;
            return None;
        }
        ctx.links += 1;
        if ctx.links > MAX_LINKS {
            return None;
        }
        let token = self.signer.sign(&Claims {
            u: url.as_str().to_string(),
            m: ctx.message_id.to_string(),
            e: ctx.expires,
        });
        Some(format!("{}/u/{token}", self.base))
    }
}

/// End of a bare `http://` or `https://` link starting at `i`, without
/// trailing sentence punctuation or an unbalanced closing bracket.
fn link_end(text: &[u8], i: usize) -> Option<usize> {
    let rest = &text[i..];
    let scheme = if starts_with_ignore_case(rest, b"https://") {
        8
    } else if starts_with_ignore_case(rest, b"http://") {
        7
    } else {
        return None;
    };
    if i > 0 && text[i - 1].is_ascii_alphanumeric() {
        return None;
    }
    let start = i + scheme;
    let mut end = start;
    while end < text.len()
        && text[end] > b' '
        && text[end] < 0x7f
        && !matches!(
            text[end],
            b'<' | b'>' | b'"' | b'`' | b'{' | b'}' | b'|' | b'\\' | b'^'
        )
    {
        end += 1;
    }
    while end > start {
        let last = text[end - 1];
        let unbalanced = |open: u8| {
            let span = &text[i..end];
            span.iter().filter(|b| **b == last).count()
                > span.iter().filter(|b| **b == open).count()
        };
        let trim = match last {
            b'.' | b',' | b';' | b':' | b'!' | b'?' | b'\'' | b'*' => true,
            b')' => unbalanced(b'('),
            b']' => unbalanced(b'['),
            _ => false,
        };
        if !trim {
            break;
        }
        end -= 1;
    }
    (end > start).then_some(end)
}

fn starts_with_ignore_case(text: &[u8], prefix: &[u8]) -> bool {
    text.len() >= prefix.len() && text[..prefix.len()].eq_ignore_ascii_case(prefix)
}

/// The part's header block with any Content-Transfer-Encoding replaced by
/// quoted-printable. `None` when the block does not end in a blank line.
fn qp_headers(block: &[u8]) -> Option<Vec<u8>> {
    let crlf = block.ends_with(b"\r\n\r\n");
    if !crlf && !block.ends_with(b"\n\n") {
        return None;
    }
    let eol: &[u8] = if crlf { b"\r\n" } else { b"\n" };
    let fields = &block[..block.len() - eol.len()];
    let mut out = Vec::with_capacity(block.len() + 48);
    let mut dropping = false;
    for line in fields.split_inclusive(|b| *b == b'\n') {
        let folded = line.first().is_some_and(|b| matches!(b, b' ' | b'\t'));
        if !folded {
            dropping = starts_with_ignore_case(line, b"content-transfer-encoding:");
        }
        if !dropping {
            out.extend_from_slice(line);
        }
    }
    out.extend_from_slice(b"Content-Transfer-Encoding: quoted-printable");
    out.extend_from_slice(eol);
    out.extend_from_slice(eol);
    Some(out)
}

/// Character references in an attribute value: named ones a link uses and
/// numeric ones. Anything else is kept as written.
fn decode_entities(value: &str) -> String {
    if !value.contains('&') {
        return value.to_string();
    }
    let mut out = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(at) = rest.find('&') {
        out.push_str(&rest[..at]);
        rest = &rest[at..];
        let end = rest[1..]
            .find(|c: char| !c.is_ascii_alphanumeric() && c != '#')
            .map(|n| n + 1)
            .unwrap_or(rest.len());
        let name = &rest[1..end];
        let decoded = match name {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            "colon" => Some(':'),
            "sol" => Some('/'),
            "Tab" => Some('\t'),
            "NewLine" => Some('\n'),
            _ => name.strip_prefix('#').and_then(|n| {
                let code = match n.strip_prefix(['x', 'X']) {
                    Some(hex) => u32::from_str_radix(hex, 16).ok(),
                    None => n.parse().ok(),
                };
                code.and_then(char::from_u32)
            }),
        };
        match decoded {
            Some(c) => {
                out.push(c);
                rest = &rest[end..];
                rest = rest.strip_prefix(';').unwrap_or(rest);
            }
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rewriter() -> UrlRewriter {
        UrlRewriter::new(
            UrlSigner::new(vec![9; 32]).unwrap(),
            "https://links.example.com.au/",
            &["Trusted.example".into()],
            86_400,
            1024 * 1024,
        )
        .unwrap()
    }

    fn ctx() -> Ctx<'static> {
        Ctx {
            message_id: "m1",
            expires: 10,
            links: 0,
            too_long: 0,
        }
    }

    #[test]
    fn urls_text_links_end_before_punctuation() {
        let text = b"See https://a.test/x. Or (http://b.test/y_(z)) and \"HTTPS://c.test\", mailto:x@y.test";
        let found: Vec<&str> = (0..text.len())
            .filter_map(|i| link_end(text, i).map(|end| &text[i..end]))
            .map(|s| std::str::from_utf8(s).unwrap())
            .collect();
        assert_eq!(
            found,
            ["https://a.test/x", "http://b.test/y_(z)", "HTTPS://c.test"]
        );
        let out = rewriter().rewrite_text(text, &mut ctx());
        let out = String::from_utf8(out).unwrap();
        assert_eq!(
            out.matches("https://links.example.com.au/u/").count(),
            3,
            "{out}"
        );
        assert!(out.ends_with(", mailto:x@y.test"));
    }

    #[test]
    fn urls_html_obfuscated_schemes_are_still_rewritten() {
        let html = br#"<a href=" ht&#9;tps://evil.test/a?b=1&amp;c=2 ">x</a><a href="javascript:alert(1)">j</a><a href="https://www.trusted.example/">t</a><AREA HREF='HTTP://Evil.test'>"#;
        let mut c = ctx();
        let out = rewriter()
            .rewrite_html(
                html,
                AsciiCompatibleEncoding::new(encoding_rs::UTF_8).unwrap(),
                &mut c,
            )
            .unwrap();
        let out = String::from_utf8(out).unwrap();
        assert_eq!(c.links, 2, "{out}");
        assert!(out.contains("javascript:alert(1)"));
        assert!(out.contains("https://www.trusted.example/"));
        assert!(!out.contains("evil.test"));
    }

    #[test]
    fn urls_entities_decode() {
        assert_eq!(
            decode_entities("a&amp;b&#38;c&#x26;d&bogus;e&"),
            "a&b&c&d&bogus;e&"
        );
        assert_eq!(decode_entities("https&colon;&sol;&sol;x"), "https://x");
    }

    #[test]
    fn urls_qp_headers_replace_transfer_encoding() {
        let block =
            b"Content-Type: text/plain\r\nContent-Transfer-Encoding:\r\n 7bit\r\nX-A: b\r\n\r\n";
        assert_eq!(
            qp_headers(block).unwrap(),
            b"Content-Type: text/plain\r\nX-A: b\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n"
        );
        assert!(qp_headers(b"Content-Type: text/plain\r\n").is_none());
    }
}
