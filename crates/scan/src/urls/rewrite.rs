//! Rewrite http(s) links in the text and HTML parts of a message to
//! `<base_url>/u/<token>`. Only the bytes of rewritten parts change: other
//! parts, boundaries, headers, charsets and transfer encodings are kept.
//! Attachments and attached messages are left alone. Signed parts are left
//! alone too, and so are parts this code cannot read: each such part that
//! holds a link is counted in `Rewritten::skipped` so policy can act.
use super::{
    reputation::{host_matches, normalise_domain},
    token::{Claims, UrlSigner},
    transfer,
};
use encoding_rs::Encoding;
use lol_html::{element, html_content::Element, AsciiCompatibleEncoding, HtmlRewriter};
use mail_parser::{MessageParser, MessagePart, MimeHeaders, PartType};
use std::cell::RefCell;
use url::Url;

/// More links than this in one message and the message is left unchanged.
pub const MAX_LINKS: usize = 10_000;
/// Longer links are not rewritten (and counted as skipped).
pub const MAX_URL_BYTES: usize = 8 * 1024;
/// Memory the HTML rewriter may use for one part.
const HTML_MEMORY: usize = 32 * 1024 * 1024;
/// More `multipart/` or attached-message headers than this and the message is
/// not parsed in process: `mail-parser` recurses into nesting, and a stack
/// overflow would abort the daemon. The same limits as the classify stage.
const MAX_MULTIPARTS: usize = 512;
const MAX_EMBEDDED_MESSAGES: usize = 32;
/// `multipart/signed` protocols whose second part is a detached signature.
const SIGNATURE_PROTOCOLS: &[&str] = &[
    "application/pkcs7-signature",
    "application/x-pkcs7-signature",
    "application/pgp-signature",
];

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RewriteError {
    #[error("message larger than the rewrite limit")]
    TooLarge,
    #[error("message could not be parsed for rewriting")]
    Unparsable,
    #[error("more than {MAX_LINKS} links")]
    TooManyLinks,
    #[error("message nested too deeply to parse safely")]
    TooNested,
}

#[derive(Debug, Default)]
pub struct Rewritten {
    pub message: Vec<u8>,
    /// Links replaced. Zero means `message` equals the input.
    pub links: usize,
    /// Parts with links left as they were (signed, unreadable charset or
    /// encoding, HTML the rewriter gave up on) plus over-long links.
    pub skipped: usize,
    pub notes: Vec<String>,
}

/// Who and when the tokens in one message are for.
#[derive(Debug, Clone, Copy)]
pub struct Delivery<'a> {
    pub message_id: &'a str,
    /// The recipients of this copy, comma separated. May be empty.
    pub recipient: &'a str,
    /// Arrival time, Unix seconds. Tokens expire `ttl_secs` later.
    pub issued_at: u64,
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
    delivery: Delivery<'a>,
    expires: u64,
    links: usize,
    too_long: usize,
    /// Clear-signed PGP spans with links in them.
    signed_text: usize,
    /// Relative links with no `<base href>` to resolve them.
    relative: usize,
}

/// What happened to one part.
enum Part {
    Unchanged,
    /// Replace the body (`false`) or the header block and body (`true`).
    Replace(bool, Vec<u8>),
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
        let parsed = Url::parse(base_url).map_err(|err| format!("base_url: {err}"))?;
        let base_host = parsed
            .host_str()
            .ok_or("base_url has no host")?
            .to_ascii_lowercase();
        Ok(Self {
            signer,
            base: base_url.trim_end_matches('/').to_string(),
            base_host,
            allow: allow.iter().filter_map(|d| normalise_domain(d)).collect(),
            ttl_secs,
            max_bytes,
        })
    }

    pub fn signer(&self) -> &UrlSigner {
        &self.signer
    }

    /// The same input and delivery always give the same bytes.
    pub fn rewrite_message(
        &self,
        raw: &[u8],
        delivery: &Delivery,
    ) -> Result<Rewritten, RewriteError> {
        if raw.len() > self.max_bytes {
            return Err(RewriteError::TooLarge);
        }
        if too_nested(raw) {
            return Err(RewriteError::TooNested);
        }
        let message = MessageParser::default()
            .parse(raw)
            .ok_or(RewriteError::Unparsable)?;
        let mut ctx = Ctx {
            delivery: *delivery,
            expires: delivery.issued_at.saturating_add(self.ttl_secs),
            links: 0,
            too_long: 0,
            signed_text: 0,
            relative: 0,
        };
        let mut out = Rewritten::default();
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
            let subtype = part
                .content_type()
                .and_then(|ct| ct.subtype())
                .unwrap_or("plain")
                .to_ascii_lowercase();
            let html = match &part.body {
                PartType::Multipart(children) => {
                    let protected = is_signed(part, children, parts, raw);
                    stack.extend(children.iter().map(|&c| (c as usize, signed || protected)));
                    continue;
                }
                PartType::Html(_) => true,
                PartType::Text(_) if subtype == "x-amp-html" => true,
                PartType::Text(_) if subtype == "plain" => false,
                _ => continue,
            };
            if part
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
            let cte = part
                .content_transfer_encoding()
                .unwrap_or("7bit")
                .trim()
                .to_ascii_lowercase();
            if signed {
                if decode(&raw[body..end], &cte).is_none_or(|text| has_link(&text)) {
                    out.skipped += 1;
                    out.notes
                        .push("links in a signed part not rewritten".into());
                }
                continue;
            }
            let label = part
                .content_type()
                .and_then(|ct| ct.attribute("charset"))
                .unwrap_or("utf-8");
            let encoding =
                Encoding::for_label(label.trim().as_bytes()).unwrap_or(encoding_rs::WINDOWS_1252);
            let Some(encoding) = AsciiCompatibleEncoding::new(encoding) else {
                out.skipped += 1;
                out.notes
                    .push(format!("links in a {label} part not rewritten"));
                continue;
            };
            match self.rewrite_part(
                &raw[header..body],
                &raw[body..end],
                &cte,
                html,
                encoding,
                &mut ctx,
            ) {
                Ok(Part::Replace(true, bytes)) => edits.push((header, end, bytes)),
                Ok(Part::Replace(false, bytes)) => edits.push((body, end, bytes)),
                Ok(Part::Unchanged) => {}
                Err(note) => {
                    out.skipped += 1;
                    out.notes.push(note);
                }
            }
            if ctx.links > MAX_LINKS {
                return Err(RewriteError::TooManyLinks);
            }
        }
        for (count, what) in [
            (ctx.too_long, "links too long to rewrite"),
            (ctx.signed_text, "PGP signed texts with links not rewritten"),
            (ctx.relative, "relative links with no base not rewritten"),
        ] {
            if count > 0 {
                out.skipped += count;
                out.notes.push(format!("{count} {what}"));
            }
        }
        if edits.is_empty() {
            out.message = raw.to_vec();
            return Ok(out);
        }
        edits.sort_by_key(|edit| edit.0);
        let mut message = Vec::with_capacity(raw.len() + raw.len() / 2);
        let mut at = 0;
        for (start, end, bytes) in edits {
            if start < at {
                continue;
            }
            message.extend_from_slice(&raw[at..start]);
            message.extend_from_slice(&bytes);
            at = end;
        }
        message.extend_from_slice(&raw[at..]);
        out.message = message;
        out.links = ctx.links;
        Ok(out)
    }

    /// `Err` with a note when the part has links that could not be rewritten.
    fn rewrite_part(
        &self,
        headers: &[u8],
        body: &[u8],
        cte: &str,
        html: bool,
        encoding: AsciiCompatibleEncoding,
        ctx: &mut Ctx,
    ) -> Result<Part, String> {
        let before = ctx.links;
        let eol: &[u8] = if body.contains(&b'\r') || headers.ends_with(b"\r\n\r\n") {
            b"\r\n"
        } else {
            b"\n"
        };
        let rewrite = |decoded: &[u8], ctx: &mut Ctx| {
            if html {
                return self.rewrite_html(decoded, encoding, ctx);
            }
            // Only the clear-signed span is left alone: text before the
            // header or after the signature is not covered by it.
            let Some((start, end)) = pgp_signed(decoded) else {
                return Ok(self.rewrite_text(decoded, ctx));
            };
            if has_link(&decoded[start..end]) {
                ctx.signed_text += 1;
            }
            let mut out = self.rewrite_text(&decoded[..start], ctx);
            out.extend_from_slice(&decoded[start..end]);
            out.extend_from_slice(&self.rewrite_text(&decoded[end..], ctx));
            Ok(out)
        };
        let out = match cte {
            "base64" => {
                let trimmed = body.trim_ascii_end();
                let decoded = transfer::decode_base64(trimmed)
                    .ok_or("undecodable base64 part, links not rewritten")?;
                let mut out = transfer::encode_base64(&rewrite(&decoded, ctx)?, eol);
                out.extend_from_slice(&body[trimmed.len()..]);
                Part::Replace(false, out)
            }
            "quoted-printable" => Part::Replace(
                false,
                transfer::encode_qp(&rewrite(&transfer::decode_qp(body), ctx)?, eol),
            ),
            _ => {
                let rewritten = rewrite(body, ctx)?;
                if transfer::longest_line(&rewritten) <= transfer::MAX_LINE {
                    Part::Replace(false, rewritten)
                } else {
                    // A long link made a line SMTP cannot carry.
                    let mut out = qp_headers(headers)
                        .ok_or("part headers not understood, links not rewritten")?;
                    out.extend_from_slice(&transfer::encode_qp(&rewritten, eol));
                    Part::Replace(true, out)
                }
            }
        };
        Ok(if ctx.links > before {
            out
        } else {
            Part::Unchanged
        })
    }

    /// Rewrites `href`, `xlink:href` (SVG) and `formaction` on any element
    /// (so VML buttons such as `<v:roundrect href>` too) and `<form action>`.
    /// `<link>` (style sheets) and `<base>` are left alone. Relative links are
    /// resolved against the first `<base href>`, wherever it is, as a browser
    /// does; protocol-relative ones (`//host/`) as https. A relative link
    /// with no base is counted as skipped.
    fn rewrite_html(
        &self,
        html: &[u8],
        encoding: AsciiCompatibleEncoding,
        ctx: &mut Ctx,
    ) -> Result<Vec<u8>, String> {
        let failed =
            |err: lol_html::errors::RewritingError| format!("HTML part not rewritten: {err}");
        let settings = || {
            lol_html::Settings::new()
                .with_encoding(encoding)
                .with_strict(false)
                .with_memory_settings(
                    lol_html::MemorySettings::new().with_max_allowed_memory_usage(HTML_MEMORY),
                )
        };
        let base: RefCell<Option<Url>> = RefCell::new(None);
        let find_base = settings().append_element_content_handler(element!("base[href]", |el| {
            let mut base = base.borrow_mut();
            if base.is_none() {
                let href = decode_entities(&el.get_attribute("href").unwrap_or_default());
                *base = Url::parse(&href)
                    .ok()
                    .filter(|url| matches!(url.scheme(), "http" | "https"));
            }
            Ok(())
        }));
        {
            let mut scan = HtmlRewriter::new(find_base, |_: &[u8]| {});
            scan.write(html).map_err(failed)?;
            scan.end().map_err(failed)?;
        }
        let base = base.borrow().clone();
        let ctx = RefCell::new(ctx);
        let mut out = Vec::with_capacity(html.len() + html.len() / 4);
        let attr = |el: &mut Element,
                    name: &str|
         -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            let Some(value) = el.get_attribute(name) else {
                return Ok(());
            };
            let href = decode_entities(&value);
            let url = resolve(&href, base.as_ref());
            if url.is_none() && base.is_none() && is_relative(&href) {
                ctx.borrow_mut().relative += 1;
            }
            if let Some(link) = url.and_then(|url| self.link(url, &mut ctx.borrow_mut())) {
                el.set_attribute(name, &link)?;
            }
            Ok(())
        };
        let rewrite = settings().append_element_content_handler(element!("*", |el| {
            match el.tag_name().as_str() {
                "base" | "link" => return Ok(()),
                "form" => attr(el, "action")?,
                _ => {}
            }
            attr(el, "href")?;
            attr(el, "xlink:href")?;
            attr(el, "formaction")
        }));
        let mut rewriter = HtmlRewriter::new(rewrite, |chunk: &[u8]| {
            out.extend_from_slice(chunk);
        });
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
            let found = std::str::from_utf8(&text[i..end])
                .ok()
                .and_then(|url| Url::parse(url).ok());
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

    /// The rewritten link, or `None` when this link is kept.
    fn link(&self, url: Url, ctx: &mut Ctx) -> Option<String> {
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
            m: ctx.delivery.message_id.to_string(),
            r: ctx.delivery.recipient.to_string(),
            t: ctx.delivery.issued_at,
            e: ctx.expires,
        });
        Some(format!("{}/u/{token}", self.base))
    }
}

/// The URL a browser opens for `href`. Parsing is the WHATWG one, so tabs,
/// newlines, backslashes and case tricks in the scheme cannot hide a link.
/// A relative link is resolved against `base`, or dropped without one; a
/// protocol-relative one without a base is taken as https.
fn resolve(href: &str, base: Option<&Url>) -> Option<Url> {
    match Url::parse(href) {
        Ok(url) => Some(url),
        Err(url::ParseError::RelativeUrlWithoutBase) => match base {
            Some(base) => base.join(href).ok(),
            None => {
                let probe = Url::parse("https://relative.invalid/").ok()?;
                let url = probe.join(href).ok()?;
                (url.host_str() != Some("relative.invalid")).then_some(url)
            }
        },
        Err(_) => None,
    }
}

/// A relative reference that goes somewhere once resolved: not empty and not
/// a fragment of the same document.
fn is_relative(href: &str) -> bool {
    let href = href.trim();
    !href.is_empty()
        && !href.starts_with('#')
        && matches!(
            Url::parse(href),
            Err(url::ParseError::RelativeUrlWithoutBase)
        )
}

/// A `multipart/signed` whose protocol names a detached signature and whose
/// second part is that signature and parses as one: a CMS SignedData
/// structure for S/MIME, an OpenPGP signature packet for PGP. The signature
/// itself is not verified. A wrapper with junk in the signature part does not
/// exempt its links.
fn is_signed(part: &MessagePart, children: &[u32], parts: &[MessagePart], raw: &[u8]) -> bool {
    let Some(ct) = part.content_type() else {
        return false;
    };
    let signed = ct.ctype().eq_ignore_ascii_case("multipart")
        && ct
            .subtype()
            .is_some_and(|s| s.eq_ignore_ascii_case("signed"));
    let protocol = ct
        .attribute("protocol")
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if !signed || !SIGNATURE_PROTOCOLS.contains(&protocol.as_str()) || children.len() != 2 {
        return false;
    }
    let Some(sig) = parts.get(children[1] as usize) else {
        return false;
    };
    let matches = sig.content_type().is_some_and(|ct| {
        format!("{}/{}", ct.ctype(), ct.subtype().unwrap_or("")).eq_ignore_ascii_case(&protocol)
    });
    let (body, end) = (sig.offset_body as usize, sig.offset_end as usize);
    if !matches || body > end || end > raw.len() {
        return false;
    }
    let cte = sig
        .content_transfer_encoding()
        .unwrap_or("7bit")
        .trim()
        .to_ascii_lowercase();
    let Some(bytes) = decode(&raw[body..end], &cte) else {
        return false;
    };
    if protocol.ends_with("pgp-signature") {
        pgp_signature(&bytes)
    } else {
        cms_signed_data(&bytes)
    }
}

/// DER or BER `ContentInfo` with content type signedData (1.2.840.113549.1.7.2).
fn cms_signed_data(der: &[u8]) -> bool {
    const SIGNED_DATA: &[u8] = &[
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02,
    ];
    if der.first() != Some(&0x30) || der.len() < 2 + SIGNED_DATA.len() {
        return false;
    }
    let (header, length) = match der[1] {
        // Indefinite length (BER), common from Outlook.
        0x80 => (2, None),
        n if n < 0x80 => (2, Some(n as usize)),
        n => {
            let count = (n & 0x7f) as usize;
            if count > 4 || der.len() < 2 + count {
                return false;
            }
            let len = der[2..2 + count]
                .iter()
                .fold(0usize, |acc, b| acc << 8 | *b as usize);
            (2 + count, Some(len))
        }
    };
    let fits = length.is_none_or(|len| header + len <= der.len() && len > SIGNED_DATA.len());
    fits && der[header..].starts_with(SIGNED_DATA)
}

/// An OpenPGP signature packet (tag 2), ASCII armoured or binary.
fn pgp_signature(bytes: &[u8]) -> bool {
    let packet = match armoured(bytes, b"-----BEGIN PGP SIGNATURE-----") {
        Some(decoded) => decoded,
        None => bytes.to_vec(),
    };
    let Some(&first) = packet.first() else {
        return false;
    };
    let tag = if first & 0x80 == 0 {
        return false;
    } else if first & 0x40 != 0 {
        first & 0x3f
    } else {
        (first >> 2) & 0x0f
    };
    tag == 2 && packet.len() > 8
}

/// The base64 body of an ASCII armour block starting with `begin`: header
/// lines up to a blank line, then base64 up to the `=` checksum or the end
/// line.
fn armoured(text: &[u8], begin: &[u8]) -> Option<Vec<u8>> {
    let at = text.windows(begin.len()).position(|w| w == begin)?;
    let mut lines = text[at + begin.len()..]
        .split(|b| *b == b'\n')
        .map(|line| line.trim_ascii())
        .skip(1);
    for line in lines.by_ref() {
        if line.is_empty() {
            break;
        }
        if !line.contains(&b':') {
            return None;
        }
    }
    let mut body = Vec::new();
    for line in lines {
        if line.starts_with(b"=") || line.starts_with(b"-----") {
            return transfer::decode_base64(&body);
        }
        body.extend_from_slice(line);
    }
    None
}

/// The span of clear-signed PGP text, from the header line to the end of a
/// signature block that parses as a signature packet.
fn pgp_signed(text: &[u8]) -> Option<(usize, usize)> {
    let find = |needle: &[u8], from: usize| {
        text.get(from..)?
            .windows(needle.len())
            .position(|w| w == needle)
            .map(|at| at + from)
    };
    let start = find(b"-----BEGIN PGP SIGNED MESSAGE-----", 0)?;
    if start != 0 && text[start - 1] != b'\n' {
        return None;
    }
    let signature = find(b"-----BEGIN PGP SIGNATURE-----", start)?;
    let end_marker = b"-----END PGP SIGNATURE-----";
    let end = find(end_marker, signature)? + end_marker.len();
    pgp_signature(&text[signature..end]).then_some((start, end))
}

/// More embedded messages or multiparts than `mail-parser` can safely
/// recurse into. A plain byte scan, so it cannot itself be driven deep.
pub fn too_nested(raw: &[u8]) -> bool {
    let count = |needle: &[u8], limit: usize| {
        raw.windows(needle.len())
            .filter(|w| w.eq_ignore_ascii_case(needle))
            .nth(limit)
            .is_some()
    };
    count(b"multipart/", MAX_MULTIPARTS)
        || count(b"message/rfc822", MAX_EMBEDDED_MESSAGES)
        || count(b"message/global", MAX_EMBEDDED_MESSAGES)
}

fn decode(body: &[u8], cte: &str) -> Option<Vec<u8>> {
    match cte {
        "base64" => transfer::decode_base64(body.trim_ascii_end()),
        "quoted-printable" => Some(transfer::decode_qp(body)),
        _ => Some(body.to_vec()),
    }
}

/// Anything that could be a web link, in text or markup.
fn has_link(text: &[u8]) -> bool {
    text.windows(5).any(|w| w.eq_ignore_ascii_case(b"http:"))
        || text.windows(6).any(|w| w.eq_ignore_ascii_case(b"https:"))
        || text.windows(2).any(|w| w == b"//")
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

/// Character references in an attribute value, decoded as a browser does
/// for the ones a link can use: numeric references with or without `;`,
/// `&amp;` `&lt;` `&gt;` `&quot;` (also without `;` unless `=` or a letter
/// follows, the legacy rule) and a few named ones that need `;`. Anything
/// else is kept as written.
fn decode_entities(value: &str) -> String {
    if !value.contains('&') {
        return value.to_string();
    }
    let mut out = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(at) = rest.find('&') {
        out.push_str(&rest[..at]);
        rest = &rest[at + 1..];
        let (decoded, used) = if let Some(num) = rest.strip_prefix('#') {
            let (hex, digits) = match num.strip_prefix(['x', 'X']) {
                Some(hex) => (true, hex),
                None => (false, num),
            };
            let len = digits
                .find(|c: char| {
                    !(if hex {
                        c.is_ascii_hexdigit()
                    } else {
                        c.is_ascii_digit()
                    })
                })
                .unwrap_or(digits.len());
            let code = match len {
                0 => None,
                // Overlong references are U+FFFD in a browser too.
                _ => Some(
                    u32::from_str_radix(&digits[..len], if hex { 16 } else { 10 })
                        .ok()
                        .and_then(char::from_u32)
                        .filter(|c| *c != '\0')
                        .unwrap_or('\u{FFFD}'),
                ),
            };
            (code, num.len() - digits.len() + 1 + len)
        } else {
            let len = rest
                .find(|c: char| !c.is_ascii_alphanumeric())
                .unwrap_or(rest.len());
            let name = &rest[..len];
            let semicolon = rest[len..].starts_with(';');
            let legacy_ok = semicolon || !rest[len..].starts_with('=');
            let c = match name {
                "amp" if legacy_ok => Some('&'),
                "lt" if legacy_ok => Some('<'),
                "gt" if legacy_ok => Some('>'),
                "quot" if legacy_ok => Some('"'),
                "apos" if semicolon => Some('\''),
                "colon" if semicolon => Some(':'),
                "sol" if semicolon => Some('/'),
                "period" if semicolon => Some('.'),
                "Tab" if semicolon => Some('\t'),
                "NewLine" if semicolon => Some('\n'),
                _ => None,
            };
            (c, len)
        };
        match decoded {
            Some(c) => {
                out.push(c);
                rest = &rest[used..];
                rest = rest.strip_prefix(';').unwrap_or(rest);
            }
            None => out.push('&'),
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
            delivery: Delivery {
                message_id: "m1",
                recipient: "r@example.test",
                issued_at: 0,
            },
            expires: 10,
            links: 0,
            too_long: 0,
            signed_text: 0,
            relative: 0,
        }
    }

    fn html(input: &[u8]) -> (String, usize) {
        let mut c = ctx();
        let out = rewriter()
            .rewrite_html(
                input,
                AsciiCompatibleEncoding::new(encoding_rs::UTF_8).unwrap(),
                &mut c,
            )
            .unwrap();
        (String::from_utf8(out).unwrap(), c.links)
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
        let (out, links) = html(
            br#"<a href=" ht&#9;tps://evil.test/a?b=1&amp;c=2 ">x</a><a href="javascript:alert(1)">j</a><a href="https://www.trusted.example/">t</a><AREA HREF='HTTP://Evil.test'><a href="&#104ttps://evil.test/">n</a><a href="&#x68;ttps&#58//evil.test/">h</a>"#,
        );
        assert_eq!(links, 4, "{out}");
        assert!(out.contains("javascript:alert(1)"));
        assert!(out.contains("https://www.trusted.example/"));
        assert!(!out.contains("evil.test"), "{out}");
    }

    #[test]
    fn urls_html_relative_base_form_and_svg_links_are_rewritten() {
        let (out, links) = html(
            br#"<a href="//evil.test/a">p</a><a href="\\evil.test\b">b</a><a href="/local">l</a><form action="https://evil.test/post"></form><svg><a xlink:href="https://evil.test/svg"><text>s</text></a></svg>"#,
        );
        assert_eq!(links, 4, "{out}");
        assert!(out.contains(r#"href="/local""#), "{out}");
        assert!(!out.contains("evil.test"), "{out}");
        let (out, links) = html(
            br##"<head><base href="https://evil.test/dir/"></head><a href="page">r</a><a href="#top">t</a>"##,
        );
        assert_eq!(links, 2, "{out}");
        assert_eq!(out.matches("links.example.com.au/u/").count(), 2);
    }

    #[test]
    fn urls_entities_decode_like_a_browser() {
        assert_eq!(
            decode_entities("a&amp;b&#38;c&#x26;d&bogus;e&"),
            "a&b&c&d&bogus;e&"
        );
        assert_eq!(decode_entities("https&colon;&sol;&sol;x"), "https://x");
        assert_eq!(decode_entities("&#104ttp&#x3a//a&#46b"), "http://a.b");
        // The legacy rule: no `;` and a letter or `=` next means no reference.
        assert_eq!(
            decode_entities("?a=1&ampb=2&amp=3&amp x"),
            "?a=1&ampb=2&amp=3& x"
        );
        assert_eq!(
            decode_entities("&#0;&#99999999;&#x;"),
            "\u{FFFD}\u{FFFD}&#x;"
        );
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

    #[test]
    fn urls_inline_pgp_needs_a_signature_packet() {
        let signed = b"x\n-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nhi\n-----BEGIN PGP SIGNATURE-----\n\niQAQAQIDBAUGBwgJCgsMDQ4PEA==\n=abcd\n-----END PGP SIGNATURE-----\ny\n";
        let (start, end) = pgp_signed(signed).unwrap();
        assert_eq!(&signed[..start], b"x\n");
        assert_eq!(&signed[end..], b"\ny\n");
        let junk = b"-----BEGIN PGP SIGNED MESSAGE-----\n\nhi\n-----BEGIN PGP SIGNATURE-----\nabc\n-----END PGP SIGNATURE-----\n";
        assert!(pgp_signed(junk).is_none());
        assert!(pgp_signed(b"-----BEGIN PGP SIGNED MESSAGE-----\nhttps://evil.test/\n").is_none());
    }

    #[test]
    fn urls_cms_structure_is_checked() {
        let cms =
            transfer::decode_base64(b"MIIAIAYJKoZIhvcNAQcCoBMBAgMEBQYHCAkKCwwNDg8QERIT").unwrap();
        assert!(cms_signed_data(&cms));
        let mut indefinite = cms.clone();
        indefinite[1] = 0x80;
        indefinite.drain(2..4);
        assert!(cms_signed_data(&indefinite));
        // Wrong content type (data, not signedData), and a length past the end.
        let mut data = cms.clone();
        data[14] = 0x01;
        assert!(!cms_signed_data(&data));
        assert!(!cms_signed_data(&cms[..20]));
        assert!(!cms_signed_data(b"AAAA"));
    }

    #[test]
    fn urls_vml_formaction_and_late_base_are_rewritten() {
        let (out, links) = html(
            br#"<a href="page">early</a><v:roundrect href="https://evil.test/vml"><w:anchorlock/></v:roundrect><button formaction="https://evil.test/f">b</button><link rel="stylesheet" href="https://cdn.example.net/s.css"><base href="https://evil.test/dir/">"#,
        );
        assert_eq!(links, 3, "{out}");
        assert!(out.contains("https://cdn.example.net/s.css"), "{out}");
        assert!(out.contains(r#"<base href="https://evil.test/dir/">"#));
        let mut c = ctx();
        rewriter()
            .rewrite_html(
                br##"<a href="other.html">r</a><a href="#top">t</a><a href="">e</a>"##,
                AsciiCompatibleEncoding::new(encoding_rs::UTF_8).unwrap(),
                &mut c,
            )
            .unwrap();
        assert_eq!((c.links, c.relative), (0, 1));
    }
}
