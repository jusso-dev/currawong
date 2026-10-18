//! MIME parse. A message that cannot be parsed returns an error, it does not panic.
use crate::archive::{self, passwords_from_message, Budget};
use crate::filetype::{self, FileKind};
use crate::ipc::{FoundUrl, ParseRequest, ParseResponse, UrlSource};
use crate::yara::{RulesCache, YaraScan};
use crate::{html_smuggling, qr};
use currawong_core::config::ExtractLimits;
use currawong_core::{PartFlag, PartInfo};
use mail_parser::decoders::{base64::base64_decode, quoted_printable::quoted_printable_decode};
use mail_parser::{Encoding, Message, MessageParser, MessagePart, MimeHeaders, PartType};
use std::borrow::Cow;
use std::fs;
use std::path::Path;
use yara_x::Rules;

/// URLs reported per message. Keeps the response frame bounded.
const MAX_URLS: usize = 512;
/// mail-parser recurses per nested message and multipart; past these the
/// message is refused before it is parsed (a deep stack would overflow).
const MAX_NESTED_MESSAGES: usize = 32;
const MAX_MULTIPARTS: usize = 512;

pub fn parse_request(req: &ParseRequest, cache: &mut RulesCache) -> ParseResponse {
    let raw = match fs::read(&req.raw_path) {
        Ok(raw) => raw,
        Err(err) => return ParseResponse::failed(&req.id, format!("read input: {err}")),
    };
    let rules = match req.yara_generation {
        Some(generation) => match cache.get(generation) {
            Ok(rules) => Some(rules),
            Err(err) => return ParseResponse::failed(&req.id, err),
        },
        None => None,
    };
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        parse_full(
            &req.id,
            &raw,
            &req.limits,
            req.out_dir.as_deref(),
            rules,
            true,
        )
    })) {
        Ok(response) => response,
        Err(_) => ParseResponse::failed(&req.id, "parser panicked"),
    }
}

/// In-process parse. PDF and Office text extraction only runs in the
/// worker (`parse_request`), so documents here mark DLP text incomplete.
pub fn parse_bytes(id: &str, raw: &[u8], limits: &ExtractLimits) -> ParseResponse {
    parse_with(id, raw, limits, None)
}

/// In-process parse with YARA rules matched against the raw message, every
/// MIME part and every archive member. Documents mark DLP text incomplete.
pub fn parse_bytes_with(
    id: &str,
    raw: &[u8],
    limits: &ExtractLimits,
    rules: Option<&Rules>,
) -> ParseResponse {
    parse_full(id, raw, limits, None, rules, false)
}

/// Parses `raw`. Limits apply to the whole message, not to each attachment.
/// With `out_dir`, decoded parts are written there for the AV engines.
pub fn parse_with(
    id: &str,
    raw: &[u8],
    limits: &ExtractLimits,
    out_dir: Option<&Path>,
) -> ParseResponse {
    parse_full(id, raw, limits, out_dir, None, false)
}

/// `documents` is true only in the worker: PDF and Office text extraction
/// for DLP never runs in the supervisor.
pub fn parse_full(
    id: &str,
    raw: &[u8],
    limits: &ExtractLimits,
    out_dir: Option<&Path>,
    rules: Option<&Rules>,
    documents: bool,
) -> ParseResponse {
    if let Some(reason) = nesting_limit(raw) {
        return ParseResponse::failed(id, reason);
    }
    let Some(message) = MessageParser::default().with_mime_headers().parse(raw) else {
        return ParseResponse::failed(id, "message has no headers");
    };
    let mut text = String::new();
    collect_text(&message, &mut text, limits.max_depth);
    let mut yara = rules.map(YaraScan::new);
    if let Some(yara) = yara.as_mut() {
        yara.scan("message", raw);
    }
    let mut walk = Walk {
        budget: Budget::new(limits, out_dir)
            .with_yara(yara.as_mut())
            .with_checks(ContentChecks::new(documents)),
        passwords: passwords_from_message(&text),
        parts: Vec::new(),
        urls: Vec::new(),
    };
    walk.message(&message);
    if walk.parts.is_empty() {
        let part = walk
            .budget
            .part(None, Some("message/rfc822".into()), raw, Vec::new());
        walk.parts.push(part);
    }
    let Walk {
        mut budget,
        parts,
        mut urls,
        ..
    } = walk;
    let qr_urls = budget
        .checks
        .take()
        .map(|checks| checks.urls)
        .unwrap_or_default();
    if let Some(err) = budget.store_failed {
        return ParseResponse::failed(id, err);
    }
    let (yara, error) = match yara {
        Some(scan) => (scan.matches, scan.error),
        None => (Vec::new(), None),
    };
    urls.extend(crate::fuzz::urls_in(raw).into_iter().take(32));
    urls.sort();
    urls.dedup();
    urls.truncate(MAX_URLS);
    // QR URLs are bounded by the QR budget and kept even when text links
    // filled `MAX_URLS`.
    let mut url_sources: Vec<FoundUrl> = urls
        .iter()
        .map(|url| FoundUrl {
            url: url.clone(),
            source: UrlSource::Text,
        })
        .chain(qr_urls)
        .collect();
    url_sources.sort();
    url_sources.dedup();
    let mut urls: Vec<String> = url_sources.iter().map(|found| found.url.clone()).collect();
    urls.dedup();
    ParseResponse {
        id: id.to_string(),
        parts,
        urls,
        url_sources,
        error,
        warnings: Vec::new(),
        yara,
        dlp: crate::text::message_text(&message, documents),
    }
}

struct Walk<'a, 'r> {
    budget: Budget<'a, 'r>,
    passwords: Vec<String>,
    parts: Vec<PartInfo>,
    urls: Vec<String>,
}

impl Walk<'_, '_> {
    /// Every leaf part once, descending into attached messages.
    fn message(&mut self, message: &Message<'_>) {
        for part in &message.parts {
            if self.budget.hit {
                return;
            }
            if let PartType::Multipart(_) = part.body {
                continue;
            }
            if !self.budget.admit() {
                self.limit_part();
                return;
            }
            let filename = part.attachment_name().map(str::to_string);
            let content_type = part.content_type().map(|ct| match &ct.c_subtype {
                Some(sub) => format!("{}/{}", ct.c_type, sub).to_ascii_lowercase(),
                None => ct.c_type.to_ascii_lowercase(),
            });
            let bytes = &*part_bytes(message, part);
            if let PartType::Message(inner) = &part.body {
                let entry = self
                    .budget
                    .part(filename.as_deref(), content_type, bytes, Vec::new());
                self.parts.push(entry);
                if !self.budget.enter() {
                    self.limit_part();
                    return;
                }
                self.message(inner);
                self.budget.leave();
                continue;
            }
            if self.urls.len() < MAX_URLS {
                self.urls
                    .extend(crate::fuzz::urls_in(bytes).into_iter().take(64));
            }
            let mut flags = archive::inspect(
                bytes,
                filename.as_deref(),
                &self.passwords,
                &mut self.budget,
                &mut self.parts,
            );
            let kind = filetype::detect(bytes);
            if declared_type_mismatch(content_type.as_deref(), &kind)
                && !flags.contains(&PartFlag::ExtMismatch)
            {
                flags.push(PartFlag::ExtMismatch);
            }
            let html = matches!(part.body, PartType::Html(_))
                || content_type.as_deref() == Some("text/html");
            self.budget
                .check(bytes, filename.as_deref(), html, &mut flags);
            let entry = self
                .budget
                .part(filename.as_deref(), content_type, bytes, flags);
            self.parts.push(entry);
        }
    }

    /// Records that parts were left uninspected.
    fn limit_part(&mut self) {
        let part = self.budget.part(
            None,
            Some("application/octet-stream".into()),
            b"",
            vec![PartFlag::LimitExceeded],
        );
        self.parts.push(part);
    }
}

/// HTML smuggling and QR code checks for MIME parts and archive members.
pub struct ContentChecks {
    qr: qr::Budget,
    /// PDFs are rendered only in the worker, like document text.
    documents: bool,
    urls: Vec<FoundUrl>,
}

impl ContentChecks {
    fn new(documents: bool) -> Self {
        Self {
            qr: qr::Budget::default(),
            documents,
            urls: Vec::new(),
        }
    }

    pub(crate) fn run(
        &mut self,
        bytes: &[u8],
        filename: Option<&str>,
        html_type: bool,
        kind: &FileKind,
        flags: &mut Vec<PartFlag>,
    ) {
        if html_smuggling::is_html(html_type, filename, &kind.label, bytes)
            && html_smuggling::flagged(bytes)
        {
            flags.push(PartFlag::HtmlSmuggling);
        }
        let codes = if kind.label.starts_with("image/") {
            self.qr.image(bytes)
        } else if self.documents && kind.label == "application/pdf" {
            self.qr.pdf(bytes)
        } else {
            return;
        };
        match codes {
            Ok(codes) => {
                if !codes.is_empty() {
                    flags.push(PartFlag::QrCode);
                }
                self.urls
                    .extend(qr::urls(&codes).into_iter().map(|url| FoundUrl {
                        url,
                        source: UrlSource::Qr,
                    }));
            }
            // A possible decode bomb fails closed like an archive limit.
            Err(qr::Skipped::TooLarge) => {
                if !flags.contains(&PartFlag::LimitExceeded) {
                    flags.push(PartFlag::LimitExceeded);
                }
            }
            // QR is a tagging signal: a used-up budget does not hold mail.
            Err(qr::Skipped::Budget) => flags.push(PartFlag::QrSkipped),
        }
    }
}

/// A cheap count before mail-parser sees the message.
pub fn nesting_limit(raw: &[u8]) -> Option<String> {
    let count = |needle: &[u8]| {
        raw.windows(needle.len())
            .filter(|window| window.eq_ignore_ascii_case(needle))
            .count()
    };
    let messages = count(b"message/rfc822") + count(b"message/global");
    if messages > MAX_NESTED_MESSAGES {
        return Some(format!(
            "nesting limit: {messages} attached messages (limit {MAX_NESTED_MESSAGES})"
        ));
    }
    let multiparts = count(b"multipart/");
    if multiparts > MAX_MULTIPARTS {
        return Some(format!(
            "nesting limit: {multiparts} multipart sections (limit {MAX_MULTIPARTS})"
        ));
    }
    None
}

/// The bytes the AV engines should see. Text parts are decoded from their
/// transfer encoding only, not converted to UTF-8, which could lose bytes.
fn part_bytes<'a>(message: &'a Message<'a>, part: &'a MessagePart<'a>) -> Cow<'a, [u8]> {
    if !matches!(part.body, PartType::Text(_) | PartType::Html(_)) {
        return Cow::Borrowed(part.contents());
    }
    let raw = message
        .raw_message
        .get(part.offset_body as usize..part.offset_end as usize);
    let decoded = raw.and_then(|raw| match part.encoding {
        Encoding::Base64 => base64_decode(raw),
        Encoding::QuotedPrintable => quoted_printable_decode(raw),
        Encoding::None => Some(raw.to_vec()),
    });
    decoded.map_or(Cow::Borrowed(part.contents()), Cow::Owned)
}

/// Executable content declared as something else (a PE sent as
/// `application/pdf` with no file name, for example).
fn declared_type_mismatch(declared: Option<&str>, kind: &FileKind) -> bool {
    let Some(declared) = declared else {
        return false;
    };
    kind.executable
        && !matches!(
            declared,
            "application/octet-stream"
                | "application/x-msdownload"
                | "application/x-msdos-program"
                | "application/x-dosexec"
                | "application/x-executable"
                | "application/x-sharedlib"
                | "application/x-elf"
                | "application/x-mach-binary"
                | "application/x-ms-shortcut"
                | "application/vnd.microsoft.portable-executable"
        )
}

/// Body text for candidate archive passwords, from this message and any
/// attached ones.
fn collect_text(message: &Message<'_>, out: &mut String, depth: u32) {
    for part in &message.parts {
        if out.len() >= 16_000 {
            return;
        }
        match &part.body {
            PartType::Text(text) | PartType::Html(text) => out.push_str(text),
            PartType::Message(inner) if depth > 0 => collect_text(inner, out, depth - 1),
            _ => {}
        }
        out.push('\n');
    }
}
