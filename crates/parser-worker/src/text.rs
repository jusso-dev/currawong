//! Plain text for DLP: the subject, attachment names, text bodies, HTML
//! without tags, forwarded messages, and docx, xlsx and PDF attachments.
//!
//! Bodies are collected before attachments so a padded attachment cannot
//! push them out of the budget. Anything that could not be read in full
//! (budget reached, a document that failed to parse, or documents skipped
//! because this is not a sandboxed worker) sets `incomplete`.
use mail_parser::{Message, MimeHeaders, PartType};
use serde::{Deserialize, Serialize};
use std::io::{Cursor, Read};

/// Total text handed to DLP for one message. JSON escaping can grow this
/// sixfold, which must stay under the 8 MiB IPC frame limit.
pub const MAX_TEXT_BYTES: usize = 1024 * 1024;
/// Larger documents are not parsed.
pub const MAX_DOCUMENT_BYTES: usize = 32 * 1024 * 1024;
/// Uncompressed XML read from one docx.
const MAX_XML_BYTES: usize = 8 * 1024 * 1024;
const MAX_CELLS: usize = 1_000_000;
const MAX_NESTED: u32 = 3;

/// Extracted text. `Debug` shows the size only, so the text cannot reach a
/// log through a `{:?}` of a parse response.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DlpText {
    pub text: String,
    pub incomplete: bool,
}

impl std::fmt::Debug for DlpText {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DlpText")
            .field("bytes", &self.text.len())
            .field("incomplete", &self.incomplete)
            .finish()
    }
}

impl DlpText {
    fn push(&mut self, text: &str) {
        let room = MAX_TEXT_BYTES.saturating_sub(self.text.len());
        let mut end = text.len().min(room);
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        if end < text.len() {
            self.incomplete = true;
        }
        self.text.push_str(&text[..end]);
        self.text.push('\n');
    }
}

/// `documents` is true only in the sandboxed worker. PDF and Office parsing
/// never runs in the supervisor; skipped documents mark the text incomplete.
pub fn message_text(message: &Message, documents: bool) -> DlpText {
    let mut out = DlpText::default();
    collect(message, documents, &mut out, 0);
    out
}

/// Text bodies only, for when no parser worker runs. Attachments that are
/// documents mark the result incomplete.
pub fn body_text(raw: &[u8]) -> DlpText {
    match mail_parser::MessageParser::default().parse(raw) {
        Some(message) => message_text(&message, false),
        None => DlpText {
            text: String::from_utf8_lossy(raw).into_owned(),
            incomplete: false,
        },
    }
}

fn collect(message: &Message, documents: bool, out: &mut DlpText, depth: u32) {
    if let Some(subject) = message.subject() {
        out.push(subject);
    }
    for part in message.text_bodies().chain(message.html_bodies()) {
        match &part.body {
            PartType::Text(text) => out.push(text),
            PartType::Html(html) => out.push(&strip_markup(html, Markup::Html)),
            _ => {}
        }
    }
    for part in message.attachments() {
        if let Some(name) = part.attachment_name() {
            out.push(name);
        }
        match &part.body {
            PartType::Text(text) => out.push(text),
            PartType::Html(html) => out.push(&strip_markup(html, Markup::Html)),
            PartType::Binary(bytes) | PartType::InlineBinary(bytes) => {
                match document_text(bytes, documents) {
                    Document::NotDocument => {}
                    Document::Text(text) => {
                        out.incomplete |= text.incomplete;
                        out.push(&text.text);
                    }
                    Document::Unread => out.incomplete = true,
                }
            }
            PartType::Message(nested) if depth < MAX_NESTED => {
                collect(nested, documents, out, depth + 1)
            }
            PartType::Message(_) => out.incomplete = true,
            _ => {}
        }
    }
}

#[derive(Debug)]
pub enum Document {
    NotDocument,
    Text(DlpText),
    /// A PDF or Office document that was too large, failed to parse, or was
    /// skipped outside the worker.
    Unread,
}

pub fn document_text(bytes: &[u8], documents: bool) -> Document {
    let pdf = bytes.starts_with(b"%PDF");
    let office = bytes.starts_with(b"PK") && office_kind(bytes).is_some();
    if !pdf && !office {
        return Document::NotDocument;
    }
    if !documents || bytes.len() > MAX_DOCUMENT_BYTES {
        return Document::Unread;
    }
    let text = if pdf {
        pdf_text(bytes)
    } else {
        match office_kind(bytes) {
            Some(Office::Word) => docx_text(bytes),
            Some(Office::Excel) => xlsx_text(bytes),
            None => None,
        }
    };
    text.map_or(Document::Unread, Document::Text)
}

enum Office {
    Word,
    Excel,
}

fn office_kind(bytes: &[u8]) -> Option<Office> {
    let archive = zip::ZipArchive::new(Cursor::new(bytes)).ok()?;
    let names: Vec<&str> = archive.file_names().collect();
    if names.contains(&"word/document.xml") {
        Some(Office::Word)
    } else if names.contains(&"xl/workbook.xml") {
        Some(Office::Excel)
    } else {
        None
    }
}

fn pdf_text(bytes: &[u8]) -> Option<DlpText> {
    // pdf-extract can panic on malformed input. Time and memory are bounded
    // by the worker's limits.
    let text = std::panic::catch_unwind(|| pdf_extract::extract_text_from_mem(bytes).ok())
        .ok()
        .flatten()?;
    let mut out = DlpText::default();
    out.push(&text);
    Some(out)
}

/// The body, headers, footers, footnotes, endnotes and comments. Text boxes
/// live inside the body part.
fn docx_text(bytes: &[u8]) -> Option<DlpText> {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).ok()?;
    let names: Vec<String> = archive
        .file_names()
        .filter(|name| {
            let Some(rest) = name.strip_prefix("word/") else {
                return false;
            };
            rest.ends_with(".xml")
                && [
                    "document",
                    "header",
                    "footer",
                    "footnotes",
                    "endnotes",
                    "comments",
                ]
                .iter()
                .any(|part| rest.starts_with(part))
        })
        .map(str::to_string)
        .collect();
    let mut out = DlpText::default();
    let mut budget = MAX_XML_BYTES;
    for name in names {
        let Ok(file) = archive.by_name(&name) else {
            out.incomplete = true;
            continue;
        };
        let mut xml = Vec::new();
        if file.take(budget as u64 + 1).read_to_end(&mut xml).is_err() {
            out.incomplete = true;
            continue;
        }
        if xml.len() > budget {
            xml.truncate(budget);
            out.incomplete = true;
        }
        budget -= xml.len();
        out.push(&strip_markup(&String::from_utf8_lossy(&xml), Markup::Word));
    }
    Some(out)
}

/// Streams cells, so a sparse sheet that claims a huge range is not
/// expanded into a dense grid.
fn xlsx_text(bytes: &[u8]) -> Option<DlpText> {
    use calamine::{DataRef, Reader};
    let mut workbook = calamine::Xlsx::new(Cursor::new(bytes)).ok()?;
    let mut out = DlpText::default();
    let mut cells = 0;
    for name in workbook.sheet_names() {
        let Ok(mut reader) = workbook.worksheet_cells_reader(&name) else {
            out.incomplete = true;
            continue;
        };
        loop {
            match reader.next_cell() {
                Ok(Some(cell)) => {
                    cells += 1;
                    if cells > MAX_CELLS {
                        out.incomplete = true;
                        return Some(out);
                    }
                    match cell.get_value() {
                        DataRef::Int(n) => out.push(&n.to_string()),
                        DataRef::Float(n) => out.push(&n.to_string()),
                        DataRef::String(s) | DataRef::DateTimeIso(s) | DataRef::DurationIso(s) => {
                            out.push(s)
                        }
                        DataRef::SharedString(s) => out.push(s),
                        _ => {}
                    }
                }
                Ok(None) => break,
                Err(_) => {
                    out.incomplete = true;
                    break;
                }
            }
        }
    }
    Some(out)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Markup {
    Html,
    Word,
}

fn is_break(markup: Markup, tag: &str) -> bool {
    match markup {
        Markup::Html => matches!(
            tag,
            "p" | "br"
                | "div"
                | "td"
                | "th"
                | "tr"
                | "li"
                | "table"
                | "h1"
                | "h2"
                | "h3"
                | "h4"
                | "h5"
                | "h6"
        ),
        Markup::Word => matches!(tag, "w:p" | "w:tc" | "w:br" | "w:tab" | "w:cr"),
    }
}

/// Drops tag syntax and keeps everything else, including comment, CDATA,
/// script and style content, and (for HTML) quoted attribute values. A `<`
/// that does not start a well-formed tag is text, so `a < b` survives.
/// Linear: a tag scan stops at the next `<`.
fn strip_markup(markup: &str, kind: Markup) -> String {
    let mut out = String::with_capacity(markup.len().min(MAX_TEXT_BYTES));
    let mut rest = markup;
    while let Some(open) = rest.find('<') {
        out.push_str(&rest[..open]);
        let tail = &rest[open..];
        if let Some((body, after)) = comment_or_cdata(tail) {
            out.push('\n');
            out.push_str(body);
            out.push('\n');
            rest = after;
            continue;
        }
        match tag_end(&tail[1..]) {
            Some((len, values)) => {
                let tag = &tail[1..1 + len];
                let name = tag
                    .trim_start_matches('/')
                    .split(|c: char| c.is_whitespace() || c == '/' || c == '>')
                    .next()
                    .unwrap_or("")
                    .to_ascii_lowercase();
                if is_break(kind, &name) {
                    out.push('\n');
                }
                if kind == Markup::Html {
                    for value in values {
                        out.push('\n');
                        out.push_str(&tag[value.0..value.1]);
                        out.push('\n');
                    }
                }
                rest = &tail[len + 2..];
            }
            None => {
                out.push('<');
                rest = &tail[1..];
            }
        }
        if out.len() >= MAX_TEXT_BYTES {
            return decode_entities(&out);
        }
    }
    out.push_str(rest);
    decode_entities(&out)
}

/// The content of a comment or CDATA section at the start of `tail`, and
/// the text after it.
fn comment_or_cdata(tail: &str) -> Option<(&str, &str)> {
    for (start, end) in [("<!--", "-->"), ("<![CDATA[", "]]>")] {
        if let Some(body) = tail.strip_prefix(start) {
            let stop = body.find(end).unwrap_or(body.len());
            return Some((&body[..stop], body.get(stop + end.len()..).unwrap_or("")));
        }
    }
    None
}

/// For text just after `<`: the length up to the closing `>` and the byte
/// ranges of quoted attribute values. `None` unless it starts like a tag
/// (letter, `/`, `!` or `?`) and closes before the next `<`.
fn tag_end(text: &str) -> Option<(usize, Vec<(usize, usize)>)> {
    let first = text.bytes().next()?;
    if !(first.is_ascii_alphabetic() || matches!(first, b'/' | b'!' | b'?')) {
        return None;
    }
    let mut quote: Option<(u8, usize)> = None;
    let mut values = Vec::new();
    for (i, b) in text.bytes().enumerate() {
        match (quote, b) {
            (_, b'<') => return None,
            (None, b'>') => return Some((i, values)),
            (None, b'"' | b'\'') => quote = Some((b, i + 1)),
            (Some((q, start)), _) if b == q => {
                if i > start {
                    values.push((start, i));
                }
                quote = None;
            }
            _ => {}
        }
    }
    None
}

/// Named entities that matter for numbers, and every numeric entity.
fn decode_entities(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        let tail = &rest[amp..];
        // Look a few bytes ahead only, so `&&&&...` stays linear.
        let decoded = tail.as_bytes()[1..]
            .iter()
            .take(11)
            .position(|b| *b == b';')
            .and_then(|semi| entity(tail.get(1..1 + semi)?).map(|c| (c, semi + 2)));
        match decoded {
            Some((c, len)) => {
                out.push(c);
                rest = &tail[len..];
            }
            None => {
                out.push('&');
                rest = &tail[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

fn entity(name: &str) -> Option<char> {
    let code = if let Some(hex) = name.strip_prefix("#x").or_else(|| name.strip_prefix("#X")) {
        u32::from_str_radix(hex, 16).ok()?
    } else if let Some(dec) = name.strip_prefix('#') {
        dec.parse().ok()?
    } else {
        return match name {
            "nbsp" => Some('\u{a0}'),
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            _ => None,
        };
    };
    char::from_u32(code)
}
