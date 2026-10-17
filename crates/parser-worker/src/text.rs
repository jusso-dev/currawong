//! Plain text for DLP: text bodies, HTML without tags, and docx, xlsx and PDF
//! attachments. Output is bounded and extraction errors yield no text.
use mail_parser::PartType;
use std::io::{Cursor, Read};

/// Total text handed to DLP for one message. JSON escaping can grow this
/// sixfold, which must stay under the 8 MiB IPC frame limit.
pub const MAX_TEXT_BYTES: usize = 1024 * 1024;
/// Uncompressed XML read from one docx.
const MAX_XML_BYTES: u64 = 8 * 1024 * 1024;
const MAX_NESTED: u32 = 3;

pub fn extract(body: &PartType, out: &mut String) {
    extract_at(body, out, 0);
}

fn extract_at(body: &PartType, out: &mut String, depth: u32) {
    match body {
        PartType::Text(text) => push(out, text),
        PartType::Html(html) => push(out, &strip_markup(html, html_break)),
        PartType::Binary(bytes) | PartType::InlineBinary(bytes) => {
            if let Some(text) = document_text(bytes) {
                push(out, &text);
            }
        }
        PartType::Message(message) if depth < MAX_NESTED => {
            for part in &message.parts {
                extract_at(&part.body, out, depth + 1);
            }
        }
        _ => {}
    }
}

pub fn document_text(bytes: &[u8]) -> Option<String> {
    if bytes.starts_with(b"%PDF") {
        return pdf_text(bytes);
    }
    if !bytes.starts_with(b"PK") {
        return None;
    }
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).ok()?;
    if let Ok(file) = archive.by_name("word/document.xml") {
        let mut xml = String::new();
        file.take(MAX_XML_BYTES).read_to_string(&mut xml).ok()?;
        return Some(strip_markup(&xml, docx_break));
    }
    if archive.by_name("xl/workbook.xml").is_ok() {
        return xlsx_text(bytes);
    }
    None
}

fn pdf_text(bytes: &[u8]) -> Option<String> {
    // pdf-extract can panic on malformed input. The worker also catches
    // panics, but parse_bytes runs in-process when no worker is configured.
    std::panic::catch_unwind(|| pdf_extract::extract_text_from_mem(bytes).ok())
        .ok()
        .flatten()
}

fn xlsx_text(bytes: &[u8]) -> Option<String> {
    use calamine::Reader;
    let mut workbook = calamine::Xlsx::new(Cursor::new(bytes)).ok()?;
    let mut out = String::new();
    for name in workbook.sheet_names() {
        let Ok(range) = workbook.worksheet_range(&name) else {
            continue;
        };
        for row in range.rows() {
            for cell in row {
                if out.len() >= MAX_TEXT_BYTES {
                    return Some(out);
                }
                out.push_str(&cell.to_string());
                out.push('\n');
            }
        }
    }
    Some(out)
}

fn html_break(tag: &str) -> bool {
    matches!(
        tag,
        "p" | "br" | "div" | "td" | "th" | "tr" | "li" | "table" | "h1" | "h2" | "h3" | "h4"
    )
}

fn docx_break(tag: &str) -> bool {
    matches!(tag, "w:p" | "w:tc" | "w:br" | "w:tab" | "w:cr")
}

/// Drops tags, turning block tags into newlines so adjacent table cells do
/// not run together, and decodes the entities that matter for numbers.
fn strip_markup(markup: &str, is_break: fn(&str) -> bool) -> String {
    let mut out = String::with_capacity(markup.len().min(MAX_TEXT_BYTES));
    let mut rest = markup;
    while let Some(open) = rest.find('<') {
        out.push_str(&rest[..open]);
        let Some(close) = rest[open..].find('>') else {
            rest = "";
            break;
        };
        let tag = &rest[open + 1..open + close];
        let name = tag
            .trim_start_matches('/')
            .split(|c: char| c.is_whitespace() || c == '/')
            .next()
            .unwrap_or("")
            .to_ascii_lowercase();
        if is_break(&name) {
            out.push('\n');
        }
        rest = &rest[open + close + 1..];
        if out.len() >= MAX_TEXT_BYTES {
            return decode_entities(&out);
        }
    }
    out.push_str(rest);
    decode_entities(&out)
}

fn decode_entities(text: &str) -> String {
    text.replace("&nbsp;", " ")
        .replace("&#160;", " ")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

fn push(out: &mut String, text: &str) {
    let room = MAX_TEXT_BYTES.saturating_sub(out.len());
    if room == 0 {
        return;
    }
    let mut end = text.len().min(room);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    out.push_str(&text[..end]);
    out.push('\n');
}
