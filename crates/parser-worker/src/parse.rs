//! MIME parse. A message that cannot be parsed returns an error, it does not panic.
use crate::archive::{self, passwords_from_message};
use crate::filetype::{self, FileKind};
use crate::ipc::{ParseRequest, ParseResponse};
use crate::office;
use crate::yara::{RulesCache, YaraScan};
use currawong_core::config::ExtractLimits;
use currawong_core::{PartFlag, PartInfo};
use mail_parser::{MessageParser, MimeHeaders, PartType};
use std::fs;
use yara_x::Rules;

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
        parse_bytes_with(&req.id, &raw, &req.limits, rules)
    })) {
        Ok(response) => response,
        Err(_) => ParseResponse::failed(&req.id, "parser panicked"),
    }
}

pub fn parse_bytes(id: &str, raw: &[u8], limits: &ExtractLimits) -> ParseResponse {
    parse_bytes_with(id, raw, limits, None)
}

/// Parse, and match YARA rules against the raw message, every MIME part and
/// every archive member.
pub fn parse_bytes_with(
    id: &str,
    raw: &[u8],
    limits: &ExtractLimits,
    rules: Option<&Rules>,
) -> ParseResponse {
    let Some(message) = MessageParser::default().with_mime_headers().parse(raw) else {
        return ParseResponse::failed(id, "message has no headers");
    };
    let mut yara = rules.map(YaraScan::new);
    if let Some(yara) = yara.as_mut() {
        yara.scan("message", raw);
    }
    let mut parts = Vec::new();
    let mut urls = Vec::new();
    let mut text = String::new();
    for part in message
        .attachments()
        .chain(message.text_bodies())
        .chain(message.html_bodies())
    {
        let filename = part.attachment_name().map(|name| name.to_string());
        let content_type = part
            .content_type()
            .map(|ct| ct.c_type.to_string())
            .unwrap_or_else(|| "application/octet-stream".into());
        let bytes = part.contents();
        if let Some(yara) = yara.as_mut() {
            yara.scan(filename.as_deref().unwrap_or(&content_type), bytes);
        }
        collect_text(&part.body, &mut text);
        urls.extend(crate::fuzz::urls_in(bytes).into_iter().take(64));
        let kind = filetype::detect(bytes);
        let mut flags = filetype::flags_for(bytes, filename.as_deref(), &kind);
        if office::ooxml_macro(&[filename.clone().unwrap_or_default()]) {
            flags.push(PartFlag::HasMacro);
        }
        parts.push(make_part(content_type, filename.clone(), bytes, flags));
        if is_container(&kind) || bytes.starts_with(b"PK") {
            let extracted =
                archive::extract_with(bytes, filename.as_deref(), limits, &[], yara.as_mut());
            parts.extend(extracted.parts);
        }
    }
    if parts.is_empty() {
        let kind = FileKind {
            label: "message/rfc822".into(),
            executable: false,
        };
        parts.push(make_part(kind.label, None, raw, Vec::new()));
    }
    let passwords = passwords_from_message(&text);
    if !passwords.is_empty() {
        let mut extra = Vec::new();
        for part in &parts {
            if part.flags.contains(&PartFlag::Encrypted) {
                extra.push(part.filename.clone());
            }
        }
        let _ = extra;
    }
    urls.extend(crate::fuzz::urls_in(raw).into_iter().take(32));
    urls.sort();
    urls.dedup();
    let (yara, error) = match yara {
        Some(scan) => (scan.matches, scan.error),
        None => (Vec::new(), None),
    };
    ParseResponse {
        id: id.to_string(),
        parts,
        urls,
        error,
        yara,
    }
}

fn make_part(
    content_type: String,
    filename: Option<String>,
    bytes: &[u8],
    mut flags: Vec<PartFlag>,
) -> PartInfo {
    let kind = filetype::detect(bytes);
    for flag in filetype::flags_for(bytes, filename.as_deref(), &kind) {
        if !flags.contains(&flag) {
            flags.push(flag);
        }
    }
    if bytes.starts_with(b"PK")
        && office::ooxml_macro_bytes(bytes)
        && !flags.contains(&PartFlag::HasMacro)
    {
        flags.push(PartFlag::HasMacro);
    }
    PartInfo {
        content_type: if content_type.is_empty() {
            kind.label
        } else {
            content_type
        },
        filename,
        size: bytes.len() as u64,
        sha256: filetype::sha256(bytes),
        flags,
        path: None,
    }
}

fn is_container(kind: &FileKind) -> bool {
    matches!(
        kind.label.as_str(),
        "application/zip"
            | "application/gzip"
            | "application/x-tar"
            | "application/x-iso9660-image"
            | "application/x-7z-compressed"
    )
}

fn collect_text(body: &PartType, out: &mut String) {
    match body {
        PartType::Text(text) | PartType::Html(text) if out.len() < 16_000 => out.push_str(text),
        _ => {}
    }
}
