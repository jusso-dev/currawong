//! MIME parse. A message that cannot be parsed returns an error, it does not panic.
use crate::archive::{self, passwords_from_message, Budget};
use crate::filetype::{self, FileKind};
use crate::ipc::{ParseRequest, ParseResponse};
use currawong_core::config::ExtractLimits;
use currawong_core::{PartFlag, PartInfo};
use mail_parser::{Message, MessageParser, MimeHeaders, PartType};
use std::fs;
use std::path::Path;

/// URLs reported per message. Keeps the response frame bounded.
const MAX_URLS: usize = 512;

pub fn parse_request(req: &ParseRequest) -> ParseResponse {
    let raw = match fs::read(&req.raw_path) {
        Ok(raw) => raw,
        Err(err) => return ParseResponse::failed(&req.id, format!("read input: {err}")),
    };
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        parse_with(&req.id, &raw, &req.limits, req.out_dir.as_deref())
    })) {
        Ok(response) => response,
        Err(_) => ParseResponse::failed(&req.id, "parser panicked"),
    }
}

pub fn parse_bytes(id: &str, raw: &[u8], limits: &ExtractLimits) -> ParseResponse {
    parse_with(id, raw, limits, None)
}

/// Parses `raw`. Limits apply to the whole message, not to each attachment.
/// With `out_dir`, decoded parts are written there for the AV engines.
pub fn parse_with(
    id: &str,
    raw: &[u8],
    limits: &ExtractLimits,
    out_dir: Option<&Path>,
) -> ParseResponse {
    let Some(message) = MessageParser::default().with_mime_headers().parse(raw) else {
        return ParseResponse::failed(id, "message has no headers");
    };
    let mut text = String::new();
    collect_text(&message, &mut text, limits.max_depth);
    let mut walk = Walk {
        budget: Budget::new(limits, out_dir),
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
    if let Some(err) = walk.budget.store_failed {
        return ParseResponse::failed(id, err);
    }
    let mut urls = walk.urls;
    urls.extend(crate::fuzz::urls_in(raw).into_iter().take(32));
    urls.sort();
    urls.dedup();
    urls.truncate(MAX_URLS);
    ParseResponse {
        id: id.to_string(),
        parts: walk.parts,
        urls,
        error: None,
    }
}

struct Walk {
    budget: Budget,
    passwords: Vec<String>,
    parts: Vec<PartInfo>,
    urls: Vec<String>,
}

impl Walk {
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
            let bytes = part.contents();
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
