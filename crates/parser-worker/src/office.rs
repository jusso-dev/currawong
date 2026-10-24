//! Macro and OLE object detection, and content an Office document loads
//! from outside itself (remote templates, DDE, protocol handlers). This does
//! not deobfuscate VBA.
use crate::external::{self, xml_unescape, Findings};
use currawong_core::PartFlag;
use regex::Regex;
use std::io::Cursor;
use std::sync::OnceLock;

pub fn has_macro_ole(bytes: &[u8]) -> bool {
    ole_name_matches(bytes, |name| {
        let lower = name.to_ascii_lowercase();
        lower.contains("vba") || lower.contains("macros")
    })
}

pub fn has_ole_object(bytes: &[u8]) -> bool {
    ole_name_matches(bytes, |name| {
        name.to_ascii_lowercase().contains("objectpool")
    })
}

fn ole_name_matches(bytes: &[u8], pred: impl Fn(&str) -> bool) -> bool {
    let Ok(file) = cfb::CompoundFile::open(Cursor::new(bytes)) else {
        return false;
    };
    file.walk()
        .any(|entry| pred(entry.path().to_string_lossy().as_ref()))
}

pub fn ooxml_macro_bytes(bytes: &[u8]) -> bool {
    if !bytes.starts_with(b"PK") {
        return false;
    }
    let Ok(mut archive) = zip::ZipArchive::new(std::io::Cursor::new(bytes)) else {
        return false;
    };
    let mut names = Vec::new();
    for index in 0..archive.len() {
        if let Ok(file) = archive.by_index(index) {
            if let Ok(name) = file.name() {
                names.push(name.to_string());
            }
        }
    }
    ooxml_macro(&names)
}

pub fn ooxml_macro(names: &[String]) -> bool {
    names.iter().any(|name| {
        let lower = name.replace('\\', "/").to_ascii_lowercase();
        lower.ends_with("vbaproject.bin")
    })
}

/// Any `\obj...` control word (`\object`, `\objdata`, `\objemb` and so
/// on), anywhere in the document. Padding does not hide it.
pub fn rtf_has_object(bytes: &[u8]) -> bool {
    bytes
        .windows(4)
        .any(|window| window.eq_ignore_ascii_case(br"\obj"))
}

/// Tokens from the same message, bounded. Used only as candidate archive
/// passwords. This is not a wordlist cracker.
pub fn password_candidates(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    for ch in text.chars().take(8_000) {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
            if current.len() < 64 {
                current.push(ch);
            }
        } else if !current.is_empty() {
            if (4..=64).contains(&current.len()) {
                out.push(std::mem::take(&mut current));
            } else {
                current.clear();
            }
            if out.len() >= 32 {
                break;
            }
        }
    }
    if (4..=64).contains(&current.len()) && out.len() < 32 {
        out.push(current);
    }
    out
}

/// Remote templates, DDE and protocol handlers in one OOXML member, by its
/// path in the package: relationships (`*.rels`), Word fields
/// (`word/*.xml`) and Excel external links (`xl/externalLinks/*.xml`).
pub fn ooxml_external(name: &str, bytes: &[u8]) -> Findings {
    let mut found = Findings::default();
    let lower = name.replace('\\', "/").to_ascii_lowercase();
    let text = String::from_utf8_lossy(bytes);
    if lower.ends_with(".rels") {
        relationships(&text, &mut found);
    } else if lower.starts_with("word/") && lower.ends_with(".xml") {
        word_fields(&text, &mut found);
    } else if lower.starts_with("xl/externallinks/")
        && lower.ends_with(".xml")
        && regexes().dde_link.is_match(&text)
    {
        found.flag(PartFlag::DdeField);
    }
    found
}

/// Relationship types that load their target when the document opens.
const LOADED_ON_OPEN: &[&str] = &["attachedtemplate", "frame", "oleobject", "subdocument"];

fn relationships(text: &str, found: &mut Findings) {
    let re = regexes();
    for rel in re.relationship.captures_iter(text).take(MAX_RELATIONSHIPS) {
        let attrs = &rel[1];
        let attr = |re: &Regex| {
            re.captures(attrs).map(|caps| {
                let value = caps
                    .get(1)
                    .or_else(|| caps.get(2))
                    .map_or("", |m| m.as_str());
                xml_unescape(value)
            })
        };
        let Some(target) = attr(&re.target) else {
            continue;
        };
        if external::is_handler(&target) {
            found.flag(PartFlag::ProtocolHandler);
            found.link(&target);
        }
        let external =
            attr(&re.target_mode).is_some_and(|mode| mode.eq_ignore_ascii_case("External"));
        let kind = attr(&re.rel_type).unwrap_or_default().to_ascii_lowercase();
        let kind = kind.rsplit('/').next().unwrap_or_default();
        if external && LOADED_ON_OPEN.contains(&kind) && external::is_remote(&target) {
            found.flag(PartFlag::ExternalTemplate);
            found.link(&target);
        }
    }
}

/// Field instructions from `fldSimple` and from `instrText` runs between a
/// `fldChar` begin and end, joined (Word splits an instruction across runs).
fn word_fields(text: &str, found: &mut Findings) {
    let mut open: Vec<String> = Vec::new();
    let mut fields = 0;
    for caps in regexes().field.captures_iter(text) {
        if fields >= MAX_FIELDS {
            return;
        }
        if let Some(kind) = caps.name("char") {
            match kind.as_str().to_ascii_lowercase().as_str() {
                "begin" if open.len() < MAX_FIELD_DEPTH => open.push(String::new()),
                "end" => {
                    if let Some(instruction) = open.pop() {
                        fields += 1;
                        external::field(&instruction, found);
                    }
                }
                _ => {}
            }
        } else if let Some(instr) = caps.name("instr") {
            if let Some(current) = open.last_mut() {
                if current.len() < MAX_FIELD_LEN {
                    current.push_str(&xml_unescape(instr.as_str()));
                }
            }
        } else if let Some(simple) = caps.name("simple").or_else(|| caps.name("simple1")) {
            fields += 1;
            external::field(&xml_unescape(simple.as_str()), found);
        }
    }
    // A field left open at the end of the part still counts.
    for instruction in open {
        external::field(&instruction, found);
    }
}

/// RTF: a remote `\*\template`, `\objupdate` (an object refreshed when the
/// document opens, how linked-object exploits fetch their payload), and DDE
/// or protocol handler field instructions (`\fldinst`).
pub fn rtf_external(bytes: &[u8]) -> Findings {
    let mut found = Findings::default();
    let re = regexes();
    for caps in re.rtf_template.captures_iter(bytes).take(MAX_FIELDS) {
        let target = rtf_text(&caps[1]);
        if external::is_remote(&target) || external::is_handler(&target) {
            found.flag(PartFlag::ExternalTemplate);
            found.link(&target);
        }
    }
    if re.rtf_objupdate.is_match(bytes) {
        found.flag(PartFlag::ExternalTemplate);
    }
    for m in re.rtf_fldinst.find_iter(bytes).take(MAX_FIELDS) {
        let rest = &bytes[m.end()..bytes.len().min(m.end() + MAX_FIELD_LEN)];
        external::field(&rtf_text(rest), &mut found);
    }
    found
}

/// Plain text of an RTF fragment up to the end of its group: control words
/// dropped, `\'hh` and `\\`, `\{`, `\}` decoded.
fn rtf_text(bytes: &[u8]) -> String {
    let mut out = Vec::new();
    let mut depth = 0usize;
    let mut i = 0;
    while i < bytes.len() && out.len() < MAX_FIELD_LEN {
        match bytes[i] {
            b'{' => depth += 1,
            b'}' => {
                if depth == 0 {
                    break;
                }
                depth -= 1;
            }
            b'\\' => {
                let next = bytes.get(i + 1).copied();
                match next {
                    Some(b'\\' | b'{' | b'}') => {
                        out.push(next.unwrap_or_default());
                        i += 1;
                    }
                    Some(b'\'') => {
                        let hex = bytes
                            .get(i + 2..i + 4)
                            .and_then(|h| std::str::from_utf8(h).ok());
                        if let Some(byte) = hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                            out.push(byte);
                        }
                        i += 3;
                    }
                    Some(c) if c.is_ascii_alphabetic() => {
                        i += 1;
                        while bytes.get(i + 1).is_some_and(u8::is_ascii_alphabetic) {
                            i += 1;
                        }
                        if bytes.get(i + 1) == Some(&b'-') {
                            i += 1;
                        }
                        while bytes.get(i + 1).is_some_and(u8::is_ascii_digit) {
                            i += 1;
                        }
                        // One space ends a control word and is part of it.
                        if bytes.get(i + 1) == Some(&b' ') {
                            i += 1;
                        }
                    }
                    _ => i += 1,
                }
            }
            b'\r' | b'\n' => {}
            byte => out.push(byte),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

const MAX_RELATIONSHIPS: usize = 10_000;
const MAX_FIELDS: usize = 10_000;
const MAX_FIELD_DEPTH: usize = 32;
const MAX_FIELD_LEN: usize = 4096;

struct Patterns {
    relationship: Regex,
    target: Regex,
    target_mode: Regex,
    rel_type: Regex,
    field: Regex,
    dde_link: Regex,
    rtf_template: regex::bytes::Regex,
    rtf_objupdate: regex::bytes::Regex,
    rtf_fldinst: regex::bytes::Regex,
}

/// Element and attribute names may carry any namespace prefix.
fn regexes() -> &'static Patterns {
    static PATTERNS: OnceLock<Patterns> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        let re = |pattern: &str| Regex::new(pattern).expect("static pattern");
        let bytes = |pattern: &str| regex::bytes::Regex::new(pattern).expect("static pattern");
        let attr = |name: &str| {
            re(&format!(
                r#"(?:^|[\s:]){name}\s*=\s*(?:"([^"]*)"|'([^']*)')"#
            ))
        };
        Patterns {
            relationship: re(r"<(?:[\w.-]+:)?Relationship\b([^>]*)>"),
            target: attr("Target"),
            target_mode: attr("TargetMode"),
            rel_type: attr("Type"),
            field: re(concat!(
                r#"<(?:[\w.-]+:)?fldChar\b[^>]*?\bfldCharType\s*=\s*["'](?P<char>\w+)["']"#,
                r#"|<(?:[\w.-]+:)?instrText(?:\s[^>]*)?>(?P<instr>[^<]*)"#,
                r#"|<(?:[\w.-]+:)?fldSimple\b[^>]*?\binstr\s*=\s*(?:"(?P<simple>[^"]*)"|'(?P<simple1>[^']*)')"#,
            )),
            dde_link: re(r"<(?:[\w.-]+:)?ddeLink\b"),
            rtf_template: bytes(r"(?i)\\\*\s*\\template\b\s?([^}]{0,4096})"),
            rtf_objupdate: bytes(r"(?i)\\objupdate\b"),
            rtf_fldinst: bytes(r"(?i)\\fldinst\b\s?"),
        }
    })
}
