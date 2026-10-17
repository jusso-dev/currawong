//! Macro and OLE object detection. This does not deobfuscate VBA.
use std::io::Cursor;

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
            names.push(file.name().to_string());
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

pub fn rtf_has_object(bytes: &[u8]) -> bool {
    let lower: Vec<u8> = bytes
        .iter()
        .take(1024 * 1024)
        .map(|b| b.to_ascii_lowercase())
        .collect();
    contains_token(&lower, br"\object") || contains_token(&lower, br"\objdata")
}

fn contains_token(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|window| window == needle)
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
