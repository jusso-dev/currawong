//! Bounded archive extraction. Limits stop zip bombs before they expand.
use crate::filetype::{self, FileKind};
use crate::office::{self, password_candidates};
use crate::yara::YaraScan;
use currawong_core::config::ExtractLimits;
use currawong_core::{PartFlag, PartInfo};
use std::io::{Cursor, Read};

#[derive(Debug, Default)]
pub struct Extracted {
    pub parts: Vec<PartInfo>,
    pub limit_hit: bool,
}

pub fn extract(
    bytes: &[u8],
    filename: Option<&str>,
    limits: &ExtractLimits,
    passwords: &[String],
) -> Extracted {
    extract_with(bytes, filename, limits, passwords, None)
}

/// Same as [`extract`], and matches YARA rules against every member.
pub fn extract_with(
    bytes: &[u8],
    filename: Option<&str>,
    limits: &ExtractLimits,
    passwords: &[String],
    yara: Option<&mut YaraScan<'_>>,
) -> Extracted {
    let mut out = Extracted::default();
    let mut budget = Budget {
        depth: 0,
        files: 0,
        bytes: 0,
        limits: limits.clone(),
        hit: false,
        yara,
    };
    walk(bytes, filename, passwords, &mut budget, &mut out.parts);
    out.limit_hit = budget.hit;
    if budget.hit {
        for part in &mut out.parts {
            if !part.flags.contains(&PartFlag::LimitExceeded) {
                part.flags.push(PartFlag::LimitExceeded);
            }
        }
    }
    out
}

struct Budget<'a, 'r> {
    depth: u32,
    files: u32,
    bytes: u64,
    limits: ExtractLimits,
    hit: bool,
    yara: Option<&'a mut YaraScan<'r>>,
}

fn walk(
    bytes: &[u8],
    filename: Option<&str>,
    passwords: &[String],
    budget: &mut Budget,
    parts: &mut Vec<PartInfo>,
) {
    if budget.hit {
        return;
    }
    // Depth 0 is the attachment itself, already matched by the caller.
    if budget.depth > 0 {
        if let Some(yara) = budget.yara.as_mut() {
            yara.scan(filename.unwrap_or("archive member"), bytes);
        }
    }
    let kind = filetype::detect(bytes);
    let mut flags = filetype::flags_for(bytes, filename, &kind);
    if is_archive(&kind) {
        if budget.depth >= budget.limits.max_depth {
            budget.hit = true;
            flags.push(PartFlag::LimitExceeded);
            parts.push(part(filename, &kind, bytes, flags));
            return;
        }
        budget.depth += 1;
        match kind.label.as_str() {
            "application/zip" => unzip(bytes, passwords, budget, parts, &mut flags),
            "application/gzip" => gunzip(bytes, filename, passwords, budget, parts),
            "application/x-tar" => untar(bytes, passwords, budget, parts),
            "application/x-iso9660-image" => unpack_iso(bytes, passwords, budget, parts),
            "application/x-7z-compressed" => {
                flags.push(PartFlag::Encrypted);
                parts.push(part(filename, &kind, bytes, flags.clone()));
            }
            "application/vnd.rar" => {
                flags.push(PartFlag::Encrypted);
            }
            _ => {}
        }
        budget.depth -= 1;
    }
    if (!flags.is_empty() || filename.is_some())
        && !parts.iter().any(|existing| {
            existing.sha256 == filetype::sha256(bytes)
                && existing.filename == filename.map(str::to_string)
        })
    {
        parts.push(part(filename, &kind, bytes, flags));
    }
}

fn part(filename: Option<&str>, kind: &FileKind, bytes: &[u8], flags: Vec<PartFlag>) -> PartInfo {
    PartInfo {
        content_type: kind.label.clone(),
        filename: filename.map(str::to_string),
        size: bytes.len() as u64,
        sha256: filetype::sha256(bytes),
        flags,
        path: None,
    }
}

fn is_archive(kind: &FileKind) -> bool {
    matches!(
        kind.label.as_str(),
        "application/zip"
            | "application/gzip"
            | "application/x-tar"
            | "application/x-iso9660-image"
            | "application/x-7z-compressed"
            | "application/vnd.rar"
    )
}

fn charge(budget: &mut Budget, size: u64, compressed: u64) -> bool {
    if budget.files >= budget.limits.max_files
        || budget.bytes.saturating_add(size) > budget.limits.max_uncompressed_bytes
    {
        budget.hit = true;
        return false;
    }
    if compressed > 0 && size / compressed.max(1) > budget.limits.max_ratio as u64 {
        budget.hit = true;
        return false;
    }
    budget.files += 1;
    budget.bytes += size;
    true
}

fn unzip(
    bytes: &[u8],
    passwords: &[String],
    budget: &mut Budget,
    parts: &mut Vec<PartInfo>,
    flags: &mut Vec<PartFlag>,
) {
    let Ok(mut archive) = zip::ZipArchive::new(Cursor::new(bytes)) else {
        return;
    };
    let names: Vec<String> = (0..archive.len())
        .filter_map(|i| archive.by_index(i).ok().map(|f| f.name().to_string()))
        .collect();
    if office::ooxml_macro(&names) && !flags.contains(&PartFlag::HasMacro) {
        flags.push(PartFlag::HasMacro);
    }
    for index in 0..archive.len() {
        if budget.hit {
            return;
        }
        let file = match archive.by_index(index) {
            Ok(file) => file,
            Err(_) => {
                if !flags.contains(&PartFlag::Encrypted) {
                    flags.push(PartFlag::Encrypted);
                }
                if let Some(inner) = decrypt_zip_entry(bytes, index, passwords) {
                    let name = names.get(index).cloned();
                    if !charge(budget, inner.len() as u64, 1) {
                        return;
                    }
                    walk(&inner, name.as_deref(), passwords, budget, parts);
                }
                continue;
            }
        };
        if file.is_dir() {
            continue;
        }
        let name = file.name().to_string();
        let declared = file.size();
        let compressed = file.compressed_size();
        if !charge(budget, declared, compressed) {
            return;
        }
        let reader = file;
        let mut buf = Vec::new();
        if reader
            .take(budget.limits.max_uncompressed_bytes)
            .read_to_end(&mut buf)
            .is_err()
        {
            budget.hit = true;
            return;
        }
        if buf.len() as u64 > budget.limits.max_uncompressed_bytes {
            budget.hit = true;
            return;
        }
        walk(&buf, Some(&name), passwords, budget, parts);
    }
}

fn decrypt_zip_entry(bytes: &[u8], index: usize, passwords: &[String]) -> Option<Vec<u8>> {
    if passwords.is_empty() {
        return None;
    }
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).ok()?;
    for password in passwords.iter().take(32) {
        if let Ok(mut file) = archive.by_index_decrypt(index, password.as_bytes()) {
            let mut buf = Vec::new();
            if file.read_to_end(&mut buf).is_ok() {
                return Some(buf);
            }
        }
    }
    None
}

fn gunzip(
    bytes: &[u8],
    filename: Option<&str>,
    passwords: &[String],
    budget: &mut Budget,
    parts: &mut Vec<PartInfo>,
) {
    let decoder = flate2::read::GzDecoder::new(bytes);
    let mut buf = Vec::new();
    let cap = budget
        .limits
        .max_uncompressed_bytes
        .saturating_sub(budget.bytes) as usize;
    if decoder.take(cap as u64 + 1).read_to_end(&mut buf).is_err() || buf.len() as u64 > cap as u64
    {
        budget.hit = true;
        return;
    }
    if !charge(budget, buf.len() as u64, bytes.len() as u64) {
        return;
    }
    let inner_name = filename
        .and_then(|name| name.strip_suffix(".gz"))
        .unwrap_or("gunzip");
    if buf.len() > 262 && &buf[257..262] == b"ustar" {
        untar(&buf, passwords, budget, parts);
    }
    walk(&buf, Some(inner_name), passwords, budget, parts);
}

fn untar(bytes: &[u8], passwords: &[String], budget: &mut Budget, parts: &mut Vec<PartInfo>) {
    let mut archive = tar::Archive::new(Cursor::new(bytes));
    let entries = match archive.entries() {
        Ok(entries) => entries,
        Err(_) => return,
    };
    for entry in entries {
        if budget.hit {
            return;
        }
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => continue,
        };
        let name = entry
            .path()
            .ok()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();
        let declared = entry.size();
        if !charge(budget, declared, declared.max(1)) {
            return;
        }
        let mut buf = Vec::new();
        if entry
            .take(budget.limits.max_uncompressed_bytes)
            .read_to_end(&mut buf)
            .is_err()
        {
            budget.hit = true;
            return;
        }
        walk(&buf, Some(&name), passwords, budget, parts);
    }
}

fn unpack_iso(bytes: &[u8], passwords: &[String], budget: &mut Budget, parts: &mut Vec<PartInfo>) {
    if bytes.len() < 0x8000 + 156 + 34 {
        return;
    }
    let pvd = &bytes[0x8000..];
    if pvd.len() < 156 + 34 || &pvd[1..6] != b"CD001" {
        return;
    }
    let root = &pvd[156..];
    let extent = u32::from_le_bytes(root[2..6].try_into().unwrap_or([0; 4])) as usize;
    let size = u32::from_le_bytes(root[10..14].try_into().unwrap_or([0; 4])) as usize;
    let start = extent.saturating_mul(2048);
    let end = start.saturating_add(size).min(bytes.len());
    if start >= bytes.len() || end <= start {
        return;
    }
    let mut offset = start;
    let mut files = 0u32;
    while offset + 33 < end && files < budget.limits.max_files {
        let len = bytes[offset] as usize;
        if len < 33 {
            break;
        }
        if offset + len > bytes.len() {
            break;
        }
        let rec = &bytes[offset..offset + len];
        let file_extent = u32::from_le_bytes(rec[2..6].try_into().unwrap_or([0; 4])) as usize;
        let file_size = u32::from_le_bytes(rec[10..14].try_into().unwrap_or([0; 4])) as usize;
        let name_len = rec[32] as usize;
        if 33 + name_len > rec.len() {
            break;
        }
        let name = String::from_utf8_lossy(&rec[33..33 + name_len])
            .trim_end_matches(';')
            .trim_end_matches('.')
            .to_string();
        let flags = rec[25];
        let is_dir = flags & 0x02 != 0;
        if !is_dir && name != "\u{0}" && name != "\u{1}" && file_size > 0 {
            let file_start = file_extent.saturating_mul(2048);
            let file_end = file_start.saturating_add(file_size).min(bytes.len());
            if file_start < bytes.len()
                && file_end > file_start
                && charge(
                    budget,
                    (file_end - file_start) as u64,
                    (file_end - file_start) as u64,
                )
            {
                walk(
                    &bytes[file_start..file_end],
                    Some(&name),
                    passwords,
                    budget,
                    parts,
                );
            }
        }
        offset += len;
        files += 1;
    }
}

pub fn passwords_from_message(text: &str) -> Vec<String> {
    password_candidates(text)
}
