//! Bounded archive extraction. Limits stop zip bombs before they expand.
//! Sizes declared in archive headers are never trusted: every read is capped
//! by what is left of the budget and charged with the bytes actually read.
use crate::filetype::{self, FileKind};
use crate::office::{self, password_candidates};
use currawong_core::config::ExtractLimits;
use currawong_core::{PartFlag, PartInfo};
use std::collections::HashMap;
use std::io::{Cursor, ErrorKind, Read};
use std::path::{Path, PathBuf};

#[derive(Debug, Default)]
pub struct Extracted {
    pub parts: Vec<PartInfo>,
    pub limit_hit: bool,
}

/// Standalone extraction of one blob (fuzzing and tests). The first part is
/// the blob itself, followed by everything extracted from it.
pub fn extract(
    bytes: &[u8],
    filename: Option<&str>,
    limits: &ExtractLimits,
    passwords: &[String],
) -> Extracted {
    let mut budget = Budget::new(limits, None);
    let mut parts = Vec::new();
    let flags = inspect(bytes, filename, passwords, &mut budget, &mut parts);
    let root = budget.part(filename, None, bytes, flags);
    parts.insert(0, root);
    if budget.hit {
        for part in &mut parts {
            add(&mut part.flags, PartFlag::LimitExceeded);
        }
    }
    Extracted {
        parts,
        limit_hit: budget.hit,
    }
}

/// Limits shared by every attachment of one message.
pub struct Budget {
    depth: u32,
    files: u32,
    bytes: u64,
    limits: ExtractLimits,
    out_dir: Option<PathBuf>,
    stored: HashMap<String, String>,
    pub hit: bool,
    pub store_failed: Option<String>,
}

enum Stop {
    Limit,
    Corrupt,
}

impl Budget {
    pub fn new(limits: &ExtractLimits, out_dir: Option<&Path>) -> Self {
        Self {
            depth: 0,
            files: 0,
            bytes: 0,
            limits: limits.clone(),
            out_dir: out_dir.map(Path::to_path_buf),
            stored: HashMap::new(),
            hit: false,
            store_failed: None,
        }
    }

    pub fn limits(&self) -> &ExtractLimits {
        &self.limits
    }

    /// Counts one more file. Past `max_files` the limit is hit.
    pub fn admit(&mut self) -> bool {
        if self.files >= self.limits.max_files {
            self.hit = true;
            return false;
        }
        self.files += 1;
        true
    }

    /// Nesting of archives and attached messages.
    pub fn enter(&mut self) -> bool {
        if self.depth >= self.limits.max_depth {
            self.hit = true;
            return false;
        }
        self.depth += 1;
        true
    }

    pub fn leave(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    fn remaining(&self) -> u64 {
        self.limits
            .max_uncompressed_bytes
            .saturating_sub(self.bytes)
    }

    fn ratio_cap(&self, compressed: u64) -> u64 {
        compressed
            .max(1)
            .saturating_mul(self.limits.max_ratio.max(1) as u64)
    }

    /// Reads at most `allowed` bytes and what is left of the byte budget,
    /// whichever is smaller. One byte more than that is a limit hit.
    fn read_bounded(&mut self, reader: impl Read, allowed: u64) -> Result<Vec<u8>, Stop> {
        let cap = self.remaining().min(allowed);
        let mut buf = Vec::new();
        match reader.take(cap.saturating_add(1)).read_to_end(&mut buf) {
            Ok(_) => {}
            Err(err) if err.kind() == ErrorKind::OutOfMemory => {
                self.hit = true;
                return Err(Stop::Limit);
            }
            Err(_) => return Err(Stop::Corrupt),
        }
        if buf.len() as u64 > cap {
            self.hit = true;
            return Err(Stop::Limit);
        }
        self.bytes += buf.len() as u64;
        Ok(buf)
    }

    /// Writes the bytes to the output directory, once per distinct content.
    fn store(&mut self, sha256: &str, bytes: &[u8]) -> Option<String> {
        let dir = self.out_dir.as_ref()?;
        if let Some(path) = self.stored.get(sha256) {
            return Some(path.clone());
        }
        let path = dir.join(format!("{:04}.part", self.stored.len()));
        if let Err(err) = std::fs::write(&path, bytes) {
            self.store_failed = Some(format!("write {}: {err}", path.display()));
            return None;
        }
        let path = path.to_string_lossy().to_string();
        self.stored.insert(sha256.to_string(), path.clone());
        Some(path)
    }

    pub fn part(
        &mut self,
        filename: Option<&str>,
        content_type: Option<String>,
        bytes: &[u8],
        flags: Vec<PartFlag>,
    ) -> PartInfo {
        let sha256 = filetype::sha256(bytes);
        let path = self.store(&sha256, bytes);
        PartInfo {
            content_type: content_type
                .filter(|ct| !ct.is_empty())
                .unwrap_or_else(|| filetype::detect(bytes).label),
            filename: filename.map(str::to_string),
            size: bytes.len() as u64,
            sha256,
            flags,
            path,
        }
    }
}

/// Flags for one blob. Archive members are pushed to `parts`; the caller
/// records the blob itself.
pub fn inspect(
    bytes: &[u8],
    filename: Option<&str>,
    passwords: &[String],
    budget: &mut Budget,
    parts: &mut Vec<PartInfo>,
) -> Vec<PartFlag> {
    let kind = filetype::detect(bytes);
    let mut flags = filetype::flags_for(bytes, filename, &kind);
    if !is_archive(&kind) {
        return flags;
    }
    if budget.hit || !budget.enter() {
        add(&mut flags, PartFlag::LimitExceeded);
        return flags;
    }
    match kind.label.as_str() {
        "application/zip" => unzip(bytes, passwords, budget, parts, &mut flags),
        "application/gzip" => gunzip(bytes, filename, passwords, budget, parts, &mut flags),
        "application/x-tar" => untar(bytes, passwords, budget, parts, &mut flags),
        "application/x-iso9660-image" => unpack_iso(bytes, passwords, budget, parts),
        "application/x-7z-compressed" => un7z(bytes, passwords, budget, parts, &mut flags),
        // RAR is not unpacked (licence), so it cannot be inspected.
        _ => add(&mut flags, PartFlag::Unscannable),
    }
    budget.leave();
    if budget.hit {
        add(&mut flags, PartFlag::LimitExceeded);
    }
    flags
}

fn child(
    bytes: &[u8],
    name: &str,
    passwords: &[String],
    budget: &mut Budget,
    parts: &mut Vec<PartInfo>,
) {
    let flags = inspect(bytes, Some(name), passwords, budget, parts);
    let part = budget.part(Some(name), None, bytes, flags);
    parts.push(part);
}

fn add(flags: &mut Vec<PartFlag>, flag: PartFlag) {
    if !flags.contains(&flag) {
        flags.push(flag);
    }
}

pub fn is_archive(kind: &FileKind) -> bool {
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

fn unzip(
    bytes: &[u8],
    passwords: &[String],
    budget: &mut Budget,
    parts: &mut Vec<PartInfo>,
    flags: &mut Vec<PartFlag>,
) {
    let Ok(mut archive) = zip::ZipArchive::new(Cursor::new(bytes)) else {
        add(flags, PartFlag::Unscannable);
        return;
    };
    let names: Vec<String> = archive
        .file_names()
        .filter_map(|name| name.ok().map(|name| name.to_string()))
        .collect();
    if office::ooxml_macro(&names) {
        add(flags, PartFlag::HasMacro);
    }
    for index in 0..archive.len() {
        if budget.hit {
            return;
        }
        let (encrypted, is_dir, name, compressed) = match archive.by_index_raw(index) {
            Ok(file) => (
                file.encrypted(),
                file.is_dir(),
                file.name().map(|name| name.to_string()).unwrap_or_default(),
                file.compressed_size(),
            ),
            Err(_) => {
                add(flags, PartFlag::Unscannable);
                continue;
            }
        };
        if is_dir {
            continue;
        }
        if !budget.admit() {
            return;
        }
        let allowed = budget.ratio_cap(compressed);
        let read = if encrypted {
            add(flags, PartFlag::Encrypted);
            match decrypt_zip_entry(&mut archive, index, passwords, budget, allowed) {
                Some(read) => read,
                None => continue,
            }
        } else {
            match archive.by_index(index) {
                Ok(file) => budget.read_bounded(file, allowed),
                Err(_) => Err(Stop::Corrupt),
            }
        };
        match read {
            Ok(buf) => child(&buf, &name, passwords, budget, parts),
            Err(Stop::Limit) => return,
            Err(Stop::Corrupt) => add(flags, PartFlag::Unscannable),
        }
    }
}

/// Tries candidate passwords from the message body. `None` when none work.
fn decrypt_zip_entry(
    archive: &mut zip::ZipArchive<Cursor<&[u8]>>,
    index: usize,
    passwords: &[String],
    budget: &mut Budget,
    allowed: u64,
) -> Option<Result<Vec<u8>, Stop>> {
    for password in passwords.iter().take(32) {
        let Ok(file) = archive.by_index_decrypt(index, password.as_bytes()) else {
            continue;
        };
        match budget.read_bounded(file, allowed) {
            Ok(buf) => return Some(Ok(buf)),
            Err(Stop::Limit) => return Some(Err(Stop::Limit)),
            // A wrong password can pass the ZipCrypto check byte and then
            // fail the CRC. Try the next one.
            Err(Stop::Corrupt) => continue,
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
    flags: &mut Vec<PartFlag>,
) {
    if !budget.admit() {
        return;
    }
    // Every member, not just the first: a PE can sit behind an empty one.
    let decoder = flate2::read::MultiGzDecoder::new(bytes);
    let allowed = budget.ratio_cap(bytes.len() as u64);
    let buf = match budget.read_bounded(decoder, allowed) {
        Ok(buf) => buf,
        Err(Stop::Limit) => return,
        Err(Stop::Corrupt) => {
            add(flags, PartFlag::Unscannable);
            return;
        }
    };
    let inner_name = filename
        .and_then(|name| {
            name.strip_suffix(".gz")
                .or_else(|| name.strip_suffix(".tgz"))
                .or_else(|| name.strip_suffix(".GZ"))
        })
        .unwrap_or("gunzip");
    child(&buf, inner_name, passwords, budget, parts);
}

fn untar(
    bytes: &[u8],
    passwords: &[String],
    budget: &mut Budget,
    parts: &mut Vec<PartInfo>,
    flags: &mut Vec<PartFlag>,
) {
    let mut archive = tar::Archive::new(Cursor::new(bytes));
    let entries = match archive.entries() {
        Ok(entries) => entries,
        Err(_) => {
            add(flags, PartFlag::Unscannable);
            return;
        }
    };
    for entry in entries {
        if budget.hit {
            return;
        }
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => {
                add(flags, PartFlag::Unscannable);
                return;
            }
        };
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let name = entry
            .path()
            .ok()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();
        if !budget.admit() {
            return;
        }
        // Tar does not compress, so the ratio does not apply to members.
        match budget.read_bounded(entry, u64::MAX) {
            Ok(buf) => child(&buf, &name, passwords, budget, parts),
            Err(Stop::Limit) => return,
            Err(Stop::Corrupt) => {
                add(flags, PartFlag::Unscannable);
                return;
            }
        }
    }
}

fn un7z(
    bytes: &[u8],
    passwords: &[String],
    budget: &mut Budget,
    parts: &mut Vec<PartInfo>,
    flags: &mut Vec<PartFlag>,
) {
    use sevenz_rust2::{Error, Password};
    let start = parts.len();
    let candidates = std::iter::once(Password::empty())
        .chain(passwords.iter().take(32).map(|p| Password::new(p)))
        .collect::<Vec<_>>();
    for password in candidates {
        parts.truncate(start);
        match un7z_with(bytes, password, passwords, budget, parts) {
            Ok(()) => return,
            Err(Error::PasswordRequired | Error::MaybeBadPassword(_)) => {
                add(flags, PartFlag::Encrypted);
                if budget.hit {
                    return;
                }
            }
            Err(_) if budget.hit => return,
            Err(_) if flags.contains(&PartFlag::Encrypted) => {
                // A wrong password usually surfaces as a checksum or data
                // error. Keep trying the remaining candidates.
            }
            Err(_) => {
                add(flags, PartFlag::Unscannable);
                return;
            }
        }
    }
    parts.truncate(start);
}

fn un7z_with(
    bytes: &[u8],
    password: sevenz_rust2::Password,
    passwords: &[String],
    budget: &mut Budget,
    parts: &mut Vec<PartInfo>,
) -> Result<(), sevenz_rust2::Error> {
    let mut reader = sevenz_rust2::ArchiveReader::new(Cursor::new(bytes), password)?;
    reader.set_thread_count(1);
    // Solid blocks give no per-file compressed size, so the ratio applies
    // to everything taken out of this archive.
    let mut allowed = budget.ratio_cap(bytes.len() as u64);
    reader.for_each_entries(|entry, data| {
        if entry.is_directory {
            return Ok(true);
        }
        if budget.hit || !budget.admit() {
            return Ok(false);
        }
        match budget.read_bounded(data, allowed) {
            Ok(buf) => {
                allowed = allowed.saturating_sub(buf.len() as u64);
                child(&buf, &entry.name, passwords, budget, parts);
                Ok(true)
            }
            Err(Stop::Limit) => Ok(false),
            Err(Stop::Corrupt) => Err(sevenz_rust2::Error::Other("7z member read".into())),
        }
    })
}

const SECTOR: usize = 2048;
const ISO_MAX_DIR_DEPTH: u32 = 8;

/// ISO 9660 directory walk, subdirectories included. A zero length record
/// pads to the next sector.
fn unpack_iso(bytes: &[u8], passwords: &[String], budget: &mut Budget, parts: &mut Vec<PartInfo>) {
    let Some(pvd) = bytes.get(0x8000..0x8000 + 190) else {
        return;
    };
    if &pvd[1..6] != b"CD001" {
        return;
    }
    let root = &pvd[156..190];
    let mut dirs = vec![(le32(&root[2..6]), le32(&root[10..14]), 0u32)];
    let mut seen = Vec::new();
    while let Some((extent, size, depth)) = dirs.pop() {
        if budget.hit || seen.contains(&extent) || seen.len() >= 256 {
            continue;
        }
        seen.push(extent);
        let start = extent.saturating_mul(SECTOR);
        let end = start.saturating_add(size).min(bytes.len());
        let mut offset = start;
        while offset < end && !budget.hit {
            let len = bytes[offset] as usize;
            if len == 0 {
                offset = (offset / SECTOR + 1) * SECTOR;
                continue;
            }
            let Some(rec) = bytes
                .get(offset..offset + len)
                .filter(|rec| rec.len() >= 33)
            else {
                break;
            };
            offset += len;
            let name_len = rec[32] as usize;
            let Some(raw_name) = rec.get(33..33 + name_len) else {
                continue;
            };
            if raw_name == [0] || raw_name == [1] {
                continue;
            }
            let file_extent = le32(&rec[2..6]);
            let file_size = le32(&rec[10..14]);
            if rec[25] & 0x02 != 0 {
                if depth < ISO_MAX_DIR_DEPTH {
                    dirs.push((file_extent, file_size, depth + 1));
                }
                continue;
            }
            let name = String::from_utf8_lossy(raw_name)
                .trim_end_matches(";1")
                .trim_end_matches('.')
                .to_string();
            let file_start = file_extent.saturating_mul(SECTOR);
            let file_end = file_start.saturating_add(file_size).min(bytes.len());
            if file_end <= file_start || !budget.admit() {
                continue;
            }
            match budget.read_bounded(&bytes[file_start..file_end], u64::MAX) {
                Ok(buf) => child(&buf, &name, passwords, budget, parts),
                Err(_) => return,
            }
        }
    }
}

fn le32(bytes: &[u8]) -> usize {
    u32::from_le_bytes(bytes.try_into().unwrap_or([0; 4])) as usize
}

pub fn passwords_from_message(text: &str) -> Vec<String> {
    password_candidates(text)
}
