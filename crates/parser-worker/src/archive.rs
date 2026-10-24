//! Bounded archive extraction. Limits stop zip bombs before they expand.
//! Sizes declared in archive headers are never trusted: every read is capped
//! by what is left of the budget and charged with the bytes actually read.
use crate::external::Findings;
use crate::filetype::{self, FileKind};
use crate::office::{self, password_candidates};
use crate::parse::ContentChecks;
use crate::yara::YaraScan;
use crate::{html_smuggling, onenote, pdf, shortcut, svg};
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
    extract_with(bytes, filename, limits, passwords, None)
}

/// Same as [`extract`], and matches YARA rules against the blob and every
/// member.
pub fn extract_with(
    bytes: &[u8],
    filename: Option<&str>,
    limits: &ExtractLimits,
    passwords: &[String],
    yara: Option<&mut YaraScan<'_>>,
) -> Extracted {
    let mut budget = Budget::new(limits, None).with_yara(yara);
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

/// Limits shared by every attachment of one message. With YARA rules, every
/// part recorded through [`Budget::part`] is matched as well.
pub struct Budget<'a, 'r> {
    depth: u32,
    files: u32,
    bytes: u64,
    limits: ExtractLimits,
    out_dir: Option<PathBuf>,
    stored: HashMap<String, String>,
    pub hit: bool,
    pub store_failed: Option<String>,
    yara: Option<&'a mut YaraScan<'r>>,
    /// HTML smuggling and QR checks, for a message parse.
    pub(crate) checks: Option<ContentChecks>,
}

enum Stop {
    Limit,
    Corrupt,
}

impl<'a, 'r> Budget<'a, 'r> {
    pub fn with_yara(mut self, yara: Option<&'a mut YaraScan<'r>>) -> Self {
        self.yara = yara;
        self
    }

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
            yara: None,
            checks: None,
        }
    }

    pub(crate) fn with_checks(mut self, checks: ContentChecks) -> Self {
        self.checks = Some(checks);
        self
    }

    /// HTML smuggling and QR checks on one part or member.
    pub(crate) fn check(
        &mut self,
        bytes: &[u8],
        filename: Option<&str>,
        html_type: bool,
        flags: &mut Vec<PartFlag>,
    ) {
        if let Some(checks) = self.checks.as_mut() {
            checks.run(bytes, filename, html_type, &filetype::detect(bytes), flags);
        }
    }

    /// Flags and links a document check found. Links go to link analysis
    /// with the message's other URLs (message parse only).
    pub(crate) fn record(&mut self, found: Findings, flags: &mut Vec<PartFlag>) {
        for flag in found.flags {
            add(flags, flag);
        }
        if let Some(checks) = self.checks.as_mut() {
            for link in found.links {
                checks.link(link);
            }
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
        if let Some(yara) = self.yara.as_mut() {
            let name = filename.or(content_type.as_deref()).unwrap_or("part");
            yara.scan(name, bytes);
        }
        let sha256 = filetype::sha256(bytes);
        let path = self.store(&sha256, bytes);
        PartInfo {
            is_attachment: filename.is_some(),
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
        documents(bytes, filename, &kind, passwords, budget, parts, &mut flags);
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
        // Not unpacked: flagged for policy, and fails closed like any
        // container that cannot be opened.
        _ if filetype::is_disk_image(&kind) => {
            add(&mut flags, PartFlag::DiskImage);
            add(&mut flags, PartFlag::Unscannable);
        }
        // RAR is not unpacked (licence), so it cannot be inspected.
        _ => add(&mut flags, PartFlag::Unscannable),
    }
    budget.leave();
    if budget.hit {
        add(&mut flags, PartFlag::LimitExceeded);
    }
    flags
}

/// Active content in documents and shell files that are not archives:
/// SVG, shortcuts, RTF, PDF and OneNote. PDF and OneNote embedded files
/// become child parts under the same limits as archive members.
fn documents(
    bytes: &[u8],
    filename: Option<&str>,
    kind: &FileKind,
    passwords: &[String],
    budget: &mut Budget,
    parts: &mut Vec<PartInfo>,
    flags: &mut Vec<PartFlag>,
) {
    let text = html_smuggling::decoded(bytes);
    if svg::is_svg(filename, &kind.label, &text) && svg::active(&text) {
        add(flags, PartFlag::SvgActive);
    }
    if let Some(found) = shortcut::inspect(bytes, filename, kind) {
        budget.record(found, flags);
    }
    if kind.label == "application/rtf" {
        budget.record(office::rtf_external(bytes), flags);
    }
    if pdf::is_pdf(bytes) {
        let scan = pdf::scan(bytes);
        budget.record(scan.found, flags);
        if scan.limit_hit {
            budget.hit = true;
            add(flags, PartFlag::LimitExceeded);
        }
        if scan.unscannable {
            add(flags, PartFlag::Unscannable);
        }
        let embedded = scan.embedded.into_iter().enumerate().map(|(n, file)| {
            let name = file
                .name
                .unwrap_or_else(|| format!("pdf-embedded-{}", n + 1));
            (name, file.data, file.flate)
        });
        embedded_files(embedded, passwords, budget, parts, flags);
    } else if kind.label == "application/onenote" {
        let (files, more) = onenote::embedded(bytes);
        if !files.is_empty() {
            add(flags, PartFlag::OneNoteEmbedded);
        }
        if more {
            budget.hit = true;
            add(flags, PartFlag::LimitExceeded);
        }
        let embedded = files
            .into_iter()
            .enumerate()
            .map(|(n, data)| (format!("onenote-embedded-{}", n + 1), data, false));
        embedded_files(embedded, passwords, budget, parts, flags);
    }
}

/// Files embedded in a document, as child parts: (name, stream bytes,
/// FlateDecode). They count against the same budget as archive members.
fn embedded_files<'b>(
    files: impl Iterator<Item = (String, &'b [u8], bool)>,
    passwords: &[String],
    budget: &mut Budget,
    parts: &mut Vec<PartInfo>,
    flags: &mut Vec<PartFlag>,
) {
    let mut files = files.peekable();
    if files.peek().is_none() {
        return;
    }
    if budget.hit || !budget.enter() {
        add(flags, PartFlag::LimitExceeded);
        return;
    }
    for (name, data, flate) in files {
        if budget.hit || !budget.admit() {
            break;
        }
        let read = if flate {
            let allowed = budget.ratio_cap(data.len() as u64);
            budget.read_bounded(flate2::read::ZlibDecoder::new(data), allowed)
        } else {
            budget.read_bounded(data, u64::MAX)
        };
        match read {
            Ok(buf) => child(&buf, &name, passwords, budget, parts),
            Err(Stop::Limit) => break,
            Err(Stop::Corrupt) => add(flags, PartFlag::Unscannable),
        }
    }
    budget.leave();
    if budget.hit {
        add(flags, PartFlag::LimitExceeded);
    }
}

fn child(
    bytes: &[u8],
    name: &str,
    passwords: &[String],
    budget: &mut Budget,
    parts: &mut Vec<PartInfo>,
) {
    let mut flags = inspect(bytes, Some(name), passwords, budget, parts);
    budget.check(bytes, Some(name), false, &mut flags);
    let part = budget.part(Some(name), None, bytes, flags);
    parts.push(part);
}

fn add(flags: &mut Vec<PartFlag>, flag: PartFlag) {
    if !flags.contains(&flag) {
        flags.push(flag);
    }
}

pub fn is_archive(kind: &FileKind) -> bool {
    filetype::is_archive(kind)
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
            Ok(buf) => {
                // The document, not the member, carries what its parts load.
                budget.record(office::ooxml_external(&name, &buf), flags);
                child(&buf, &name, passwords, budget, parts);
            }
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

/// Body-text passwords tried on one 7z archive. Each try runs the archive's
/// key derivation (2^NumCyclesPower SHA-256 rounds), so it is capped by
/// count, by time and by the declared cost.
const MAX_7Z_GUESSES: usize = 4;
const MAX_7Z_GUESS_TIME: std::time::Duration = std::time::Duration::from_secs(3);
/// 7-Zip's own default; anything above it is refused for guessing.
const MAX_7Z_CYCLES_POWER: u8 = 19;
const AES_7Z: &[u8] = &[0x06, 0xf1, 0x07, 0x01];

fn un7z(
    bytes: &[u8],
    passwords: &[String],
    budget: &mut Budget,
    parts: &mut Vec<PartInfo>,
    flags: &mut Vec<PartFlag>,
) {
    use sevenz_rust2::{Error, Password};
    let start = parts.len();
    let deadline = std::time::Instant::now() + MAX_7Z_GUESS_TIME;
    let candidates = std::iter::once(Password::empty()).chain(
        passwords
            .iter()
            .take(MAX_7Z_GUESSES)
            .map(|p| Password::new(p)),
    );
    let costly = aes_cycles_power(bytes).is_some_and(|power| power > MAX_7Z_CYCLES_POWER);
    for (attempt, password) in candidates.enumerate() {
        if attempt > 0 && (costly || std::time::Instant::now() > deadline) {
            break;
        }
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

/// Highest AES NumCyclesPower named in the archive's header, read before
/// any key derivation. The header itself may be encrypted, so the coder
/// records (`flags, 06 F1 07 01, prop size, props...`) are found by search.
fn aes_cycles_power(bytes: &[u8]) -> Option<u8> {
    let le = |range: std::ops::Range<usize>| -> Option<usize> {
        let raw: [u8; 8] = bytes.get(range)?.try_into().ok()?;
        usize::try_from(u64::from_le_bytes(raw)).ok()
    };
    let start = 32usize.checked_add(le(12..20)?)?;
    let end = start.checked_add(le(20..28)?)?.min(bytes.len());
    let header = bytes.get(start..end)?;
    header
        .windows(AES_7Z.len() + 2)
        .filter(|window| window.starts_with(AES_7Z) && window[AES_7Z.len()] > 0)
        .map(|window| window[AES_7Z.len() + 1] & 0x3f)
        .max()
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
