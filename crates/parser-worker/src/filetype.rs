//! Content identification. A renamed executable is still an executable.
use currawong_core::PartFlag;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileKind {
    pub label: String,
    pub executable: bool,
}

/// Shell link header size and CLSID 00021401-0000-0000-C000-000000000046.
const LNK_MAGIC: [u8; 20] = [
    0x4c, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x46,
];

pub fn detect(bytes: &[u8]) -> FileKind {
    if looks_like_pe(bytes) {
        return FileKind {
            label: "application/vnd.microsoft.portable-executable".into(),
            executable: true,
        };
    }
    if bytes.starts_with(&[0x7f, b'E', b'L', b'F']) {
        return FileKind {
            label: "application/x-elf".into(),
            executable: true,
        };
    }
    if bytes.len() >= 4
        && (bytes.starts_with(&[0xfe, 0xed, 0xfa, 0xce])
            || bytes.starts_with(&[0xfe, 0xed, 0xfa, 0xcf])
            || bytes.starts_with(&[0xcf, 0xfa, 0xed, 0xfe]))
    {
        return FileKind {
            label: "application/x-mach-binary".into(),
            executable: true,
        };
    }
    if bytes.starts_with(&LNK_MAGIC) {
        return FileKind {
            label: "application/x-ms-shortcut".into(),
            executable: true,
        };
    }
    if is_ole(bytes) {
        return FileKind {
            label: "application/x-cfb".into(),
            executable: false,
        };
    }
    if bytes.starts_with(b"PK\x03\x04") || bytes.starts_with(b"PK\x05\x06") {
        return FileKind {
            label: "application/zip".into(),
            executable: false,
        };
    }
    if bytes.starts_with(b"7z\xbc\xaf\x27\x1c") {
        return FileKind {
            label: "application/x-7z-compressed".into(),
            executable: false,
        };
    }
    if bytes.starts_with(b"Rar!\x1a\x07") {
        return FileKind {
            label: "application/vnd.rar".into(),
            executable: false,
        };
    }
    if bytes.starts_with(&[0x1f, 0x8b]) {
        return FileKind {
            label: "application/gzip".into(),
            executable: false,
        };
    }
    if bytes.len() > 262 && &bytes[257..262] == b"ustar" {
        return FileKind {
            label: "application/x-tar".into(),
            executable: false,
        };
    }
    if is_iso(bytes) {
        return FileKind {
            label: "application/x-iso9660-image".into(),
            executable: false,
        };
    }
    // Word opens anything that starts with `{\rt`, not only `{\rtf1`.
    if bytes.starts_with(b"{\\rt") {
        return FileKind {
            label: "application/rtf".into(),
            executable: false,
        };
    }
    if crate::onenote::is_onenote(bytes) {
        return FileKind {
            label: "application/onenote".into(),
            executable: false,
        };
    }
    if let Some(label) = opaque_container(bytes) {
        return FileKind {
            label: label.into(),
            executable: false,
        };
    }
    // A zip appended to something else (a polyglot, or a self-extractor
    // that is not a PE) is still opened as a zip.
    if has_trailing_zip(bytes) {
        return FileKind {
            label: "application/zip".into(),
            executable: false,
        };
    }
    if let Some(kind) = infer::get(bytes) {
        let executable = matches!(kind.extension(), "exe" | "dll" | "elf" | "so" | "dylib");
        return FileKind {
            label: kind.mime_type().to_string(),
            executable,
        };
    }
    FileKind {
        label: "application/octet-stream".into(),
        executable: false,
    }
}

/// Containers that are recognised and not unpacked. They cannot be
/// inspected, so they fail closed.
fn opaque_container(bytes: &[u8]) -> Option<&'static str> {
    let at = |offset: usize, magic: &[u8]| bytes.get(offset..offset + magic.len()) == Some(magic);
    let tail = |magic: &[u8]| bytes.len() >= 512 && bytes[bytes.len() - 512..].starts_with(magic);
    if at(0, b"BZh") && bytes.get(3).is_some_and(u8::is_ascii_digit) {
        return Some("application/x-bzip2");
    }
    if at(0, &[0xfd, b'7', b'z', b'X', b'Z', 0]) {
        return Some("application/x-xz");
    }
    if at(0, &[0x28, 0xb5, 0x2f, 0xfd]) {
        return Some("application/zstd");
    }
    if at(0, b"MSCF\0\0\0\0") {
        return Some("application/vnd.ms-cab-compressed");
    }
    if at(0, &[0x60, 0xea]) {
        return Some("application/x-arj");
    }
    if at(2, b"-lh") && bytes.get(6) == Some(&b'-') {
        return Some("application/x-lzh-compressed");
    }
    if at(7, b"**ACE**") {
        return Some("application/x-ace-compressed");
    }
    if at(0, b"LZIP") || at(0, &[0x1f, 0x9d]) {
        return Some("application/x-compress");
    }
    if at(0, b"MSWIM\0\0\0") {
        return Some("application/x-ms-wim");
    }
    if at(0, b"vhdxfile") || at(0, b"conectix") || tail(b"conectix") {
        return Some("application/x-vhd");
    }
    if tail(b"koly") {
        return Some("application/x-apple-diskimage");
    }
    if raw_disk(bytes) {
        return Some(RAW_DISK);
    }
    let udf = (0x8001..0x10001)
        .step_by(2048)
        .any(|offset| at(offset, b"BEA01") || at(offset, b"NSR02") || at(offset, b"NSR03"));
    if udf {
        return Some("application/x-udf-image");
    }
    None
}

pub const RAW_DISK: &str = "application/x-raw-disk-image";

/// Disk images whose files Windows mounts without the Mark of the Web. They
/// are recognised and not unpacked.
pub fn is_disk_image(kind: &FileKind) -> bool {
    matches!(
        kind.label.as_str(),
        "application/x-vhd" | "application/x-apple-diskimage" | RAW_DISK
    )
}

/// A FAT, exFAT or NTFS boot sector at the start, or an MBR whose first
/// partition starts with one, or a GPT header.
fn raw_disk(bytes: &[u8]) -> bool {
    if bytes.get(510..512) != Some(&[0x55, 0xaa]) {
        return false;
    }
    if boot_sector(bytes) || bytes.get(512..520) == Some(b"EFI PART") {
        return true;
    }
    (0..4).any(|entry| {
        let at = 446 + entry * 16;
        let kind = bytes[at + 4];
        let lba = u32::from_le_bytes(bytes[at + 8..at + 12].try_into().unwrap_or([0; 4]));
        let start = (lba as usize).saturating_mul(512);
        kind != 0 && lba != 0 && bytes.get(start..).is_some_and(boot_sector)
    })
}

fn boot_sector(sector: &[u8]) -> bool {
    let at = |offset: usize, magic: &[u8]| sector.get(offset..offset + magic.len()) == Some(magic);
    sector.get(510..512) == Some(&[0x55, 0xaa])
        && matches!(sector.first(), Some(0xeb | 0xe9))
        && (at(54, b"FAT12   ")
            || at(54, b"FAT16   ")
            || at(54, b"FAT     ")
            || at(82, b"FAT32   ")
            || at(3, b"NTFS    ")
            || at(3, b"EXFAT   "))
}

/// A zip end-of-central-directory record near the end of a blob that does
/// not start like a zip.
fn has_trailing_zip(bytes: &[u8]) -> bool {
    let start = bytes.len().saturating_sub(65_557);
    bytes.len() >= 22
        && bytes[start..]
            .windows(4)
            .any(|window| window == b"PK\x05\x06")
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
            | "application/x-bzip2"
            | "application/x-xz"
            | "application/zstd"
            | "application/vnd.ms-cab-compressed"
            | "application/x-arj"
            | "application/x-lzh-compressed"
            | "application/x-ace-compressed"
            | "application/x-compress"
            | "application/x-ms-wim"
            | "application/x-vhd"
            | "application/x-apple-diskimage"
            | "application/x-udf-image"
            | RAW_DISK
    )
}

/// Extensions of archives and disk images. A file named like one whose
/// content is not a container we can open cannot be inspected.
const CONTAINER_EXTENSIONS: &[&str] = &[
    "zip", "7z", "rar", "gz", "tgz", "tar", "iso", "bz2", "tbz", "tbz2", "xz", "txz", "zst",
    "tzst", "cab", "arj", "lzh", "lha", "ace", "img", "vhd", "vhdx", "udf", "dmg", "wim", "z",
    "lz", "lzma",
];

/// The extension Windows would act on: last path component, before any
/// `:stream` suffix, with trailing dots, spaces and control characters
/// removed (Windows drops them), in lower case.
pub fn file_extension(name: &str) -> Option<String> {
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
    let base = base.split(':').next().unwrap_or(base);
    let base = base.trim_end_matches(|c: char| c == '.' || c.is_whitespace() || c.is_control());
    let (_, ext) = base.rsplit_once('.')?;
    let ext = ext.trim();
    (!ext.is_empty()).then(|| ext.to_ascii_lowercase())
}

pub fn flags_for(bytes: &[u8], filename: Option<&str>, kind: &FileKind) -> Vec<PartFlag> {
    let mut flags = Vec::new();
    if kind.executable {
        flags.push(PartFlag::Executable);
    }
    let ext = filename.and_then(file_extension);
    if !is_archive(kind)
        && ext
            .as_deref()
            .is_some_and(|e| CONTAINER_EXTENSIONS.contains(&e))
    {
        flags.push(PartFlag::Unscannable);
    }
    if extension_mismatch(filename, kind) {
        flags.push(PartFlag::ExtMismatch);
    }
    if is_ole(bytes) {
        if office::has_macro_ole(bytes) {
            flags.push(PartFlag::HasMacro);
        }
        if office::has_ole_object(bytes) {
            flags.push(PartFlag::HasOleObject);
        }
    }
    if kind.label == "application/rtf" && office::rtf_has_object(bytes) {
        flags.push(PartFlag::HasOleObject);
    }
    flags
}

fn extension_mismatch(filename: Option<&str>, kind: &FileKind) -> bool {
    let Some(ext) = filename.and_then(file_extension) else {
        return false;
    };
    let expected = match kind.label.as_str() {
        "application/vnd.microsoft.portable-executable"
        | "application/x-elf"
        | "application/x-mach-binary" => {
            matches!(
                ext.as_str(),
                "exe" | "dll" | "scr" | "com" | "elf" | "so" | "dylib" | "bin"
            )
        }
        "application/x-ms-shortcut" => ext == "lnk",
        "application/zip" => matches!(
            ext.as_str(),
            "zip"
                | "docx"
                | "xlsx"
                | "pptx"
                | "docm"
                | "xlsm"
                | "pptm"
                | "dotx"
                | "dotm"
                | "xltx"
                | "xltm"
                | "xlsb"
                | "xlam"
                | "potx"
                | "potm"
                | "ppsx"
                | "ppsm"
                | "ppam"
                | "vsdx"
                | "vsdm"
                | "odt"
                | "ods"
                | "odp"
                | "odg"
                | "epub"
                | "kmz"
                | "jar"
        ),
        "application/x-cfb" => matches!(
            ext.as_str(),
            "doc"
                | "dot"
                | "xls"
                | "xlt"
                | "xla"
                | "ppt"
                | "pps"
                | "pot"
                | "msi"
                | "msg"
                | "vsd"
                | "pub"
                | "mpp"
                | "bin"
        ),
        "application/pdf" => ext == "pdf",
        "application/rtf" => matches!(ext.as_str(), "rtf" | "doc"),
        "application/gzip" => matches!(ext.as_str(), "gz" | "tgz"),
        "application/x-tar" => matches!(ext.as_str(), "tar" | "tgz"),
        "application/x-7z-compressed" => ext == "7z",
        "application/x-iso9660-image" => ext == "iso",
        _ => true,
    };
    !expected
}

pub fn looks_like_pe(bytes: &[u8]) -> bool {
    if bytes.len() < 0x40 || bytes[0] != b'M' || bytes[1] != b'Z' {
        return false;
    }
    let off = u32::from_le_bytes([bytes[0x3c], bytes[0x3d], bytes[0x3e], bytes[0x3f]]) as usize;
    bytes.get(off..off + 4) == Some(&[b'P', b'E', 0, 0])
}

pub fn is_ole(bytes: &[u8]) -> bool {
    bytes.starts_with(&[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1])
}

pub fn is_iso(bytes: &[u8]) -> bool {
    bytes.len() > 0x8005 && &bytes[0x8001..0x8006] == b"CD001"
}

pub fn sha256(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(bytes))
}

mod office {
    pub use crate::office::{has_macro_ole, has_ole_object, rtf_has_object};
}
