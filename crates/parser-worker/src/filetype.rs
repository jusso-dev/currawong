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

pub fn flags_for(bytes: &[u8], filename: Option<&str>, kind: &FileKind) -> Vec<PartFlag> {
    let mut flags = Vec::new();
    if kind.executable {
        flags.push(PartFlag::Executable);
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
    let Some(name) = filename else { return false };
    let ext = name.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    if ext.is_empty() || ext == name.to_ascii_lowercase() {
        return false;
    }
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
