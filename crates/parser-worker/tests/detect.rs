use currawong_core::config::ExtractLimits;
use currawong_core::PartFlag;
use currawong_parser::archive::extract;
use currawong_parser::filetype::{detect, flags_for};
use currawong_parser::parse::parse_bytes;
use std::io::{Cursor, Write};

fn pe_stub() -> Vec<u8> {
    let mut bytes = vec![0u8; 0x80];
    bytes[0] = b'M';
    bytes[1] = b'Z';
    bytes[0x3c] = 0x40;
    bytes[0x40] = b'P';
    bytes[0x41] = b'E';
    bytes
}

fn limits() -> ExtractLimits {
    ExtractLimits {
        max_depth: 2,
        max_uncompressed_bytes: 4096,
        max_files: 4,
        max_ratio: 8,
    }
}

#[test]
fn renamed_pe_is_executable_without_clamav() {
    let bytes = pe_stub();
    let kind = detect(&bytes);
    let flags = flags_for(&bytes, Some("invoice.pdf"), &kind);
    assert!(flags.contains(&PartFlag::Executable));
    assert!(flags.contains(&PartFlag::ExtMismatch));
}

#[test]
fn docm_has_macro() {
    let mut cursor = Cursor::new(Vec::new());
    {
        let mut zip = zip::ZipWriter::new(&mut cursor);
        let opts = zip::write::SimpleFileOptions::default();
        zip.start_file("word/vbaProject.bin", opts).unwrap();
        zip.write_all(b"benign-placeholder").unwrap();
        zip.finish().unwrap();
    }
    let bytes = cursor.into_inner();
    let message = format!(
        "From: a@example.test\r\nTo: b@example.test\r\nSubject: doc\r\nMIME-Version: 1.0\r\nContent-Type: application/vnd.ms-word.document.macroEnabled.12; name=\"note.docm\"\r\nContent-Disposition: attachment; filename=\"note.docm\"\r\nContent-Transfer-Encoding: base64\r\n\r\n{}\r\n",
        base64_encode(&bytes)
    );
    let parsed = parse_bytes("m", message.as_bytes(), &limits());
    assert!(parsed.error.is_none(), "{:?}", parsed.error);
    assert!(
        parsed
            .parts
            .iter()
            .any(|part| part.flags.contains(&PartFlag::HasMacro)),
        "{:?}",
        parsed.parts
    );
}

#[test]
fn zip_bomb_hits_the_limit() {
    let mut cursor = Cursor::new(Vec::new());
    {
        let mut zip = zip::ZipWriter::new(&mut cursor);
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        zip.start_file("zeros.bin", opts).unwrap();
        zip.write_all(&vec![0u8; 64 * 1024]).unwrap();
        zip.finish().unwrap();
    }
    let bytes = cursor.into_inner();
    let extracted = extract(&bytes, Some("bomb.zip"), &limits(), &[]);
    assert!(extracted.limit_hit, "compressed {} bytes", bytes.len());
    assert!(extracted
        .parts
        .iter()
        .any(|part| part.flags.contains(&PartFlag::LimitExceeded)));
}

fn base64_encode(bytes: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    let mut i = 0;
    while i + 3 <= bytes.len() {
        let n = ((bytes[i] as u32) << 16) | ((bytes[i + 1] as u32) << 8) | bytes[i + 2] as u32;
        out.push(T[((n >> 18) & 63) as usize] as char);
        out.push(T[((n >> 12) & 63) as usize] as char);
        out.push(T[((n >> 6) & 63) as usize] as char);
        out.push(T[(n & 63) as usize] as char);
        i += 3;
    }
    if i < bytes.len() {
        let b0 = bytes[i] as u32;
        let b1 = if i + 1 < bytes.len() {
            bytes[i + 1] as u32
        } else {
            0
        };
        let n = (b0 << 16) | (b1 << 8);
        out.push(T[((n >> 18) & 63) as usize] as char);
        out.push(T[((n >> 12) & 63) as usize] as char);
        if i + 1 < bytes.len() {
            out.push(T[((n >> 6) & 63) as usize] as char);
        } else {
            out.push('=');
        }
        out.push('=');
    }
    out
}
