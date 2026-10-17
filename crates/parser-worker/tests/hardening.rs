//! Review round 2: extension tricks, opaque containers, raw text bytes,
//! 7z guessing cost and the nesting guard.
use base64::Engine as _;
use currawong_core::config::ExtractLimits;
use currawong_core::{PartFlag, PartInfo};
use currawong_parser::archive::extract;
use currawong_parser::filetype::{detect, file_extension, flags_for};
use currawong_parser::parse::{nesting_limit, parse_bytes, parse_with};
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

fn roomy() -> ExtractLimits {
    ExtractLimits {
        max_depth: 5,
        max_uncompressed_bytes: 1024 * 1024,
        max_files: 64,
        max_ratio: 100,
    }
}

fn has(parts: &[PartInfo], flag: PartFlag) -> bool {
    parts.iter().any(|part| part.flags.contains(&flag))
}

#[test]
fn extension_is_the_one_windows_acts_on() {
    for name in [
        "evil.exe",
        "evil.EXE",
        "evil.exe.",
        "evil.exe . .",
        "evil.exe\0",
        "evil.exe\r\n",
        "docs/evil.exe",
        "C:\\Users\\x\\evil.exe",
        "evil.exe:Zone.Identifier",
        "evil.exe::$DATA",
    ] {
        assert_eq!(file_extension(name).as_deref(), Some("exe"), "{name:?}");
    }
    assert_eq!(file_extension("README"), None);
    assert_eq!(file_extension("archive.tar.gz").as_deref(), Some("gz"));
}

#[test]
fn renamed_pe_with_trailing_dot_is_still_a_mismatch() {
    let pe = pe_stub();
    let kind = detect(&pe);
    let flags = flags_for(&pe, Some("invoice.pdf."), &kind);
    assert!(flags.contains(&PartFlag::ExtMismatch), "{flags:?}");
}

#[test]
fn containers_we_cannot_open_fail_closed() {
    let samples: Vec<(&str, Vec<u8>)> = vec![
        ("a.bz2", b"BZh91AY&SY rest".to_vec()),
        ("a.xz", b"\xfd7zXZ\0 rest".to_vec()),
        ("a.zst", b"\x28\xb5\x2f\xfd rest".to_vec()),
        ("a.cab", b"MSCF\0\0\0\0 rest".to_vec()),
        ("a.arj", b"\x60\xea rest".to_vec()),
        ("a.lzh", b"..-lh5- rest".to_vec()),
        ("a.ace", b"1234567**ACE** rest".to_vec()),
        ("a.vhd", b"conectix rest".to_vec()),
        // Named like an archive, content is nothing we recognise (a v7 tar).
        ("old.tar", vec![b'a'; 1024]),
        ("disk.img", vec![0u8; 4096]),
    ];
    for (name, bytes) in samples {
        let extracted = extract(&bytes, Some(name), &roomy(), &[]);
        assert!(
            has(&extracted.parts, PartFlag::Unscannable),
            "{name}: {:?}",
            extracted.parts
        );
    }
}

#[test]
fn zip_appended_to_an_image_is_opened() {
    let mut cursor = Cursor::new(Vec::new());
    {
        let mut zip = zip::ZipWriter::new(&mut cursor);
        zip.start_file("invoice.pdf", zip::write::SimpleFileOptions::default())
            .unwrap();
        zip.write_all(&pe_stub()).unwrap();
        zip.finish().unwrap();
    }
    let mut polyglot = vec![0xff, 0xd8, 0xff, 0xe0, 0, 16, b'J', b'F', b'I', b'F', 0];
    polyglot.extend(vec![0u8; 512]);
    polyglot.extend(cursor.into_inner());
    let extracted = extract(&polyglot, Some("photo.jpg"), &roomy(), &[]);
    let root = &extracted.parts[0];
    assert!(root.flags.contains(&PartFlag::ExtMismatch), "{root:?}");
    let pe = extracted
        .parts
        .iter()
        .find(|part| part.filename.as_deref() == Some("invoice.pdf"))
        .expect("member found");
    assert!(pe.flags.contains(&PartFlag::Executable));
}

#[test]
fn text_parts_reach_the_engines_as_sent_not_as_utf8() {
    let body = [0xff, 0xfe, b'A', 0x80];
    let raw = format!(
        "From: a@example.test\r\nTo: b@example.test\r\nSubject: t\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=iso-8859-1\r\nContent-Transfer-Encoding: base64\r\n\r\n{}\r\n",
        base64::engine::general_purpose::STANDARD.encode(body)
    );
    let dir = tempfile::tempdir().unwrap();
    let parsed = parse_with("m", raw.as_bytes(), &roomy(), Some(dir.path()));
    let path = parsed.parts[0].path.as_ref().expect("written");
    assert_eq!(std::fs::read(path).unwrap(), body);
}

fn seven_zip(password: &str, power: u8) -> Vec<u8> {
    let mut writer = sevenz_rust2::ArchiveWriter::new(Cursor::new(Vec::new())).unwrap();
    let mut aes = sevenz_rust2::encoder_options::AesEncoderOptions::new(password.into());
    aes.num_cycles_power = power;
    writer.set_content_methods(vec![aes.into(), sevenz_rust2::EncoderMethod::LZMA2.into()]);
    writer
        .push_archive_entry(
            sevenz_rust2::ArchiveEntry::new_file("invoice.pdf"),
            Some(pe_stub().as_slice()),
        )
        .unwrap();
    writer.finish().unwrap().into_inner()
}

#[test]
fn seven_zip_guessing_is_capped() {
    // The right password is the fifth candidate: past the cap of four.
    let archive = seven_zip("Secret123", 8);
    let words = ["alpha1", "bravo2", "charlie3", "delta4", "Secret123"];
    let passwords: Vec<String> = words.iter().map(|w| w.to_string()).collect();
    let extracted = extract(&archive, Some("docs.7z"), &roomy(), &passwords);
    assert!(has(&extracted.parts, PartFlag::Encrypted));
    assert!(
        !has(&extracted.parts, PartFlag::Executable),
        "{:?}",
        extracted.parts
    );
    let extracted = extract(&archive, Some("docs.7z"), &roomy(), &passwords[4..]);
    assert!(has(&extracted.parts, PartFlag::Executable));
}

#[test]
fn costly_seven_zip_key_derivation_is_not_guessed() {
    let archive = seven_zip("Secret123", 20);
    let started = std::time::Instant::now();
    let extracted = extract(&archive, Some("docs.7z"), &roomy(), &["Secret123".into()]);
    assert!(has(&extracted.parts, PartFlag::Encrypted));
    assert!(
        !has(&extracted.parts, PartFlag::Executable),
        "{:?}",
        extracted.parts
    );
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
}

/// Builds `depth` messages, each attached to the next.
pub fn nested_messages(depth: usize) -> Vec<u8> {
    let mut raw = String::with_capacity(depth * 80);
    for _ in 0..depth {
        raw.push_str("From: a@example.test\r\nContent-Type: message/rfc822\r\n\r\n");
    }
    raw.push_str("From: a@example.test\r\nSubject: bottom\r\n\r\nhello\r\n");
    raw.into_bytes()
}

#[test]
fn deep_nesting_is_refused_before_parsing() {
    let raw = nested_messages(50_000);
    assert!(nesting_limit(&raw).is_some());
    let parsed = parse_bytes("m", &raw, &roomy());
    let reason = parsed.error.expect("refused");
    assert!(reason.contains("nesting limit"), "{reason}");
    assert!(nesting_limit(&nested_messages(3)).is_none());
}
