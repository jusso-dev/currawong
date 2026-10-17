//! Review regressions for #25: archives, nested mail and active content.
use base64::Engine as _;
use currawong_core::config::ExtractLimits;
use currawong_core::{PartFlag, PartInfo};
use currawong_parser::archive::extract;
use currawong_parser::filetype::{detect, flags_for};
use currawong_parser::parse::{parse_bytes, parse_with};
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

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn zip_of(entries: &[(&str, &[u8])], method: zip::CompressionMethod) -> Vec<u8> {
    let mut cursor = Cursor::new(Vec::new());
    {
        let mut zip = zip::ZipWriter::new(&mut cursor);
        let opts = zip::write::SimpleFileOptions::default().compression_method(method);
        for (name, data) in entries {
            zip.start_file(*name, opts).unwrap();
            zip.write_all(data).unwrap();
        }
        zip.finish().unwrap();
    }
    cursor.into_inner()
}

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(data).unwrap();
    enc.finish().unwrap()
}

fn attachment(name: &str, content_type: &str, bytes: &[u8]) -> String {
    format!(
        "--b\r\nContent-Type: {content_type}; name=\"{name}\"\r\nContent-Disposition: attachment; filename=\"{name}\"\r\nContent-Transfer-Encoding: base64\r\n\r\n{}\r\n",
        b64(bytes)
    )
}

fn multipart(body: &str, parts: &[String]) -> String {
    let mut out = String::from(
        "From: a@example.test\r\nTo: b@example.test\r\nSubject: t\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"b\"\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\n",
    );
    out.push_str(body);
    out.push_str("\r\n");
    for part in parts {
        out.push_str(part);
    }
    out.push_str("--b--\r\n");
    out
}

fn has(parts: &[PartInfo], flag: PartFlag) -> bool {
    parts.iter().any(|part| part.flags.contains(&flag))
}

fn named<'a>(parts: &'a [PartInfo], name: &str) -> &'a PartInfo {
    parts
        .iter()
        .find(|part| part.filename.as_deref() == Some(name))
        .unwrap_or_else(|| panic!("no part {name} in {parts:?}"))
}

/// Rewrites the uncompressed size in every local and central header.
fn lie_about_size(zip: &mut [u8], size: u32) {
    let mut i = 0;
    while i + 4 <= zip.len() {
        if zip[i..i + 4] == *b"PK\x03\x04" {
            zip[i + 22..i + 26].copy_from_slice(&size.to_le_bytes());
        }
        if zip[i..i + 4] == *b"PK\x01\x02" {
            zip[i + 24..i + 28].copy_from_slice(&size.to_le_bytes());
        }
        i += 1;
    }
}

#[test]
fn zip_entry_with_a_lying_size_header_is_flagged() {
    let mut bomb = zip_of(
        &[("zeros.bin", &vec![0u8; 64 * 1024])],
        zip::CompressionMethod::Deflated,
    );
    lie_about_size(&mut bomb, 100);
    let limits = ExtractLimits {
        max_depth: 3,
        max_uncompressed_bytes: 8 * 1024,
        max_files: 16,
        max_ratio: 1000,
    };
    // Reads are capped by the budget whatever the header says (zip 2 read
    // past the declared size), and zip 9 also rejects the mismatch. Either
    // way the archive must fail closed, never come back silently truncated.
    let extracted = extract(&bomb, Some("bomb.zip"), &limits, &[]);
    assert!(
        has(&extracted.parts, PartFlag::LimitExceeded)
            || has(&extracted.parts, PartFlag::Unscannable),
        "{:?}",
        extracted.parts
    );
    assert!(!extracted.parts.iter().any(|p| p.flags.is_empty()));
    // The root carries the verdict, and no truncated member is reported.
    assert_eq!(extracted.parts[0].filename.as_deref(), Some("bomb.zip"));
    assert!(!extracted
        .parts
        .iter()
        .any(|p| p.filename.as_deref() == Some("zeros.bin")
            && p.size as usize >= 8 * 1024
            && !p.flags.contains(&PartFlag::LimitExceeded)));
}

#[test]
fn nameless_zip_part_over_the_ratio_is_flagged() {
    let bomb = zip_of(
        &[("zeros.bin", &vec![0u8; 512 * 1024])],
        zip::CompressionMethod::Deflated,
    );
    let raw = format!(
        "From: a@example.test\r\nTo: b@example.test\r\nSubject: t\r\nMIME-Version: 1.0\r\nContent-Type: application/zip\r\nContent-Transfer-Encoding: base64\r\n\r\n{}\r\n",
        b64(&bomb)
    );
    let parsed = parse_bytes("m", raw.as_bytes(), &roomy());
    assert!(parsed.error.is_none(), "{:?}", parsed.error);
    assert!(
        has(&parsed.parts, PartFlag::LimitExceeded),
        "{:?}",
        parsed.parts
    );
}

#[test]
fn limits_apply_to_the_whole_message() {
    let one = zip_of(
        &[("a.txt", &vec![b'a'; 3000])],
        zip::CompressionMethod::Stored,
    );
    let two = zip_of(
        &[("b.txt", &vec![b'b'; 3000])],
        zip::CompressionMethod::Stored,
    );
    let raw = multipart(
        "two archives",
        &[
            attachment("one.zip", "application/zip", &one),
            attachment("two.zip", "application/zip", &two),
        ],
    );
    let limits = ExtractLimits {
        max_depth: 3,
        max_uncompressed_bytes: 4000,
        max_files: 64,
        max_ratio: 100,
    };
    let parsed = parse_bytes("m", raw.as_bytes(), &limits);
    assert!(
        has(&parsed.parts, PartFlag::LimitExceeded),
        "{:?}",
        parsed.parts
    );
}

#[test]
fn pe_inside_a_forwarded_message_is_flagged() {
    let inner = multipart(
        "see attached",
        &[attachment("invoice.pdf", "application/pdf", &pe_stub())],
    );
    let raw = format!(
        "From: c@example.test\r\nTo: d@example.test\r\nSubject: Fwd\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"outer\"\r\n\r\n--outer\r\nContent-Type: text/plain\r\n\r\nforwarding\r\n--outer\r\nContent-Type: message/rfc822\r\nContent-Disposition: attachment; filename=\"fwd.eml\"\r\n\r\n{inner}\r\n--outer--\r\n"
    );
    let parsed = parse_bytes("m", raw.as_bytes(), &roomy());
    assert!(parsed.error.is_none(), "{:?}", parsed.error);
    let pe = named(&parsed.parts, "invoice.pdf");
    assert!(pe.flags.contains(&PartFlag::Executable), "{pe:?}");
    assert!(pe.flags.contains(&PartFlag::ExtMismatch), "{pe:?}");
}

#[test]
fn every_gzip_member_is_read() {
    let mut data = gzip(b"");
    data.extend(gzip(&pe_stub()));
    let extracted = extract(&data, Some("invoice.pdf.gz"), &roomy(), &[]);
    let pe = named(&extracted.parts, "invoice.pdf");
    assert!(pe.flags.contains(&PartFlag::Executable), "{pe:?}");
}

#[test]
fn tar_gz_members_are_charged_once() {
    let file = vec![b'x'; 3000];
    let mut builder = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_ustar();
    header.set_size(file.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    builder
        .append_data(&mut header, "notes.txt", file.as_slice())
        .unwrap();
    let tarball = builder.into_inner().unwrap();
    let data = gzip(&tarball);
    // Room for the tar and its member once, not twice.
    let limits = ExtractLimits {
        max_depth: 5,
        max_uncompressed_bytes: (tarball.len() + file.len() + 64) as u64,
        max_files: 64,
        max_ratio: 1000,
    };
    let extracted = extract(&data, Some("notes.tar.gz"), &limits, &[]);
    assert!(!extracted.limit_hit, "{:?}", extracted.parts);
    named(&extracted.parts, "notes.txt");
}

#[test]
fn seven_zip_members_are_extracted() {
    let mut writer = sevenz_rust2::ArchiveWriter::new(Cursor::new(Vec::new())).unwrap();
    writer
        .push_archive_entry(
            sevenz_rust2::ArchiveEntry::new_file("invoice.pdf"),
            Some(pe_stub().as_slice()),
        )
        .unwrap();
    let archive = writer.finish().unwrap().into_inner();
    let extracted = extract(&archive, Some("docs.7z"), &roomy(), &[]);
    let pe = named(&extracted.parts, "invoice.pdf");
    assert!(pe.flags.contains(&PartFlag::Executable), "{pe:?}");
    assert!(!has(&extracted.parts, PartFlag::Encrypted));
}

#[test]
fn encrypted_seven_zip_is_flagged_and_opened_with_a_body_password() {
    let mut writer = sevenz_rust2::ArchiveWriter::new(Cursor::new(Vec::new())).unwrap();
    writer.set_content_methods(vec![
        sevenz_rust2::encoder_options::AesEncoderOptions::new("Secret123".into()).into(),
        sevenz_rust2::EncoderMethod::LZMA2.into(),
    ]);
    writer
        .push_archive_entry(
            sevenz_rust2::ArchiveEntry::new_file("invoice.pdf"),
            Some(pe_stub().as_slice()),
        )
        .unwrap();
    let archive = writer.finish().unwrap().into_inner();
    let locked = extract(&archive, Some("docs.7z"), &roomy(), &[]);
    assert!(
        has(&locked.parts, PartFlag::Encrypted),
        "{:?}",
        locked.parts
    );
    assert!(!has(&locked.parts, PartFlag::Executable));

    let raw = multipart(
        "The password is Secret123 for the invoice.",
        &[attachment(
            "docs.7z",
            "application/x-7z-compressed",
            &archive,
        )],
    );
    let parsed = parse_bytes("m", raw.as_bytes(), &roomy());
    assert!(
        has(&parsed.parts, PartFlag::Encrypted),
        "{:?}",
        parsed.parts
    );
    let pe = named(&parsed.parts, "invoice.pdf");
    assert!(pe.flags.contains(&PartFlag::Executable), "{pe:?}");
}

#[test]
fn zip_crypto_archive_is_flagged_and_opened_with_a_body_password() {
    let archive = zip_crypto("invoice.pdf", &pe_stub(), b"Secret123");
    let locked = extract(&archive, Some("docs.zip"), &roomy(), &[]);
    assert!(
        has(&locked.parts, PartFlag::Encrypted),
        "{:?}",
        locked.parts
    );
    assert!(!has(&locked.parts, PartFlag::Unscannable));

    let raw = multipart(
        "Use Secret123 to open it.",
        &[attachment("docs.zip", "application/zip", &archive)],
    );
    let parsed = parse_bytes("m", raw.as_bytes(), &roomy());
    assert!(has(&parsed.parts, PartFlag::Encrypted));
    let pe = named(&parsed.parts, "invoice.pdf");
    assert!(pe.flags.contains(&PartFlag::Executable), "{pe:?}");
}

#[test]
fn corrupt_zip_and_rar_cannot_be_inspected() {
    let mut zip = zip_of(&[("a.txt", b"hello")], zip::CompressionMethod::Stored);
    zip.truncate(zip.len() - 30);
    let extracted = extract(&zip, Some("a.zip"), &roomy(), &[]);
    assert!(
        has(&extracted.parts, PartFlag::Unscannable),
        "{:?}",
        extracted.parts
    );
    assert!(!has(&extracted.parts, PartFlag::Encrypted));

    let rar = b"Rar!\x1a\x07\x01\x00rest-of-archive".to_vec();
    let extracted = extract(&rar, Some("a.rar"), &roomy(), &[]);
    assert!(has(&extracted.parts, PartFlag::Unscannable));
}

#[test]
fn iso_subdirectories_and_padded_records_are_walked() {
    let iso = iso_with_nested_file("INVOICE.PDF;1", &pe_stub());
    let extracted = extract(&iso, Some("disk.iso"), &roomy(), &[]);
    let pe = named(&extracted.parts, "INVOICE.PDF");
    assert!(pe.flags.contains(&PartFlag::Executable), "{pe:?}");
}

#[test]
fn rtf_object_after_padding_and_short_header_is_flagged() {
    let mut rtf = b"{\\rt1 ".to_vec();
    rtf.extend(std::iter::repeat_n(b' ', 2 * 1024 * 1024));
    rtf.extend_from_slice(b"{\\object\\objemb{\\*\\objdata 0105}}}");
    let kind = detect(&rtf);
    assert_eq!(kind.label, "application/rtf");
    assert!(flags_for(&rtf, Some("note.rtf"), &kind).contains(&PartFlag::HasOleObject));
}

#[test]
fn shortcut_is_executable_by_content() {
    let mut lnk = vec![
        0x4c, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x46,
    ];
    lnk.resize(76, 0);
    let kind = detect(&lnk);
    let flags = flags_for(&lnk, Some("report.pdf"), &kind);
    assert!(flags.contains(&PartFlag::Executable), "{flags:?}");
    assert!(flags.contains(&PartFlag::ExtMismatch), "{flags:?}");
}

#[test]
fn executable_declared_as_a_document_is_a_mismatch() {
    let raw = format!(
        "From: a@example.test\r\nTo: b@example.test\r\nSubject: t\r\nMIME-Version: 1.0\r\nContent-Type: application/pdf\r\nContent-Transfer-Encoding: base64\r\n\r\n{}\r\n",
        b64(&pe_stub())
    );
    let parsed = parse_bytes("m", raw.as_bytes(), &roomy());
    assert!(
        has(&parsed.parts, PartFlag::ExtMismatch),
        "{:?}",
        parsed.parts
    );
}

#[test]
fn part_count_is_capped_and_flagged() {
    let parts: Vec<String> = (0..300)
        .map(|i| format!("--b\r\nContent-Type: text/plain\r\n\r\npart {i}\r\n"))
        .collect();
    let raw = multipart("many", &parts);
    let limits = ExtractLimits {
        max_files: 100,
        ..roomy()
    };
    let parsed = parse_bytes("m", raw.as_bytes(), &limits);
    assert!(parsed.parts.len() <= 101, "{}", parsed.parts.len());
    assert!(has(&parsed.parts, PartFlag::LimitExceeded));
}

#[test]
fn text_parts_are_reported_once() {
    let raw = b"From: a@example.test\r\nTo: b@example.test\r\nSubject: t\r\n\r\nhello\r\n";
    let parsed = parse_bytes("m", raw, &roomy());
    assert_eq!(parsed.parts.len(), 1, "{:?}", parsed.parts);
}

#[test]
fn extracted_parts_are_written_for_the_av_engines() {
    let archive = zip_of(
        &[("inner.txt", b"archive member")],
        zip::CompressionMethod::Deflated,
    );
    let raw = multipart(
        "see attached",
        &[attachment("a.zip", "application/zip", &archive)],
    );
    let dir = tempfile::tempdir().unwrap();
    let parsed = parse_with("m", raw.as_bytes(), &roomy(), Some(dir.path()));
    let member = named(&parsed.parts, "inner.txt");
    let path = member.path.as_ref().expect("member written");
    assert_eq!(std::fs::read(path).unwrap(), b"archive member");
}

/// A stored ZipCrypto entry. The zip crate can read these but not write them.
fn zip_crypto(name: &str, data: &[u8], password: &[u8]) -> Vec<u8> {
    let mut crc = flate2::Crc::new();
    crc.update(data);
    let crc = crc.sum();
    let mut keys = ZipKeys::new(password);
    let mut header = [0u8; 12];
    header[11] = (crc >> 24) as u8;
    let mut body: Vec<u8> = header.iter().map(|b| keys.encrypt(*b)).collect();
    body.extend(data.iter().map(|b| keys.encrypt(*b)));
    let name = name.as_bytes();
    let mut out = Vec::new();
    let fields = |out: &mut Vec<u8>| {
        out.extend_from_slice(&1u16.to_le_bytes()); // encrypted
        out.extend_from_slice(&0u16.to_le_bytes()); // stored
        out.extend_from_slice(&[0, 0, 0x21, 0]); // time, date
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&(body.len() as u32).to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
    };
    out.extend_from_slice(b"PK\x03\x04");
    out.extend_from_slice(&20u16.to_le_bytes());
    fields(&mut out);
    out.extend_from_slice(name);
    out.extend_from_slice(&body);
    let central = out.len();
    out.extend_from_slice(b"PK\x01\x02");
    out.extend_from_slice(&20u16.to_le_bytes());
    out.extend_from_slice(&20u16.to_le_bytes());
    fields(&mut out);
    out.extend_from_slice(&[0; 6]); // comment, disk, internal attrs
    out.extend_from_slice(&0u32.to_le_bytes()); // external attrs
    out.extend_from_slice(&0u32.to_le_bytes()); // local header offset
    out.extend_from_slice(name);
    let central_len = out.len() - central;
    out.extend_from_slice(b"PK\x05\x06");
    out.extend_from_slice(&[0; 4]);
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&(central_len as u32).to_le_bytes());
    out.extend_from_slice(&(central as u32).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

struct ZipKeys([u32; 3]);

impl ZipKeys {
    fn new(password: &[u8]) -> Self {
        let mut keys = Self([0x1234_5678, 0x2345_6789, 0x3456_7890]);
        for b in password {
            keys.update(*b);
        }
        keys
    }

    fn update(&mut self, b: u8) {
        self.0[0] = crc_byte(self.0[0], b);
        self.0[1] = self.0[1]
            .wrapping_add(self.0[0] & 0xff)
            .wrapping_mul(134_775_813)
            .wrapping_add(1);
        self.0[2] = crc_byte(self.0[2], (self.0[1] >> 24) as u8);
    }

    fn encrypt(&mut self, plain: u8) -> u8 {
        let t = (self.0[2] | 2) as u16;
        let key = (t.wrapping_mul(t ^ 1) >> 8) as u8;
        self.update(plain);
        plain ^ key
    }
}

fn crc_byte(crc: u32, b: u8) -> u32 {
    let mut c = (crc ^ b as u32) & 0xff;
    for _ in 0..8 {
        c = if c & 1 != 0 {
            0xedb8_8320 ^ (c >> 1)
        } else {
            c >> 1
        };
    }
    c ^ (crc >> 8)
}

/// Root directory (two sectors, the second reached only past zero padding)
/// holding a subdirectory that holds the file.
fn iso_with_nested_file(name: &str, data: &[u8]) -> Vec<u8> {
    const S: usize = 2048;
    let (root, root2, sub, file) = (20usize, 21usize, 22usize, 23usize);
    let mut iso = vec![0u8; (file + 1) * S];
    let record = |extent: usize, size: usize, dir: bool, id: &[u8]| {
        let len = 33 + id.len() + (id.len() + 1) % 2;
        let mut rec = vec![0u8; len];
        rec[0] = len as u8;
        rec[2..6].copy_from_slice(&(extent as u32).to_le_bytes());
        rec[10..14].copy_from_slice(&(size as u32).to_le_bytes());
        rec[25] = if dir { 2 } else { 0 };
        rec[32] = id.len() as u8;
        rec[33..33 + id.len()].copy_from_slice(id);
        rec
    };
    let pvd = 16 * S;
    iso[pvd] = 1;
    iso[pvd + 1..pvd + 6].copy_from_slice(b"CD001");
    let root_rec = record(root, 2 * S, true, &[0]);
    iso[pvd + 156..pvd + 156 + root_rec.len()].copy_from_slice(&root_rec);
    let mut at = root * S;
    for rec in [
        record(root, 2 * S, true, &[0]),
        record(root, 2 * S, true, &[1]),
    ] {
        iso[at..at + rec.len()].copy_from_slice(&rec);
        at += rec.len();
    }
    let sub_rec = record(sub, S, true, b"DOCS");
    iso[root2 * S..root2 * S + sub_rec.len()].copy_from_slice(&sub_rec);
    let mut at = sub * S;
    for rec in [
        record(sub, S, true, &[0]),
        record(root, 2 * S, true, &[1]),
        record(file, data.len(), false, name.as_bytes()),
    ] {
        iso[at..at + rec.len()].copy_from_slice(&rec);
        at += rec.len();
    }
    iso[file * S..file * S + data.len()].copy_from_slice(data);
    iso
}
