//! Document and shell-file checks: SVG, Office external content, RTF,
//! OneNote, shortcuts, disk images and PDF. Every fixture is built here from
//! benign bytes that carry only the structural markers being detected.
use base64::Engine as _;
use currawong_core::config::ExtractLimits;
use currawong_core::{PartFlag, PartInfo};
use currawong_parser::archive::extract;
use currawong_parser::parse::parse_bytes;
use std::io::{Cursor, Write};

fn roomy() -> ExtractLimits {
    ExtractLimits {
        max_depth: 5,
        max_uncompressed_bytes: 64 * 1024 * 1024,
        max_files: 64,
        max_ratio: 100,
    }
}

fn pe_stub() -> Vec<u8> {
    let mut bytes = vec![0u8; 0x80];
    bytes[0] = b'M';
    bytes[1] = b'Z';
    bytes[0x3c] = 0x40;
    bytes[0x40] = b'P';
    bytes[0x41] = b'E';
    bytes
}

fn zip_of(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut cursor = Cursor::new(Vec::new());
    {
        let mut zip = zip::ZipWriter::new(&mut cursor);
        let opts = zip::write::SimpleFileOptions::default();
        for (name, data) in entries {
            zip.start_file(*name, opts).unwrap();
            zip.write_all(data).unwrap();
        }
        zip.finish().unwrap();
    }
    cursor.into_inner()
}

fn zlib(data: &[u8]) -> Vec<u8> {
    let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(data).unwrap();
    enc.finish().unwrap()
}

fn flags(bytes: &[u8], name: &str) -> Vec<PartFlag> {
    extract(bytes, Some(name), &roomy(), &[]).parts[0]
        .flags
        .clone()
}

fn has(parts: &[PartInfo], flag: PartFlag) -> bool {
    parts.iter().any(|part| part.flags.contains(&flag))
}

fn message(name: &str, content_type: &str, bytes: &[u8]) -> Vec<u8> {
    format!(
        "From: a@example.test\r\nTo: b@example.test\r\nSubject: t\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"b\"\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nSee attached.\r\n--b\r\nContent-Type: {content_type}; name=\"{name}\"\r\nContent-Disposition: attachment; filename=\"{name}\"\r\nContent-Transfer-Encoding: base64\r\n\r\n{}\r\n--b--\r\n",
        base64::engine::general_purpose::STANDARD.encode(bytes)
    )
    .into_bytes()
}

// ---- SVG ----

const PLAIN_SVG: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="120" height="40" viewBox="0 0 120 40">
  <title>JavaScript training logo</title>
  <rect x="0" y="0" width="120" height="40" fill="steelblue"/>
  <a href="https://example.test/about"><text x="10" y="25" font-family="Arial">online</text></a>
</svg>"#;

/// draw.io exports wrap text in XHTML inside `<foreignObject>`.
const DIAGRAM_SVG: &str = r#"<svg xmlns="http://www.w3.org/2000/svg" width="200" height="80">
<g><foreignObject width="180" height="60"><div xmlns="http://www.w3.org/1999/xhtml" style="display:flex">
<div>Order flow</div></div></foreignObject></g></svg>"#;

#[test]
fn active_svg_is_flagged() {
    let samples = [
        r#"<svg xmlns="http://www.w3.org/2000/svg"><script>var a = 1;</script></svg>"#,
        r#"<svg xmlns="http://www.w3.org/2000/svg" onload="go()"><rect/></svg>"#,
        r#"<svg xmlns="http://www.w3.org/2000/svg"><a href="java&#9;script&#58;go()"><text>x</text></a></svg>"#,
        r#"<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><a xlink:href="data:text/html;base64,PGI+"><text>x</text></a></svg>"#,
        r#"<svg xmlns="http://www.w3.org/2000/svg"><foreignObject><form action="https://example.test/login"><input name="password"/></form></foreignObject></svg>"#,
        r#"<svg xmlns="http://www.w3.org/2000/svg"><foreignObject><meta http-equiv="refresh" content="0;url=https://example.test/"/></foreignObject></svg>"#,
    ];
    for svg in samples {
        assert!(
            flags(svg.as_bytes(), "invoice.svg").contains(&PartFlag::SvgActive),
            "{svg}"
        );
        // By content as well, under another name.
        assert!(
            flags(svg.as_bytes(), "invoice.dat").contains(&PartFlag::SvgActive),
            "{svg}"
        );
    }
}

#[test]
fn utf16_svg_is_read() {
    let svg = r#"<svg xmlns="http://www.w3.org/2000/svg"><script>go()</script></svg>"#;
    let mut bytes = vec![0xff, 0xfe];
    for unit in svg.encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    assert!(flags(&bytes, "scan.svg").contains(&PartFlag::SvgActive));
}

#[test]
fn plain_svg_and_diagrams_are_not_flagged() {
    for svg in [PLAIN_SVG, DIAGRAM_SVG] {
        let flags = flags(svg.as_bytes(), "logo.svg");
        assert!(!flags.contains(&PartFlag::SvgActive), "{svg}: {flags:?}");
    }
    // HTML is not SVG: its script is the HTML smuggling scorer's business.
    let html = b"<html><body><script>var a = 1;</script></body></html>";
    assert!(!flags(html, "page.html").contains(&PartFlag::SvgActive));
}

#[test]
fn svg_in_a_zip_is_flagged() {
    let svg = br#"<svg xmlns="http://www.w3.org/2000/svg" onload="go()"/>"#;
    let zip = zip_of(&[("docs/remittance.svg", svg)]);
    let extracted = extract(&zip, Some("docs.zip"), &roomy(), &[]);
    assert!(
        has(&extracted.parts, PartFlag::SvgActive),
        "{:?}",
        extracted.parts
    );
}

#[test]
fn svg_smuggling_is_scored() {
    let payload = base64::engine::general_purpose::STANDARD.encode("harmless ".repeat(7000));
    let svg = format!(
        r#"<svg xmlns="http://www.w3.org/2000/svg"><script><![CDATA[
var b = atob("{payload}");
var blob = new Blob([b]);
var a = document.createElementNS("http://www.w3.org/1999/xhtml", "a");
a.href = URL.createObjectURL(blob); a.download = "invoice.iso"; a.click();
]]></script></svg>"#
    );
    let parsed = parse_bytes(
        "m",
        &message("doc.svg", "image/svg+xml", svg.as_bytes()),
        &roomy(),
    );
    assert!(parsed.error.is_none(), "{:?}", parsed.error);
    assert!(
        has(&parsed.parts, PartFlag::HtmlSmuggling),
        "{:?}",
        parsed.parts
    );
    assert!(
        has(&parsed.parts, PartFlag::SvgActive),
        "{:?}",
        parsed.parts
    );
}

// ---- Office external content ----

const CONTENT_TYPES: &[u8] = br#"<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>"#;

fn rels(entries: &str) -> Vec<u8> {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">{entries}</Relationships>"#
    )
    .into_bytes()
}

fn document(body: &str) -> Vec<u8> {
    format!(
        r#"<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>{body}</w:body></w:document>"#
    )
    .into_bytes()
}

fn docx(extra: &[(&str, &[u8])]) -> Vec<u8> {
    let body = document("<w:p><w:r><w:t>Quarterly report</w:t></w:r></w:p>");
    let mut entries: Vec<(&str, &[u8])> = vec![
        ("[Content_Types].xml", CONTENT_TYPES),
        ("word/document.xml", &body),
    ];
    entries.extend_from_slice(extra);
    zip_of(&entries)
}

#[test]
fn remote_template_is_flagged_and_its_url_recorded() {
    let settings = rels(
        r#"<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="https://templates.example.test/a.dotm?x=1&amp;y=2" TargetMode="External"/>"#,
    );
    let doc = docx(&[("word/_rels/settings.xml.rels", &settings)]);
    assert!(flags(&doc, "report.docx").contains(&PartFlag::ExternalTemplate));
    let parsed = parse_bytes(
        "m",
        &message("report.docx", "application/octet-stream", &doc),
        &roomy(),
    );
    assert!(
        parsed
            .urls
            .contains(&"https://templates.example.test/a.dotm?x=1&y=2".to_string()),
        "{:?}",
        parsed.urls
    );
}

#[test]
fn unc_frame_and_ole_object_are_flagged() {
    for (kind, target) in [
        ("frame", r"\\fileserver.example.test\share\frame.html"),
        ("oleObject", "http://example.test/object.html!"),
        (
            "attachedTemplate",
            "file://fileserver.example.test/share/t.dotm",
        ),
    ] {
        let rel = rels(&format!(
            r#"<Relationship Id="rId9" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/{kind}" TargetMode="External" Target="{target}"/>"#
        ));
        let doc = docx(&[("word/_rels/document.xml.rels", &rel)]);
        assert!(
            flags(&doc, "a.docx").contains(&PartFlag::ExternalTemplate),
            "{kind} {target}"
        );
    }
}

#[test]
fn local_template_and_web_hyperlink_are_not_flagged() {
    let rel = rels(concat!(
        r#"<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="file:///C:\Users\a\AppData\Roaming\Microsoft\Templates\Normal.dotm" TargetMode="External"/>"#,
        r#"<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="https://example.test/" TargetMode="External"/>"#,
        r#"<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>"#,
    ));
    let body = document(
        r#"<w:p><w:fldSimple w:instr=" PAGE \* MERGEFORMAT "><w:r><w:t>1</w:t></w:r></w:fldSimple></w:p>
<w:p><w:r><w:fldChar w:fldCharType="begin"/></w:r><w:r><w:instrText xml:space="preserve"> HYPERLINK "https://example.test/" </w:instrText></w:r><w:r><w:fldChar w:fldCharType="end"/></w:r></w:p>"#,
    );
    let doc = zip_of(&[
        ("[Content_Types].xml", CONTENT_TYPES),
        ("word/document.xml", &body),
        ("word/_rels/settings.xml.rels", &rel),
    ]);
    let flags = flags(&doc, "letter.docx");
    for flag in [
        PartFlag::ExternalTemplate,
        PartFlag::DdeField,
        PartFlag::ProtocolHandler,
    ] {
        assert!(!flags.contains(&flag), "{flags:?}");
    }
}

#[test]
fn protocol_handler_relationship_is_flagged() {
    let rel = rels(
        r#"<Relationship Id="rId5" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="search-ms:query=invoice&amp;crumb=location:\\fileserver.example.test\share" TargetMode="External"/>"#,
    );
    let doc = docx(&[("word/_rels/document.xml.rels", &rel)]);
    assert!(flags(&doc, "a.docx").contains(&PartFlag::ProtocolHandler));
    let parsed = parse_bytes(
        "m",
        &message("a.docx", "application/octet-stream", &doc),
        &roomy(),
    );
    assert!(
        parsed.urls.iter().any(|url| url.starts_with("search-ms:")),
        "{:?}",
        parsed.urls
    );
}

#[test]
fn split_dde_field_is_flagged() {
    // Word splits field instructions across runs; they are joined.
    let body = document(concat!(
        r#"<w:p><w:r><w:fldChar w:fldCharType="begin"/></w:r>"#,
        r#"<w:r><w:instrText> DD</w:instrText></w:r><w:r><w:instrText>EAUTO c:\\windows\\system32\\notepad.exe "x"</w:instrText></w:r>"#,
        r#"<w:r><w:fldChar w:fldCharType="separate"/></w:r><w:r><w:t>x</w:t></w:r><w:r><w:fldChar w:fldCharType="end"/></w:r></w:p>"#,
    ));
    let doc = zip_of(&[
        ("[Content_Types].xml", CONTENT_TYPES),
        ("word/document.xml", &body),
    ]);
    assert!(flags(&doc, "a.docx").contains(&PartFlag::DdeField));

    let simple = document(r#"<w:p><w:fldSimple w:instr="DDE notepad x y"/></w:p>"#);
    let doc = zip_of(&[("word/footer1.xml", &simple)]);
    assert!(flags(&doc, "a.docx").contains(&PartFlag::DdeField));
}

#[test]
fn excel_dde_link_is_flagged() {
    let link = br#"<?xml version="1.0"?><externalLink xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><ddeLink ddeService="notepad" ddeTopic="x"/></externalLink>"#;
    let xlsx = zip_of(&[
        ("[Content_Types].xml", CONTENT_TYPES),
        ("xl/externalLinks/externalLink1.xml", link),
    ]);
    assert!(flags(&xlsx, "book.xlsx").contains(&PartFlag::DdeField));
}

#[test]
fn docx_inside_a_zip_carries_its_flag() {
    let settings = rels(
        r#"<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="https://templates.example.test/a.dotm" TargetMode="External"/>"#,
    );
    let doc = docx(&[("word/_rels/settings.xml.rels", &settings)]);
    let outer = zip_of(&[("report.docx", &doc)]);
    let extracted = extract(&outer, Some("bundle.zip"), &roomy(), &[]);
    let inner = extracted
        .parts
        .iter()
        .find(|part| part.filename.as_deref() == Some("report.docx"))
        .unwrap();
    assert!(
        inner.flags.contains(&PartFlag::ExternalTemplate),
        "{inner:?}"
    );
}

// ---- RTF ----

#[test]
fn rtf_remote_template_dde_and_objupdate_are_flagged() {
    let template = br"{\rtf1{\*\template https://templates.example.test/a.dot}Hello}";
    assert!(flags(template, "a.rtf").contains(&PartFlag::ExternalTemplate));
    let unc = br"{\rtf1{\*\template \\\\fileserver.example.test\\share\\a.dot}Hello}";
    assert!(flags(unc, "a.rtf").contains(&PartFlag::ExternalTemplate));
    let dde = br"{\rtf1{\field{\*\fldinst {\rtlch\fcs1 DDEAUTO} c:\\windows\\notepad.exe x}{\fldrslt x}}}";
    assert!(flags(dde, "a.rtf").contains(&PartFlag::DdeField));
    let handler =
        br#"{\rtf1{\field{\*\fldinst HYPERLINK "ms-msdt:/id PCWDiagnostic"}{\fldrslt x}}}"#;
    assert!(flags(handler, "a.rtf").contains(&PartFlag::ProtocolHandler));
    let update = br"{\rtf1{\object\objautlink\objupdate{\*\objdata 01}}}";
    assert!(flags(update, "a.rtf").contains(&PartFlag::ExternalTemplate));
}

#[test]
fn plain_rtf_is_not_flagged() {
    let rtf = br"{\rtf1\ansi{\*\template C:\\Users\\a\\Normal.dotm}{\field{\*\fldinst PAGE}{\fldrslt 1}}Searching for search: tips and its: uses.}";
    assert!(flags(rtf, "a.rtf").is_empty(), "{:?}", flags(rtf, "a.rtf"));
}

// ---- OneNote ----

const ONE_FILE: [u8; 16] = [
    0xe4, 0x52, 0x5c, 0x7b, 0x8c, 0xd8, 0xa7, 0x4d, 0xae, 0xb1, 0x53, 0x78, 0xd0, 0x29, 0x96, 0xd3,
];
const FILE_DATA: [u8; 16] = [
    0xe7, 0x16, 0xe3, 0xbd, 0x65, 0x26, 0x11, 0x45, 0xa4, 0xc4, 0x8d, 0x4d, 0x0b, 0x7a, 0x9e, 0xac,
];
const FILE_DATA_FOOTER: [u8; 16] = [
    0x22, 0xa7, 0xfb, 0x71, 0x79, 0x0f, 0x0b, 0x4a, 0xbb, 0x13, 0x89, 0x92, 0x56, 0x42, 0x6b, 0x24,
];

fn onenote(payloads: &[&[u8]]) -> Vec<u8> {
    let mut out = ONE_FILE.to_vec();
    out.resize(1024, 0);
    for payload in payloads {
        out.extend_from_slice(&FILE_DATA);
        out.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        out.extend_from_slice(&[0; 12]);
        out.extend_from_slice(payload);
        while !out.len().is_multiple_of(8) {
            out.push(0);
        }
        out.extend_from_slice(&FILE_DATA_FOOTER);
    }
    out
}

#[test]
fn onenote_embedded_files_are_extracted() {
    let pe = pe_stub();
    let one = onenote(&[b"just a picture", &pe]);
    let extracted = extract(&one, Some("notes.dat"), &roomy(), &[]);
    let root = &extracted.parts[0];
    assert_eq!(root.content_type, "application/onenote");
    assert!(root.flags.contains(&PartFlag::OneNoteEmbedded), "{root:?}");
    let child = extracted
        .parts
        .iter()
        .find(|part| part.filename.as_deref() == Some("onenote-embedded-2"))
        .unwrap();
    assert!(child.flags.contains(&PartFlag::Executable), "{child:?}");
}

#[test]
fn onenote_without_files_and_truncated_lengths() {
    assert!(!flags(&onenote(&[]), "notes.one").contains(&PartFlag::OneNoteEmbedded));
    let mut one = onenote(&[b"x"]);
    let at = 1024 + 16;
    one[at..at + 8].copy_from_slice(&u64::MAX.to_le_bytes());
    let extracted = extract(&one, Some("notes.one"), &roomy(), &[]);
    assert!(has(&extracted.parts, PartFlag::OneNoteEmbedded));
}

#[test]
fn onenote_embedded_files_respect_the_file_limit() {
    let payloads: Vec<&[u8]> = vec![b"x"; 10];
    let limits = ExtractLimits {
        max_files: 4,
        ..roomy()
    };
    let extracted = extract(&onenote(&payloads), Some("notes.one"), &limits, &[]);
    assert!(extracted.limit_hit);
    assert!(has(&extracted.parts, PartFlag::LimitExceeded));
}

// ---- Shortcuts and shell files ----

#[test]
fn internet_shortcuts_to_shares_are_flagged() {
    for url in [
        "file://fileserver.example.test/share/invoice.pdf.exe",
        r"\\fileserver.example.test\share\invoice",
        "search-ms:query=invoice&crumb=location:\\\\fileserver.example.test\\share",
    ] {
        let text = format!("[InternetShortcut]\r\nURL={url}\r\n");
        assert!(
            flags(text.as_bytes(), "invoice.url").contains(&PartFlag::Shortcut),
            "{url}"
        );
        // By content under another name.
        assert!(
            flags(text.as_bytes(), "invoice.txt").contains(&PartFlag::Shortcut),
            "{url}"
        );
    }
    let icon = b"[InternetShortcut]\r\nURL=https://example.test/\r\nIconFile=\\\\fileserver.example.test\\icon.ico\r\nIconIndex=1\r\n";
    assert!(flags(icon, "a.url").contains(&PartFlag::Shortcut));
}

#[test]
fn web_shortcut_is_recorded_not_flagged() {
    let text = b"[InternetShortcut]\r\nURL=https://intranet.example.test/timesheets\r\n";
    assert!(!flags(text, "timesheets.url").contains(&PartFlag::Shortcut));
    let parsed = parse_bytes(
        "m",
        &message("timesheets.url", "application/octet-stream", text),
        &roomy(),
    );
    assert!(parsed
        .urls
        .contains(&"https://intranet.example.test/timesheets".to_string()));
}

#[test]
fn shell_files_are_flagged() {
    let library = br#"<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library"><searchConnectorDescriptionList/></libraryDescription>"#;
    let samples: Vec<(&str, &[u8])> = vec![
        ("Documents.library-ms", library),
        ("invoice.xml", library),
        (
            "a.searchConnector-ms",
            b"<?xml version=\"1.0\"?><searchConnectorDescription/>",
        ),
        (
            "a.search-ms",
            b"<?xml version=\"1.0\"?><persistedQuery version=\"1.0\"/>",
        ),
        (
            "a.scf",
            b"[Shell]\r\nCommand=2\r\nIconFile=\\\\server\\icon.ico\r\n",
        ),
        (
            "a.settingcontent-ms",
            b"<?xml version=\"1.0\"?><PCSettings><SearchableContent/></PCSettings>",
        ),
    ];
    for (name, bytes) in samples {
        assert!(flags(bytes, name).contains(&PartFlag::Shortcut), "{name}");
    }
}

#[test]
fn lnk_stays_executable_and_is_not_double_flagged() {
    let mut lnk = vec![
        0x4c, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x46,
    ];
    lnk.resize(76, 0);
    let flags = flags(&lnk, "report.lnk");
    assert!(flags.contains(&PartFlag::Executable));
    assert!(!flags.contains(&PartFlag::Shortcut));
}

// ---- Disk images ----

fn boot_sector(fs: &[u8], at: usize) -> Vec<u8> {
    let mut sector = vec![0u8; 512];
    sector[0] = 0xeb;
    sector[1] = 0x3c;
    sector[2] = 0x90;
    sector[at..at + fs.len()].copy_from_slice(fs);
    sector[510] = 0x55;
    sector[511] = 0xaa;
    sector
}

#[test]
fn disk_images_are_flagged_and_fail_closed() {
    let mut vhd = vec![0u8; 4096];
    vhd[4096 - 512..4096 - 504].copy_from_slice(b"conectix");
    let mut vhdx = b"vhdxfile".to_vec();
    vhdx.resize(4096, 0);
    let mut dmg = vec![0u8; 4096];
    dmg[4096 - 512..4096 - 508].copy_from_slice(b"koly");
    let mut fat = boot_sector(b"FAT16   ", 54);
    fat.resize(8192, 0);
    let mut fat32 = boot_sector(b"FAT32   ", 82);
    fat32.resize(8192, 0);
    let mut ntfs = boot_sector(b"NTFS    ", 3);
    ntfs.resize(8192, 0);
    // An MBR with one partition at sector 2.
    let mut mbr = vec![0u8; 512];
    mbr[446 + 4] = 0x06;
    mbr[446 + 8] = 2;
    mbr[510] = 0x55;
    mbr[511] = 0xaa;
    mbr.resize(1024, 0);
    mbr.extend(boot_sector(b"FAT16   ", 54));
    for (name, bytes) in [
        ("a.vhd", vhd),
        ("a.vhdx", vhdx),
        ("a.dmg", dmg),
        ("a.img", fat),
        ("renamed.pdf", fat32),
        ("a.bin", ntfs),
        ("disk.img", mbr),
    ] {
        let flags = flags(&bytes, name);
        assert!(flags.contains(&PartFlag::DiskImage), "{name}: {flags:?}");
        assert!(flags.contains(&PartFlag::Unscannable), "{name}: {flags:?}");
    }
}

#[test]
fn iso_and_blank_images_are_not_disk_images() {
    // An .img of nothing recognisable is unscannable, not a disk image.
    let flags = flags(&[0u8; 4096], "disk.img");
    assert!(!flags.contains(&PartFlag::DiskImage));
    assert!(flags.contains(&PartFlag::Unscannable));
    // A boot signature with no file system is not enough.
    let mut sector = vec![0u8; 512];
    sector[510] = 0x55;
    sector[511] = 0xaa;
    assert!(!flags_of_bin(&sector).contains(&PartFlag::DiskImage));
}

fn flags_of_bin(bytes: &[u8]) -> Vec<PartFlag> {
    flags(bytes, "data.bin")
}

// ---- PDF ----

/// A PDF with the given objects (bodies between `obj` and `endobj`). No
/// cross-reference table: the scan does not need one, and readers rebuild it.
fn pdf(objects: &[Vec<u8>]) -> Vec<u8> {
    let mut out = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n".to_vec();
    for (index, body) in objects.iter().enumerate() {
        out.extend_from_slice(format!("{} 0 obj\n", index + 1).as_bytes());
        out.extend_from_slice(body);
        out.extend_from_slice(b"\nendobj\n");
    }
    out.extend_from_slice(b"trailer\n<< /Root 1 0 R >>\n%%EOF\n");
    out
}

fn stream(dict: &str, data: &[u8]) -> Vec<u8> {
    let mut out = format!("<< {dict} /Length {} >>\nstream\n", data.len()).into_bytes();
    out.extend_from_slice(data);
    out.extend_from_slice(b"\nendstream");
    out
}

fn catalog(extra: &str) -> Vec<u8> {
    format!("<< /Type /Catalog /Pages 2 0 R {extra} >>").into_bytes()
}

fn pages() -> Vec<u8> {
    b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_vec()
}

fn page(extra: &str) -> Vec<u8> {
    format!("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R {extra} >>")
        .into_bytes()
}

fn contents() -> Vec<u8> {
    // Page text that mentions names; inside stream data it is not counted.
    stream("", b"BT /F1 12 Tf (Use /JavaScript and /Launch) Tj /JS ET")
}

fn plain_pdf() -> Vec<u8> {
    pdf(&[catalog(""), pages(), page(""), contents()])
}

#[test]
fn plain_pdf_is_not_flagged() {
    let flags = flags(&plain_pdf(), "statement.pdf");
    assert!(flags.is_empty(), "{flags:?}");
}

#[test]
fn pdf_active_names_are_flagged() {
    let cases = [
        (
            "/OpenAction 5 0 R",
            "<< /Type /Action /S /JavaScript /JS (app.alert\\(1\\)) >>",
            vec![PartFlag::PdfJavaScript, PartFlag::PdfAutoAction],
        ),
        (
            "/OpenAction 5 0 R",
            "<< /Type /Action /S /Launch /F (calc.exe) >>",
            vec![PartFlag::PdfLaunch, PartFlag::PdfAutoAction],
        ),
        (
            "/AcroForm 5 0 R",
            "<< /XFA 6 0 R /Fields [] >>",
            vec![PartFlag::PdfForm],
        ),
        (
            "/OpenAction 5 0 R",
            "<< /S /GoToR /F (other.pdf) /D [0 /Fit] >>",
            vec![PartFlag::PdfRemoteAction, PartFlag::PdfAutoAction],
        ),
        (
            "/OpenAction 5 0 R",
            "<< /S /SubmitForm /F (https://example.test/collect) >>",
            vec![PartFlag::PdfForm, PartFlag::PdfAutoAction],
        ),
    ];
    for (root, action, expected) in cases {
        let bytes = pdf(&[
            catalog(root),
            pages(),
            page(""),
            contents(),
            action.as_bytes().to_vec(),
        ]);
        let mut flags = flags(&bytes, "a.pdf");
        flags.sort_by_key(|flag| flag.as_str());
        let mut expected = expected.clone();
        expected.sort_by_key(|flag| flag.as_str());
        assert_eq!(flags, expected, "{action}");
    }
}

#[test]
fn auto_action_alone_is_only_an_auto_action() {
    let bytes = pdf(&[
        catalog("/OpenAction [3 0 R /Fit]"),
        pages(),
        page(""),
        contents(),
    ]);
    assert_eq!(flags(&bytes, "a.pdf"), vec![PartFlag::PdfAutoAction]);
}

#[test]
fn obfuscated_pdf_names_are_normalised() {
    let bytes = pdf(&[
        catalog("/Open#41ction 5 0 R"),
        pages(),
        page(""),
        contents(),
        b"<< /S /J#61va#53cript /J#53 (x) >>".to_vec(),
    ]);
    let flags = flags(&bytes, "a.pdf");
    assert!(flags.contains(&PartFlag::PdfJavaScript), "{flags:?}");
    assert!(flags.contains(&PartFlag::PdfAutoAction), "{flags:?}");
}

#[test]
fn names_inside_compressed_object_streams_are_found() {
    let objects = b"5 0 6 40 << /S /Launch /F (calc.exe) >> << /S /JavaScript /JS 7 0 R >>";
    let objstm = stream(
        "/Type /ObjStm /N 2 /First 8 /Filter /FlateDecode",
        &zlib(objects),
    );
    let bytes = pdf(&[
        catalog("/OpenAction 5 0 R"),
        pages(),
        page(""),
        contents(),
        objstm,
    ]);
    let flags = flags(&bytes, "a.pdf");
    assert!(flags.contains(&PartFlag::PdfLaunch), "{flags:?}");
    assert!(flags.contains(&PartFlag::PdfJavaScript), "{flags:?}");
    // The same names in a compressed page stream are content, not objects.
    let page_stream = stream("/Filter /FlateDecode", &zlib(objects));
    let bytes = pdf(&[catalog(""), pages(), page(""), page_stream]);
    assert!(flags_of(&bytes).is_empty(), "{:?}", flags_of(&bytes));
}

fn flags_of(bytes: &[u8]) -> Vec<PartFlag> {
    flags(bytes, "a.pdf")
}

#[test]
fn object_stream_bomb_hits_the_limit() {
    let zeros = vec![b' '; 17 * 1024 * 1024];
    let objstm = stream(
        "/Type /ObjStm /N 1 /First 4 /Filter /FlateDecode",
        &zlib(&zeros),
    );
    let bytes = pdf(&[catalog(""), pages(), page(""), contents(), objstm]);
    let extracted = extract(&bytes, Some("a.pdf"), &roomy(), &[]);
    assert!(
        has(&extracted.parts, PartFlag::LimitExceeded),
        "{:?}",
        extracted.parts
    );
}

#[test]
fn pdf_uri_targets_are_recorded() {
    let annot = b"<< /Type /Annot /Subtype /Link /Rect [0 0 10 10] /A << /S /URI /URI (https://example.test/pay\\(now\\)) >> >>".to_vec();
    let hex = b"<< /Type /Annot /Subtype /Link /A << /S /URI /URI <6d732d6d7364743a2f6964> >> >>"
        .to_vec();
    let bytes = pdf(&[
        catalog(""),
        pages(),
        page("/Annots [5 0 R 6 0 R]"),
        contents(),
        annot,
        hex,
    ]);
    let flags = flags(&bytes, "a.pdf");
    assert_eq!(flags, vec![PartFlag::ProtocolHandler]);
    let parsed = parse_bytes("m", &message("a.pdf", "application/pdf", &bytes), &roomy());
    assert!(
        parsed
            .urls
            .contains(&"https://example.test/pay(now)".to_string()),
        "{:?}",
        parsed.urls
    );
    assert!(
        parsed.urls.contains(&"ms-msdt:/id".to_string()),
        "{:?}",
        parsed.urls
    );
}

fn embedded_pdf(data: &[u8], compressed: bool) -> Vec<u8> {
    let file = if compressed {
        stream("/Type /EmbeddedFile /Filter /FlateDecode", &zlib(data))
    } else {
        stream("/Type /EmbeddedFile", data)
    };
    pdf(&[
        catalog("/Names << /EmbeddedFiles 5 0 R >>"),
        pages(),
        page(""),
        contents(),
        b"<< /Names [(invoice) 6 0 R] >>".to_vec(),
        b"<< /Type /Filespec /F (invoice.exe) /UF (invoice.exe) /EF << /F 7 0 R >> >>".to_vec(),
        file,
    ])
}

#[test]
fn pdf_embedded_files_become_child_parts() {
    for compressed in [false, true] {
        let bytes = embedded_pdf(&pe_stub(), compressed);
        let extracted = extract(&bytes, Some("a.pdf"), &roomy(), &[]);
        assert!(
            extracted.parts[0]
                .flags
                .contains(&PartFlag::PdfEmbeddedFile),
            "{:?}",
            extracted.parts
        );
        let child = extracted
            .parts
            .iter()
            .find(|part| part.filename.as_deref() == Some("invoice.exe"))
            .unwrap_or_else(|| panic!("{:?}", extracted.parts));
        assert!(child.flags.contains(&PartFlag::Executable), "{child:?}");
    }
}

#[test]
fn embedded_file_without_a_type_is_found_by_reference() {
    let bytes = pdf(&[
        catalog(""),
        pages(),
        page(""),
        contents(),
        b"<< /Type /Filespec /UF (notes.txt) /EF << /F 6 0 R >> >>".to_vec(),
        stream("", b"plain notes"),
    ]);
    let extracted = extract(&bytes, Some("a.pdf"), &roomy(), &[]);
    assert!(extracted
        .parts
        .iter()
        .any(|part| part.filename.as_deref() == Some("notes.txt")));
}

#[test]
fn encrypted_pdf_embedded_files_cannot_be_inspected() {
    let mut bytes = embedded_pdf(&pe_stub(), true);
    let trailer = b"trailer\n<< /Root 1 0 R >>";
    let at = bytes
        .windows(trailer.len())
        .position(|w| w == trailer)
        .unwrap();
    bytes.splice(
        at..at + trailer.len(),
        b"trailer\n<< /Root 1 0 R /Encrypt 9 0 R >>".iter().copied(),
    );
    let flags = flags(&bytes, "a.pdf");
    assert!(flags.contains(&PartFlag::PdfEmbeddedFile), "{flags:?}");
    assert!(flags.contains(&PartFlag::Unscannable), "{flags:?}");
}

#[test]
fn pdf_in_a_zip_is_checked() {
    let bytes = pdf(&[
        catalog("/OpenAction 5 0 R"),
        pages(),
        page(""),
        contents(),
        b"<< /S /JavaScript /JS (x) >>".to_vec(),
    ]);
    let zip = zip_of(&[("statement.pdf", &bytes)]);
    let extracted = extract(&zip, Some("statements.zip"), &roomy(), &[]);
    assert!(
        has(&extracted.parts, PartFlag::PdfJavaScript),
        "{:?}",
        extracted.parts
    );
}

// ---- Negative: ordinary files ----

#[test]
fn ordinary_files_are_not_flagged() {
    let png = {
        let mut out = Vec::new();
        let img = image::RgbImage::from_pixel(4, 4, image::Rgb([200, 100, 50]));
        img.write_to(&mut Cursor::new(&mut out), image::ImageFormat::Png)
            .unwrap();
        out
    };
    let new = [
        PartFlag::SvgActive,
        PartFlag::ExternalTemplate,
        PartFlag::DdeField,
        PartFlag::ProtocolHandler,
        PartFlag::OneNoteEmbedded,
        PartFlag::Shortcut,
        PartFlag::DiskImage,
        PartFlag::PdfJavaScript,
        PartFlag::PdfLaunch,
        PartFlag::PdfEmbeddedFile,
        PartFlag::PdfAutoAction,
        PartFlag::PdfForm,
        PartFlag::PdfRemoteAction,
    ];
    let xlsx = zip_of(&[
        ("[Content_Types].xml", CONTENT_TYPES),
        (
            "xl/worksheets/sheet1.xml",
            br#"<worksheet><sheetData><row><c><f>SUM(A1:A3)</f></c></row></sheetData></worksheet>"#,
        ),
    ]);
    let samples: Vec<(&str, Vec<u8>)> = vec![
        ("photo.png", png),
        ("report.docx", docx(&[])),
        ("book.xlsx", xlsx),
        ("statement.pdf", plain_pdf()),
        ("logo.svg", PLAIN_SVG.as_bytes().to_vec()),
        (
            "notes.txt",
            b"Meeting notes: [Shell] training on Tuesday.".to_vec(),
        ),
    ];
    for (name, bytes) in samples {
        let extracted = extract(&bytes, Some(name), &roomy(), &[]);
        for part in &extracted.parts {
            for flag in &new {
                assert!(!part.flags.contains(flag), "{name}: {part:?}");
            }
        }
    }
}
