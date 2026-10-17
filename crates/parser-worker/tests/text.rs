//! Text extraction for DLP. Documents are built here; `123456782` is the
//! ATO's published TFN sample and the other numbers are placeholders.
use base64::Engine;
use currawong_core::config::ExtractLimits;
use currawong_parser::parse::{parse_bytes, parse_request};
use currawong_parser::text::{body_text, document_text, DlpText, Document};
use currawong_parser::ParseRequest;
use std::io::{Cursor, Write};
use std::time::Instant;

fn zip(files: &[(&str, &str)]) -> Vec<u8> {
    let mut out = Cursor::new(Vec::new());
    let mut writer = zip::ZipWriter::new(&mut out);
    for (name, body) in files {
        writer
            .start_file(*name, zip::write::SimpleFileOptions::default())
            .unwrap();
        writer.write_all(body.as_bytes()).unwrap();
    }
    writer.finish().unwrap();
    out.into_inner()
}

const W: &str = r#"xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main""#;

fn docx() -> Vec<u8> {
    zip(&[
        (
            "word/document.xml",
            &format!(
                r#"<?xml version="1.0"?><w:document {W}><w:body><w:p><w:r><w:t>TFN </w:t></w:r><w:r><w:t>123 456</w:t></w:r><w:r><w:t> 782</w:t></w:r></w:p><w:tbl><w:tr><w:tc><w:p><w:r><w:t>11111111</w:t></w:r></w:p></w:tc><w:tc><w:p><w:r><w:t>22222222</w:t></w:r></w:p></w:tc></w:tr></w:tbl></w:body></w:document>"#
            ),
        ),
        (
            "word/header1.xml",
            &format!(r#"<w:hdr {W}><w:p><w:r><w:t>header &#49;&#x32;3</w:t></w:r></w:p></w:hdr>"#),
        ),
        (
            "word/footnotes.xml",
            &format!(
                r#"<w:footnotes {W}><w:footnote><w:p><w:r><w:t>footnote 456782</w:t></w:r></w:p></w:footnote></w:footnotes>"#
            ),
        ),
        ("word/styles.xml", "<w:styles>styles-not-text</w:styles>"),
    ])
}

fn xlsx(sheet: &str) -> Vec<u8> {
    zip(&[
        (
            "[Content_Types].xml",
            r#"<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>"#,
        ),
        (
            "_rels/.rels",
            r#"<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>"#,
        ),
        (
            "xl/workbook.xml",
            r#"<?xml version="1.0"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Staff" sheetId="1" r:id="rId1"/></sheets></workbook>"#,
        ),
        (
            "xl/_rels/workbook.xml.rels",
            r#"<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>"#,
        ),
        ("xl/worksheets/sheet1.xml", sheet),
    ])
}

const SHEET: &str = r#"<?xml version="1.0"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData><row r="1"><c r="A1" t="inlineStr"><is><t>TFN</t></is></c><c r="B1"><v>123456782</v></c></row></sheetData></worksheet>"#;

/// One cell at A1 and one at the last cell Excel allows. Expanded densely
/// that is about 1.7e10 cells.
const SPARSE: &str = r#"<?xml version="1.0"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><dimension ref="A1:XFD1048576"/><sheetData><row r="1"><c r="A1" t="inlineStr"><is><t>TFN</t></is></c></row><row r="1048576"><c r="XFD1048576"><v>123456782</v></c></row></sheetData></worksheet>"#;

fn pdf() -> Vec<u8> {
    let content = "BT /F1 12 Tf 72 712 Td (TFN 123 456 782) Tj ET";
    let objects = [
        "<< /Type /Catalog /Pages 2 0 R >>".to_string(),
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_string(),
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>".to_string(),
        format!("<< /Length {} >>\nstream\n{content}\nendstream", content.len()),
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_string(),
    ];
    let mut out = b"%PDF-1.4\n".to_vec();
    let mut offsets = Vec::new();
    for (i, body) in objects.iter().enumerate() {
        offsets.push(out.len());
        out.extend_from_slice(format!("{} 0 obj\n{body}\nendobj\n", i + 1).as_bytes());
    }
    let xref = out.len();
    out.extend_from_slice(
        format!("xref\n0 {}\n0000000000 65535 f \n", objects.len() + 1).as_bytes(),
    );
    for offset in offsets {
        out.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
    }
    out.extend_from_slice(
        format!(
            "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n",
            objects.len() + 1
        )
        .as_bytes(),
    );
    out
}

fn text_of(document: Document) -> DlpText {
    match document {
        Document::Text(text) => text,
        other => panic!("{other:?}"),
    }
}

fn digits(text: &str) -> String {
    text.chars().filter(char::is_ascii_digit).collect()
}

#[test]
fn docx_xlsx_and_pdf_yield_text() {
    let doc = text_of(document_text(&docx(), true)).text;
    assert!(doc.contains("TFN 123 456 782"), "{doc:?}");
    // Table cells stay apart so two numbers do not run together.
    assert!(doc.contains("11111111\n"), "{doc:?}");
    // Headers and footnotes, with numeric entities decoded.
    assert!(doc.contains("header 123"), "{doc:?}");
    assert!(doc.contains("footnote 456782"), "{doc:?}");
    assert!(!doc.contains("styles-not-text"), "{doc:?}");
    let sheet = text_of(document_text(&xlsx(SHEET), true)).text;
    assert!(digits(&sheet).contains("123456782"), "{sheet:?}");
    let pdf = text_of(document_text(&pdf(), true)).text;
    assert!(pdf.contains("123 456 782"), "{pdf:?}");
    assert!(matches!(
        document_text(b"%PDF-1.4 broken", true),
        Document::Unread
    ));
    assert!(matches!(
        document_text(b"PK\x03\x04 broken", true),
        Document::NotDocument
    ));
}

#[test]
fn sparse_xlsx_is_streamed_not_expanded() {
    let started = Instant::now();
    let sheet = text_of(document_text(&xlsx(SPARSE), true));
    assert!(sheet.text.contains("123456782"), "{sheet:?}");
    assert!(started.elapsed().as_secs() < 5);
}

#[test]
fn documents_are_only_parsed_in_the_worker() {
    // In-process: documents are not parsed and the text is marked incomplete.
    assert!(matches!(document_text(&docx(), false), Document::Unread));
    let attachment = base64::engine::general_purpose::STANDARD.encode(docx());
    let raw = format!(
        "From: a@example.test\r\nTo: b@example.test\r\nSubject: staff\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"b\"\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nsee attached\r\n--b\r\nContent-Type: application/vnd.openxmlformats-officedocument.wordprocessingml.document; name=\"staff.docx\"\r\nContent-Disposition: attachment; filename=\"staff.docx\"\r\nContent-Transfer-Encoding: base64\r\n\r\n{attachment}\r\n--b--\r\n"
    );
    let local = parse_bytes("id", raw.as_bytes(), &ExtractLimits::default());
    assert!(local.dlp.incomplete);
    assert!(!local.dlp.text.contains("123 456 782"));
    let body = body_text(raw.as_bytes());
    assert!(body.incomplete && body.text.contains("see attached"));

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("m.eml");
    std::fs::write(&path, &raw).unwrap();
    let worker = parse_request(
        &ParseRequest {
            id: "id".into(),
            raw_path: path,
            limits: ExtractLimits::default(),
            yara_generation: None,
        },
        &mut currawong_parser::yara::RulesCache::default(),
    );
    assert!(!worker.dlp.incomplete, "{:?}", worker.dlp);
    assert!(worker.dlp.text.contains("TFN 123 456 782"));
    assert!(worker.dlp.text.contains("staff.docx"));
}

#[test]
fn html_markup_cannot_hide_text() {
    let html = concat!(
        "<p>a < b TFN 123456782</p>",
        "<table><tr><td>11111111</td><td>22222222</td></tr></table>",
        "<span title=\"x>y\">after</span>",
        "<!-- hidden 333 -->",
        "<img alt=\"alt 444\">",
        "&#49;&#x32;&#51;&nbsp;&amp;",
        "&&&&<<<<",
    );
    let raw = format!(
        "From: a@example.test\r\nTo: b@example.test\r\nSubject: Subject 555\r\nMIME-Version: 1.0\r\nContent-Type: text/html\r\n\r\n{html}\r\n"
    );
    let text = parse_bytes("id", raw.as_bytes(), &ExtractLimits::default())
        .dlp
        .text;
    for wanted in [
        "a < b TFN 123456782",
        "11111111\n",
        "after",
        "hidden 333",
        "alt 444",
        "123\u{a0}&",
        "Subject 555",
    ] {
        assert!(text.contains(wanted), "{wanted:?} missing from {text:?}");
    }
    assert!(
        !text.contains("<td>") && !text.contains("title="),
        "{text:?}"
    );
}

#[test]
fn bodies_come_before_attachments_and_overflow_is_flagged() {
    let padding = "x".repeat(2 * 1024 * 1024);
    let raw = format!(
        "From: a@example.test\r\nTo: b@example.test\r\nSubject: pad\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"b\"\r\n\r\n--b\r\nContent-Type: text/plain; name=\"pad.txt\"\r\nContent-Disposition: attachment; filename=\"pad.txt\"\r\n\r\n{padding}\r\n--b\r\nContent-Type: text/plain\r\n\r\nTFN 123 456 782\r\n--b--\r\n"
    );
    let dlp = parse_bytes("id", raw.as_bytes(), &ExtractLimits::default()).dlp;
    assert!(dlp.text.contains("TFN 123 456 782"));
    assert!(dlp.incomplete);
}

#[test]
fn hostile_markup_is_linear() {
    // Release takes milliseconds; unoptimised builds are far slower.
    let limit = if cfg!(debug_assertions) { 10 } else { 1 };
    for unit in ["<a", "<a title=\"", "&&", "<!--"] {
        let html = unit.repeat(512 * 1024 / unit.len());
        let raw = format!("Subject: x\r\nContent-Type: text/html\r\n\r\n{html}\r\n");
        let started = Instant::now();
        let _ = body_text(raw.as_bytes());
        let elapsed = started.elapsed();
        assert!(elapsed.as_secs() < limit, "{unit:?} took {elapsed:?}");
    }
}

#[test]
fn debug_output_hides_text() {
    let text = DlpText {
        text: "TFN 123456782".into(),
        incomplete: false,
    };
    assert!(!format!("{text:?}").contains("123456782"));
}
