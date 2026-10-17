//! Text extraction for DLP. Documents are built here; `123456782` is the
//! ATO's published TFN sample.
use base64::Engine;
use currawong_core::config::ExtractLimits;
use currawong_parser::parse::parse_bytes;
use currawong_parser::text::document_text;
use std::io::{Cursor, Write};

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

fn docx() -> Vec<u8> {
    zip(&[(
        "word/document.xml",
        r#"<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>TFN </w:t></w:r><w:r><w:t>123 456</w:t></w:r><w:r><w:t> 782</w:t></w:r></w:p><w:tbl><w:tr><w:tc><w:p><w:r><w:t>876543210</w:t></w:r></w:p></w:tc><w:tc><w:p><w:r><w:t>100000060</w:t></w:r></w:p></w:tc></w:tr></w:tbl></w:body></w:document>"#,
    )])
}

fn xlsx() -> Vec<u8> {
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
        (
            "xl/worksheets/sheet1.xml",
            r#"<?xml version="1.0"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData><row r="1"><c r="A1" t="inlineStr"><is><t>TFN</t></is></c><c r="B1"><v>123456782</v></c></row></sheetData></worksheet>"#,
        ),
    ])
}

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

fn digits(text: &str) -> String {
    text.chars().filter(char::is_ascii_digit).collect()
}

#[test]
fn docx_xlsx_and_pdf_yield_text() {
    let doc = document_text(&docx()).unwrap();
    assert!(doc.contains("TFN 123 456 782"), "{doc:?}");
    // Table cells stay apart so two numbers do not run together.
    assert!(doc.contains("876543210\n"), "{doc:?}");
    let sheet = document_text(&xlsx()).unwrap();
    assert!(digits(&sheet).contains("123456782"), "{sheet:?}");
    let pdf = document_text(&pdf()).unwrap();
    assert!(pdf.contains("123 456 782"), "{pdf:?}");
    assert!(document_text(b"%PDF-1.4 broken").is_none());
    assert!(document_text(b"PK\x03\x04 broken").is_none());
}

#[test]
fn parse_collects_text_from_html_bodies_and_attachments() {
    let attachment = base64::engine::general_purpose::STANDARD.encode(docx());
    let raw = format!(
        "From: a@example.test\r\nTo: b@example.test\r\nSubject: staff\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"b\"\r\n\r\n--b\r\nContent-Type: text/html\r\n\r\n<table><tr><td>200000010</td><td>300000070</td></tr></table>&nbsp;\r\n--b\r\nContent-Type: application/vnd.openxmlformats-officedocument.wordprocessingml.document; name=\"staff.docx\"\r\nContent-Disposition: attachment; filename=\"staff.docx\"\r\nContent-Transfer-Encoding: base64\r\n\r\n{attachment}\r\n--b--\r\n"
    );
    let response = parse_bytes("id", raw.as_bytes(), &ExtractLimits::default());
    assert!(response.error.is_none(), "{:?}", response.error);
    assert!(response.text.contains("200000010\n"), "{:?}", response.text);
    assert!(response.text.contains("300000070"), "{:?}", response.text);
    assert!(!response.text.contains("<td>"), "{:?}", response.text);
    assert!(
        response.text.contains("TFN 123 456 782"),
        "{:?}",
        response.text
    );
}
