//! QR fixtures are generated here with the `qrcode` crate; none are committed.
use base64::Engine;
use currawong_core::{config::ExtractLimits, PartFlag};
use currawong_parser::{parse::parse_bytes, qr, FoundUrl, UrlSource};
use image::{GrayImage, ImageFormat, Luma, LumaA};
use std::io::{Cursor, Write};

fn qr_grey(payload: &str) -> GrayImage {
    let code = qrcode::QrCode::new(payload.as_bytes()).unwrap();
    code.render::<Luma<u8>>().min_dimensions(240, 240).build()
}

fn png(image: impl Into<image::DynamicImage>) -> Vec<u8> {
    let mut out = Cursor::new(Vec::new());
    image.into().write_to(&mut out, ImageFormat::Png).unwrap();
    out.into_inner()
}

fn qr_png(payload: &str) -> Vec<u8> {
    png(qr_grey(payload))
}

fn decode(bytes: &[u8]) -> Result<Vec<String>, qr::Skipped> {
    qr::Budget::default().image(bytes)
}

fn attachment(name: &str, content_type: &str, bytes: &[u8]) -> String {
    let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
    let wrapped: Vec<&str> = encoded
        .as_bytes()
        .chunks(76)
        .map(|line| std::str::from_utf8(line).unwrap())
        .collect();
    format!(
        "--b\r\nContent-Type: {content_type}; name=\"{name}\"\r\nContent-Disposition: attachment; filename=\"{name}\"\r\nContent-Transfer-Encoding: base64\r\n\r\n{}\r\n",
        wrapped.join("\r\n")
    )
}

fn message(attachments: &[String]) -> Vec<u8> {
    format!(
        "From: a@example.test\r\nTo: b@example.test\r\nSubject: scan to verify\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"b\"\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nScan the code to keep your account.\r\n{}--b--\r\n",
        attachments.concat()
    )
    .into_bytes()
}

fn message_with_image(name: &str, image: &[u8]) -> Vec<u8> {
    message(&[attachment(name, "image/png", image)])
}

fn qr_from(parsed: &currawong_parser::ParseResponse) -> Vec<&str> {
    parsed
        .url_sources
        .iter()
        .filter(|found| found.source == UrlSource::Qr)
        .map(|found| found.url.as_str())
        .collect()
}

#[test]
fn qr_png_yields_its_url_with_source_qr() {
    let png = qr_png("https://evil.example/login");
    assert_eq!(decode(&png).unwrap(), vec!["https://evil.example/login"]);

    let raw = message_with_image("verify.png", &png);
    let parsed = parse_bytes("m1", &raw, &ExtractLimits::default());
    assert!(parsed.error.is_none(), "{:?}", parsed.error);
    assert!(
        parsed.url_sources.contains(&FoundUrl {
            url: "https://evil.example/login".into(),
            source: UrlSource::Qr,
        }),
        "{:?}",
        parsed.url_sources
    );
    // In `urls` too, so link analysis sees it.
    assert!(parsed
        .urls
        .contains(&"https://evil.example/login".to_string()));
    let image = parsed
        .parts
        .iter()
        .find(|part| part.filename.as_deref() == Some("verify.png"))
        .unwrap();
    assert!(image.flags.contains(&PartFlag::QrCode), "{:?}", image.flags);
}

#[test]
fn qr_url_from_the_worker_has_source_qr() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("m.eml");
    std::fs::write(
        &path,
        message_with_image("code.png", &qr_png("https://evil.example/login")),
    )
    .unwrap();
    let request = currawong_parser::ParseRequest {
        id: "m2".into(),
        raw_path: path,
        limits: ExtractLimits::default(),
        out_dir: None,
        yara_generation: None,
    };
    let parsed = currawong_parser::parse_request(&request, &mut Default::default());
    assert_eq!(qr_from(&parsed), vec!["https://evil.example/login"]);
}

#[test]
fn qr_upper_case_and_www_urls_are_read() {
    let png = qr_png("HTTPS://EVIL.EXAMPLE/LOGIN");
    assert_eq!(
        qr::urls(&decode(&png).unwrap()),
        vec!["https://evil.example/LOGIN"]
    );
    let png = qr_png("WWW.EVIL.EXAMPLE/login");
    assert_eq!(
        qr::urls(&decode(&png).unwrap()),
        vec!["http://www.evil.example/login"]
    );
}

#[test]
fn qr_payload_that_is_not_a_url_flags_the_image_without_a_url() {
    let raw = message_with_image("ticket.png", &qr_png("TICKET 12345"));
    let parsed = parse_bytes("m3", &raw, &ExtractLimits::default());
    assert!(qr_from(&parsed).is_empty());
    assert!(parsed
        .parts
        .iter()
        .any(|p| p.flags.contains(&PartFlag::QrCode)));
}

#[test]
fn qr_text_urls_are_listed_with_source_text() {
    let raw = b"From: a@example.test\r\nTo: b@example.test\r\nSubject: hi\r\n\r\nSee https://example.test/page\r\n";
    let parsed = parse_bytes("m4", raw, &ExtractLimits::default());
    assert_eq!(
        parsed.url_sources,
        vec![FoundUrl {
            url: "https://example.test/page".into(),
            source: UrlSource::Text,
        }]
    );
    assert_eq!(parsed.urls, vec!["https://example.test/page"]);
}

#[test]
fn qr_on_a_wide_canvas_inverted_or_transparent_is_read() {
    let code = qr_grey("https://evil.example/login");
    // 5000 pixels wide: a pixel budget, not a per-side one.
    let mut canvas = GrayImage::from_pixel(5000, 300, Luma([255]));
    image::imageops::overlay(&mut canvas, &code, 2000, 10);
    assert_eq!(decode(&png(canvas)).unwrap().len(), 1);
    // Light modules on a dark background.
    let mut inverted = code.clone();
    image::imageops::invert(&mut inverted);
    assert_eq!(decode(&png(inverted)).unwrap().len(), 1);
    // Dark modules on a transparent background (light pixels are black but
    // fully transparent, so flattening alpha away would lose the code).
    let transparent = image::ImageBuffer::from_fn(code.width(), code.height(), |x, y| {
        let dark = code.get_pixel(x, y).0[0] < 128;
        LumaA([0u8, if dark { 255 } else { 0 }])
    });
    assert_eq!(decode(&png(transparent)).unwrap().len(), 1);
}

/// A small PNG claiming `width` x `height`: valid chunks, no pixel data.
fn png_header(width: u32, height: u32) -> Vec<u8> {
    let mut ihdr = Vec::new();
    ihdr.extend_from_slice(&width.to_be_bytes());
    ihdr.extend_from_slice(&height.to_be_bytes());
    ihdr.extend_from_slice(&[8, 0, 0, 0, 0]);
    let mut out = b"\x89PNG\r\n\x1a\n".to_vec();
    for (kind, data) in [(&b"IHDR"[..], &ihdr[..]), (b"IDAT", &[]), (b"IEND", &[])] {
        let mut crc = flate2::Crc::new();
        crc.update(kind);
        crc.update(data);
        out.extend_from_slice(&(data.len() as u32).to_be_bytes());
        out.extend_from_slice(kind);
        out.extend_from_slice(data);
        out.extend_from_slice(&crc.sum().to_be_bytes());
    }
    out
}

#[test]
fn qr_broken_images_decode_to_nothing_and_huge_ones_are_over_the_limit() {
    let png = qr_png("https://evil.example/login");
    assert_eq!(decode(&png[..png.len() / 2]), Ok(Vec::new()));
    assert_eq!(decode(b"\x89PNG\r\n\x1a\nnot really"), Ok(Vec::new()));
    // 36 MP, an A4 scan at 600 dpi: not read, but not a bomb.
    assert_eq!(decode(&png_header(6000, 6000)), Err(qr::Skipped::Budget));
    assert_eq!(
        decode(&png_header(20000, 20000)),
        Err(qr::Skipped::TooLarge)
    );

    let flags = |image: &[u8]| {
        let raw = message_with_image("huge.png", image);
        let parsed = parse_bytes("m5", &raw, &ExtractLimits::default());
        parsed
            .parts
            .into_iter()
            .find(|part| part.filename.as_deref() == Some("huge.png"))
            .unwrap()
            .flags
    };
    // A large scan is tagged, not held.
    let scan = flags(&png_header(6000, 6000));
    assert!(scan.contains(&PartFlag::QrSkipped), "{scan:?}");
    assert!(!scan.contains(&PartFlag::LimitExceeded), "{scan:?}");
    // A possible decode bomb fails closed.
    let bomb = flags(&png_header(20000, 20000));
    assert!(bomb.contains(&PartFlag::LimitExceeded), "{bomb:?}");
}

#[test]
fn qr_inverted_code_beside_a_normal_one_is_read() {
    let benign = qr_grey("https://example.test/menu");
    let mut phishing = qr_grey("https://evil.example/login");
    image::imageops::invert(&mut phishing);
    let mut canvas = GrayImage::from_pixel(
        benign.width() + phishing.width() + 40,
        benign.height().max(phishing.height()) + 40,
        Luma([255]),
    );
    image::imageops::overlay(&mut canvas, &benign, 10, 10);
    image::imageops::overlay(&mut canvas, &phishing, i64::from(benign.width()) + 30, 10);
    let mut codes = decode(&png(canvas)).unwrap();
    codes.sort();
    assert_eq!(
        codes,
        vec!["https://evil.example/login", "https://example.test/menu"]
    );
}

#[test]
fn qr_urls_are_capped_per_message_and_the_rest_flagged_qr_skipped() {
    let many: Vec<String> = (0..qr::MAX_URLS + 20)
        .map(|i| format!("WWW.A{i}.TEST"))
        .collect();
    let raw = message_with_image("many.png", &qr_png(&many.join(" ")));
    let parsed = parse_bytes("m9", &raw, &ExtractLimits::default());
    assert_eq!(qr_from(&parsed).len(), qr::MAX_URLS);
    let part = parsed
        .parts
        .iter()
        .find(|part| part.filename.as_deref() == Some("many.png"))
        .unwrap();
    assert!(part.flags.contains(&PartFlag::QrSkipped), "{part:?}");
}

#[test]
fn qr_images_past_the_per_message_cap_are_flagged_qr_skipped_not_held() {
    let blank = png(GrayImage::from_pixel(32, 32, Luma([255])));
    let mut attachments: Vec<String> = (0..qr::MAX_IMAGES)
        .map(|i| attachment(&format!("decoy{i}.png"), "image/png", &blank))
        .collect();
    attachments.push(attachment(
        "code.png",
        "image/png",
        &qr_png("https://evil.example/login"),
    ));
    let parsed = parse_bytes("m6", &message(&attachments), &ExtractLimits::default());
    let code = parsed
        .parts
        .iter()
        .find(|part| part.filename.as_deref() == Some("code.png"))
        .unwrap();
    assert!(code.flags.contains(&PartFlag::QrSkipped), "{code:?}");
    // A used-up QR budget does not fail the message closed.
    assert!(parsed
        .parts
        .iter()
        .all(|part| !part.flags.contains(&PartFlag::LimitExceeded)));
    // Icons too small to hold a code do not use up the cap.
    let icon = png(GrayImage::from_pixel(16, 16, Luma([255])));
    let mut attachments: Vec<String> = (0..qr::MAX_IMAGES + 10)
        .map(|i| attachment(&format!("icon{i}.png"), "image/png", &icon))
        .collect();
    attachments.push(attachment(
        "code.png",
        "image/png",
        &qr_png("https://evil.example/login"),
    ));
    let parsed = parse_bytes("m7", &message(&attachments), &ExtractLimits::default());
    assert_eq!(qr_from(&parsed), vec!["https://evil.example/login"]);
}

#[test]
fn qr_png_inside_a_zip_is_read() {
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    zip.start_file("scan-me.png", zip::write::SimpleFileOptions::default())
        .unwrap();
    zip.write_all(&qr_png("https://evil.example/login"))
        .unwrap();
    let archive = zip.finish().unwrap().into_inner();
    let raw = message(&[attachment("invoice.zip", "application/zip", &archive)]);
    let parsed = parse_bytes("m8", &raw, &ExtractLimits::default());
    assert_eq!(qr_from(&parsed), vec!["https://evil.example/login"]);
    let member = parsed
        .parts
        .iter()
        .find(|part| part.filename.as_deref() == Some("scan-me.png"))
        .unwrap();
    assert!(member.flags.contains(&PartFlag::QrCode), "{member:?}");
}
