//! Fixtures are built here. The "payload" is repeated harmless text, not a file.
use base64::Engine;
use currawong_core::{config::ExtractLimits, PartFlag};
use currawong_parser::{html_smuggling, parse::parse_bytes};

fn payload(bytes: usize) -> String {
    let plain = "harmless test payload ".repeat(bytes / 22 + 1);
    base64::engine::general_purpose::STANDARD.encode(&plain.as_bytes()[..bytes])
}

fn smuggling_page() -> String {
    format!(
        r#"<!doctype html><html><body><p>Loading your document...</p>
<script>
var data = "{}";
var bin = atob(data);
var bytes = new Uint8Array(bin.length);
for (var i = 0; i < bin.length; i++) {{ bytes[i] = bin.charCodeAt(i); }}
var blob = new Blob([bytes], {{ type: "application/octet-stream" }});
if (window.navigator.msSaveOrOpenBlob) {{
  window.navigator.msSaveOrOpenBlob(blob, "invoice.iso");
}} else {{
  var a = document.createElement("a");
  a.href = window.URL.createObjectURL(blob);
  a.download = "invoice.iso";
  a.click();
}}
</script></body></html>"#,
        payload(60 * 1024)
    )
}

fn newsletter() -> String {
    format!(
        r#"<!doctype html><html><head><style>td {{ font-family: Arial; }}</style></head>
<body><table width="600"><tr><td>
<img src="data:image/png;base64,{}" alt="Spring sale">
<h1>Spring sale at Example Outdoors</h1>
<p>Our biggest sale of the year starts today. Tents, packs and boots are up to 40% off.</p>
<p><a href="https://shop.example.test/sale?utm_source=newsletter">Shop the sale</a></p>
<p><a href="https://shop.example.test/catalogue.pdf" download>Download the catalogue</a></p>
<p>Questions? Reply to this email or call us on 1300 000 000.</p>
<p><a href="https://shop.example.test/unsubscribe">Unsubscribe</a></p>
<img src="https://track.example.test/open.gif" width="1" height="1">
<script type="application/ld+json">{{"@context": "https://schema.org"}}</script>
</td></tr></table></body></html>"#,
        payload(64 * 1024)
    )
}

#[test]
fn html_smuggling_fixture_scores_over_0_7_and_a_newsletter_under_0_2() {
    let smuggling = html_smuggling::score(smuggling_page().as_bytes());
    assert!(smuggling > 0.7, "{smuggling}");
    let newsletter = html_smuggling::score(newsletter().as_bytes());
    assert!(newsletter < 0.2, "{newsletter}");
}

#[test]
fn html_smuggling_single_signals_stay_under_the_flag() {
    let page = format!("<script>var d = \"{}\";</script>", payload(60 * 1024));
    let alone = html_smuggling::score(page.as_bytes());
    assert!(alone < html_smuggling::FLAG_SCORE, "{alone}");
    let decode_only = html_smuggling::score(b"<script>var s = atob(x);</script>");
    assert!(decode_only < 0.2, "{decode_only}");
    // A comparison is not an assignment.
    assert_eq!(
        html_smuggling::score(b"<script>if (a.download == b) {}</script>"),
        0.0
    );
    // A short payload counts for less, and alone is not flagged.
    let short = format!("<script>var d = \"{}\";</script>", payload(30 * 1024));
    assert_eq!(html_smuggling::score(short.as_bytes()), 0.2);
    let tiny = format!("<script>var d = \"{}\";</script>", payload(4 * 1024));
    assert_eq!(html_smuggling::score(tiny.as_bytes()), 0.0);
}

fn flagged(html: &str) -> bool {
    html_smuggling::flagged(html.as_bytes())
}

#[test]
fn html_smuggling_image_data_uri_in_a_script_is_still_a_payload() {
    // Without msSaveOrOpenBlob, so the payload weight decides it.
    let kit = format!(
        r#"<script>var d = "data:image/png;base64,{}";
var b = new Blob([atob(d.split(",")[1])]);
var a = document.createElement("a"); a.href = URL.createObjectURL(b); a.download = "x.iso";</script>"#,
        payload(60 * 1024)
    );
    assert!(flagged(&kit));
    assert!(html_smuggling::score(kit.as_bytes()) >= 0.95);
    // The same data URI as an <img> outside any script is exempt.
    let image = format!(
        r#"<p><img src="data:image/png;base64,{}"></p>"#,
        payload(60 * 1024)
    );
    assert_eq!(html_smuggling::score(image.as_bytes()), 0.0);
}

#[test]
fn html_smuggling_split_payloads_and_spaced_calls_are_caught() {
    // A 60 KiB payload in 76-character string chunks.
    let chunks: Vec<String> = payload(60 * 1024)
        .as_bytes()
        .chunks(76)
        .map(|chunk| format!("\"{}\"", std::str::from_utf8(chunk).unwrap()))
        .collect();
    let split = format!(
        "<script>var d = [{}].join('');</script>",
        chunks.join(",\n")
    );
    assert_eq!(html_smuggling::score(split.as_bytes()), 0.4);
    // Spacing and quoted property access.
    let spaced = r#"<script>var b = new  Blob ( [window["atob"](d)] );
navigator.msSaveBlob(b, "x.iso");</script>"#;
    assert!(
        flagged(spaced),
        "{}",
        html_smuggling::score(spaced.as_bytes())
    );
    // Blob, an object URL and a download trigger make the chain on their own.
    let chain = r#"<script>var b = new Blob([bytes]); var a = document.createElement('a');
a.href = URL.createObjectURL(b); a.setAttribute('download', 'x.iso'); a.click();</script>"#;
    assert!(flagged(chain));
    // A small payload with three calls is flagged.
    let small = format!(
        "<script>var d = \"{}\"; var b = new Blob([atob(d)]); location = URL.createObjectURL(b);</script>",
        payload(30 * 1024)
    );
    assert!(flagged(&small));
}

#[test]
fn html_smuggling_in_a_zip_or_sniffed_without_a_name_is_flagged() {
    use std::io::Write;
    let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    zip.start_file("invoice.html", zip::write::SimpleFileOptions::default())
        .unwrap();
    zip.write_all(smuggling_page().as_bytes()).unwrap();
    let archive = zip.finish().unwrap().into_inner();
    let raw = message_with_bytes("invoice.zip", &archive);
    let parsed = parse_bytes("m2", &raw, &ExtractLimits::default());
    assert!(parsed
        .parts
        .iter()
        .any(|part| part.filename.as_deref() == Some("invoice.html")
            && part.flags.contains(&PartFlag::HtmlSmuggling)));

    // application/octet-stream with no file name: sniffed as HTML.
    let encoded = base64::engine::general_purpose::STANDARD.encode(smuggling_page());
    let raw = format!(
        "From: a@example.test\r\nTo: b@example.test\r\nSubject: x\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"b\"\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nhi\r\n--b\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment\r\nContent-Transfer-Encoding: base64\r\n\r\n{encoded}\r\n--b--\r\n"
    );
    let parsed = parse_bytes("m3", raw.as_bytes(), &ExtractLimits::default());
    assert!(parsed
        .parts
        .iter()
        .any(|part| part.flags.contains(&PartFlag::HtmlSmuggling)));
}

fn message_with_html(name: &str, html: &str) -> Vec<u8> {
    message_with_bytes(name, html.as_bytes())
}

fn message_with_bytes(name: &str, bytes: &[u8]) -> Vec<u8> {
    let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
    let wrapped: Vec<&str> = encoded
        .as_bytes()
        .chunks(76)
        .map(|line| std::str::from_utf8(line).unwrap())
        .collect();
    format!(
        "From: a@example.test\r\nTo: b@example.test\r\nSubject: invoice\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"b\"\r\n\r\n--b\r\nContent-Type: text/html\r\n\r\n{}\r\n--b\r\nContent-Type: application/octet-stream; name=\"{name}\"\r\nContent-Disposition: attachment; filename=\"{name}\"\r\nContent-Transfer-Encoding: base64\r\n\r\n{}\r\n--b--\r\n",
        newsletter(),
        wrapped.join("\r\n")
    )
    .into_bytes()
}

#[test]
fn html_smuggling_attachment_is_flagged_and_the_newsletter_body_is_not() {
    let raw = message_with_html("Invoice.HTM", &smuggling_page());
    let parsed = parse_bytes("m1", &raw, &ExtractLimits::default());
    assert!(parsed.error.is_none(), "{:?}", parsed.error);
    let flagged: Vec<_> = parsed
        .parts
        .iter()
        .filter(|part| part.flags.contains(&PartFlag::HtmlSmuggling))
        .map(|part| part.filename.clone())
        .collect();
    assert_eq!(flagged, vec![Some("Invoice.HTM".to_string())]);
}
