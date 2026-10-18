//! Static HTML smuggling heuristics. Nothing is executed: the score comes
//! from an inline payload and the JavaScript calls that turn one into a
//! download in the browser.
use regex::bytes::Regex;
use std::sync::OnceLock;

/// Base64 inside scripts (summed over every chunk of at least
/// [`SCRIPT_CHUNK`] characters) or outside them (runs of at least
/// [`PAGE_CHUNK`]) is scored as an inline payload past these sizes.
pub const LARGE_PAYLOAD: usize = 50 * 1024;
pub const SMALL_PAYLOAD: usize = 8 * 1024;
const SCRIPT_CHUNK: usize = 32;
/// Long enough that tracking tokens in newsletter links do not add up.
const PAGE_CHUNK: usize = 1024;

/// A part scoring at least this is flagged `HtmlSmuggling`.
pub const FLAG_SCORE: f64 = 0.7;

/// Points out of [`MAX_POINTS`]; integers so the threshold is exact.
const MAX_POINTS: u32 = 20;
const FLAG_POINTS: u32 = 14;
const LARGE_POINTS: u32 = 8;
const SMALL_POINTS: u32 = 4;
const CALL_POINTS: u32 = 3;
/// A Blob together with an object URL or save call for it. With one more
/// call (a download trigger, `atob`) or a small payload it is flagged.
const CHAIN_POINTS: u32 = 5;

struct Calls {
    blob: Regex,
    atob: Regex,
    object_url: Regex,
    ms_save: Regex,
    download: Regex,
}

/// Whitespace and quoted property access (`window["atob"]`) are allowed.
fn calls() -> &'static Calls {
    static CALLS: OnceLock<Calls> = OnceLock::new();
    CALLS.get_or_init(|| {
        let re = |pattern: &str| Regex::new(pattern).expect("static pattern");
        Calls {
            blob: re(r#"new\s+(?:(?:window|self|globalThis)\s*\.\s*)?Blob\s*\(|\[\s*["']Blob["']\s*\]"#),
            atob: re(r#"\batob\s*\(|\[\s*["']atob["']\s*\]"#),
            object_url: re(r#"createObjectURL\s*\(|\[\s*["']createObjectURL["']\s*\]"#),
            ms_save: re(r"msSave(?:OrOpen)?Blob"),
            download: re(
                r#"\.\s*download\s*=[^=]|setAttribute\s*\(\s*["']download["']|\[\s*["']download["']\s*\]\s*=[^=]"#,
            ),
        }
    })
}

/// 0 to 1. A large payload alone (0.4) or any one call (0.15) stays under
/// [`FLAG_SCORE`].
pub fn score(html: &[u8]) -> f64 {
    f64::from(points(html)) / f64::from(MAX_POINTS)
}

/// The score reaches [`FLAG_SCORE`].
pub fn flagged(html: &[u8]) -> bool {
    points(html) >= FLAG_POINTS
}

fn points(html: &[u8]) -> u32 {
    let calls = calls();
    let mut points = match payload_chars(html) {
        n if n > LARGE_PAYLOAD => LARGE_POINTS,
        n if n > SMALL_PAYLOAD => SMALL_POINTS,
        _ => 0,
    };
    let blob = calls.blob.is_match(html);
    let object_url = calls.object_url.is_match(html);
    let ms_save = calls.ms_save.is_match(html);
    let download = calls.download.is_match(html);
    let atob = calls.atob.is_match(html);
    for hit in [blob, atob, object_url, ms_save, download] {
        if hit {
            points += CALL_POINTS;
        }
    }
    if blob && (object_url || ms_save) {
        points += CHAIN_POINTS;
    }
    points.min(MAX_POINTS)
}

/// HTML by MIME type, attachment name, or a sniff of the first bytes of a
/// part with no better type.
pub fn is_html(subtype_html: bool, filename: Option<&str>, label: &str, bytes: &[u8]) -> bool {
    if subtype_html {
        return true;
    }
    if let Some((_, ext)) = filename.and_then(|name| name.rsplit_once('.')) {
        if ["html", "htm", "xhtml", "xht", "shtml"]
            .iter()
            .any(|html| ext.eq_ignore_ascii_case(html))
        {
            return true;
        }
    }
    if label != "application/octet-stream" && !label.starts_with("text/") {
        return false;
    }
    let head = bytes[..bytes.len().min(1024)].to_ascii_lowercase();
    [&b"<html"[..], b"<script", b"<!doctype html"]
        .iter()
        .any(|tag| head.windows(tag.len()).any(|window| window == *tag))
}

/// Base64 characters that look like a payload. Inside `<script>` every
/// chunk of [`SCRIPT_CHUNK`] or more counts, so `"AAAA" + "BBBB"` and chunk
/// arrays add up. Outside, only runs of [`PAGE_CHUNK`] or more count, and
/// an inline image (`src="data:image/...;base64,` or `url(data:image/...`)
/// is exempt; the same data URI inside a script is not.
fn payload_chars(html: &[u8]) -> usize {
    let mut total = 0;
    let mut run = 0;
    let mut in_script = false;
    for (at, byte) in html.iter().enumerate() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=') {
            run += 1;
            continue;
        }
        total += counted(html, at, run, in_script);
        run = 0;
        if *byte == b'<' {
            let tag = &html[at..html.len().min(at + 9)];
            if starts_with_ignore_case(tag, b"<script") {
                in_script = true;
            } else if starts_with_ignore_case(tag, b"</script") {
                in_script = false;
            }
        }
    }
    total + counted(html, html.len(), run, in_script)
}

fn counted(html: &[u8], end: usize, run: usize, in_script: bool) -> usize {
    if in_script {
        return if run >= SCRIPT_CHUNK { run } else { 0 };
    }
    if run < PAGE_CHUNK || inline_image(&html[..end - run]) {
        return 0;
    }
    run
}

fn inline_image(before: &[u8]) -> bool {
    let tail = &before[before.len().saturating_sub(96)..];
    let tail = String::from_utf8_lossy(tail).to_ascii_lowercase();
    if !tail.ends_with(";base64,") {
        return false;
    }
    let Some(at) = tail.rfind("data:image/") else {
        return false;
    };
    let lead = tail[..at].trim_end_matches(['"', '\'', ' ', '\t', '\r', '\n']);
    lead.ends_with("src=") || lead.ends_with("srcset=") || lead.ends_with("url(")
}

fn starts_with_ignore_case(bytes: &[u8], prefix: &[u8]) -> bool {
    bytes.len() >= prefix.len() && bytes[..prefix.len()].eq_ignore_ascii_case(prefix)
}
