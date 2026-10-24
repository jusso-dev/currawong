//! Active SVG. A browser runs script in an SVG opened from disk or a link,
//! so phishing kits send SVG attachments that redirect or draw a login form.
//! Nothing is rendered or run; this looks for the markup that does it.
use crate::external::xml_unescape;
use regex::bytes::Regex;
use std::sync::OnceLock;

/// Bytes of a part searched for an `<svg` root.
const SNIFF: usize = 64 * 1024;
/// Bytes of an SVG checked for active content.
const MAX_SCAN: usize = 8 * 1024 * 1024;

/// SVG by name or, for a part with no better type, by its root element.
/// `text` is the part after `html_smuggling::decoded` (UTF-16 read).
pub fn is_svg(filename: Option<&str>, label: &str, text: &[u8]) -> bool {
    if filename
        .and_then(crate::filetype::file_extension)
        .is_some_and(|ext| ext == "svg" || ext == "svgz")
    {
        return true;
    }
    let texty = label == "application/octet-stream"
        || label.starts_with("text/")
        || label.contains("xml")
        || label == "image/svg+xml";
    if !texty {
        return false;
    }
    let start = text
        .iter()
        .position(|b| !b.is_ascii_whitespace() && !matches!(b, 0xEF | 0xBB | 0xBF))
        .unwrap_or(text.len());
    if text.get(start) != Some(&b'<') {
        return false;
    }
    let head = &text[start..text.len().min(start + SNIFF)];
    head.windows(4).any(|w| w.eq_ignore_ascii_case(b"<svg"))
}

struct Patterns {
    script: Regex,
    handler: Regex,
    foreign_object: Regex,
    foreign_html: Regex,
    scheme: Regex,
    refresh: Regex,
    redirect: Regex,
}

fn patterns() -> &'static Patterns {
    static PATTERNS: OnceLock<Patterns> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        let re = |pattern: &str| Regex::new(pattern).expect("static pattern");
        Patterns {
            script: re(r"(?i)<(?:[\w.-]+:)?script\b"),
            handler: re(r#"(?i)<[^<>]*[\s"'/]on[a-z]{3,}\s*="#),
            foreign_object: re(r"(?i)<(?:[\w.-]+:)?foreignObject\b"),
            foreign_html: re(
                r"(?i)<(?:[\w.-]+:)?(?:form|input|button|textarea|select|iframe|frame|embed|object|meta|base)\b",
            ),
            scheme: re(r"(?i)\b(?:javascript|vbscript|livescript)\s*:|\bdata:\s*text/html"),
            refresh: re(r#"(?i)http-equiv\s*=\s*["']?\s*refresh"#),
            redirect: re(
                r"(?i)(?:\b(?:window|document|top|self|parent)\s*\.\s*location\b|\blocation\s*\.\s*(?:href|replace|assign)\b)",
            ),
        }
    })
}

/// Script, event handlers, script or HTML links, HTML forms and frames in
/// `<foreignObject>`, a meta refresh or a `location` redirect. Diagrams that
/// use `<foreignObject>` for wrapped text (draw.io exports) are not flagged.
pub fn active(text: &[u8]) -> bool {
    let text = &text[..text.len().min(MAX_SCAN)];
    // Entities can spell out a scheme (`javascript&#58;`), and browsers drop
    // tabs and newlines inside one (`java&#9;script:`).
    let decoded = xml_unescape(&String::from_utf8_lossy(text));
    let compact: Vec<u8> = decoded
        .bytes()
        .filter(|b| !matches!(b, b'\t' | b'\r' | b'\n'))
        .collect();
    let markup = decoded.as_bytes();
    let p = patterns();
    // A scheme needs its colon: "JavaScript" in a title is not a link.
    if p.script.is_match(markup)
        || p.handler.is_match(markup)
        || p.scheme.is_match(&compact)
        || p.refresh.is_match(markup)
        || p.redirect.is_match(markup)
    {
        return true;
    }
    match p.foreign_object.find(markup) {
        Some(at) => p.foreign_html.is_match(&markup[at.end()..]),
        None => false,
    }
}
