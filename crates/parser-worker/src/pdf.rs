//! PDF active content, in the manner of pdfid: the names that make a PDF do
//! something (`/JavaScript`, `/Launch`, `/OpenAction`...) counted after
//! `#xx` escapes are undone, in the file and inside compressed object
//! streams. `/URI` targets are recorded for link analysis and embedded files
//! are returned for extraction. Nothing is rendered or run, and the
//! cross-reference table is not trusted or needed.
use crate::external::{self, Findings};
use currawong_core::PartFlag;
use regex::bytes::Regex;
use std::io::Read;
use std::ops::Range;
use std::sync::OnceLock;

/// Readers accept the header anywhere in the first KiB.
const HEADER_WINDOW: usize = 1024;
/// Streams tracked per file. Past this the rest is scanned as plain text.
const MAX_STREAMS: usize = 65_536;
/// How far back from `stream` the object header is looked for.
const DICT_WINDOW: usize = 4096;
/// Inflated bytes per object stream, and for all of them in one file.
const MAX_OBJSTM_BYTES: u64 = 16 * 1024 * 1024;
const MAX_OBJSTM_TOTAL: u64 = 64 * 1024 * 1024;
/// Embedded files returned per file. More is a limit hit.
pub const MAX_EMBEDDED: usize = 256;
const MAX_NAME: usize = 127;
const MAX_STRING: usize = 4096;

/// One embedded file's stream data, still encoded when `flate`.
pub struct Embedded<'a> {
    pub name: Option<String>,
    pub data: &'a [u8],
    pub flate: bool,
}

#[derive(Default)]
pub struct Scan<'a> {
    pub found: Findings,
    pub embedded: Vec<Embedded<'a>>,
    /// Object streams inflated past their limit, or too many embedded files.
    pub limit_hit: bool,
    /// An embedded file that cannot be decoded (encrypted file, or a filter
    /// other than FlateDecode).
    pub unscannable: bool,
}

pub fn is_pdf(bytes: &[u8]) -> bool {
    bytes[..bytes.len().min(HEADER_WINDOW)]
        .windows(5)
        .any(|window| window == b"%PDF-")
}

struct Stream {
    obj: Option<u32>,
    dict: Range<usize>,
    data: Range<usize>,
}

/// What the name scan has seen so far.
#[derive(Default)]
struct State {
    encrypted: bool,
    /// Object numbers named by `/EF` dictionaries, with the file name from
    /// the same file specification when one was found.
    embedded_refs: Vec<(u32, Option<String>)>,
}

pub fn scan(bytes: &[u8]) -> Scan<'_> {
    let mut scan = Scan::default();
    let mut state = State::default();
    let streams = streams(bytes);
    // Stream data is skipped: binary content would give false names.
    let mut at = 0;
    for stream in &streams {
        text(&bytes[at..stream.data.start], &mut state, &mut scan.found);
        at = stream.data.end;
    }
    text(&bytes[at.min(bytes.len())..], &mut state, &mut scan.found);

    // Encrypted object streams cannot be read without the key; the names
    // outside them (and the dictionary keys of every stream) still are.
    let mut inflated_total = 0u64;
    for stream in &streams {
        let names = dict_names(&bytes[stream.dict.clone()]);
        if state.encrypted || !names.iter().any(|name| name == b"ObjStm") {
            continue;
        }
        let data = &bytes[stream.data.clone()];
        let inner = match filters(&names).as_slice() {
            [] => data.to_vec(),
            [Filter::Flate] => {
                let cap = MAX_OBJSTM_BYTES.min(MAX_OBJSTM_TOTAL.saturating_sub(inflated_total));
                let (out, over) = inflate(data, cap);
                if over {
                    scan.limit_hit = true;
                }
                inflated_total += out.len() as u64;
                out
            }
            // Other filters on an object stream are not decoded (a gap,
            // see docs/VALIDATION.md).
            _ => continue,
        };
        text(&inner, &mut state, &mut scan.found);
    }

    for stream in &streams {
        let names = dict_names(&bytes[stream.dict.clone()]);
        let referenced = stream
            .obj
            .and_then(|obj| state.embedded_refs.iter().find(|(r, _)| *r == obj));
        let typed = names.iter().any(|name| name == b"EmbeddedFile");
        if !typed && referenced.is_none() {
            continue;
        }
        scan.found.flag(PartFlag::PdfEmbeddedFile);
        if state.encrypted {
            scan.unscannable = true;
            continue;
        }
        let flate = match filters(&names).as_slice() {
            [] => false,
            [Filter::Flate] => true,
            _ => {
                scan.unscannable = true;
                continue;
            }
        };
        if scan.embedded.len() >= MAX_EMBEDDED {
            scan.limit_hit = true;
            break;
        }
        scan.embedded.push(Embedded {
            name: referenced.and_then(|(_, name)| name.clone()),
            data: &bytes[stream.data.clone()],
            flate,
        });
    }
    scan
}

/// Names and strings in object text: keyword flags, `/URI` targets,
/// `/Encrypt` and `/EF` references.
fn text(segment: &[u8], state: &mut State, found: &mut Findings) {
    each_name(segment, |name, end| {
        let flag = match name {
            b"JavaScript" | b"JS" | b"RichMedia" => Some(PartFlag::PdfJavaScript),
            b"Launch" => Some(PartFlag::PdfLaunch),
            b"EmbeddedFile" | b"EmbeddedFiles" => Some(PartFlag::PdfEmbeddedFile),
            b"OpenAction" | b"AA" => Some(PartFlag::PdfAutoAction),
            b"XFA" | b"SubmitForm" => Some(PartFlag::PdfForm),
            b"GoToR" | b"GoToE" => Some(PartFlag::PdfRemoteAction),
            _ => None,
        };
        if let Some(flag) = flag {
            found.flag(flag);
        }
        match name {
            b"Encrypt" => state.encrypted = true,
            b"URI" => {
                if let Some(uri) = string_at(&segment[end..]) {
                    if uri.contains(':') {
                        found.link(&uri);
                    }
                    if external::is_handler(&uri) {
                        found.flag(PartFlag::ProtocolHandler);
                    }
                }
            }
            b"EF" if state.embedded_refs.len() < MAX_EMBEDDED * 4 => {
                let name = file_name_near(segment, end);
                for obj in references(&segment[end..]) {
                    state.embedded_refs.push((obj, name.clone()));
                }
            }
            _ => {}
        }
    });
}

/// Calls `f` with every name (without the slash, `#xx` decoded) and the
/// offset just past it. Over-long names are skipped.
fn each_name(text: &[u8], mut f: impl FnMut(&[u8], usize)) {
    let mut name = Vec::with_capacity(32);
    let mut i = 0;
    while i < text.len() {
        if text[i] != b'/' {
            i += 1;
            continue;
        }
        i += 1;
        name.clear();
        let mut long = false;
        while i < text.len() && !is_delimiter(text[i]) {
            let mut byte = text[i];
            if byte == b'#' {
                let hex = text
                    .get(i + 1..i + 3)
                    .and_then(|h| std::str::from_utf8(h).ok())
                    .and_then(|h| u8::from_str_radix(h, 16).ok());
                if let Some(decoded) = hex {
                    byte = decoded;
                    i += 2;
                }
            }
            if name.len() < MAX_NAME {
                name.push(byte);
            } else {
                long = true;
            }
            i += 1;
        }
        if !long && !name.is_empty() {
            f(&name, i);
        }
    }
}

fn is_delimiter(byte: u8) -> bool {
    matches!(
        byte,
        0 | b'\t'
            | b'\n'
            | 0x0c
            | b'\r'
            | b' '
            | b'('
            | b')'
            | b'<'
            | b'>'
            | b'['
            | b']'
            | b'{'
            | b'}'
            | b'/'
            | b'%'
    )
}

fn dict_names(dict: &[u8]) -> Vec<Vec<u8>> {
    let mut names = Vec::new();
    each_name(dict, |name, _| {
        if names.len() < 256 {
            names.push(name.to_vec());
        }
    });
    names
}

#[derive(Debug, PartialEq)]
enum Filter {
    Flate,
    Other,
}

/// The decode filters a stream dictionary names, in order.
fn filters(names: &[Vec<u8>]) -> Vec<Filter> {
    names
        .iter()
        .filter_map(|name| match name.as_slice() {
            b"FlateDecode" | b"Fl" => Some(Filter::Flate),
            b"ASCIIHexDecode" | b"AHx" | b"ASCII85Decode" | b"A85" | b"LZWDecode" | b"LZW"
            | b"RunLengthDecode" | b"RL" | b"CCITTFaxDecode" | b"CCF" | b"JBIG2Decode"
            | b"DCTDecode" | b"DCT" | b"JPXDecode" | b"Crypt" => Some(Filter::Other),
            _ => None,
        })
        .collect()
}

/// At most `cap` bytes. A truncated or corrupt stream yields what inflated
/// before the error. The bool is true when there was more than `cap`.
fn inflate(data: &[u8], cap: u64) -> (Vec<u8>, bool) {
    let mut out = Vec::new();
    let decoder = flate2::read::ZlibDecoder::new(data);
    let _ = decoder.take(cap.saturating_add(1)).read_to_end(&mut out);
    let over = out.len() as u64 > cap;
    out.truncate(usize::try_from(cap).unwrap_or(usize::MAX));
    (out, over)
}

struct Patterns {
    stream: Regex,
    length: Regex,
    reference: Regex,
    file_name: Regex,
}

fn patterns() -> &'static Patterns {
    static PATTERNS: OnceLock<Patterns> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        let re = |pattern: &str| Regex::new(pattern).expect("static pattern");
        Patterns {
            stream: re(r"stream(?:\r\n|\n|\r)"),
            length: re(r"/Length\s+(\d{1,12})(\s+\d+\s+R)?"),
            reference: re(r"(\d{1,10})\s+\d{1,5}\s+R\b"),
            file_name: re(r"/(?:UF|F)\s*\("),
        }
    })
}

/// Every `stream ... endstream` that follows a dictionary, in file order.
fn streams(bytes: &[u8]) -> Vec<Stream> {
    let p = patterns();
    let mut out = Vec::new();
    let mut pos = 0;
    let mut prev_end = 0;
    while let Some(m) = p.stream.find_at(bytes, pos) {
        if out.len() >= MAX_STREAMS {
            break;
        }
        let keyword = m.start();
        pos = m.end();
        let before = trim_end(&bytes[prev_end..keyword]);
        if !before.ends_with(b">>") {
            continue;
        }
        let dict_end = prev_end + before.len();
        let window = dict_end.saturating_sub(DICT_WINDOW).max(prev_end);
        let header = rfind(&bytes[window..dict_end], b"obj").map(|at| window + at);
        let dict_start = header.map_or(window, |at| at + 3);
        let obj = header.and_then(|at| object_number(&bytes[window..at]));
        let data_start = m.end();
        let declared = p
            .length
            .captures(&bytes[dict_start..dict_end])
            .filter(|caps| caps.get(2).is_none())
            .and_then(|caps| std::str::from_utf8(&caps[1]).ok()?.parse::<usize>().ok())
            .and_then(|len| data_start.checked_add(len))
            .filter(|&end| {
                end <= bytes.len() && trim_start(&bytes[end..]).starts_with(b"endstream")
            });
        let data_end = declared.unwrap_or_else(|| {
            find(&bytes[data_start..], b"endstream").map_or(bytes.len(), |at| data_start + at)
        });
        out.push(Stream {
            obj,
            dict: dict_start..dict_end,
            data: data_start..data_end,
        });
        pos = data_end.max(pos);
        prev_end = data_end;
    }
    out
}

/// `12 0` before `obj`.
fn object_number(before: &[u8]) -> Option<u32> {
    let before = trim_end(before);
    let generation = before.len()
        - before
            .iter()
            .rev()
            .take_while(|b| b.is_ascii_digit())
            .count();
    let rest = trim_end(&before[..generation]);
    let digits = rest.iter().rev().take_while(|b| b.is_ascii_digit()).count();
    if digits == 0 || generation == before.len() {
        return None;
    }
    std::str::from_utf8(&rest[rest.len() - digits..])
        .ok()?
        .parse()
        .ok()
}

/// Indirect references in the dictionary that starts at `text`.
fn references(text: &[u8]) -> Vec<u32> {
    let text = trim_start(text);
    if !text.starts_with(b"<<") {
        return Vec::new();
    }
    let end = find(text, b">>").unwrap_or(text.len()).min(512);
    patterns()
        .reference
        .captures_iter(&text[..end])
        .filter_map(|caps| std::str::from_utf8(&caps[1]).ok()?.parse().ok())
        .take(8)
        .collect()
}

/// `/UF (name)` or `/F (name)` near an `/EF` entry: file specifications
/// keep the name beside the embedded file reference. `/UF` wins.
fn file_name_near(segment: &[u8], at: usize) -> Option<String> {
    let window = &segment[at.saturating_sub(512)..segment.len().min(at + 512)];
    let mut best: Option<(bool, String)> = None;
    for m in patterns().file_name.find_iter(window) {
        let unicode = window[m.start()..].starts_with(b"/UF");
        let Some(name) = string_at(&window[m.end() - 1..]) else {
            continue;
        };
        if name.is_empty() || best.as_ref().is_some_and(|(u, _)| *u && !unicode) {
            continue;
        }
        best = Some((unicode, name));
    }
    best.map(|(_, name)| name)
}

/// A literal `( )` or hex `< >` string at the start of `text`, after
/// whitespace. UTF-16BE with a byte order mark is decoded.
fn string_at(text: &[u8]) -> Option<String> {
    let text = trim_start(text);
    let raw = match text.first()? {
        b'(' => literal(&text[1..]),
        b'<' if text.get(1) != Some(&b'<') => hex(&text[1..]),
        _ => return None,
    };
    if let Some(utf16) = raw.strip_prefix(&[0xfe, 0xff]) {
        let units = utf16
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u16::from_be_bytes(*pair));
        return Some(
            char::decode_utf16(units)
                .map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER))
                .collect(),
        );
    }
    Some(String::from_utf8_lossy(&raw).into_owned())
}

fn literal(text: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut depth = 1u32;
    let mut i = 0;
    while i < text.len() && out.len() < MAX_STRING {
        let byte = text[i];
        match byte {
            b'\\' => {
                i += 1;
                match text.get(i) {
                    Some(b'n') => out.push(b'\n'),
                    Some(b'r') => out.push(b'\r'),
                    Some(b't') => out.push(b'\t'),
                    Some(b'b') => out.push(8),
                    Some(b'f') => out.push(12),
                    Some(b'\r') => {
                        if text.get(i + 1) == Some(&b'\n') {
                            i += 1;
                        }
                    }
                    Some(b'\n') => {}
                    Some(d) if (b'0'..=b'7').contains(d) => {
                        let mut value = 0u32;
                        let mut n = 0;
                        while n < 3 && text.get(i).is_some_and(|c| (b'0'..=b'7').contains(c)) {
                            value = value * 8 + u32::from(text[i] - b'0');
                            i += 1;
                            n += 1;
                        }
                        out.push(value as u8);
                        continue;
                    }
                    Some(other) => out.push(*other),
                    None => break,
                }
            }
            b'(' => {
                depth += 1;
                out.push(byte);
            }
            b')' => {
                depth -= 1;
                if depth == 0 {
                    break;
                }
                out.push(byte);
            }
            _ => out.push(byte),
        }
        i += 1;
    }
    out
}

fn hex(text: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut high: Option<u8> = None;
    for &byte in text.iter().take(MAX_STRING * 2 + 64) {
        if byte == b'>' {
            break;
        }
        let Some(value) = (byte as char).to_digit(16) else {
            continue;
        };
        match high.take() {
            Some(h) => out.push((h << 4) | value as u8),
            None => high = Some(value as u8),
        }
    }
    if let Some(h) = high {
        out.push(h << 4);
    }
    out
}

fn trim_end(bytes: &[u8]) -> &[u8] {
    let end = bytes.len()
        - bytes
            .iter()
            .rev()
            .take_while(|b| is_whitespace(**b))
            .count();
    &bytes[..end]
}

fn trim_start(bytes: &[u8]) -> &[u8] {
    let start = bytes.iter().take_while(|b| is_whitespace(**b)).count();
    &bytes[start..]
}

fn is_whitespace(byte: u8) -> bool {
    matches!(byte, 0 | b'\t' | b'\n' | 0x0c | b'\r' | b' ')
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn rfind(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .rposition(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_decoded() {
        let mut seen = Vec::new();
        each_name(b"<</J#61vaScript/JS(x)/A#41 /Type/Ann#6Ft>>", |name, _| {
            seen.push(String::from_utf8_lossy(name).into_owned())
        });
        assert_eq!(seen, ["JavaScript", "JS", "AA", "Type", "Annot"]);
    }

    #[test]
    fn strings() {
        assert_eq!(
            string_at(b" (a\\(b\\)c (d) \\101)").as_deref(),
            Some("a(b)c (d) A")
        );
        assert_eq!(string_at(b"<68747470 3>").as_deref(), Some("http0"));
        assert_eq!(string_at(b"<</X 1>>"), None);
        assert_eq!(string_at(b"(\xfe\xff\x00h\x00i)").as_deref(), Some("hi"));
    }

    #[test]
    fn object_numbers() {
        assert_eq!(object_number(b"\n12 0 "), Some(12));
        assert_eq!(object_number(b"endobj\n7 3"), Some(7));
        assert_eq!(object_number(b"x"), None);
    }
}
