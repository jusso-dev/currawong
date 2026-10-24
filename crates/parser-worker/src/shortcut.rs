//! Windows shell files that open something else when double-clicked.
//! `.lnk` is recognised by its header in `filetype` and flagged `Executable`;
//! this covers the text formats. Nothing is resolved or followed.
use crate::external::{self, Findings};
use crate::filetype::{file_extension, FileKind};
use crate::html_smuggling;
use currawong_core::PartFlag;

/// Bytes read from the start of a part to recognise a shell file.
const SNIFF: usize = 4096;
/// Bytes of an Internet shortcut read for its lines.
const MAX_READ: usize = 1024 * 1024;
/// Lines of an Internet shortcut read for `URL=` and `IconFile=`.
const MAX_LINES: usize = 4096;

/// Shell files that are never content: they point at a share, a saved
/// search or a settings page, or run a shell command.
const SHELL_EXTENSIONS: &[&str] = &[
    "library-ms",
    "search-ms",
    "searchconnector-ms",
    "scf",
    "settingcontent-ms",
];

/// Root elements and section headers of the same files, for parts sent
/// under another name.
const SHELL_MARKERS: &[&[u8]] = &[
    b"<librarydescription",
    b"<searchconnectordescription",
    b"<persistedquery",
    b"<pcsettings",
];

/// `None` when the part is not a shell file.
pub fn inspect(bytes: &[u8], filename: Option<&str>, kind: &FileKind) -> Option<Findings> {
    if kind.executable {
        return None;
    }
    let ext = filename.and_then(file_extension);
    let text = html_smuggling::decoded(&bytes[..bytes.len().min(MAX_READ)]);
    let head = text[..text.len().min(SNIFF)].to_ascii_lowercase();
    let head = trim_start(&head);
    let texty = kind.label == "application/octet-stream"
        || kind.label.starts_with("text/")
        || kind.label.contains("xml");
    let mut found = Findings::default();
    if ext.as_deref() == Some("url") || (texty && head.starts_with(b"[internetshortcut]")) {
        internet_shortcut(&text, &mut found);
        return Some(found);
    }
    let marked = texty
        && (head.starts_with(b"[shell]")
            || SHELL_MARKERS
                .iter()
                .any(|marker| head.windows(marker.len()).any(|w| w == *marker)));
    if marked
        || ext
            .as_deref()
            .is_some_and(|ext| SHELL_EXTENSIONS.contains(&ext))
    {
        found.flag(PartFlag::Shortcut);
        return Some(found);
    }
    None
}

/// An Internet shortcut is a lure when it points somewhere other than a web
/// page (a share, `file:`, a protocol handler) or loads its icon from a share
/// (which sends the reader's NTLM hash). Web URLs are only recorded.
fn internet_shortcut(text: &[u8], found: &mut Findings) {
    let text = String::from_utf8_lossy(text);
    for line in text.lines().take(MAX_LINES) {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();
        if key.eq_ignore_ascii_case("URL") {
            found.link(value);
            let lower = value.to_ascii_lowercase();
            if !(lower.starts_with("http://") || lower.starts_with("https://")) {
                found.flag(PartFlag::Shortcut);
            }
            if external::is_handler(value) {
                found.flag(PartFlag::ProtocolHandler);
            }
        } else if key.eq_ignore_ascii_case("IconFile") && external::is_remote(value) {
            let lower = value.to_ascii_lowercase();
            if !(lower.starts_with("http://") || lower.starts_with("https://")) {
                found.flag(PartFlag::Shortcut);
            }
        }
    }
}

fn trim_start(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|b| !b.is_ascii_whitespace() && !matches!(b, 0xEF | 0xBB | 0xBF))
        .unwrap_or(bytes.len());
    &bytes[start..]
}
