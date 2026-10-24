//! Targets a document reaches outside itself: remote locations and protocol
//! handlers that start a Windows program. Shared by the Office, RTF, PDF and
//! shortcut checks. Nothing is fetched.

/// Links recorded per document. The message-wide cap is in `parse.rs`.
pub const MAX_LINKS: usize = 64;
/// Longest link recorded; longer ones are cut.
const MAX_LINK_LEN: usize = 2048;

/// Schemes whose handler runs a program or searches a remote share
/// (Follina's `ms-msdt:`, `search-ms:` lures and so on).
const HANDLERS: &[&str] = &[
    "ms-msdt:",
    "search-ms:",
    "search:",
    "ms-search:",
    "ms-officecmd:",
    "mhtml:",
    "ms-its:",
    "mk:@msitstore:",
    "ms-appinstaller:",
];

/// Office URI schemes. Dangerous with a command and a `u` (URL) argument,
/// such as `ms-word:ofe|u|https://...`, which opens a remote file for editing.
const OFFICE_SCHEMES: &[&str] = &[
    "ms-word:",
    "ms-excel:",
    "ms-powerpoint:",
    "ms-visio:",
    "ms-access:",
    "ms-project:",
    "ms-publisher:",
    "ms-spd:",
    "ms-infopath:",
];

/// Flags and links found in one document.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Findings {
    pub flags: Vec<currawong_core::PartFlag>,
    pub links: Vec<String>,
}

impl Findings {
    pub fn flag(&mut self, flag: currawong_core::PartFlag) {
        if !self.flags.contains(&flag) {
            self.flags.push(flag);
        }
    }

    /// Records a link once, cut to a bounded length.
    pub fn link(&mut self, target: &str) {
        let target = target.trim();
        if target.is_empty() || self.links.len() >= MAX_LINKS {
            return;
        }
        let mut end = target.len().min(MAX_LINK_LEN);
        while !target.is_char_boundary(end) {
            end -= 1;
        }
        let target = target[..end].to_string();
        if !self.links.contains(&target) {
            self.links.push(target);
        }
    }

    pub fn merge(&mut self, other: Findings) {
        for flag in other.flags {
            self.flag(flag);
        }
        for link in other.links {
            self.link(&link);
        }
    }
}

/// A target that starts with a dangerous protocol handler.
pub fn is_handler(target: &str) -> bool {
    let target = clean(target);
    let lower = target.to_ascii_lowercase();
    if HANDLERS.iter().any(|scheme| lower.starts_with(scheme)) {
        return true;
    }
    OFFICE_SCHEMES
        .iter()
        .any(|scheme| lower.starts_with(scheme))
        && lower.contains("|u|")
}

/// A target on another host: http(s), a UNC path, `file://host/...` or
/// WebDAV. `file:///C:/...` and `C:\...` are local and are not remote:
/// Word records local template paths in ordinary documents.
pub fn is_remote(target: &str) -> bool {
    let target = clean(target);
    let lower = target.to_ascii_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") {
        return true;
    }
    if lower.starts_with("smb:") || lower.starts_with("webdav:") || lower.starts_with("ftp://") {
        return true;
    }
    if target.starts_with("\\\\") || target.starts_with("//") {
        return true;
    }
    let Some(rest) = lower.strip_prefix("file:") else {
        return false;
    };
    let separators = rest.chars().take_while(|c| matches!(c, '/' | '\\')).count();
    let path = &rest[separators..];
    let drive = path
        .as_bytes()
        .get(1)
        .is_some_and(|c| matches!(c, b':' | b'|'))
        && path.as_bytes()[0].is_ascii_alphabetic();
    !drive && !path.is_empty() && separators != 3 && separators >= 2
}

/// Leading quotes, whitespace and control characters go: Windows and the
/// Office link parser ignore them.
fn clean(target: &str) -> &str {
    target.trim_matches(|c: char| c.is_whitespace() || c.is_control() || c == '"' || c == '\'')
}

/// Field instruction arguments, split on whitespace and quotes. A field's
/// type is its first word, and its target is any argument.
pub fn words(text: &str) -> impl Iterator<Item = &str> {
    text.split(|c: char| c.is_whitespace() || c == '"')
        .filter(|word| !word.is_empty())
}

/// A Word field instruction (OOXML or RTF): DDE fields and links to
/// protocol handlers.
pub fn field(instruction: &str, found: &mut Findings) {
    let mut args = words(instruction);
    let Some(kind) = args.next() else {
        return;
    };
    if kind.eq_ignore_ascii_case("DDE") || kind.eq_ignore_ascii_case("DDEAUTO") {
        found.flag(currawong_core::PartFlag::DdeField);
    }
    for arg in std::iter::once(kind).chain(args) {
        if is_handler(arg) {
            found.flag(currawong_core::PartFlag::ProtocolHandler);
            found.link(arg);
        }
    }
}

/// `&amp;`, `&quot;`, `&#58;` and the like. Unknown entities stay as they are.
pub fn xml_unescape(text: &str) -> String {
    if !text.contains('&') {
        return text.to_string();
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find('&') {
        out.push_str(&rest[..at]);
        rest = &rest[at..];
        // Bytes, not a str slice: 12 bytes in may be inside a character.
        let Some(end) = rest.bytes().take(12).position(|b| b == b';') else {
            out.push('&');
            rest = &rest[1..];
            continue;
        };
        let entity = &rest[1..end];
        let decoded = match entity {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            "colon" => Some(':'),
            "tab" => Some('\t'),
            "newline" => Some('\n'),
            _ => entity
                .strip_prefix("#x")
                .or_else(|| entity.strip_prefix("#X"))
                .and_then(|hex| u32::from_str_radix(hex, 16).ok())
                .or_else(|| entity.strip_prefix('#').and_then(|dec| dec.parse().ok()))
                .and_then(char::from_u32),
        };
        match decoded {
            Some(c) => {
                out.push(c);
                rest = &rest[end + 1..];
            }
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_targets() {
        for remote in [
            "https://example.test/t.dotm",
            "http://example.test/t",
            "\\\\server\\share\\t.dotm",
            "//server/share/t.dotm",
            "file://server/share/t.dotm",
            "file:////server/share/t.dotm",
            "file:///\\\\server\\share",
            " \"HTTPS://example.test\"",
        ] {
            assert!(is_remote(remote), "{remote}");
        }
        for local in [
            "file:///C:/Users/a/AppData/Roaming/Microsoft/Templates/Normal.dotm",
            "file:///C:\\Users\\a\\Normal.dotm",
            "file://C:/Users/a/Normal.dotm",
            "C:\\Users\\a\\Normal.dotm",
            "Normal.dotm",
            "file:///home/a/t.dotx",
            "",
        ] {
            assert!(!is_remote(local), "{local}");
        }
    }

    #[test]
    fn handlers() {
        for handler in [
            "ms-msdt:/id PCWDiagnostic",
            "search-ms:query=invoice&crumb=location:\\\\server\\share",
            "MS-OFFICECMD:{}",
            "ms-word:ofe|u|https://example.test/a.docx",
            "mhtml:https://example.test/a!x-usc:https://example.test/b",
        ] {
            assert!(is_handler(handler), "{handler}");
        }
        for benign in [
            "https://example.test/",
            "mailto:a@example.test",
            "ms-word:",
            "researcher:",
        ] {
            assert!(!is_handler(benign), "{benign}");
        }
    }

    #[test]
    fn fields() {
        let mut found = Findings::default();
        field(" DDEAUTO c:\\\\windows\\\\notepad.exe \"x\" ", &mut found);
        assert_eq!(found.flags, vec![currawong_core::PartFlag::DdeField]);
        let mut found = Findings::default();
        field("HYPERLINK \"search-ms:query=a\"", &mut found);
        assert_eq!(found.flags, vec![currawong_core::PartFlag::ProtocolHandler]);
        assert_eq!(found.links, vec!["search-ms:query=a"]);
        let mut found = Findings::default();
        field("PAGE \\* MERGEFORMAT", &mut found);
        field("HYPERLINK \"https://example.test/\"", &mut found);
        assert!(found.flags.is_empty());
    }

    #[test]
    fn entities() {
        assert_eq!(
            xml_unescape("a&amp;b&#58;&#x3A;&lt;&bogus;&"),
            "a&b::<&bogus;&"
        );
        assert_eq!(
            xml_unescape("&\u{1F600}\u{1F600}\u{1F600};"),
            "&\u{1F600}\u{1F600}\u{1F600};"
        );
    }
}
