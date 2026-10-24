//! OneNote sections ([MS-ONESTORE]). Embedded files (and pictures) are
//! stored whole in `FileDataStoreObject` structures, so they are found by
//! their header GUID without walking the revision store.

/// `guidFileType` of a `.one` section: {7B5C52E4-D88C-4DA7-AEB1-5378D02996D3}.
const ONE_FILE: [u8; 16] = [
    0xe4, 0x52, 0x5c, 0x7b, 0x8c, 0xd8, 0xa7, 0x4d, 0xae, 0xb1, 0x53, 0x78, 0xd0, 0x29, 0x96, 0xd3,
];

/// `FileDataStoreObject.guidHeader`: {BDE316E7-2665-4511-A4C4-8D4D0B7A9EAC}.
pub const FILE_DATA_HEADER: [u8; 16] = [
    0xe7, 0x16, 0xe3, 0xbd, 0x65, 0x26, 0x11, 0x45, 0xa4, 0xc4, 0x8d, 0x4d, 0x0b, 0x7a, 0x9e, 0xac,
];

/// guidHeader (16), cbLength (8), unused (4), reserved (8).
const FILE_DATA_OFFSET: usize = 36;

/// Payloads returned per section. More is a limit hit.
pub const MAX_EMBEDDED: usize = 256;

pub fn is_onenote(bytes: &[u8]) -> bool {
    bytes.starts_with(&ONE_FILE)
}

/// Embedded file payloads, in file order. A payload whose declared length
/// runs past the end of the section is cut there. The bool is true when
/// there were more than [`MAX_EMBEDDED`].
pub fn embedded(bytes: &[u8]) -> (Vec<&[u8]>, bool) {
    let mut out = Vec::new();
    let mut at = ONE_FILE.len();
    while let Some(found) = find(&bytes[at.min(bytes.len())..], &FILE_DATA_HEADER) {
        let start = at + found;
        let Some(raw) = bytes.get(start + 16..start + 24) else {
            break;
        };
        if out.len() >= MAX_EMBEDDED {
            return (out, true);
        }
        let len = u64::from_le_bytes(raw.try_into().unwrap_or([0; 8]));
        let data = start + FILE_DATA_OFFSET;
        let end = usize::try_from(len)
            .ok()
            .and_then(|len| data.checked_add(len))
            .map_or(bytes.len(), |end| end.min(bytes.len()));
        out.push(bytes.get(data..end).unwrap_or_default());
        // A payload can itself hold the header GUID; skip past it.
        at = end.max(start + 16);
    }
    (out, false)
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}
