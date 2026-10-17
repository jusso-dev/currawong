//! Panic-free parser entry points for cargo-fuzz and the cargo test stand-in.
use crate::archive::extract;
use crate::parse::parse_bytes;
use currawong_core::config::ExtractLimits;

pub fn mime(data: &[u8]) {
    let data = cap(data);
    let _ = parse_bytes("fuzz", data, &tight());
}

pub fn archive(data: &[u8]) {
    let data = cap(data);
    let _ = extract(data, Some("fuzz.bin"), &tight(), &[]);
}

pub fn urls_in(data: &[u8]) -> Vec<String> {
    let data = cap(data);
    let mut out = Vec::new();
    let text = String::from_utf8_lossy(data);
    let bytes = text.as_bytes();
    let mut i = 0;
    while i + 8 < bytes.len() && out.len() < 32 {
        let rest = &bytes[i..];
        let scheme = if rest.starts_with(b"https://") {
            Some(8)
        } else if rest.starts_with(b"http://") {
            Some(7)
        } else {
            None
        };
        if let Some(skip) = scheme {
            let start = i;
            i += skip;
            let mut len = skip;
            while i < bytes.len() && len < 2048 {
                let b = bytes[i];
                if b.is_ascii_whitespace() || matches!(b, b'<' | b'>' | b'"' | b'\'' | b')' | b'(')
                {
                    break;
                }
                i += 1;
                len += 1;
            }
            if let Ok(url) = std::str::from_utf8(&bytes[start..i]) {
                out.push(url.to_string());
            }
        } else {
            i += 1;
        }
    }
    out
}

fn cap(data: &[u8]) -> &[u8] {
    if data.len() > 256 * 1024 {
        &data[..256 * 1024]
    } else {
        data
    }
}

fn tight() -> ExtractLimits {
    ExtractLimits {
        max_depth: 3,
        max_uncompressed_bytes: 1024 * 1024,
        max_files: 32,
        max_ratio: 50,
    }
}
