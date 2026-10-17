//! Linear URL scan. Bounded, no regular expressions.
//! Rewriting for click-time protection is an M2 product. This function only
//! finds URLs and can substitute a local token of the same length budget.

pub fn find_urls(input: &str) -> Vec<String> {
    currawong_parser::fuzz::urls_in(input.as_bytes())
}

pub fn rewrite(input: &str, replacement_prefix: &str) -> String {
    let bytes = input.as_bytes();
    let limit = bytes.len().min(1024 * 1024);
    let mut out = String::new();
    let mut i = 0;
    let mut rewritten = 0u32;
    while i < limit && rewritten < 64 {
        let rest = &bytes[i..limit];
        let scheme = if rest.starts_with(b"https://") {
            8
        } else if rest.starts_with(b"http://") {
            7
        } else {
            0
        };
        if scheme == 0 {
            out.push(bytes[i] as char);
            i += 1;
            continue;
        }
        let start = i;
        i += scheme;
        while i < limit {
            let b = bytes[i];
            if b.is_ascii_whitespace() || matches!(b, b'<' | b'>' | b'"' | b'\'') {
                break;
            }
            if i - start >= 2048 {
                break;
            }
            i += 1;
        }
        out.push_str(replacement_prefix);
        out.push_str(&format!("{rewritten}"));
        rewritten += 1;
    }
    if i < bytes.len() {
        out.push_str(&String::from_utf8_lossy(&bytes[i..limit.min(bytes.len())]));
    }
    out
}

pub fn fuzz(data: &[u8]) {
    let text = String::from_utf8_lossy(if data.len() > 64 * 1024 {
        &data[..64 * 1024]
    } else {
        data
    });
    let _ = rewrite(&text, "https://rewrite.local/");
}
