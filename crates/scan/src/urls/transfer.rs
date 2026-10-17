//! Content-Transfer-Encoding round trips for rewritten parts. Lenient on
//! decode, RFC 2045 on encode.
use base64::{engine::general_purpose::STANDARD, Engine};

/// Longest line SMTP carries, without the line ending (RFC 5321 4.5.3.1.6).
pub const MAX_LINE: usize = 998;

pub fn decode_qp(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        let b = input[i];
        if b != b'=' {
            out.push(b);
            i += 1;
            continue;
        }
        // Soft line break, allowing trailing whitespace some encoders leave.
        let mut j = i + 1;
        while j < input.len() && matches!(input[j], b' ' | b'\t') {
            j += 1;
        }
        if input[j..].starts_with(b"\r\n") {
            i = j + 2;
        } else if input[j..].starts_with(b"\n") {
            i = j + 1;
        } else if let (Some(hi), Some(lo)) = (
            input.get(i + 1).and_then(|c| hex(*c)),
            input.get(i + 2).and_then(|c| hex(*c)),
        ) {
            out.push(hi << 4 | lo);
            i += 3;
        } else {
            out.push(b'=');
            i += 1;
        }
    }
    out
}

fn hex(c: u8) -> Option<u8> {
    (c as char).to_digit(16).map(|d| d as u8)
}

pub fn encode_qp(input: &[u8]) -> Vec<u8> {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = Vec::with_capacity(input.len() + input.len() / 8);
    let mut col = 0;
    let mut i = 0;
    while i < input.len() {
        let b = input[i];
        if b == b'\n' || (b == b'\r' && input.get(i + 1) == Some(&b'\n')) {
            let len = if b == b'\r' { 2 } else { 1 };
            out.extend_from_slice(&input[i..i + len]);
            col = 0;
            i += len;
            continue;
        }
        let at_eol =
            matches!(input.get(i + 1), None | Some(b'\n')) || input[i + 1..].starts_with(b"\r\n");
        let literal = matches!(b, 33..=60 | 62..=126) || (matches!(b, b' ' | b'\t') && !at_eol);
        let width = if literal { 1 } else { 3 };
        if col + width > 75 {
            out.extend_from_slice(b"=\r\n");
            col = 0;
        }
        if literal {
            out.push(b);
        } else {
            out.extend_from_slice(&[b'=', HEX[(b >> 4) as usize], HEX[(b & 15) as usize]]);
        }
        col += width;
        i += 1;
    }
    out
}

pub fn decode_base64(input: &[u8]) -> Option<Vec<u8>> {
    let clean: Vec<u8> = input
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    STANDARD.decode(clean).ok()
}

/// 76-character lines separated by CRLF, no trailing line break.
pub fn encode_base64(input: &[u8]) -> Vec<u8> {
    let text = STANDARD.encode(input);
    let mut out = Vec::with_capacity(text.len() + text.len() / 38);
    for (n, line) in text.as_bytes().chunks(76).enumerate() {
        if n > 0 {
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(line);
    }
    out
}

pub fn longest_line(input: &[u8]) -> usize {
    input
        .split(|b| *b == b'\n')
        .map(|line| line.strip_suffix(b"\r").unwrap_or(line).len())
        .max()
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_qp_round_trips_long_lines_and_trailing_space() {
        let text = format!("caf\u{e9} = {} end \r\nline two\t\r\n", "x".repeat(200));
        let encoded = encode_qp(text.as_bytes());
        assert!(
            longest_line(&encoded) <= 76,
            "{}",
            String::from_utf8_lossy(&encoded)
        );
        assert!(encoded.is_ascii());
        assert_eq!(decode_qp(&encoded), text.as_bytes());
        assert_eq!(decode_qp(b"a=3Db=\r\nc= \r\nd=ZZ"), b"a=bcd=ZZ");
    }

    #[test]
    fn urls_base64_round_trips_with_folded_lines() {
        let data = vec![0xAB; 500];
        let encoded = encode_base64(&data);
        assert!(longest_line(&encoded) <= 76);
        assert_eq!(decode_base64(&encoded).unwrap(), data);
        assert!(decode_base64(b"!!!").is_none());
    }
}
