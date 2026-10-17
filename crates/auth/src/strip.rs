//! Remove Authentication-Results headers that claim to be from us
//! (RFC 8601 section 5). The authserv-id is read with a small CFWS-aware
//! tokeniser so comments, odd whitespace and a trailing dot do not hide a
//! forgery.
pub fn strip_forged(raw: &[u8], authserv_id: &str) -> Vec<u8> {
    let id = normalise(authserv_id.as_bytes());
    let mut out = Vec::with_capacity(raw.len());
    let mut index = 0;
    while index < raw.len() {
        let line_end = next_line(raw, index);
        let line = &raw[index..line_end];
        if line == b"\r\n" || line == b"\n" {
            break;
        }
        // A field is its first line plus any lines starting with WSP.
        let mut end = line_end;
        while end < raw.len() && (raw[end] == b' ' || raw[end] == b'\t') {
            end = next_line(raw, end);
        }
        let field = &raw[index..end];
        if !claims_id(field, &id) {
            out.extend_from_slice(field);
        }
        index = end;
    }
    out.extend_from_slice(&raw[index..]);
    out
}

fn next_line(raw: &[u8], start: usize) -> usize {
    raw[start..]
        .iter()
        .position(|&byte| byte == b'\n')
        .map(|pos| start + pos + 1)
        .unwrap_or(raw.len())
}

fn claims_id(field: &[u8], id: &[u8]) -> bool {
    let Some(colon) = field.iter().position(|&byte| byte == b':') else {
        return false;
    };
    let name = field[..colon].trim_ascii_end();
    if !name.eq_ignore_ascii_case(b"authentication-results") {
        return false;
    }
    let value: Vec<u8> = field[colon + 1..]
        .iter()
        .copied()
        .filter(|&byte| byte != b'\r' && byte != b'\n')
        .collect();
    let found = authserv_id(&value);
    // Control bytes (FF, VT, NUL, DEL...) hide an id from us while other
    // parsers may skip them, so such a header is never trusted.
    found.iter().any(u8::is_ascii_control) || normalise(&found) == id
}

/// First token or quoted-string after optional CFWS.
fn authserv_id(value: &[u8]) -> Vec<u8> {
    let mut index = skip_cfws(value, 0);
    let mut out = Vec::new();
    if value.get(index) == Some(&b'"') {
        index += 1;
        while let Some(&byte) = value.get(index) {
            match byte {
                b'"' => break,
                b'\\' => {
                    if let Some(&next) = value.get(index + 1) {
                        out.push(next);
                    }
                    index += 2;
                }
                _ => {
                    out.push(byte);
                    index += 1;
                }
            }
        }
        return out;
    }
    while let Some(&byte) = value.get(index) {
        if byte == b';' || byte == b'(' || byte == b' ' || byte == b'\t' {
            break;
        }
        out.push(byte);
        index += 1;
    }
    out
}

fn skip_cfws(value: &[u8], mut index: usize) -> usize {
    let mut depth = 0usize;
    while let Some(&byte) = value.get(index) {
        match byte {
            b'(' => depth += 1,
            b')' if depth > 0 => depth -= 1,
            b'\\' if depth > 0 => index += 1,
            b' ' | b'\t' => {}
            _ if depth > 0 => {}
            _ => break,
        }
        index += 1;
    }
    index
}

fn normalise(id: &[u8]) -> Vec<u8> {
    let id = id.trim_ascii();
    let id = id.strip_suffix(b".").unwrap_or(id);
    id.to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::strip_forged;

    const ID: &str = "currawong.example.test";

    fn stripped(headers: &str) -> String {
        let raw = format!("From: a@example.test\r\n{headers}Subject: hi\r\n\r\nbody\r\n");
        String::from_utf8(strip_forged(raw.as_bytes(), ID)).unwrap()
    }

    #[test]
    fn removes_our_authserv_id_including_folded_headers() {
        let raw = b"From: a@example.test\r\nAuthentication-Results: currawong.example.test;\r\n\tdkim=pass\r\nAuthentication-Results: other.example;\r\n\tspf=pass\r\nSubject: hi\r\n\r\nbody\r\n";
        let stripped = strip_forged(raw, ID);
        let text = String::from_utf8(stripped).unwrap();
        assert!(!text.to_ascii_lowercase().contains("dkim=pass"));
        assert!(text.contains("other.example"));
        assert!(text.contains("body"));
    }

    #[test]
    fn evasions_from_the_review_are_removed() {
        for forged in [
            "Authentication-Results : currawong.example.test; dkim=pass\r\n",
            "Authentication-Results:\t(trust me) currawong.example.test; dkim=pass\r\n",
            "Authentication-Results: (a (nested) comment)currawong.example.test; dkim=pass\r\n",
            "Authentication-Results: currawong.example.test.; dkim=pass\r\n",
            "Authentication-Results: currawong.example.test\t; dkim=pass\r\n",
            "Authentication-Results: \"currawong.example.test\"; dkim=pass\r\n",
            "authentication-results: CURRAWONG.Example.Test; dkim=pass\r\n",
            "Authentication-Results:\r\n currawong.example.test;\r\n dkim=pass\r\n",
            "Authentication-Results: currawong.example.test(c); dkim=pass\r\n",
        ] {
            let text = stripped(forged);
            assert!(!text.contains("dkim=pass"), "kept {forged:?}: {text}");
            assert!(text.contains("Subject: hi"), "{text}");
        }
    }

    /// Re-review finding 6: FF and VT are not CFWS, and an authserv-id with
    /// control characters is never trusted downstream, so it is dropped.
    #[test]
    fn control_characters_in_the_authserv_id_are_dropped() {
        for forged in [
            "Authentication-Results: currawong.example.test\x0c; dkim=pass\r\n",
            "Authentication-Results: currawong.example.test\x0b; dkim=pass\r\n",
            "Authentication-Results: currawong\x00.example.test; dkim=pass\r\n",
            "Authentication-Results: \"currawong.example.test\x7f\"; dkim=pass\r\n",
        ] {
            let text = stripped(forged);
            assert!(!text.contains("dkim=pass"), "kept {forged:?}");
        }
        // Non-atom bytes are a different id, not ours: kept.
        assert!(
            stripped("Authentication-Results: currawong.example.test,x; dkim=pass\r\n")
                .contains("dkim=pass")
        );
    }

    #[test]
    fn other_ids_and_lookalikes_are_kept() {
        for kept in [
            "Authentication-Results: currawong.example.test.evil; dkim=pass\r\n",
            "Authentication-Results: mx.other.example; dkim=pass\r\n",
            "X-Authentication-Results: currawong.example.test; dkim=pass\r\n",
            "Authentication-Results: (currawong.example.test) other.example; dkim=pass\r\n",
        ] {
            assert!(stripped(kept).contains("dkim=pass"), "dropped {kept:?}");
        }
    }

    #[test]
    fn body_lines_are_never_treated_as_headers() {
        let raw = b"From: a@example.test\n\nAuthentication-Results: currawong.example.test; dkim=pass\r\n\r\nmore\r\n";
        let out = strip_forged(raw, ID);
        assert_eq!(out, raw.to_vec());
        let raw =
            b"From: a@example.test\r\n\r\nAuthentication-Results: currawong.example.test; x\n";
        assert_eq!(strip_forged(raw, ID), raw.to_vec());
    }

    #[test]
    fn bare_lf_headers_are_handled() {
        let raw = b"From: a@example.test\nAuthentication-Results: currawong.example.test; dkim=pass\nSubject: hi\n\nbody\n";
        let out = String::from_utf8(strip_forged(raw, ID)).unwrap();
        assert_eq!(out, "From: a@example.test\nSubject: hi\n\nbody\n");
    }
}
