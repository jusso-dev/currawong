//! Remove Authentication-Results headers that claim to be from us.
pub fn strip_forged(raw: &[u8], authserv_id: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len());
    let mut index = 0;
    let id = authserv_id.to_ascii_lowercase();
    while index < raw.len() {
        if raw[index..].starts_with(b"\r\n\r\n") || raw[index..].starts_with(b"\n\n") {
            out.extend_from_slice(&raw[index..]);
            break;
        }
        let (header, next) = read_header(raw, index);
        if is_forged_auth_results(header, &id) {
            index = next;
            continue;
        }
        out.extend_from_slice(header);
        index = next;
    }
    out
}

fn read_header(raw: &[u8], start: usize) -> (&[u8], usize) {
    let mut end = start;
    while end < raw.len() {
        if raw[end] == b'\n' {
            let next = end + 1;
            if next >= raw.len() || (raw[next] != b' ' && raw[next] != b'\t') {
                return (&raw[start..next], next);
            }
        }
        end += 1;
    }
    (&raw[start..], raw.len())
}

fn is_forged_auth_results(header: &[u8], authserv_id: &str) -> bool {
    let unfolded = unfold(header);
    let lower = unfolded.to_ascii_lowercase();
    let Some(rest) = lower.strip_prefix("authentication-results:") else {
        return false;
    };
    let value = rest.trim();
    value == authserv_id
        || value.starts_with(&format!("{authserv_id};"))
        || value.starts_with(&format!("{authserv_id} "))
}

fn unfold(header: &[u8]) -> String {
    let text = String::from_utf8_lossy(header);
    let mut out = String::new();
    for (i, line) in text.lines().enumerate() {
        if i == 0 {
            out.push_str(line.trim_end_matches('\r'));
        } else {
            out.push(' ');
            out.push_str(line.trim());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::strip_forged;

    #[test]
    fn removes_our_authserv_id_including_folded_headers() {
        let raw = b"From: a@example.test\r\nAuthentication-Results: currawong.example.test;\r\n\tdkim=pass\r\nAuthentication-Results: other.example;\r\n\tspf=pass\r\nSubject: hi\r\n\r\nbody\r\n";
        let stripped = strip_forged(raw, "currawong.example.test");
        let text = String::from_utf8(stripped).unwrap();
        assert!(!text.to_ascii_lowercase().contains("dkim=pass"));
        assert!(text.contains("other.example"));
        assert!(text.contains("body"));
    }
}
