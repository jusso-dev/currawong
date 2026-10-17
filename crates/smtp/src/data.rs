//! Dot-unstuffing and message size enforcement for the DATA command.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineDecision {
    Continue,
    Done,
    TooLong,
    TooLarge,
    /// A CR or LF that is not part of a CRLF pair. Accepting these lets a
    /// client smuggle a second message past the next hop (SMTP smuggling).
    BareNewline,
}

/// Unstuff one SMTP data line (without its CRLF) and append it, with CRLF, to
/// `out`. `max_line` counts the CRLF, as RFC 5321 section 4.5.3.1 does.
pub fn push_data_line(
    line: &[u8],
    out: &mut Vec<u8>,
    max_line: usize,
    max_bytes: usize,
) -> LineDecision {
    match unstuff(line, out.len(), max_line, max_bytes) {
        Ok(Some(unstuffed)) => {
            out.extend_from_slice(unstuffed);
            out.extend_from_slice(b"\r\n");
            LineDecision::Continue
        }
        Ok(None) => LineDecision::Done,
        Err(decision) => decision,
    }
}

/// The unstuffed line, `None` at the terminating dot, or why it was refused.
/// `so_far` is the number of message bytes already kept.
pub fn unstuff(
    line: &[u8],
    so_far: usize,
    max_line: usize,
    max_bytes: usize,
) -> Result<Option<&[u8]>, LineDecision> {
    if line.len() + 2 > max_line {
        return Err(LineDecision::TooLong);
    }
    if line.contains(&b'\r') || line.contains(&b'\n') {
        return Err(LineDecision::BareNewline);
    }
    if line == b"." {
        return Ok(None);
    }
    let unstuffed = line.strip_prefix(b".").unwrap_or(line);
    if so_far.saturating_add(unstuffed.len() + 2) > max_bytes {
        return Err(LineDecision::TooLarge);
    }
    Ok(Some(unstuffed))
}

/// Feed a raw DATA payload, including the terminating dot line, for fuzzing.
pub fn decode_data(
    input: &[u8],
    max_line: usize,
    max_bytes: usize,
) -> Result<Vec<u8>, &'static str> {
    let mut out = Vec::new();
    let mut rest = input;
    while let Some(pos) = rest.windows(2).position(|w| w == b"\r\n") {
        let line = &rest[..pos];
        rest = &rest[pos + 2..];
        match push_data_line(line, &mut out, max_line, max_bytes) {
            LineDecision::Continue => {}
            LineDecision::Done => return Ok(out),
            LineDecision::TooLong => return Err("line"),
            LineDecision::TooLarge => return Err("size"),
            LineDecision::BareNewline => return Err("bare newline"),
        }
    }
    Err("truncated")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unstuffs_and_stops_at_dot() {
        let mut out = Vec::new();
        assert_eq!(
            push_data_line(b"..hidden", &mut out, 1000, 1000),
            LineDecision::Continue
        );
        assert_eq!(
            push_data_line(b".", &mut out, 1000, 1000),
            LineDecision::Done
        );
        assert_eq!(out, b".hidden\r\n");
    }

    #[test]
    fn rejects_oversize_before_the_message_is_kept() {
        let mut out = Vec::new();
        assert_eq!(
            push_data_line(b"abcd", &mut out, 1000, 3),
            LineDecision::TooLarge
        );
        assert!(out.is_empty());
    }

    #[test]
    fn line_limit_counts_the_crlf_and_bare_newlines_are_refused() {
        let mut out = Vec::new();
        assert_eq!(
            push_data_line(&[b'a'; 998], &mut out, 1000, 10_000),
            LineDecision::Continue
        );
        assert_eq!(
            push_data_line(&[b'a'; 999], &mut out, 1000, 10_000),
            LineDecision::TooLong
        );
        assert_eq!(
            push_data_line(b"a\rb", &mut out, 1000, 10_000),
            LineDecision::BareNewline
        );
        assert_eq!(
            decode_data(b"line1\n.\nMAIL FROM:<evil@x.test>\r\n.\r\n", 1000, 10_000),
            Err("bare newline")
        );
        assert_eq!(
            decode_data(b"caf\xc3\xa9 \xe9\xff\r\n.\r\n", 1000, 10_000).unwrap(),
            b"caf\xc3\xa9 \xe9\xff\r\n"
        );
    }
}
