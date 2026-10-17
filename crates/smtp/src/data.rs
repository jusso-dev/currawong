//! Dot-unstuffing and message size enforcement for the DATA command.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineDecision {
    Continue,
    Done,
    TooLong,
    TooLarge,
}

/// Push one SMTP data line (without its CRLF) into the reconstructed message.
pub fn push_data_line(
    line: &str,
    out: &mut Vec<u8>,
    max_line: usize,
    max_bytes: usize,
) -> LineDecision {
    let line = line.trim_end_matches('\r');
    if line.len() > max_line {
        return LineDecision::TooLong;
    }
    if line == "." {
        return LineDecision::Done;
    }
    let unstuffed = line.strip_prefix('.').unwrap_or(line);
    let extra = unstuffed.len() + 2;
    if out.len().saturating_add(extra) > max_bytes {
        return LineDecision::TooLarge;
    }
    if !out.is_empty() {
        // The previous line already ended with CRLF. Nothing to do.
    }
    out.extend_from_slice(unstuffed.as_bytes());
    out.extend_from_slice(b"\r\n");
    LineDecision::Continue
}

/// Feed a raw DATA payload, including the terminating dot line, for fuzzing.
pub fn decode_data(
    input: &[u8],
    max_line: usize,
    max_bytes: usize,
) -> Result<Vec<u8>, &'static str> {
    let mut out = Vec::new();
    let text = String::from_utf8_lossy(input);
    for line in text.split('\n') {
        match push_data_line(line, &mut out, max_line, max_bytes) {
            LineDecision::Continue => {}
            LineDecision::Done => return Ok(out),
            LineDecision::TooLong => return Err("line"),
            LineDecision::TooLarge => return Err("size"),
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
            push_data_line("..hidden", &mut out, 1000, 1000),
            LineDecision::Continue
        );
        assert_eq!(
            push_data_line(".", &mut out, 1000, 1000),
            LineDecision::Done
        );
        assert_eq!(out, b".hidden\r\n");
    }

    #[test]
    fn rejects_oversize_before_the_message_is_kept() {
        let mut out = Vec::new();
        assert_eq!(
            push_data_line("abcd", &mut out, 1000, 3),
            LineDecision::TooLarge
        );
        assert!(out.is_empty());
    }
}
