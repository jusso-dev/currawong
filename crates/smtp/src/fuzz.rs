//! Panic-free entry points used by cargo-fuzz and the `cargo test` stand-in.
use crate::{
    auth_sasl::{self, SaslOutcome},
    command::parse_command,
    data::{unstuff, LineDecision},
};

const MAX_LINE: usize = 1000;
const MAX_BYTES: usize = 1024 * 1024;

fn cap(data: &[u8]) -> &[u8] {
    &data[..data.len().min(256 * 1024)]
}

pub fn command(data: &[u8]) {
    let end = data
        .iter()
        .position(|b| *b == b'\n')
        .unwrap_or(data.len())
        .min(4096);
    let _ = parse_command(&data[..end]);
}

/// The DATA phase as the session reads it: CRLF framing with the line limit
/// (a bare LF ends it), then `unstuff`, including the drain after a size
/// overflow.
pub fn data(data: &[u8]) {
    let mut rest = cap(data);
    let mut out = Vec::new();
    let mut too_large = false;
    while let Some(pos) = rest.iter().position(|b| *b == b'\n') {
        let Some(line) = rest[..pos].strip_suffix(b"\r") else {
            return;
        };
        rest = &rest[pos + 1..];
        match unstuff(line, out.len(), MAX_LINE, MAX_BYTES) {
            Ok(None) => return,
            Ok(Some(_)) | Err(LineDecision::TooLarge) if too_large => {}
            Ok(Some(chunk)) => {
                out.extend_from_slice(chunk);
                out.extend_from_slice(b"\r\n");
            }
            Err(LineDecision::TooLarge) => too_large = true,
            Err(_) => return,
        }
    }
}

/// AUTH: the first line is `MECHANISM [initial-response]`, later lines are
/// client responses.
pub fn sasl(data: &[u8]) {
    let text = String::from_utf8_lossy(cap(data));
    let mut lines = text.split('\n').map(|line| line.trim_end_matches('\r'));
    let first = lines.next().unwrap_or("");
    let (mechanism, initial) = match first.split_once(' ') {
        Some((mechanism, initial)) => (mechanism, Some(initial)),
        None => (first, None),
    };
    let (mut state, mut outcome) = auth_sasl::start(mechanism, initial, true);
    for line in lines.take(16) {
        if !matches!(outcome, SaslOutcome::Continue(_)) {
            return;
        }
        (state, outcome) = auth_sasl::next(state, line);
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn command_does_not_split_a_multibyte_character_at_the_cap() {
        let mut input = vec![b'a'; 4095];
        input.extend_from_slice("é".as_bytes());
        super::command(&input);
    }

    #[test]
    fn data_drains_after_an_oversized_message() {
        let mut input = Vec::new();
        for _ in 0..1100 {
            input.extend_from_slice(&[b'x'; 990]);
            input.extend_from_slice(b"\r\n");
        }
        input.extend_from_slice(b".\r\n");
        super::data(&input);
        super::data("\u{fffd}\r\n\u{0}\n.\n".as_bytes());
    }

    #[test]
    fn sasl_walks_the_login_exchange() {
        super::sasl(b"LOGIN\r\ndXNlcg==\r\ncGFzcw==\r\n");
        super::sasl(b"PLAIN AHVzZXIAcGFzcw==");
        super::sasl(b"PLAIN\n!!!");
    }
}
