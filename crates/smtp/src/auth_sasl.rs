//! RFC 4954 AUTH PLAIN and AUTH LOGIN. Clear-text authentication is refused.
use base64::{engine::general_purpose, Engine};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SaslOutcome {
    Continue(String),
    Done { username: String, password: String },
    Failure(&'static str),
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum SaslState {
    #[default]
    Idle,
    LoginUser,
    LoginPassword {
        username: String,
    },
    PlainChallenge,
}

pub fn start(mechanism: &str, initial: Option<&str>, tls: bool) -> (SaslState, SaslOutcome) {
    if !tls {
        return (
            SaslState::Idle,
            SaslOutcome::Failure(
                "538 5.7.11 encryption required for requested authentication mechanism",
            ),
        );
    }
    match mechanism {
        "PLAIN" => match initial {
            Some(initial) => (SaslState::Idle, decode_plain(initial)),
            None => (
                SaslState::PlainChallenge,
                SaslOutcome::Continue("334 ".into()),
            ),
        },
        "LOGIN" => (
            SaslState::LoginUser,
            SaslOutcome::Continue("334 VXNlcm5hbWU6".into()),
        ),
        _ => (
            SaslState::Idle,
            SaslOutcome::Failure("504 5.5.4 unsupported authentication mechanism"),
        ),
    }
}

pub fn next(state: SaslState, line: &str) -> (SaslState, SaslOutcome) {
    match state {
        SaslState::PlainChallenge => (SaslState::Idle, decode_plain(line)),
        SaslState::LoginUser => match b64(line) {
            Some(username) => (
                SaslState::LoginPassword { username },
                SaslOutcome::Continue("334 UGFzc3dvcmQ6".into()),
            ),
            None => (
                SaslState::Idle,
                SaslOutcome::Failure("501 5.5.2 invalid base64"),
            ),
        },
        SaslState::LoginPassword { username } => match b64(line) {
            Some(password) => (SaslState::Idle, SaslOutcome::Done { username, password }),
            None => (
                SaslState::Idle,
                SaslOutcome::Failure("501 5.5.2 invalid base64"),
            ),
        },
        SaslState::Idle => (
            SaslState::Idle,
            SaslOutcome::Failure("503 5.5.1 not in AUTH"),
        ),
    }
}

fn decode_plain(encoded: &str) -> SaslOutcome {
    let Some(bytes) = b64_raw(encoded) else {
        return SaslOutcome::Failure("501 5.5.2 invalid base64");
    };
    let mut parts = bytes.split(|b| *b == 0);
    let _authz = parts.next();
    let Some(user) = parts.next() else {
        return SaslOutcome::Failure("501 5.5.2 malformed AUTH PLAIN");
    };
    let Some(pass) = parts.next() else {
        return SaslOutcome::Failure("501 5.5.2 malformed AUTH PLAIN");
    };
    match (
        String::from_utf8(user.to_vec()),
        String::from_utf8(pass.to_vec()),
    ) {
        (Ok(username), Ok(password)) if !username.is_empty() => {
            SaslOutcome::Done { username, password }
        }
        _ => SaslOutcome::Failure("501 5.5.2 malformed AUTH PLAIN"),
    }
}

fn b64(encoded: &str) -> Option<String> {
    let bytes = b64_raw(encoded)?;
    String::from_utf8(bytes).ok()
}

fn b64_raw(encoded: &str) -> Option<Vec<u8>> {
    let encoded = encoded.trim();
    general_purpose::STANDARD
        .decode(encoded)
        .or_else(|_| general_purpose::STANDARD_NO_PAD.decode(encoded))
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;

    #[test]
    fn plaintext_auth_is_refused() {
        let (_, outcome) = start("PLAIN", Some("abc"), false);
        assert!(matches!(outcome, SaslOutcome::Failure(msg) if msg.starts_with("538")));
    }

    #[test]
    fn plain_decodes_user_and_password() {
        let token = STANDARD.encode(b"\0ada@example.test\0secret");
        let (_, outcome) = start("PLAIN", Some(&token), true);
        match outcome {
            SaslOutcome::Done { username, password } => {
                assert_eq!(username, "ada@example.test");
                assert_eq!(password, "secret");
            }
            other => panic!("unexpected {other:?}"),
        }
    }
}
