//! SMTP command parser. Verbs are case-insensitive. A syntax error is a 500.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Ehlo(String),
    Helo(String),
    Mail {
        address: String,
        params: Vec<(String, String)>,
    },
    Rcpt {
        address: String,
        params: Vec<(String, String)>,
    },
    Data,
    Rset,
    Noop,
    Quit,
    StartTls,
    Auth {
        mechanism: String,
        initial: Option<String>,
    },
    /// Continuation line during AUTH LOGIN or AUTH PLAIN.
    AuthLine(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplyCode;

/// RFC 5321 section 4.5.3.1 size limits, in octets.
const MAX_LOCAL_PART: usize = 64;
const MAX_DOMAIN: usize = 255;
const MAX_PATH: usize = 256;

/// Parse one command line without its CRLF. Lines must be UTF-8 (SMTPUTF8)
/// and must not carry control characters.
pub fn parse_command(line: &[u8]) -> Result<Command, ReplyCode> {
    let line = std::str::from_utf8(line).map_err(|_| ReplyCode)?;
    if line.chars().any(|c| c.is_control() && c != '\t') {
        return Err(ReplyCode);
    }
    let line = line.trim();
    if line.is_empty() {
        return Err(ReplyCode);
    }
    let (verb, rest) = split_verb(line);
    let verb_up = verb.to_ascii_uppercase();
    match verb_up.as_str() {
        "EHLO" => Ok(Command::Ehlo(rest.unwrap_or_default().to_string())),
        "HELO" => Ok(Command::Helo(rest.unwrap_or_default().to_string())),
        "MAIL" => {
            let rest = rest.ok_or(ReplyCode)?;
            let (address, params) = parse_path(rest, "FROM:")?;
            let address = if address.is_empty() || address.eq_ignore_ascii_case("postmaster") {
                address
            } else {
                mailbox(&address)?
            };
            Ok(Command::Mail { address, params })
        }
        "RCPT" => {
            let rest = rest.ok_or(ReplyCode)?;
            let (address, params) = parse_path(rest, "TO:")?;
            let address = if address.eq_ignore_ascii_case("postmaster") {
                address
            } else {
                mailbox(&address)?
            };
            Ok(Command::Rcpt { address, params })
        }
        "DATA" if rest.is_none() => Ok(Command::Data),
        "RSET" if rest.is_none() => Ok(Command::Rset),
        "NOOP" => Ok(Command::Noop),
        "QUIT" if rest.is_none() => Ok(Command::Quit),
        "STARTTLS" if rest.is_none() => Ok(Command::StartTls),
        "AUTH" => {
            let rest = rest.ok_or(ReplyCode)?;
            let mut parts = rest.splitn(2, char::is_whitespace);
            let mechanism = parts.next().unwrap_or("").trim().to_ascii_uppercase();
            if mechanism.is_empty() {
                return Err(ReplyCode);
            }
            let initial = parts
                .next()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string);
            Ok(Command::Auth { mechanism, initial })
        }
        _ => Err(ReplyCode),
    }
}

fn split_verb(line: &str) -> (&str, Option<&str>) {
    match line.split_once(char::is_whitespace) {
        Some((verb, rest)) => (verb, Some(rest.trim())),
        None => (line, None),
    }
}

/// `FROM:<path> params` or `TO:<path> params`. Nothing but optional spaces may
/// sit between the colon and `<`, and parameters follow `>` after a space.
/// Spaces and `>` are only allowed inside a quoted local part.
fn parse_path(rest: &str, keyword: &str) -> Result<(String, Vec<(String, String)>), ReplyCode> {
    let head = rest.get(..keyword.len()).ok_or(ReplyCode)?;
    if !head.eq_ignore_ascii_case(keyword) {
        return Err(ReplyCode);
    }
    let after = rest[keyword.len()..].trim_start_matches(' ');
    let inner = after.strip_prefix('<').ok_or(ReplyCode)?;
    let mut quoted = false;
    let mut escaped = false;
    let mut end = None;
    for (at, c) in inner.char_indices() {
        if c == '\t' {
            return Err(ReplyCode);
        }
        if escaped {
            escaped = false;
        } else if quoted {
            match c {
                '\\' => escaped = true,
                '"' => quoted = false,
                _ => {}
            }
        } else {
            match c {
                '"' => quoted = true,
                '>' => {
                    end = Some(at);
                    break;
                }
                '<' | ' ' => return Err(ReplyCode),
                _ => {}
            }
        }
    }
    let end = end.ok_or(ReplyCode)?;
    let path = &inner[..end];
    let param_src = &inner[end + 1..];
    if !param_src.is_empty() && !param_src.starts_with(' ') {
        return Err(ReplyCode);
    }
    if path.len() > MAX_PATH {
        return Err(ReplyCode);
    }
    Ok((path.to_string(), parse_params(param_src)?))
}

fn parse_params(src: &str) -> Result<Vec<(String, String)>, ReplyCode> {
    let mut out = Vec::new();
    for token in src.split_whitespace() {
        let (key, value) = token.split_once('=').unwrap_or((token, ""));
        if key.is_empty() || !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
            return Err(ReplyCode);
        }
        out.push((key.to_ascii_uppercase(), value.to_string()));
    }
    Ok(out)
}

/// `local-part@domain` with RFC 5321 lengths, returned with any trailing
/// dot on the domain removed. Source routes are refused.
fn mailbox(address: &str) -> Result<String, ReplyCode> {
    let (local, domain) = address.rsplit_once('@').ok_or(ReplyCode)?;
    if local.is_empty() || local.len() > MAX_LOCAL_PART {
        return Err(ReplyCode);
    }
    if let Some(body) = local.strip_prefix('"') {
        quoted_local(body)?;
    } else if local
        .chars()
        .any(|c| "()<>[]\\,;:@\" ".contains(c) || c.is_control())
    {
        return Err(ReplyCode);
    }
    let domain = domain.strip_suffix('.').unwrap_or(domain);
    if domain.is_empty() || domain.len() > MAX_DOMAIN {
        return Err(ReplyCode);
    }
    if let Some(literal) = domain.strip_prefix('[') {
        let literal = literal.strip_suffix(']').ok_or(ReplyCode)?;
        let valid = match literal.get(..5) {
            Some(tag) if tag.eq_ignore_ascii_case("IPv6:") => {
                literal[5..].parse::<std::net::Ipv6Addr>().is_ok()
            }
            _ => literal.parse::<std::net::Ipv4Addr>().is_ok(),
        };
        if !valid {
            return Err(ReplyCode);
        }
    } else {
        for label in domain.split('.') {
            if label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || !c.is_ascii())
            {
                return Err(ReplyCode);
            }
        }
    }
    Ok(format!("{local}@{domain}"))
}

/// The rest of a quoted local part after its opening quote: printable text
/// and backslash pairs, then exactly one closing quote.
fn quoted_local(body: &str) -> Result<(), ReplyCode> {
    let mut chars = body.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                chars.next().ok_or(ReplyCode)?;
            }
            '"' => {
                return if chars.next().is_none() {
                    Ok(())
                } else {
                    Err(ReplyCode)
                };
            }
            c if c.is_control() => return Err(ReplyCode),
            _ => {}
        }
    }
    Err(ReplyCode)
}

pub fn domain_of(address: &str) -> Option<&str> {
    let address = address.trim().trim_start_matches('<').trim_end_matches('>');
    address.rsplit_once('@').map(|(_, domain)| domain.trim())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_mail_and_rcpt() {
        let cmd = parse_command(b"mail from:<a@example.test> SIZE=100").unwrap();
        match cmd {
            Command::Mail { address, params } => {
                assert_eq!(address, "a@example.test");
                assert_eq!(params, vec![("SIZE".into(), "100".into())]);
            }
            other => panic!("unexpected {other:?}"),
        }
        assert!(parse_command(b"RCPT TO:<>").is_err());
        let rcpt = parse_command(b"RCPT TO:<b@example.test>").unwrap();
        assert!(matches!(rcpt, Command::Rcpt { .. }));
        assert!(matches!(
            parse_command(b"MAIL FROM:<>").unwrap(),
            Command::Mail { address, .. } if address.is_empty()
        ));
        assert!(matches!(
            parse_command(b"RCPT TO:<Postmaster>").unwrap(),
            Command::Rcpt { address, .. } if address == "Postmaster"
        ));
        assert!(parse_command(b"MAIL FROM: <a@example.test>").is_ok());
        assert!(parse_command("MAIL FROM:<j\u{f6}rg@b\u{fc}cher.test>".as_bytes()).is_ok());
        assert!(parse_command(b"MAIL FROM:<\"odd,local\"@example.test>").is_ok());
        assert!(parse_command(b"RCPT TO:<a@[192.0.2.1]>").is_ok());
    }

    fn path(line: &str) -> Option<String> {
        match parse_command(line.as_bytes()) {
            Ok(Command::Rcpt { address, .. }) | Ok(Command::Mail { address, .. }) => Some(address),
            _ => None,
        }
    }

    #[test]
    fn accepts_the_valid_forms_rfc_5321_allows() {
        let cases = [
            (
                "RCPT TO:<a@mail_relay.example.test>",
                "a@mail_relay.example.test",
            ),
            (
                r#"RCPT TO:<"john smith"@example.test>"#,
                r#""john smith"@example.test"#,
            ),
            (
                r#"RCPT TO:<"a\"b\\c"@example.test>"#,
                r#""a\"b\\c"@example.test"#,
            ),
            (
                r#"RCPT TO:<"odd>local"@example.test>"#,
                r#""odd>local"@example.test"#,
            ),
            ("MAIL FROM:<postmaster>", "postmaster"),
            ("MAIL FROM:<a@example.test.>", "a@example.test"),
            ("RCPT TO:<a@[IPv6:2001:db8::1]>", "a@[IPv6:2001:db8::1]"),
        ];
        for (line, want) in cases {
            assert_eq!(path(line).as_deref(), Some(want), "{line}");
        }
    }

    #[test]
    fn rejects_junk_literals_and_broken_quotes() {
        for line in [
            "RCPT TO:<a@[foo]>",
            "RCPT TO:<a@[300.1.1.1]>",
            "RCPT TO:<a@[IPv6:zz::1]>",
            "RCPT TO:<a@[]>",
            r#"RCPT TO:<"unterminated@example.test>"#,
            r#"RCPT TO:<"a"b"@example.test>"#,
            "RCPT TO:<a b@example.test>",
            "RCPT TO:<a@example.test..>",
            "MAIL FROM:<postmaster@>",
        ] {
            assert!(path(line).is_none(), "accepted {line}");
        }
    }

    #[test]
    fn rejects_injection_and_malformed_paths() {
        let bad: &[&[u8]] = &[
            b"RCPT TO:<a@b.test\rQUIT\r>",
            b"RCPT TO:<a@b.test\0>",
            b"RCPT TO:<a b@b.test>",
            b"RCPT TO:junk<a@b.test>",
            b"MAIL FROM:junk <a@b.test>",
            b"MAIL FROM:<a@b.test>SIZE=1",
            b"RCPT TO:<a@b.test> X\x01=1",
            b"RCPT TO:<@relay.test:a@b.test>",
            b"RCPT TO:<nobody>",
            b"RCPT TO:<a@>",
            b"RCPT TO:<a@-bad.test>",
            b"RCPT TO:<a@b..test>",
            b"RCPT TO:<a<b@c.test>",
            b"MAIL FROM:<a@b.test",
            b"MAIL FROM:<\xff@b.test>",
            b"NOOP \x1b[2J",
        ];
        for line in bad {
            assert!(
                parse_command(line).is_err(),
                "accepted {:?}",
                String::from_utf8_lossy(line)
            );
        }
        let long_local = format!("RCPT TO:<{}@b.test>", "a".repeat(65));
        assert!(parse_command(long_local.as_bytes()).is_err());
        let ok_local = format!("RCPT TO:<{}@b.test>", "a".repeat(64));
        assert!(parse_command(ok_local.as_bytes()).is_ok());
        let label = "d".repeat(63);
        let long_domain = format!("RCPT TO:<a@{label}.{label}.{label}.{label}.test>");
        assert!(parse_command(long_domain.as_bytes()).is_err());
    }
}
