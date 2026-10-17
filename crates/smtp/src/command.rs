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

pub fn parse_command(line: &str) -> Result<Command, ReplyCode> {
    let line = line.trim_end_matches(['\r', '\n']).trim();
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
            let (address, params) = parse_reverse_path(rest, "FROM:")?;
            Ok(Command::Mail { address, params })
        }
        "RCPT" => {
            let rest = rest.ok_or(ReplyCode)?;
            let (address, params) = parse_reverse_path(rest, "TO:")?;
            if address.is_empty() {
                return Err(ReplyCode);
            }
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

fn parse_reverse_path(
    rest: &str,
    keyword: &str,
) -> Result<(String, Vec<(String, String)>), ReplyCode> {
    let rest = rest.trim();
    if !rest.to_ascii_uppercase().starts_with(keyword) {
        return Err(ReplyCode);
    }
    let after = rest[keyword.len()..].trim();
    let (path, param_src) = if let Some(start) = after.find('<') {
        let end = after.find('>').ok_or(ReplyCode)?;
        if end < start {
            return Err(ReplyCode);
        }
        (&after[start + 1..end], after.get(end + 1..).unwrap_or(""))
    } else {
        return Err(ReplyCode);
    };
    Ok((path.trim().to_string(), parse_params(param_src)))
}

fn parse_params(src: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for token in src.split_whitespace() {
        if let Some((key, value)) = token.split_once('=') {
            out.push((key.to_ascii_uppercase(), value.to_string()));
        } else if !token.is_empty() {
            out.push((token.to_ascii_uppercase(), String::new()));
        }
    }
    out
}

pub fn domain_of(address: &str) -> Option<&str> {
    let address = address.trim().trim_start_matches('<').trim_end_matches('>');
    address.split_once('@').map(|(_, domain)| domain.trim())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_mail_and_rcpt() {
        let cmd = parse_command("mail from:<a@example.test> SIZE=100").unwrap();
        match cmd {
            Command::Mail { address, params } => {
                assert_eq!(address, "a@example.test");
                assert_eq!(params, vec![("SIZE".into(), "100".into())]);
            }
            other => panic!("unexpected {other:?}"),
        }
        let rcpt = parse_command("RCPT TO:<>").unwrap_err();
        let _ = rcpt;
        let rcpt = parse_command("RCPT TO:<b@example.test>").unwrap();
        assert!(matches!(rcpt, Command::Rcpt { .. }));
    }
}
