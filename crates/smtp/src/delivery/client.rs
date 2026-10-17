//! Outbound SMTP client. One transaction per connection, every step bounded
//! in time and size, results kept per recipient.
use super::DeliveryOutcome;
use crate::delivery::is_null_sender;
use mail_auth::report::tlsrpt::ResultType;
use rustls::{pki_types::ServerName, CertificateError, ClientConfig};
use std::{future::Future, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    net::TcpStream,
    time::timeout,
};
use tokio_rustls::TlsConnector;

/// RFC 5321 section 4.5.3.2 timeouts, connect excepted.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
pub const COMMAND_TIMEOUT: Duration = Duration::from_secs(5 * 60);
pub const DATA_END_TIMEOUT: Duration = Duration::from_secs(10 * 60);
/// Upper bound on one whole session, however many recipients it carries.
pub const SESSION_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const MAX_REPLY_LINE: usize = 2048;
const MAX_REPLY_LINES: usize = 64;
const MAX_REPLY_TEXT: usize = 1024;

/// The host could not take the transaction; the next host may be tried.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostFailure {
    pub detail: String,
    pub permanent: bool,
    /// Set when TLS could not be negotiated or authenticated.
    pub tls: Option<ResultType>,
}

impl HostFailure {
    pub fn temp(detail: impl Into<String>) -> Self {
        Self {
            detail: detail.into(),
            permanent: false,
            tls: None,
        }
    }

    fn tls(starttls: &Starttls, result: ResultType, reason: &str) -> Self {
        Self {
            detail: format!(
                "4.7.5 {} requires TLS with {}: {reason}",
                starttls.policy,
                starttls.server_name.to_str()
            ),
            permanent: false,
            tls: Some(result),
        }
    }
}

/// STARTTLS for one session. Certificates are always verified by `config`.
pub struct Starttls {
    pub config: Arc<ClientConfig>,
    pub server_name: ServerName<'static>,
    /// Without TLS the session fails. When false, a server that does not
    /// offer STARTTLS gets the message in clear text.
    pub required: bool,
    /// Named in failure details, for example "MTA-STS policy for example.test".
    pub policy: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    pub code: u16,
    pub text: String,
    pub lines: Vec<String>,
}

impl Reply {
    pub fn detail(&self) -> String {
        format!("{} {}", self.code, self.text)
    }

    fn outcome(&self) -> DeliveryOutcome {
        classify(self)
    }
}

pub fn classify(reply: &Reply) -> DeliveryOutcome {
    match reply.code {
        200..=299 => DeliveryOutcome::Delivered,
        400..=499 => DeliveryOutcome::TempFail(reply.detail()),
        _ => DeliveryOutcome::PermFail(reply.detail()),
    }
}

/// Message to send: envelope sender, recipients and the bytes on the wire.
pub struct Transaction<'a> {
    pub helo: &'a str,
    pub mail_from: &'a str,
    pub rcpts: &'a [String],
    /// Our `Received` header, in the form for a TLS session and the form
    /// that records the next hop got the message in clear text.
    pub received_tls: &'a [u8],
    pub received_clear: &'a [u8],
    pub message: &'a [u8],
}

pub async fn connect(addr: SocketAddr) -> Result<TcpStream, HostFailure> {
    let stream = bounded(CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .map_err(|err| HostFailure::temp(format!("4.4.1 connect {addr}: {err}")))?;
    let _ = stream.set_nodelay(true);
    Ok(stream)
}

/// Run one transaction. Per-recipient results are returned once MAIL FROM is
/// accepted; anything earlier is a host failure.
pub async fn send<S>(
    stream: S,
    tx: &Transaction<'_>,
    tls: Option<&Starttls>,
) -> Result<Vec<(String, DeliveryOutcome)>, HostFailure>
where
    S: tokio::io::AsyncRead + AsyncWrite + Unpin + Send,
{
    match timeout(SESSION_TIMEOUT, send_inner(BufReader::new(stream), tx, tls)).await {
        Ok(result) => result,
        Err(_) => Err(HostFailure::temp("4.4.2 session timed out")),
    }
}

async fn send_inner<S>(
    mut conn: BufReader<S>,
    tx: &Transaction<'_>,
    tls: Option<&Starttls>,
) -> Result<Vec<(String, DeliveryOutcome)>, HostFailure>
where
    S: tokio::io::AsyncRead + AsyncWrite + Unpin + Send,
{
    let greeting = read_reply_timed(&mut conn, COMMAND_TIMEOUT).await?;
    expect_2xx(&greeting, "greeting")?;
    let ehlo = command(&mut conn, &format!("EHLO {}\r\n", tx.helo)).await?;
    expect_2xx(&ehlo, "EHLO")?;
    let Some(starttls) = tls else {
        return finish(conn, tx, false).await;
    };
    if !offers(&ehlo, "STARTTLS") {
        if starttls.required {
            return Err(HostFailure::tls(
                starttls,
                ResultType::StartTlsNotSupported,
                "STARTTLS not offered",
            ));
        }
        cleartext_fallback(starttls, "starttls_not_offered", "STARTTLS not offered");
        return finish(conn, tx, false).await;
    }
    let reply = command(&mut conn, "STARTTLS\r\n").await?;
    if reply.code != 220 {
        let reason = format!("STARTTLS refused: {}", reply.detail());
        if starttls.required {
            return Err(HostFailure::tls(
                starttls,
                ResultType::StartTlsNotSupported,
                &reason,
            ));
        }
        cleartext_fallback(starttls, "starttls_refused", &reason);
        return finish(conn, tx, false).await;
    }
    // Bytes already buffered arrived before TLS; reading them as if they
    // came over TLS is the classic STARTTLS injection.
    if !conn.buffer().is_empty() {
        return Err(HostFailure::tls(
            starttls,
            ResultType::ValidationFailure,
            "data arrived before the TLS handshake",
        ));
    }
    let connector = TlsConnector::from(Arc::clone(&starttls.config));
    let handshake = connector.connect(starttls.server_name.clone(), conn.into_inner());
    let stream = match timeout(COMMAND_TIMEOUT, handshake).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(err)) => {
            let (result, reason) = handshake_failure(&err);
            return Err(HostFailure::tls(starttls, result, &reason));
        }
        Err(_) => {
            return Err(HostFailure::tls(
                starttls,
                ResultType::ValidationFailure,
                "TLS handshake timed out",
            ))
        }
    };
    let mut conn = BufReader::new(stream);
    let ehlo = command(&mut conn, &format!("EHLO {}\r\n", tx.helo)).await?;
    expect_2xx(&ehlo, "EHLO after STARTTLS")?;
    finish(conn, tx, true).await
}

/// Every message that leaves without TLS is logged and counted.
pub fn cleartext_fallback(starttls: &Starttls, reason: &'static str, detail: &str) {
    tracing::warn!(host = %starttls.server_name.to_str(), %reason, %detail, "delivering without TLS");
    metrics::counter!("currawong_delivery_tls_fallback_total", "reason" => reason).increment(1);
}

fn offers(ehlo: &Reply, keyword: &str) -> bool {
    ehlo.lines.iter().skip(1).any(|line| {
        line.split_whitespace()
            .next()
            .is_some_and(|word| word.eq_ignore_ascii_case(keyword))
    })
}

/// RFC 8460 result type and a readable reason for a failed handshake.
fn handshake_failure(err: &std::io::Error) -> (ResultType, String) {
    let result = match err
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<rustls::Error>())
    {
        Some(rustls::Error::InvalidCertificate(cert)) => match cert {
            CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. } => {
                ResultType::CertificateHostMismatch
            }
            CertificateError::Expired
            | CertificateError::ExpiredContext { .. }
            | CertificateError::NotValidYet
            | CertificateError::NotValidYetContext { .. } => ResultType::CertificateExpired,
            _ => ResultType::CertificateNotTrusted,
        },
        _ => ResultType::ValidationFailure,
    };
    (result, sanitise(&err.to_string()))
}

/// MAIL, RCPT, DATA and QUIT on an established, greeted session.
pub(crate) async fn finish<S>(
    mut conn: BufReader<S>,
    tx: &Transaction<'_>,
    tls: bool,
) -> Result<Vec<(String, DeliveryOutcome)>, HostFailure>
where
    S: tokio::io::AsyncRead + AsyncWrite + Unpin + Send,
{
    let from = if is_null_sender(tx.mail_from) {
        "<>".to_string()
    } else if valid_path(tx.mail_from) {
        format!("<{}>", tx.mail_from)
    } else {
        let detail = "550 5.1.7 bad sender address syntax".to_string();
        return Ok(all(tx.rcpts, DeliveryOutcome::PermFail(detail)));
    };
    let mail = command(&mut conn, &format!("MAIL FROM:{from}\r\n")).await?;
    if mail.code >= 300 {
        quit(&mut conn).await;
        return Ok(all(tx.rcpts, mail.outcome()));
    }
    let mut results = Vec::with_capacity(tx.rcpts.len());
    let mut accepted = Vec::new();
    for rcpt in tx.rcpts {
        if !valid_path(rcpt) {
            let detail = "550 5.1.3 bad recipient address syntax".to_string();
            results.push((rcpt.clone(), DeliveryOutcome::PermFail(detail)));
            continue;
        }
        let reply = command(&mut conn, &format!("RCPT TO:<{rcpt}>\r\n")).await?;
        if reply.code < 300 {
            accepted.push(results.len());
            results.push((rcpt.clone(), DeliveryOutcome::Delivered));
        } else {
            results.push((rcpt.clone(), reply.outcome()));
        }
    }
    if accepted.is_empty() {
        quit(&mut conn).await;
        return Ok(results);
    }
    let data = command(&mut conn, "DATA\r\n").await?;
    let end = if data.code == 354 {
        let received = if tls {
            tx.received_tls
        } else {
            tx.received_clear
        };
        let mut wire = dot_stuff(&[received, tx.message].concat());
        wire.extend_from_slice(b".\r\n");
        write_timed(&mut conn, &wire, DATA_END_TIMEOUT).await?;
        read_reply_timed(&mut conn, DATA_END_TIMEOUT).await?
    } else if data.code < 400 {
        // Nothing was sent, so a stray 2xx must not count as delivery.
        Reply {
            code: 451,
            text: format!("4.5.0 unexpected reply to DATA: {}", data.detail()),
            lines: Vec::new(),
        }
    } else {
        data
    };
    for index in accepted {
        results[index].1 = end.outcome();
    }
    quit(&mut conn).await;
    Ok(results)
}

fn all(rcpts: &[String], outcome: DeliveryOutcome) -> Vec<(String, DeliveryOutcome)> {
    rcpts
        .iter()
        .map(|rcpt| (rcpt.clone(), outcome.clone()))
        .collect()
}

fn expect_2xx(reply: &Reply, stage: &str) -> Result<(), HostFailure> {
    if (200..300).contains(&reply.code) {
        Ok(())
    } else {
        Err(HostFailure {
            detail: format!("{} (at {stage})", reply.detail()),
            permanent: reply.code >= 500,
            tls: None,
        })
    }
}

pub(crate) async fn command<S>(conn: &mut BufReader<S>, line: &str) -> Result<Reply, HostFailure>
where
    S: tokio::io::AsyncRead + AsyncWrite + Unpin + Send,
{
    write_timed(conn, line.as_bytes(), COMMAND_TIMEOUT).await?;
    read_reply_timed(conn, COMMAND_TIMEOUT).await
}

async fn quit<S>(conn: &mut BufReader<S>)
where
    S: tokio::io::AsyncRead + AsyncWrite + Unpin + Send,
{
    let short = Duration::from_secs(5);
    if write_timed(conn, b"QUIT\r\n", short).await.is_ok() {
        let _ = read_reply_timed(conn, short).await;
    }
}

async fn write_timed<S>(
    conn: &mut BufReader<S>,
    bytes: &[u8],
    limit: Duration,
) -> Result<(), HostFailure>
where
    S: tokio::io::AsyncRead + AsyncWrite + Unpin + Send,
{
    let write = async {
        conn.get_mut().write_all(bytes).await?;
        conn.get_mut().flush().await
    };
    bounded(limit, write)
        .await
        .map_err(|err| HostFailure::temp(format!("4.4.2 write: {err}")))
}

pub(crate) async fn read_reply_timed<R>(read: &mut R, limit: Duration) -> Result<Reply, HostFailure>
where
    R: AsyncBufRead + Unpin + Send,
{
    match timeout(limit, read_reply(read)).await {
        Ok(result) => result.map_err(|err| HostFailure::temp(format!("4.4.2 {err}"))),
        Err(_) => Err(HostFailure::temp("4.4.2 timed out waiting for reply")),
    }
}

async fn bounded<T>(
    limit: Duration,
    fut: impl Future<Output = std::io::Result<T>>,
) -> std::io::Result<T> {
    match timeout(limit, fut).await {
        Ok(result) => result,
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "timed out",
        )),
    }
}

/// Read one possibly multi-line reply. Bytes, not `str`, so a non-ASCII
/// reply cannot panic, and each line and the whole reply are capped.
pub async fn read_reply<R>(read: &mut R) -> Result<Reply, String>
where
    R: AsyncBufRead + Unpin + Send,
{
    let mut text = String::new();
    let mut lines = Vec::new();
    let mut first = None;
    for _ in 0..MAX_REPLY_LINES {
        let mut line = Vec::new();
        let n = (&mut *read)
            .take(MAX_REPLY_LINE as u64)
            .read_until(b'\n', &mut line)
            .await
            .map_err(|err| format!("read: {err}"))?;
        if n == 0 {
            return Err("connection closed".into());
        }
        if !line.ends_with(b"\n") {
            return Err("reply line too long or truncated".into());
        }
        while matches!(line.last(), Some(b'\n' | b'\r')) {
            line.pop();
        }
        let code = parse_code(&line)?;
        if *first.get_or_insert(code) != code {
            return Err("reply lines disagree on the code".into());
        }
        let rest = sanitise(&String::from_utf8_lossy(line.get(4..).unwrap_or_default()));
        if !rest.is_empty() && text.len() < MAX_REPLY_TEXT {
            if !text.is_empty() {
                text.push(' ');
            }
            // Cut on a character boundary; `String::truncate` would panic.
            text.extend(rest.chars().take(MAX_REPLY_TEXT - text.len()));
        }
        lines.push(rest);
        if line.get(3) != Some(&b'-') {
            return Ok(Reply { code, text, lines });
        }
    }
    Err("reply has too many lines".into())
}

fn parse_code(line: &[u8]) -> Result<u16, String> {
    let digits = line
        .get(..3)
        .filter(|digits| digits.iter().all(u8::is_ascii_digit))
        .ok_or_else(|| format!("bad reply: {}", sanitise(&String::from_utf8_lossy(line))))?;
    if !matches!(line.get(3), None | Some(b' ' | b'-')) || !(b'2'..=b'5').contains(&digits[0]) {
        return Err(format!(
            "bad reply: {}",
            sanitise(&String::from_utf8_lossy(line))
        ));
    }
    Ok(digits
        .iter()
        .fold(0u16, |acc, digit| acc * 10 + u16::from(digit - b'0')))
}

/// Replace control characters so remote text cannot break our own headers.
pub fn sanitise(text: &str) -> String {
    text.chars()
        .map(|ch| if ch.is_control() { ' ' } else { ch })
        .collect()
}

/// RFC 5321 path syntax, loosely: one `@`, bounded parts, and nothing that
/// could end the command early or smuggle another one.
pub fn valid_path(addr: &str) -> bool {
    let Some((local, domain)) = addr.rsplit_once('@') else {
        return false;
    };
    !local.is_empty()
        && local.len() <= 64
        && !domain.is_empty()
        && domain.len() <= 255
        && addr.len() <= 256
        && addr
            .bytes()
            .all(|byte| byte > b' ' && byte != 0x7f && byte != b'<' && byte != b'>')
}

/// Dot-stuff, write CRLF line endings (a lone CR or LF becomes CRLF, so no
/// bare line end reaches the next hop), and leave the buffer ending in CRLF
/// so the terminator is just `.` CRLF.
pub fn dot_stuff(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len() + 8);
    let mut at_line = true;
    for (index, &byte) in bytes.iter().enumerate() {
        if at_line && byte == b'.' {
            out.push(b'.');
        }
        match byte {
            b'\r' if bytes.get(index + 1) != Some(&b'\n') => {
                out.extend_from_slice(b"\r\n");
                at_line = true;
                continue;
            }
            b'\n' if index == 0 || bytes[index - 1] != b'\r' => out.push(b'\r'),
            _ => {}
        }
        out.push(byte);
        at_line = byte == b'\n';
    }
    if !out.is_empty() && !out.ends_with(b"\r\n") {
        out.extend_from_slice(b"\r\n");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn parse(bytes: &[u8]) -> Result<Reply, String> {
        let mut read = BufReader::new(bytes);
        read_reply(&mut read).await
    }

    #[tokio::test]
    async fn non_ascii_reply_does_not_panic() {
        let reply = parse("250\u{e9} ok\r\n".as_bytes()).await;
        assert!(reply.is_err());
        let reply = parse("250 caf\u{e9}\r\n".as_bytes()).await.unwrap();
        assert_eq!(reply.code, 250);
        let reply = parse(b"250 \xff\xfe\r\n").await.unwrap();
        assert_eq!(reply.code, 250);
    }

    #[tokio::test]
    async fn multi_line_and_limits() {
        let reply = parse(b"250-first\r\n250 second\r\n").await.unwrap();
        assert_eq!(reply.text, "first second");
        let long = [b"250 ".as_slice(), &[b'a'; 5000], b"\r\n"].concat();
        assert!(parse(&long).await.is_err());
        let wide = format!(
            "250-{}\r\n250 {}\r\n",
            "\u{e9}".repeat(700),
            "\u{e9}".repeat(700)
        );
        let reply = parse(wide.as_bytes()).await.unwrap();
        assert!(
            reply.text.len() <= 2 * MAX_REPLY_TEXT,
            "capped without panicking"
        );
        assert!(offers(
            &parse(b"250-mx\r\n250 STARTTLS\r\n").await.unwrap(),
            "STARTTLS"
        ));
        assert!(!offers(
            &parse(b"250 STARTTLS\r\n").await.unwrap(),
            "STARTTLS"
        ));
        let many = b"250-x\r\n".repeat(100);
        assert!(parse(&many).await.is_err());
        assert!(parse(b"25\r\n").await.is_err());
        assert!(parse(b"").await.is_err());
    }

    #[test]
    fn paths_reject_injection() {
        assert!(valid_path("user@example.test"));
        assert!(!valid_path("a@b.test\rQUIT\r"));
        assert!(!valid_path("a@b.test>\r\nRCPT TO:<c@d.test"));
        assert!(!valid_path("a b@example.test"));
        assert!(!valid_path("nobody"));
        assert!(!valid_path(&format!("{}@example.test", "a".repeat(65))));
    }

    #[test]
    fn dot_stuffing_and_terminator() {
        assert_eq!(dot_stuff(b"a\r\n.b\r\n"), b"a\r\n..b\r\n");
        assert_eq!(dot_stuff(b"a\n.\n"), b"a\r\n..\r\n");
        assert_eq!(dot_stuff(b"no newline"), b"no newline\r\n");
        assert_eq!(dot_stuff(b"a\r.\r\nb\rc"), b"a\r\n..\r\nb\r\nc\r\n");
    }
}
