//! RFC 5424 syslog over TCP or TLS, with octet-counted framing (RFC 6587 and RFC 5425).
use super::{cef, tls, Event, ExportError, Exporter};
use currawong_core::ResidencyGuard;
use rustls::pki_types::ServerName;
use std::{net::SocketAddr, path::Path, sync::Arc, time::Duration};
use time::{macros::format_description, UtcOffset};
use tokio::{
    io::{AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    sync::Mutex,
};
use tokio_rustls::TlsConnector;
use url::Url;

/// `local0`.
const FACILITY: u8 = 16;
const APP_NAME: &str = "currawong";
const IO_TIMEOUT: Duration = Duration::from_secs(10);

/// The MSG part: the CEF line (default) or the JSON event.
pub use currawong_core::config::EventPayload as Payload;

type Conn = Box<dyn AsyncWrite + Unpin + Send>;

pub struct SyslogExporter {
    address: String,
    /// `https://host:port`: the residency rules are written for HTTP URLs,
    /// so the collector is checked as that URL with the same host and port.
    rule_url: Url,
    guard: Arc<ResidencyGuard>,
    tls: Option<(TlsConnector, ServerName<'static>)>,
    hostname: String,
    payload: Payload,
    conn: Mutex<Option<Conn>>,
}

impl SyslogExporter {
    /// `address` is `host:port`. With `use_tls`, the server certificate is verified
    /// against the public roots and `ca_file`.
    pub fn new(
        guard: Arc<ResidencyGuard>,
        address: &str,
        use_tls: bool,
        ca_file: Option<&Path>,
        hostname: &str,
        payload: Payload,
    ) -> Result<Self, ExportError> {
        let scheme = if use_tls { "syslog-tls" } else { "syslog" };
        let url = Url::parse(&format!("{scheme}://{address}"))
            .map_err(|err| ExportError::Config(format!("syslog address {address}: {err}")))?;
        let host = url
            .host_str()
            .ok_or_else(|| ExportError::Config(format!("syslog address {address} has no host")))?;
        let port = url
            .port()
            .ok_or_else(|| ExportError::Config(format!("syslog address {address} has no port")))?;
        let rule_url = Url::parse(&format!("https://{host}:{port}"))
            .map_err(|err| ExportError::Config(format!("syslog address {address}: {err}")))?;
        guard.check(&rule_url)?;
        let tls = if use_tls {
            let name = host
                .trim_start_matches('[')
                .trim_end_matches(']')
                .to_string();
            let name = ServerName::try_from(name)
                .map_err(|err| ExportError::Config(format!("syslog server name: {err}")))?;
            let config = tls::client_config(ca_file)?;
            Some((TlsConnector::from(Arc::new(config)), name))
        } else {
            None
        };
        Ok(Self {
            address: format!("{host}:{port}"),
            rule_url,
            guard,
            tls,
            hostname: header_field(hostname, 255),
            payload,
            conn: Mutex::new(None),
        })
    }

    /// Resolve the collector and check the answer through the residency
    /// guard's `pin`. Returns the pinned address first, then the rest of
    /// the same answer, so a DNS change after the check cannot move the
    /// connection.
    async fn peers(&self) -> Result<Vec<SocketAddr>, ExportError> {
        let resolved: Vec<SocketAddr> =
            tokio::time::timeout(IO_TIMEOUT, tokio::net::lookup_host(&self.address))
                .await
                .map_err(|_| ExportError::Transport("syslog resolve timed out".into()))?
                .map_err(|err| ExportError::Transport(format!("syslog resolve: {err}")))?
                .collect();
        let pinned = self.guard.pin(&self.rule_url, &resolved)?;
        let mut peers = vec![pinned];
        peers.extend(resolved.into_iter().filter(|addr| *addr != pinned));
        Ok(peers)
    }

    async fn connect(&self) -> Result<Conn, ExportError> {
        let mut last = ExportError::Transport("syslog address did not resolve".into());
        let mut tcp = None;
        // `localhost` may answer ::1 first while the collector listens on
        // 127.0.0.1: try each checked address in order.
        for peer in self.peers().await? {
            match tokio::time::timeout(IO_TIMEOUT, TcpStream::connect(peer)).await {
                Ok(Ok(stream)) => {
                    tcp = Some(stream);
                    break;
                }
                Ok(Err(err)) => last = ExportError::Transport(format!("syslog connect: {err}")),
                Err(_) => last = ExportError::Transport("syslog connect timed out".into()),
            }
        }
        let Some(tcp) = tcp else {
            return Err(last);
        };
        match &self.tls {
            None => Ok(Box::new(tcp)),
            Some((connector, name)) => {
                let stream = tokio::time::timeout(IO_TIMEOUT, connector.connect(name.clone(), tcp))
                    .await
                    .map_err(|_| ExportError::Transport("syslog TLS handshake timed out".into()))?
                    .map_err(|err| ExportError::Transport(format!("syslog TLS: {err}")))?;
                Ok(Box::new(stream))
            }
        }
    }
}

#[async_trait::async_trait]
impl Exporter for SyslogExporter {
    fn name(&self) -> &'static str {
        "syslog"
    }

    async fn send(&self, batch: &[Event]) -> Result<(), ExportError> {
        let mut frames = Vec::new();
        for event in batch {
            let line = line(event, &self.hostname, self.payload);
            frames.extend_from_slice(format!("{} {line}", line.len()).as_bytes());
        }
        let mut conn = self.conn.lock().await;
        if conn.is_none() {
            *conn = Some(self.connect().await?);
        }
        let stream = conn.as_mut().expect("connected");
        let written = tokio::time::timeout(IO_TIMEOUT, async {
            stream.write_all(&frames).await?;
            stream.flush().await
        })
        .await;
        match written {
            Ok(Ok(())) => Ok(()),
            Ok(Err(err)) => {
                *conn = None;
                Err(ExportError::Transport(format!("syslog write: {err}")))
            }
            Err(_) => {
                *conn = None;
                Err(ExportError::Transport("syslog write timed out".into()))
            }
        }
    }
}

/// One RFC 5424 message: `<PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG`.
pub fn line(event: &Event, hostname: &str, payload: Payload) -> String {
    let pri = FACILITY * 8 + syslog_severity(event.severity());
    let ts = event
        .time
        .to_offset(UtcOffset::UTC)
        .format(format_description!(
            "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]Z"
        ))
        .expect("timestamp formats");
    let msg = match payload {
        Payload::Cef => cef::format(event),
        Payload::Json => serde_json::to_string(event).expect("event serialises"),
    };
    format!(
        "<{pri}>1 {ts} {} {APP_NAME} - {} - {msg}",
        header_field(hostname, 255),
        event.type_name()
    )
}

/// CEF 0 to 10 onto syslog severities: informational up to error.
fn syslog_severity(cef: u8) -> u8 {
    match cef {
        0..=3 => 6,
        4..=6 => 5,
        7..=8 => 4,
        _ => 3,
    }
}

/// Header fields are printable US-ASCII without spaces, or `-` when empty.
fn header_field(value: &str, max: usize) -> String {
    let clean: String = value
        .chars()
        .filter(|ch| ch.is_ascii_graphic())
        .take(max)
        .collect();
    if clean.is_empty() {
        "-".into()
    } else {
        clean
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::export::{event::tests::samples, testutil};
    use currawong_core::config::ResidencyConfig;
    use tokio::{io::AsyncReadExt, net::TcpListener};

    fn guard() -> Arc<ResidencyGuard> {
        Arc::new(ResidencyGuard::from_config(&ResidencyConfig::default()).unwrap())
    }

    /// Checks the RFC 5424 header grammar and returns the MSG part.
    fn validate_rfc5424(line: &str) -> Result<&str, String> {
        let rest = line.strip_prefix('<').ok_or("no PRI")?;
        let (pri, rest) = rest.split_once('>').ok_or("no PRI end")?;
        if pri.is_empty() || pri.len() > 3 || pri.parse::<u8>().map_err(|e| e.to_string())? > 191 {
            return Err(format!("bad PRI {pri}"));
        }
        let rest = rest.strip_prefix("1 ").ok_or("version is not 1")?;
        let parts: Vec<&str> = rest.splitn(7, ' ').collect();
        let [ts, host, app, procid, msgid, sd, msg] = parts[..] else {
            return Err("missing header fields".into());
        };
        time::OffsetDateTime::parse(ts, &time::format_description::well_known::Rfc3339)
            .map_err(|e| format!("timestamp {ts}: {e}"))?;
        let frac = ts
            .split_once('.')
            .map(|(_, f)| f.trim_end_matches('Z').len());
        if frac.unwrap_or(0) > 6 {
            return Err("TIME-SECFRAC has more than 6 digits".into());
        }
        for (field, max) in [(host, 255), (app, 48), (procid, 128), (msgid, 32)] {
            if field.is_empty() || field.len() > max || !field.chars().all(|c| c.is_ascii_graphic())
            {
                return Err(format!("bad header field {field:?}"));
            }
        }
        if sd != "-" && !sd.starts_with('[') {
            return Err(format!("bad STRUCTURED-DATA {sd}"));
        }
        Ok(msg)
    }

    /// Splits an octet-counted stream into messages.
    fn frames(mut data: &[u8]) -> Vec<String> {
        let mut out = Vec::new();
        while !data.is_empty() {
            let space = data.iter().position(|b| *b == b' ').unwrap();
            let len: usize = std::str::from_utf8(&data[..space])
                .unwrap()
                .parse()
                .unwrap();
            let start = space + 1;
            out.push(String::from_utf8(data[start..start + len].to_vec()).unwrap());
            data = &data[start + len..];
        }
        out
    }

    async fn receive(
        listener: TcpListener,
        acceptor: Option<tokio_rustls::TlsAcceptor>,
    ) -> Vec<u8> {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut buf = Vec::new();
        match acceptor {
            Some(acceptor) => {
                let mut tls = acceptor.accept(tcp).await.unwrap();
                tls.read_to_end(&mut buf).await.ok();
            }
            None => {
                let mut tcp = tcp;
                tcp.read_to_end(&mut buf).await.unwrap();
            }
        }
        buf
    }

    #[tokio::test]
    async fn export_syslog_receiver_gets_valid_rfc5424_over_tcp() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let server = tokio::spawn(receive(listener, None));
        let exporter = SyslogExporter::new(
            guard(),
            &addr,
            false,
            None,
            "gw1.example.com.au",
            Payload::Cef,
        )
        .unwrap();
        let batch = samples();
        exporter.send(&batch).await.unwrap();
        drop(exporter);
        let lines = frames(&server.await.unwrap());
        assert_eq!(lines.len(), batch.len());
        for (line, event) in lines.iter().zip(&batch) {
            let msg = validate_rfc5424(line).unwrap_or_else(|e| panic!("{e}: {line}"));
            assert_eq!(msg, cef::format(event));
            assert!(line.contains(&format!(" {} ", event.type_name())));
        }
        assert!(lines[0].starts_with("<132>1 2026-"), "{}", lines[0]);
    }

    #[tokio::test]
    async fn export_syslog_over_tls_verifies_the_server() {
        let dir = tempfile::tempdir().unwrap();
        let (acceptor, ca_file) = testutil::tls_acceptor(dir.path());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(receive(listener, Some(acceptor)));
        let exporter = SyslogExporter::new(
            guard(),
            &format!("localhost:{port}"),
            true,
            Some(&ca_file),
            "gw1",
            Payload::Json,
        )
        .unwrap();
        exporter.send(&samples()).await.unwrap();
        drop(exporter);
        let lines = frames(&server.await.unwrap());
        assert_eq!(lines.len(), samples().len());
        for line in &lines {
            let msg = validate_rfc5424(line).unwrap();
            let event: Event = serde_json::from_str(msg).unwrap();
            assert_eq!(event.schema, "currawong.event.v1");
        }

        // Without the private CA the handshake must fail.
        let (acceptor, _) = testutil::tls_acceptor(dir.path());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let _ = acceptor.accept(tcp).await;
        });
        let exporter = SyslogExporter::new(
            guard(),
            &format!("localhost:{port}"),
            true,
            None,
            "gw1",
            Payload::Cef,
        )
        .unwrap();
        assert!(exporter.send(&samples()).await.is_err());
    }

    #[test]
    fn export_syslog_refuses_a_foreign_collector() {
        let err = SyslogExporter::new(
            guard(),
            "siem.example.com:6514",
            true,
            None,
            "gw1",
            Payload::Cef,
        )
        .err()
        .unwrap();
        assert!(matches!(err, ExportError::Residency(_)), "{err}");
    }
}
