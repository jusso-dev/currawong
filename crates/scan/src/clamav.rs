//! clamd INSTREAM. Supplemental signature directories are operator config:
//! point clamd at them (`OfficialDatabaseOnly no`). Mail is not uploaded.
use crate::engines::{EngineResult, ScanItem, Scanner};
use async_trait::async_trait;
use currawong_core::PartInfo;
use std::{
    collections::HashSet,
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::{timeout_at, Instant},
};

#[derive(Debug, Clone)]
pub enum ClamdAddress {
    /// `host:port`; names are resolved when connecting.
    Tcp(String),
    Unix(PathBuf),
}

impl ClamdAddress {
    pub fn parse(text: &str) -> Result<Self, String> {
        if let Some(path) = text.strip_prefix("unix:") {
            return Ok(Self::Unix(PathBuf::from(path)));
        }
        if let Some(addr) = text.strip_prefix("tcp:") {
            let valid = addr.parse::<std::net::SocketAddr>().is_ok()
                || addr
                    .rsplit_once(':')
                    .is_some_and(|(host, port)| !host.is_empty() && port.parse::<u16>().is_ok());
            if !valid {
                return Err(format!("clamd tcp address {addr:?} is not host:port"));
            }
            return Ok(Self::Tcp(addr.to_string()));
        }
        Err("clamd address must start with unix: or tcp:".into())
    }

    /// The host of a TCP address, for the residency check.
    pub fn host(&self) -> Option<&str> {
        match self {
            Self::Tcp(addr) => addr
                .rsplit_once(':')
                .map(|(host, _)| host.trim_start_matches('[').trim_end_matches(']')),
            Self::Unix(_) => None,
        }
    }
}

pub struct ClamdClient {
    pub address: ClamdAddress,
    pub required: bool,
    pub chunk: usize,
    /// Deadline for one message: the raw stream and every extracted part.
    pub timeout: Duration,
}

/// Longest reply read from clamd. Real replies are a line.
const MAX_REPLY: usize = 4096;
/// A clamd that does not accept a connection in this time is unreachable.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// `unreachable`: clamd could not be reached (defer). Otherwise clamd was
/// reached and did not finish the scan (fail closed).
struct ClamdError {
    reason: String,
    unreachable: bool,
}

impl ClamdClient {
    pub fn new(address: ClamdAddress, required: bool) -> Self {
        Self {
            address,
            required,
            chunk: 16 * 1024,
            timeout: Duration::from_secs(120),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Includes the signature database version and date. Bounded like PING.
    pub async fn version(&self) -> Result<String, String> {
        let deadline = Instant::now() + self.timeout.min(CONNECT_TIMEOUT);
        let reply = self
            .round_trip(b"zVERSION\0", &[], deadline)
            .await
            .map_err(|err| err.reason)?;
        if reply.starts_with("ClamAV ") {
            Ok(reply)
        } else {
            Err("clamd VERSION returned an invalid reply".into())
        }
    }

    pub async fn ping(&self) -> Result<(), String> {
        let deadline = Instant::now() + self.timeout.min(CONNECT_TIMEOUT);
        let reply = self
            .round_trip(b"zPING\0", &[], deadline)
            .await
            .map_err(|err| err.reason)?;
        if reply == "PONG" {
            Ok(())
        } else {
            Err(format!("clamd ping replied {reply}"))
        }
    }

    /// The raw message, then every distinct part the parser worker wrote to
    /// disk (decoded attachments and archive members), all under one
    /// deadline. Stops at the first malware or unreachable result.
    pub async fn scan_message(&self, raw: &[u8], parts: &[PartInfo]) -> EngineResult {
        let deadline = Instant::now() + self.timeout;
        let mut result = self.scan_until(raw, deadline).await;
        let mut seen = HashSet::new();
        for part in parts {
            if matches!(
                result,
                EngineResult::Malware { .. }
                    | EngineResult::Failed {
                        unreachable: true,
                        ..
                    }
            ) {
                break;
            }
            let Some(path) = &part.path else { continue };
            if !seen.insert(part.sha256.as_str()) {
                continue;
            }
            let next = match tokio::fs::read(path).await {
                Ok(bytes) => self.scan_until(&bytes, deadline).await,
                Err(err) => EngineResult::Failed {
                    reason: format!("read extracted part: {err}"),
                    unreachable: false,
                },
            };
            if severity(&next) > severity(&result) {
                result = next;
            }
        }
        result
    }

    async fn scan_until(&self, bytes: &[u8], deadline: Instant) -> EngineResult {
        match self.round_trip(b"zINSTREAM\0", bytes, deadline).await {
            Ok(reply) => classify(&reply),
            Err(err) => EngineResult::Failed {
                reason: err.reason,
                unreachable: err.unreachable,
            },
        }
    }

    async fn round_trip(
        &self,
        command: &[u8],
        body: &[u8],
        deadline: Instant,
    ) -> Result<String, ClamdError> {
        let unreachable = |reason: String| ClamdError {
            reason,
            unreachable: true,
        };
        let late = || ClamdError {
            reason: "clamd did not finish the scan in time".into(),
            unreachable: false,
        };
        if Instant::now() >= deadline {
            return Err(late());
        }
        let connect_by = deadline.min(Instant::now() + CONNECT_TIMEOUT);
        let connect_timed_out = || {
            if Instant::now() >= deadline {
                late()
            } else {
                unreachable("clamd connect timed out".into())
            }
        };
        let exchange = match &self.address {
            ClamdAddress::Tcp(addr) => {
                let stream = timeout_at(connect_by, TcpStream::connect(addr.as_str()))
                    .await
                    .map_err(|_| connect_timed_out())?
                    .map_err(|err| unreachable(format!("clamd connect: {err}")))?;
                timeout_at(deadline, exchange(stream, command, body, self.chunk)).await
            }
            ClamdAddress::Unix(path) => {
                let stream = timeout_at(connect_by, tokio::net::UnixStream::connect(path))
                    .await
                    .map_err(|_| connect_timed_out())?
                    .map_err(|err| unreachable(format!("clamd connect: {err}")))?;
                timeout_at(deadline, exchange(stream, command, body, self.chunk)).await
            }
        };
        match exchange {
            Ok(Ok(reply)) => Ok(reply),
            // Connected and then lost: clamd went away, try again later.
            Ok(Err(reason)) => Err(unreachable(reason)),
            // Connected and stalled: do not keep retrying the same message.
            Err(_) => Err(late()),
        }
    }
}

/// Sends while reading, so a reply clamd sends early (size limit) and then
/// closes on is still seen. The reply ends at the NUL of the `z` protocol.
async fn exchange<S>(stream: S, command: &[u8], body: &[u8], chunk: usize) -> Result<String, String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (mut rd, mut wr) = tokio::io::split(stream);
    let send = async {
        wr.write_all(command).await?;
        if command.starts_with(b"zINSTREAM") {
            for piece in body.chunks(chunk.max(1)) {
                wr.write_all(&(piece.len() as u32).to_be_bytes()).await?;
                wr.write_all(piece).await?;
            }
            wr.write_all(&0u32.to_be_bytes()).await?;
        }
        wr.flush().await
    };
    let recv = read_reply(&mut rd);
    tokio::pin!(send, recv);
    let mut sent = None;
    let reply = loop {
        tokio::select! {
            result = &mut send, if sent.is_none() => sent = Some(result),
            reply = &mut recv => break reply,
        }
    };
    match reply {
        Ok(text) if !text.is_empty() => Ok(text),
        Ok(_) | Err(_) => match sent {
            Some(Err(err)) => Err(format!("clamd send: {err}")),
            _ => Err("clamd closed without a reply".into()),
        },
    }
}

async fn read_reply<R>(rd: &mut R) -> std::io::Result<String>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut buf = Vec::new();
    let mut tmp = [0u8; 512];
    loop {
        let n = match rd.read(&mut tmp).await {
            Ok(n) => n,
            Err(_) if !buf.is_empty() => 0,
            Err(err) => return Err(err),
        };
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.contains(&0) || buf.len() >= MAX_REPLY {
            break;
        }
    }
    let end = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
    Ok(String::from_utf8_lossy(&buf[..end]).trim().to_string())
}

/// `stream: OK`, `stream: <signature> FOUND`, or an error. Anything else
/// fails closed.
fn classify(reply: &str) -> EngineResult {
    if reply.contains("INSTREAM size limit exceeded") {
        return EngineResult::Failed {
            reason: reply.to_string(),
            unreachable: false,
        };
    }
    match reply.strip_prefix("stream: ") {
        Some("OK") => EngineResult::Clean,
        Some(rest) if rest.ends_with(" FOUND") => EngineResult::Malware {
            signature: rest.trim_end_matches(" FOUND").trim().to_string(),
        },
        _ => EngineResult::Failed {
            reason: reply.to_string(),
            unreachable: false,
        },
    }
}

/// Malware, then an unreachable engine (defer), then a failure (quarantine).
fn severity(result: &EngineResult) -> u8 {
    match result {
        EngineResult::Malware { .. } => 4,
        EngineResult::Failed {
            unreachable: true, ..
        } => 3,
        EngineResult::Failed { .. } => 2,
        EngineResult::Suspicious { .. } => 1,
        EngineResult::Clean => 0,
    }
}

#[async_trait]
impl Scanner for ClamdClient {
    fn name(&self) -> &str {
        "clamav"
    }

    async fn scan(&self, item: &ScanItem<'_>) -> EngineResult {
        self.scan_until(item.bytes, Instant::now() + self.timeout)
            .await
    }
}

/// Directories and database files the operator asked clamd to load as well.
/// Currawong checks they exist. It does not upload mail to build them.
pub fn supplemental_paths_ready(dirs: &[PathBuf], files: &[PathBuf]) -> Result<(), String> {
    for dir in dirs {
        if !dir.is_dir() {
            return Err(format!(
                "supplemental signature directory missing: {}",
                dir.display()
            ));
        }
    }
    for file in files {
        if !file.is_file() {
            return Err(format!(
                "supplemental signature database missing: {}",
                file.display()
            ));
        }
    }
    Ok(())
}

pub fn path_is_configured(path: &Path) -> bool {
    !path.as_os_str().is_empty()
}
