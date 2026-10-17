//! clamd INSTREAM. Supplemental signature directories are operator config:
//! point clamd at them (`OfficialDatabaseOnly no`). Mail is not uploaded.
use crate::engines::{EngineResult, ScanItem, Scanner};
use async_trait::async_trait;
use std::{
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};

#[derive(Debug, Clone)]
pub enum ClamdAddress {
    Tcp(std::net::SocketAddr),
    Unix(PathBuf),
}

impl ClamdAddress {
    pub fn parse(text: &str) -> Result<Self, String> {
        if let Some(path) = text.strip_prefix("unix:") {
            return Ok(Self::Unix(PathBuf::from(path)));
        }
        if let Some(addr) = text.strip_prefix("tcp:") {
            let addr = addr
                .parse()
                .map_err(|err| format!("clamd tcp address: {err}"))?;
            return Ok(Self::Tcp(addr));
        }
        Err("clamd address must start with unix: or tcp:".into())
    }
}

pub struct ClamdClient {
    pub address: ClamdAddress,
    pub required: bool,
    pub chunk: usize,
}

impl ClamdClient {
    pub fn new(address: ClamdAddress, required: bool) -> Self {
        Self {
            address,
            required,
            chunk: 16 * 1024,
        }
    }

    pub async fn ping(&self) -> Result<(), String> {
        let reply = self.round_trip(b"zPING\0", &[]).await?;
        if reply.contains("PONG") {
            Ok(())
        } else {
            Err(format!("clamd ping replied {reply}"))
        }
    }

    async fn instream(&self, bytes: &[u8]) -> Result<String, String> {
        self.round_trip(b"zINSTREAM\0", bytes).await
    }

    async fn round_trip(&self, command: &[u8], body: &[u8]) -> Result<String, String> {
        match &self.address {
            ClamdAddress::Tcp(addr) => {
                let stream = timeout(Duration::from_secs(5), TcpStream::connect(addr))
                    .await
                    .map_err(|_| "clamd timed out".to_string())?
                    .map_err(|err| format!("clamd connect: {err}"))?;
                exchange(stream, command, body, self.chunk).await
            }
            ClamdAddress::Unix(path) => {
                let stream = timeout(
                    Duration::from_secs(5),
                    tokio::net::UnixStream::connect(path),
                )
                .await
                .map_err(|_| "clamd timed out".to_string())?
                .map_err(|err| format!("clamd connect: {err}"))?;
                exchange(stream, command, body, self.chunk).await
            }
        }
    }
}

async fn exchange<S>(
    mut stream: S,
    command: &[u8],
    body: &[u8],
    chunk: usize,
) -> Result<String, String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    stream
        .write_all(command)
        .await
        .map_err(|err| err.to_string())?;
    if command.starts_with(b"zINSTREAM") {
        for piece in body.chunks(chunk.max(1)) {
            let len = (piece.len() as u32).to_be_bytes();
            stream
                .write_all(&len)
                .await
                .map_err(|err| err.to_string())?;
            stream
                .write_all(piece)
                .await
                .map_err(|err| err.to_string())?;
        }
        stream
            .write_all(&0u32.to_be_bytes())
            .await
            .map_err(|err| err.to_string())?;
    }
    stream.flush().await.map_err(|err| err.to_string())?;
    let mut buf = vec![0u8; 4096];
    let n = timeout(Duration::from_secs(30), stream.read(&mut buf))
        .await
        .map_err(|_| "clamd read timed out".to_string())?
        .map_err(|err| err.to_string())?;
    Ok(String::from_utf8_lossy(&buf[..n])
        .trim_matches('\0')
        .trim()
        .to_string())
}

fn classify(reply: &str, required: bool) -> EngineResult {
    if reply.contains("INSTREAM size limit exceeded") {
        return EngineResult::Failed {
            reason: reply.to_string(),
            unreachable: false,
        };
    }
    if reply.contains("FOUND") {
        let signature = reply
            .split(':')
            .nth(1)
            .unwrap_or(reply)
            .trim()
            .trim_end_matches("FOUND")
            .trim()
            .to_string();
        return EngineResult::Malware { signature };
    }
    if reply.contains("OK") {
        return EngineResult::Clean;
    }
    if reply.is_empty() {
        return EngineResult::Failed {
            reason: "empty clamd reply".into(),
            unreachable: required,
        };
    }
    EngineResult::Failed {
        reason: reply.to_string(),
        unreachable: false,
    }
}

#[async_trait]
impl Scanner for ClamdClient {
    fn name(&self) -> &str {
        "clamav"
    }

    async fn scan(&self, item: &ScanItem<'_>) -> EngineResult {
        match self.instream(item.bytes).await {
            Ok(reply) => classify(&reply, self.required),
            Err(reason) => EngineResult::Failed {
                reason,
                unreachable: true,
            },
        }
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
