//! Parser worker processes. A crash, timeout or limit is a fail-closed result.
use currawong_core::config::ExtractLimits;
use currawong_parser::{ParseRequest, ParseResponse};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::{
    io::AsyncWriteExt,
    process::{Child, Command},
    time::timeout,
};
use tokio_util::codec::{FramedRead, LengthDelimitedCodec};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanOutcome {
    Parsed(ParseResponse),
    Failed { reason: String },
}

pub struct WorkerPool {
    binary: PathBuf,
    timeout: Duration,
    max_jobs: u64,
    memory_mib: u64,
    cpu_secs: u64,
    child: Option<ChildHandle>,
}

struct ChildHandle {
    child: Child,
    jobs: u64,
}

impl WorkerPool {
    pub fn new(binary: impl Into<PathBuf>, timeout_secs: u64, max_jobs: u64) -> Self {
        Self {
            binary: binary.into(),
            timeout: Duration::from_secs(timeout_secs.max(1)),
            max_jobs: max_jobs.max(1),
            memory_mib: 512,
            cpu_secs: 30,
            child: None,
        }
    }

    pub fn with_limits(mut self, memory_mib: u64, cpu_secs: u64) -> Self {
        self.memory_mib = memory_mib;
        self.cpu_secs = cpu_secs;
        self
    }

    pub async fn scan_file(
        &mut self,
        id: &str,
        path: &Path,
        limits: &ExtractLimits,
    ) -> ScanOutcome {
        let request = ParseRequest {
            id: id.to_string(),
            raw_path: path.to_path_buf(),
            limits: limits.clone(),
        };
        let bytes = match serde_json::to_vec(&request) {
            Ok(bytes) => bytes,
            Err(err) => {
                return ScanOutcome::Failed {
                    reason: err.to_string(),
                }
            }
        };
        match timeout(self.timeout, self.round_trip(&bytes)).await {
            Ok(Ok(response)) => {
                if response.error.is_some() {
                    ScanOutcome::Failed {
                        reason: response.error.unwrap_or_else(|| "parser error".into()),
                    }
                } else {
                    ScanOutcome::Parsed(response)
                }
            }
            Ok(Err(err)) => ScanOutcome::Failed { reason: err },
            Err(_) => {
                self.kill().await;
                ScanOutcome::Failed {
                    reason: "parser worker timed out".into(),
                }
            }
        }
    }

    async fn round_trip(&mut self, request: &[u8]) -> Result<ParseResponse, String> {
        if self
            .child
            .as_ref()
            .map(|child| child.jobs >= self.max_jobs)
            .unwrap_or(false)
        {
            self.kill().await;
        }
        if self.child.is_none() {
            self.spawn().await?;
        }
        let handle = self.child.as_mut().ok_or("worker missing")?;
        let stdin = handle.child.stdin.as_mut().ok_or("worker stdin")?;
        let mut framed_in = bytes::BytesMut::new();
        {
            use tokio_util::codec::Encoder;
            let mut codec = LengthDelimitedCodec::new();
            codec
                .encode(bytes::Bytes::from(request.to_vec()), &mut framed_in)
                .map_err(|err| err.to_string())?;
        }
        stdin
            .write_all(&framed_in)
            .await
            .map_err(|err| err.to_string())?;
        stdin.flush().await.map_err(|err| err.to_string())?;
        let stdout = handle.child.stdout.as_mut().ok_or("worker stdout")?;
        let mut reader = FramedRead::new(stdout, LengthDelimitedCodec::new());
        let frame = futures::StreamExt::next(&mut reader)
            .await
            .ok_or("worker closed")?
            .map_err(|err| err.to_string())?;
        handle.jobs += 1;
        serde_json::from_slice(&frame).map_err(|err| err.to_string())
    }

    async fn spawn(&mut self) -> Result<(), String> {
        if !self.binary.exists() {
            return Err(format!(
                "parser worker binary missing: {}",
                self.binary.display()
            ));
        }
        let mut child = Command::new(&self.binary)
            .env("CURRAWONG_WORKER_AS_MIB", self.memory_mib.to_string())
            .env("CURRAWONG_WORKER_CPU_SECS", self.cpu_secs.to_string())
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|err| format!("spawn parser worker: {err}"))?;
        let _ = child.stdin.as_mut();
        self.child = Some(ChildHandle { child, jobs: 0 });
        Ok(())
    }

    pub async fn kill(&mut self) {
        if let Some(mut handle) = self.child.take() {
            let _ = handle.child.kill().await;
        }
    }
}

pub fn worker_binary_from_exe() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?.parent()?;
    let candidate = dir.join("currawong-parser-worker");
    if candidate.is_file() {
        Some(candidate)
    } else {
        None
    }
}
