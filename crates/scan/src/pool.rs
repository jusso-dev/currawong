//! Parser worker processes. A crash, timeout or limit is a fail-closed result,
//! and the worker is discarded so the next job gets a fresh one.
use currawong_core::config::ExtractLimits;
use currawong_parser::ipc::codec;
use currawong_parser::{ParseRequest, ParseResponse};
use futures::{SinkExt, StreamExt};
use std::{
    path::{Path, PathBuf},
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};
use tokio::{
    process::{Child, ChildStdin, ChildStdout, Command},
    sync::{Mutex, MutexGuard},
    time::timeout,
};
use tokio_util::codec::{FramedRead, FramedWrite, LengthDelimitedCodec};

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
    slots: Vec<Mutex<Option<Worker>>>,
    next: AtomicUsize,
}

struct Worker {
    child: Child,
    stdin: FramedWrite<ChildStdin, LengthDelimitedCodec>,
    stdout: FramedRead<ChildStdout, LengthDelimitedCodec>,
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
            slots: vec![Mutex::new(None)],
            next: AtomicUsize::new(0),
        }
    }

    /// Number of worker processes (`scanner.worker_pool_size`).
    pub fn with_size(mut self, size: usize) -> Self {
        self.slots = (0..size.max(1)).map(|_| Mutex::new(None)).collect();
        self
    }

    pub fn with_limits(mut self, memory_mib: u64, cpu_secs: u64) -> Self {
        self.memory_mib = memory_mib;
        self.cpu_secs = cpu_secs;
        self
    }

    pub async fn scan_file(&self, id: &str, path: &Path, limits: &ExtractLimits) -> ScanOutcome {
        self.scan_file_into(id, path, limits, None).await
    }

    /// Parses `path`. With `out_dir`, decoded parts are written there.
    pub async fn scan_file_into(
        &self,
        id: &str,
        path: &Path,
        limits: &ExtractLimits,
        out_dir: Option<&Path>,
    ) -> ScanOutcome {
        let request = ParseRequest {
            id: id.to_string(),
            raw_path: path.to_path_buf(),
            limits: limits.clone(),
            out_dir: out_dir.map(Path::to_path_buf),
        };
        let bytes = match serde_json::to_vec(&request) {
            Ok(bytes) => bytes,
            Err(err) => {
                return ScanOutcome::Failed {
                    reason: err.to_string(),
                }
            }
        };
        let mut slot = self.acquire().await;
        let result = timeout(self.timeout, self.round_trip(&mut slot, bytes)).await;
        let reason = match result {
            Ok(Ok(response)) if response.id == id => {
                return match response.error {
                    Some(reason) => ScanOutcome::Failed { reason },
                    None => ScanOutcome::Parsed(response),
                };
            }
            // Out of step: a startup failure or a reply for another job.
            Ok(Ok(response)) => format!(
                "parser worker answered for {:?}: {}",
                response.id,
                response.error.unwrap_or_default()
            ),
            Ok(Err(err)) => format!("parser worker failed: {err}"),
            Err(_) => "parser worker timed out".to_string(),
        };
        kill(&mut slot).await;
        ScanOutcome::Failed { reason }
    }

    /// A free worker if there is one, otherwise wait for the next in turn.
    async fn acquire(&self) -> MutexGuard<'_, Option<Worker>> {
        let start = self.next.fetch_add(1, Ordering::Relaxed);
        for offset in 0..self.slots.len() {
            if let Ok(guard) = self.slots[(start + offset) % self.slots.len()].try_lock() {
                return guard;
            }
        }
        self.slots[start % self.slots.len()].lock().await
    }

    async fn round_trip(
        &self,
        slot: &mut Option<Worker>,
        request: Vec<u8>,
    ) -> Result<ParseResponse, String> {
        if slot
            .as_mut()
            .is_some_and(|w| w.jobs >= self.max_jobs || !matches!(w.child.try_wait(), Ok(None)))
        {
            // Recycled, or it died between jobs.
            kill(slot).await;
        }
        if slot.is_none() {
            *slot = Some(self.spawn()?);
        }
        let worker = slot.as_mut().ok_or("worker missing")?;
        worker.jobs += 1;
        worker
            .stdin
            .send(bytes::Bytes::from(request))
            .await
            .map_err(|err| err.to_string())?;
        let frame = worker
            .stdout
            .next()
            .await
            .ok_or("worker closed")?
            .map_err(|err| err.to_string())?;
        serde_json::from_slice(&frame).map_err(|err| err.to_string())
    }

    fn spawn(&self) -> Result<Worker, String> {
        if !self.binary.is_file() {
            return Err(format!(
                "parser worker binary missing: {}",
                self.binary.display()
            ));
        }
        // No inherited environment: secrets in the daemon's env stay there.
        let mut child = Command::new(&self.binary)
            .env_clear()
            .env("CURRAWONG_WORKER_AS_MIB", self.memory_mib.to_string())
            .env("CURRAWONG_WORKER_CPU_SECS", self.cpu_secs.to_string())
            .env("CURRAWONG_WORKER_MAX_JOBS", self.max_jobs.to_string())
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|err| format!("spawn parser worker: {err}"))?;
        let stdin = child.stdin.take().ok_or("worker stdin")?;
        let stdout = child.stdout.take().ok_or("worker stdout")?;
        Ok(Worker {
            child,
            stdin: FramedWrite::new(stdin, codec()),
            stdout: FramedRead::new(stdout, codec()),
            jobs: 0,
        })
    }

    /// Process ids of running workers, for diagnostics and tests.
    pub fn worker_pids(&self) -> Vec<u32> {
        self.slots
            .iter()
            .filter_map(|slot| slot.try_lock().ok()?.as_ref()?.child.id())
            .collect()
    }

    pub async fn kill(&self) {
        for slot in &self.slots {
            kill(&mut *slot.lock().await).await;
        }
    }
}

async fn kill(slot: &mut Option<Worker>) {
    if let Some(mut worker) = slot.take() {
        let _ = worker.child.kill().await;
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
