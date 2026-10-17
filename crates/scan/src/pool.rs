//! Parser worker processes (ADR 0002).
//!
//! Each worker gets a private 0700 directory with `in/` and `out/`. For each
//! job the supervisor copies the message into `in/`, the worker (confined by
//! Landlock on Linux to those two directories) writes decoded parts into
//! `out/`, and the supervisor checks and moves them out before the next job.
//!
//! Outcomes: a crash, timeout, protocol error or bad output fails the
//! message closed (quarantine). A worker that cannot be started at all
//! (missing binary, sandbox unavailable, no disk) is an infrastructure
//! fault: the message is deferred, not judged.
use currawong_core::config::ExtractLimits;
use currawong_parser::ipc::{codec, READY_ID, STARTUP_ID};
use currawong_parser::{ParseRequest, ParseResponse};
use futures::{SinkExt, StreamExt};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    io::Read,
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
    /// The message could not be parsed safely: quarantine.
    Failed {
        reason: String,
    },
    /// No worker could be run: defer and try again later.
    Unavailable {
        reason: String,
    },
}

enum Fault {
    Failed(String),
    Unavailable(String),
}

pub struct WorkerPool {
    binary: PathBuf,
    timeout: Duration,
    max_jobs: u64,
    memory_mib: u64,
    cpu_secs: u64,
    work_dir: PathBuf,
    landlock_required: bool,
    user: Option<(u32, u32)>,
    slots: Vec<Mutex<Option<Worker>>>,
    next: AtomicUsize,
}

struct Worker {
    child: Child,
    stdin: FramedWrite<ChildStdin, LengthDelimitedCodec>,
    stdout: FramedRead<ChildStdout, LengthDelimitedCodec>,
    jobs: u64,
    /// Removed when the worker is dropped.
    dir: tempfile::TempDir,
}

const INPUT_NAME: &str = "message.eml";
/// Parts beyond `max_files` the worker may add (attached messages, the
/// limit marker).
const PART_SLACK: usize = 16;

impl WorkerPool {
    pub fn new(binary: impl Into<PathBuf>, timeout_secs: u64, max_jobs: u64) -> Self {
        Self {
            binary: binary.into(),
            timeout: Duration::from_secs(timeout_secs.max(1)),
            max_jobs: max_jobs.max(1),
            memory_mib: 512,
            cpu_secs: 30,
            work_dir: std::env::temp_dir(),
            landlock_required: true,
            user: None,
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

    /// Where worker directories are made. Keep it on the spool's disk.
    pub fn with_work_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.work_dir = dir.into();
        self
    }

    /// `false` lets workers run without Landlock (logged on every start).
    pub fn with_landlock_required(mut self, required: bool) -> Self {
        self.landlock_required = required;
        self
    }

    /// uid and gid for workers. Required when the daemon runs as root.
    pub fn with_user(mut self, user: Option<(u32, u32)>) -> Self {
        self.user = user;
        self
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    pub async fn scan_file(&self, id: &str, path: &Path, limits: &ExtractLimits) -> ScanOutcome {
        self.scan_file_into(id, path, limits, None).await
    }

    /// Parses `path`. With `dest`, checked parts are moved there and
    /// `PartInfo::path` points at them.
    pub async fn scan_file_into(
        &self,
        id: &str,
        path: &Path,
        limits: &ExtractLimits,
        dest: Option<&Path>,
    ) -> ScanOutcome {
        let mut slot = self.acquire().await;
        match self.run(&mut slot, id, path, limits, dest).await {
            Ok(response) => match response.error {
                Some(reason) => ScanOutcome::Failed { reason },
                None => ScanOutcome::Parsed(response),
            },
            Err(fault) => {
                kill(&mut slot).await;
                match fault {
                    Fault::Failed(reason) => ScanOutcome::Failed { reason },
                    Fault::Unavailable(reason) => ScanOutcome::Unavailable { reason },
                }
            }
        }
    }

    /// A tiny message through a real worker: used at startup and by /readyz.
    pub async fn self_test(&self) -> Result<(), String> {
        std::fs::create_dir_all(&self.work_dir)
            .map_err(|err| format!("self-test directory: {err}"))?;
        let dir = tempfile::Builder::new()
            .prefix("selftest-")
            .tempdir_in(&self.work_dir)
            .map_err(|err| format!("self-test directory: {err}"))?;
        let path = dir.path().join(INPUT_NAME);
        std::fs::write(
            &path,
            b"From: a@example.test\r\nTo: b@example.test\r\nSubject: self-test\r\n\r\nok\r\n",
        )
        .map_err(|err| format!("self-test message: {err}"))?;
        match self
            .scan_file("self-test", &path, &ExtractLimits::default())
            .await
        {
            ScanOutcome::Parsed(_) => Ok(()),
            ScanOutcome::Failed { reason } | ScanOutcome::Unavailable { reason } => Err(reason),
        }
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

    async fn run(
        &self,
        slot: &mut Option<Worker>,
        id: &str,
        path: &Path,
        limits: &ExtractLimits,
        dest: Option<&Path>,
    ) -> Result<ParseResponse, Fault> {
        if slot
            .as_mut()
            .is_some_and(|w| w.jobs >= self.max_jobs || !matches!(w.child.try_wait(), Ok(None)))
        {
            // Recycled, or it died between jobs.
            kill(slot).await;
        }
        if slot.is_none() {
            *slot = Some(self.spawn().await?);
        }
        let worker = slot
            .as_mut()
            .ok_or_else(|| Fault::Unavailable("worker missing".into()))?;
        let input = worker.dir.path().join("in").join(INPUT_NAME);
        let out = worker.dir.path().join("out");
        self.stage(path, &input, &out).map_err(Fault::Unavailable)?;
        let request = ParseRequest {
            id: id.to_string(),
            raw_path: input.clone(),
            limits: limits.clone(),
            // Parts are written only when the caller wants them.
            out_dir: dest.map(|_| out.clone()),
        };
        let bytes = serde_json::to_vec(&request).map_err(|err| Fault::Failed(err.to_string()))?;
        worker.jobs += 1;
        let exchange = async {
            worker
                .stdin
                .send(bytes::Bytes::from(bytes))
                .await
                .map_err(|err| format!("parser worker failed: {err}"))?;
            let frame = worker
                .stdout
                .next()
                .await
                .ok_or("parser worker failed: worker closed")?
                .map_err(|err| format!("parser worker failed: {err}"))?;
            serde_json::from_slice::<ParseResponse>(&frame)
                .map_err(|err| format!("parser worker failed: {err}"))
        };
        let mut response = timeout(self.timeout, exchange)
            .await
            .map_err(|_| Fault::Failed("parser worker timed out".into()))?
            .map_err(Fault::Failed)?;
        let _ = std::fs::remove_file(&input);
        if response.id != id {
            // Out of step: a reply for another job.
            return Err(Fault::Failed(format!(
                "parser worker answered for {:?}: {}",
                response.id,
                response.error.unwrap_or_default()
            )));
        }
        let collected = collect_parts(&mut response, &out, dest, limits);
        clear(&out);
        collected.map_err(Fault::Failed)?;
        Ok(response)
    }

    /// A private copy of the message for the worker, and an empty `out/`.
    fn stage(&self, source: &Path, input: &Path, out: &Path) -> Result<(), String> {
        clear(out);
        std::fs::copy(source, input).map_err(|err| format!("stage message: {err}"))?;
        set_mode(input, 0o600).map_err(|err| format!("stage message: {err}"))?;
        if let Some((uid, gid)) = self.user {
            chown(input, uid, gid).map_err(|err| format!("stage message: {err}"))?;
        }
        Ok(())
    }

    async fn spawn(&self) -> Result<Worker, Fault> {
        let unavailable = |reason: String| Fault::Unavailable(reason);
        if !self.binary.is_file() {
            return Err(unavailable(format!(
                "parser worker binary missing: {}",
                self.binary.display()
            )));
        }
        if running_as_root() && self.user.is_none() {
            return Err(unavailable(
                "refusing to run the parser worker as root: set scanner.worker_uid and \
                 scanner.worker_gid"
                    .into(),
            ));
        }
        std::fs::create_dir_all(&self.work_dir)
            .map_err(|err| unavailable(format!("worker directory: {err}")))?;
        let dir = tempfile::Builder::new()
            .prefix("worker-")
            .tempdir_in(&self.work_dir)
            .map_err(|err| unavailable(format!("worker directory: {err}")))?;
        for sub in ["in", "out"] {
            let path = dir.path().join(sub);
            std::fs::create_dir(&path)
                .and_then(|()| set_mode(&path, 0o700))
                .map_err(|err| unavailable(format!("worker directory: {err}")))?;
        }
        // No inherited environment: secrets in the daemon's env stay there.
        let mut command = Command::new(&self.binary);
        command
            .env_clear()
            .env("CURRAWONG_WORKER_AS_MIB", self.memory_mib.to_string())
            .env("CURRAWONG_WORKER_CPU_SECS", self.cpu_secs.to_string())
            .env("CURRAWONG_WORKER_MAX_JOBS", self.max_jobs.to_string())
            .env("CURRAWONG_WORKER_DIR", dir.path())
            .env(
                "CURRAWONG_WORKER_LANDLOCK",
                if self.landlock_required {
                    "required"
                } else {
                    "optional"
                },
            )
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true);
        #[cfg(unix)]
        if let Some((uid, gid)) = self.user {
            for path in [
                dir.path().to_path_buf(),
                dir.path().join("in"),
                dir.path().join("out"),
            ] {
                chown(&path, uid, gid)
                    .map_err(|err| unavailable(format!("worker directory: {err}")))?;
            }
            command
                .uid(uid)
                .gid(gid)
                .env("CURRAWONG_WORKER_NPROC", "64");
        }
        let mut child = command
            .spawn()
            .map_err(|err| unavailable(format!("spawn parser worker: {err}")))?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| unavailable("worker stdin".into()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| unavailable("worker stdout".into()))?;
        let mut worker = Worker {
            child,
            stdin: FramedWrite::new(stdin, codec()),
            stdout: FramedRead::new(stdout, codec()),
            jobs: 0,
            dir,
        };
        // The worker sends `ready` once its sandbox is in place.
        let ready = timeout(self.timeout, worker.stdout.next())
            .await
            .map_err(|_| unavailable("parser worker did not start in time".into()))?
            .ok_or_else(|| unavailable("parser worker exited during startup".into()))?
            .map_err(|err| unavailable(format!("parser worker startup: {err}")))?;
        let ready: ParseResponse = serde_json::from_slice(&ready)
            .map_err(|err| unavailable(format!("parser worker startup: {err}")))?;
        match ready.id.as_str() {
            READY_ID => {
                for warning in &ready.warnings {
                    tracing::warn!(%warning, "parser worker sandbox");
                }
                Ok(worker)
            }
            STARTUP_ID => Err(unavailable(format!(
                "parser worker could not start: {}",
                ready.error.unwrap_or_default()
            ))),
            other => Err(unavailable(format!("parser worker startup sent {other:?}"))),
        }
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

/// Removes worker and scratch directories left by an earlier run.
pub fn sweep(work_dir: &Path, prefixes: &[&str]) {
    let Ok(entries) = std::fs::read_dir(work_dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if prefixes.iter().any(|prefix| name.starts_with(prefix)) {
            let _ = std::fs::remove_dir_all(entry.path());
        }
    }
}

async fn kill(slot: &mut Option<Worker>) {
    if let Some(mut worker) = slot.take() {
        let _ = worker.child.kill().await;
    }
}

fn clear(dir: &Path) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

/// The worker is not trusted with paths: only `out/NNNN.part` regular files
/// are accepted, read without following links, size-capped, hashed here,
/// deduplicated and copied to `dest` under names the supervisor chooses.
fn collect_parts(
    response: &mut ParseResponse,
    out: &Path,
    dest: Option<&Path>,
    limits: &ExtractLimits,
) -> Result<(), String> {
    if response.parts.len() > limits.max_files as usize + PART_SLACK {
        return Err(format!(
            "parser worker returned {} parts, over the limit",
            response.parts.len()
        ));
    }
    let mut copied: HashMap<String, (String, String, u64)> = HashMap::new();
    let mut by_hash: HashMap<String, String> = HashMap::new();
    for part in &mut response.parts {
        let Some(claimed) = part.path.take() else {
            continue;
        };
        if let Some((sha, path, size)) = copied.get(&claimed) {
            part.sha256 = sha.clone();
            part.size = *size;
            part.path = dest.map(|_| path.clone());
            continue;
        }
        let source = PathBuf::from(&claimed);
        let well_formed = source.parent() == Some(out)
            && source
                .file_name()
                .and_then(|name| name.to_str())
                .and_then(|name| name.strip_suffix(".part"))
                .is_some_and(|stem| stem.len() >= 4 && stem.bytes().all(|b| b.is_ascii_digit()));
        if !well_formed {
            return Err(format!(
                "parser worker named a file outside its output directory: {:?}",
                display_name(&claimed)
            ));
        }
        let bytes = read_part(&source, limits.max_uncompressed_bytes)?;
        let sha = hex(&Sha256::digest(&bytes));
        let size = bytes.len() as u64;
        let path = match dest {
            Some(dest) => match by_hash.get(&sha) {
                Some(path) => path.clone(),
                None => {
                    let path = dest.join(format!("{:04}.part", by_hash.len()));
                    std::fs::write(&path, &bytes).map_err(|err| format!("copy part: {err}"))?;
                    let path = path.to_string_lossy().to_string();
                    by_hash.insert(sha.clone(), path.clone());
                    path
                }
            },
            None => String::new(),
        };
        part.sha256 = sha.clone();
        part.size = size;
        part.path = dest.map(|_| path.clone());
        copied.insert(claimed, (sha, path, size));
    }
    Ok(())
}

fn read_part(path: &Path, cap: u64) -> Result<Vec<u8>, String> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options
        .open(path)
        .map_err(|err| format!("parser worker part: {err}"))?;
    let meta = file
        .metadata()
        .map_err(|err| format!("parser worker part: {err}"))?;
    if !meta.is_file() || meta.len() > cap {
        return Err("parser worker part is not a regular file within the size limit".into());
    }
    let mut bytes = Vec::new();
    file.take(cap.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|err| format!("parser worker part: {err}"))?;
    if bytes.len() as u64 > cap {
        return Err("parser worker part grew past the size limit".into());
    }
    Ok(bytes)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Control characters removed and length capped, for logs and notes.
pub fn display_name(name: &str) -> String {
    let clean: String = name
        .chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .take(120)
        .collect();
    if name.chars().count() > 120 {
        format!("{clean}...")
    } else {
        clean
    }
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> std::io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn chown(path: &Path, uid: u32, gid: u32) -> std::io::Result<()> {
    std::os::unix::fs::chown(path, Some(uid), Some(gid))
}

#[cfg(not(unix))]
fn chown(_path: &Path, _uid: u32, _gid: u32) -> std::io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn running_as_root() -> bool {
    // SAFETY: geteuid cannot fail.
    unsafe { libc::geteuid() == 0 }
}

#[cfg(not(unix))]
fn running_as_root() -> bool {
    false
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
