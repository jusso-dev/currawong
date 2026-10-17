//! Durable on-disk spool. See ADR 0001.
//!
//! A 250 reply is only returned after the message file and its metadata have
//! been renamed into place and the directory has been synced.
//!
//! Crash invariants, which `recover` relies on:
//! - A message is live in the state directory that holds both `<id>.eml` and
//!   `<id>.json`. Any other `<id>.json` is stale.
//! - `accept` renames the JSON before the eml, so a crash inside `accept`
//!   (before the 250) can leave a JSON with no eml, never an eml with no JSON.
//! - `transition` writes the destination JSON before moving the eml and only
//!   removes the source JSON afterwards, so every step leaves a complete pair.
use currawong_core::{Direction, MessageId};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    net::IpAddr,
    path::{Path, PathBuf},
    time::Duration,
};
use time::OffsetDateTime;
use tokio::io::{AsyncRead, AsyncWriteExt};

pub use currawong_core::Error as CoreError;

#[cfg(test)]
mod crash_tests;

#[derive(Debug, thiserror::Error)]
pub enum SpoolError {
    #[error("spool i/o: {0}")]
    Io(#[from] std::io::Error),
    #[error("spool metadata: {0}")]
    Json(#[from] serde_json::Error),
    #[error("message {0} was not found")]
    NotFound(String),
    #[error("message id {0} is not a safe spool id")]
    UnsafeId(String),
    #[error("task join: {0}")]
    Join(String),
    #[error("envelope in {file} names message {found}")]
    IdMismatch { file: String, found: String },
}

pub type Result<T> = std::result::Result<T, SpoolError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SpoolState {
    Incoming,
    Active,
    Deferred,
    Done,
}

const STATES: [SpoolState; 4] = [
    SpoolState::Incoming,
    SpoolState::Active,
    SpoolState::Deferred,
    SpoolState::Done,
];

/// Entries recovery cannot repair are moved here for an operator to inspect.
const BAD_DIR: &str = "bad";

impl SpoolState {
    pub fn dir_name(self) -> &'static str {
        match self {
            Self::Incoming => "incoming",
            Self::Active => "active",
            Self::Deferred => "deferred",
            Self::Done => "done",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RcptStatus {
    pub address: String,
    pub status: String,
    pub detail: String,
}

/// Envelope metadata stored beside the immutable `.eml` bytes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Envelope {
    pub id: MessageId,
    pub tenant_id: Option<String>,
    /// SMTP AUTH login that submitted the message. `None` for inbound mail
    /// and trusted-network relay. Policy can scope user and group rules by it.
    #[serde(default)]
    pub authenticated_as: Option<String>,
    pub mail_from: String,
    pub rcpt_to: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub received_at: OffsetDateTime,
    pub remote_ip: IpAddr,
    pub helo: String,
    pub attempts: u32,
    #[serde(with = "time::serde::rfc3339::option")]
    pub next_attempt_at: Option<OffsetDateTime>,
    pub state: SpoolState,
    #[serde(default)]
    pub direction: Direction,
    #[serde(default)]
    pub tls_version: Option<String>,
    #[serde(default)]
    pub tls_cipher: Option<String>,
    #[serde(default)]
    pub rcpt_status: Vec<RcptStatus>,
    #[serde(default)]
    pub prepend_headers: Vec<String>,
    #[serde(default)]
    pub dsn_sent: bool,
    /// `pending`, `deliver`, `quarantine` or `scan_defer`. Missing on old
    /// envelopes means the pipeline has not run.
    #[serde(default = "default_pipeline")]
    pub pipeline: String,
}

fn default_pipeline() -> String {
    "pending".into()
}

impl Envelope {
    pub fn new_id() -> MessageId {
        MessageId(ulid::Ulid::new().to_string())
    }
}

/// A body being streamed into `incoming/`. Until `Spool::commit` succeeds,
/// dropping it removes the temporary file, so an abandoned transaction leaves
/// nothing behind. After a real crash `recover` deletes the `.eml.tmp`.
pub struct PendingBody {
    id: MessageId,
    dir: PathBuf,
    file: Option<tokio::io::BufWriter<tokio::fs::File>>,
    armed: bool,
}

impl PendingBody {
    pub fn id(&self) -> &MessageId {
        &self.id
    }

    pub async fn write(&mut self, bytes: &[u8]) -> Result<()> {
        if let Some(file) = self.file.as_mut() {
            file.write_all(bytes).await?;
        }
        Ok(())
    }

    fn tmp_path(&self) -> PathBuf {
        self.dir.join(format!("{}.eml.tmp", self.id))
    }
}

impl Drop for PendingBody {
    fn drop(&mut self) {
        // Crash tests panic to stop dead; a real crash runs no cleanup either.
        #[cfg(test)]
        if std::thread::panicking() {
            return;
        }
        if self.armed {
            let _ = std::fs::remove_file(self.tmp_path());
        }
    }
}

#[derive(Debug, Clone)]
pub struct Spool {
    root: PathBuf,
    /// fsyncs made while committing new messages; lets tests check that the
    /// SMTP layer only replies 250 after them.
    syncs: std::sync::Arc<std::sync::atomic::AtomicU64>,
    /// Test-only crash injection: number of durable steps left before a panic.
    #[cfg(test)]
    crash_after: Option<std::sync::Arc<std::sync::atomic::AtomicUsize>>,
}

impl Spool {
    pub async fn open(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        create_private_dir(&root, false).await?;
        for state in STATES {
            create_private_dir(&root.join(state.dir_name()), true).await?;
        }
        create_private_dir(&root.join(BAD_DIR), true).await?;
        // Make the new directory entries durable before the first 250. The
        // parent may not be ours to open, so that sync is best effort.
        sync_dir(&root).await?;
        if let Some(parent) = root.parent().filter(|p| !p.as_os_str().is_empty()) {
            if let Err(err) = sync_dir(parent).await {
                tracing::warn!(%err, dir = %parent.display(), "could not sync spool parent directory");
            }
        }
        Ok(Self {
            root,
            syncs: Default::default(),
            #[cfg(test)]
            crash_after: None,
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// File and directory fsyncs made by `commit` so far.
    pub fn commit_syncs(&self) -> u64 {
        self.syncs.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn note_sync(&self) {
        self.syncs.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }

    pub async fn accept(
        &self,
        env: Envelope,
        mut body: impl AsyncRead + Unpin,
    ) -> Result<MessageId> {
        let mut pending = self.begin(&env.id).await?;
        if let Some(file) = pending.file.as_mut() {
            if let Err(err) = tokio::io::copy(&mut body, file).await {
                // Dropping `pending` removes the partial body.
                return Err(err.into());
            }
        }
        self.commit(pending, env).await
    }

    /// Start streaming a body to `incoming/<id>.eml.tmp`. Nothing is visible
    /// to the queue until `commit`, and recovery deletes a stray `.eml.tmp`.
    pub async fn begin(&self, id: &MessageId) -> Result<PendingBody> {
        if !is_safe_id(id.as_str()) {
            return Err(SpoolError::UnsafeId(id.as_str().to_string()));
        }
        let dir = self.state_dir(SpoolState::Incoming);
        let tmp = dir.join(format!("{id}.eml.tmp"));
        let file = create_private_file(&tmp).await?;
        self.step();
        Ok(PendingBody {
            id: id.clone(),
            dir,
            file: Some(tokio::io::BufWriter::new(file)),
            armed: true,
        })
    }

    /// Make a streamed body durable and visible: fsync it, write the JSON,
    /// rename the eml into place, sync the directory. Only after `Ok` may the
    /// caller reply 250. On error nothing of the message is left behind.
    pub async fn commit(&self, mut pending: PendingBody, mut env: Envelope) -> Result<MessageId> {
        env.id = pending.id.clone();
        env.state = SpoolState::Incoming;
        let mut placed = false;
        if let Err(err) = self.commit_files(&mut pending, &env, &mut placed).await {
            // The caller replies 451, so nothing may stay behind to be
            // delivered twice when the client retries. The eml goes first so a
            // crash here leaves at most a JSON with no eml, which recovery drops.
            let id = &env.id;
            let mut names = vec![format!("{id}.eml.tmp"), format!("{id}.json.tmp")];
            if placed {
                names.splice(0..0, [format!("{id}.eml"), format!("{id}.json")]);
            }
            for name in names {
                let _ = tokio::fs::remove_file(pending.dir.join(name)).await;
            }
            let _ = sync_dir(&pending.dir).await;
            pending.armed = false;
            return Err(err);
        }
        pending.armed = false;
        Ok(env.id)
    }

    async fn commit_files(
        &self,
        pending: &mut PendingBody,
        env: &Envelope,
        placed: &mut bool,
    ) -> Result<()> {
        let dir = pending.dir.clone();
        let eml_tmp = pending.tmp_path();
        let eml = dir.join(format!("{}.eml", env.id));
        if let Some(file) = pending.file.as_mut() {
            file.flush().await?;
            file.get_mut().sync_all().await?;
            self.note_sync();
        }
        pending.file = None;
        self.step();
        // JSON before eml: an eml in a state directory always has its envelope.
        *placed = true;
        self.write_json(&dir, env).await?;
        self.note_sync();
        tokio::fs::rename(&eml_tmp, &eml).await?;
        self.step();
        sync_dir(&dir).await?;
        self.note_sync();
        self.step();
        Ok(())
    }

    pub async fn transition(&self, id: &MessageId, to: SpoolState) -> Result<()> {
        let mut env = self.load(id).await?;
        let from = env.state;
        if from == to {
            return Ok(());
        }
        let from_dir = self.state_dir(from);
        let to_dir = self.state_dir(to);
        env.state = to;
        // Destination JSON first, then the eml, then drop the source JSON.
        // Recovery treats the JSON beside the eml as live, so a crash at any
        // point leaves the message whole in either `from` or `to`.
        self.write_json(&to_dir, &env).await?;
        tokio::fs::rename(
            from_dir.join(format!("{id}.eml")),
            to_dir.join(format!("{id}.eml")),
        )
        .await?;
        self.step();
        sync_dir(&to_dir).await?;
        self.step();
        sync_dir(&from_dir).await?;
        self.step();
        remove_if_present(&from_dir.join(format!("{id}.json"))).await?;
        self.step();
        sync_dir(&from_dir).await?;
        self.step();
        Ok(())
    }

    pub async fn update(&self, env: &Envelope) -> Result<()> {
        if !is_safe_id(env.id.as_str()) {
            return Err(SpoolError::UnsafeId(env.id.0.clone()));
        }
        let dir = self.state_dir(env.state);
        self.write_json(&dir, env).await?;
        sync_dir(&dir).await?;
        self.step();
        Ok(())
    }

    /// Load the envelope that sits beside the message's eml.
    pub async fn load(&self, id: &MessageId) -> Result<Envelope> {
        if !is_safe_id(id.as_str()) {
            return Err(SpoolError::UnsafeId(id.0.clone()));
        }
        for state in STATES {
            let dir = self.state_dir(state);
            if tokio::fs::try_exists(dir.join(format!("{id}.eml"))).await?
                && tokio::fs::try_exists(dir.join(format!("{id}.json"))).await?
            {
                return read_envelope(&dir, id.as_str(), state).await;
            }
        }
        Err(SpoolError::NotFound(id.0.clone()))
    }

    pub async fn read_body(&self, id: &MessageId) -> Result<Vec<u8>> {
        let env = self.load(id).await?;
        let path = self.state_dir(env.state).join(format!("{}.eml", id));
        Ok(tokio::fs::read(path).await?)
    }

    /// Messages in `state`. Entries that cannot be read are logged and
    /// skipped so one bad file cannot stop the whole queue.
    pub async fn list(&self, state: SpoolState) -> Result<Vec<Envelope>> {
        let dir = self.state_dir(state);
        let mut out = Vec::new();
        for id in self.ids_with(&dir, ".json").await? {
            match tokio::fs::try_exists(dir.join(format!("{id}.eml"))).await {
                // A JSON with no eml beside it is stale or mid-transition.
                Ok(false) => continue,
                Ok(true) => {}
                Err(err) => {
                    tracing::warn!(%id, %err, "skipping unreadable spool entry");
                    continue;
                }
            }
            match read_envelope(&dir, &id, state).await {
                Ok(env) => out.push(env),
                // Moved by a concurrent transition.
                Err(SpoolError::Io(err)) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => tracing::warn!(%id, %err, "skipping unreadable spool entry"),
            }
        }
        Ok(out)
    }

    /// Finish or roll back anything a crash interrupted, then move orphaned
    /// `active/` messages back to `incoming/` so a crash cannot lose accepted
    /// mail. Returns the messages the daemon still has to process.
    pub async fn recover(&self) -> Result<Vec<Envelope>> {
        for state in STATES {
            self.delete_tmp(state).await?;
        }
        self.repair().await?;
        for env in self.list(SpoolState::Active).await? {
            self.transition(&env.id, SpoolState::Incoming).await?;
        }
        let mut recovered = self.list(SpoolState::Incoming).await?;
        recovered.extend(self.list(SpoolState::Deferred).await?);
        Ok(recovered)
    }

    /// Leave every message as exactly one eml and JSON pair in one state
    /// directory, removing stale JSON and quarantining what cannot be read.
    async fn repair(&self) -> Result<()> {
        let mut ids = BTreeSet::new();
        for state in STATES {
            let dir = self.state_dir(state);
            ids.extend(self.ids_with(&dir, ".eml").await?);
            ids.extend(self.ids_with(&dir, ".json").await?);
        }
        for id in ids {
            self.repair_one(&id).await?;
        }
        Ok(())
    }

    /// Every step leaves a state from which a rerun picks the same home, so a
    /// crash during recovery is repaired by the next recovery.
    async fn repair_one(&self, id: &str) -> Result<()> {
        let eml = format!("{id}.eml");
        let json = format!("{id}.json");
        let mut emls = Vec::new();
        let mut jsons = Vec::new();
        for state in STATES {
            let dir = self.state_dir(state);
            if tokio::fs::try_exists(dir.join(&eml)).await? {
                emls.push(state);
            }
            if tokio::fs::try_exists(dir.join(&json)).await? {
                jsons.push(state);
            }
        }
        if emls.is_empty() {
            // Only a crash inside `accept` leaves a JSON with no eml, and that
            // was before the 250, so there is no message to keep.
            for state in jsons {
                tracing::warn!(%id, state = state.dir_name(), "removing envelope with no message");
                self.remove_json(state, id).await?;
            }
            return Ok(());
        }
        // Home is the first eml with a readable envelope beside it, else the
        // first eml.
        let mut home = emls[0];
        let mut paired = false;
        for &state in &emls {
            if jsons.contains(&state)
                && read_envelope(&self.state_dir(state), id, state)
                    .await
                    .is_ok()
            {
                home = state;
                paired = true;
                break;
            }
        }
        if !paired {
            if jsons.contains(&home) {
                tracing::warn!(%id, state = home.dir_name(), "quarantining unreadable envelope");
                self.quarantine(home, &json).await?;
                jsons.retain(|&state| state != home);
            }
            // Split by an older spool that moved the eml before the JSON, or
            // the envelope beside the eml was unreadable: adopt the first
            // readable envelope from another directory.
            let mut adopted = None;
            for &state in &jsons {
                if let Ok(env) = read_envelope(&self.state_dir(state), id, state).await {
                    adopted = Some(env);
                    break;
                }
            }
            let Some(mut env) = adopted else {
                tracing::warn!(%id, state = home.dir_name(), "quarantining message with no envelope");
                for state in emls {
                    self.quarantine(state, &eml).await?;
                }
                for state in jsons {
                    self.quarantine(state, &json).await?;
                }
                return Ok(());
            };
            tracing::warn!(%id, state = home.dir_name(), "rejoining envelope with its message");
            env.state = home;
            let home_dir = self.state_dir(home);
            self.write_json(&home_dir, &env).await?;
            sync_dir(&home_dir).await?;
            self.step();
        }
        // A second copy of the message is kept for an operator, out of the queue.
        for state in emls {
            if state != home {
                tracing::warn!(%id, state = state.dir_name(), "quarantining duplicate message");
                if jsons.contains(&state) {
                    self.quarantine(state, &json).await?;
                    jsons.retain(|&other| other != state);
                }
                self.quarantine(state, &eml).await?;
            }
        }
        for state in jsons {
            if state != home {
                self.remove_json(state, id).await?;
            }
        }
        Ok(())
    }

    async fn remove_json(&self, state: SpoolState, id: &str) -> Result<()> {
        let dir = self.state_dir(state);
        remove_if_present(&dir.join(format!("{id}.json"))).await?;
        self.step();
        sync_dir(&dir).await?;
        Ok(())
    }

    /// Move `name` from a state directory into `bad/`, never over an
    /// earlier quarantined file.
    async fn quarantine(&self, state: SpoolState, name: &str) -> Result<()> {
        let dir = self.state_dir(state);
        let bad = self.root.join(BAD_DIR);
        let mut target = bad.join(name);
        let mut n = 1;
        while tokio::fs::try_exists(&target).await? {
            target = bad.join(format!("{name}.{n}"));
            n += 1;
        }
        tokio::fs::rename(dir.join(name), target).await?;
        self.step();
        sync_dir(&bad).await?;
        sync_dir(&dir).await?;
        Ok(())
    }

    /// Safe ids of files in `dir` ending in `suffix`.
    async fn ids_with(&self, dir: &Path, suffix: &str) -> Result<Vec<String>> {
        let mut out = Vec::new();
        let mut rd = tokio::fs::read_dir(dir).await?;
        while let Some(entry) = rd.next_entry().await? {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if let Some(id) = name.strip_suffix(suffix) {
                if is_safe_id(id) {
                    out.push(id.to_string());
                }
            }
        }
        Ok(out)
    }

    async fn delete_tmp(&self, state: SpoolState) -> Result<()> {
        let dir = self.state_dir(state);
        let mut rd = tokio::fs::read_dir(&dir).await?;
        while let Some(entry) = rd.next_entry().await? {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.ends_with(".tmp") {
                tokio::fs::remove_file(entry.path()).await?;
                self.step();
            }
        }
        Ok(())
    }

    fn state_dir(&self, state: SpoolState) -> PathBuf {
        self.root.join(state.dir_name())
    }

    async fn write_json(&self, dir: &Path, env: &Envelope) -> Result<()> {
        let tmp = dir.join(format!("{}.json.tmp", env.id));
        let final_path = dir.join(format!("{}.json", env.id));
        {
            let mut file = create_private_file(&tmp).await?;
            self.step();
            let bytes = serde_json::to_vec_pretty(env)?;
            file.write_all(&bytes).await?;
            file.sync_all().await?;
            self.step();
        }
        tokio::fs::rename(tmp, final_path).await?;
        self.step();
        Ok(())
    }

    /// Marks a point where the on-disk state is what a crash would leave.
    /// Tests panic here to stop the operation dead, skipping any cleanup.
    fn step(&self) {
        #[cfg(test)]
        if let Some(left) = &self.crash_after {
            if left.fetch_sub(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                panic!("injected crash");
            }
        }
    }
}

/// Retry schedule from ADR 0001: 5m, 15m, 30m, 1h, then hourly.
/// `attempts` is the number of failures so far (1 after the first failure).
pub fn next_retry(attempts: u32) -> Duration {
    match attempts {
        0 | 1 => Duration::from_secs(5 * 60),
        2 => Duration::from_secs(15 * 60),
        3 => Duration::from_secs(30 * 60),
        _ => Duration::from_secs(60 * 60),
    }
}

pub fn is_safe_id(id: &str) -> bool {
    id.len() == 26
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() && !c.is_ascii_lowercase())
}

async fn read_envelope(dir: &Path, id: &str, state: SpoolState) -> Result<Envelope> {
    let bytes = tokio::fs::read(dir.join(format!("{id}.json"))).await?;
    let mut env: Envelope = serde_json::from_slice(&bytes)?;
    if env.id.as_str() != id {
        return Err(SpoolError::IdMismatch {
            file: format!("{}/{id}.json", state.dir_name()),
            found: env.id.0,
        });
    }
    env.state = state;
    Ok(env)
}

async fn remove_if_present(path: &Path) -> Result<()> {
    match tokio::fs::remove_file(path).await {
        Err(err) if err.kind() != std::io::ErrorKind::NotFound => Err(err.into()),
        _ => Ok(()),
    }
}

/// Message files are readable by the spool owner only.
async fn create_private_file(path: &Path) -> Result<tokio::fs::File> {
    let mut opts = tokio::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    opts.mode(0o600);
    Ok(opts.open(path).await?)
}

/// Create `dir` as owner-only. State directories belong to the spool, so
/// existing ones are tightened too; the root may be operator-provided.
async fn create_private_dir(dir: &Path, tighten: bool) -> Result<()> {
    let mut builder = tokio::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    builder.mode(0o700);
    builder.create(dir).await?;
    #[cfg(unix)]
    if tighten {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).await?;
    }
    #[cfg(not(unix))]
    let _ = tighten;
    Ok(())
}

async fn sync_dir(dir: &Path) -> Result<()> {
    let dir = dir.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let file = std::fs::File::open(&dir)?;
        file.sync_all()?;
        Ok::<(), std::io::Error>(())
    })
    .await
    .map_err(|err| SpoolError::Join(err.to_string()))??;
    Ok(())
}
