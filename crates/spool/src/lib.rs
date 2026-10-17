//! Durable on-disk spool. See ADR 0001.
//!
//! A 250 reply is only returned after the message file and its metadata have
//! been renamed into place and the directory has been synced.
use currawong_core::{Direction, MessageId};
use serde::{Deserialize, Serialize};
use std::{
    net::IpAddr,
    path::{Path, PathBuf},
    time::Duration,
};
use time::OffsetDateTime;
use tokio::io::{AsyncRead, AsyncWriteExt};

pub use currawong_core::Error as CoreError;

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

#[derive(Debug, Clone)]
pub struct Spool {
    root: PathBuf,
}

impl Spool {
    pub async fn open(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        for state in [
            SpoolState::Incoming,
            SpoolState::Active,
            SpoolState::Deferred,
            SpoolState::Done,
        ] {
            tokio::fs::create_dir_all(root.join(state.dir_name())).await?;
        }
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub async fn accept(
        &self,
        mut env: Envelope,
        mut body: impl AsyncRead + Unpin,
    ) -> Result<MessageId> {
        if !is_safe_id(env.id.as_str()) {
            return Err(SpoolError::UnsafeId(env.id.as_str().to_string()));
        }
        env.state = SpoolState::Incoming;
        let dir = self.state_dir(SpoolState::Incoming);
        let eml_tmp = dir.join(format!("{}.eml.tmp", env.id));
        let eml = dir.join(format!("{}.eml", env.id));
        {
            let mut file = tokio::fs::File::create(&eml_tmp).await?;
            tokio::io::copy(&mut body, &mut file).await?;
            file.sync_all().await?;
        }
        tokio::fs::rename(&eml_tmp, &eml).await?;
        self.write_json(&dir, &env).await?;
        sync_dir(&dir).await?;
        Ok(env.id)
    }

    pub async fn transition(&self, id: &MessageId, to: SpoolState) -> Result<()> {
        let mut env = self.load(id).await?;
        let from = env.state;
        if from == to {
            return Ok(());
        }
        let from_dir = self.state_dir(from);
        let to_dir = self.state_dir(to);
        let eml_from = from_dir.join(format!("{}.eml", id));
        let eml_to = to_dir.join(format!("{}.eml", id));
        tokio::fs::rename(&eml_from, &eml_to).await?;
        env.state = to;
        // JSON is renamed last so a crash between the two renames is visible.
        let json_from = from_dir.join(format!("{}.json", id));
        let _ = tokio::fs::remove_file(&json_from).await;
        self.write_json(&to_dir, &env).await?;
        sync_dir(&to_dir).await?;
        Ok(())
    }

    pub async fn update(&self, env: &Envelope) -> Result<()> {
        if !is_safe_id(env.id.as_str()) {
            return Err(SpoolError::UnsafeId(env.id.0.clone()));
        }
        let dir = self.state_dir(env.state);
        self.write_json(&dir, env).await?;
        sync_dir(&dir).await?;
        Ok(())
    }

    pub async fn load(&self, id: &MessageId) -> Result<Envelope> {
        for state in [
            SpoolState::Incoming,
            SpoolState::Active,
            SpoolState::Deferred,
            SpoolState::Done,
        ] {
            let path = self.state_dir(state).join(format!("{}.json", id));
            if tokio::fs::try_exists(&path).await? {
                let bytes = tokio::fs::read(&path).await?;
                let mut env: Envelope = serde_json::from_slice(&bytes)?;
                env.state = state;
                return Ok(env);
            }
        }
        Err(SpoolError::NotFound(id.0.clone()))
    }

    pub async fn read_body(&self, id: &MessageId) -> Result<Vec<u8>> {
        let env = self.load(id).await?;
        let path = self.state_dir(env.state).join(format!("{}.eml", id));
        Ok(tokio::fs::read(path).await?)
    }

    pub async fn list(&self, state: SpoolState) -> Result<Vec<Envelope>> {
        let mut out = Vec::new();
        let mut dir = tokio::fs::read_dir(self.state_dir(state)).await?;
        while let Some(entry) = dir.next_entry().await? {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if let Some(id) = name.strip_suffix(".json") {
                if is_safe_id(id) {
                    out.push(self.load(&MessageId(id.to_string())).await?);
                }
            }
        }
        Ok(out)
    }

    /// Delete stray temporary files and move orphaned `active/` messages back
    /// to `incoming/` so a crash cannot lose accepted mail.
    pub async fn recover(&self) -> Result<Vec<Envelope>> {
        for state in [
            SpoolState::Incoming,
            SpoolState::Active,
            SpoolState::Deferred,
            SpoolState::Done,
        ] {
            self.delete_tmp(state).await?;
        }
        let active = self.list(SpoolState::Active).await?;
        for env in active {
            self.transition(&env.id, SpoolState::Incoming).await?;
        }
        self.repair_split_pairs().await?;
        let mut recovered = self.list(SpoolState::Incoming).await?;
        recovered.extend(self.list(SpoolState::Deferred).await?);
        Ok(recovered)
    }

    async fn repair_split_pairs(&self) -> Result<()> {
        // An eml that moved without its json is finished by writing json into
        // the directory that holds the eml.
        for state in [
            SpoolState::Incoming,
            SpoolState::Active,
            SpoolState::Deferred,
            SpoolState::Done,
        ] {
            let dir = self.state_dir(state);
            let mut rd = tokio::fs::read_dir(&dir).await?;
            while let Some(entry) = rd.next_entry().await? {
                let name = entry.file_name();
                let name = name.to_string_lossy().to_string();
                let Some(id) = name.strip_suffix(".eml") else {
                    continue;
                };
                if !is_safe_id(id) {
                    continue;
                }
                let json = dir.join(format!("{id}.json"));
                if tokio::fs::try_exists(&json).await? {
                    continue;
                }
                if let Ok(mut env) = self.load_any_json(id).await {
                    env.state = state;
                    self.write_json(&dir, &env).await?;
                    for other in [
                        SpoolState::Incoming,
                        SpoolState::Active,
                        SpoolState::Deferred,
                        SpoolState::Done,
                    ] {
                        if other == state {
                            continue;
                        }
                        let stray = self.state_dir(other).join(format!("{id}.json"));
                        let _ = tokio::fs::remove_file(stray).await;
                    }
                }
            }
        }
        Ok(())
    }

    async fn load_any_json(&self, id: &str) -> Result<Envelope> {
        self.load(&MessageId(id.to_string())).await
    }

    async fn delete_tmp(&self, state: SpoolState) -> Result<()> {
        let dir = self.state_dir(state);
        let mut rd = tokio::fs::read_dir(&dir).await?;
        while let Some(entry) = rd.next_entry().await? {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.ends_with(".tmp") {
                tokio::fs::remove_file(entry.path()).await?;
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
            let mut file = tokio::fs::File::create(&tmp).await?;
            let bytes = serde_json::to_vec_pretty(env)?;
            file.write_all(&bytes).await?;
            file.sync_all().await?;
        }
        tokio::fs::rename(tmp, final_path).await?;
        Ok(())
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
