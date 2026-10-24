//! On-premises asynchronous attachment detonation. The spool carries the
//! message; SQLite carries tasks and cached verdicts between scan attempts.
mod cache;
pub mod cape;
use crate::{EngineOutput, EngineResult, ServiceError};
use async_trait::async_trait;
use cache::{Cache, Entry};
use currawong_core::{
    config::SandboxConfig, residency::ResidencyGuard, PartFlag, PartInfo, SandboxResult,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    path::Path,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::io::AsyncReadExt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskId(pub String);
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SandboxVerdict {
    pub malicious: bool,
    /// Normalised 0..1. CAPE malscore >=5/10 is malicious.
    pub score: f64,
    pub signatures: Vec<String>,
    pub report_url: Option<String>,
}
#[derive(Debug, Clone, PartialEq)]
pub enum SandboxStatus {
    Pending,
    Done(SandboxVerdict),
    Failed(String),
}
#[async_trait]
pub trait Sandbox: Send + Sync {
    async fn submit(
        &self,
        bytes: &[u8],
        filename: &str,
        content_type: &str,
    ) -> Result<TaskId, ServiceError>;
    async fn status(&self, task: &TaskId) -> Result<SandboxStatus, ServiceError>;
}
#[derive(Default)]
pub struct Assessment {
    pub results: Vec<SandboxResult>,
    pub outputs: Vec<EngineOutput>,
    pub pending: bool,
    pub timeout: bool,
    pub notes: Vec<String>,
}
pub struct SandboxEngine {
    cfg: SandboxConfig,
    client: Arc<dyn Sandbox>,
    cache: Cache,
    service: String,
    gate: tokio::sync::Mutex<()>,
}
impl SandboxEngine {
    pub fn new(
        cfg: &SandboxConfig,
        guard: Arc<ResidencyGuard>,
        cache_path: &Path,
    ) -> Result<Self, String> {
        let client = Arc::new(cape::Cape::new(cfg, guard)?);
        Self::with_client(cfg, client, cache_path)
    }
    pub fn with_client(
        cfg: &SandboxConfig,
        client: Arc<dyn Sandbox>,
        cache_path: &Path,
    ) -> Result<Self, String> {
        Ok(Self {
            cfg: cfg.clone(),
            client,
            cache: Cache::open(cache_path)?,
            service: format!("{}:{}", cfg.kind, cfg.url.trim_end_matches('/')),
            gate: tokio::sync::Mutex::new(()),
        })
    }
    pub async fn assess(&self, parts: &[PartInfo]) -> Assessment {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .min(i64::MAX as u64) as i64;
        self.assess_at(parts, now).await
    }
    /// Explicit clock supports deterministic TTL, timeout and poll tests.
    pub async fn assess_at(&self, parts: &[PartInfo], now: i64) -> Assessment {
        let _gate = self.gate.lock().await;
        let mut assessment = Assessment::default();
        let mut seen = HashSet::new();
        for part in parts {
            if !self.selected(part) || !seen.insert(&part.sha256) {
                continue;
            }
            match self.assess_part(part, now).await {
                Ok(result) => {
                    assessment.pending |= result.status == "pending";
                    assessment.timeout |= result.status == "timeout";
                    if result.malicious {
                        assessment.outputs.push(self.output(EngineResult::Malware {
                            signature: format!(
                                "sandbox malicious ({:.1}/10): {}",
                                result.score * 10.0,
                                result.signatures.join(", ")
                            ),
                        }));
                    } else if result.status == "timeout" && self.cfg.on_timeout == "quarantine" {
                        assessment.outputs.push(self.output(EngineResult::Failed {
                            reason: "sandbox timeout; quarantine required".into(),
                            unreachable: false,
                        }));
                    } else {
                        assessment.outputs.push(self.output(EngineResult::Clean));
                    }
                    assessment.results.push(result);
                }
                Err(err) => {
                    assessment.notes.push(format!("sandbox: {err}"));
                    assessment.outputs.push(self.output(err.engine_result()));
                    assessment.results.push(SandboxResult {
                        sha256: part.sha256.clone(),
                        task_id: None,
                        status: "failed".into(),
                        malicious: false,
                        score: 0.0,
                        signatures: Vec::new(),
                        report_url: None,
                    });
                }
            }
        }
        if assessment.pending {
            assessment.notes.push("awaiting sandbox".into());
        }
        if assessment.timeout {
            assessment
                .notes
                .push(format!("sandbox timeout: {}", self.cfg.on_timeout));
        }
        assessment
    }
    fn output(&self, result: EngineResult) -> EngineOutput {
        EngineOutput {
            name: "sandbox".into(),
            result,
            required: self.cfg.required,
        }
    }
    pub fn selected(&self, part: &PartInfo) -> bool {
        let has = |name| self.cfg.submit.iter().any(|s| s == name);
        let kind = part.content_type.to_ascii_lowercase();
        let ext = part
            .filename
            .as_deref()
            .unwrap_or("")
            .rsplit('.')
            .next()
            .unwrap_or("")
            .to_ascii_lowercase();
        (has("executable")
            && (part.flags.contains(&PartFlag::Executable)
                || matches!(
                    ext.as_str(),
                    "exe" | "dll" | "scr" | "com" | "msi" | "cpl" | "lnk"
                )))
            || (has("script")
                && (kind.contains("javascript")
                    || kind.contains("powershell")
                    || kind.contains("shellscript")
                    || matches!(
                        ext.as_str(),
                        "js" | "jse"
                            | "vbs"
                            | "vbe"
                            | "ps1"
                            | "bat"
                            | "cmd"
                            | "sh"
                            | "py"
                            | "wsf"
                            | "hta"
                    )))
            || (has("office")
                && part
                    .flags
                    .iter()
                    .any(|f| matches!(f, PartFlag::HasMacro | PartFlag::HasOleObject)))
            || (has("pdf") && (kind == "application/pdf" || ext == "pdf"))
            || (has("archive")
                && (matches!(ext.as_str(), "zip" | "7z" | "rar" | "tar" | "gz")
                    || matches!(
                        kind.as_str(),
                        "application/zip"
                            | "application/x-7z-compressed"
                            | "application/x-rar-compressed"
                            | "application/x-tar"
                            | "application/gzip"
                    )))
            || (has("disk_image")
                && (matches!(ext.as_str(), "iso" | "img" | "vhd" | "vhdx" | "dmg")
                    || kind.contains("iso9660")))
            || (has("html")
                && (part.is_attachment || part.filename.is_some())
                && (kind == "text/html"
                    || matches!(ext.as_str(), "html" | "htm" | "xhtml" | "shtml")))
    }
    async fn assess_part(&self, part: &PartInfo, now: i64) -> Result<SandboxResult, ServiceError> {
        if let Some(entry) = self
            .cache
            .load(
                &self.service,
                &part.sha256,
                now,
                self.cfg.cache_ttl_secs as i64,
            )
            .await?
        {
            return self.existing(part, entry, now).await;
        }
        if part.size > self.cfg.max_file_size {
            return Err(ServiceError::invalid(
                "attachment exceeds sandbox max_file_size",
            ));
        }
        let path = part
            .path
            .as_ref()
            .ok_or_else(|| ServiceError::invalid("sandbox attachment bytes unavailable"))?;
        let file = tokio::fs::File::open(path)
            .await
            .map_err(|_| ServiceError::invalid("sandbox attachment cannot be read"))?;
        let mut bytes = Vec::new();
        file.take(self.cfg.max_file_size.saturating_add(1))
            .read_to_end(&mut bytes)
            .await
            .map_err(|_| ServiceError::invalid("sandbox attachment cannot be read"))?;
        if bytes.len() as u64 > self.cfg.max_file_size {
            return Err(ServiceError::invalid(
                "attachment exceeds sandbox max_file_size",
            ));
        }
        if hex::encode(Sha256::digest(&bytes)) != part.sha256 {
            return Err(ServiceError::invalid("sandbox attachment digest mismatch"));
        }
        if !self.cache.reserve(&self.service, &part.sha256, now).await? {
            let entry = self
                .cache
                .load(
                    &self.service,
                    &part.sha256,
                    now,
                    self.cfg.cache_ttl_secs as i64,
                )
                .await?
                .ok_or_else(|| ServiceError::unavailable("sandbox reservation disappeared"))?;
            return self.existing(part, entry, now).await;
        }
        let task = self
            .client
            .submit(
                &bytes,
                part.filename.as_deref().unwrap_or("attachment"),
                &part.content_type,
            )
            .await;
        let mut entry = Entry {
            task: None,
            submitted: now,
            polled: now,
            verdict: None,
            failed: None,
        };
        match task {
            Ok(task) => entry.task = Some(task.0),
            Err(err) => {
                // A lost HTTP reply may have created a task. Keep the
                // reservation; retries must not detonate it twice.
                entry.failed = Some(format!(
                    "{}: {}",
                    if err.unreachable {
                        "unavailable"
                    } else {
                        "invalid"
                    },
                    err.reason
                ));
                self.cache.save(&self.service, &part.sha256, entry).await?;
                return Err(err);
            }
        }
        self.cache
            .save(&self.service, &part.sha256, entry.clone())
            .await?;
        Ok(self.result(part, &entry, "pending"))
    }
    async fn existing(
        &self,
        part: &PartInfo,
        mut entry: Entry,
        now: i64,
    ) -> Result<SandboxResult, ServiceError> {
        if let Some(verdict) = &entry.verdict {
            let mut result = self.result(part, &entry, "done");
            result.malicious = verdict.malicious;
            result.score = verdict.score;
            result.signatures = verdict.signatures.clone();
            result.report_url = verdict.report_url.clone();
            return Ok(result);
        }
        if entry.failed.as_deref() == Some("timeout") {
            return Ok(self.result(part, &entry, "timeout"));
        }
        if now.saturating_sub(entry.submitted) >= self.cfg.max_wait_secs as i64 {
            entry.failed = Some("timeout".into());
            entry.polled = now;
            self.cache
                .save(&self.service, &part.sha256, entry.clone())
                .await?;
            return Ok(self.result(part, &entry, "timeout"));
        }
        if let Some(reason) = &entry.failed {
            return Err(cached_failure(reason));
        }
        if now.saturating_sub(entry.polled) < self.cfg.poll_secs as i64 {
            return Ok(self.result(part, &entry, "pending"));
        }
        let Some(task) = &entry.task else {
            return Ok(self.result(part, &entry, "pending"));
        };
        let status = self.client.status(&TaskId(task.clone())).await?;
        entry.polled = now;
        match status {
            SandboxStatus::Pending => {}
            SandboxStatus::Done(verdict) => {
                if !verdict.score.is_finite() || !(0.0..=1.0).contains(&verdict.score) {
                    return Err(ServiceError::invalid("sandbox score outside 0..1"));
                }
                entry.verdict = Some(verdict);
            }
            SandboxStatus::Failed(reason) => {
                entry.failed = Some(format!("invalid: {reason}"));
            }
        }
        self.cache
            .save(&self.service, &part.sha256, entry.clone())
            .await?;
        if let Some(reason) = &entry.failed {
            return Err(cached_failure(reason));
        }
        let mut result = self.result(
            part,
            &entry,
            if entry.verdict.is_some() {
                "done"
            } else {
                "pending"
            },
        );
        if let Some(verdict) = entry.verdict {
            result.malicious = verdict.malicious;
            result.score = verdict.score;
            result.signatures = verdict.signatures;
            result.report_url = verdict.report_url;
        }
        Ok(result)
    }
    fn result(&self, part: &PartInfo, entry: &Entry, status: &str) -> SandboxResult {
        SandboxResult {
            sha256: part.sha256.clone(),
            task_id: entry.task.clone(),
            status: status.into(),
            malicious: false,
            score: 0.0,
            signatures: Vec::new(),
            report_url: None,
        }
    }
}

fn cached_failure(reason: &str) -> ServiceError {
    if let Some(reason) = reason.strip_prefix("invalid: ") {
        ServiceError::invalid(reason)
    } else {
        ServiceError::unavailable(reason.strip_prefix("unavailable: ").unwrap_or(reason))
    }
}
