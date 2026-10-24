//! CAPEv2 /apiv2, not the legacy Cuckoo REST API.
use super::{Sandbox, SandboxStatus, SandboxVerdict, TaskId};
use crate::service_http::{credential, EngineHttp, ServiceError};
use async_trait::async_trait;
use currawong_core::{config::SandboxConfig, residency::ResidencyGuard, Secret};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{sync::Arc, time::Duration};

pub struct Cape {
    http: EngineHttp,
    token: Option<Secret<String>>,
}
impl Cape {
    pub fn new(cfg: &SandboxConfig, guard: Arc<ResidencyGuard>) -> Result<Self, String> {
        if cfg.kind != "cape" {
            return Err("only CAPEv2 is supported".into());
        }
        Ok(Self {
            http: EngineHttp::new(&cfg.url, guard, Duration::from_secs(15), true)?,
            token: credential(cfg.token_file.as_deref())?,
        })
    }
    fn headers(&self) -> Vec<(String, String)> {
        self.token
            .as_ref()
            .map(|token| vec![("Authorization".into(), format!("Token {}", token.expose()))])
            .unwrap_or_default()
    }
    async fn get(&self, path: &str) -> Result<serde_json::Value, ServiceError> {
        let body = self
            .http
            .send(
                reqwest::Method::GET,
                path,
                &self.headers(),
                Vec::new(),
                8 * 1024 * 1024,
            )
            .await?;
        let value: serde_json::Value = serde_json::from_slice(&body)
            .map_err(|_| ServiceError::invalid("invalid CAPE JSON"))?;
        if value.get("error").and_then(|v| v.as_bool()) == Some(true) {
            return Err(ServiceError::unavailable("CAPE API returned an error"));
        }
        Ok(value)
    }
}

#[async_trait]
impl Sandbox for Cape {
    async fn submit(
        &self,
        bytes: &[u8],
        filename: &str,
        content_type: &str,
    ) -> Result<TaskId, ServiceError> {
        // The digest makes a per-content boundary. Check it as well, so no
        // attachment can inject another multipart field.
        let mut boundary = format!("currawong-{}", hex::encode(Sha256::digest(bytes)));
        while bytes
            .windows(boundary.len())
            .any(|w| w == boundary.as_bytes())
        {
            boundary.push('x');
        }
        let filename: String = filename
            .chars()
            .take(200)
            .map(|c| {
                if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        let filename = if filename.is_empty() {
            "attachment"
        } else {
            &filename
        };
        let content_type = if content_type
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"/.-+".contains(&c))
            && content_type.contains('/')
        {
            content_type
        } else {
            "application/octet-stream"
        };
        let mut body = format!("--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\nContent-Type: {content_type}\r\n\r\n").into_bytes();
        body.extend_from_slice(bytes);
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        let mut headers = self.headers();
        headers.push((
            "Content-Type".into(),
            format!("multipart/form-data; boundary={boundary}"),
        ));
        let body = self
            .http
            .send(
                reqwest::Method::POST,
                "apiv2/tasks/create/file/",
                &headers,
                body,
                64 * 1024,
            )
            .await?;
        #[derive(Deserialize)]
        struct Created {
            error: bool,
            data: Option<CreatedData>,
        }
        #[derive(Deserialize)]
        struct CreatedData {
            task_ids: Vec<u64>,
        }
        let response: Created = serde_json::from_slice(&body)
            .map_err(|_| ServiceError::invalid("invalid CAPE create JSON"))?;
        if response.error {
            return Err(ServiceError::unavailable("CAPE submission rejected"));
        }
        let tasks = response
            .data
            .ok_or_else(|| ServiceError::invalid("CAPE create has no task IDs"))?
            .task_ids;
        if tasks.len() != 1 || tasks[0] == 0 {
            return Err(ServiceError::invalid(
                "CAPE must return exactly one positive task ID",
            ));
        }
        Ok(TaskId(tasks[0].to_string()))
    }
    async fn status(&self, task: &TaskId) -> Result<SandboxStatus, ServiceError> {
        let id: u64 = task
            .0
            .parse()
            .map_err(|_| ServiceError::invalid("invalid CAPE task ID"))?;
        let value = self.get(&format!("apiv2/tasks/status/{id}/")).await?;
        let status = value
            .get("data")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ServiceError::invalid("CAPE status has no state"))?;
        match status {
            "pending" | "running" | "completed" | "distributed" | "recovered" => {
                Ok(SandboxStatus::Pending)
            }
            "reported" => {
                let path = format!("apiv2/tasks/get/report/{id}/json/");
                let report = self.get(&path).await?;
                let score = report
                    .get("malscore")
                    .and_then(|v| v.as_f64())
                    .filter(|s| s.is_finite() && (0.0..=10.0).contains(s))
                    .ok_or_else(|| ServiceError::invalid("CAPE report has no valid malscore"))?;
                let signatures = report
                    .get("signatures")
                    .and_then(|v| v.as_array())
                    .ok_or_else(|| ServiceError::invalid("CAPE report has no signatures array"))?;
                let signatures = signatures
                    .iter()
                    .take(256)
                    .map(|s| {
                        s.get("name")
                            .and_then(|v| v.as_str())
                            .map(|s| s.chars().take(256).collect())
                            .ok_or_else(|| ServiceError::invalid("CAPE signature has no name"))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(SandboxStatus::Done(SandboxVerdict {
                    malicious: score >= 5.0,
                    score: score / 10.0,
                    signatures,
                    report_url: Some(self.http.endpoint(&path).into()),
                }))
            }
            "failed_analysis" | "failed_processing" | "failed_reporting" | "banned" => {
                Ok(SandboxStatus::Failed(format!("CAPE task {status}")))
            }
            _ => Err(ServiceError::invalid("unknown CAPE task status")),
        }
    }
}
