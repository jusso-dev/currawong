//! Auth, parse, scan and the M1 policy decision.
use currawong_auth::{strip_forged, AuthChecker, KeyStore, StoredKey, GATEWAY_TENANT};
use currawong_core::{
    config::Config, AuthResults, Direction, EngineFinding, PartFlag, ScanReport, Verdict,
};
use currawong_parser::{parse::parse_bytes, ParseResponse};
use currawong_policy::decide;
use currawong_scan::{
    combine, ClamdAddress, ClamdClient, EngineOutput, FileTypeScanner, ScanItem, ScanOutcome,
    Scanner, WorkerPool,
};
use currawong_spool::Envelope;
use std::{path::Path, sync::Arc};

pub struct Pipeline {
    pub cfg: Arc<Config>,
    pub auth: AuthChecker,
    pub pool: Option<WorkerPool>,
    /// DKIM and ARC keys. `None` means nothing is signed or sealed.
    pub keys: Option<Arc<KeyStore>>,
}

impl Pipeline {
    pub fn new(cfg: Arc<Config>, auth: AuthChecker) -> Self {
        let pool = worker_binary(&cfg).map(|binary| {
            WorkerPool::new(
                binary,
                cfg.scanner.job_timeout_secs,
                cfg.scanner.max_jobs_per_worker as u64,
            )
            .with_limits(cfg.scanner.worker_memory_mib, cfg.scanner.worker_cpu_secs)
        });
        Self {
            cfg,
            auth,
            pool,
            keys: None,
        }
    }

    pub fn with_keys(mut self, keys: KeyStore) -> Self {
        self.keys = Some(Arc::new(keys));
        self
    }

    /// Evaluate a spooled message and build the headers to prepend. Forged
    /// Authentication-Results left in older spool files are stripped from
    /// `body_path` first, so they are never delivered. A DKIM signing
    /// failure defers rather than sending the mail unsigned.
    pub async fn classify(
        &mut self,
        env: &Envelope,
        raw: &[u8],
        body_path: Option<&Path>,
    ) -> (ScanReport, Verdict, Vec<String>) {
        let cleaned = strip_forged(raw, self.auth.authserv_id());
        if cleaned.len() != raw.len() {
            if let Some(path) = body_path {
                if let Err(err) = rewrite_body(path, &cleaned).await {
                    let reason = format!("could not strip forged headers: {err}");
                    let report = ScanReport::new(env.id.clone());
                    return (report, Verdict::Defer { reason }, Vec::new());
                }
            }
        }
        let (report, verdict) = self.evaluate(env, &cleaned, body_path).await;
        if !matches!(verdict, Verdict::Deliver) {
            let headers = self.auth_headers(env, &report);
            return (report, verdict, headers);
        }
        match self.delivery_headers(env, &cleaned, &report).await {
            Ok(headers) => (report, verdict, headers),
            Err(reason) => {
                tracing::error!(id = %env.id, %reason, "deferring: outbound signing failed");
                (report, Verdict::Defer { reason }, Vec::new())
            }
        }
    }

    /// Our Authentication-Results, for inbound mail only: on outbound mail
    /// it would leak internal addresses and attest a meaningless SPF result.
    fn auth_headers(&self, env: &Envelope, report: &ScanReport) -> Vec<String> {
        match env.direction {
            Direction::Inbound => report.auth.iter().map(auth_header).collect(),
            Direction::Outbound => Vec::new(),
        }
    }

    /// Headers the deliverer prepends. Inbound: Authentication-Results, plus
    /// an ARC set when a stage modified the message. Outbound: DKIM
    /// signatures with the tenant's active keys. Replaces any earlier set so
    /// re-evaluating deferred mail never stacks. `Err` when the tenant has a
    /// key but signing failed.
    pub async fn delivery_headers(
        &self,
        env: &Envelope,
        raw: &[u8],
        report: &ScanReport,
    ) -> Result<Vec<String>, String> {
        if env.direction == Direction::Inbound {
            if report.modified {
                if let Some(sealer) = self.arc_sealer().await {
                    let sealed = self.auth.check_and_seal(raw, env, Some(&sealer)).await;
                    return Ok(vec![sealed.header]);
                }
            }
            return Ok(self.auth_headers(env, report));
        }
        let (Some(keys), Some(tenant), true) =
            (&self.keys, &env.tenant_id, self.cfg.dkim.sign_outbound)
        else {
            return Ok(Vec::new());
        };
        let (keys, tenant_id, owned) = (Arc::clone(keys), tenant.clone(), raw.to_vec());
        let signed = tokio::task::spawn_blocking(move || {
            currawong_auth::sign_outbound(&keys, &owned, &tenant_id)
        })
        .await
        .map_err(|err| err.to_string())??;
        if signed.is_empty() {
            tracing::warn!(id = %env.id, %tenant, "no active DKIM key for sender domain");
            return Ok(Vec::new());
        }
        Ok(vec![signed])
    }

    /// Active gateway key for the authserv-id domain, RSA first because
    /// RFC 8617 verifiers are only required to support rsa-sha256.
    async fn arc_sealer(&self) -> Option<StoredKey> {
        if !self.cfg.dkim.seal_arc {
            return None;
        }
        let keys = Arc::clone(self.keys.as_ref()?);
        let domain = self.auth.authserv_id().to_string();
        let found =
            tokio::task::spawn_blocking(move || keys.signing_keys(GATEWAY_TENANT, &domain, now()))
                .await
                .map_err(|err| err.to_string())
                .and_then(|found| found);
        match found {
            Ok(mut found) => {
                found.sort_by_key(|key| key.algorithm != "rsa-sha256");
                found.into_iter().next()
            }
            Err(err) => {
                tracing::error!(%err, "ARC key lookup failed");
                None
            }
        }
    }

    pub async fn evaluate(
        &mut self,
        env: &Envelope,
        raw: &[u8],
        body_path: Option<&Path>,
    ) -> (ScanReport, Verdict) {
        let mut report = ScanReport::new(env.id.clone());
        let auth = self.auth.check(raw, env).await;
        // The DMARC record could not be fetched, so its policy is unknown:
        // retry rather than deliver a possible p=reject spoof.
        if auth.dmarc.result == "temperror" {
            report.defer = true;
            report
                .notes
                .push("dmarc temperror: policy DNS unreachable".into());
        }
        report.auth = Some(auth);
        if !self.cfg.scanner.enabled {
            let verdict = decide(&report);
            return (report, verdict);
        }
        let parsed = self.parse(env, raw, body_path).await;
        report.parts = parsed.parts.clone();
        report.urls = parsed.urls.clone();
        let parser_failed = parsed.error.is_some();
        if let Some(err) = parsed.error {
            report.notes.push(err);
        }
        self.fold_part_flags(&mut report);
        let mut outputs = Vec::new();
        let filetype = FileTypeScanner {
            treat_macros_as_active: self.cfg.scanner.treat_macros_as_active,
            treat_executables_as_active: self.cfg.scanner.treat_executables_as_active,
            limits: self.cfg.scanner.extract.clone(),
        };
        let result = filetype
            .scan(&ScanItem {
                name: "message.eml",
                bytes: raw,
            })
            .await;
        outputs.push(finding("filetype", &result));
        if !self.cfg.scanner.clamd.address.is_empty() {
            match ClamdAddress::parse(&self.cfg.scanner.clamd.address) {
                Ok(address) => {
                    let client = ClamdClient::new(address, self.cfg.scanner.clamd.required);
                    let result = client
                        .scan(&ScanItem {
                            name: "message.eml",
                            bytes: raw,
                        })
                        .await;
                    let mut output = finding("clamav", &result);
                    output.required = self.cfg.scanner.clamd.required;
                    outputs.push(output);
                }
                Err(err) => {
                    outputs.push(EngineOutput {
                        name: "clamav".into(),
                        result: currawong_scan::EngineResult::Failed {
                            reason: err,
                            unreachable: self.cfg.scanner.clamd.required,
                        },
                        required: self.cfg.scanner.clamd.required,
                    });
                }
            }
        }
        let combined = combine(&outputs, parser_failed);
        report.malware = combined.malware;
        report.active_content = report.active_content || combined.active_content;
        report.defer = combined.defer;
        report.fail_closed = combined.fail_closed;
        report.notes.extend(combined.notes);
        for output in &outputs {
            report.engines.push(EngineFinding {
                engine: output.name.clone(),
                result: format!("{:?}", output.result),
                detail: String::new(),
            });
        }
        let verdict = decide(&report);
        (report, verdict)
    }

    fn fold_part_flags(&self, report: &mut ScanReport) {
        for part in &report.parts {
            if self.cfg.scanner.treat_executables_as_active
                && part.flags.contains(&PartFlag::Executable)
            {
                report.active_content = true;
                report.notes.push(format!(
                    "executable {}",
                    part.filename.as_deref().unwrap_or("attachment")
                ));
            }
            if self.cfg.scanner.treat_macros_as_active && part.flags.contains(&PartFlag::HasMacro) {
                report.active_content = true;
                report.notes.push(format!(
                    "macro {}",
                    part.filename.as_deref().unwrap_or("attachment")
                ));
            }
            if part.flags.contains(&PartFlag::LimitExceeded) {
                report.fail_closed = true;
                report
                    .notes
                    .push("archive extraction limit exceeded".into());
            }
        }
    }

    async fn parse(
        &mut self,
        env: &Envelope,
        raw: &[u8],
        body_path: Option<&Path>,
    ) -> ParseResponse {
        if let (Some(pool), Some(path)) = (self.pool.as_mut(), body_path) {
            return match pool
                .scan_file(env.id.as_str(), path, &self.cfg.scanner.extract)
                .await
            {
                ScanOutcome::Parsed(response) => response,
                ScanOutcome::Failed { reason } => ParseResponse::failed(env.id.as_str(), reason),
            };
        }
        parse_bytes(env.id.as_str(), raw, &self.cfg.scanner.extract)
    }
}

fn finding(name: &str, result: &currawong_scan::EngineResult) -> EngineOutput {
    EngineOutput {
        name: name.into(),
        result: result.clone(),
        required: false,
    }
}

pub fn worker_binary(cfg: &Config) -> Option<std::path::PathBuf> {
    if let Some(path) = &cfg.scanner.worker_binary {
        if path.exists() {
            return Some(path.clone());
        }
    }
    let exe = std::env::current_exe().ok()?;
    let candidate = exe.parent()?.join("currawong-parser-worker");
    if candidate.exists() {
        Some(candidate)
    } else {
        None
    }
}

pub fn auth_header(auth: &AuthResults) -> String {
    auth.header.clone()
}

/// Atomically replace a spool body (write beside it, fsync, rename).
async fn rewrite_body(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;
    let tmp = path.with_extension("eml.strip");
    let mut file = tokio::fs::File::create(&tmp).await?;
    file.write_all(bytes).await?;
    file.sync_all().await?;
    tokio::fs::rename(&tmp, path).await
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}
