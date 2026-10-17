//! Auth, parse, scan and the M1 policy decision.
use currawong_auth::{AuthChecker, KeyStore, StoredKey, GATEWAY_TENANT};
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
    pub keys: Option<KeyStore>,
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
        self.keys = Some(keys);
        self
    }

    /// Headers the deliverer prepends: our Authentication-Results (plus the
    /// ARC set when sealing), then DKIM signatures for outbound tenant mail.
    /// Replaces any earlier set so re-evaluating deferred mail never stacks.
    pub fn delivery_headers(&self, env: &Envelope, raw: &[u8], report: &ScanReport) -> Vec<String> {
        let mut headers: Vec<String> = report.auth.iter().map(auth_header).collect();
        if let (Some(keys), Some(tenant), Direction::Outbound, true) = (
            &self.keys,
            &env.tenant_id,
            env.direction,
            self.cfg.dkim.sign_outbound,
        ) {
            match currawong_auth::sign_outbound(keys, raw, tenant) {
                Ok(signed) if !signed.is_empty() => headers.push(signed),
                Ok(_) => tracing::warn!(id = %env.id, %tenant, "no DKIM key for sender domain"),
                Err(err) => tracing::error!(id = %env.id, %err, "DKIM signing failed"),
            }
        }
        headers
    }

    /// Active gateway key for the authserv-id domain, RSA first because
    /// RFC 8617 verifiers are only required to support rsa-sha256.
    fn arc_sealer(&self) -> Option<StoredKey> {
        if !self.cfg.dkim.seal_arc {
            return None;
        }
        let keys = self.keys.as_ref()?;
        match keys.signing_keys(GATEWAY_TENANT, self.auth.authserv_id(), now()) {
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
        let sealer = self.arc_sealer();
        let auth = self.auth.check_and_seal(raw, env, sealer.as_ref()).await;
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

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}
