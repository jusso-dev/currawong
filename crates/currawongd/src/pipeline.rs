//! Auth, parse, scan, classify and the policy decision.
use currawong_auth::AuthChecker;
use currawong_classify::{message::MAX_RAW_BYTES, Classifier, TenantContext};
use currawong_core::{config::Config, AuthResults, EngineFinding, PartFlag, ScanReport, Verdict};
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
    /// Spam and lookalike scoring. `None` when `classify.enabled` is off or
    /// the classifier failed to load (`classify_error`, noted on each report).
    pub classifier: Option<Arc<Classifier>>,
    pub classify_error: Option<String>,
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
        // `--check-config` has already loaded the rules and brands, so a
        // failure here is logged rather than stopping the daemon.
        let (classifier, classify_error) =
            match cfg.classify.enabled.then(|| Classifier::from_config(&cfg)) {
                Some(Ok(classifier)) => (Some(Arc::new(classifier)), None),
                Some(Err(err)) => {
                    tracing::error!(%err, "classifier disabled");
                    (None, Some(err.to_string()))
                }
                None => (None, None),
            };
        Self {
            cfg,
            auth,
            pool,
            classifier,
            classify_error,
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
        report.auth = Some(auth);
        if !self.cfg.scanner.enabled {
            self.classify(env, raw, &mut report).await;
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
        self.classify(env, raw, &mut report).await;
        let verdict = decide(&report);
        (report, verdict)
    }

    /// Classification is CPU and SQLite work, so it runs off the async workers.
    async fn classify(&self, env: &Envelope, raw: &[u8], report: &mut ScanReport) {
        let Some(classifier) = self.classifier.clone() else {
            if let Some(err) = &self.classify_error {
                report.notes.push(format!("classifier unavailable: {err}"));
            }
            return;
        };
        let tenant = tenant_context(&self.cfg, env);
        // One byte past the cap so the classifier still notes the truncation.
        let raw = raw[..raw.len().min(MAX_RAW_BYTES + 1)].to_vec();
        let sender = env.mail_from.clone();
        let urls = report.urls.clone();
        match tokio::task::spawn_blocking(move || {
            classifier.classify(&tenant, &raw, &sender, &urls)
        })
        .await
        {
            Ok(result) => {
                report.spam = Some(result.spam);
                report.lookalikes = result.lookalikes;
                report.notes.extend(result.notes);
            }
            Err(err) => report.notes.push(format!("classifier failed: {err}")),
        }
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

/// The tenant a message is classified for: the relay tenant that submitted
/// it, else the tenant owning the first recipient domain that one claims,
/// else the first recipient domain on its own. Per-recipient tenancy belongs
/// to the policy engine; this only picks the Bayes store and protected domains.
fn tenant_context(cfg: &Config, env: &Envelope) -> TenantContext {
    let tenants = &cfg.relay.tenants;
    if let Some(id) = &env.tenant_id {
        let domains = tenants
            .iter()
            .find(|tenant| &tenant.id == id)
            .map(|tenant| tenant.domains.clone())
            .unwrap_or_default();
        return TenantContext::tenant(id, &domains);
    }
    let recipient_domains: Vec<&str> = env
        .rcpt_to
        .iter()
        .filter_map(|rcpt| rcpt.rsplit_once('@'))
        .map(|(_, domain)| domain.trim_end_matches('>'))
        .collect();
    for domain in &recipient_domains {
        if let Some(tenant) = tenants.iter().find(|tenant| {
            tenant
                .domains
                .iter()
                .any(|owned| owned.eq_ignore_ascii_case(domain))
        }) {
            return TenantContext::tenant(&tenant.id, &tenant.domains);
        }
    }
    TenantContext::domain(recipient_domains.first().copied().unwrap_or("unknown"))
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
