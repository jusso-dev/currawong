//! Auth, parse, scan and the M1 policy decision.
use currawong_auth::{AuthChecker, DmarcEventStore};
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
    /// Where inbound DMARC results go for aggregate reports.
    pub dmarc_events: Option<DmarcEventStore>,
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
            dmarc_events: None,
        }
    }

    pub fn with_dmarc_events(mut self, store: DmarcEventStore) -> Self {
        self.dmarc_events = Some(store);
        self
    }

    pub async fn evaluate(
        &mut self,
        env: &Envelope,
        raw: &[u8],
        body_path: Option<&Path>,
    ) -> (ScanReport, Verdict) {
        let mut report = ScanReport::new(env.id.clone());
        let auth = self.auth.evaluate(raw, env).await;
        if let (Some(store), Some(event)) = (&self.dmarc_events, &auth.dmarc_event) {
            if env.direction == Direction::Inbound {
                if let Err(err) = store.record(event) {
                    tracing::warn!(id = %env.id, %err, "dmarc event not recorded");
                }
            }
        }
        report.auth = Some(auth.results);
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
