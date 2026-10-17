//! Auth, parse, scan and the policy decision.
use currawong_auth::AuthChecker;
use currawong_core::{
    config::Config, AuthResults, Direction, EngineFinding, PartFlag, ScanReport, Verdict,
};
use currawong_parser::ParseResponse;
use currawong_policy::{
    canonical_domain, default_pack, evaluate_message, Context, MessageDecision, PolicySet,
};
use currawong_scan::{combine, ClamdAddress, ClamdClient, EngineOutput, ScanOutcome, WorkerPool};
use currawong_spool::Envelope;
use std::{path::Path, sync::Arc};

pub struct Pipeline {
    pub cfg: Arc<Config>,
    pub auth: AuthChecker,
    pub pool: Option<WorkerPool>,
    pub policies: PolicySet,
    policy_stamp: Option<currawong_policy::Stamp>,
}

impl Pipeline {
    pub fn new(cfg: Arc<Config>, auth: AuthChecker) -> Self {
        let pool = worker_binary(&cfg).map(|binary| {
            WorkerPool::new(
                binary,
                cfg.scanner.job_timeout_secs,
                cfg.scanner.max_jobs_per_worker as u64,
            )
            .with_size(cfg.scanner.worker_pool_size)
            .with_limits(cfg.scanner.worker_memory_mib, cfg.scanner.worker_cpu_secs)
        });
        Self {
            cfg,
            auth,
            pool,
            policies: default_pack().clone(),
            policy_stamp: None,
        }
    }

    pub fn with_policies(mut self, policies: PolicySet) -> Self {
        self.policies = policies;
        self
    }

    /// Load the configured policies again if their source changed. Runs the
    /// file and SQLite reads on a blocking thread. Returns whether they changed.
    pub async fn reload_policies(&mut self) -> Result<bool, String> {
        let cfg = self.cfg.policy.clone();
        let last = self.policy_stamp.clone();
        let loaded = tokio::task::spawn_blocking(move || {
            let stamp = currawong_policy::stamp(&cfg)?;
            if last.as_ref() == Some(&stamp) {
                return Ok(None);
            }
            Ok(Some((stamp, currawong_policy::load(&cfg))))
        })
        .await
        .map_err(|err| err.to_string())?
        .map_err(|err: currawong_policy::PolicyError| err.to_string())?;
        let Some((stamp, set)) = loaded else {
            return Ok(false);
        };
        // A bad source is reported once, then again only after it changes.
        self.policy_stamp = Some(stamp);
        let set = set.map_err(|err| err.to_string())?;
        if set == self.policies {
            return Ok(false);
        }
        for policy in set.policies.iter().filter(|p| !p.override_floor.is_empty()) {
            tracing::warn!(
                policy = %policy.id,
                rules = ?policy.override_floor,
                "policy lifts the built-in floor for the mail it matches"
            );
        }
        self.policies = set;
        Ok(true)
    }

    /// One verdict for the whole message. See `assess` for per-recipient decisions.
    pub async fn evaluate(
        &mut self,
        env: &Envelope,
        raw: &[u8],
        body_path: Option<&Path>,
    ) -> (ScanReport, Verdict) {
        let (report, decision) = self.assess(env, raw, body_path).await;
        (report, decision.verdict())
    }

    pub async fn assess(
        &mut self,
        env: &Envelope,
        raw: &[u8],
        body_path: Option<&Path>,
    ) -> (ScanReport, MessageDecision) {
        let mut report = ScanReport::new(env.id.clone());
        let auth = self.auth.check(raw, env).await;
        report.auth = Some(auth);
        if !self.cfg.scanner.enabled {
            let decision = self.decide(env, &report);
            return (report, decision);
        }
        // Holds the extracted parts on disk until the engines have run.
        let (parsed, _parts_dir) = self.parse(env, raw, body_path).await;
        report.parts = parsed.parts.clone();
        report.urls = parsed.urls.clone();
        let parser_failed = parsed.error.is_some();
        if let Some(err) = parsed.error {
            report.notes.push(err);
        }
        self.fold_part_flags(&mut report);
        let mut outputs = Vec::new();
        if self.cfg.scanner.clamd.address.is_empty() && self.cfg.scanner.clamd.required {
            outputs.push(EngineOutput {
                name: "clamav".into(),
                result: currawong_scan::EngineResult::Failed {
                    reason: "clamd is required and no address is configured".into(),
                    unreachable: true,
                },
                required: true,
            });
        }
        if !self.cfg.scanner.clamd.address.is_empty() {
            match ClamdAddress::parse(&self.cfg.scanner.clamd.address) {
                Ok(address) => {
                    let client = ClamdClient::new(address, self.cfg.scanner.clamd.required);
                    let result = client.scan_message(raw, &report.parts).await;
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
        report.fail_closed = report.fail_closed || combined.fail_closed;
        report.notes.extend(combined.notes);
        for output in &outputs {
            report.engines.push(EngineFinding {
                engine: output.name.clone(),
                result: format!("{:?}", output.result),
                detail: String::new(),
            });
        }
        let decision = self.decide(env, &report);
        (report, decision)
    }

    /// Tenant and direction per recipient: a message can reach several tenants,
    /// and submitted mail to a local mailbox is decided for that mailbox.
    fn decide(&self, env: &Envelope, report: &ScanReport) -> MessageDecision {
        let tenants = &self.cfg.relay.tenants;
        let tenant_of = |domain: &str| {
            tenants
                .iter()
                .find(|t| t.domains.iter().any(|d| canonical_domain(d) == domain))
                .map(|t| t.id.as_str())
        };
        let is_local = |domain: &str| {
            tenant_of(domain).is_some()
                || self
                    .cfg
                    .domains
                    .accept
                    .iter()
                    .any(|d| canonical_domain(d) == domain)
        };
        let sender_tenant = env
            .tenant_id
            .as_deref()
            .or_else(|| tenant_of(&domain_of(&env.mail_from)));
        let empty = [String::new()];
        let rcpts = if env.rcpt_to.is_empty() {
            &empty[..]
        } else {
            &env.rcpt_to
        };
        let contexts: Vec<Context> = rcpts
            .iter()
            .map(|rcpt| {
                let domain = domain_of(rcpt);
                let direction = match env.direction {
                    Direction::Outbound if !is_local(&domain) => Direction::Outbound,
                    _ => Direction::Inbound,
                };
                Context {
                    tenant_id: match direction {
                        Direction::Inbound => tenant_of(&domain),
                        Direction::Outbound => sender_tenant,
                    },
                    direction,
                    sender: &env.mail_from,
                    // The SMTP session does not record the login on the envelope yet,
                    // so outbound user and group scopes do not match.
                    sender_identity: None,
                    recipient: rcpt,
                }
            })
            .collect();
        let mut decision = evaluate_message(report, &contexts, &self.policies);
        if !tenants.is_empty() {
            for d in decision
                .decisions
                .iter_mut()
                .filter(|d| d.tenant_id.is_none())
            {
                tracing::warn!(id = %env.id, recipient = %d.recipient, "no tenant for recipient");
                d.explanation
                    .push("no tenant for this recipient: only platform policies applied".into());
            }
        }
        decision
    }

    /// Part flags from the parser worker become the M1 verdict inputs.
    fn fold_part_flags(&self, report: &mut ScanReport) {
        let scanner = &self.cfg.scanner;
        let mut notes = Vec::new();
        for part in &mut report.parts {
            let name = part.filename.as_deref().unwrap_or("attachment").to_string();
            if blocked_extension(part.filename.as_deref(), &scanner.blocked_extensions)
                && !part.flags.contains(&PartFlag::Executable)
            {
                part.flags.push(PartFlag::Executable);
            }
            for flag in &part.flags {
                let (active, note) = match flag {
                    PartFlag::Executable if scanner.treat_executables_as_active => {
                        (true, format!("executable {name}"))
                    }
                    PartFlag::HasMacro if scanner.treat_macros_as_active => {
                        (true, format!("macro {name}"))
                    }
                    PartFlag::Encrypted => (true, format!("encrypted archive {name}")),
                    PartFlag::HasOleObject => (true, format!("embedded OLE object {name}")),
                    PartFlag::ExtMismatch => (true, format!("type does not match name {name}")),
                    PartFlag::LimitExceeded => {
                        (false, "archive extraction limit exceeded".to_string())
                    }
                    PartFlag::Unscannable => (false, format!("could not inspect {name}")),
                    PartFlag::Executable | PartFlag::HasMacro => continue,
                };
                if active {
                    report.active_content = true;
                } else {
                    report.fail_closed = true;
                }
                notes.push(note);
            }
        }
        report.notes.extend(notes);
    }

    /// Always in a worker process (ADR 0002). No worker, no parse: the
    /// message fails closed rather than being parsed inside the daemon.
    async fn parse(
        &mut self,
        env: &Envelope,
        raw: &[u8],
        body_path: Option<&Path>,
    ) -> (ParseResponse, Option<tempfile::TempDir>) {
        let id = env.id.as_str();
        let Some(pool) = self.pool.as_ref() else {
            return (
                ParseResponse::failed(id, "parser worker binary not found"),
                None,
            );
        };
        let dir = match parts_dir(&self.cfg) {
            Ok(dir) => dir,
            Err(err) => {
                return (
                    ParseResponse::failed(id, format!("parts directory: {err}")),
                    None,
                )
            }
        };
        let path = match body_path {
            Some(path) => path.to_path_buf(),
            None => {
                let path = dir.path().join("message.eml");
                if let Err(err) = tokio::fs::write(&path, raw).await {
                    return (
                        ParseResponse::failed(id, format!("stage message: {err}")),
                        Some(dir),
                    );
                }
                path
            }
        };
        let out = dir.path().join("parts");
        if let Err(err) = tokio::fs::create_dir(&out).await {
            return (
                ParseResponse::failed(id, format!("parts directory: {err}")),
                Some(dir),
            );
        }
        let response = match pool
            .scan_file_into(id, &path, &self.cfg.scanner.extract, Some(&out))
            .await
        {
            ScanOutcome::Parsed(response) => response,
            ScanOutcome::Failed { reason } => ParseResponse::failed(id, reason),
        };
        (response, Some(dir))
    }
}

/// Per-message scratch space for extracted parts, next to the spool.
fn parts_dir(cfg: &Config) -> std::io::Result<tempfile::TempDir> {
    let base = cfg.spool.dir.join("parts");
    std::fs::create_dir_all(&base)?;
    tempfile::Builder::new().prefix("scan-").tempdir_in(base)
}

fn blocked_extension(filename: Option<&str>, blocked: &[String]) -> bool {
    let Some((_, ext)) = filename.and_then(|name| name.rsplit_once('.')) else {
        return false;
    };
    blocked.iter().any(|b| b.eq_ignore_ascii_case(ext))
}

fn finding(name: &str, result: &currawong_scan::EngineResult) -> EngineOutput {
    EngineOutput {
        name: name.into(),
        result: result.clone(),
        required: false,
    }
}

/// The configured worker, or one next to the daemon. A configured path that
/// does not exist is not silently replaced.
pub fn worker_binary(cfg: &Config) -> Option<std::path::PathBuf> {
    if let Some(path) = &cfg.scanner.worker_binary {
        return path.is_file().then(|| path.clone());
    }
    let exe = std::env::current_exe().ok()?;
    let candidate = exe.parent()?.join("currawong-parser-worker");
    if candidate.exists() {
        Some(candidate)
    } else {
        None
    }
}

fn domain_of(address: &str) -> String {
    address
        .rsplit_once('@')
        .map(|(_, d)| canonical_domain(d))
        .unwrap_or_default()
}

pub fn auth_header(auth: &AuthResults) -> String {
    auth.header.clone()
}
