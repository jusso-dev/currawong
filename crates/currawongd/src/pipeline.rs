//! Auth, parse, scan and the policy decision.
use currawong_auth::AuthChecker;
use currawong_core::{
    config::Config, AuthResults, Direction, EngineFinding, PartFlag, ScanReport, Verdict,
};
use currawong_parser::{parse::parse_bytes, ParseResponse};
use currawong_policy::{
    canonical_domain, default_pack, evaluate_message, Context, MessageDecision, PolicySet,
};
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

fn domain_of(address: &str) -> String {
    address
        .rsplit_once('@')
        .map(|(_, d)| canonical_domain(d))
        .unwrap_or_default()
}

pub fn auth_header(auth: &AuthResults) -> String {
    auth.header.clone()
}
