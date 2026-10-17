//! Auth, parse, scan, DLP, classify and the policy decision.
use currawong_auth::{
    strip_forged, AuthChecker, DmarcEventStore, KeyStore, StoredKey, GATEWAY_TENANT,
};
use currawong_classify::{
    message::{too_nested, MAX_RAW_BYTES},
    Classifier, TenantContext,
};
use currawong_core::telemetry::SCAN_DURATION_SECONDS;
use currawong_core::{
    config::{Config, TenantConfig},
    AuthResults, Direction, EngineFinding, PartFlag, ScanReport, Verdict,
};
use currawong_parser::{parse::parse_bytes_with, text::DlpText, ParseResponse};
use currawong_policy::{
    canonical_domain, default_pack, evaluate_message, Context, MessageDecision, PolicySet,
};
use currawong_scan::engines::yara::{self, CompiledRules, PollWatcher};
use currawong_scan::urls::UrlRewriter;
use currawong_scan::{
    combine, ClamdAddress, ClamdClient, EngineOutput, FileTypeScanner, ScanItem, ScanOutcome,
    Scanner, WorkerPool, YaraEngine,
};
use currawong_smtp::checks::{CheckStack, VerdictSignal};
use currawong_spool::Envelope;
use std::{path::Path, sync::Arc};
use tracing::Instrument;

pub struct Pipeline {
    pub cfg: Arc<Config>,
    pub auth: AuthChecker,
    pub pool: Option<WorkerPool>,
    /// Connection checks that learn from verdicts (reputation, greylist DMARC pass).
    pub checks: Option<Arc<CheckStack>>,
    pub yara: Option<Arc<YaraEngine>>,
    /// YARA is configured but its rules could not be loaded: fail closed.
    pub yara_error: Option<String>,
    _yara_watch: Option<PollWatcher>,
    /// DKIM and ARC keys. `None` means nothing is signed or sealed.
    pub keys: Option<Arc<KeyStore>>,
    /// Where inbound DMARC results go for aggregate reports.
    pub dmarc_events: Option<DmarcEventStore>,
    /// Quarantined mail waiting for a BIMI lookup on the background worker.
    pub bimi_jobs: Option<tokio::sync::mpsc::Sender<crate::dmarc::BimiJob>>,
    pub policies: PolicySet,
    policy_stamp: Option<currawong_policy::Stamp>,
    /// Click-time link protection for delivered inbound mail.
    pub url_rewriter: Option<Arc<UrlRewriter>>,
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
            .with_rules_load_timeout(cfg.scanner.yara.load_timeout_secs)
        });
        let (yara, yara_error) = match yara_engine(&cfg) {
            Ok(yara) => (yara, None),
            Err(err) => {
                tracing::error!(%err, "yara rules unavailable, mail fails closed");
                (None, Some(err))
            }
        };
        let _yara_watch = yara.as_ref().and_then(|engine| match engine.watch() {
            Ok(watcher) => Some(watcher),
            Err(err) => {
                tracing::error!(%err, "yara hot reload disabled");
                None
            }
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
            yara,
            yara_error,
            _yara_watch,
            keys: None,
            dmarc_events: None,
            bimi_jobs: None,
            policies: default_pack().clone(),
            policy_stamp: None,
            url_rewriter: None,
            checks: None,
            classifier,
            classify_error,
        }
    }

    pub fn with_checks(mut self, checks: Arc<CheckStack>) -> Self {
        self.checks = Some(checks);
        self
    }

    /// Feed an inbound verdict back to the SMTP connection checks.
    fn feedback(&self, env: &Envelope, report: &ScanReport, verdict: &Verdict) {
        let Some(checks) = &self.checks else {
            return;
        };
        if env.tenant_id.is_some() {
            return;
        }
        let signal = match verdict {
            Verdict::Deliver => VerdictSignal::Delivered {
                dmarc_pass: report
                    .auth
                    .as_ref()
                    .is_some_and(|auth| auth.dmarc.result == "pass"),
            },
            _ if report.malware => VerdictSignal::Malware,
            _ => VerdictSignal::Neutral,
        };
        checks.record_verdict(env.remote_ip, &env.mail_from, signal);
    }

    pub fn with_keys(mut self, keys: KeyStore) -> Self {
        self.keys = Some(Arc::new(keys));
        self
    }

    /// Forged Authentication-Results left in older spool files (accepted
    /// before DATA stripped them) are removed from `body_path` too, so they
    /// are never delivered. Returns the cleaned bytes.
    pub async fn strip_spooled(
        &self,
        raw: &[u8],
        body_path: Option<&Path>,
    ) -> Result<Vec<u8>, String> {
        let cleaned = strip_forged(raw, self.auth.authserv_id());
        if cleaned.len() != raw.len() {
            if let Some(path) = body_path {
                rewrite_body(path, &cleaned)
                    .await
                    .map_err(|err| format!("could not strip forged headers: {err}"))?;
            }
        }
        Ok(cleaned)
    }

    /// Our Authentication-Results, for inbound mail only: on outbound mail
    /// it would leak internal addresses and attest a meaningless SPF result.
    pub fn auth_headers(&self, env: &Envelope, report: &ScanReport) -> Vec<String> {
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

    pub fn with_url_rewriter(mut self, rewriter: UrlRewriter) -> Self {
        self.url_rewriter = Some(Arc::new(rewriter));
        self
    }

    /// Links in inbound mail that will be delivered point at the click
    /// service. Returns the rewritten message and marks the report modified,
    /// or `None` when nothing changed. A message that cannot be rewritten is
    /// delivered as it is, with the reason in the report.
    pub async fn rewrite_urls(
        &self,
        env: &Envelope,
        raw: &[u8],
        report: &mut ScanReport,
    ) -> Option<Vec<u8>> {
        let rewriter = Arc::clone(self.url_rewriter.as_ref()?);
        if env.direction != Direction::Inbound {
            return None;
        }
        // Arrival time, not now, so a retry rebuilds the same bytes.
        let issued = env.received_at.unix_timestamp().max(0) as u64;
        let (owned, id) = (raw.to_vec(), env.id.to_string());
        let result =
            tokio::task::spawn_blocking(move || rewriter.rewrite_message(&owned, &id, issued))
                .await;
        match result {
            Ok(Ok(out)) => {
                report.notes.extend(out.notes);
                if out.links == 0 {
                    return None;
                }
                tracing::info!(id = %env.id, links = out.links, "links rewritten");
                report.modified = true;
                Some(out.message)
            }
            Ok(Err(err)) => {
                tracing::warn!(id = %env.id, %err, "links not rewritten");
                report.notes.push(format!("links not rewritten: {err}"));
                None
            }
            Err(err) => {
                tracing::error!(id = %env.id, %err, "link rewriting failed");
                report
                    .notes
                    .push("links not rewritten: rewriter failed".into());
                None
            }
        }
    }

    pub fn with_dmarc_events(mut self, store: DmarcEventStore) -> Self {
        self.dmarc_events = Some(store);
        self
    }

    pub fn with_bimi(mut self, jobs: tokio::sync::mpsc::Sender<crate::dmarc::BimiJob>) -> Self {
        self.bimi_jobs = Some(jobs);
        self
    }

    /// Hand a quarantined message to the BIMI worker without waiting. When
    /// the queue is full the lookup is skipped: a logo is a nicety.
    pub fn queue_bimi(&self, id: currawong_core::MessageId, auth: AuthResults) {
        let Some(jobs) = &self.bimi_jobs else {
            return;
        };
        if jobs.try_send(crate::dmarc::BimiJob { id, auth }).is_err() {
            tracing::debug!("BIMI queue full, lookup skipped");
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

    /// Every log line from one assessment carries a `message` span with the
    /// `message_id` field. Scan time goes to `currawong_scan_duration_seconds`.
    pub async fn assess(
        &mut self,
        env: &Envelope,
        raw: &[u8],
        body_path: Option<&Path>,
    ) -> (ScanReport, MessageDecision) {
        let span = tracing::info_span!("message", message_id = %env.id);
        async {
            let started = std::time::Instant::now();
            let (report, decision) = self.assess_inner(env, raw, body_path).await;
            metrics::histogram!(SCAN_DURATION_SECONDS).record(started.elapsed().as_secs_f64());
            tracing::info!(verdict = ?decision.verdict(), "message evaluated");
            (report, decision)
        }
        .instrument(span)
        .await
    }

    async fn assess_inner(
        &mut self,
        env: &Envelope,
        raw: &[u8],
        body_path: Option<&Path>,
    ) -> (ScanReport, MessageDecision) {
        let mut report = ScanReport::new(env.id.clone());
        let wants_event = self.dmarc_events.is_some() && env.direction == Direction::Inbound;
        let auth = self.auth.evaluate(raw, env, wants_event).await;
        // Recorded once per message id, however often a deferred message is
        // classified again.
        if let (Some(store), Some(event)) = (&self.dmarc_events, &auth.dmarc_event) {
            if let Err(err) = store.record(event) {
                tracing::warn!(id = %env.id, %err, "dmarc event not recorded");
            }
        }
        let auth = auth.results;
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
            // No worker: decoded text bodies only; documents mark it incomplete.
            // In-process mail-parser would overflow the stack on a deeply nested
            // message, so that one is scanned as raw text and marked incomplete.
            let text = if too_nested(raw) {
                DlpText {
                    text: String::from_utf8_lossy(raw).into_owned(),
                    incomplete: true,
                }
            } else {
                currawong_parser::text::body_text(raw)
            };
            self.scan_dlp(env, &text, &mut report);
            self.classify(env, raw, &mut report).await;
            let decision = self.decide(env, &report);
            self.feedback(env, &report, &decision.verdict());
            return (report, decision);
        }
        let rules = self.yara.as_ref().map(|engine| engine.current());
        let parsed = self.parse(env, raw, body_path, rules.as_deref()).await;
        drop(rules);
        report.parts = parsed.parts.clone();
        report.urls = parsed.urls.clone();
        report.yara = parsed.yara.clone();
        self.scan_dlp(env, &parsed.dlp, &mut report);
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
        if self.yara.is_some() {
            outputs.push(finding("yara", &yara::result_for(&report.yara)));
        }
        if let Some(reason) = &self.yara_error {
            outputs.push(finding(
                "yara",
                &currawong_scan::EngineResult::Failed {
                    reason: format!("rules unavailable: {reason}"),
                    unreachable: false,
                },
            ));
        }
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
        report.defer = report.defer || combined.defer;
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
        let decision = self.decide(env, &report);
        self.feedback(env, &report, &decision.verdict());
        (report, decision)
    }

    /// Tenant and direction per recipient: a message can reach several tenants,
    /// and submitted mail to a local mailbox is decided for that mailbox.
    fn decide(&self, env: &Envelope, report: &ScanReport) -> MessageDecision {
        let tenants = &self.cfg.relay.tenants;
        let tenant_of = |domain: &str| tenant_owning(tenants, domain).map(|t| t.id.as_str());
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
                    // The SMTP AUTH login, recorded by the session. Trusted-network
                    // relay and inbound mail have none, so user scopes never match them.
                    sender_identity: env.authenticated_as.as_deref(),
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

    /// Outbound mail, and inbound when configured. Logs counts only.
    fn scan_dlp(&self, env: &Envelope, text: &DlpText, report: &mut ScanReport) {
        let profile = &self.cfg.dlp;
        if !profile.enabled || (env.direction == Direction::Inbound && !profile.scan_inbound) {
            return;
        }
        let mut dlp = currawong_dlp::scan(&text.text, profile);
        dlp.incomplete |= text.incomplete;
        if !dlp.counts.is_empty() || dlp.incomplete {
            tracing::info!(id = %env.id, counts = ?dlp.counts, incomplete = dlp.incomplete, "dlp findings");
        }
        report.dlp = Some(dlp);
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
                // A message too nested to parse safely is held, not delivered unscored.
                if result.flags.iter().any(|flag| flag == "classify_skipped") {
                    report.fail_closed = true;
                }
                report.spam = result.spam;
                report.lookalikes = result.lookalikes;
                report.flags.extend(result.flags);
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
        rules: Option<&CompiledRules>,
    ) -> ParseResponse {
        if let (Some(pool), Some(path)) = (self.pool.as_mut(), body_path) {
            return match pool
                .scan_file_with_rules(env.id.as_str(), path, &self.cfg.scanner.extract, rules)
                .await
            {
                ScanOutcome::Parsed(response) => response,
                ScanOutcome::Failed { reason } => ParseResponse::failed(env.id.as_str(), reason),
            };
        }
        parse_bytes_with(
            env.id.as_str(),
            raw,
            &self.cfg.scanner.extract,
            rules.map(|compiled| &compiled.rules),
        )
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
    let recipient_domains: Vec<String> = env
        .rcpt_to
        .iter()
        .filter_map(|rcpt| rcpt.rsplit_once('@'))
        .map(|(_, domain)| canonical_domain(domain.trim_end_matches('>')))
        .collect();
    for domain in &recipient_domains {
        if let Some(tenant) = tenant_owning(tenants, domain) {
            return TenantContext::tenant(&tenant.id, &tenant.domains);
        }
    }
    TenantContext::domain(
        recipient_domains
            .first()
            .map(String::as_str)
            .unwrap_or("unknown"),
    )
}

/// The relay tenant that owns `domain` (already canonical). Policy decisions
/// and classification both resolve tenants through this.
fn tenant_owning<'a>(tenants: &'a [TenantConfig], domain: &str) -> Option<&'a TenantConfig> {
    tenants
        .iter()
        .find(|t| t.domains.iter().any(|d| canonical_domain(d) == domain))
}

fn finding(name: &str, result: &currawong_scan::EngineResult) -> EngineOutput {
    EngineOutput {
        name: name.into(),
        result: result.clone(),
        required: false,
    }
}

fn yara_engine(cfg: &Config) -> Result<Option<Arc<YaraEngine>>, String> {
    let dir = &cfg.scanner.yara.rules_dir;
    if !cfg.scanner.enabled || dir.as_os_str().is_empty() {
        return Ok(None);
    }
    YaraEngine::new(dir).map(|engine| Some(Arc::new(engine)))
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

/// Atomically replace a spool body (write beside it, fsync, rename).
pub(crate) async fn rewrite_body(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
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
