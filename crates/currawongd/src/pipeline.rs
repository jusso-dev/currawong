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
use currawong_parser::{text::DlpText, ParseResponse};
use currawong_policy::{
    canonical_domain, default_pack, evaluate_message, Context, MessageDecision, PolicySet,
};
use currawong_scan::engines::yara::{self, CompiledRules, PollWatcher};
use currawong_scan::pool::{display_name, sweep};
use currawong_scan::urls::{Delivery, UrlRewriter};
use currawong_scan::{
    combine, ClamdAddress, ClamdClient, EngineOutput, ScanOutcome, WorkerPool, YaraEngine,
};
use currawong_smtp::checks::{CheckStack, VerdictSignal};
use currawong_spool::Envelope;
use std::{path::Path, sync::Arc};
use tracing::Instrument;

/// Policy flag: some links in an inbound message were left as they were.
pub const URL_REWRITE_SKIPPED: &str = "url_rewrite.skipped";
/// Longer recipient lists are left out of click tokens.
const MAX_TOKEN_RECIPIENTS: usize = 256;

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
        // Scratch left by an earlier run: worker directories and parts.
        sweep(&parts_root(&cfg), &["scan-", "worker-", "selftest-"]);
        if cfg.scanner.enabled && !cfg.scanner.require_landlock {
            tracing::warn!(
                "scanner.require_landlock is false: on kernels without Landlock the parser \
                 worker can read every file this user can"
            );
        }
        let pool = worker_pool(&cfg);
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
        self.delivery_headers_for(env, raw, None, report).await
    }

    /// [`Self::delivery_headers`] for a copy whose body a stage changed:
    /// results come from the message as it arrived (`raw`), the ARC seal
    /// covers `delivered`, the bytes that leave.
    pub async fn delivery_headers_for(
        &self,
        env: &Envelope,
        raw: &[u8],
        delivered: Option<&[u8]>,
        report: &ScanReport,
    ) -> Result<Vec<String>, String> {
        if env.direction == Direction::Inbound {
            if report.modified {
                if let Some(sealer) = self.arc_sealer().await {
                    let sealed = self
                        .auth
                        .seal_delivered(raw, delivered.unwrap_or(raw), env, &sealer)
                        .await;
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

    /// Links in inbound mail point at the click service. Returns the
    /// rewritten message and marks the report modified, or `None` when
    /// nothing changed. Links left as they were (a message over the limits,
    /// a signed part, an unreadable charset) set the `url_rewrite.skipped`
    /// flag, so policy decides whether such mail is delivered.
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
        // Sorted, so a retry from a split plan builds the same tokens.
        let mut recipients = env.rcpt_to.clone();
        recipients.sort();
        recipients.dedup();
        let mut recipient = recipients.join(",");
        if recipient.len() > MAX_TOKEN_RECIPIENTS {
            recipient.clear();
        }
        let (owned, id) = (raw.to_vec(), env.id.to_string());
        let result = tokio::task::spawn_blocking(move || {
            let delivery = Delivery {
                message_id: &id,
                recipient: &recipient,
                issued_at: issued,
            };
            rewriter.rewrite_message(&owned, &delivery)
        })
        .await;
        let skipped = |report: &mut ScanReport, note: String| {
            report.notes.push(note);
            if !report.flags.iter().any(|f| f == URL_REWRITE_SKIPPED) {
                report.flags.push(URL_REWRITE_SKIPPED.into());
            }
        };
        match result {
            Ok(Ok(out)) => {
                if out.skipped > 0 {
                    for note in out.notes {
                        skipped(report, note);
                    }
                } else {
                    report.notes.extend(out.notes);
                }
                if out.links == 0 {
                    return None;
                }
                tracing::info!(id = %env.id, links = out.links, "links rewritten");
                report.modified = true;
                Some(out.message)
            }
            Ok(Err(err)) => {
                tracing::warn!(id = %env.id, %err, "links not rewritten");
                skipped(report, format!("links not rewritten: {err}"));
                None
            }
            Err(err) => {
                tracing::error!(id = %env.id, %err, "link rewriting failed");
                skipped(report, "links not rewritten: rewriter failed".into());
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
        &self,
        env: &Envelope,
        raw: &[u8],
        body_path: Option<&Path>,
    ) -> (ScanReport, MessageDecision) {
        let (report, decision, _) = self.assess_for_delivery(env, raw, body_path).await;
        (report, decision)
    }

    /// [`Self::assess`], plus the body delivered copies carry when links were
    /// rewritten. Rewriting runs before the decision so policy sees the
    /// `url_rewrite.*` flags.
    pub async fn assess_for_delivery(
        &self,
        env: &Envelope,
        raw: &[u8],
        body_path: Option<&Path>,
    ) -> (ScanReport, MessageDecision, Option<Vec<u8>>) {
        let span = tracing::info_span!("message", message_id = %env.id);
        async {
            let started = std::time::Instant::now();
            let (report, decision, rewritten) = self.assess_inner(env, raw, body_path).await;
            metrics::histogram!(SCAN_DURATION_SECONDS).record(started.elapsed().as_secs_f64());
            tracing::info!(verdict = ?decision.verdict(), "message evaluated");
            (report, decision, rewritten)
        }
        .instrument(span)
        .await
    }

    async fn assess_inner(
        &self,
        env: &Envelope,
        raw: &[u8],
        body_path: Option<&Path>,
    ) -> (ScanReport, MessageDecision, Option<Vec<u8>>) {
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
        report.marking = Some(currawong_dlp::pspf::inspect(raw));
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
            let rewritten = self.rewrite_urls(env, raw, &mut report).await;
            let decision = self.decide(env, &report);
            self.feedback(env, &report, &decision.verdict());
            return (report, decision, rewritten);
        }
        let rules = self.yara.as_ref().map(|engine| engine.current());
        // Holds the extracted parts on disk until the engines have run.
        let (parsed, _parts_dir) = self.parse(env, raw, body_path, rules.as_deref()).await;
        drop(rules);
        let (parsed, parser_failed) = match parsed {
            Ok(parsed) => {
                let failed = parsed.error.is_some();
                (parsed, failed)
            }
            // No worker could run: not the message's fault, try again later.
            Err(reason) => {
                report.defer = true;
                report
                    .notes
                    .push(format!("parser worker unreachable: {reason}"));
                (ParseResponse::failed(env.id.as_str(), reason), false)
            }
        };
        report.parts = parsed.parts.clone();
        report.urls = parsed.urls.clone();
        report.url_sources = parsed.url_sources.clone();
        report.yara = parsed.yara.clone();
        self.scan_dlp(env, &parsed.dlp, &mut report);
        if let Some(err) = parsed.error.filter(|_| parser_failed) {
            report.notes.push(err);
        }
        self.fold_part_flags(&mut report);
        let mut outputs = Vec::new();
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
        report.defer = report.defer || combined.defer;
        report.fail_closed = report.fail_closed || combined.fail_closed;
        report.notes.extend(combined.notes);
        for output in &outputs {
            report.engines.push(EngineFinding {
                engine: output.name.clone(),
                result: format!("{:?}", output.result),
                detail: String::new(),
            });
        }
        self.classify(env, raw, &mut report).await;
        let rewritten = self.rewrite_urls(env, raw, &mut report).await;
        let decision = self.decide(env, &report);
        self.feedback(env, &report, &decision.verdict());
        (report, decision, rewritten)
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
        let bec =
            (env.direction == Direction::Inbound).then(|| currawong_classify::bec::BecContext {
                dmarc_failed: report
                    .auth
                    .as_ref()
                    .is_some_and(|auth| auth.dmarc.result.eq_ignore_ascii_case("fail")),
                ..Default::default()
            });
        match tokio::task::spawn_blocking(move || {
            classifier.classify_with(&tenant, &raw, &sender, &urls, bec)
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
                report.bec = result.bec;
                report.flags.extend(result.flags);
                report.notes.extend(result.notes);
            }
            Err(err) => report.notes.push(format!("classifier failed: {err}")),
        }
    }

    /// Part flags from the parser worker become the M1 verdict inputs.
    fn fold_part_flags(&self, report: &mut ScanReport) {
        let scanner = &self.cfg.scanner;
        let mut notes = Vec::new();
        for part in &mut report.parts {
            let name = display_name(part.filename.as_deref().unwrap_or("attachment"));
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
                    PartFlag::LimitExceeded => (false, format!("extraction limit exceeded {name}")),
                    PartFlag::Unscannable => (false, format!("could not inspect {name}")),
                    // Policy acts on these through its signals.
                    PartFlag::Executable
                    | PartFlag::HasMacro
                    | PartFlag::HtmlSmuggling
                    | PartFlag::QrCode
                    | PartFlag::QrSkipped => continue,
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

    /// Always in a worker process (ADR 0002); never inside the daemon.
    /// `Err` means no worker could run (defer), not a verdict on the mail.
    async fn parse(
        &self,
        env: &Envelope,
        raw: &[u8],
        body_path: Option<&Path>,
        rules: Option<&CompiledRules>,
    ) -> (Result<ParseResponse, String>, Option<tempfile::TempDir>) {
        let id = env.id.as_str();
        let Some(pool) = self.pool.as_ref() else {
            return (Err("parser worker binary not found".into()), None);
        };
        let dir = match parts_dir(&self.cfg) {
            Ok(dir) => dir,
            Err(err) => return (Err(format!("parts directory: {err}")), None),
        };
        let path = match body_path {
            Some(path) => path.to_path_buf(),
            None => {
                let path = dir.path().join("message.eml");
                if let Err(err) = tokio::fs::write(&path, raw).await {
                    return (Err(format!("stage message: {err}")), Some(dir));
                }
                path
            }
        };
        let out = dir.path().join("parts");
        if let Err(err) = tokio::fs::create_dir(&out).await {
            return (Err(format!("parts directory: {err}")), Some(dir));
        }
        let response = match pool
            .scan_job(id, &path, &self.cfg.scanner.extract, Some(&out), rules)
            .await
        {
            ScanOutcome::Parsed(response) => Ok(response),
            ScanOutcome::Failed { reason } => Ok(ParseResponse::failed(id, reason)),
            ScanOutcome::Unavailable { reason } => Err(reason),
        };
        (response, Some(dir))
    }
}

impl Pipeline {
    /// The From address to remember for BEC first-time sender checks:
    /// inbound mail whose SPF or DMARC passed, so a forged From cannot
    /// pre-seed the history.
    pub fn history_sender(
        &self,
        env: &Envelope,
        raw: &[u8],
        report: &ScanReport,
    ) -> Option<String> {
        if env.direction != Direction::Inbound || self.classifier.is_none() {
            return None;
        }
        let auth = report.auth.as_ref()?;
        let passed = auth.spf.result.eq_ignore_ascii_case("pass")
            || auth.dmarc.result.eq_ignore_ascii_case("pass");
        if !passed {
            return None;
        }
        currawong_classify::message::from_address(raw)
    }

    /// Inbound mail handed to delivery: later mail from the same From
    /// address is no longer a first-time sender.
    pub async fn record_delivery(&self, env: &Envelope, sender: &str, recipients: Vec<String>) {
        if env.direction != Direction::Inbound || recipients.is_empty() {
            return;
        }
        let Some(classifier) = self.classifier.clone() else {
            return;
        };
        let tenant = tenant_context(&self.cfg, env);
        let sender = sender.to_string();
        let _ = tokio::task::spawn_blocking(move || {
            classifier.record_delivery(&tenant, &sender, &recipients)
        })
        .await;
    }
}

fn parts_root(cfg: &Config) -> std::path::PathBuf {
    cfg.spool.dir.join("parts")
}

/// Per-message scratch space for extracted parts, next to the spool.
fn parts_dir(cfg: &Config) -> std::io::Result<tempfile::TempDir> {
    let base = parts_root(cfg);
    std::fs::create_dir_all(&base)?;
    tempfile::Builder::new().prefix("scan-").tempdir_in(base)
}

/// The worker pool the config describes, if the worker binary exists.
pub fn worker_pool(cfg: &Config) -> Option<WorkerPool> {
    let scanner = &cfg.scanner;
    let user = scanner.worker_uid.zip(scanner.worker_gid);
    worker_binary(cfg).map(|binary| {
        WorkerPool::new(
            binary,
            scanner.job_timeout_secs,
            scanner.max_jobs_per_worker as u64,
        )
        .with_size(scanner.worker_pool_size)
        .with_limits(scanner.worker_memory_mib, scanner.worker_cpu_secs)
        .with_work_dir(parts_root(cfg))
        .with_landlock_required(scanner.require_landlock)
        .with_user(user)
        .with_rules_load_timeout(scanner.yara.load_timeout_secs)
    })
}

/// Same rule as the parser worker: the extension Windows would act on.
fn blocked_extension(filename: Option<&str>, blocked: &[String]) -> bool {
    let Some(ext) = filename.and_then(currawong_parser::filetype::file_extension) else {
        return false;
    };
    blocked.iter().any(|b| b.eq_ignore_ascii_case(&ext))
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

/// Atomically replace a spool body (write beside it, fsync, rename).
pub(crate) async fn rewrite_body(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;
    let tmp = path.with_extension("eml.strip");
    let mut file = tokio::fs::File::create(&tmp).await?;
    file.write_all(bytes).await?;
    file.sync_all().await?;
    tokio::fs::rename(&tmp, path).await?;
    match path.parent() {
        Some(dir) => sync_dir(dir).await,
        None => Ok(()),
    }
}

/// fsync a directory so a rename in it survives power loss.
pub(crate) async fn sync_dir(dir: &Path) -> std::io::Result<()> {
    tokio::fs::File::open(dir).await?.sync_all().await
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}
