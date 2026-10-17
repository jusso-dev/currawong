//! Outbound delivery, retries and DSNs. TLS precedence for MX delivery is
//! DANE, then MTA-STS, then opportunistic STARTTLS.
pub mod client;
pub mod dane;
mod dsn;
pub mod mta_sts;
pub mod outbound_tls;
pub mod route;

use crate::{dns::DnsLookup, tlsrpt::TlsRpt};
pub use dsn::{build_dsn, status_code};
pub use outbound_tls::OutboundTls;
pub use route::{resolve_route, RouteError};

use client::{HostFailure, Starttls, Transaction};
use currawong_core::{config::Config, MessageId};
use currawong_spool::{next_retry, Envelope, RcptStatus, Spool, SpoolError, SpoolState};
use futures::{FutureExt, StreamExt};
use mail_auth::report::tlsrpt::{PolicyDetails, PolicyType, ResultType};
use mta_sts::{Discovery, HttpsFetcher, Mode, MtaSts};
use route::Hop;
use rustls::pki_types::ServerName;
use sha2::{Digest, Sha256};
use std::{net::SocketAddr, panic::AssertUnwindSafe, sync::Arc, time::Duration};
use time::OffsetDateTime;
use tokio::time::Instant;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliveryOutcome {
    Delivered,
    TempFail(String),
    PermFail(String),
}

#[derive(Clone)]
pub struct TokioClock {
    start_instant: Instant,
    start_wall: OffsetDateTime,
}

impl TokioClock {
    pub fn new() -> Self {
        Self {
            start_instant: Instant::now(),
            start_wall: OffsetDateTime::now_utc(),
        }
    }

    pub fn now(&self) -> OffsetDateTime {
        let elapsed = self.start_instant.elapsed();
        self.start_wall + time::Duration::try_from(elapsed).unwrap_or(time::Duration::ZERO)
    }
}

impl Default for TokioClock {
    fn default() -> Self {
        Self::new()
    }
}

/// Recipient states kept in `Envelope::rcpt_status`.
const PENDING: &str = "pending";
const TEMP: &str = "temp";
const PERM: &str = "perm";
const BOUNCED: &str = "bounced";
const DELIVERED: &str = "delivered";

pub struct Deliverer<D: DnsLookup> {
    pub spool: Arc<Spool>,
    pub cfg: Arc<Config>,
    pub dns: Arc<D>,
    pub clock: TokioClock,
    /// Port for MX-routed hops. Always 25 outside tests.
    pub mx_port: u16,
    /// Trust roots for STARTTLS and HTTPS.
    pub tls: OutboundTls,
    /// `None` when `delivery.mta_sts` is off.
    pub mta_sts: Option<Arc<MtaSts>>,
    /// `None` when `delivery.tls_rpt.enabled` is off.
    pub tlsrpt: Option<Arc<TlsRpt>>,
    /// For TLS-RPT uploads to `https:` report addresses.
    pub http: Option<reqwest::Client>,
}

/// The TLS rule for one MX host, chosen in RFC 7672 / RFC 8461 order.
enum Plan {
    Dane(Vec<crate::dns::Tlsa>),
    Sts(Arc<mta_sts::Policy>),
    Opportunistic,
}

impl<D: DnsLookup> Deliverer<D> {
    pub fn new(spool: Arc<Spool>, cfg: Arc<Config>, dns: Arc<D>) -> Self {
        let tls = OutboundTls::webpki();
        let http = match tls.http_client() {
            Ok(client) => Some(client),
            Err(err) => {
                tracing::error!(%err, "HTTPS client for MTA-STS and TLS-RPT failed");
                None
            }
        };
        let db = cfg.delivery.tls_database.clone();
        let mta_sts = match (&http, cfg.delivery.mta_sts) {
            (Some(client), true) => Some(Arc::new(MtaSts::new(
                Box::new(HttpsFetcher::new(client.clone())),
                db.clone(),
            ))),
            _ => None,
        };
        let tlsrpt = cfg
            .delivery
            .tls_rpt
            .enabled
            .then(|| Arc::new(TlsRpt::new(db)));
        Self {
            spool,
            cfg,
            dns,
            clock: TokioClock::new(),
            mx_port: 25,
            tls,
            mta_sts,
            tlsrpt,
            http,
        }
    }

    /// Send TLS-RPT reports for finished days. The daemon calls this after
    /// each delivery pass.
    pub async fn send_tls_reports(&self) -> Result<usize, String> {
        let Some(tlsrpt) = &self.tlsrpt else {
            return Ok(0);
        };
        tlsrpt
            .send_due(
                &self.cfg,
                self.dns.as_ref(),
                &self.spool,
                self.http.as_ref(),
                self.clock.now().date(),
            )
            .await
    }

    /// One delivery attempt for every recipient still pending. Permanent
    /// failures are bounced straight away, even if others will be retried.
    pub async fn deliver(&self, id: &MessageId) -> Result<DeliveryOutcome, String> {
        let mut env = self.spool.load(id).await.map_err(|err| err.to_string())?;
        let body = self
            .spool
            .read_body(id)
            .await
            .map_err(|err| err.to_string())?;
        if env.rcpt_status.is_empty() {
            for rcpt in env.rcpt_to.clone() {
                set_status(&mut env, &rcpt, PENDING, "");
            }
        }
        let pending: Vec<String> = env
            .rcpt_status
            .iter()
            .filter(|status| status.status == PENDING || status.status == TEMP)
            .map(|status| status.address.clone())
            .collect();
        let max_age = Duration::from_secs(self.cfg.delivery.max_age_days.saturating_mul(86_400));
        let age = self.clock.now() - env.received_at;
        let expired = age > time::Duration::try_from(max_age).unwrap_or(time::Duration::days(5));
        let mut outcome = DeliveryOutcome::Delivered;
        if expired {
            for rcpt in &pending {
                let last = env
                    .rcpt_status
                    .iter()
                    .find(|status| &status.address == rcpt)
                    .map(|status| status.detail.clone())
                    .filter(|detail| !detail.is_empty())
                    .unwrap_or_else(|| "none".into());
                let detail = format!(
                    "4.4.7 message expired after {} days; last error: {last}",
                    self.cfg.delivery.max_age_days
                );
                set_status(&mut env, rcpt, PERM, &detail);
            }
        } else if !pending.is_empty() {
            let message = outbound_bytes(&env, &body, &self.cfg.gateway.hostname);
            for (domain, rcpts) in group_by_domain(&pending) {
                for (rcpt, result) in self.deliver_domain(&env, &message, &domain, &rcpts).await {
                    match result {
                        DeliveryOutcome::Delivered => set_status(&mut env, &rcpt, DELIVERED, "250"),
                        DeliveryOutcome::TempFail(detail) => {
                            set_status(&mut env, &rcpt, TEMP, &detail);
                            outcome = DeliveryOutcome::TempFail(detail);
                        }
                        DeliveryOutcome::PermFail(detail) => {
                            set_status(&mut env, &rcpt, PERM, &detail);
                            if outcome == DeliveryOutcome::Delivered {
                                outcome = DeliveryOutcome::PermFail(detail);
                            }
                        }
                    }
                }
            }
        }
        // Persist results before bouncing, so a crash here leaves `perm`
        // recipients that the next pass bounces exactly once.
        self.spool
            .update(&env)
            .await
            .map_err(|err| err.to_string())?;
        if let Some(detail) = self.bounce(&mut env, &body).await? {
            if outcome == DeliveryOutcome::Delivered {
                outcome = DeliveryOutcome::PermFail(detail);
            }
        }
        let retry = env.rcpt_status.iter().any(|status| status.status == TEMP);
        if retry {
            env.attempts = env.attempts.saturating_add(1);
            let wait = next_retry(env.attempts);
            env.next_attempt_at = Some(
                self.clock.now()
                    + time::Duration::try_from(wait).unwrap_or(time::Duration::minutes(5)),
            );
        }
        self.spool
            .update(&env)
            .await
            .map_err(|err| err.to_string())?;
        let next = if retry {
            SpoolState::Deferred
        } else {
            SpoolState::Done
        };
        if env.state != next {
            self.spool
                .transition(&env.id, next)
                .await
                .map_err(|err| err.to_string())?;
        }
        Ok(outcome)
    }

    /// Queue one DSN for the recipients now `perm`, then mark them bounced.
    /// The DSN id is derived from the message and recipients, so a retry after
    /// a crash finds the DSN already spooled instead of sending another.
    async fn bounce(&self, env: &mut Envelope, body: &[u8]) -> Result<Option<String>, String> {
        let failed: Vec<RcptStatus> = env
            .rcpt_status
            .iter()
            .filter(|status| status.status == PERM)
            .cloned()
            .collect();
        let Some(first) = failed.first() else {
            return Ok(None);
        };
        let detail = first.detail.clone();
        if !is_null_sender(&env.mail_from) && client::valid_path(&env.mail_from) {
            let dsn_id = dsn_id(&env.id, &failed);
            let exists = match self.spool.load(&dsn_id).await {
                Ok(_) => true,
                Err(SpoolError::NotFound(_)) => false,
                Err(err) => return Err(err.to_string()),
            };
            if !exists {
                let dsn = build_dsn(&self.cfg.gateway.hostname, env, body, &failed);
                let dsn_env = Envelope {
                    id: dsn_id,
                    tenant_id: env.tenant_id.clone(),
                    mail_from: String::new(),
                    rcpt_to: vec![env.mail_from.clone()],
                    received_at: self.clock.now(),
                    remote_ip: "127.0.0.1".parse().unwrap(),
                    helo: self.cfg.gateway.hostname.clone(),
                    attempts: 0,
                    next_attempt_at: None,
                    state: SpoolState::Incoming,
                    direction: currawong_core::Direction::Inbound,
                    tls_version: None,
                    tls_cipher: None,
                    rcpt_status: Vec::new(),
                    prepend_headers: Vec::new(),
                    dsn_sent: true,
                    pipeline: "pending".into(),
                };
                self.spool
                    .accept(dsn_env, std::io::Cursor::new(dsn))
                    .await
                    .map_err(|err| err.to_string())?;
            }
            env.dsn_sent = true;
        }
        for status in &failed {
            set_status(env, &status.address, BOUNCED, &status.detail);
        }
        Ok(Some(detail))
    }

    async fn deliver_domain(
        &self,
        env: &Envelope,
        message: &[u8],
        domain: &str,
        rcpts: &[String],
    ) -> Vec<(String, DeliveryOutcome)> {
        let all = |outcome: DeliveryOutcome| {
            rcpts
                .iter()
                .map(|rcpt| (rcpt.clone(), outcome.clone()))
                .collect()
        };
        let route = match resolve_route(domain, &self.cfg, self.dns.as_ref()).await {
            Ok(mut route) => {
                if route.via_mx {
                    for addr in route.hops.iter_mut().flat_map(|hop| hop.addrs.iter_mut()) {
                        addr.set_port(self.mx_port);
                    }
                }
                route
            }
            Err(RouteError::Temp(detail)) => return all(DeliveryOutcome::TempFail(detail)),
            Err(RouteError::Perm(detail)) => return all(DeliveryOutcome::PermFail(detail)),
        };
        let tx = Transaction {
            helo: &self.cfg.gateway.hostname,
            mail_from: &env.mail_from,
            rcpts,
            message,
        };
        let sts = match (&self.mta_sts, route.via_mx) {
            (Some(sts), true) => {
                let now = self.clock.now().unix_timestamp();
                sts.discover(domain, self.dns.as_ref(), now).await
            }
            _ => Discovery::NoPolicy,
        };
        if let Discovery::Failed { result, .. } = &sts {
            let policy = PolicyDetails::new(PolicyType::Sts, domain);
            self.record(&policy, Some(failure(*result, "", None))).await;
        }
        let mut last = HostFailure::temp(format!("4.4.1 no host accepted mail for {domain}"));
        for hop in &route.hops {
            let plan = match self.plan(domain, &route, hop, &sts).await {
                Ok(plan) => plan,
                Err(failure) => {
                    tracing::info!(host = %hop.host, detail = %failure.detail, "MX host ruled out");
                    last = failure;
                    continue;
                }
            };
            for addr in &hop.addrs {
                match self.attempt(domain, hop, *addr, &plan, &tx).await {
                    Ok(results) => return results,
                    Err(failure) => {
                        tracing::debug!(host = %hop.host, %addr, detail = %failure.detail, "delivery attempt failed");
                        last = failure;
                    }
                }
            }
        }
        if last.permanent {
            all(DeliveryOutcome::PermFail(last.detail))
        } else {
            all(DeliveryOutcome::TempFail(last.detail))
        }
    }

    /// DANE when the MX and address answers are DNSSEC-secure and usable
    /// TLSA records exist (RFC 7672 section 2.2), else MTA-STS, else
    /// opportunistic. Configured routes skip both policies.
    async fn plan(
        &self,
        domain: &str,
        route: &route::Route,
        hop: &Hop,
        sts: &Discovery,
    ) -> Result<Plan, HostFailure> {
        if !route.via_mx {
            return Ok(Plan::Opportunistic);
        }
        if self.cfg.delivery.dane && route.mx_secure && hop.secure {
            let name = format!("_25._tcp.{}", hop.host);
            match self.dns.resolve_tlsa(&name).await {
                Ok(answer) if answer.secure => {
                    let usable = dane::usable(&answer.records);
                    if !usable.is_empty() {
                        return Ok(Plan::Dane(usable));
                    }
                }
                Ok(_) | Err(crate::dns::LookupError::NxDomain) => {}
                // Fail closed: a TLSA answer that cannot be trusted rules the
                // host out rather than letting delivery fall back.
                Err(err) => {
                    let result = if err == crate::dns::LookupError::Bogus {
                        ResultType::DnssecInvalid
                    } else {
                        ResultType::TlsaInvalid
                    };
                    let mut policy = PolicyDetails::new(PolicyType::Tlsa, domain);
                    policy.mx_host = vec![hop.host.clone()];
                    self.record(&policy, Some(failure(result, &hop.host, None)))
                        .await;
                    return Err(HostFailure {
                        detail: format!("4.7.5 DANE: TLSA lookup for {name} failed: {err}"),
                        permanent: false,
                        tls: Some(result),
                    });
                }
            }
        }
        let Discovery::Found(policy) = sts else {
            return Ok(Plan::Opportunistic);
        };
        if policy.allows(&hop.host) {
            return Ok(Plan::Sts(Arc::clone(policy)));
        }
        let details = sts_policy(domain, policy);
        let result = ResultType::ValidationFailure;
        self.record(&details, Some(failure(result, &hop.host, None)))
            .await;
        if policy.mode == Mode::Enforce {
            return Err(HostFailure {
                detail: format!(
                    "4.7.5 MTA-STS policy for {domain} does not list MX host {}",
                    hop.host
                ),
                permanent: false,
                tls: Some(result),
            });
        }
        Ok(Plan::Opportunistic)
    }

    /// One session to `addr` under `plan`. TLS is verified or not used: when
    /// verification fails and the plan allows it (opportunistic, or an
    /// MTA-STS policy in testing mode), the message goes on a fresh
    /// connection without TLS, never over unverified TLS.
    async fn attempt(
        &self,
        domain: &str,
        hop: &Hop,
        addr: SocketAddr,
        plan: &Plan,
        tx: &Transaction<'_>,
    ) -> Result<Vec<(String, DeliveryOutcome)>, HostFailure> {
        let server_name = ServerName::try_from(hop.host.clone())
            .map_err(|_| HostFailure::temp(format!("4.7.5 bad host name {}", hop.host)))?;
        let webpki = || self.tls.webpki_config().map_err(HostFailure::temp);
        let (starttls, fallback, report) = match plan {
            Plan::Dane(records) => {
                let names = [hop.host.as_str(), domain]
                    .iter()
                    .filter_map(|name| ServerName::try_from(name.to_string()).ok())
                    .collect();
                let config = self
                    .tls
                    .dane_config(records.clone(), names)
                    .map_err(HostFailure::temp)?;
                let mut policy = PolicyDetails::new(PolicyType::Tlsa, domain);
                policy.policy_string = records.iter().map(ToString::to_string).collect();
                policy.mx_host = vec![hop.host.clone()];
                let starttls = Starttls {
                    config,
                    server_name,
                    required: true,
                    policy: format!("DANE for {}", hop.host),
                };
                (starttls, false, Some(policy))
            }
            Plan::Sts(policy) => {
                let starttls = Starttls {
                    config: webpki()?,
                    server_name,
                    required: true,
                    policy: format!("MTA-STS policy for {domain}"),
                };
                let testing = policy.mode == Mode::Testing;
                (starttls, testing, Some(sts_policy(domain, policy)))
            }
            Plan::Opportunistic => {
                let required = self.cfg.delivery.require_tls;
                let starttls = Starttls {
                    config: webpki()?,
                    server_name,
                    required,
                    policy: "delivery.require_tls".into(),
                };
                (starttls, !required, None)
            }
        };
        let stream = client::connect(addr).await?;
        let result = client::send(stream, tx, Some(&starttls)).await;
        if let Some(policy) = &report {
            match &result {
                Ok(_) => self.record(policy, None).await,
                Err(HostFailure {
                    tls: Some(result), ..
                }) => {
                    let failed = failure(*result, &hop.host, Some(addr));
                    self.record(policy, Some(failed)).await;
                }
                Err(_) => {}
            }
        }
        match result {
            Err(failure) if failure.tls.is_some() && fallback => {
                tracing::info!(host = %hop.host, detail = %failure.detail, "TLS did not verify; delivering without TLS");
                let stream = client::connect(addr).await?;
                client::send(stream, tx, None).await
            }
            other => other,
        }
    }

    async fn record(&self, policy: &PolicyDetails, failure: Option<crate::tlsrpt::Failure>) {
        if let Some(store) = &self.tlsrpt {
            let day = self.clock.now().date();
            if let Err(err) = store.record(day, policy, failure.as_ref()).await {
                tracing::warn!(%err, "TLS-RPT result not recorded");
            }
        }
    }

    /// The delivery pass the daemon runs: every scanned message whose retry
    /// time has come, a bounded number at once. One message failing or
    /// panicking cannot stop the others.
    pub async fn poll_due(&self) -> Result<(), String> {
        let now = self.clock.now();
        let mut due = Vec::new();
        for state in [SpoolState::Incoming, SpoolState::Deferred] {
            for env in self
                .spool
                .list(state)
                .await
                .map_err(|err| err.to_string())?
            {
                if is_due(&env, now) {
                    due.push(env.id);
                }
            }
        }
        let limit = self.cfg.delivery.max_concurrent.max(1);
        futures::stream::iter(due)
            .for_each_concurrent(limit, |id| async move {
                match AssertUnwindSafe(self.deliver(&id)).catch_unwind().await {
                    Ok(Ok(_)) => {}
                    Ok(Err(err)) => tracing::error!(%id, %err, "delivery failed"),
                    Err(_) => tracing::error!(%id, "delivery panicked"),
                }
            })
            .await;
        Ok(())
    }
}

fn failure(result: ResultType, mx: &str, ip: Option<SocketAddr>) -> crate::tlsrpt::Failure {
    crate::tlsrpt::Failure {
        result,
        receiving_mx: mx.to_string(),
        receiving_ip: ip.map(|addr| addr.ip()),
    }
}

fn sts_policy(domain: &str, policy: &mta_sts::Policy) -> PolicyDetails {
    let mut details = PolicyDetails::new(PolicyType::Sts, domain);
    details.policy_string = policy.lines();
    details.mx_host = policy.mx.clone();
    details
}

/// Scanned (`pipeline == "deliver"`) and past its retry time.
pub fn is_due(env: &Envelope, now: OffsetDateTime) -> bool {
    env.pipeline == "deliver" && env.next_attempt_at.is_none_or(|at| at <= now)
}

fn group_by_domain(rcpts: &[String]) -> Vec<(String, Vec<String>)> {
    let mut groups: Vec<(String, Vec<String>)> = Vec::new();
    for rcpt in rcpts {
        let domain = rcpt
            .rsplit_once('@')
            .map(|(_, d)| d.to_ascii_lowercase())
            .unwrap_or_default();
        if let Some(group) = groups.iter_mut().find(|item| item.0 == domain) {
            group.1.push(rcpt.clone());
        } else {
            groups.push((domain, vec![rcpt.clone()]));
        }
    }
    groups
}

fn dsn_id(original: &MessageId, failed: &[RcptStatus]) -> MessageId {
    let mut rcpts: Vec<&str> = failed
        .iter()
        .map(|status| status.address.as_str())
        .collect();
    rcpts.sort_unstable();
    let mut hash = Sha256::new();
    hash.update(original.as_str().as_bytes());
    hash.update(b"\0dsn\0");
    hash.update(rcpts.join("\n").as_bytes());
    let digest = hash.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    MessageId(ulid::Ulid::from_bytes(bytes).to_string())
}

fn set_status(env: &mut Envelope, rcpt: &str, status: &str, detail: &str) {
    if let Some(existing) = env.rcpt_status.iter_mut().find(|item| item.address == rcpt) {
        existing.status = status.into();
        existing.detail = detail.into();
    } else {
        env.rcpt_status.push(RcptStatus {
            address: rcpt.into(),
            status: status.into(),
            detail: detail.into(),
        });
    }
}

pub fn is_null_sender(mail_from: &str) -> bool {
    let trimmed = mail_from.trim();
    trimmed.is_empty() || trimmed == "<>"
}

fn received_header(env: &Envelope, hostname: &str) -> String {
    let tls = match &env.tls_version {
        Some(version) => format!(
            "\r\n\t(using {} with cipher {})",
            sanitise_token(version),
            sanitise_token(env.tls_cipher.as_deref().unwrap_or("unknown"))
        ),
        None => String::new(),
    };
    let date = env
        .received_at
        .format(&time::format_description::well_known::Rfc2822)
        .unwrap_or_else(|_| "Thu, 01 Jan 1970 00:00:00 +0000".into());
    format!(
        "Received: from {} ([{}]) by {} with ESMTP id {}{tls};\r\n\t{date}\r\n",
        sanitise_token(&env.helo),
        env.remote_ip,
        hostname,
        env.id
    )
}

fn sanitise_token(value: &str) -> String {
    value
        .chars()
        .map(|ch| if ch.is_ascii_graphic() { ch } else { '_' })
        .collect()
}

pub fn outbound_bytes(env: &Envelope, body: &[u8], hostname: &str) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(received_header(env, hostname).as_bytes());
    for header in &env.prepend_headers {
        out.extend_from_slice(header.as_bytes());
        if !header.ends_with("\r\n") {
            out.extend_from_slice(b"\r\n");
        }
    }
    out.extend_from_slice(body);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status(address: &str) -> RcptStatus {
        RcptStatus {
            address: address.into(),
            status: PERM.into(),
            detail: "550 no".into(),
        }
    }

    #[test]
    fn dsn_id_is_stable_and_spool_safe() {
        let id = MessageId("01HZY0000000000000000000AA".into());
        let a = dsn_id(&id, &[status("a@x.test"), status("b@x.test")]);
        let b = dsn_id(&id, &[status("b@x.test"), status("a@x.test")]);
        assert_eq!(a, b);
        assert!(currawong_spool::is_safe_id(a.as_str()), "{a:?}");
        assert_ne!(a, dsn_id(&id, &[status("a@x.test")]));
    }
}
