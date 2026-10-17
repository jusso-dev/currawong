//! Outbound delivery, retries and DSNs.
pub mod client;
mod dsn;
pub mod route;

use crate::dns::DnsLookup;
pub use dsn::{build_dsn, status_code};
pub use route::{resolve_route, RouteError};

use client::{HostFailure, Transaction};
use currawong_core::{config::Config, MessageId};
use currawong_spool::{next_retry, Envelope, RcptStatus, Spool, SpoolError, SpoolState};
use futures::{FutureExt, StreamExt};
use sha2::{Digest, Sha256};
use std::{panic::AssertUnwindSafe, sync::Arc, time::Duration};
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
}

impl<D: DnsLookup> Deliverer<D> {
    pub fn new(spool: Arc<Spool>, cfg: Arc<Config>, dns: Arc<D>) -> Self {
        Self {
            spool,
            cfg,
            dns,
            clock: TokioClock::new(),
            mx_port: 25,
        }
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
        let mut last = HostFailure {
            detail: format!("4.4.1 no host accepted mail for {domain}"),
            permanent: false,
        };
        for hop in &route.hops {
            for addr in &hop.addrs {
                let attempt = match client::connect(*addr).await {
                    Ok(stream) => client::send(stream, &tx).await,
                    Err(failure) => Err(failure),
                };
                match attempt {
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
