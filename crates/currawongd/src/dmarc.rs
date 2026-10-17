//! Daily DMARC aggregate reports into the outbound spool, and BIMI logos for
//! quarantined mail. Both run off the classify and delivery loop so slow or
//! hostile DNS cannot stall mail.
use currawong_auth::{
    bimi::{self, Bimi, TxtLookup},
    dmarc_report::{render_report, submitter, valid_address, Failure},
    AuthChecker, DmarcEventStore,
};
use currawong_core::{config::Config, AuthResults, Direction, MessageId};
use currawong_quarantine::QuarantineStore;
use currawong_smtp::dns::DnsLookup;
use currawong_spool::{Envelope, Spool, SpoolState};
use futures::StreamExt;
use std::{
    collections::HashMap,
    future::Future,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::{Duration, Instant},
};
use time::OffsetDateTime;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

const DNS_TIMEOUT: Duration = Duration::from_secs(5);
/// More MX hosts than this and the destination is refused outright.
const MAX_MX_HOSTS: usize = 10;
/// Domain-days worked on at once.
const CONCURRENCY: usize = 8;
/// Whatever is unfinished when a pass hits this is left for the next pass.
const PASS_DEADLINE: Duration = Duration::from_secs(240);
const BIMI_CACHE_TTL: Duration = Duration::from_secs(60 * 60);
const BIMI_CACHE_MAX: usize = 10_000;
pub const BIMI_QUEUE: usize = 256;

/// What became of one due domain-day.
enum Outcome {
    Queued,
    Finished,
    Retry(String),
}

/// Queue reports for every due domain-day, a few at a time, within
/// [`PASS_DEADLINE`]. Each domain-day is finished on its own right after its
/// report is spooled; one that hits a DNS failure backs off without holding
/// up the rest, and is given up after `MAX_ATTEMPTS`. Returns how many
/// reports were queued.
pub async fn send_dmarc_reports(
    spool: &Spool,
    auth: &AuthChecker,
    store: &DmarcEventStore,
    cfg: &Config,
    dns: &dyn DnsLookup,
    now: OffsetDateTime,
) -> Result<usize, String> {
    let secs = now.unix_timestamp().max(0) as u64;
    let local = local_domains(cfg);
    let local = &local;
    let mut work = futures::stream::iter(store.due(secs)?)
        .map(|(day, domain)| async move {
            let outcome = report_domain(spool, auth, store, cfg, dns, local, day, &domain, now)
                .await
                .unwrap_or_else(Outcome::Retry);
            (day, domain, outcome)
        })
        .buffer_unordered(CONCURRENCY);
    let deadline = tokio::time::sleep(PASS_DEADLINE);
    tokio::pin!(deadline);
    let mut queued = 0;
    loop {
        tokio::select! {
            item = work.next() => {
                let Some((day, domain, outcome)) = item else { break };
                match outcome {
                    Outcome::Queued => queued += 1,
                    Outcome::Finished => {}
                    Outcome::Retry(reason) => match store.note_failure(day, &domain, secs)? {
                        Failure::Retry => tracing::info!(%domain, day, %reason, "dmarc report will be retried"),
                        Failure::Dropped => tracing::warn!(%domain, day, %reason, "dmarc report given up"),
                    },
                }
            }
            _ = &mut deadline => {
                tracing::info!("dmarc report pass hit its deadline, the rest waits for the next pass");
                break;
            }
        }
    }
    Ok(queued)
}

#[allow(clippy::too_many_arguments)]
async fn report_domain(
    spool: &Spool,
    auth: &AuthChecker,
    store: &DmarcEventStore,
    cfg: &Config,
    dns: &dyn DnsLookup,
    local: &[String],
    day: u64,
    domain: &str,
    now: OffsetDateTime,
) -> Result<Outcome, String> {
    let settings = &cfg.auth.dmarc_reports;
    // Claimed first: rows recorded from now on are refused, so everything
    // loaded here is exactly what `finish` removes.
    let id = MessageId(store.claim(day, domain, Envelope::new_id().as_str())?);
    let Some(data) = store.load(day, domain)? else {
        store.finish(day, domain)?;
        return Ok(Outcome::Finished);
    };
    let Some(allowed) = auth.authorised_rua(domain, &data.rua, local).await else {
        return Ok(Outcome::Retry("rua verification hit a DNS error".into()));
    };
    let mut destinations = Vec::new();
    for uri in allowed {
        let host = uri
            .uri()
            .rsplit_once('@')
            .map(|(_, host)| host)
            .unwrap_or("");
        match public_destination(dns, host).await {
            None => return Ok(Outcome::Retry(format!("MX lookup for {host} failed"))),
            Some(true) => destinations.push(uri),
            Some(false) => {
                tracing::warn!(%domain, %host, "rua destination is not a public mail host, refused")
            }
        }
    }
    let Some(report) = render_report(settings, &data, &destinations)? else {
        tracing::info!(%domain, "no usable rua destination, report not sent");
        store.finish(day, domain)?;
        return Ok(Outcome::Finished);
    };
    let rcpt_to: Vec<String> = report
        .to
        .iter()
        .filter(|address| valid_address(address))
        .cloned()
        .collect();
    // A report spooled before a crash is not queued a second time.
    if spool.load(&id).await.is_err() && !rcpt_to.is_empty() {
        // Generated here, so there is nothing to scan: mark it deliverable.
        // Not DKIM signed yet: signing happens at classify with a tenant
        // key, and a report skips classify and carries no tenant.
        let env = Envelope {
            id: id.clone(),
            tenant_id: None,
            authenticated_as: None,
            mail_from: report.from.clone(),
            rcpt_to,
            received_at: now,
            remote_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            helo: submitter(settings).to_string(),
            attempts: 0,
            next_attempt_at: None,
            state: SpoolState::Incoming,
            direction: Direction::Outbound,
            tls_version: None,
            tls_cipher: None,
            rcpt_status: Vec::new(),
            prepend_headers: Vec::new(),
            dsn_sent: false,
            pipeline: "deliver".into(),
        };
        spool
            .accept(env, report.message.as_slice())
            .await
            .map_err(|err| err.to_string())?;
        tracing::info!(%domain, rcpts = report.to.len(), "dmarc aggregate report queued");
    }
    store.finish(day, domain)?;
    Ok(Outcome::Queued)
}

/// Domains the gateway accepts, routes or relays for. Reports never go there.
fn local_domains(cfg: &Config) -> Vec<String> {
    let mut domains = cfg.domains.accept.clone();
    domains.extend(cfg.domains.routes.iter().map(|route| route.domain.clone()));
    for tenant in &cfg.relay.tenants {
        domains.extend(tenant.domains.iter().cloned());
    }
    domains
}

/// Whether every MX host (or the host itself, when it has no MX) resolves
/// only to public addresses. A null MX or more than [`MAX_MX_HOSTS`] hosts is
/// a definitive refusal. `None` is a DNS failure or timeout.
async fn public_destination(dns: &dyn DnsLookup, host: &str) -> Option<bool> {
    let mx = tokio::time::timeout(DNS_TIMEOUT, dns.lookup_mx(host))
        .await
        .ok()?
        .ok()?;
    if mx.len() > MAX_MX_HOSTS {
        return Some(false);
    }
    let mut hosts = Vec::new();
    for (_, exchange) in &mx {
        let exchange = exchange.trim_end_matches('.');
        // RFC 7505 null MX: the domain accepts no mail.
        if exchange.is_empty() {
            return Some(false);
        }
        hosts.push(exchange.to_string());
    }
    if hosts.is_empty() {
        hosts.push(host.to_string());
    }
    let mut any = false;
    for host in hosts {
        let ips = tokio::time::timeout(DNS_TIMEOUT, dns.lookup_ips(&host))
            .await
            .ok()?
            .ok()?;
        if ips.iter().any(|ip| !is_public(*ip)) {
            return Some(false);
        }
        any |= !ips.is_empty();
    }
    Some(any)
}

/// Loopback, private, link-local, CGNAT, benchmarking, IETF protocol,
/// unique-local, site-local, multicast, unspecified and transition
/// (NAT64, 6to4, IPv4-compatible and IPv4-mapped to a non-public v4)
/// addresses are not public.
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, c, _] = v4.octets();
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || a == 0
                || a >= 240
                || (a == 100 && (64..128).contains(&b))
                || (a == 198 && (b == 18 || b == 19))
                || (a == 192 && b == 0 && c == 0))
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_public(IpAddr::V4(v4));
            }
            let segments = v6.segments();
            let first = segments[0];
            let nat64 = segments[..6] == [0x64, 0xff9b, 0, 0, 0, 0];
            let compatible = segments[..6] == [0; 6] && v6 != Ipv6Addr::UNSPECIFIED;
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || nat64
                || compatible
                || first == 0x2002
                || (first & 0xfe00) == 0xfc00
                || (first & 0xffc0) == 0xfe80
                || (first & 0xffc0) == 0xfec0)
        }
    }
}

/// Run `make()` as a task until it returns or `shutdown` fires. A panic is
/// logged and the task restarted after a backoff that doubles from `base`
/// up to five minutes.
pub async fn supervise<F, Fut>(name: &str, shutdown: CancellationToken, base: Duration, mut make: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = ()> + Send + 'static,
{
    let mut failures = 0u32;
    loop {
        let mut task = tokio::spawn(make());
        tokio::select! {
            _ = shutdown.cancelled() => {
                task.abort();
                return;
            }
            result = &mut task => match result {
                Ok(()) => return,
                Err(err) => {
                    failures = failures.saturating_add(1);
                    let wait = base
                        .saturating_mul(1 << failures.min(10))
                        .min(Duration::from_secs(300));
                    tracing::error!(task = name, %err, ?wait, "task stopped, restarting");
                    tokio::select! {
                        _ = shutdown.cancelled() => return,
                        _ = tokio::time::sleep(wait) => {}
                    }
                }
            },
        }
    }
}

/// A quarantined message to look up a BIMI logo for.
#[derive(Debug, Clone)]
pub struct BimiJob {
    pub id: MessageId,
    pub auth: AuthResults,
}

/// Looks BIMI up off the classify loop, one domain lookup per hour at most.
#[derive(Default)]
pub struct BimiWorker {
    cache: HashMap<String, (Instant, Option<Bimi>)>,
}

impl BimiWorker {
    pub async fn handle(
        &mut self,
        txt: &dyn TxtLookup,
        quarantine: &QuarantineStore,
        job: BimiJob,
    ) {
        let Some(domain) = bimi::eligible(&job.auth) else {
            return;
        };
        let cached = self
            .cache
            .get(&domain)
            .filter(|(at, _)| at.elapsed() < BIMI_CACHE_TTL)
            .map(|(_, found)| found.clone());
        let found = match cached {
            Some(found) => found,
            None => {
                let found = tokio::time::timeout(DNS_TIMEOUT, bimi::fetch(txt, &domain))
                    .await
                    .ok()
                    .flatten();
                if self.cache.len() >= BIMI_CACHE_MAX {
                    self.cache.clear();
                }
                self.cache
                    .insert(domain.clone(), (Instant::now(), found.clone()));
                found
            }
        };
        let Some(found) = found else {
            return;
        };
        let id = job.id.as_str();
        let result = serde_json::to_string(&found)
            .map_err(|err| err.to_string())
            .and_then(|json| {
                quarantine
                    .set_bimi(id, &json)
                    .map_err(|err| err.to_string())
            });
        if let Err(err) = result {
            tracing::warn!(%id, %err, "BIMI not stored");
        }
    }

    /// Serve jobs until every sender is gone.
    pub async fn run(
        mut self,
        txt: impl TxtLookup,
        quarantine: QuarantineStore,
        mut jobs: mpsc::Receiver<BimiJob>,
    ) {
        while let Some(job) = jobs.recv().await {
            self.handle(&txt, &quarantine, job).await;
        }
    }
}
