//! Daily DMARC aggregate reports into the outbound spool, and BIMI logos for
//! quarantined mail. Runs as its own task so slow DNS cannot stall delivery.
use currawong_auth::{
    bimi::{self, TxtLookup},
    dmarc_report::{render_report, submitter, valid_address},
    AuthChecker, DmarcEventStore,
};
use currawong_core::{config::Config, Direction, MessageId, ScanReport};
use currawong_quarantine::QuarantineStore;
use currawong_smtp::dns::DnsLookup;
use currawong_spool::{Envelope, Spool, SpoolState};
use std::{
    net::{IpAddr, Ipv4Addr},
    time::Duration,
};
use time::OffsetDateTime;

const DNS_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_MX_HOSTS: usize = 5;

/// Queue reports for every due day. Each domain-day is finished on its own,
/// right after its report is spooled. A DNS failure leaves that domain's rows
/// for the next pass. Returns how many reports were queued.
pub async fn send_dmarc_reports(
    spool: &Spool,
    auth: &AuthChecker,
    store: &DmarcEventStore,
    cfg: &Config,
    dns: &dyn DnsLookup,
    now: OffsetDateTime,
) -> Result<usize, String> {
    let local = local_domains(cfg);
    let mut queued = 0;
    for day in store.pending_days(now.unix_timestamp().max(0) as u64)? {
        for domain in store.domains(day)? {
            match report_domain(spool, auth, store, cfg, dns, &local, day, &domain, now).await {
                Ok(true) => queued += 1,
                Ok(false) => {}
                Err(err) => tracing::warn!(%domain, day, %err, "dmarc report failed, will retry"),
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
) -> Result<bool, String> {
    let settings = &cfg.auth.dmarc_reports;
    let Some(data) = store.load(day, domain)? else {
        return Ok(false);
    };
    let Some(allowed) = auth.authorised_rua(domain, &data.rua, local).await else {
        tracing::info!(%domain, "rua verification hit a DNS error, will retry");
        return Ok(false);
    };
    let mut destinations = Vec::new();
    for uri in allowed {
        let host = uri
            .uri()
            .rsplit_once('@')
            .map(|(_, host)| host)
            .unwrap_or("");
        match public_destination(dns, host).await {
            None => {
                tracing::info!(%domain, %host, "rua MX lookup failed, will retry");
                return Ok(false);
            }
            Some(true) => destinations.push(uri),
            Some(false) => {
                tracing::warn!(%domain, %host, "rua destination resolves to a non-public address, refused")
            }
        }
    }
    let Some(report) = render_report(settings, &data, &destinations)? else {
        if !data.rua.is_empty() {
            tracing::info!(%domain, "no usable rua destination, report not sent");
        }
        store.finish(day, domain)?;
        return Ok(false);
    };
    let rcpt_to: Vec<String> = report
        .to
        .iter()
        .filter(|address| valid_address(address))
        .cloned()
        .collect();
    let id = MessageId(store.spool_id(day, domain, Envelope::new_id().as_str())?);
    // A report spooled before a crash is not queued a second time.
    if spool.load(&id).await.is_err() && !rcpt_to.is_empty() {
        // Generated here, so there is nothing to scan: mark it deliverable.
        // Reports leave through outbound delivery like any other message, so
        // they pick up outbound DKIM signing once delivery applies it.
        let env = Envelope {
            id: id.clone(),
            tenant_id: None,
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
    Ok(true)
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

/// Whether every MX (or the host itself) resolves only to public addresses.
/// `None` is a DNS failure or timeout.
async fn public_destination(dns: &dyn DnsLookup, host: &str) -> Option<bool> {
    let mx = tokio::time::timeout(DNS_TIMEOUT, dns.lookup_mx(host))
        .await
        .ok()?
        .ok()?;
    let hosts: Vec<String> = if mx.is_empty() {
        vec![host.to_string()]
    } else {
        mx.into_iter()
            .take(MAX_MX_HOSTS)
            .map(|(_, exchange)| exchange.trim_end_matches('.').to_string())
            .collect()
    };
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

/// Loopback, private, link-local, CGNAT, unique-local, multicast and
/// unspecified addresses are not public.
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || a == 0
                || a >= 240
                || (a == 100 && (64..128).contains(&b)))
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_public(IpAddr::V4(v4));
            }
            let first = v6.segments()[0];
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (first & 0xfe00) == 0xfc00
                || (first & 0xffc0) == 0xfe80)
        }
    }
}

/// Store the BIMI logo and VMC status beside a quarantined message.
pub async fn annotate_bimi(txt: &dyn TxtLookup, quarantine: &QuarantineStore, report: &ScanReport) {
    let Some(auth) = &report.auth else {
        return;
    };
    let Ok(Some(found)) = tokio::time::timeout(DNS_TIMEOUT, bimi::lookup(txt, auth)).await else {
        return;
    };
    let id = report.message_id.as_str();
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
