//! Next-hop selection: configured smart host, then MX, then A/AAAA.
use crate::dns::{normalise, DnsLookup};
use currawong_core::config::Config;
use std::net::{IpAddr, SocketAddr};

pub async fn resolve_route(
    domain: &str,
    cfg: &Config,
    dns: &dyn DnsLookup,
) -> Result<Vec<SocketAddr>, String> {
    let domain_l = normalise(domain);
    if let Some(route) = cfg
        .domains
        .routes
        .iter()
        .find(|route| normalise(&route.domain) == domain_l)
    {
        return resolve_hop(&route.next_hop, dns).await;
    }
    let mx = dns.lookup_mx(&domain_l).await?;
    let mut hosts: Vec<(u16, String)> = mx;
    hosts.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    if hosts.is_empty() {
        return resolve_host(&domain_l, 25, dns).await;
    }
    let mut out = Vec::new();
    for (_, host) in hosts {
        let host = normalise(&host);
        if host == "." || host.is_empty() {
            continue;
        }
        match resolve_host(&host, 25, dns).await {
            Ok(addrs) => out.extend(addrs),
            Err(err) => tracing::debug!(%err, %host, "MX host lookup failed"),
        }
    }
    if out.is_empty() {
        resolve_host(&domain_l, 25, dns).await
    } else {
        Ok(out)
    }
}

async fn resolve_hop(next_hop: &str, dns: &dyn DnsLookup) -> Result<Vec<SocketAddr>, String> {
    if let Ok(addr) = next_hop.parse::<SocketAddr>() {
        return Ok(vec![addr]);
    }
    if let Ok(ip) = next_hop.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, 25)]);
    }
    let (host, port) = match next_hop.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() && port.chars().all(|ch| ch.is_ascii_digit()) => {
            let port: u16 = port
                .parse()
                .map_err(|_| format!("bad port in {next_hop}"))?;
            (host, port)
        }
        _ => (next_hop, 25),
    };
    resolve_host(host, port, dns).await
}

async fn resolve_host(
    host: &str,
    port: u16,
    dns: &dyn DnsLookup,
) -> Result<Vec<SocketAddr>, String> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    let ips = dns.lookup_ips(host).await?;
    if ips.is_empty() {
        return Err(format!("no address for {host}"));
    }
    Ok(ips
        .into_iter()
        .map(|ip| SocketAddr::new(ip, port))
        .collect())
}
