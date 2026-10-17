//! Next-hop selection: configured smart host, then MX, then the implicit MX
//! (the domain's own A/AAAA, only when it has no MX records).
use crate::dns::{normalise, DnsLookup, LookupError};
use currawong_core::config::Config;
use std::net::{IpAddr, SocketAddr};

/// One next-hop host and its addresses, in preference order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hop {
    pub host: String,
    pub addrs: Vec<SocketAddr>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    pub hops: Vec<Hop>,
    /// True when the hops came from DNS rather than `domains.routes`.
    pub via_mx: bool,
}

/// Details start with an RFC 3463 enhanced status code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteError {
    Temp(String),
    Perm(String),
}

pub async fn resolve_route(
    domain: &str,
    cfg: &Config,
    dns: &dyn DnsLookup,
) -> Result<Route, RouteError> {
    let domain_l = normalise(domain);
    if let Some(route) = cfg
        .domains
        .routes
        .iter()
        .find(|route| normalise(&route.domain) == domain_l)
    {
        let hop = resolve_hop(&route.next_hop, dns).await?;
        return Ok(Route {
            hops: vec![hop],
            via_mx: false,
        });
    }
    let mx = match dns.resolve_mx(&domain_l).await {
        Ok(answer) => answer.records,
        Err(LookupError::NxDomain) => {
            return Err(RouteError::Perm(format!(
                "5.1.2 domain {domain_l} does not exist"
            )))
        }
        Err(err) => return Err(RouteError::Temp(format!("4.4.3 MX for {domain_l}: {err}"))),
    };
    // RFC 7505: a null MX means the domain accepts no mail at all.
    if mx.iter().any(|(_, host)| normalise(host).is_empty()) {
        return Err(RouteError::Perm(format!(
            "5.1.10 domain {domain_l} does not accept mail (null MX)"
        )));
    }
    let implicit = mx.is_empty();
    let mut hosts = if implicit {
        vec![(0, domain_l.clone())]
    } else {
        mx
    };
    hosts.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    let mut hops = Vec::new();
    let mut last = String::new();
    for (_, host) in hosts {
        let host = normalise(&host);
        match dns.resolve_ips(&host).await {
            Ok(answer) => {
                let addrs: Vec<SocketAddr> = answer
                    .records
                    .into_iter()
                    .filter(|ip| cfg.delivery.allow_private_mx || is_public(ip))
                    .map(|ip| SocketAddr::new(ip, 25))
                    .collect();
                if addrs.is_empty() {
                    last = format!("no usable public address for {host}");
                    if implicit {
                        return Err(RouteError::Perm(format!(
                            "5.1.2 domain {domain_l} has no MX and no usable address"
                        )));
                    }
                } else {
                    hops.push(Hop { host, addrs });
                }
            }
            Err(LookupError::NxDomain) if implicit => {
                return Err(RouteError::Perm(format!(
                    "5.1.2 domain {domain_l} does not exist"
                )))
            }
            Err(err) => {
                tracing::debug!(%err, %host, "MX host lookup failed");
                last = format!("{host}: {err}");
            }
        }
    }
    if hops.is_empty() {
        return Err(RouteError::Temp(format!(
            "4.4.3 no reachable MX host for {domain_l}: {last}"
        )));
    }
    Ok(Route { hops, via_mx: true })
}

/// Addresses an MX answer may point at. Loopback, private, link-local and
/// other special ranges are refused so DNS cannot aim delivery inward.
pub fn is_public(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            !(v4.is_unspecified()
                || v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_documentation()
                || a == 0
                || a >= 240
                || (a == 100 && (64..128).contains(&b))
                || (a == 198 && (18..20).contains(&b)))
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_public(&IpAddr::V4(v4));
            }
            let first = v6.segments()[0];
            !(v6.is_unspecified()
                || v6.is_loopback()
                || v6.is_multicast()
                || v6.is_unicast_link_local()
                || v6.is_unique_local()
                || (first == 0x2001 && v6.segments()[1] == 0x0db8))
        }
    }
}

async fn resolve_hop(next_hop: &str, dns: &dyn DnsLookup) -> Result<Hop, RouteError> {
    if let Ok(addr) = next_hop.parse::<SocketAddr>() {
        return Ok(Hop {
            host: addr.ip().to_string(),
            addrs: vec![addr],
        });
    }
    if let Ok(ip) = next_hop.parse::<IpAddr>() {
        return Ok(Hop {
            host: ip.to_string(),
            addrs: vec![SocketAddr::new(ip, 25)],
        });
    }
    let (host, port) = match next_hop.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() && port.chars().all(|ch| ch.is_ascii_digit()) => {
            let port: u16 = port
                .parse()
                .map_err(|_| RouteError::Temp(format!("4.3.5 bad port in {next_hop}")))?;
            (host, port)
        }
        _ => (next_hop, 25),
    };
    let host = normalise(host);
    let ips = dns
        .resolve_ips(&host)
        .await
        .map_err(|err| RouteError::Temp(format!("4.4.3 next hop {host}: {err}")))?
        .records;
    if ips.is_empty() {
        return Err(RouteError::Temp(format!("4.4.3 no address for {host}")));
    }
    Ok(Hop {
        addrs: ips
            .into_iter()
            .map(|ip| SocketAddr::new(ip, port))
            .collect(),
        host,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::MapDns;

    fn cfg() -> Config {
        Config::default()
    }

    #[tokio::test]
    async fn null_mx_is_permanent() {
        let mut dns = MapDns::new();
        dns.mx.insert("null.test".into(), vec![(0, ".".into())]);
        let err = resolve_route("null.test", &cfg(), &dns).await.unwrap_err();
        assert!(
            matches!(err, RouteError::Perm(ref d) if d.starts_with("5.1.10")),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn nxdomain_is_permanent() {
        let mut dns = MapDns::new();
        dns.nxdomain.insert("gone.test".into());
        let err = resolve_route("gone.test", &cfg(), &dns).await.unwrap_err();
        assert!(
            matches!(err, RouteError::Perm(ref d) if d.starts_with("5.1.2")),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn no_mx_falls_back_to_address() {
        let mut dns = MapDns::new();
        dns.ips
            .insert("plain.test".into(), vec!["192.0.0.9".parse().unwrap()]);
        let route = resolve_route("plain.test", &cfg(), &dns).await.unwrap();
        assert_eq!(route.hops[0].host, "plain.test");
        assert!(route.via_mx);
    }

    #[tokio::test]
    async fn mx_hosts_without_addresses_do_not_fall_back_to_the_domain() {
        let mut dns = MapDns::new();
        dns.mx
            .insert("mx.test".into(), vec![(10, "missing.mx.test".into())]);
        dns.ips
            .insert("mx.test".into(), vec!["192.0.0.9".parse().unwrap()]);
        let err = resolve_route("mx.test", &cfg(), &dns).await.unwrap_err();
        assert!(matches!(err, RouteError::Temp(_)), "{err:?}");
    }

    #[tokio::test]
    async fn private_mx_answers_are_refused() {
        let mut dns = MapDns::new();
        dns.mx
            .insert("inward.test".into(), vec![(10, "mx.inward.test".into())]);
        dns.ips.insert(
            "mx.inward.test".into(),
            vec![
                "127.0.0.1".parse().unwrap(),
                "10.1.2.3".parse().unwrap(),
                "::ffff:192.168.1.1".parse().unwrap(),
                "fd00::1".parse().unwrap(),
            ],
        );
        let err = resolve_route("inward.test", &cfg(), &dns)
            .await
            .unwrap_err();
        assert!(matches!(err, RouteError::Temp(_)), "{err:?}");
        let mut allowed = cfg();
        allowed.delivery.allow_private_mx = true;
        let route = resolve_route("inward.test", &allowed, &dns).await.unwrap();
        assert_eq!(route.hops[0].addrs.len(), 4);
    }

    #[test]
    fn public_addresses_pass() {
        assert!(is_public(&"192.0.0.9".parse().unwrap()));
        assert!(is_public(&"2606:4700::1".parse().unwrap()));
        assert!(!is_public(&"100.64.0.1".parse().unwrap()));
        assert!(!is_public(&"169.254.1.1".parse().unwrap()));
        assert!(!is_public(&"fe80::1".parse().unwrap()));
    }
}
