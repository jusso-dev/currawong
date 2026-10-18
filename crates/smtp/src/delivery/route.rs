//! Next-hop selection: configured smart host, then MX, then the implicit MX
//! (the domain's own A/AAAA, only when it has no MX records).
use crate::dns::{normalise, DnsLookup, LookupError};
use currawong_core::config::{Config, MailboxPlatform};
use rand::seq::SliceRandom;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/// Bounds on what one domain's MX answer can make us try.
pub const MAX_MX_HOSTS: usize = 5;
pub const MAX_ADDRESSES: usize = 10;

/// One next-hop host and its addresses, in preference order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hop {
    pub host: String,
    pub addrs: Vec<SocketAddr>,
    /// The address records (A and AAAA, and any CNAME on the way) were
    /// DNSSEC-validated.
    pub secure: bool,
    /// Where the host name's CNAME chain ended, if anywhere.
    pub canonical: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    pub hops: Vec<Hop>,
    /// True when the hops came from DNS rather than `domains.routes`.
    pub via_mx: bool,
    /// The MX answer (or, for an implicit MX, its absence) was DNSSEC-validated.
    pub mx_secure: bool,
    /// The matched `domains.routes` entry's platform, so the TLS rule comes
    /// from the same lookup as the hops.
    pub platform: Option<MailboxPlatform>,
}

/// Details start with an RFC 3463 enhanced status code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteError {
    Temp(String),
    Perm(String),
}

/// A plain host name: dot-separated labels of letters, digits and inner
/// hyphens. Checked before a name goes into a DNS query or a URL, so a
/// recipient domain cannot smuggle a port, path, user or address literal.
pub fn valid_domain(name: &str) -> bool {
    let name = name.strip_suffix('.').unwrap_or(name);
    // No top-level domain is all digits, so this also rules out IPv4 literals.
    let numeric_tld = name
        .rsplit('.')
        .next()
        .is_some_and(|tld| tld.chars().all(|ch| ch.is_ascii_digit()));
    !numeric_tld
        && (1..=253).contains(&name.len())
        && name.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.chars().all(|ch| ch.is_alphanumeric() || ch == '-')
        })
}

pub async fn resolve_route(
    domain: &str,
    cfg: &Config,
    dns: &dyn DnsLookup,
) -> Result<Route, RouteError> {
    let domain_l = normalise(domain);
    if let Some(route) = cfg.domains.route_for(&domain_l) {
        let hops = match &route.platform {
            // One hop per Mailbox server, in order. A server whose name does
            // not resolve is skipped, with a warning; delivery fails over to
            // the next.
            Some(MailboxPlatform::ExchangeOnPrem { mailbox_hosts, .. }) => {
                let mut hops = Vec::new();
                let mut last = None;
                for host in mailbox_hosts {
                    match resolve_hop(host, dns).await {
                        Ok(hop) => hops.push(hop),
                        Err(err) => {
                            tracing::warn!(domain = %domain_l, %host, ?err, "Exchange Mailbox server skipped");
                            last = Some(err);
                        }
                    }
                }
                match (hops.is_empty(), last) {
                    (true, Some(err)) => return Err(err),
                    _ => hops,
                }
            }
            _ => vec![resolve_hop(&route.next_hop, dns).await?],
        };
        return Ok(Route {
            hops,
            via_mx: false,
            mx_secure: false,
            platform: route.platform.clone(),
        });
    }
    let (mx, mx_secure) = match dns.resolve_mx(&domain_l).await {
        Ok(answer) => (answer.records, answer.secure),
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
    // RFC 5321 5.1: hosts of equal preference are tried in random order.
    hosts.shuffle(&mut rand::thread_rng());
    hosts.sort_by_key(|host| host.0);
    hosts.truncate(MAX_MX_HOSTS);
    let mut hops = Vec::new();
    let mut budget = MAX_ADDRESSES;
    let mut last = String::new();
    for (_, host) in hosts {
        if budget == 0 {
            break;
        }
        let host = normalise(&host);
        match dns.resolve_ips(&host).await {
            Ok(answer) => {
                let addrs: Vec<SocketAddr> = answer
                    .records
                    .into_iter()
                    .filter(|ip| cfg.delivery.allow_private_mx || is_public(ip))
                    .map(|ip| SocketAddr::new(ip, 25))
                    .take(budget)
                    .collect();
                budget -= addrs.len();
                if addrs.is_empty() {
                    last = format!("no usable public address for {host}");
                    if implicit {
                        return Err(RouteError::Perm(format!(
                            "5.1.2 domain {domain_l} has no MX and no usable address"
                        )));
                    }
                } else {
                    hops.push(Hop {
                        host,
                        addrs,
                        secure: answer.secure,
                        canonical: answer.canonical,
                    });
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
    Ok(Route {
        hops,
        via_mx: true,
        mx_secure,
        platform: None,
    })
}

/// Addresses an MX answer may point at. Loopback, private, link-local and
/// other special ranges are refused so DNS cannot aim delivery inward.
pub fn is_public(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            let c = v4.octets()[2];
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
                || (a == 198 && (18..20).contains(&b))
                // IETF protocol assignments and the old 6to4 relay anycast.
                || (a == 192 && b == 0 && c == 0)
                || (a == 192 && b == 88 && c == 99))
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_public(&IpAddr::V4(v4));
            }
            let s = v6.segments();
            let embedded = |hi: u16, lo: u16| {
                is_public(&IpAddr::V4(Ipv4Addr::new(
                    (hi >> 8) as u8,
                    hi as u8,
                    (lo >> 8) as u8,
                    lo as u8,
                )))
            };
            // NAT64 (64:ff9b::/96) and 6to4 (2002::/16) carry an IPv4
            // address that must itself be public.
            if s[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
                return embedded(s[6], s[7]);
            }
            if s[0] == 0x2002 {
                return embedded(s[1], s[2]);
            }
            !(v6.is_unspecified()
                || v6.is_loopback()
                || v6.is_multicast()
                || v6.is_unicast_link_local()
                || v6.is_unique_local()
                // IPv4-compatible ::/96, deprecated site-local fec0::/10,
                // Teredo 2001::/32 and documentation 2001:db8::/32, 3fff::/20.
                || s[..6] == [0; 6]
                || (s[0] & 0xffc0) == 0xfec0
                || (s[0] == 0x2001 && (s[1] == 0 || s[1] == 0x0db8))
                || (s[0] == 0x3fff && s[1] < 0x1000))
        }
    }
}

async fn resolve_hop(next_hop: &str, dns: &dyn DnsLookup) -> Result<Hop, RouteError> {
    if let Ok(addr) = next_hop.parse::<SocketAddr>() {
        return Ok(Hop {
            host: addr.ip().to_string(),
            addrs: vec![addr],
            secure: false,
            canonical: None,
        });
    }
    if let Ok(ip) = next_hop.parse::<IpAddr>() {
        return Ok(Hop {
            host: ip.to_string(),
            addrs: vec![SocketAddr::new(ip, 25)],
            secure: false,
            canonical: None,
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
    let answer = dns
        .resolve_ips(&host)
        .await
        .map_err(|err| RouteError::Temp(format!("4.4.3 next hop {host}: {err}")))?;
    let ips = answer.records;
    if ips.is_empty() {
        return Err(RouteError::Temp(format!("4.4.3 no address for {host}")));
    }
    Ok(Hop {
        addrs: ips
            .into_iter()
            .map(|ip| SocketAddr::new(ip, port))
            .collect(),
        host,
        secure: answer.secure,
        canonical: answer.canonical,
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
            .insert("plain.test".into(), vec!["93.184.216.34".parse().unwrap()]);
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
            .insert("mx.test".into(), vec!["93.184.216.34".parse().unwrap()]);
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
        assert!(is_public(&"93.184.216.34".parse().unwrap()));
        assert!(is_public(&"2606:4700::1".parse().unwrap()));
        assert!(!is_public(&"100.64.0.1".parse().unwrap()));
        assert!(!is_public(&"169.254.1.1".parse().unwrap()));
        assert!(!is_public(&"fe80::1".parse().unwrap()));
        for special in [
            "192.0.0.9",
            "192.88.99.1",
            "64:ff9b::a00:1",
            "2002:7f00:1::",
            "2001:0:4136:e378::1",
            "::127.0.0.1",
            "fec0::1",
            "3fff::1",
        ] {
            assert!(!is_public(&special.parse().unwrap()), "{special}");
        }
        assert!(is_public(&"64:ff9b::5db8:d822".parse().unwrap()));
        assert!(is_public(&"2002:5db8:d822::".parse().unwrap()));
    }

    #[test]
    fn domains_are_plain_host_names() {
        assert!(valid_domain("example.test"));
        assert!(valid_domain("xn--bcher-kva.test."));
        for bad in [
            "",
            "evil.test:8443",
            "evil.test/path",
            "user@evil.test",
            "[127.0.0.1]",
            "127.0.0.1",
            "-x.test",
            "a..test",
            "a b.test",
        ] {
            assert!(!valid_domain(bad), "{bad}");
        }
    }

    #[tokio::test]
    async fn mx_hosts_and_addresses_are_capped() {
        let mut dns = MapDns::new();
        let hosts: Vec<(u16, String)> = (0..8).map(|i| (10, format!("mx{i}.big.test"))).collect();
        for (_, host) in &hosts {
            let ips = (1..=4)
                .map(|n| format!("93.184.216.{n}").parse().unwrap())
                .collect();
            dns.ips.insert(host.clone(), ips);
        }
        dns.mx.insert("big.test".into(), hosts);
        let route = resolve_route("big.test", &cfg(), &dns).await.unwrap();
        assert!(route.hops.len() <= MAX_MX_HOSTS);
        let addresses: usize = route.hops.iter().map(|hop| hop.addrs.len()).sum();
        assert_eq!(addresses, MAX_ADDRESSES);
    }
}
