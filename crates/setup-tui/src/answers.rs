//! Wizard answers: validation and the TOML they produce.
use serde::Serialize;
use std::net::IpAddr;

pub const CLAMD_SOCKET: &str = "unix:/run/clamav/clamd.ctl";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answers {
    pub hostname: String,
    pub domains: Vec<String>,
    pub next_hop: String,
    pub relay_cidrs: Vec<String>,
    pub clamd: bool,
}

impl Answers {
    /// Validate raw form input. Errors name the field so the form can show them.
    pub fn parse(
        hostname: &str,
        domains: &str,
        next_hop: &str,
        relay_cidrs: &str,
        clamd: bool,
    ) -> Result<Self, String> {
        let hostname = parse_hostname(hostname).map_err(|err| format!("Hostname: {err}"))?;
        let domains = parse_domains(domains).map_err(|err| format!("Domains: {err}"))?;
        let next_hop = parse_next_hop(next_hop).map_err(|err| format!("Next hop: {err}"))?;
        let relay_cidrs =
            parse_cidrs(relay_cidrs).map_err(|err| format!("Relay networks: {err}"))?;
        Ok(Self {
            hostname,
            domains,
            next_hop,
            relay_cidrs,
            clamd,
        })
    }

    /// The config file. Values go through the TOML serialiser, never string
    /// formatting, so input cannot add keys. Keys not written keep defaults.
    pub fn to_toml(&self) -> String {
        let doc = Doc {
            gateway: Gateway {
                hostname: &self.hostname,
            },
            auth: Auth {
                authserv_id: &self.hostname,
            },
            domains: Domains {
                accept: &self.domains,
                routes: self
                    .domains
                    .iter()
                    .map(|domain| Route {
                        domain,
                        next_hop: &self.next_hop,
                    })
                    .collect(),
            },
            relay: Relay {
                tenants: vec![Tenant {
                    id: "default",
                    domains: &self.domains,
                    trusted_cidrs: &self.relay_cidrs,
                }],
            },
            scanner: Scanner {
                clamd: Clamd {
                    address: if self.clamd { CLAMD_SOCKET } else { "" },
                    // Off means the operator chose to run without ClamAV.
                    // Required with no address fails config validation.
                    required: self.clamd,
                },
            },
        };
        let body = toml::to_string(&doc).expect("wizard config serialises");
        format!(
            "# Written by currawong-setup. Keys not set here keep their defaults.\n\
             # Every key is documented in /usr/share/doc/currawong/currawong.example.toml.\n\n{body}"
        )
    }
}

#[derive(Serialize)]
struct Doc<'a> {
    gateway: Gateway<'a>,
    auth: Auth<'a>,
    domains: Domains<'a>,
    relay: Relay<'a>,
    scanner: Scanner<'a>,
}

#[derive(Serialize)]
struct Gateway<'a> {
    hostname: &'a str,
}

#[derive(Serialize)]
struct Auth<'a> {
    authserv_id: &'a str,
}

#[derive(Serialize)]
struct Domains<'a> {
    accept: &'a [String],
    routes: Vec<Route<'a>>,
}

#[derive(Serialize)]
struct Route<'a> {
    domain: &'a str,
    next_hop: &'a str,
}

#[derive(Serialize)]
struct Relay<'a> {
    tenants: Vec<Tenant<'a>>,
}

#[derive(Serialize)]
struct Tenant<'a> {
    id: &'a str,
    domains: &'a [String],
    trusted_cidrs: &'a [String],
}

#[derive(Serialize)]
struct Scanner<'a> {
    clamd: Clamd<'a>,
}

#[derive(Serialize)]
struct Clamd<'a> {
    address: &'a str,
    required: bool,
}

/// A fully qualified DNS name: two or more RFC 1123 labels.
pub fn parse_hostname(input: &str) -> Result<String, String> {
    let name = input.trim().trim_end_matches('.').to_ascii_lowercase();
    if name.is_empty() {
        return Err("required".into());
    }
    if name.len() > 253 {
        return Err("longer than 253 characters".into());
    }
    let labels: Vec<&str> = name.split('.').collect();
    if labels.len() < 2 {
        return Err(format!("'{name}' is not fully qualified"));
    }
    for label in labels {
        let valid = !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '-');
        if !valid {
            return Err(format!("'{name}' is not a valid DNS name"));
        }
    }
    Ok(name)
}

/// Domains separated by commas or spaces. At least one, duplicates dropped.
pub fn parse_domains(input: &str) -> Result<Vec<String>, String> {
    let mut out: Vec<String> = Vec::new();
    for item in split_list(input) {
        let domain = parse_hostname(item)?;
        if !out.contains(&domain) {
            out.push(domain);
        }
    }
    if out.is_empty() {
        return Err("at least one domain is required".into());
    }
    Ok(out)
}

/// `host`, `host:port`, an IP address or `ip:port`, as the delivery router accepts.
pub fn parse_next_hop(input: &str) -> Result<String, String> {
    let hop = input.trim();
    if hop.is_empty() {
        return Err("required".into());
    }
    if hop.parse::<std::net::SocketAddr>().is_ok() || hop.parse::<IpAddr>().is_ok() {
        return Ok(hop.to_string());
    }
    let (host, port) = match hop.rsplit_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (hop, None),
    };
    if let Some(port) = port {
        match port.parse::<u16>() {
            Ok(port) if port > 0 => {}
            _ => return Err(format!("'{port}' is not a port")),
        }
    }
    let host = if host.parse::<IpAddr>().is_ok() {
        host.to_string()
    } else {
        parse_hostname(host)?
    };
    Ok(match port {
        Some(port) => format!("{host}:{port}"),
        None => host,
    })
}

/// CIDRs separated by commas or spaces. May be empty (no relaying).
pub fn parse_cidrs(input: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for item in split_list(input) {
        let net: ipnet::IpNet = item
            .parse()
            .map_err(|_| format!("'{item}' is not a CIDR such as 10.0.0.0/8"))?;
        out.push(net.to_string());
    }
    Ok(out)
}

fn split_list(input: &str) -> impl Iterator<Item = &str> {
    input
        .split(|ch: char| ch == ',' || ch.is_whitespace())
        .filter(|item| !item.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Answers {
        Answers::parse(
            "GW.Example.Test.",
            "example.test, example.org example.test",
            "tenant.mail.protection.outlook.com",
            "10.0.0.0/8, 2001:db8::/32",
            true,
        )
        .unwrap()
    }

    #[test]
    fn parses_and_normalises() {
        let answers = sample();
        assert_eq!(answers.hostname, "gw.example.test");
        assert_eq!(answers.domains, ["example.test", "example.org"]);
        assert_eq!(answers.relay_cidrs, ["10.0.0.0/8", "2001:db8::/32"]);
    }

    #[test]
    fn rejects_bad_input() {
        assert!(parse_hostname("localhost").is_err());
        assert!(parse_hostname("-bad.example.test").is_err());
        assert!(parse_hostname("gw\".example.test").is_err());
        assert!(parse_domains("").is_err());
        assert!(parse_domains("example.test\"]\n[x]").is_err());
        assert!(parse_next_hop("").is_err());
        assert!(parse_next_hop("mx.example.test:0").is_err());
        assert!(parse_next_hop("mx.example.test:smtp").is_err());
        assert!(parse_cidrs("10.0.0.0/33").is_err());
        assert!(parse_cidrs("10.0.0.0/8\"").is_err());
    }

    #[test]
    fn next_hop_forms() {
        assert_eq!(parse_next_hop("10.1.2.3").unwrap(), "10.1.2.3");
        assert_eq!(parse_next_hop("10.1.2.3:2525").unwrap(), "10.1.2.3:2525");
        assert_eq!(
            parse_next_hop("[2001:db8::1]:25").unwrap(),
            "[2001:db8::1]:25"
        );
        assert_eq!(
            parse_next_hop("Exchange.Corp.Example:25").unwrap(),
            "exchange.corp.example:25"
        );
    }

    #[test]
    fn empty_relay_networks_are_allowed() {
        assert_eq!(parse_cidrs("  ").unwrap(), Vec::<String>::new());
    }

    #[test]
    fn rendered_config_loads_and_validates() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("currawong.toml");
        std::fs::write(&path, sample().to_toml()).unwrap();
        let cfg = currawong_core::Config::load(&path).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.gateway.hostname, "gw.example.test");
        assert_eq!(cfg.auth.authserv_id, "gw.example.test");
        assert_eq!(cfg.domains.accept, ["example.test", "example.org"]);
        assert_eq!(cfg.domains.routes.len(), 2);
        assert_eq!(
            cfg.domains.routes[1].next_hop,
            "tenant.mail.protection.outlook.com"
        );
        assert_eq!(cfg.relay.tenants[0].trusted_cidrs.len(), 2);
        assert_eq!(cfg.scanner.clamd.address, CLAMD_SOCKET);
        assert!(cfg.scanner.clamd.required);
    }

    #[test]
    fn clamd_off_writes_empty_address() {
        let mut answers = sample();
        answers.clamd = false;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("currawong.toml");
        std::fs::write(&path, answers.to_toml()).unwrap();
        let cfg = currawong_core::Config::load(&path).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.scanner.clamd.address, "");
        assert!(!cfg.scanner.clamd.required);
    }
}
