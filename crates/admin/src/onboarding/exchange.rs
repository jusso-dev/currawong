//! Exchange on-premises (2016, 2019 and Subscription Edition) onboarding: the
//! PowerShell the customer runs in the Exchange Management Shell, and the DNS
//! records to publish. Every value is checked before it reaches a script, so
//! a tenant setting cannot inject PowerShell.
use askama::Template;
use currawong_core::config::{Config, ExchangeVersion, MailboxPlatform};
use ipnet::IpNet;
use std::net::IpAddr;

/// What the wizard collects for one Exchange organisation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExchangeOnboarding {
    pub version: ExchangeVersion,
    /// Currawong's host name: the smart host, and the TLS name Exchange checks.
    pub gateway_fqdn: String,
    /// Addresses Currawong delivers from. The Receive connector accepts only these.
    pub gateway_ips: Vec<IpAddr>,
    /// Accepted domains whose mail moves behind Currawong.
    pub domains: Vec<String>,
    /// Exchange Mailbox server names, as `Get-ExchangeServer` lists them.
    pub servers: Vec<String>,
    /// `limits.max_message_bytes`, so Exchange and Currawong agree on size.
    pub max_message_bytes: u64,
    /// Currawong presents a client certificate to Exchange (the route's
    /// `client_cert`, opt in). Only then is the Receive connector rendered
    /// as Partner (domain secure, mutual TLS); without one it is the
    /// AnonymousUsers connector, TLS required, limited by RemoteIPRanges.
    pub domain_secure: bool,
    /// Exchange authenticates to Currawong with SMTP AUTH on 587 instead of
    /// relaying from a trusted address on 25.
    pub smtp_auth: bool,
    /// Ticked by the admin: restrict each server's Default Frontend connector
    /// to these internal ranges so mail cannot bypass Currawong.
    pub lock_down_default_frontend: Option<Vec<IpNet>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExchangeScripts {
    pub receive: String,
    pub send: String,
    pub transport: String,
    pub rollback: String,
    /// The MX change and SPF mechanisms to publish. Currawong does not change DNS.
    pub dns: String,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum OnboardingError {
    #[error("{0}")]
    Invalid(String),
    #[error("template: {0}")]
    Render(String),
}

impl ExchangeOnboarding {
    /// Wizard defaults for `domain` from the running config. The admin still
    /// enters the gateway addresses, and may correct the server names, which
    /// default to the first label of each mailbox host.
    pub fn from_config(cfg: &Config, domain: &str) -> Result<Self, OnboardingError> {
        let route = cfg
            .domains
            .route_for(domain)
            .ok_or_else(|| OnboardingError::Invalid(format!("no route for {domain}")))?;
        let Some(
            platform @ MailboxPlatform::ExchangeOnPrem {
                version,
                mailbox_hosts,
                ..
            },
        ) = &route.platform
        else {
            return Err(OnboardingError::Invalid(format!(
                "{domain} is not an exchange_onprem route"
            )));
        };
        let mut servers: Vec<String> = Vec::new();
        for host in mailbox_hosts {
            let host = host.rsplit_once(':').map_or(host.as_str(), |(h, _)| h);
            if host.parse::<IpAddr>().is_ok() {
                continue;
            }
            let name = host
                .split('.')
                .next()
                .unwrap_or_default()
                .to_ascii_uppercase();
            if !name.is_empty() && !servers.contains(&name) {
                servers.push(name);
            }
        }
        Ok(Self {
            version: *version,
            gateway_fqdn: cfg.gateway.hostname.clone(),
            gateway_ips: Vec::new(),
            domains: vec![route.domain.to_ascii_lowercase()],
            servers,
            max_message_bytes: cfg.limits.max_message_bytes,
            domain_secure: platform.client_identity().is_some(),
            smtp_auth: false,
            lock_down_default_frontend: None,
        })
    }
}

/// Values shared by every template, already checked and formatted.
struct Ctx {
    version: &'static str,
    fqdn: String,
    remote_ips: String,
    servers: Vec<String>,
    source_servers: String,
    size: String,
    domain_secure: bool,
    smtp_auth: bool,
    port: u16,
    lockdown: bool,
    internal_ranges: String,
    domains: Vec<String>,
    spf: String,
}

#[derive(Template)]
#[template(path = "onboarding/exchange/receive.ps1.j2", escape = "none")]
struct Receive<'a> {
    c: &'a Ctx,
}

#[derive(Template)]
#[template(path = "onboarding/exchange/send.ps1.j2", escape = "none")]
struct Send<'a> {
    c: &'a Ctx,
}

#[derive(Template)]
#[template(path = "onboarding/exchange/transport.ps1.j2", escape = "none")]
struct Transport<'a> {
    c: &'a Ctx,
}

#[derive(Template)]
#[template(path = "onboarding/exchange/rollback.ps1.j2", escape = "none")]
struct Rollback<'a> {
    c: &'a Ctx,
}

#[derive(Template)]
#[template(path = "onboarding/exchange/dns.txt.j2", escape = "none")]
struct Dns<'a> {
    c: &'a Ctx,
}

pub fn render_scripts(t: &ExchangeOnboarding) -> Result<ExchangeScripts, OnboardingError> {
    let c = context(t)?;
    // Askama drops the template's final newline; scripts end with exactly one.
    let render = |result: askama::Result<String>| {
        result
            .map(|text| format!("{}\n", text.trim_end()))
            .map_err(|err| OnboardingError::Render(err.to_string()))
    };
    Ok(ExchangeScripts {
        receive: render(Receive { c: &c }.render())?,
        send: render(Send { c: &c }.render())?,
        transport: render(Transport { c: &c }.render())?,
        rollback: render(Rollback { c: &c }.render())?,
        dns: render(Dns { c: &c }.render())?,
    })
}

fn context(t: &ExchangeOnboarding) -> Result<Ctx, OnboardingError> {
    let invalid = |msg: String| Err(OnboardingError::Invalid(msg));
    let fqdn = t.gateway_fqdn.trim_end_matches('.').to_ascii_lowercase();
    if !is_fqdn(&fqdn) {
        return invalid(format!(
            "gateway host name {:?} is not a fully qualified name",
            t.gateway_fqdn
        ));
    }
    if t.gateway_ips.is_empty() {
        return invalid("enter at least one Currawong gateway address".into());
    }
    // RemoteIPRanges is the connector's key control: only real unicast
    // addresses, each once.
    for (i, ip) in t.gateway_ips.iter().enumerate() {
        if ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() {
            return invalid(format!("gateway address {ip} is not a unicast address"));
        }
        if t.gateway_ips[..i].contains(ip) {
            return invalid(format!("gateway address {ip} is listed twice"));
        }
    }
    if t.domains.is_empty() {
        return invalid("enter at least one domain".into());
    }
    let mut domains = Vec::new();
    for domain in &t.domains {
        let domain = domain.trim_end_matches('.').to_ascii_lowercase();
        if !is_fqdn(&domain) {
            return invalid(format!("domain {domain:?} is not a domain name"));
        }
        domains.push(domain);
    }
    if t.servers.is_empty() {
        return invalid("enter at least one Exchange Mailbox server".into());
    }
    for (i, server) in t.servers.iter().enumerate() {
        if !is_server_name(server) {
            return invalid(format!(
                "Exchange server {server:?} must be a server name of letters, digits and hyphens"
            ));
        }
        if t.servers[..i]
            .iter()
            .any(|other| other.eq_ignore_ascii_case(server))
        {
            return invalid(format!("Exchange server {server} is listed twice"));
        }
    }
    if t.max_message_bytes < 1024 * 1024 {
        return invalid("max_message_bytes must be at least 1 MiB".into());
    }
    // Exchange's largest size limit is 2097151 KB.
    if t.max_message_bytes > 2_097_151 * 1024 {
        return invalid("max_message_bytes is above Exchange's 2 GB limit".into());
    }
    let internal_ranges = match &t.lock_down_default_frontend {
        Some(ranges) if ranges.is_empty() => {
            return invalid(
                "locking down Default Frontend needs the internal ranges that still use it".into(),
            )
        }
        Some(ranges) => {
            for range in ranges {
                if range.prefix_len() == 0 {
                    return invalid(format!("{range} is every address, not an internal range"));
                }
                if range.trunc() != *range {
                    return invalid(format!("{range} has host bits set; use {}", range.trunc()));
                }
            }
            join(ranges)
        }
        None => String::new(),
    };
    let spf = t
        .gateway_ips
        .iter()
        .map(|ip| match ip {
            IpAddr::V4(ip) => format!("ip4:{ip}"),
            IpAddr::V6(ip) => format!("ip6:{ip}"),
        })
        .collect::<Vec<_>>()
        .join(" ");
    Ok(Ctx {
        version: t.version.label(),
        remote_ips: join(&t.gateway_ips),
        source_servers: t.servers.join(","),
        servers: t.servers.clone(),
        size: exchange_size(t.max_message_bytes),
        domain_secure: t.domain_secure,
        smtp_auth: t.smtp_auth,
        port: if t.smtp_auth { 587 } else { 25 },
        lockdown: t.lock_down_default_frontend.is_some(),
        internal_ranges,
        domains,
        spf,
        fqdn,
    })
}

fn join<T: std::fmt::Display>(items: &[T]) -> String {
    items
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

/// Exchange size syntax, exact to the byte.
fn exchange_size(bytes: u64) -> String {
    const MIB: u64 = 1024 * 1024;
    if bytes.is_multiple_of(MIB) {
        format!("{}MB", bytes / MIB)
    } else if bytes.is_multiple_of(1024) {
        format!("{}KB", bytes / 1024)
    } else {
        format!("{bytes}B")
    }
}

fn is_label(label: &str) -> bool {
    (1..=63).contains(&label.len())
        && label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        && !label.starts_with('-')
        && !label.ends_with('-')
}

fn is_fqdn(name: &str) -> bool {
    name.len() <= 253 && name.split('.').count() >= 2 && name.split('.').all(is_label)
}

fn is_server_name(name: &str) -> bool {
    is_label(name) && name.len() <= 15
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tenant() -> ExchangeOnboarding {
        ExchangeOnboarding {
            version: ExchangeVersion::Ex2019,
            gateway_fqdn: "gw.currawong.example".into(),
            gateway_ips: vec!["203.0.113.10".parse().unwrap()],
            domains: vec!["agency.example".into()],
            servers: vec!["EXCH01".into()],
            max_message_bytes: 50 * 1024 * 1024,
            domain_secure: true,
            smtp_auth: false,
            lock_down_default_frontend: None,
        }
    }

    #[test]
    fn sizes_use_exchange_units() {
        assert_eq!(exchange_size(50 * 1024 * 1024), "50MB");
        assert_eq!(exchange_size(1536 * 1024), "1536KB");
        assert_eq!(exchange_size(1_048_577), "1048577B");
    }

    #[test]
    fn values_that_could_inject_powershell_are_refused() {
        let mut t = tenant();
        t.servers = vec!["EXCH01\"; Remove-Mailbox x; \"".into()];
        assert!(render_scripts(&t).is_err());
        let mut t = tenant();
        t.gateway_fqdn = "gw.example\" -Port 26 #".into();
        assert!(render_scripts(&t).is_err());
        let mut t = tenant();
        t.domains = vec!["agency.example$(calc)".into()];
        assert!(render_scripts(&t).is_err());
    }

    #[test]
    fn missing_wizard_values_are_named() {
        let mut t = tenant();
        t.gateway_ips.clear();
        let err = render_scripts(&t).unwrap_err().to_string();
        assert!(err.contains("gateway address"), "{err}");
        let mut t = tenant();
        t.lock_down_default_frontend = Some(Vec::new());
        let err = render_scripts(&t).unwrap_err().to_string();
        assert!(err.contains("internal ranges"), "{err}");
    }

    #[test]
    fn unsafe_or_duplicate_wizard_values_are_refused() {
        for (change, needle) in [
            (
                (|t: &mut ExchangeOnboarding| t.gateway_ips = vec!["0.0.0.0".parse().unwrap()])
                    as fn(&mut ExchangeOnboarding),
                "unicast",
            ),
            (
                |t| t.gateway_ips = vec!["127.0.0.1".parse().unwrap()],
                "unicast",
            ),
            (
                |t| t.gateway_ips = vec!["ff02::1".parse().unwrap()],
                "unicast",
            ),
            (
                |t| t.gateway_ips = vec!["203.0.113.10".parse().unwrap(); 2],
                "twice",
            ),
            (
                |t| t.servers = vec!["EXCH01".into(), "exch01".into()],
                "twice",
            ),
            (|t| t.max_message_bytes = 3 << 30, "2 GB"),
            (
                |t| t.lock_down_default_frontend = Some(vec!["0.0.0.0/0".parse().unwrap()]),
                "every address",
            ),
            (
                |t| t.lock_down_default_frontend = Some(vec!["10.1.2.3/8".parse().unwrap()]),
                "10.0.0.0/8",
            ),
        ] {
            let mut t = tenant();
            change(&mut t);
            let err = render_scripts(&t).unwrap_err().to_string();
            assert!(err.contains(needle), "{needle}: {err}");
        }
    }
}
