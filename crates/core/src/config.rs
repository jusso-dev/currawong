//! Typed TOML configuration. Unknown keys fail closed so a typo cannot
//! silently disable a control.
use crate::{residency::ResidencyGuard, secret::Secret};
use figment::{
    providers::{Env, Format, Toml},
    Figment,
};
use serde::{Deserialize, Serialize};
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
};

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to load configuration: {0}")]
    Load(String),
    #[error("invalid configuration: {0}")]
    Invalid(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    pub log: LogConfig,
    pub metrics: MetricsConfig,
    pub limits: LimitsConfig,
    pub spool: SpoolConfig,
    pub listeners: Vec<ListenerConfig>,
    pub tls: TlsConfig,
    pub scanner: ScannerConfig,
    pub residency: ResidencyConfig,
    pub gateway: GatewayConfig,
    pub domains: DomainsConfig,
    pub delivery: DeliveryConfig,
    pub checks: ChecksConfig,
    pub relay: RelayConfig,
    pub dkim: DkimConfig,
    pub auth: AuthConfig,
    pub classify: ClassifyConfig,
    pub policy: PolicyConfig,
    pub url_rewrite: UrlRewriteConfig,
    pub dlp: DlpProfile,
    pub events: EventsConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct LogConfig {
    /// `json` or `pretty`.
    pub format: String,
    pub level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct MetricsConfig {
    /// Prometheus, `/healthz` and `/readyz` bind address.
    pub listen: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct LimitsConfig {
    pub max_message_bytes: u64,
    pub max_recipients: usize,
    pub smtp_command_timeout_secs: u64,
    pub max_connections: usize,
    pub max_line_bytes: usize,
    pub max_connections_per_ip: usize,
    /// Implicit TLS and STARTTLS handshakes that take longer are dropped.
    pub tls_handshake_timeout_secs: u64,
    /// Longest a whole DATA transfer may take, however steadily lines arrive.
    pub data_timeout_secs: u64,
    /// DATA is answered 452 4.3.1 when the spool file system has less free.
    pub spool_min_free_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpoolConfig {
    pub dir: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ListenerMode {
    Plain,
    Starttls,
    Implicit,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ListenerRole {
    Inbound,
    Submission,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListenerConfig {
    pub name: String,
    pub bind: String,
    pub mode: ListenerMode,
    pub role: ListenerRole,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct TlsConfig {
    pub cert: Option<PathBuf>,
    pub key: Option<PathBuf>,
    pub acme: Option<AcmeConfig>,
}

/// Optional ACME (RFC 8555) certificates, used instead of `tls.cert` and
/// `tls.key`. Off unless the section is present.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcmeConfig {
    /// The CA's directory, for example Let's Encrypt's
    /// `https://acme-v02.api.letsencrypt.org/directory`.
    pub directory_url: String,
    /// Names on the certificate. HTTP-01 cannot validate wildcards.
    pub domains: Vec<String>,
    /// `mailto:` address the CA may send expiry notices to.
    pub contact: String,
    /// The account key, certificate and private key are kept here.
    pub cache_dir: PathBuf,
    /// HTTP-01 challenge listener. The CA connects to port 80 on every name
    /// in `domains`, so this must be reachable as port 80.
    #[serde(default = "default_acme_http_bind")]
    pub http_bind: String,
}

fn default_acme_http_bind() -> String {
    "0.0.0.0:80".into()
}

impl AcmeConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        let invalid = |text: String| Err(ConfigError::Invalid(format!("tls.acme: {text}")));
        if !self.directory_url.starts_with("https://") {
            return invalid("directory_url must be an https:// URL".into());
        }
        if self.domains.is_empty() {
            return invalid("domains must name at least one host".into());
        }
        for domain in &self.domains {
            if !is_host_name(domain) {
                return invalid(format!(
                    "'{domain}' is not a host name (HTTP-01 cannot issue wildcards)"
                ));
            }
        }
        if self
            .contact
            .strip_prefix("mailto:")
            .is_none_or(str::is_empty)
        {
            return invalid("contact must be a mailto: address".into());
        }
        if !self.cache_dir.is_absolute() {
            return invalid("cache_dir must be an absolute path".into());
        }
        match self.http_bind.parse::<SocketAddr>() {
            Ok(addr) if addr.port() != 0 => Ok(()),
            _ => invalid(format!(
                "http_bind '{}' is not a socket address with a port",
                self.http_bind
            )),
        }
    }
}

fn is_host_name(name: &str) -> bool {
    name.len() <= 253
        && name.contains('.')
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ScannerConfig {
    pub enabled: bool,
    pub worker_pool_size: usize,
    pub max_jobs_per_worker: usize,
    pub worker_memory_mib: u64,
    pub worker_cpu_secs: u64,
    pub job_timeout_secs: u64,
    pub worker_binary: Option<PathBuf>,
    pub clamd: ClamdConfig,
    pub yara: YaraConfig,
    /// Directories of supplemental on-premises signatures (the SaneSecurity
    /// approach). Currawong does not upload mail. Point `clamd` at these
    /// paths as well; they are recorded and checked locally.
    pub extra_signature_dirs: Vec<PathBuf>,
    pub extra_database_paths: Vec<PathBuf>,
    pub blocked_extensions: Vec<String>,
    pub treat_macros_as_active: bool,
    pub treat_executables_as_active: bool,
    pub extract: ExtractLimits,
    /// Linux: refuse to run a worker without Landlock. Turning this off is
    /// logged as a warning on every worker start.
    pub require_landlock: bool,
    /// When the daemon runs as root, workers run as this uid and gid
    /// (required in that case).
    pub worker_uid: Option<u32>,
    pub worker_gid: Option<u32>,
    /// A message deferred by the scanner this many times is quarantined.
    pub max_scan_deferrals: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ClamdConfig {
    /// `unix:/path` or `tcp:127.0.0.1:3310`. Empty disables the engine only
    /// when `required` is false.
    pub address: String,
    /// An unreachable or unconfigured required engine fails closed (defer).
    pub required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct YaraConfig {
    /// Directory of `*.yar` and `*.yara` files, recompiled when it changes.
    /// Empty disables the engine.
    pub rules_dir: PathBuf,
    /// Time a parser worker may take to load a rules generation. Loading
    /// recompiles the rules, so large sets need far longer than one job.
    pub load_timeout_secs: u64,
}

impl Default for YaraConfig {
    fn default() -> Self {
        Self {
            rules_dir: PathBuf::new(),
            load_timeout_secs: 120,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ExtractLimits {
    pub max_depth: u32,
    pub max_uncompressed_bytes: u64,
    pub max_files: u32,
    pub max_ratio: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ResidencyConfig {
    /// `au` (default) or `off`.
    pub mode: String,
    pub allowed_host_suffixes: Vec<String>,
    pub allowed_names: Vec<String>,
    pub allowed_cidrs: Vec<String>,
    pub content_endpoints: Vec<String>,
    pub overrides: Vec<ResidencyOverride>,
    /// Required when `mode = "off"`. Startup refuses `off` without it.
    pub off_approval: Option<ResidencyApproval>,
    pub signing_key_path: Option<PathBuf>,
    pub report_dir: PathBuf,
    /// Signed reports older than this are deleted.
    pub report_retention_days: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ResidencyOverride {
    pub url: String,
    pub reason: String,
    pub approved_by: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ResidencyApproval {
    pub reason: String,
    pub approved_by: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct GatewayConfig {
    pub hostname: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct DomainsConfig {
    pub accept: Vec<String>,
    pub routes: Vec<DomainRoute>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(try_from = "DomainRouteToml", into = "DomainRouteToml")]
pub struct DomainRoute {
    /// Lower case with no trailing dot once loaded.
    pub domain: String,
    /// `host` or `host:port`. Skips MX lookup. Empty for Exchange
    /// on-premises, which delivers to its `mailbox_hosts` instead.
    pub next_hop: String,
    /// The mailbox platform behind this domain. `None` is a plain smart host.
    pub platform: Option<MailboxPlatform>,
}

/// `M365` and `GoogleWorkspace` only label a route for now: delivery uses
/// its `next_hop` exactly as for a plain smart host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MailboxPlatform {
    M365,
    GoogleWorkspace,
    ExchangeOnPrem {
        version: ExchangeVersion,
        /// Exchange Mailbox servers, `host` or `host:port`, tried in order.
        mailbox_hosts: Vec<String>,
        /// Name the Exchange certificate must carry. Delivery requires TLS.
        tls_cert_name: String,
        /// PEM file with the CA that issued the Exchange certificate, trusted
        /// in addition to the WebPKI roots. For an internal enterprise CA.
        ca_file: Option<PathBuf>,
        /// Client certificate and key (PEM) presented to Exchange, for a
        /// domain secure (mutual TLS) Receive connector. Both or neither.
        /// Opt in: with neither, no client certificate is presented and the
        /// connector is the anonymous, IP-restricted one. The gateway's
        /// `tls.cert` is not used, as a server certificate often lacks the
        /// client authentication usage Exchange needs.
        client_cert: Option<PathBuf>,
        client_key: Option<PathBuf>,
    },
}

impl MailboxPlatform {
    /// The certificate and key Currawong presents to an Exchange route, set
    /// explicitly on the route. `None` means the connector is not domain secure.
    pub fn client_identity(&self) -> Option<(&Path, &Path)> {
        let Self::ExchangeOnPrem {
            client_cert,
            client_key,
            ..
        } = self
        else {
            return None;
        };
        match (client_cert, client_key) {
            (Some(cert), Some(key)) => Some((cert.as_path(), key.as_path())),
            _ => None,
        }
    }
}

/// Exchange Server 2016, 2019 or Subscription Edition. SE uses the 2019 cmdlets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExchangeVersion {
    #[serde(rename = "2016")]
    Ex2016,
    #[serde(rename = "2019")]
    Ex2019,
    #[serde(rename = "se")]
    Se,
}

impl ExchangeVersion {
    pub fn label(self) -> &'static str {
        match self {
            Self::Ex2016 => "Exchange Server 2016",
            Self::Ex2019 => "Exchange Server 2019",
            Self::Se => "Exchange Server Subscription Edition",
        }
    }
}

/// Lower case, no surrounding space, no trailing dot. Route lookups compare
/// domains in this form on both sides.
pub fn normalise_domain(name: &str) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase()
}

impl DomainsConfig {
    /// The configured route for `domain`, if any. The one lookup delivery
    /// uses for both the next hop and its TLS rule.
    pub fn route_for(&self, domain: &str) -> Option<&DomainRoute> {
        let domain = normalise_domain(domain);
        self.routes
            .iter()
            .find(|route| normalise_domain(&route.domain) == domain)
    }
}

/// A DNS host name: dot-separated labels of letters, digits and inner hyphens.
fn is_host_name(name: &str) -> bool {
    (1..=253).contains(&name.len())
        && !name
            .rsplit('.')
            .next()
            .is_some_and(|tld| tld.bytes().all(|b| b.is_ascii_digit()))
        && name.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

/// `host`, `host:port`, an IP address or `ip:port` (`[v6]:port`).
fn is_hop(hop: &str) -> bool {
    if hop.parse::<SocketAddr>().is_ok() || hop.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    let (host, port) = match hop.rsplit_once(':') {
        Some((host, port)) => (host, port.parse::<u16>().ok().filter(|p| *p != 0)),
        None => (hop, Some(25)),
    };
    port.is_some() && is_host_name(host)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum PlatformKind {
    M365,
    GoogleWorkspace,
    ExchangeOnprem,
}

/// The flat TOML form of a route. `DomainRoute` is checked on the way in.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DomainRouteToml {
    domain: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    next_hop: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mailbox_platform: Option<PlatformKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    exchange_version: Option<ExchangeVersion>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    mailbox_hosts: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tls_cert_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ca_file: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    client_cert: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    client_key: Option<PathBuf>,
}

impl TryFrom<DomainRouteToml> for DomainRoute {
    type Error = String;

    fn try_from(raw: DomainRouteToml) -> Result<Self, String> {
        let domain = normalise_domain(&raw.domain);
        if !is_host_name(&domain) {
            return Err(format!(
                "route {:?}: domain is not a domain name",
                raw.domain
            ));
        }
        let exchange_only = raw.exchange_version.is_some()
            || !raw.mailbox_hosts.is_empty()
            || raw.tls_cert_name.is_some()
            || raw.ca_file.is_some()
            || raw.client_cert.is_some()
            || raw.client_key.is_some();
        let platform = match raw.mailbox_platform {
            Some(PlatformKind::ExchangeOnprem) => {
                let version = raw.exchange_version.ok_or_else(|| {
                    format!("route {domain}: exchange_onprem needs exchange_version \"2016\", \"2019\" or \"se\"")
                })?;
                if raw.mailbox_hosts.is_empty() {
                    return Err(format!(
                        "route {domain}: exchange_onprem needs at least one mailbox_hosts entry"
                    ));
                }
                if let Some(bad) = raw.mailbox_hosts.iter().find(|host| !is_hop(host)) {
                    return Err(format!(
                        "route {domain}: mailbox_hosts entry {bad:?} must be host or host:port"
                    ));
                }
                let tls_cert_name = normalise_domain(&raw.tls_cert_name.unwrap_or_default());
                if !is_host_name(&tls_cert_name)
                    && tls_cert_name.parse::<std::net::IpAddr>().is_err()
                {
                    return Err(format!(
                        "route {domain}: exchange_onprem needs tls_cert_name, the host name on the Exchange certificate"
                    ));
                }
                if raw.client_cert.is_some() != raw.client_key.is_some() {
                    return Err(format!(
                        "route {domain}: set both client_cert and client_key, or neither"
                    ));
                }
                if !raw.next_hop.is_empty() {
                    return Err(format!(
                        "route {domain}: exchange_onprem uses mailbox_hosts, not next_hop"
                    ));
                }
                return Ok(Self {
                    domain,
                    next_hop: String::new(),
                    platform: Some(MailboxPlatform::ExchangeOnPrem {
                        version,
                        mailbox_hosts: raw.mailbox_hosts,
                        tls_cert_name,
                        ca_file: raw.ca_file,
                        client_cert: raw.client_cert,
                        client_key: raw.client_key,
                    }),
                });
            }
            Some(PlatformKind::M365) => Some(MailboxPlatform::M365),
            Some(PlatformKind::GoogleWorkspace) => Some(MailboxPlatform::GoogleWorkspace),
            None => None,
        };
        if exchange_only {
            return Err(format!(
                "route {domain}: exchange_version, mailbox_hosts, tls_cert_name, ca_file, client_cert and client_key need mailbox_platform = \"exchange_onprem\""
            ));
        }
        if raw.next_hop.trim().is_empty() {
            return Err(format!("route {domain}: next_hop is required"));
        }
        Ok(Self {
            domain,
            next_hop: raw.next_hop,
            platform,
        })
    }
}

impl From<DomainRoute> for DomainRouteToml {
    fn from(route: DomainRoute) -> Self {
        let mut raw = DomainRouteToml {
            domain: route.domain,
            next_hop: route.next_hop,
            mailbox_platform: None,
            exchange_version: None,
            mailbox_hosts: Vec::new(),
            tls_cert_name: None,
            ca_file: None,
            client_cert: None,
            client_key: None,
        };
        match route.platform {
            None => {}
            Some(MailboxPlatform::M365) => raw.mailbox_platform = Some(PlatformKind::M365),
            Some(MailboxPlatform::GoogleWorkspace) => {
                raw.mailbox_platform = Some(PlatformKind::GoogleWorkspace)
            }
            Some(MailboxPlatform::ExchangeOnPrem {
                version,
                mailbox_hosts,
                tls_cert_name,
                ca_file,
                client_cert,
                client_key,
            }) => {
                raw.mailbox_platform = Some(PlatformKind::ExchangeOnprem);
                raw.exchange_version = Some(version);
                raw.mailbox_hosts = mailbox_hosts;
                raw.tls_cert_name = Some(tls_cert_name);
                raw.ca_file = ca_file;
                raw.client_cert = client_cert;
                raw.client_key = client_key;
            }
        }
        raw
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct DeliveryConfig {
    pub poll_secs: u64,
    pub max_age_days: u64,
    /// Require STARTTLS with a WebPKI-valid certificate on every hop that has
    /// no DANE or MTA-STS policy, including `domains.routes` next hops.
    pub require_tls: bool,
    /// Messages delivered at once in one pass.
    pub max_concurrent: usize,
    /// Sessions open at once to one recipient domain.
    pub max_per_destination: usize,
    /// Allow MX answers that point at loopback, private or other non-public
    /// addresses. Off by default so DNS cannot aim delivery inward.
    pub allow_private_mx: bool,
    /// DANE (RFC 7672) for MX delivery. Validates DNSSEC locally, so the
    /// system resolver must pass DNSSEC records through.
    pub dane: bool,
    /// MTA-STS (RFC 8461) for MX delivery.
    pub mta_sts: bool,
    /// SQLite file for the MTA-STS policy cache and TLS-RPT results.
    pub tls_database: PathBuf,
    pub tls_rpt: TlsRptConfig,
}

/// Daily TLS-RPT (RFC 8460) reports to domains that publish `_smtp._tls`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct TlsRptConfig {
    pub enabled: bool,
    /// `organization-name` in reports.
    pub organisation: String,
    /// `contact-info` in reports. Empty means `postmaster@<gateway.hostname>`.
    pub contact: String,
}

impl Default for TlsRptConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            organisation: "Currawong".into(),
            contact: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ChecksConfig {
    pub dnsbl_enabled: bool,
    pub ratelimit_enabled: bool,
    pub greylist_enabled: bool,
    pub reputation_enabled: bool,
    pub greylist_delay_secs: u64,
    pub greylist_database: PathBuf,
    pub dnsbl: Vec<DnsblZone>,
    /// Connection checks (rate limits, DNSBL, greylisting, reputation) skip these CIDRs.
    /// Use this for published Microsoft and Google outbound ranges.
    pub allow_cidrs: Vec<String>,
    pub rate_per_minute_ip: u32,
    pub rate_per_minute_net: u32,
    pub rate_per_minute_sender: u32,
    pub reputation_reject_score: f32,
    pub reputation_half_life_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsblZone {
    pub zone: String,
    pub dqs_key: Option<Secret<String>>,
    pub listings: Vec<DnsblListing>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsblListing {
    /// Reply address, for example `127.0.0.2`.
    pub code: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct RelayConfig {
    pub database: PathBuf,
    pub tenants: Vec<TenantConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantConfig {
    pub id: String,
    pub domains: Vec<String>,
    pub trusted_cidrs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct DkimConfig {
    pub database: PathBuf,
    pub kek_path: PathBuf,
    pub sign_outbound: bool,
    pub seal_arc: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AuthConfig {
    pub authserv_id: String,
    pub dmarc_reports: DmarcReportConfig,
    /// Look up BIMI logos for quarantined mail that passes DMARC at enforcement.
    pub bimi: bool,
}

/// Daily DMARC aggregate (RUA) reports. Failure (RUF) reports are never sent.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct DmarcReportConfig {
    pub enabled: bool,
    /// SQLite file holding the `dmarc_events` table.
    pub database: PathBuf,
    pub org_name: String,
    /// Report sender. Its domain is the report submitter.
    pub email: String,
    /// Only the first N `rua` addresses of a record are considered.
    pub max_rua_per_record: usize,
    /// Policy domains recorded per day across all organisations.
    pub max_domains_per_day: usize,
    /// Policy domains per organisational (registrable) domain per day, so
    /// wildcard `_dmarc` subdomains cannot fill the daily cap.
    pub max_domains_per_org: usize,
    /// Events stored per policy domain per day.
    pub max_events_per_domain_day: usize,
    /// Rows per report. The rest are counted in the report's `error` field.
    pub max_rows_per_report: usize,
    /// Rendered report message size limit.
    pub max_report_bytes: usize,
    /// Unsent events older than this are dropped.
    pub retention_days: u64,
}

impl Default for DmarcReportConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            database: PathBuf::from("/var/lib/currawong/dmarc.sqlite"),
            org_name: "Currawong".into(),
            email: String::new(),
            max_rua_per_record: 5,
            max_domains_per_day: 5_000,
            max_domains_per_org: 20,
            max_events_per_domain_day: 100_000,
            max_rows_per_report: 1_000,
            max_report_bytes: 5 * 1024 * 1024,
            retention_days: 7,
        }
    }
}

/// Links in delivered inbound mail point at the click service, which checks
/// the real link again when it is clicked.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct UrlRewriteConfig {
    pub enabled: bool,
    /// Public `https://` base of the click service. Links become `<base_url>/u/<token>`.
    pub base_url: String,
    /// Click service bind address. It speaks plain HTTP: put a TLS proxy in front.
    pub listen: String,
    /// HMAC key, at least 32 bytes. Every node that serves clicks needs the same file.
    pub key_file: PathBuf,
    /// Links stop working this many days after the message arrived.
    pub ttl_days: u64,
    /// Links to these domains and their subdomains are not rewritten.
    pub allow_domains: Vec<String>,
    /// Domains or URL prefixes blocked at click time, one per line (`warn <entry>`
    /// warns, `allow <entry>` marks a known site). Read again when it changes.
    pub blocklist: Option<PathBuf>,
    /// Links to sites not on an `allow` line of the block list get the warning page.
    pub warn_unknown: bool,
    /// Click events, one JSON object per line, mode 0600.
    pub click_log: PathBuf,
    /// The click log is rotated to `<click_log>.1` past this size.
    pub click_log_max_bytes: u64,
    /// Addresses or CIDRs of the TLS proxy in front of the click service. Its
    /// `X-Forwarded-For` names the client; from anyone else it is ignored.
    pub trusted_proxies: Vec<String>,
    /// Verified clicks per minute from one client address (an IPv6 /64 counts as one).
    pub clicks_per_minute_per_client: u32,
    /// Verified clicks per minute on one link, per recipient of its message.
    pub clicks_per_minute_per_link: u32,
    /// Larger messages are delivered without rewriting.
    pub max_message_bytes: usize,
}

impl Default for UrlRewriteConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            base_url: String::new(),
            listen: "127.0.0.1:8090".into(),
            key_file: PathBuf::from("/etc/currawong/url.key"),
            ttl_days: 7,
            allow_domains: Vec::new(),
            blocklist: None,
            warn_unknown: false,
            click_log: PathBuf::from("/var/lib/currawong/clicks.jsonl"),
            click_log_max_bytes: 64 * 1024 * 1024,
            trusted_proxies: Vec::new(),
            clicks_per_minute_per_client: 600,
            clicks_per_minute_per_link: 30,
            max_message_bytes: 10 * 1024 * 1024,
        }
    }
}

/// `[dlp]`: Australian identifier detection on outbound mail, and inbound
/// mail when `scan_inbound` is set. What happens to a message with findings
/// is set by policy (`dlp.<kind>` counts and the `dlp.incomplete` flag).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct DlpProfile {
    pub enabled: bool,
    pub scan_inbound: bool,
    /// Matches below this confidence (0 to 100) are not counted.
    pub min_confidence: u8,
}

/// Spam scoring and lookalike domains. Scores go on the report; policy decides.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ClassifyConfig {
    pub enabled: bool,
    /// SQLite file holding per-tenant Bayes token counts.
    pub bayes_database: PathBuf,
    /// Directory of `*.toml` spam rules. Unset uses the built-in rules.
    pub spam_rules_dir: Option<PathBuf>,
    /// Brand list, `Name: domain ...` per line. Unset uses the built-in Australian list.
    pub brands_file: Option<PathBuf>,
    /// More domains to protect in every tenant's mail. A tenant's own domains
    /// are protected in its own mail.
    pub protected_domains: Vec<String>,
    /// Domains never flagged as lookalikes, such as partners or vendors whose
    /// names resemble a tenant's.
    pub allowed_domains: Vec<String>,
    /// Staff directory CSV (`email,name[,vip]`) used to spot display-name
    /// impersonation. Unset disables that check.
    pub directory_csv: Option<PathBuf>,
    /// SQLite file recording who has had mail delivered to whom, for
    /// first-time sender checks.
    pub history_database: PathBuf,
}

/// Policy engine. With neither set, the built-in default pack applies.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct PolicyConfig {
    /// TOML policy pack. Seeds the database when the database has no policies.
    pub pack: Option<PathBuf>,
    /// SQLite policy store. When set, policies are read from it.
    pub database: Option<PathBuf>,
    /// Domains outside the tenant's own that redirect and bcc may send to.
    pub forward_domains: Vec<String>,
}

/// Event export to SIEMs. See `docs/events.md`. Every sink is off unless set.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct EventsConfig {
    /// Events held in memory per sink before overflowing to disk.
    pub queue_capacity: usize,
    pub batch_size: usize,
    /// Defaults to `<spool.dir>/events`.
    pub overflow_dir: Option<PathBuf>,
    /// Events held on disk per sink before new events are dropped.
    pub overflow_max_files: usize,
    pub syslog: Option<SyslogSinkConfig>,
    pub webhook: Option<WebhookSinkConfig>,
    pub wedgetail: Option<WedgetailSinkConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyslogSinkConfig {
    /// `host:port`, for example `siem.corp.example:6514`.
    pub address: String,
    #[serde(default = "default_true")]
    pub tls: bool,
    /// PEM bundle for a private CA. Public roots are always trusted.
    #[serde(default)]
    pub ca_file: Option<PathBuf>,
    #[serde(default)]
    pub payload: EventPayload,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum EventPayload {
    #[default]
    Cef,
    Json,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebhookSinkConfig {
    pub url: String,
    /// File holding the HMAC key (at least 16 bytes, trailing newline ignored).
    pub secret_file: PathBuf,
    #[serde(default)]
    pub ca_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WedgetailSinkConfig {
    pub url: String,
    pub token_file: PathBuf,
    #[serde(default)]
    pub ca_file: Option<PathBuf>,
}

fn default_true() -> bool {
    true
}

impl Default for EventsConfig {
    fn default() -> Self {
        Self {
            queue_capacity: 1024,
            batch_size: 100,
            overflow_dir: None,
            overflow_max_files: 100_000,
            syslog: None,
            webhook: None,
            wedgetail: None,
        }
    }
}

impl EventsConfig {
    /// Every sink destination as a URL, in the form the residency guard checks.
    /// Syslog is `syslog://host:port` or `syslog-tls://host:port`.
    pub fn destinations(&self) -> Vec<String> {
        let mut out = Vec::new();
        if let Some(syslog) = &self.syslog {
            let scheme = if syslog.tls { "syslog-tls" } else { "syslog" };
            out.push(format!("{scheme}://{}", syslog.address));
        }
        out.extend(self.webhook.iter().map(|w| w.url.clone()));
        out.extend(self.wedgetail.iter().map(|w| w.url.clone()));
        out
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.queue_capacity == 0 || self.batch_size == 0 {
            return Err(ConfigError::Invalid(
                "events.queue_capacity and events.batch_size must be at least 1".into(),
            ));
        }
        if let Some(syslog) = &self.syslog {
            let url = url::Url::parse(&format!("syslog://{}", syslog.address)).ok();
            if url.as_ref().and_then(|u| u.host_str()).is_none()
                || url.as_ref().and_then(|u| u.port()).is_none()
            {
                return Err(ConfigError::Invalid(format!(
                    "events.syslog.address '{}' must be host:port",
                    syslog.address
                )));
            }
        }
        let https = self
            .webhook
            .iter()
            .map(|w| ("webhook", &w.url))
            .chain(self.wedgetail.iter().map(|w| ("wedgetail", &w.url)));
        for (name, url) in https {
            match url::Url::parse(url) {
                Ok(parsed) if parsed.scheme() == "https" && parsed.host_str().is_some() => {}
                _ => {
                    return Err(ConfigError::Invalid(format!(
                        "events.{name}.url '{url}' must be an https URL"
                    )))
                }
            }
        }
        Ok(())
    }
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            format: "json".into(),
            level: "info".into(),
        }
    }
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:9090".into(),
        }
    }
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_message_bytes: 52_428_800,
            max_recipients: 100,
            smtp_command_timeout_secs: 300,
            max_connections: 1000,
            max_line_bytes: 1000,
            max_connections_per_ip: 20,
            tls_handshake_timeout_secs: 30,
            data_timeout_secs: 600,
            spool_min_free_bytes: 1024 * 1024 * 1024,
        }
    }
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            worker_pool_size: 2,
            max_jobs_per_worker: 500,
            worker_memory_mib: 512,
            worker_cpu_secs: 30,
            job_timeout_secs: 30,
            worker_binary: None,
            clamd: ClamdConfig::default(),
            yara: YaraConfig::default(),
            extra_signature_dirs: Vec::new(),
            extra_database_paths: Vec::new(),
            blocked_extensions: default_blocked_extensions(),
            treat_macros_as_active: true,
            treat_executables_as_active: true,
            extract: ExtractLimits::default(),
            require_landlock: true,
            worker_uid: None,
            worker_gid: None,
            max_scan_deferrals: 288,
        }
    }
}

impl Default for ClamdConfig {
    fn default() -> Self {
        Self {
            address: String::new(),
            required: true,
        }
    }
}

impl Default for ExtractLimits {
    fn default() -> Self {
        Self {
            max_depth: 5,
            max_uncompressed_bytes: 200 * 1024 * 1024,
            max_files: 1000,
            max_ratio: 100,
        }
    }
}

impl Default for ResidencyConfig {
    fn default() -> Self {
        Self {
            mode: "au".into(),
            allowed_host_suffixes: vec![
                "s3.ap-southeast-2.amazonaws.com".into(),
                "s3.ap-southeast-4.amazonaws.com".into(),
            ],
            allowed_names: vec!["localhost".into()],
            allowed_cidrs: vec![
                "127.0.0.0/8".into(),
                "::1/128".into(),
                "10.0.0.0/8".into(),
                "192.168.0.0/16".into(),
                "172.16.0.0/12".into(),
            ],
            content_endpoints: Vec::new(),
            overrides: Vec::new(),
            off_approval: None,
            signing_key_path: None,
            report_dir: PathBuf::from("/var/lib/currawong/residency"),
            report_retention_days: 400,
        }
    }
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            hostname: "currawong.local".into(),
        }
    }
}

impl Default for DomainsConfig {
    fn default() -> Self {
        Self {
            accept: vec!["example.test".into()],
            routes: Vec::new(),
        }
    }
}

impl Default for DeliveryConfig {
    fn default() -> Self {
        Self {
            poll_secs: 30,
            max_age_days: 5,
            require_tls: false,
            max_concurrent: 16,
            max_per_destination: 4,
            allow_private_mx: false,
            dane: true,
            mta_sts: true,
            tls_database: PathBuf::from("/var/lib/currawong/tls.sqlite"),
            tls_rpt: TlsRptConfig::default(),
        }
    }
}

impl Default for ChecksConfig {
    fn default() -> Self {
        Self {
            dnsbl_enabled: false,
            ratelimit_enabled: true,
            greylist_enabled: true,
            reputation_enabled: true,
            greylist_delay_secs: 300,
            greylist_database: PathBuf::from("/var/lib/currawong/greylist.sqlite"),
            dnsbl: Vec::new(),
            allow_cidrs: Vec::new(),
            rate_per_minute_ip: 60,
            rate_per_minute_net: 300,
            rate_per_minute_sender: 120,
            reputation_reject_score: 100.0,
            reputation_half_life_secs: 86_400,
        }
    }
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            database: PathBuf::from("/var/lib/currawong/relay.sqlite"),
            tenants: Vec::new(),
        }
    }
}

impl Default for DkimConfig {
    fn default() -> Self {
        Self {
            database: PathBuf::from("/var/lib/currawong/dkim.sqlite"),
            kek_path: PathBuf::from("/etc/currawong/dkim.kek"),
            sign_outbound: true,
            seal_arc: true,
        }
    }
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            authserv_id: "currawong.local".into(),
            dmarc_reports: DmarcReportConfig::default(),
            bimi: false,
        }
    }
}

impl Default for DlpProfile {
    fn default() -> Self {
        Self {
            enabled: true,
            scan_inbound: false,
            min_confidence: 50,
        }
    }
}

impl Default for ClassifyConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            bayes_database: PathBuf::from("/var/lib/currawong/bayes.sqlite"),
            spam_rules_dir: None,
            brands_file: None,
            protected_domains: Vec::new(),
            allowed_domains: Vec::new(),
            directory_csv: None,
            history_database: PathBuf::from("/var/lib/currawong/sender-history.sqlite"),
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            log: LogConfig::default(),
            metrics: MetricsConfig::default(),
            limits: LimitsConfig::default(),
            spool: SpoolConfig {
                dir: PathBuf::from("/var/spool/currawong"),
            },
            listeners: vec![
                ListenerConfig {
                    name: "inbound".into(),
                    bind: "0.0.0.0:25".into(),
                    mode: ListenerMode::Starttls,
                    role: ListenerRole::Inbound,
                },
                ListenerConfig {
                    name: "submission".into(),
                    bind: "0.0.0.0:587".into(),
                    mode: ListenerMode::Starttls,
                    role: ListenerRole::Submission,
                },
                ListenerConfig {
                    name: "submissions".into(),
                    bind: "0.0.0.0:465".into(),
                    mode: ListenerMode::Implicit,
                    role: ListenerRole::Submission,
                },
            ],
            tls: TlsConfig {
                cert: Some(PathBuf::from("/etc/currawong/cert.pem")),
                key: Some(PathBuf::from("/etc/currawong/key.pem")),
                acme: None,
            },
            scanner: ScannerConfig::default(),
            residency: ResidencyConfig::default(),
            gateway: GatewayConfig::default(),
            domains: DomainsConfig::default(),
            delivery: DeliveryConfig::default(),
            checks: ChecksConfig::default(),
            relay: RelayConfig::default(),
            dkim: DkimConfig::default(),
            auth: AuthConfig::default(),
            classify: ClassifyConfig::default(),
            policy: PolicyConfig::default(),
            url_rewrite: UrlRewriteConfig::default(),
            dlp: DlpProfile::default(),
            events: EventsConfig::default(),
        }
    }
}

fn default_blocked_extensions() -> Vec<String> {
    [
        "exe",
        "scr",
        "js",
        "jse",
        "vbs",
        "vbe",
        "wsf",
        "wsh",
        "hta",
        "lnk",
        "iso",
        "one",
        "bat",
        "cmd",
        "com",
        "msi",
        "dll",
        "ps1",
        "jar",
        "cpl",
        "msc",
        "reg",
        "pif",
        "gadget",
        "application",
        "msp",
        "msix",
        "appx",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

impl Config {
    /// `--check-config` only: a required clamd needs an address. Kept out of
    /// [`Config::validate`] so library defaults stay valid in tests.
    pub fn check_clamd(&self) -> Result<(), ConfigError> {
        if self.scanner.enabled
            && self.scanner.clamd.required
            && self.scanner.clamd.address.is_empty()
        {
            return Err(ConfigError::Invalid(
                "scanner.clamd.address is empty and scanner.clamd.required is true: \
                 set the clamd address (unix:/path or tcp:ip:port), or set \
                 scanner.clamd.required = false to run without ClamAV"
                    .into(),
            ));
        }
        Ok(())
    }

    /// Load TOML, then apply `CURRAWONG_` environment variables.
    /// Nested keys use `__`, for example `CURRAWONG_LIMITS__MAX_RECIPIENTS`.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        Figment::new()
            .merge(Toml::file(path))
            .merge(Env::prefixed("CURRAWONG_").split("__"))
            .extract()
            .map_err(|err| ConfigError::Load(err.to_string()))
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if !self.spool.dir.is_absolute() {
            return Err(ConfigError::Invalid(
                "spool directory must be an absolute path".into(),
            ));
        }
        if self.listeners.is_empty() {
            return Err(ConfigError::Invalid(
                "at least one listener is required".into(),
            ));
        }
        let mut needs_tls = false;
        for listener in &self.listeners {
            let addr: SocketAddr = listener.bind.parse().map_err(|_| {
                ConfigError::Invalid(format!(
                    "listener {} bind address '{}' is not a socket address",
                    listener.name, listener.bind
                ))
            })?;
            if addr.port() == 0 {
                return Err(ConfigError::Invalid(format!(
                    "listener {} port must be non-zero",
                    listener.name
                )));
            }
            if matches!(
                listener.mode,
                ListenerMode::Starttls | ListenerMode::Implicit
            ) {
                needs_tls = true;
            }
        }
        if self.limits.max_message_bytes < 1024 * 1024 {
            return Err(ConfigError::Invalid(
                "max_message_bytes must be at least 1 MiB".into(),
            ));
        }
        if self.limits.max_recipients == 0 {
            return Err(ConfigError::Invalid(
                "max_recipients must be at least 1".into(),
            ));
        }
        if let Some(acme) = &self.tls.acme {
            if self.tls.cert.is_some() || self.tls.key.is_some() {
                return Err(ConfigError::Invalid(
                    "set tls.cert and tls.key, or tls.acme, not both".into(),
                ));
            }
            acme.validate()?;
        } else if needs_tls && (self.tls.cert.is_none() || self.tls.key.is_none()) {
            return Err(ConfigError::Invalid(
                "STARTTLS or implicit TLS requires tls.cert and tls.key, or tls.acme".into(),
            ));
        }
        if self.limits.max_connections == 0 {
            return Err(ConfigError::Invalid(
                "limits.max_connections must be at least 1".into(),
            ));
        }
        if self.limits.max_connections_per_ip == 0
            || self.limits.max_connections_per_ip > self.limits.max_connections
        {
            return Err(ConfigError::Invalid(
                "limits.max_connections_per_ip must be between 1 and limits.max_connections".into(),
            ));
        }
        if self.limits.max_line_bytes < 1000 {
            return Err(ConfigError::Invalid(
                "limits.max_line_bytes must be at least 1000 (RFC 5321 text line)".into(),
            ));
        }
        for (name, secs) in [
            (
                "limits.smtp_command_timeout_secs",
                self.limits.smtp_command_timeout_secs,
            ),
            ("scanner.job_timeout_secs", self.scanner.job_timeout_secs),
            ("delivery.poll_secs", self.delivery.poll_secs),
        ] {
            if secs == 0 {
                return Err(ConfigError::Invalid(format!("{name} must be at least 1")));
            }
        }
        if !self.scanner.clamd.address.is_empty() {
            parse_clamd_address(&self.scanner.clamd.address)?;
        }
        if self.scanner.worker_uid.is_some() != self.scanner.worker_gid.is_some() {
            return Err(ConfigError::Invalid(
                "scanner.worker_uid and scanner.worker_gid must be set together".into(),
            ));
        }
        // Every destination for message content, including clamd, must pass
        // the residency guard before the daemon starts.
        ResidencyGuard::from_config(&self.residency)
            .and_then(|guard| guard.enforce_config(self))
            .map_err(|err| ConfigError::Invalid(format!("residency: {err}")))?;
        if self.log.format != "json" && self.log.format != "pretty" {
            return Err(ConfigError::Invalid(
                "log.format must be \"json\" or \"pretty\"".into(),
            ));
        }
        tracing_subscriber::EnvFilter::try_new(&self.log.level).map_err(|err| {
            ConfigError::Invalid(format!("log.level '{}': {err}", self.log.level))
        })?;
        self.metrics.listen.parse::<SocketAddr>().map_err(|_| {
            ConfigError::Invalid(format!(
                "metrics.listen '{}' is not a socket address",
                self.metrics.listen
            ))
        })?;
        let reports = &self.auth.dmarc_reports;
        if reports.enabled && !reports.email.contains('@') {
            return Err(ConfigError::Invalid(
                "auth.dmarc_reports.email must be an address when reports are enabled".into(),
            ));
        }
        if !(1..=60).contains(&reports.retention_days) {
            return Err(ConfigError::Invalid(
                "auth.dmarc_reports.retention_days must be between 1 and 60".into(),
            ));
        }
        for (name, value) in [
            ("max_rua_per_record", reports.max_rua_per_record),
            ("max_domains_per_day", reports.max_domains_per_day),
            ("max_domains_per_org", reports.max_domains_per_org),
            (
                "max_events_per_domain_day",
                reports.max_events_per_domain_day,
            ),
            ("max_rows_per_report", reports.max_rows_per_report),
            ("max_report_bytes", reports.max_report_bytes),
        ] {
            if value == 0 {
                return Err(ConfigError::Invalid(format!(
                    "auth.dmarc_reports.{name} must be at least 1"
                )));
            }
        }
        let urls = &self.url_rewrite;
        if urls.enabled {
            if !urls.base_url.starts_with("https://") {
                return Err(ConfigError::Invalid(
                    "url_rewrite.base_url must start with https://".into(),
                ));
            }
            urls.listen.parse::<SocketAddr>().map_err(|_| {
                ConfigError::Invalid(format!(
                    "url_rewrite.listen '{}' is not a socket address",
                    urls.listen
                ))
            })?;
            if urls.clicks_per_minute_per_client == 0 || urls.clicks_per_minute_per_link == 0 {
                return Err(ConfigError::Invalid(
                    "url_rewrite click limits must be at least 1".into(),
                ));
            }
            if urls.ttl_days == 0 {
                return Err(ConfigError::Invalid(
                    "url_rewrite.ttl_days must be at least 1".into(),
                ));
            }
        }
        // An empty tenant id would share the platform's policy namespace.
        if let Some(tenant) = self
            .relay
            .tenants
            .iter()
            .find(|t| t.id.trim().is_empty() || t.id.trim() != t.id)
        {
            return Err(ConfigError::Invalid(format!(
                "relay tenant id {:?} must be non-empty with no surrounding spaces",
                tenant.id
            )));
        }
        // Exchange routes read these on every delivery; a missing file would
        // defer all mail for the domain, so fail at startup instead.
        for route in &self.domains.routes {
            let Some(MailboxPlatform::ExchangeOnPrem {
                ca_file,
                client_cert,
                client_key,
                ..
            }) = &route.platform
            else {
                continue;
            };
            for path in [ca_file, client_cert, client_key].into_iter().flatten() {
                if !path.is_file() {
                    return Err(ConfigError::Invalid(format!(
                        "route {}: {} is not a readable file",
                        route.domain,
                        path.display()
                    )));
                }
            }
        }
        self.events.validate()?;
        Ok(())
    }

    pub fn metrics_addr(&self) -> Result<SocketAddr, ConfigError> {
        self.metrics
            .listen
            .parse()
            .map_err(|_| ConfigError::Invalid("metrics.listen is not a socket address".into()))
    }
}

pub fn parse_clamd_address(address: &str) -> Result<(), ConfigError> {
    if let Some(path) = address.strip_prefix("unix:") {
        if path.is_empty() {
            return Err(ConfigError::Invalid(
                "clamd unix address is missing a path".into(),
            ));
        }
        return Ok(());
    }
    // Same rule as the runtime parser: an explicit tcp: prefix and an IP.
    let tcp = address.strip_prefix("tcp:").unwrap_or("");
    if tcp.parse::<SocketAddr>().is_err() {
        return Err(ConfigError::Invalid(format!(
            "clamd address '{address}' must be unix:/path or tcp:host:port"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Every test that loads a config takes this lock, so a test that sets a
    /// `CURRAWONG_` variable cannot leak it into another test's load.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn load(path: &Path) -> Result<Config, ConfigError> {
        let _guard = env_lock();
        Config::load(path)
    }

    fn example_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../config/currawong.example.toml")
    }

    #[test]
    fn dmarc_report_limits_are_validated() {
        let mut cfg = Config::load(&example_path()).expect("example config");
        cfg.auth.dmarc_reports.retention_days = 0;
        assert!(cfg.validate().is_err());
        cfg.auth.dmarc_reports.retention_days = 61;
        assert!(cfg.validate().is_err());
        cfg.auth.dmarc_reports.retention_days = 60;
        cfg.validate().expect("60 days is allowed");
        cfg.auth.dmarc_reports.max_domains_per_org = 0;
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("max_domains_per_org"), "{err}");
    }

    #[test]
    fn example_loads_and_validates() {
        let cfg = load(&example_path()).expect("example config");
        cfg.validate().expect("example config is valid");
        assert!(cfg.limits.max_message_bytes >= 1024 * 1024);
        assert_eq!(cfg.residency.mode, "au");
    }

    #[test]
    fn blank_tenant_id_is_refused() {
        for id in ["", " ", " t1"] {
            let mut cfg = load(&example_path()).unwrap();
            cfg.relay.tenants.push(TenantConfig {
                id: id.into(),
                domains: vec!["example.test".into()],
                trusted_cidrs: Vec::new(),
            });
            assert!(cfg.validate().is_err(), "{id:?}");
        }
    }

    fn routes(toml: &str) -> Result<Vec<DomainRoute>, ConfigError> {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("routes.toml");
        std::fs::write(&path, toml).unwrap();
        load(&path).map(|cfg| cfg.domains.routes)
    }

    #[test]
    fn exchange_onprem_route_parses() {
        let routes = routes(
            "[[domains.routes]]\ndomain = \"agency.example\"\nmailbox_platform = \"exchange_onprem\"\n\
             exchange_version = \"se\"\nmailbox_hosts = [\"exch01.agency.example\", \"exch02.agency.example:2525\"]\n\
             tls_cert_name = \"mail.agency.example\"\n\n\
             [[domains.routes]]\ndomain = \"plain.example\"\nnext_hop = \"10.0.0.5\"\n",
        )
        .unwrap();
        assert_eq!(
            routes[0].platform,
            Some(MailboxPlatform::ExchangeOnPrem {
                version: ExchangeVersion::Se,
                mailbox_hosts: vec![
                    "exch01.agency.example".into(),
                    "exch02.agency.example:2525".into()
                ],
                tls_cert_name: "mail.agency.example".into(),
                ca_file: None,
                client_cert: None,
                client_key: None,
            })
        );
        assert_eq!(routes[1].platform, None);
        assert_eq!(routes[1].next_hop, "10.0.0.5");
        // The flat form survives a round trip.
        let again: DomainRoute = toml::from_str(&toml::to_string(&routes[0]).unwrap()).unwrap();
        assert_eq!(again.platform, routes[0].platform);
    }

    #[test]
    fn exchange_onprem_route_needs_its_settings() {
        let base = "[[domains.routes]]\ndomain = \"agency.example\"\n";
        for (extra, needle) in [
            (
                "mailbox_platform = \"exchange_onprem\"\nmailbox_hosts = [\"e\"]\ntls_cert_name = \"e\"\n",
                "exchange_version",
            ),
            (
                "mailbox_platform = \"exchange_onprem\"\nexchange_version = \"2019\"\ntls_cert_name = \"e\"\n",
                "mailbox_hosts",
            ),
            (
                "mailbox_platform = \"exchange_onprem\"\nexchange_version = \"2016\"\nmailbox_hosts = [\"e\"]\n",
                "tls_cert_name",
            ),
            (
                "mailbox_platform = \"exchange_onprem\"\nexchange_version = \"2013\"\nmailbox_hosts = [\"e\"]\ntls_cert_name = \"e\"\n",
                "2013",
            ),
            ("next_hop = \"e\"\nmailbox_hosts = [\"e\"]\n", "exchange_onprem"),
            ("mailbox_platform = \"m365\"\n", "next_hop"),
            (
                "mailbox_platform = \"exchange_onprem\"\nexchange_version = \"2019\"\nmailbox_hosts = [\"exch01\", \"\"]\ntls_cert_name = \"e\"\n",
                "mailbox_hosts entry \"\"",
            ),
            (
                "mailbox_platform = \"exchange_onprem\"\nexchange_version = \"2019\"\nmailbox_hosts = [\"exch01:99999\"]\ntls_cert_name = \"e\"\n",
                "exch01:99999",
            ),
            (
                "mailbox_platform = \"exchange_onprem\"\nexchange_version = \"2019\"\nmailbox_hosts = [\"exch 01\"]\ntls_cert_name = \"e\"\n",
                "exch 01",
            ),
            (
                "mailbox_platform = \"exchange_onprem\"\nexchange_version = \"2019\"\nmailbox_hosts = [\"e\"]\ntls_cert_name = \"mail agency\"\n",
                "tls_cert_name",
            ),
            (
                "mailbox_platform = \"exchange_onprem\"\nexchange_version = \"2019\"\nmailbox_hosts = [\"e\"]\ntls_cert_name = \"e\"\nclient_cert = \"/c.pem\"\n",
                "client_key",
            ),
        ] {
            let err = routes(&format!("{base}{extra}")).unwrap_err().to_string();
            assert!(err.contains(needle), "{extra}: {err}");
        }
    }

    #[test]
    fn route_domains_are_normalised_and_looked_up_alike() {
        let routes = routes(
            "[[domains.routes]]\ndomain = \" Agency.Example. \"\nmailbox_platform = \"exchange_onprem\"\n\
             exchange_version = \"2019\"\nmailbox_hosts = [\"10.1.1.5\", \"[2001:db8::5]:2525\"]\n\
             tls_cert_name = \"Mail.Agency.Example.\"\n",
        )
        .unwrap();
        assert_eq!(routes[0].domain, "agency.example");
        let Some(MailboxPlatform::ExchangeOnPrem { tls_cert_name, .. }) = &routes[0].platform
        else {
            panic!("{:?}", routes[0]);
        };
        assert_eq!(tls_cert_name, "mail.agency.example");
        let mut domains = DomainsConfig {
            routes,
            ..DomainsConfig::default()
        };
        // A route built in code is matched the same way.
        domains.routes[0].domain = "AGENCY.example.".into();
        for name in ["agency.example", "AGENCY.EXAMPLE.", " agency.example "] {
            assert!(domains.route_for(name).is_some(), "{name}");
        }
        assert!(domains.route_for("other.example").is_none());
    }

    #[test]
    fn exchange_files_are_checked_at_startup() {
        let dir = tempfile::tempdir().unwrap();
        let platform = |ca: &str, cert: Option<&str>| MailboxPlatform::ExchangeOnPrem {
            version: ExchangeVersion::Ex2019,
            mailbox_hosts: vec!["exch01.agency.example".into()],
            tls_cert_name: "mail.agency.example".into(),
            ca_file: Some(dir.path().join(ca)),
            client_cert: cert.map(|c| dir.path().join(c)),
            client_key: cert.map(|_| dir.path().join("client.key")),
        };
        std::fs::write(dir.path().join("ca.pem"), "x").unwrap();
        std::fs::write(dir.path().join("client.pem"), "x").unwrap();
        std::fs::write(dir.path().join("client.key"), "x").unwrap();
        for (ca, cert, ok) in [
            ("ca.pem", None, true),
            ("ca.pem", Some("client.pem"), true),
            ("missing.pem", None, false),
            ("ca.pem", Some("missing.pem"), false),
        ] {
            let mut cfg = load(&example_path()).unwrap();
            cfg.domains.routes.push(DomainRoute {
                domain: "agency.example".into(),
                next_hop: String::new(),
                platform: Some(platform(ca, cert)),
            });
            assert_eq!(cfg.validate().is_ok(), ok, "{ca} {cert:?}");
        }
    }

    #[test]
    fn exchange_client_identity_is_opt_in_per_route() {
        let route = |cert: Option<&str>| MailboxPlatform::ExchangeOnPrem {
            version: ExchangeVersion::Ex2019,
            mailbox_hosts: vec!["e".into()],
            tls_cert_name: "e".into(),
            ca_file: None,
            client_cert: cert.map(PathBuf::from),
            client_key: cert.map(|_| PathBuf::from("/route.key")),
        };
        // The gateway's tls.cert is never used as the client certificate.
        assert_eq!(route(None).client_identity(), None);
        assert_eq!(
            route(Some("/route.pem")).client_identity(),
            Some((Path::new("/route.pem"), Path::new("/route.key")))
        );
        assert_eq!(MailboxPlatform::M365.client_identity(), None);
    }

    #[test]
    fn unknown_key_names_the_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.toml");
        std::fs::write(
            &path,
            "[spool]\ndir = \"/var/spool/currawong\"\nnot_a_real_key = 1\n",
        )
        .unwrap();
        let err = load(&path).unwrap_err();
        let text = err.to_string();
        assert!(
            text.contains("not_a_real_key"),
            "error should name the unknown key, got {text}"
        );
    }

    #[test]
    fn env_override_wins() {
        let _guard = env_lock();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("base.toml");
        std::fs::write(
            &path,
            "[spool]\ndir = \"/var/spool/currawong\"\n[limits]\nmax_recipients = 100\n",
        )
        .unwrap();
        let previous = std::env::var("CURRAWONG_LIMITS__MAX_RECIPIENTS").ok();
        // Safety: the mutex above serialises tests that touch this variable.
        unsafe { std::env::set_var("CURRAWONG_LIMITS__MAX_RECIPIENTS", "5") };
        let cfg = Config::load(&path).expect("load");
        unsafe {
            match previous {
                Some(value) => std::env::set_var("CURRAWONG_LIMITS__MAX_RECIPIENTS", value),
                None => std::env::remove_var("CURRAWONG_LIMITS__MAX_RECIPIENTS"),
            }
        }
        assert_eq!(cfg.limits.max_recipients, 5);
    }

    fn acme_config() -> AcmeConfig {
        AcmeConfig {
            directory_url: "https://acme.example.test/directory".into(),
            domains: vec!["mx.example.test".into()],
            contact: "mailto:ops@example.test".into(),
            cache_dir: PathBuf::from("/var/lib/currawong/acme"),
            http_bind: default_acme_http_bind(),
        }
    }

    #[test]
    fn acme_replaces_the_certificate_files() {
        let mut cfg = Config::default();
        assert!(cfg.tls.acme.is_none(), "ACME is off by default");
        cfg.tls.acme = Some(acme_config());
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("not both"), "{err}");
        cfg.tls.cert = None;
        cfg.tls.key = None;
        cfg.validate().unwrap();
        cfg.tls.acme = None;
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("tls.cert"), "{err}");
    }

    #[test]
    fn acme_settings_are_checked() {
        type Edit = fn(&mut AcmeConfig);
        let cases: [(Edit, &str); 8] = [
            (
                |a| a.directory_url = "http://acme.example.test/d".into(),
                "https://",
            ),
            (|a| a.domains.clear(), "at least one"),
            (|a| a.domains = vec!["*.example.test".into()], "wildcards"),
            (
                |a| a.domains = vec!["bad host.example".into()],
                "not a host",
            ),
            (|a| a.contact = "ops@example.test".into(), "mailto:"),
            (|a| a.contact = "mailto:".into(), "mailto:"),
            (|a| a.cache_dir = PathBuf::from("acme"), "absolute"),
            (|a| a.http_bind = "0.0.0.0:0".into(), "http_bind"),
        ];
        for (edit, expected) in cases {
            let mut cfg = Config::default();
            cfg.tls.cert = None;
            cfg.tls.key = None;
            let mut acme = acme_config();
            edit(&mut acme);
            cfg.tls.acme = Some(acme);
            let err = cfg.validate().unwrap_err().to_string();
            assert!(err.contains("tls.acme") && err.contains(expected), "{err}");
        }
    }

    #[test]
    fn acme_section_loads_with_a_default_challenge_port() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("acme.toml");
        std::fs::write(
            &path,
            "[tls.acme]\n\
             directory_url = \"https://acme.example.test/directory\"\n\
             domains = [\"mx.example.test\"]\n\
             contact = \"mailto:ops@example.test\"\n\
             cache_dir = \"/var/lib/currawong/acme\"\n",
        )
        .unwrap();
        let cfg = load(&path).unwrap();
        assert!(cfg.tls.cert.is_none());
        assert_eq!(cfg.tls.acme.as_ref().unwrap().http_bind, "0.0.0.0:80");
        cfg.validate().unwrap();
    }

    #[test]
    fn foreign_clamd_fails_validation() {
        let mut cfg = load(&example_path()).expect("load");
        cfg.scanner.clamd.address = "tcp:8.8.8.8:3310".into();
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("clamd") && err.contains("8.8.8.8"), "{err}");
        cfg.scanner.clamd.address = "tcp:127.0.0.1:3310".into();
        cfg.validate().unwrap();
    }

    #[test]
    fn clamd_address_needs_a_scheme_prefix() {
        for bad in ["127.0.0.1:3310", "unix:", "tcp:localhost:3310"] {
            assert!(parse_clamd_address(bad).is_err(), "{bad}");
        }
        parse_clamd_address("tcp:127.0.0.1:3310").unwrap();
        parse_clamd_address("unix:/run/clamav/clamd.ctl").unwrap();
    }

    #[test]
    fn foreign_content_endpoint_fails_validation() {
        let mut cfg = Config::default();
        cfg.residency.content_endpoints =
            vec!["https://mail.s3.us-east-1.amazonaws.com/box".into()];
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("us-east-1"), "{err}");
    }

    #[test]
    fn residency_off_needs_an_approval() {
        let mut cfg = Config::default();
        cfg.residency.mode = "off".into();
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("off_approval"), "{err}");
        cfg.residency.off_approval = Some(ResidencyApproval {
            reason: "isolated lab".into(),
            approved_by: "ciso".into(),
        });
        cfg.validate().unwrap();
    }

    #[test]
    fn limits_timeouts_and_log_level_are_validated() {
        type Case = (&'static str, fn(&mut Config));
        let cases: Vec<Case> = vec![
            ("max_connections", |c| c.limits.max_connections = 0),
            ("max_connections_per_ip", |c| {
                c.limits.max_connections_per_ip = 0
            }),
            ("max_connections_per_ip", |c| {
                c.limits.max_connections_per_ip = c.limits.max_connections + 1
            }),
            ("max_line_bytes", |c| c.limits.max_line_bytes = 10),
            ("smtp_command_timeout_secs", |c| {
                c.limits.smtp_command_timeout_secs = 0
            }),
            ("job_timeout_secs", |c| c.scanner.job_timeout_secs = 0),
            ("poll_secs", |c| c.delivery.poll_secs = 0),
            ("log.level", |c| c.log.level = "currawong=loud".into()),
        ];
        for (needle, mutate) in cases {
            let mut cfg = Config::default();
            mutate(&mut cfg);
            let err = cfg.validate().unwrap_err().to_string();
            assert!(err.contains(needle), "{needle}: {err}");
        }
    }

    #[test]
    fn relative_spool_dir_fails() {
        let mut cfg = Config::default();
        cfg.spool.dir = PathBuf::from("relative/spool");
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("absolute"));
    }
}
