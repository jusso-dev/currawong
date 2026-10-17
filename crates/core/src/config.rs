//! Typed TOML configuration. Unknown keys fail closed so a typo cannot
//! silently disable a control.
use crate::secret::Secret;
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcmeConfig {
    pub directory_url: String,
    pub domains: Vec<String>,
    pub contact: String,
    pub cache_dir: PathBuf,
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
    /// Directories of supplemental on-premises signatures (the SaneSecurity
    /// approach). Currawong does not upload mail. Point `clamd` at these
    /// paths as well; they are recorded and checked locally.
    pub extra_signature_dirs: Vec<PathBuf>,
    pub extra_database_paths: Vec<PathBuf>,
    pub blocked_extensions: Vec<String>,
    pub treat_macros_as_active: bool,
    pub treat_executables_as_active: bool,
    pub extract: ExtractLimits,
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
    pub signing_key_path: Option<PathBuf>,
    pub report_dir: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResidencyOverride {
    pub url: String,
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
#[serde(deny_unknown_fields)]
pub struct DomainRoute {
    pub domain: String,
    /// `host` or `host:port`. Skips MX lookup.
    pub next_hop: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct DeliveryConfig {
    pub poll_secs: u64,
    pub max_age_days: u64,
    /// Hook for a later MTA-STS policy. M1 does not enforce DANE or MTA-STS.
    pub require_tls: bool,
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
    /// Connection checks skip DNSBL, greylisting and reputation for these CIDRs.
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
            extra_signature_dirs: Vec::new(),
            extra_database_paths: Vec::new(),
            blocked_extensions: default_blocked_extensions(),
            treat_macros_as_active: true,
            treat_executables_as_active: true,
            extract: ExtractLimits::default(),
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
            signing_key_path: None,
            report_dir: PathBuf::from("/var/lib/currawong/residency"),
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
        if needs_tls
            && (self.tls.cert.is_none() || self.tls.key.is_none())
            && self.tls.acme.is_none()
        {
            return Err(ConfigError::Invalid(
                "STARTTLS or implicit TLS requires tls.cert and tls.key, or tls.acme".into(),
            ));
        }
        if self.residency.mode != "au" && self.residency.mode != "off" {
            return Err(ConfigError::Invalid(
                "residency.mode must be \"au\" or \"off\"".into(),
            ));
        }
        if !self.scanner.clamd.address.is_empty() {
            parse_clamd_address(&self.scanner.clamd.address)?;
        }
        if self.log.format != "json" && self.log.format != "pretty" {
            return Err(ConfigError::Invalid(
                "log.format must be \"json\" or \"pretty\"".into(),
            ));
        }
        self.metrics.listen.parse::<SocketAddr>().map_err(|_| {
            ConfigError::Invalid(format!(
                "metrics.listen '{}' is not a socket address",
                self.metrics.listen
            ))
        })?;
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
    let tcp = address.strip_prefix("tcp:").unwrap_or(address);
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

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn example_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../config/currawong.example.toml")
    }

    #[test]
    fn example_loads_and_validates() {
        let cfg = Config::load(&example_path()).expect("example config");
        cfg.validate().expect("example config is valid");
        assert!(cfg.limits.max_message_bytes >= 1024 * 1024);
        assert_eq!(cfg.residency.mode, "au");
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
        let err = Config::load(&path).unwrap_err();
        let text = err.to_string();
        assert!(
            text.contains("not_a_real_key"),
            "error should name the unknown key, got {text}"
        );
    }

    #[test]
    fn env_override_wins() {
        let _guard = ENV_LOCK.lock().unwrap();
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

    #[test]
    fn relative_spool_dir_fails() {
        let mut cfg = Config::default();
        cfg.spool.dir = PathBuf::from("relative/spool");
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("absolute"));
    }
}
