//! Australian data residency guard.
//!
//! Decisions use configured host suffixes and CIDRs. This crate never
//! geolocates an address by itself and never resolves names.
//!
//! Every client that carries message content off the gateway (clamd,
//! sandbox, LLM, object store, webhooks, Graph) must call the guard:
//! [`ResidencyGuard::check_request`] before each request, and
//! [`ResidencyGuard::check_redirect`] for each redirect before following it.
//! HTTP clients must turn off automatic redirects so that no hop skips the
//! guard.
use crate::config::{Config, ResidencyApproval, ResidencyOverride};
use ed25519_dalek::{Signature, Signer, Verifier};
pub use ed25519_dalek::{SigningKey, VerifyingKey};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    net::{IpAddr, SocketAddr},
    path::Path,
    sync::Mutex,
};
use url::{Host, Url};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ResidencyError {
    #[error("message content must stay in Australia: {0}")]
    Denied(String),
    #[error("invalid residency endpoint: {0}")]
    Invalid(String),
    #[error("residency signature check failed")]
    BadSignature,
}

#[derive(Debug, Clone)]
pub struct EndpointRule {
    pub suffix: Option<String>,
    pub cidr: Option<IpNet>,
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditEvent {
    pub action: String,
    pub url: String,
    pub reason: String,
    pub approved_by: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CheckedEndpoint {
    pub url: String,
    pub decision: String,
    pub matched_rule: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResidencyReport {
    pub mode: String,
    /// RFC 3339, UTC.
    pub generated_at: String,
    /// Every configured destination for message content, with its decision.
    pub endpoints: Vec<CheckedEndpoint>,
    /// Overrides used since the daemon started (one entry per override).
    pub overrides: Vec<AuditEvent>,
    /// Every override in the configuration, used or not.
    pub configured_overrides: Vec<ResidencyOverride>,
    /// Present when `mode = "off"`.
    pub off_approval: Option<ResidencyApproval>,
    pub allowed_host_suffixes: Vec<String>,
    pub allowed_names: Vec<String>,
    pub allowed_cidrs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedReport {
    pub report: ResidencyReport,
    pub public_key_hex: String,
    pub signature_hex: String,
}

pub struct ResidencyGuard {
    pub mode: String,
    allowed: Vec<EndpointRule>,
    allowed_suffixes: Vec<String>,
    allowed_cidrs: Vec<String>,
    allowed_names: Vec<String>,
    overrides: Vec<ResidencyOverride>,
    off_approval: Option<ResidencyApproval>,
    /// At most one entry per override, plus one for `mode = "off"`.
    audit: Mutex<Vec<AuditEvent>>,
}

impl ResidencyGuard {
    pub fn from_config(cfg: &crate::config::ResidencyConfig) -> Result<Self, ResidencyError> {
        match cfg.mode.as_str() {
            "au" => {}
            "off" => match &cfg.off_approval {
                Some(approval) if approved(&approval.reason, &approval.approved_by) => {}
                _ => {
                    return Err(ResidencyError::Invalid(
                        "residency.mode = \"off\" needs residency.off_approval with a reason and approved_by".into(),
                    ))
                }
            },
            other => {
                return Err(ResidencyError::Invalid(format!(
                    "residency.mode must be \"au\" or \"off\", not \"{other}\""
                )))
            }
        }
        for over in &cfg.overrides {
            if !approved(&over.reason, &over.approved_by) {
                return Err(ResidencyError::Invalid(format!(
                    "override for {} needs a reason and approved_by",
                    over.url
                )));
            }
        }
        let mut allowed = Vec::new();
        for suffix in &cfg.allowed_host_suffixes {
            let suffix = suffix.trim_start_matches('.').to_ascii_lowercase();
            if suffix.is_empty() {
                return Err(ResidencyError::Invalid(
                    "empty host suffix in residency rules".into(),
                ));
            }
            allowed.push(EndpointRule {
                suffix: Some(suffix),
                cidr: None,
                name: None,
            });
        }
        for name in &cfg.allowed_names {
            allowed.push(EndpointRule {
                suffix: None,
                cidr: None,
                name: Some(name.to_ascii_lowercase()),
            });
        }
        let mut cidrs = Vec::new();
        for cidr in &cfg.allowed_cidrs {
            let net: IpNet = cidr
                .parse()
                .map_err(|err| ResidencyError::Invalid(format!("cidr {cidr}: {err}")))?;
            cidrs.push(cidr.clone());
            allowed.push(EndpointRule {
                suffix: None,
                cidr: Some(net),
                name: None,
            });
        }
        Ok(Self {
            mode: cfg.mode.clone(),
            allowed,
            allowed_suffixes: cfg.allowed_host_suffixes.clone(),
            allowed_cidrs: cidrs,
            allowed_names: cfg.allowed_names.clone(),
            overrides: cfg.overrides.clone(),
            off_approval: cfg.off_approval.clone(),
            audit: Mutex::new(Vec::new()),
        })
    }

    /// Refuse to send message content to a URL that is outside the configured
    /// Australian and on-premises rules. Only `http` and `https` are allowed.
    /// Overrides and `mode = "off"` are allowed and audited.
    pub fn check(&self, url: &Url) -> Result<(), ResidencyError> {
        if !matches!(url.scheme(), "https" | "http") {
            return Err(ResidencyError::Invalid(format!(
                "{} uses scheme {}, only http and https are allowed",
                url,
                url.scheme()
            )));
        }
        let url_text = normalise_url(url);
        if self.off_allows() {
            return Ok(());
        }
        if let Some(over) = self
            .overrides
            .iter()
            .find(|item| normalise_str(&item.url) == url_text)
        {
            self.record(AuditEvent {
                action: "residency_override".into(),
                url: url_text,
                reason: over.reason.clone(),
                approved_by: over.approved_by.clone(),
            });
            return Ok(());
        }
        match classify_url(url, &self.allowed) {
            Some(_) => Ok(()),
            None => Err(ResidencyError::Denied(format!(
                "{url_text} is not an allowed Australian or on-premises endpoint"
            ))),
        }
    }

    /// Call before every outbound request that carries message content.
    pub fn check_request(&self, url: &Url) -> Result<(), ResidencyError> {
        self.check(url)
    }

    /// Call for each HTTP redirect before following it. `location` is the raw
    /// `Location` header; relative values resolve against `current`. Returns the
    /// URL to request next.
    pub fn check_redirect(&self, current: &Url, location: &str) -> Result<Url, ResidencyError> {
        let next = current
            .join(location)
            .map_err(|err| ResidencyError::Invalid(format!("redirect {location}: {err}")))?;
        self.check(&next)?;
        Ok(next)
    }

    /// Check a socket peer, for example a TCP clamd. Only CIDR rules apply.
    pub fn check_socket(&self, addr: &SocketAddr) -> Result<(), ResidencyError> {
        let label = format!("tcp://{addr}");
        if self.off_allows() {
            return Ok(());
        }
        if self.allowed.iter().any(|rule| {
            rule.cidr
                .map(|net| net.contains(&addr.ip()))
                .unwrap_or(false)
        }) {
            return Ok(());
        }
        Err(ResidencyError::Denied(format!(
            "{label} is not an allowed Australian or on-premises address"
        )))
    }

    /// clamd receives the whole message. `unix:` sockets are local. A TCP
    /// address must be loopback or inside an allowed CIDR.
    pub fn check_clamd(&self, address: &str) -> Result<(), ResidencyError> {
        if address.is_empty() || address.starts_with("unix:") {
            return Ok(());
        }
        let tcp = address.strip_prefix("tcp:").unwrap_or(address);
        let addr: SocketAddr = tcp
            .parse()
            .map_err(|_| ResidencyError::Invalid(format!("clamd address {address}")))?;
        self.check_socket(&addr)
    }

    /// Check every configured content destination. Startup fails on the first
    /// denied one.
    pub fn enforce_config(&self, cfg: &Config) -> Result<(), ResidencyError> {
        self.check_clamd(&cfg.scanner.clamd.address)
            .map_err(|err| match err {
                ResidencyError::Denied(text) => {
                    ResidencyError::Denied(format!("scanner.clamd.address: {text}"))
                }
                other => other,
            })?;
        self.enforce_startup(&cfg.residency.content_endpoints)
    }

    pub fn enforce_startup(&self, endpoints: &[String]) -> Result<(), ResidencyError> {
        for endpoint in endpoints {
            let url = Url::parse(endpoint)
                .map_err(|err| ResidencyError::Invalid(format!("{endpoint}: {err}")))?;
            self.check(&url)?;
        }
        Ok(())
    }

    pub fn audit_log(&self) -> Vec<AuditEvent> {
        self.audit.lock().expect("audit lock").clone()
    }

    /// Report on every configured content destination: clamd and
    /// `residency.content_endpoints`.
    pub fn report(&self, generated_at: &str, cfg: &Config) -> ResidencyReport {
        let mut checked = Vec::new();
        let clamd = &cfg.scanner.clamd.address;
        if !clamd.is_empty() {
            let decision = match self.check_clamd(clamd) {
                Ok(()) => "allowed".to_string(),
                Err(err) => format!("denied: {err}"),
            };
            let matched = clamd
                .strip_prefix("tcp:")
                .unwrap_or(clamd)
                .parse::<SocketAddr>()
                .map(|addr| describe_ip(addr.ip(), &self.allowed))
                .unwrap_or_else(|_| "local-socket".into());
            checked.push(CheckedEndpoint {
                url: format!("clamd:{clamd}"),
                decision,
                matched_rule: matched,
            });
        }
        for endpoint in &cfg.residency.content_endpoints {
            let (decision, matched) = match Url::parse(endpoint) {
                Ok(url) => (
                    match self.check(&url) {
                        Ok(()) => "allowed".to_string(),
                        Err(err) => format!("denied: {err}"),
                    },
                    describe_match(&url, &self.allowed),
                ),
                Err(err) => (format!("invalid: {err}"), "invalid".into()),
            };
            checked.push(CheckedEndpoint {
                url: endpoint.clone(),
                decision,
                matched_rule: matched,
            });
        }
        ResidencyReport {
            mode: self.mode.clone(),
            generated_at: generated_at.into(),
            endpoints: checked,
            overrides: self.audit_log(),
            configured_overrides: self.overrides.clone(),
            off_approval: self.off_approval.clone(),
            allowed_host_suffixes: self.allowed_suffixes.clone(),
            allowed_names: self.allowed_names.clone(),
            allowed_cidrs: self.allowed_cidrs.clone(),
        }
    }

    fn off_allows(&self) -> bool {
        if self.mode != "off" {
            return false;
        }
        let (reason, approved_by) = self
            .off_approval
            .as_ref()
            .map(|a| (a.reason.clone(), a.approved_by.clone()))
            .unwrap_or_default();
        self.record(AuditEvent {
            action: "residency_off".into(),
            url: "*".into(),
            reason,
            approved_by,
        });
        true
    }

    /// Keep one audit entry per override and log it once at warn level.
    fn record(&self, event: AuditEvent) {
        let mut audit = self.audit.lock().expect("audit lock");
        if audit.contains(&event) {
            return;
        }
        tracing::warn!(
            action = %event.action,
            url = %event.url,
            reason = %event.reason,
            approved_by = %event.approved_by,
            "residency override used"
        );
        audit.push(event);
    }
}

fn approved(reason: &str, approved_by: &str) -> bool {
    !reason.trim().is_empty() && !approved_by.trim().is_empty()
}

fn normalise_url(url: &Url) -> String {
    normalise_str(url.as_str())
}

fn normalise_str(value: &str) -> String {
    value.trim().trim_end_matches('/').to_ascii_lowercase()
}

fn classify_url<'a>(url: &Url, rules: &'a [EndpointRule]) -> Option<&'a EndpointRule> {
    match url.host()? {
        Host::Ipv4(ip) => classify_ip(IpAddr::V4(ip), rules),
        Host::Ipv6(ip) => classify_ip(IpAddr::V6(ip), rules),
        Host::Domain(name) => classify_name(name, rules),
    }
}

fn classify_ip(ip: IpAddr, rules: &[EndpointRule]) -> Option<&EndpointRule> {
    rules
        .iter()
        .find(|rule| rule.cidr.map(|net| net.contains(&ip)).unwrap_or(false))
}

fn classify_name<'a>(host: &str, rules: &'a [EndpointRule]) -> Option<&'a EndpointRule> {
    let host_l = host.trim_end_matches('.').to_ascii_lowercase();
    rules.iter().find(|rule| {
        if let Some(name) = &rule.name {
            return name == &host_l;
        }
        if let Some(suffix) = &rule.suffix {
            return host_l == *suffix || host_l.ends_with(&format!(".{suffix}"));
        }
        false
    })
}

fn describe_rule(rule: Option<&EndpointRule>) -> String {
    match rule {
        Some(rule) => {
            if let Some(suffix) = &rule.suffix {
                format!("suffix:{suffix}")
            } else if let Some(cidr) = &rule.cidr {
                format!("cidr:{cidr}")
            } else if let Some(name) = &rule.name {
                format!("name:{name}")
            } else {
                "none".into()
            }
        }
        None => "none".into(),
    }
}

fn describe_match(url: &Url, rules: &[EndpointRule]) -> String {
    describe_rule(classify_url(url, rules))
}

fn describe_ip(ip: IpAddr, rules: &[EndpointRule]) -> String {
    describe_rule(classify_ip(ip, rules))
}

pub fn canonical_report_bytes(report: &ResidencyReport) -> Vec<u8> {
    serde_json::to_vec(report).expect("report serialises")
}

pub fn sign_report(report: ResidencyReport, key: &SigningKey) -> SignedReport {
    let bytes = canonical_report_bytes(&report);
    let signature = key.sign(&bytes);
    SignedReport {
        report,
        public_key_hex: hex::encode(key.verifying_key().to_bytes()),
        signature_hex: hex::encode(signature.to_bytes()),
    }
}

/// Parse the hex public key an auditor pinned from `residency-signing.pub`.
pub fn verifying_key_from_hex(text: &str) -> Result<VerifyingKey, ResidencyError> {
    let bytes = hex::decode(text.trim()).map_err(|_| ResidencyError::BadSignature)?;
    let array: [u8; 32] = bytes.try_into().map_err(|_| ResidencyError::BadSignature)?;
    VerifyingKey::from_bytes(&array).map_err(|_| ResidencyError::BadSignature)
}

/// Verify a report against a key the verifier already trusts. The key embedded
/// in the report is informational and must match `trusted`.
pub fn verify_report(signed: &SignedReport, trusted: &VerifyingKey) -> Result<(), ResidencyError> {
    if verifying_key_from_hex(&signed.public_key_hex)? != *trusted {
        return Err(ResidencyError::BadSignature);
    }
    let sig_bytes = hex::decode(&signed.signature_hex).map_err(|_| ResidencyError::BadSignature)?;
    let sig_array: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| ResidencyError::BadSignature)?;
    let signature = Signature::from_bytes(&sig_array);
    trusted
        .verify(&canonical_report_bytes(&signed.report), &signature)
        .map_err(|_| ResidencyError::BadSignature)
}

pub fn load_or_create_signing_key(path: &Path) -> std::io::Result<SigningKey> {
    if path.exists() {
        let bytes = fs::read(path)?;
        let array: [u8; 32] = bytes.try_into().map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "residency signing key must be 32 bytes",
            )
        })?;
        return Ok(SigningKey::from_bytes(&array));
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let key = SigningKey::generate(&mut rand::rngs::OsRng);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        use std::io::Write;
        file.write_all(&key.to_bytes())?;
    }
    #[cfg(not(unix))]
    {
        fs::write(path, key.to_bytes())?;
    }
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ResidencyConfig;

    fn guard(overrides: Vec<ResidencyOverride>) -> ResidencyGuard {
        let cfg = ResidencyConfig {
            overrides,
            ..ResidencyConfig::default()
        };
        ResidencyGuard::from_config(&cfg).unwrap()
    }

    fn legacy_override() -> ResidencyOverride {
        ResidencyOverride {
            url: "https://legacy.s3.us-east-1.amazonaws.com/box".into(),
            reason: "contracted archive until migration".into(),
            approved_by: "tenant-admin".into(),
        }
    }

    #[test]
    fn us_east_1_is_refused_and_sydney_is_allowed() {
        let guard = guard(Vec::new());
        let denied = Url::parse("https://mail.s3.us-east-1.amazonaws.com/bucket").unwrap();
        assert!(guard.check(&denied).is_err());
        let sydney = Url::parse("https://mail.s3.ap-southeast-2.amazonaws.com/bucket").unwrap();
        assert!(guard.check(&sydney).is_ok());
        let melbourne = Url::parse("https://mail.s3.ap-southeast-4.amazonaws.com/bucket").unwrap();
        assert!(guard.check(&melbourne).is_ok());
        let on_prem = Url::parse("https://10.1.2.3/quarantine").unwrap();
        assert!(guard.check(&on_prem).is_ok());
        let lookalike =
            Url::parse("https://s3.ap-southeast-2.amazonaws.com.evil.test/bucket").unwrap();
        assert!(guard.check(&lookalike).is_err());
    }

    #[test]
    fn ipv6_literals_match_cidrs_and_other_schemes_fail() {
        let guard = guard(Vec::new());
        guard
            .check(&Url::parse("https://[::1]:8443/hook").unwrap())
            .unwrap();
        assert!(guard
            .check(&Url::parse("https://[2001:db8::1]/hook").unwrap())
            .is_err());
        let err = guard
            .check(&Url::parse("ftp://10.1.2.3/drop").unwrap())
            .unwrap_err();
        assert!(matches!(err, ResidencyError::Invalid(_)), "{err:?}");
    }

    #[test]
    fn startup_fails_for_a_foreign_bucket() {
        let guard = guard(Vec::new());
        let err = guard
            .enforce_startup(&["https://mail.s3.us-east-1.amazonaws.com/box".into()])
            .unwrap_err();
        assert!(matches!(err, ResidencyError::Denied(_)));
    }

    #[test]
    fn clamd_must_be_local_or_on_premises() {
        let guard = guard(Vec::new());
        guard.check_clamd("unix:/run/clamav/clamd.ctl").unwrap();
        guard.check_clamd("tcp:127.0.0.1:3310").unwrap();
        guard.check_clamd("tcp:10.2.3.4:3310").unwrap();
        guard.check_clamd("[::1]:3310").unwrap();
        let err = guard.check_clamd("tcp:8.8.8.8:3310").unwrap_err();
        assert!(matches!(err, ResidencyError::Denied(_)), "{err:?}");
    }

    #[test]
    fn redirects_are_checked_before_they_are_followed() {
        let guard = guard(Vec::new());
        let start = Url::parse("https://mail.s3.ap-southeast-2.amazonaws.com/bucket/a").unwrap();
        let next = guard.check_redirect(&start, "/bucket/b").unwrap();
        assert_eq!(next.path(), "/bucket/b");
        let err = guard
            .check_redirect(&start, "https://mail.s3.us-east-1.amazonaws.com/bucket/a")
            .unwrap_err();
        assert!(matches!(err, ResidencyError::Denied(_)));
        assert!(guard
            .check_request(&Url::parse("https://llm.example.com/v1").unwrap())
            .is_err());
    }

    #[test]
    fn off_mode_needs_an_approval_and_is_audited() {
        let mut cfg = ResidencyConfig {
            mode: "off".into(),
            ..ResidencyConfig::default()
        };
        let err = ResidencyGuard::from_config(&cfg).err().expect("refused");
        assert!(err.to_string().contains("off_approval"), "{err}");
        cfg.off_approval = Some(ResidencyApproval {
            reason: " ".into(),
            approved_by: "ciso".into(),
        });
        assert!(ResidencyGuard::from_config(&cfg).is_err());
        cfg.off_approval = Some(ResidencyApproval {
            reason: "lab tenant, no production mail".into(),
            approved_by: "ciso".into(),
        });
        let guard = ResidencyGuard::from_config(&cfg).unwrap();
        let foreign = Url::parse("https://mail.s3.us-east-1.amazonaws.com/box").unwrap();
        guard.check(&foreign).unwrap();
        guard.check(&foreign).unwrap();
        let audit = guard.audit_log();
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0].action, "residency_off");
        assert_eq!(audit[0].approved_by, "ciso");
        let report = guard.report("2026-10-14T00:00:00Z", &Config::default());
        assert_eq!(report.off_approval, cfg.off_approval);
    }

    #[test]
    fn overrides_are_audited_once_and_reported() {
        let guard = guard(vec![legacy_override()]);
        let url = Url::parse("https://legacy.s3.us-east-1.amazonaws.com/box").unwrap();
        for _ in 0..1000 {
            guard.check(&url).unwrap();
        }
        let audit = guard.audit_log();
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0].approved_by, "tenant-admin");
        assert_eq!(audit[0].action, "residency_override");
        let report = guard.report("2026-10-14T00:00:00Z", &Config::default());
        assert_eq!(report.overrides.len(), 1);
        assert_eq!(report.configured_overrides, vec![legacy_override()]);
    }

    #[test]
    fn overrides_need_a_reason_and_approver() {
        let mut over = legacy_override();
        over.approved_by.clear();
        let cfg = ResidencyConfig {
            overrides: vec![over],
            ..ResidencyConfig::default()
        };
        assert!(ResidencyGuard::from_config(&cfg).is_err());
    }

    #[test]
    fn report_lists_clamd_and_content_endpoints() {
        let guard = guard(Vec::new());
        let mut cfg = Config::default();
        cfg.scanner.clamd.address = "tcp:127.0.0.1:3310".into();
        cfg.residency.content_endpoints =
            vec!["https://mail.s3.ap-southeast-2.amazonaws.com/box".into()];
        let report = guard.report("2026-10-14T00:00:00Z", &cfg);
        let urls: Vec<_> = report.endpoints.iter().map(|e| e.url.as_str()).collect();
        assert_eq!(
            urls,
            [
                "clamd:tcp:127.0.0.1:3310",
                "https://mail.s3.ap-southeast-2.amazonaws.com/box"
            ]
        );
        assert!(report.endpoints.iter().all(|e| e.decision == "allowed"));
        assert_eq!(report.endpoints[0].matched_rule, "cidr:127.0.0.0/8");
    }

    #[test]
    fn report_signature_verifies_against_the_pinned_key_only() {
        let guard = guard(Vec::new());
        let mut cfg = Config::default();
        cfg.residency.content_endpoints =
            vec!["https://mail.s3.ap-southeast-2.amazonaws.com/box".into()];
        let report = guard.report("2026-10-14T00:00:00Z", &cfg);
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let trusted = verifying_key_from_hex(&hex::encode(key.verifying_key().to_bytes())).unwrap();
        let signed = sign_report(report, &key);
        verify_report(&signed, &trusted).unwrap();
        let mut tampered = signed.clone();
        tampered.report.mode = "off".into();
        assert!(verify_report(&tampered, &trusted).is_err());
        // A forger re-signs with their own key and embeds it. The pinned key rejects it.
        let forger = SigningKey::generate(&mut rand::rngs::OsRng);
        let forged = sign_report(tampered.report, &forger);
        assert!(verify_report(&forged, &trusted).is_err());
    }
}
