//! Australian data residency guard.
//!
//! Decisions use configured host suffixes and CIDRs. This crate never
//! geolocates an address by itself.
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::{fs, net::IpAddr, path::Path, sync::Mutex};
use url::Url;

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
    pub generated_at: String,
    pub endpoints: Vec<CheckedEndpoint>,
    pub overrides: Vec<AuditEvent>,
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
    overrides: Vec<crate::config::ResidencyOverride>,
    audit: Mutex<Vec<AuditEvent>>,
}

impl ResidencyGuard {
    pub fn from_config(cfg: &crate::config::ResidencyConfig) -> Result<Self, ResidencyError> {
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
            audit: Mutex::new(Vec::new()),
        })
    }

    /// Refuse to send message content to a URL that is outside the configured
    /// Australian and on-premises rules. Overrides are allowed and audited.
    pub fn check(&self, url: &Url) -> Result<(), ResidencyError> {
        if self.mode == "off" {
            return Ok(());
        }
        if self.mode != "au" {
            return Err(ResidencyError::Invalid(format!(
                "unknown residency mode {}",
                self.mode
            )));
        }
        let url_text = normalise_url(url);
        if let Some(over) = self
            .overrides
            .iter()
            .find(|item| normalise_str(&item.url) == url_text)
        {
            self.audit.lock().expect("audit lock").push(AuditEvent {
                action: "residency_override".into(),
                url: url_text,
                reason: over.reason.clone(),
                approved_by: over.approved_by.clone(),
            });
            return Ok(());
        }
        let host = url
            .host_str()
            .ok_or_else(|| ResidencyError::Invalid("URL has no host".into()))?;
        match classify_host(host, &self.allowed) {
            Some(rule) => {
                let _ = rule;
                Ok(())
            }
            None => Err(ResidencyError::Denied(format!(
                "{url_text} is not an allowed Australian or on-premises endpoint"
            ))),
        }
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

    pub fn report(&self, generated_at: &str, endpoints: &[String]) -> ResidencyReport {
        let mut checked = Vec::new();
        for endpoint in endpoints {
            let decision = match Url::parse(endpoint) {
                Ok(url) => match self.check(&url) {
                    Ok(()) => "allowed".to_string(),
                    Err(err) => format!("denied: {err}"),
                },
                Err(err) => format!("invalid: {err}"),
            };
            let matched = match Url::parse(endpoint) {
                Ok(url) => describe_match(url.host_str().unwrap_or(""), &self.allowed),
                Err(_) => "invalid".into(),
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
            allowed_host_suffixes: self.allowed_suffixes.clone(),
            allowed_names: self.allowed_names.clone(),
            allowed_cidrs: self.allowed_cidrs.clone(),
        }
    }
}

fn normalise_url(url: &Url) -> String {
    normalise_str(url.as_str())
}

fn normalise_str(value: &str) -> String {
    value.trim().trim_end_matches('/').to_ascii_lowercase()
}

fn classify_host<'a>(host: &str, rules: &'a [EndpointRule]) -> Option<&'a EndpointRule> {
    let host_l = host.trim_end_matches('.').to_ascii_lowercase();
    if let Ok(ip) = host_l.parse::<IpAddr>() {
        return rules
            .iter()
            .find(|rule| rule.cidr.map(|net| net.contains(&ip)).unwrap_or(false));
    }
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

fn describe_match(host: &str, rules: &[EndpointRule]) -> String {
    match classify_host(host, rules) {
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

pub fn verify_report(signed: &SignedReport) -> Result<(), ResidencyError> {
    let pk_bytes = hex::decode(&signed.public_key_hex).map_err(|_| ResidencyError::BadSignature)?;
    let pk_array: [u8; 32] = pk_bytes
        .try_into()
        .map_err(|_| ResidencyError::BadSignature)?;
    let verifying =
        VerifyingKey::from_bytes(&pk_array).map_err(|_| ResidencyError::BadSignature)?;
    let sig_bytes = hex::decode(&signed.signature_hex).map_err(|_| ResidencyError::BadSignature)?;
    let sig_array: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| ResidencyError::BadSignature)?;
    let signature = Signature::from_bytes(&sig_array);
    verifying
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

    fn guard(overrides: Vec<crate::config::ResidencyOverride>) -> ResidencyGuard {
        let cfg = ResidencyConfig {
            overrides,
            ..ResidencyConfig::default()
        };
        ResidencyGuard::from_config(&cfg).unwrap()
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
    fn startup_fails_for_a_foreign_bucket() {
        let guard = guard(Vec::new());
        let err = guard
            .enforce_startup(&["https://mail.s3.us-east-1.amazonaws.com/box".into()])
            .unwrap_err();
        assert!(matches!(err, ResidencyError::Denied(_)));
    }

    #[test]
    fn overrides_are_audited() {
        let guard = guard(vec![crate::config::ResidencyOverride {
            url: "https://legacy.s3.us-east-1.amazonaws.com/box".into(),
            reason: "contracted archive until migration".into(),
            approved_by: "tenant-admin".into(),
        }]);
        let url = Url::parse("https://legacy.s3.us-east-1.amazonaws.com/box").unwrap();
        guard.check(&url).unwrap();
        let audit = guard.audit_log();
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0].approved_by, "tenant-admin");
        assert_eq!(audit[0].action, "residency_override");
    }

    #[test]
    fn report_signature_verifies_and_rejects_tampering() {
        let guard = guard(Vec::new());
        let report = guard.report(
            "2026-10-14T00:00:00Z",
            &["https://mail.s3.ap-southeast-2.amazonaws.com/box".into()],
        );
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let signed = sign_report(report, &key);
        verify_report(&signed).unwrap();
        let mut tampered = signed.clone();
        tampered.report.mode = "off".into();
        assert!(verify_report(&tampered).is_err());
    }
}
