//! Policy model. The same types load from TOML, store as rows and export back to TOML.
use currawong_core::Direction;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("invalid policy: {0}")]
    Invalid(String),
    #[error("policy pack: {0}")]
    Toml(String),
    #[error("policy store: {0}")]
    Store(String),
}

/// Who a policy applies to. Inbound mail is scoped by recipient and outbound
/// mail by sender, so a domain policy always means "our users in that domain".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    #[default]
    Global,
    Tenant,
    Domain(String),
    Group(String),
    User(String),
}

impl Scope {
    /// More specific scopes are evaluated first.
    pub fn specificity(&self) -> u8 {
        match self {
            Self::Global => 0,
            Self::Tenant => 1,
            Self::Domain(_) => 2,
            Self::Group(_) => 3,
            Self::User(_) => 4,
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            Self::Global => "global",
            Self::Tenant => "tenant",
            Self::Domain(_) => "domain",
            Self::Group(_) => "group",
            Self::User(_) => "user",
        }
    }

    pub fn value(&self) -> Option<&str> {
        match self {
            Self::Global | Self::Tenant => None,
            Self::Domain(v) | Self::Group(v) | Self::User(v) => Some(v),
        }
    }

    pub fn from_parts(kind: &str, value: Option<String>) -> Result<Self, PolicyError> {
        let need = |v: Option<String>| {
            v.ok_or_else(|| PolicyError::Invalid(format!("scope {kind} needs a value")))
        };
        Ok(match kind {
            "global" => Self::Global,
            "tenant" => Self::Tenant,
            "domain" => Self::Domain(need(value)?),
            "group" => Self::Group(need(value)?),
            "user" => Self::User(need(value)?),
            other => return Err(PolicyError::Invalid(format!("unknown scope {other}"))),
        })
    }
}

/// Mail flow in policy files. Lower case, unlike the spool's `Direction`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Flow {
    Inbound,
    Outbound,
}

impl From<Direction> for Flow {
    fn from(direction: Direction) -> Self {
        match direction {
            Direction::Inbound => Self::Inbound,
            Direction::Outbound => Self::Outbound,
        }
    }
}

/// One test against the message. All conditions in a policy must hold.
/// Signal names (`flag`, `score`, `count`) are listed in `signals.rs`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Condition {
    Direction(Flow),
    /// `user@example.com.au`, `*@example.com.au` or `*`.
    Sender(String),
    Recipient(String),
    /// The recipient is a member of the named group.
    Group(String),
    Flag(String),
    /// Half-open range: `at_least <= score < below`.
    Score {
        name: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        at_least: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        below: Option<f64>,
    },
    Count {
        name: String,
        at_least: u64,
    },
    /// Protective marking, for example `OFFICIAL:Sensitive`. `none` means unmarked.
    Marking(String),
    /// `method` is `spf`, `dkim`, `dmarc`, `arc` or `dmarc_policy`.
    Auth {
        method: String,
        result: String,
    },
}

/// What to do when a policy matches. The first terminal action (deliver,
/// quarantine, reject, discard, defer) sets the verdict; the others accumulate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Action {
    Deliver,
    /// Hold in the named quarantine queue.
    Quarantine(String),
    Reject {
        #[serde(default = "default_reject_code")]
        code: u16,
    },
    Discard,
    /// Keep in the spool and retry later.
    Defer,
    AddHeader {
        name: String,
        value: String,
    },
    Banner(String),
    Redirect(String),
    Bcc(String),
    Encrypt,
    RequireTls,
}

fn default_reject_code() -> u16 {
    550
}

impl Action {
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Deliver | Self::Quarantine(_) | Self::Reject { .. } | Self::Discard | Self::Defer
        )
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub id: String,
    /// Owner. `None` is a platform policy; `Some` is a tenant's, applied only to that tenant's mail.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    #[serde(default)]
    pub scope: Scope,
    /// Lower runs first within the same scope specificity.
    #[serde(default = "default_priority")]
    pub priority: i64,
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Matches are explained but never change the verdict or actions.
    #[serde(default)]
    pub dry_run: bool,
    /// Non-terminal actions apply even after a more specific policy set the verdict.
    #[serde(default, skip_serializing_if = "is_false")]
    pub mandatory: bool,
    /// Platform global policies only: when this matches, the built-in floor
    /// (malware, scan deferred, scan failed) does not apply.
    #[serde(default, skip_serializing_if = "is_false")]
    pub override_floor: bool,
    #[serde(default)]
    pub conditions: Vec<Condition>,
    #[serde(default)]
    pub actions: Vec<Action>,
}

fn default_priority() -> i64 {
    100
}

fn default_true() -> bool {
    true
}

fn is_false(value: &bool) -> bool {
    !*value
}

/// Headers a policy may not add: forging them would mislead authentication,
/// tracing or the recipient.
const PROTECTED_HEADERS: &[&str] = &[
    "authentication-results",
    "received",
    "return-path",
    "dkim-signature",
    "from",
    "sender",
    "reply-to",
    "to",
    "cc",
    "bcc",
    "subject",
    "date",
    "message-id",
];

impl Policy {
    pub fn validate(&self) -> Result<(), PolicyError> {
        let bad = |msg: String| Err(PolicyError::Invalid(format!("{}: {msg}", self.id)));
        if self.id.trim().is_empty() {
            return Err(PolicyError::Invalid("policy id is empty".into()));
        }
        match (&self.scope, &self.tenant_id) {
            (Scope::Tenant, None) => return bad("tenant scope needs tenant_id".into()),
            (Scope::Global, Some(_)) => {
                return bad("global scope cannot have tenant_id, use tenant scope".into())
            }
            _ => {}
        }
        if self.override_floor && (self.tenant_id.is_some() || self.scope != Scope::Global) {
            return bad("only platform global policies may override the floor".into());
        }
        if self.scope.value().is_some_and(|v| v.trim().is_empty()) {
            return bad("scope value is empty".into());
        }
        for condition in &self.conditions {
            match condition {
                Condition::Auth { method, .. }
                    if !["spf", "dkim", "dmarc", "arc", "dmarc_policy"]
                        .contains(&method.as_str()) =>
                {
                    return bad(format!("unknown auth method {method}"));
                }
                Condition::Score {
                    name,
                    at_least,
                    below,
                } => {
                    if [*at_least, *below].iter().flatten().any(|v| !v.is_finite()) {
                        return bad(format!("score {name} bound is not a finite number"));
                    }
                    if let (Some(min), Some(max)) = (at_least, below) {
                        if max <= min {
                            return bad(format!("score {name} range is empty"));
                        }
                    }
                }
                _ => {}
            }
        }
        for action in &self.actions {
            match action {
                Action::AddHeader { name, value } => {
                    let lower = name.to_ascii_lowercase();
                    let name_ok = !name.is_empty()
                        && name.bytes().all(|b| b.is_ascii_graphic() && b != b':')
                        && !PROTECTED_HEADERS.contains(&lower.as_str())
                        && !lower.starts_with("arc-");
                    let value_ok = value.chars().all(|c| c == '\t' || !c.is_control());
                    if !name_ok || !value_ok || name.len() + 2 + value.len() > 998 {
                        return bad(format!("header {name} is not allowed"));
                    }
                }
                Action::Redirect(addr) | Action::Bcc(addr) => {
                    let ok = addr.contains('@')
                        && !addr.contains(|c: char| {
                            c.is_whitespace() || c.is_control() || "<>,".contains(c)
                        });
                    if !ok {
                        return bad(format!("bad address {addr}"));
                    }
                }
                Action::Reject { code } if !(500..600).contains(code) => {
                    return bad(format!("reject code {code} must be 5xx"));
                }
                // Refused rather than silently ignored: delivery cannot carry these out yet,
                // and accepting them would deliver mail the policy meant to protect.
                Action::Banner(_) | Action::Encrypt | Action::RequireTls => {
                    return bad("banner, encrypt and require_tls are not supported yet".into());
                }
                _ => {}
            }
        }
        Ok(())
    }
}

/// A policy pack: the policies plus group membership. This is the TOML file format.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct PolicySet {
    /// Platform groups, used by platform policies.
    #[serde(default)]
    pub groups: BTreeMap<String, Vec<String>>,
    /// Per-tenant groups, used by that tenant's policies.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub tenant_groups: BTreeMap<String, BTreeMap<String, Vec<String>>>,
    #[serde(default, rename = "policy")]
    pub policies: Vec<Policy>,
}

impl PolicySet {
    pub fn from_toml(text: &str) -> Result<Self, PolicyError> {
        let set: Self = toml::from_str(text).map_err(|err| PolicyError::Toml(err.to_string()))?;
        set.validate()?;
        Ok(set)
    }

    pub fn to_toml(&self) -> Result<String, PolicyError> {
        toml::to_string(self).map_err(|err| PolicyError::Toml(err.to_string()))
    }

    pub fn validate(&self) -> Result<(), PolicyError> {
        let mut seen = std::collections::BTreeSet::new();
        for policy in &self.policies {
            policy.validate()?;
            if !seen.insert((&policy.tenant_id, &policy.id)) {
                return Err(PolicyError::Invalid(format!(
                    "duplicate policy id {}",
                    policy.id
                )));
            }
        }
        Ok(())
    }

    /// Membership in the owner's namespace: platform groups for platform policies,
    /// the tenant's own groups for tenant policies.
    pub fn in_group(&self, owner: Option<&str>, group: &str, address: &str) -> bool {
        let groups = match owner {
            None => Some(&self.groups),
            Some(tenant) => self.tenant_groups.get(tenant),
        };
        let address = canonical_address(address);
        groups
            .and_then(|groups| groups.get(group))
            .is_some_and(|members| members.iter().any(|m| canonical_address(m) == address))
    }
}

/// Lower case, no `+tag` in the local part, no trailing dot on the domain.
pub fn canonical_address(address: &str) -> String {
    let address = address.trim().to_ascii_lowercase();
    match address.rsplit_once('@') {
        Some((local, domain)) => {
            let local = local.split_once('+').map_or(local, |(base, _)| base);
            format!("{local}@{}", domain.trim_end_matches('.'))
        }
        None => address,
    }
}

pub fn canonical_domain(domain: &str) -> String {
    domain.trim().trim_end_matches('.').to_ascii_lowercase()
}
