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
        if self.scope.value().is_some_and(|v| v.trim().is_empty()) {
            return bad("scope value is empty".into());
        }
        for condition in &self.conditions {
            if let Condition::Auth { method, .. } = condition {
                if !["spf", "dkim", "dmarc", "arc", "dmarc_policy"].contains(&method.as_str()) {
                    return bad(format!("unknown auth method {method}"));
                }
            }
        }
        for action in &self.actions {
            match action {
                Action::AddHeader { name, value } => {
                    let name_ok =
                        !name.is_empty() && name.bytes().all(|b| b.is_ascii_graphic() && b != b':');
                    if !name_ok || value.contains(['\r', '\n']) {
                        return bad(format!("bad header {name}"));
                    }
                }
                Action::Redirect(addr) | Action::Bcc(addr) => {
                    let ok = addr.contains('@')
                        && !addr.contains(|c: char| c.is_whitespace() || "<>,".contains(c));
                    if !ok {
                        return bad(format!("bad address {addr}"));
                    }
                }
                Action::Reject { code } if !(500..600).contains(code) => {
                    return bad(format!("reject code {code} must be 5xx"));
                }
                Action::Banner(text) if text.is_empty() => return bad("empty banner".into()),
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
    #[serde(default)]
    pub groups: BTreeMap<String, Vec<String>>,
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
            if !seen.insert(&policy.id) {
                return Err(PolicyError::Invalid(format!(
                    "duplicate policy id {}",
                    policy.id
                )));
            }
        }
        Ok(())
    }

    pub fn in_group(&self, group: &str, address: &str) -> bool {
        self.groups
            .get(group)
            .is_some_and(|members| members.iter().any(|m| m.eq_ignore_ascii_case(address)))
    }
}
