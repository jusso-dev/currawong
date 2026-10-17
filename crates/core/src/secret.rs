//! Secret values that must never appear in logs.
use serde::{Deserialize, Serialize, Serializer};

/// A value whose `Debug` output and serialised form are always `***`.
///
/// Use [`Secret::expose`] at the single call site that needs the raw value.
/// Do not log that call site.
#[derive(Clone, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct Secret<T>(T);

impl<T> Serialize for Secret<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str("***")
    }
}

impl<T> Secret<T> {
    pub fn new(value: T) -> Self {
        Self(value)
    }

    pub fn expose(&self) -> &T {
        &self.0
    }
}

impl<T> std::fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("***")
    }
}

#[cfg(test)]
mod tests {
    use super::Secret;

    #[test]
    fn secret_debug_redacts() {
        let secret = Secret::new(String::from("super-secret-value"));
        let rendered = format!("{secret:?}");
        assert_eq!(rendered, "***");
        assert!(!rendered.contains("super"));
        assert_eq!(secret.expose(), "super-secret-value");
    }

    #[test]
    fn secret_serialises_redacted_and_still_deserialises() {
        let secret = Secret::new(String::from("super-secret-value"));
        assert_eq!(serde_json::to_string(&secret).unwrap(), "\"***\"");
        let parsed: Secret<String> = serde_json::from_str("\"from-config\"").unwrap();
        assert_eq!(parsed.expose(), "from-config");
    }

    #[test]
    fn serialised_config_does_not_leak_a_dqs_key() {
        let mut cfg = crate::Config::default();
        cfg.checks.dnsbl.push(crate::config::DnsblZone {
            zone: "zen.dq.spamhaus.net".into(),
            dqs_key: Some(Secret::new("super-secret-value".into())),
            listings: Vec::new(),
        });
        let text = serde_json::to_string(&cfg).unwrap();
        assert!(!text.contains("super-secret-value"), "{text}");
    }
}
