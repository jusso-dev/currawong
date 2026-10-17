//! Secret values that must never appear in logs.
use serde::{Deserialize, Serialize};

/// A value whose `Debug` output is always `***`.
///
/// Use [`Secret::expose`] at the single call site that needs the raw value.
/// Do not log that call site.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct Secret<T>(T);

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
}
