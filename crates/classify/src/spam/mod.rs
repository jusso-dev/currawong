//! Spam scoring: a per-tenant Bayesian classifier plus weighted rules.
pub mod bayes;
pub mod rules;

pub use bayes::{Bayes, Label, Trained};
pub use currawong_core::{RuleHit, SpamReport};
pub use rules::RuleSet;

use crate::message::MessageView;

/// Points added to the total at a Bayes probability of 1 (and taken away at 0).
pub const BAYES_POINTS: f64 = 5.0;

#[derive(Debug, thiserror::Error)]
pub enum SpamError {
    #[error("spam rules: {0}")]
    Rules(String),
    #[error("bayes store: {0}")]
    Store(String),
}

impl From<rusqlite::Error> for SpamError {
    fn from(err: rusqlite::Error) -> Self {
        Self::Store(err.to_string())
    }
}

/// Training signals. A released message was not spam; user reports go either way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Feedback {
    Released,
    ReportedSpam,
    ReportedHam,
}

impl Feedback {
    pub fn label(self) -> Label {
        match self {
            Self::ReportedSpam => Label::Spam,
            Self::Released | Self::ReportedHam => Label::Ham,
        }
    }
}

pub struct SpamClassifier {
    /// `None` when the store could not be opened. Rules still run.
    pub bayes: Option<Bayes>,
    pub rules: RuleSet,
}

impl SpamClassifier {
    pub fn score(&self, tenant: &str, view: &MessageView, urls: &[String]) -> SpamReport {
        let bayes = match &self.bayes {
            Some(store) => store
                .score(tenant, &bayes::tokens(view, urls))
                .unwrap_or_else(|err| {
                    tracing::warn!(%err, "bayes score failed");
                    0.5
                }),
            None => 0.5,
        };
        let rules_hit = self.rules.evaluate(view, urls);
        let total =
            (bayes - 0.5) * 2.0 * BAYES_POINTS + rules_hit.iter().map(|hit| hit.score).sum::<f64>();
        SpamReport {
            bayes,
            rules_hit,
            total,
        }
    }

    /// Train the tenant's classifier from a quarantine release or a user
    /// report. `message_id` makes repeated feedback idempotent and lets a
    /// later report reverse an earlier one.
    pub fn learn(
        &self,
        tenant: &str,
        message_id: &str,
        raw: &[u8],
        feedback: Feedback,
    ) -> Result<Trained, SpamError> {
        let store = self
            .bayes
            .as_ref()
            .ok_or_else(|| SpamError::Store("bayes store is not open".into()))?;
        let view = MessageView::parse(raw);
        store.train(
            tenant,
            message_id,
            &bayes::tokens(&view, &[]),
            feedback.label(),
        )
    }
}
