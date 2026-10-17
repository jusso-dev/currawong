//! Classify stage: lookalike domains and spam scoring.
//! BEC signals and the optional LLM classifier join this crate later.
//! Results go on the `ScanReport`; the policy engine decides what to do.
pub mod lookalike;
pub mod message;
pub mod spam;

use currawong_core::{
    config::{ClassifyConfig, Config},
    LookalikeFinding, SpamReport,
};
use lookalike::Protected;
use message::{address_domain, url_host, MessageView};
use spam::{Bayes, Feedback, RuleSet, SpamClassifier, SpamError, Trained};

#[derive(Debug, thiserror::Error)]
pub enum ClassifyError {
    #[error(transparent)]
    Spam(#[from] SpamError),
    #[error("brand list {0}")]
    Brands(String),
}

/// Who a message is classified for. `key` partitions the Bayes store and
/// `domains` are the tenant's own domains, protected against lookalikes in
/// that tenant's mail only. Keys are namespaced so a configured tenant id can
/// never collide with a recipient domain that has no tenant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantContext {
    pub key: String,
    pub domains: Vec<String>,
}

impl TenantContext {
    /// A configured tenant and its domains.
    pub fn tenant(id: &str, domains: &[String]) -> Self {
        Self {
            key: format!("tenant:{id}"),
            domains: domains.to_vec(),
        }
    }

    /// An accepted domain that no tenant claims.
    pub fn domain(domain: &str) -> Self {
        let domain = domain.to_ascii_lowercase();
        Self {
            key: format!("domain:{domain}"),
            domains: vec![domain],
        }
    }
}

/// Lookalike findings kept per report, one per source and target.
const MAX_FINDINGS: usize = 32;

#[derive(Debug, Clone, PartialEq)]
pub struct Classification {
    /// `None` when the message was skipped.
    pub spam: Option<SpamReport>,
    pub lookalikes: Vec<LookalikeFinding>,
    /// Report flags for policy: `classify_skipped`, `link_scan_truncated`.
    pub flags: Vec<String>,
    /// Degraded scoring, for the report notes.
    pub notes: Vec<String>,
}

pub struct Classifier {
    /// Brands, `classify.protected_domains` and the allowed domains, shared
    /// by every tenant.
    protected: Protected,
    spam: SpamClassifier,
}

impl Classifier {
    /// Rules and brands must load. A Bayes store that cannot be opened is
    /// logged and skipped, so rules and lookalikes still score, and each
    /// report says so.
    pub fn from_config(cfg: &Config) -> Result<Self, ClassifyError> {
        let loaded = load(&cfg.classify)?;
        let bayes = match Bayes::open(&cfg.classify.bayes_database) {
            Ok(store) => Some(store),
            Err(err) => {
                tracing::warn!(%err, path = %cfg.classify.bayes_database.display(), "bayes store unavailable");
                None
            }
        };
        let mut protected = loaded.brands;
        protected.extend(cfg.classify.protected_domains.iter().cloned());
        let mut allowed = loaded.siblings;
        allowed.extend(cfg.classify.allowed_domains.iter().cloned());
        let rules = loaded.rules;
        Ok(Self::new(&protected, SpamClassifier { bayes, rules }).with_allowed(&allowed))
    }

    pub fn new(protected: &[String], spam: SpamClassifier) -> Self {
        Self {
            protected: Protected::new(protected),
            spam,
        }
    }

    /// Domains never flagged as lookalikes.
    pub fn with_allowed(mut self, allowed: &[String]) -> Self {
        self.protected.allow(allowed);
        self
    }

    pub fn spam(&self) -> &SpamClassifier {
        &self.spam
    }

    /// Train the tenant's Bayes store from a quarantine release or a user report.
    pub fn learn(
        &self,
        tenant: &TenantContext,
        message_id: &str,
        raw: &[u8],
        feedback: Feedback,
    ) -> Result<Trained, SpamError> {
        self.spam.learn(&tenant.key, message_id, raw, feedback)
    }

    /// Score one message for one tenant. `urls` are links the parser worker
    /// found, added to the links in the text and HTML bodies.
    pub fn classify(
        &self,
        tenant: &TenantContext,
        raw: &[u8],
        envelope_sender: &str,
        urls: &[String],
    ) -> Classification {
        let view = MessageView::parse(raw);
        let mut notes = Vec::new();
        let mut flags = Vec::new();
        if view.skipped {
            return Classification {
                spam: None,
                lookalikes: Vec::new(),
                flags: vec!["classify_skipped".into()],
                notes: vec![format!(
                    "classify skipped: more than {} embedded messages or {} multiparts",
                    message::MAX_EMBEDDED_MESSAGES,
                    message::MAX_MULTIPARTS
                )],
            };
        }
        if view.failed {
            notes.push("classify could not parse the message headers".to_string());
        }
        if view.truncated {
            notes.push(format!(
                "classify read only the first {} bytes",
                message::MAX_RAW_BYTES
            ));
        }
        if view.links_truncated {
            flags.push("link_scan_truncated".to_string());
            notes.push("link scan truncated: some links were not checked".to_string());
        }
        if self.spam.bayes.is_none() {
            notes.push("bayes store unavailable: spam score is rules only".to_string());
        }
        let mut protected = self.protected.clone();
        protected.extend(&tenant.domains);
        let mut lookalikes: Vec<LookalikeFinding> = Vec::new();
        let mut capped = false;
        let mut seen = std::collections::HashSet::new();
        let mut check = |source: &str, domain: &str| {
            let domain = domain.to_lowercase();
            if lookalikes.len() >= MAX_FINDINGS
                || !seen.insert((source.to_string(), domain.clone()))
            {
                return;
            }
            if let Some(hit) = protected.score(&domain) {
                match lookalikes
                    .iter_mut()
                    .find(|found| found.source == source && found.target == hit.target)
                {
                    // One finding per source and target: keep the strongest.
                    Some(found) if found.score >= hit.score => {}
                    Some(found) => {
                        found.domain = domain;
                        found.technique = hit.technique;
                        found.score = hit.score;
                    }
                    None => {
                        lookalikes.push(LookalikeFinding {
                            source: source.into(),
                            domain,
                            target: hit.target,
                            technique: hit.technique,
                            score: hit.score,
                        });
                        capped |= lookalikes.len() >= MAX_FINDINGS;
                    }
                }
            }
        };
        let senders = view
            .from
            .iter()
            .map(|address| ("from", address.as_str()))
            .chain(
                view.reply_to
                    .iter()
                    .map(|address| ("reply-to", address.as_str())),
            )
            .chain(std::iter::once(("envelope", envelope_sender)));
        for (source, address) in senders {
            if let Some(domain) = address_domain(address) {
                check(source, domain);
            }
        }
        let worker_hosts = urls.iter().filter_map(|link| url_host(link));
        for host in view.hosts.iter().cloned().chain(worker_hosts) {
            check("url", &host);
        }
        if capped {
            notes.push(format!("lookalike findings capped at {MAX_FINDINGS}"));
        }
        let (spam, note) = self.spam.score_noted(&tenant.key, &view, urls);
        notes.extend(note);
        Classification {
            spam: Some(spam),
            lookalikes,
            flags,
            notes,
        }
    }
}

/// Load the configured rules and brand list, and open the Bayes store when
/// its directory exists, for `--check-config`.
pub fn check_config(cfg: &ClassifyConfig) -> Result<(), ClassifyError> {
    load(cfg)?;
    if cfg.bayes_database.parent().is_some_and(|dir| dir.is_dir()) {
        Bayes::open(&cfg.bayes_database)?;
    }
    Ok(())
}

struct Loaded {
    rules: RuleSet,
    brands: Vec<String>,
    siblings: Vec<String>,
}

fn load(cfg: &ClassifyConfig) -> Result<Loaded, ClassifyError> {
    let rules = match &cfg.spam_rules_dir {
        Some(dir) => RuleSet::load_dir(dir)?,
        None => RuleSet::builtin()?,
    };
    let text = match &cfg.brands_file {
        Some(path) => std::fs::read_to_string(path)
            .map_err(|err| ClassifyError::Brands(format!("{}: {err}", path.display())))?,
        None => lookalike::BRANDS_AU.to_string(),
    };
    Ok(Loaded {
        rules,
        brands: lookalike::parse_brands(&text),
        siblings: lookalike::parse_brand_siblings(&text),
    })
}

#[cfg(test)]
mod tests {
    use super::TenantContext;

    #[test]
    fn tenant_keys_cannot_collide_with_unclaimed_domains() {
        let named = TenantContext::tenant("default", &[]);
        let tricky = TenantContext::tenant("domain:example.test", &[]);
        let unclaimed = TenantContext::domain("Example.TEST");
        assert_ne!(named.key, unclaimed.key);
        assert_ne!(tricky.key, unclaimed.key);
        assert_eq!(unclaimed.domains, vec!["example.test"]);
    }
}
