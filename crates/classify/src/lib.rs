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
use message::{address_domain, url_host, MessageView};
use spam::{Bayes, RuleSet, SpamClassifier, SpamError};

#[derive(Debug, thiserror::Error)]
pub enum ClassifyError {
    #[error(transparent)]
    Spam(#[from] SpamError),
    #[error("brand list {0}")]
    Brands(String),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Classification {
    pub spam: SpamReport,
    pub lookalikes: Vec<LookalikeFinding>,
}

pub struct Classifier {
    protected: Vec<String>,
    spam: SpamClassifier,
}

impl Classifier {
    /// Rules and brands must load. A Bayes store that cannot be opened is
    /// logged and skipped, so rules and lookalikes still score.
    pub fn from_config(cfg: &Config) -> Result<Self, ClassifyError> {
        let (rules, brands) = load(&cfg.classify)?;
        let bayes = match Bayes::open(&cfg.classify.bayes_database) {
            Ok(store) => Some(store),
            Err(err) => {
                tracing::warn!(%err, path = %cfg.classify.bayes_database.display(), "bayes store unavailable");
                None
            }
        };
        let mut protected = brands;
        protected.extend(cfg.domains.accept.iter().cloned());
        for tenant in &cfg.relay.tenants {
            protected.extend(tenant.domains.iter().cloned());
        }
        protected.extend(cfg.classify.protected_domains.iter().cloned());
        protected.sort();
        protected.dedup();
        Ok(Self::new(protected, SpamClassifier { bayes, rules }))
    }

    pub fn new(protected: Vec<String>, spam: SpamClassifier) -> Self {
        Self { protected, spam }
    }

    pub fn spam(&self) -> &SpamClassifier {
        &self.spam
    }

    /// Score one message. `urls` are links the parser worker found, added to
    /// the links in the text body.
    pub fn classify(
        &self,
        tenant: &str,
        raw: &[u8],
        envelope_sender: &str,
        urls: &[String],
    ) -> Classification {
        let view = MessageView::parse(raw);
        let mut lookalikes: Vec<LookalikeFinding> = Vec::new();
        let mut check = |source: &str, domain: &str| {
            let domain = domain.to_lowercase();
            if lookalikes
                .iter()
                .any(|found| found.source == source && found.domain == domain)
            {
                return;
            }
            if let Some(hit) = lookalike::score(&domain, &self.protected) {
                lookalikes.push(LookalikeFinding {
                    source: source.into(),
                    domain,
                    target: hit.target,
                    technique: hit.technique,
                    score: hit.score,
                });
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
        for link in view.urls.iter().chain(urls) {
            if let Some(host) = url_host(link) {
                check("url", &host);
            }
        }
        Classification {
            spam: self.spam.score(tenant, &view, urls),
            lookalikes,
        }
    }
}

/// Load the configured rules and brand list, for `--check-config`.
pub fn check_config(cfg: &ClassifyConfig) -> Result<(), ClassifyError> {
    load(cfg).map(|_| ())
}

fn load(cfg: &ClassifyConfig) -> Result<(RuleSet, Vec<String>), ClassifyError> {
    let rules = match &cfg.spam_rules_dir {
        Some(dir) => RuleSet::load_dir(dir)?,
        None => RuleSet::builtin()?,
    };
    let brands = match &cfg.brands_file {
        Some(path) => std::fs::read_to_string(path)
            .map(|text| lookalike::parse_brands(&text))
            .map_err(|err| ClassifyError::Brands(format!("{}: {err}", path.display())))?,
        None => lookalike::parse_brands(lookalike::BRANDS_AU),
    };
    Ok((rules, brands))
}
