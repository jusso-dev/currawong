//! SPF, DKIM, DMARC and ARC. DNS answers in tests come from [`TxtCache`].
pub mod bimi;
mod cache;
pub mod dmarc_report;
mod keys;
mod sign;
mod strip;

pub use bimi::{Bimi, TxtLookup, VmcStatus};
pub use cache::TxtCache;
pub use dmarc_report::{DmarcEvent, DmarcEventStore, OutgoingReport};
pub use keys::{publishable, KeyStore, StoredKey};
pub use sign::{ed25519_key, rsa_key, seal_arc, sign_message};
pub use strip::strip_forged;

use currawong_core::{AuthMethodResult, AuthResults};
use currawong_spool::Envelope;
use mail_auth::{
    common::{headers::HeaderWriter, parse::TxtRecordParser, verify::DomainKey},
    dmarc::{verify::DmarcParameters, Dmarc, Policy},
    spf::{verify::SpfParameters, Spf},
    AuthenticatedMessage, AuthenticationResults, DkimResult, DmarcResult, MessageAuthenticator,
    Parameters, SpfResult, Txt,
};
use std::sync::Arc;

pub struct AuthChecker {
    authserv_id: String,
    resolver: MessageAuthenticator,
    cache: TxtCache,
}

impl AuthChecker {
    pub fn new(authserv_id: impl Into<String>) -> Result<Self, String> {
        Self::with_cache(authserv_id, TxtCache::new())
    }

    /// Resolver cache misses stay inside the process. Use this in unit tests.
    pub fn offline(authserv_id: impl Into<String>) -> Result<Self, String> {
        Self::with_cache(authserv_id, TxtCache::offline())
    }

    fn with_cache(authserv_id: impl Into<String>, cache: TxtCache) -> Result<Self, String> {
        let resolver = MessageAuthenticator::new_cloudflare().map_err(|err| err.to_string())?;
        Ok(Self {
            authserv_id: authserv_id.into(),
            resolver,
            cache,
        })
    }

    pub fn cache(&self) -> &TxtCache {
        &self.cache
    }

    pub async fn check(&self, raw: &[u8], env: &Envelope) -> AuthResults {
        self.evaluate(raw, env, false).await.results
    }

    /// Results, plus the aggregate report row when `report` is set and the
    /// author domain publishes DMARC.
    pub async fn evaluate(&self, raw: &[u8], env: &Envelope, report: bool) -> Evaluation {
        let stripped = strip_forged(raw, &self.authserv_id);
        let Some(message) = AuthenticatedMessage::parse(&stripped) else {
            return Evaluation {
                results: empty(&self.authserv_id),
                dmarc_event: None,
            };
        };
        let dkim_params = Parameters::new(&message).with_txt_cache(&self.cache);
        let dkim = self.resolver.verify_dkim(dkim_params).await;
        let sender = if env.mail_from.is_empty() {
            "postmaster@invalid.test"
        } else {
            env.mail_from.as_str()
        };
        let helo = if env.helo.is_empty() {
            "localhost"
        } else {
            env.helo.as_str()
        };
        let spf_input =
            SpfParameters::verify_mail_from(env.remote_ip, helo, &self.authserv_id, sender);
        let spf_params = Parameters::new(spf_input).with_txt_cache(&self.cache);
        let spf = self.resolver.verify_spf(spf_params).await;
        let mail_from_domain = sender
            .rsplit_once('@')
            .map(|(_, domain)| domain)
            .unwrap_or(sender);
        let header_from = message.from.first().map(String::as_str).unwrap_or("");
        let dmarc_input = DmarcParameters::new(&message, &dkim, mail_from_domain, &spf);
        let dmarc_params = Parameters::new(dmarc_input).with_txt_cache(&self.cache);
        let dmarc = self.resolver.verify_dmarc(dmarc_params).await;
        let arc_params = Parameters::new(&message).with_txt_cache(&self.cache);
        let arc = self.resolver.verify_arc(arc_params).await;
        let built = AuthenticationResults::new(&self.authserv_id)
            .with_dkim_results(&dkim, header_from)
            .with_spf_mailfrom_result(&spf, env.remote_ip, sender, helo)
            .with_dmarc_result(&dmarc)
            .with_arc_result(&arc, env.remote_ip);
        // The domain only: a bare local part must not reach a report.
        let envelope_from = if env.mail_from.is_empty() {
            helo
        } else {
            env.mail_from
                .rsplit_once('@')
                .map(|(_, domain)| domain)
                .unwrap_or("")
        };
        let dmarc_event = if report {
            self.dmarc_event(env, envelope_from, &dkim, &spf, &dmarc)
                .await
        } else {
            None
        };
        let results = AuthResults {
            spf: spf_method(spf.result()),
            dkim: dkim
                .iter()
                .map(|item| AuthMethodResult {
                    result: dkim_label(item.result()).into(),
                    detail: String::new(),
                })
                .collect(),
            dmarc: dmarc_method(dmarc.result()),
            arc: AuthMethodResult {
                result: dkim_label(arc.result()).into(),
                detail: String::new(),
            },
            dmarc_policy: policy_label(dmarc.policy()).into(),
            dmarc_domain: dmarc.domain().to_ascii_lowercase(),
            header: built.to_header(),
        };
        Evaluation {
            results,
            dmarc_event,
        }
    }
}

pub struct Evaluation {
    pub results: AuthResults,
    /// Present when the author domain publishes a DMARC record.
    pub dmarc_event: Option<DmarcEvent>,
}

fn empty(authserv_id: &str) -> AuthResults {
    AuthResults {
        spf: AuthMethodResult::none(),
        dkim: Vec::new(),
        dmarc: AuthMethodResult::none(),
        arc: AuthMethodResult::none(),
        dmarc_policy: String::new(),
        dmarc_domain: String::new(),
        header: format!("Authentication-Results: {authserv_id}; none\r\n"),
    }
}

fn dkim_label(result: &DkimResult) -> &'static str {
    match result {
        DkimResult::Pass => "pass",
        DkimResult::Neutral(_) => "neutral",
        DkimResult::Fail(_) => "fail",
        DkimResult::PermError(_) => "permerror",
        DkimResult::TempError(_) => "temperror",
        DkimResult::None => "none",
    }
}

fn spf_method(result: SpfResult) -> AuthMethodResult {
    let label = match result {
        SpfResult::Pass => "pass",
        SpfResult::Fail => "fail",
        SpfResult::SoftFail => "softfail",
        SpfResult::Neutral => "neutral",
        SpfResult::TempError => "temperror",
        SpfResult::PermError => "permerror",
        SpfResult::None => "none",
    };
    AuthMethodResult {
        result: label.into(),
        detail: String::new(),
    }
}

fn dmarc_method(result: DmarcResult) -> AuthMethodResult {
    let label = match result {
        DmarcResult::Pass => "pass",
        DmarcResult::Fail(_) => "fail",
        DmarcResult::TempError(_) => "temperror",
        DmarcResult::PermError(_) => "permerror",
        DmarcResult::None => "none",
    };
    AuthMethodResult {
        result: label.into(),
        detail: String::new(),
    }
}

/// Taken from the verifier, never reparsed from header text: a MAIL FROM
/// such as `x@policy.dmarc=reject` lands in the header before the DMARC part.
fn policy_label(policy: Policy) -> &'static str {
    match policy {
        Policy::Quarantine => "quarantine",
        Policy::Reject => "reject",
        Policy::None | Policy::Unspecified => "none",
    }
}

pub fn seed_txt(cache: &TxtCache, name: &str, record: &str) -> Result<(), String> {
    let bytes = record.as_bytes();
    let lower = record.to_ascii_lowercase();
    let value = if lower.starts_with("v=dkim1") {
        Txt::DomainKey(Arc::new(
            DomainKey::parse(bytes).map_err(|err| err.to_string())?,
        ))
    } else if lower.starts_with("v=dmarc1") {
        Txt::Dmarc(Arc::new(
            Dmarc::parse(bytes).map_err(|err| err.to_string())?,
        ))
    } else if lower.starts_with("v=spf1") {
        Txt::Spf(Arc::new(Spf::parse(bytes).map_err(|err| err.to_string())?))
    } else {
        return Err(format!("unsupported txt record {record}"));
    };
    cache.insert_record(name, value);
    Ok(())
}

/// Make `name` answer with a temporary DNS failure. For tests.
pub fn seed_txt_error(cache: &TxtCache, name: &str) {
    cache.insert_record(
        name,
        Txt::Error(mail_auth::Error::Dns(mail_auth::DnsError::Resolver(
            "timed out".into(),
        ))),
    );
}
