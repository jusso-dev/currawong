//! SPF, DKIM, DMARC and ARC. DNS answers in tests come from [`TxtCache`].
mod cache;
mod keys;
mod sign;
mod strip;

pub use cache::TxtCache;
pub use keys::{generate, publishable, KeyStore, StoredKey, GATEWAY_TENANT};
pub use sign::{sign, sign_message, sign_outbound};
pub use strip::strip_forged;

use currawong_core::{AuthMethodResult, AuthResults};
use currawong_spool::Envelope;
use mail_auth::{
    common::{headers::HeaderWriter, parse::TxtRecordParser, verify::DomainKey},
    dmarc::{verify::DmarcParameters, Dmarc, Policy},
    hickory_resolver::config::{ResolverConfig, ResolverOpts},
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
    /// Production checker. DNS goes to the host's configured resolvers, the
    /// same ones the rest of the daemon uses.
    pub fn new(authserv_id: impl Into<String>) -> Result<Self, String> {
        let resolver = MessageAuthenticator::new_system_conf().map_err(|err| err.to_string())?;
        Ok(Self::with_parts(authserv_id, resolver, TxtCache::new()))
    }

    /// No name servers and a cache whose misses are errors, so nothing
    /// leaves the process. Use this in unit tests.
    pub fn offline(authserv_id: impl Into<String>) -> Result<Self, String> {
        let resolver = MessageAuthenticator::new(
            ResolverConfig::from_name_servers(Vec::new()),
            ResolverOpts::default(),
        )
        .map_err(|err| err.to_string())?;
        Ok(Self::with_parts(authserv_id, resolver, TxtCache::offline()))
    }

    fn with_parts(
        authserv_id: impl Into<String>,
        resolver: MessageAuthenticator,
        cache: TxtCache,
    ) -> Self {
        Self {
            authserv_id: authserv_id.into(),
            resolver,
            cache,
        }
    }

    pub fn authserv_id(&self) -> &str {
        &self.authserv_id
    }

    pub fn cache(&self) -> &TxtCache {
        &self.cache
    }

    pub async fn check(&self, raw: &[u8], env: &Envelope) -> AuthResults {
        self.check_and_seal(raw, env, None).await
    }

    /// Verify, and when `sealer` is given append an ARC set carrying these
    /// results to `header`. The seal covers the stripped message, which is
    /// what the spool holds (forged headers are removed at DATA).
    pub async fn check_and_seal(
        &self,
        raw: &[u8],
        env: &Envelope,
        sealer: Option<&StoredKey>,
    ) -> AuthResults {
        let stripped = strip_forged(raw, &self.authserv_id);
        let Some(message) = AuthenticatedMessage::parse(&stripped) else {
            return empty(&self.authserv_id);
        };
        let dkim_params = Parameters::new(&message).with_txt_cache(&self.cache);
        let dkim = self.resolver.verify_dkim(dkim_params).await;
        let helo = if env.helo.is_empty() {
            "localhost"
        } else {
            env.helo.as_str()
        };
        // RFC 7208 section 2.4: a null reverse-path is checked as postmaster@HELO.
        let null_sender = format!("postmaster@{helo}");
        let sender = if env.mail_from.is_empty() {
            null_sender.as_str()
        } else {
            env.mail_from.as_str()
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
        let mut header = built.to_header();
        if let Some(key) = sealer {
            match sign::seal_arc_set(&message, &built, &arc, key) {
                Ok(set) => header.push_str(&set),
                Err(err) => tracing::warn!(%err, "ARC seal skipped"),
            }
        }
        AuthResults {
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
            // From the evaluated DMARC record, never from header text: our
            // header echoes the attacker-controlled MAIL FROM.
            dmarc_policy: policy_label(dmarc.policy()).into(),
            header,
        }
    }
}

fn empty(authserv_id: &str) -> AuthResults {
    AuthResults {
        spf: AuthMethodResult::none(),
        dkim: Vec::new(),
        dmarc: AuthMethodResult::none(),
        arc: AuthMethodResult::none(),
        dmarc_policy: String::new(),
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

fn policy_label(policy: Policy) -> &'static str {
    match policy {
        Policy::None => "none",
        Policy::Quarantine => "quarantine",
        Policy::Reject => "reject",
        Policy::Unspecified => "",
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
