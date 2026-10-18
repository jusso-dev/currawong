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
pub use keys::{generate, now_secs, publishable, KeyStore, StoredKey, GATEWAY_TENANT};
pub use sign::{sign, sign_message, sign_outbound};
pub use strip::strip_forged;

use currawong_core::{AuthMethodResult, AuthResults};
use currawong_spool::Envelope;
use mail_auth::{
    common::{headers::HeaderWriter, parse::TxtRecordParser, verify::DomainKey},
    dmarc::{verify::DmarcParameters, Dmarc, Policy},
    hickory_resolver::config::{ConnectionConfig, NameServerConfig, ResolverConfig, ResolverOpts},
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

    /// Checker that sends every query to one name server over UDP.
    pub fn with_name_server(
        authserv_id: impl Into<String>,
        server: std::net::SocketAddr,
    ) -> Result<Self, String> {
        let mut connection = ConnectionConfig::udp();
        connection.port = server.port();
        let name_server = NameServerConfig::new(server.ip(), true, vec![connection]);
        let mut opts = ResolverOpts::default();
        opts.attempts = 1;
        opts.timeout = std::time::Duration::from_secs(2);
        let resolver =
            MessageAuthenticator::new(ResolverConfig::from_name_servers(vec![name_server]), opts)
                .map_err(|err| err.to_string())?;
        Ok(Self::with_parts(authserv_id, resolver, TxtCache::new()))
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

    /// True when DNS serves a DKIM record at the key's selector whose `p=`
    /// matches the key. Checked before a pending key is activated.
    pub async fn dkim_record_published(&self, key: &StoredKey) -> Result<bool, String> {
        use mail_auth::hickory_resolver::proto::rr::RData;
        let name = format!("{}.", key.dns_name());
        let lookup = self
            .resolver
            .resolver()
            .txt_lookup(name.as_str())
            .await
            .map_err(|err| format!("{name}: {err}"))?;
        let want = public_key_tag(&key.public_txt);
        Ok(lookup.answers().iter().any(|record| match &record.data {
            RData::TXT(txt) => {
                let joined: Vec<u8> = txt
                    .txt_data
                    .iter()
                    .flat_map(|part| part.iter().copied())
                    .collect();
                want.is_some() && public_key_tag(&String::from_utf8_lossy(&joined)) == want
            }
            _ => false,
        }))
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
        self.evaluate_and_seal(raw, env, sealer.map(|key| (key, raw)), false)
            .await
            .results
    }

    /// Verify the message as it arrived (`raw`) and seal the copy a stage
    /// changed (`delivered`). The results and the ARC chain validation are
    /// those of `raw`, so a rewritten body does not turn a DKIM pass into
    /// a fail in our Authentication-Results or ARC-Authentication-Results.
    pub async fn seal_delivered(
        &self,
        raw: &[u8],
        delivered: &[u8],
        env: &Envelope,
        sealer: &StoredKey,
    ) -> AuthResults {
        self.evaluate_and_seal(raw, env, Some((sealer, delivered)), false)
            .await
            .results
    }

    /// Results, plus the aggregate report row when `report` is set and the
    /// author domain publishes DMARC.
    pub async fn evaluate(&self, raw: &[u8], env: &Envelope, report: bool) -> Evaluation {
        self.evaluate_and_seal(raw, env, None, report).await
    }

    /// [`Self::check_and_seal`] and [`Self::evaluate`] in one pass.
    async fn evaluate_and_seal(
        &self,
        raw: &[u8],
        env: &Envelope,
        sealer: Option<(&StoredKey, &[u8])>,
        report: bool,
    ) -> Evaluation {
        let stripped = strip_forged(raw, &self.authserv_id);
        let Some(message) = AuthenticatedMessage::parse(&stripped) else {
            return Evaluation {
                results: empty(&self.authserv_id),
                dmarc_event: None,
            };
        };
        let dkim_params = Parameters::new(&message).with_txt_cache(&self.cache.dkim);
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
        let spf_params = Parameters::new(spf_input).with_txt_cache(&self.cache.spf);
        let spf = self.resolver.verify_spf(spf_params).await;
        let mail_from_domain = sender
            .rsplit_once('@')
            .map(|(_, domain)| domain)
            .unwrap_or(sender);
        let header_from = message.from.first().map(String::as_str).unwrap_or("");
        let dmarc_input = DmarcParameters::new(&message, &dkim, mail_from_domain, &spf);
        let dmarc_params = Parameters::new(dmarc_input).with_txt_cache(&self.cache.dmarc);
        let dmarc = self.resolver.verify_dmarc(dmarc_params).await;
        let arc_params = Parameters::new(&message).with_txt_cache(&self.cache.dkim);
        let arc = self.resolver.verify_arc(arc_params).await;
        let built = AuthenticationResults::new(&self.authserv_id)
            .with_dkim_results(&dkim, header_from)
            .with_spf_mailfrom_result(&spf, env.remote_ip, sender, helo)
            .with_dmarc_result(&dmarc)
            .with_arc_result(&arc, env.remote_ip);
        let mut header = built.to_header();
        if let Some((key, delivered)) = sealer {
            let delivered = strip_forged(delivered, &self.authserv_id);
            match AuthenticatedMessage::parse(&delivered) {
                Some(target) => match sign::seal_arc_set(&target, &built, &arc, key) {
                    Ok(set) => header.push_str(&set),
                    Err(err) => tracing::warn!(%err, "ARC seal skipped"),
                },
                None => tracing::warn!("ARC seal skipped: delivered copy does not parse"),
            }
        }
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
            // From the evaluated DMARC record, never from header text: our
            // header echoes the attacker-controlled MAIL FROM.
            dmarc_policy: policy_label(dmarc.policy()).into(),
            dmarc_domain: dmarc.domain().to_ascii_lowercase(),
            header,
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

/// The `p=` tag of a DKIM record with whitespace removed.
fn public_key_tag(record: &str) -> Option<String> {
    record.split(';').find_map(|tag| {
        let (name, value) = tag.split_once('=')?;
        (name.trim() == "p").then(|| value.chars().filter(|ch| !ch.is_whitespace()).collect())
    })
}

/// Taken from the verifier, never reparsed from header text: a MAIL FROM
/// such as `x@policy.dmarc=reject` lands in the header before the DMARC part.
/// Empty when no record applied.
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

/// Make `name` answer with a temporary DNS failure. For tests.
pub fn seed_txt_error(cache: &TxtCache, name: &str) {
    cache.insert_error(name);
}
