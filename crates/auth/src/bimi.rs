//! BIMI brand logos for the quarantine UI. `mail-auth` has no BIMI support,
//! so this reads the `default._bimi.<domain>` TXT record itself. A logo is
//! only offered for mail that passed DMARC for the DMARC author domain,
//! under a published record at enforcement: `p` and `sp` quarantine or
//! reject, and `pct` 100 when present.
use crate::{dmarc_report::valid_host, AuthChecker};
use async_trait::async_trait;
use currawong_core::AuthResults;
use mail_auth::hickory_resolver::proto::rr::RData;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

const MAX_URL: usize = 2048;
const MAX_WALK: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bimi {
    pub domain: String,
    /// HTTPS URL of the SVG logo.
    pub logo: String,
    /// HTTPS URL of the Verified Mark Certificate, when published.
    pub authority: Option<String>,
    pub vmc: VmcStatus,
    /// Whether the UI may present the logo as a verified brand indicator.
    /// Always false until VMC certificates are checked.
    pub displayable: bool,
}

/// What the UI may say about the brand's Verified Mark Certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VmcStatus {
    /// No `a=` tag. The logo is self-asserted.
    Absent,
    /// An `a=` tag is published. The certificate has not been fetched or
    /// checked, so the logo must not be shown as verified.
    Unverified,
}

#[async_trait]
pub trait TxtLookup: Send + Sync {
    async fn txt(&self, name: &str) -> Result<Vec<String>, String>;
}

/// Test lookups: lowercase name without the trailing dot, to TXT strings.
#[async_trait]
impl TxtLookup for HashMap<String, Vec<String>> {
    async fn txt(&self, name: &str) -> Result<Vec<String>, String> {
        let key = name.trim_end_matches('.').to_ascii_lowercase();
        Ok(self.get(&key).cloned().unwrap_or_default())
    }
}

#[async_trait]
impl TxtLookup for AuthChecker {
    async fn txt(&self, name: &str) -> Result<Vec<String>, String> {
        let fqdn = format!("{}.", name.trim_end_matches('.'));
        let lookup = match self.resolver.resolver().txt_lookup(fqdn).await {
            Ok(lookup) => lookup,
            Err(err) if err.is_no_records_found() => return Ok(Vec::new()),
            Err(err) => return Err(err.to_string()),
        };
        Ok(lookup
            .answers()
            .iter()
            .filter_map(|record| match &record.data {
                RData::TXT(txt) => Some(
                    txt.txt_data
                        .iter()
                        .map(|part| String::from_utf8_lossy(part))
                        .collect::<String>(),
                ),
                _ => None,
            })
            .collect())
    }
}

/// `l=` and `a=` from a `v=BIMI1` record. `None` when the record is invalid
/// or declines to publish a logo (`l=` empty). An invalid `a=` is dropped.
pub fn parse_record(txt: &str) -> Option<(String, Option<String>)> {
    let tags = tags(txt)?;
    if !tags
        .first()
        .is_some_and(|(name, value)| name == "v" && value == "BIMI1")
    {
        return None;
    }
    let value = |key: &str| {
        tags.iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.clone())
    };
    let logo = value("l").filter(|url| safe_url(url))?;
    Some((logo, value("a").filter(|url| safe_url(url))))
}

fn tags(txt: &str) -> Option<Vec<(String, String)>> {
    let mut out = Vec::new();
    for tag in txt.split(';').map(str::trim).filter(|tag| !tag.is_empty()) {
        let (name, value) = tag.split_once('=')?;
        out.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
    }
    Some(out)
}

/// An HTTPS URL a browser can fetch without surprises: printable ASCII,
/// bounded length, no userinfo, and a DNS host name rather than an IP.
pub fn safe_url(url: &str) -> bool {
    if url.is_empty()
        || url.len() > MAX_URL
        || !url
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && !b"\"'<>\\`".contains(&byte))
    {
        return false;
    }
    let Ok(parsed) = url::Url::parse(url) else {
        return false;
    };
    parsed.scheme() == "https"
        && parsed.username().is_empty()
        && parsed.password().is_none()
        && matches!(parsed.host(), Some(url::Host::Domain(host)) if valid_host(host))
}

/// The DMARC author domain, from the structured result. Header text is never
/// reparsed: a MAIL FROM such as `x@dmarc=pass,header.from=victim.test`
/// appears in it before the DMARC part.
pub fn dmarc_domain(auth: &AuthResults) -> Option<String> {
    let domain = auth.dmarc_domain.trim_end_matches('.').to_ascii_lowercase();
    valid_host(&domain).then_some(domain)
}

/// The published DMARC record allows BIMI: found within the tree walk,
/// `p` and `sp` at enforcement, and `pct` absent or 100.
async fn record_at_enforcement(txt: &dyn TxtLookup, domain: &str) -> bool {
    let mut name = domain;
    for _ in 0..MAX_WALK {
        let records = txt.txt(&format!("_dmarc.{name}")).await.unwrap_or_default();
        if let Some(tags) = records
            .iter()
            .filter_map(|record| tags(record))
            .find(|tags| {
                tags.first().is_some_and(|(name, value)| {
                    name == "v" && value.eq_ignore_ascii_case("DMARC1")
                })
            })
        {
            let value = |key: &str| {
                tags.iter()
                    .find(|(name, _)| name == key)
                    .map(|(_, value)| value.to_ascii_lowercase())
            };
            let enforced = |policy: &str| policy == "quarantine" || policy == "reject";
            return value("p").as_deref().is_some_and(enforced)
                && value("sp").as_deref().is_none_or(enforced)
                && value("pct").as_deref().is_none_or(|pct| pct == "100");
        }
        match name.split_once('.') {
            Some((_, parent)) if parent.contains('.') => name = parent,
            _ => return false,
        }
    }
    false
}

/// BIMI for a message whose DMARC result is already known.
pub async fn lookup(txt: &dyn TxtLookup, auth: &AuthResults) -> Option<Bimi> {
    fetch(txt, &eligible(auth)?).await
}

/// The domain to look BIMI up for, when this message passed DMARC at
/// enforcement. Needs no DNS.
pub fn eligible(auth: &AuthResults) -> Option<String> {
    let enforced = matches!(auth.dmarc_policy.as_str(), "quarantine" | "reject");
    if auth.dmarc.result != "pass" || !enforced {
        return None;
    }
    dmarc_domain(auth)
}

/// The DNS part of BIMI for one domain. The answer depends only on the
/// domain, so callers may cache it.
pub async fn fetch(txt: &dyn TxtLookup, domain: &str) -> Option<Bimi> {
    let domain = domain.to_string();
    if !record_at_enforcement(txt, &domain).await {
        return None;
    }
    let records = match txt.txt(&format!("default._bimi.{domain}")).await {
        Ok(records) => records,
        Err(err) => {
            tracing::debug!(%domain, %err, "BIMI lookup failed");
            return None;
        }
    };
    // Exactly one v=BIMI1 record, otherwise no BIMI.
    let mut candidates = records.iter().filter(|record| {
        record
            .trim_start()
            .get(..2)
            .is_some_and(|tag| tag.eq_ignore_ascii_case("v="))
    });
    let record = candidates.next()?;
    if candidates.next().is_some() {
        return None;
    }
    let (logo, authority) = parse_record(record)?;
    let vmc = if authority.is_some() {
        VmcStatus::Unverified
    } else {
        VmcStatus::Absent
    };
    Some(Bimi {
        domain,
        logo,
        authority,
        vmc,
        displayable: false,
    })
}
