//! BIMI brand logos for the quarantine UI. `mail-auth` has no BIMI support,
//! so this reads the `default._bimi.<domain>` TXT record itself. A logo is
//! only shown for mail that passes DMARC at `p=quarantine` or `p=reject`.
use crate::AuthChecker;
use async_trait::async_trait;
use currawong_core::AuthResults;
use mail_auth::hickory_resolver::proto::rr::RData;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bimi {
    pub domain: String,
    /// HTTPS URL of the SVG logo.
    pub logo: String,
    /// HTTPS URL of the Verified Mark Certificate, when published.
    pub authority: Option<String>,
    pub vmc: VmcStatus,
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
/// or declines to publish a logo (`l=` empty).
pub fn parse_record(txt: &str) -> Option<(String, Option<String>)> {
    let mut tags = txt.split(';').map(str::trim).filter(|tag| !tag.is_empty());
    let version = tags.next()?.split_once('=')?;
    if !version.0.trim().eq_ignore_ascii_case("v") || version.1.trim() != "BIMI1" {
        return None;
    }
    let mut logo = None;
    let mut authority = None;
    for tag in tags {
        let Some((name, value)) = tag.split_once('=') else {
            continue;
        };
        let value = value.trim();
        match name.trim().to_ascii_lowercase().as_str() {
            "l" => logo = Some(value.to_string()),
            "a" => authority = Some(value.to_string()),
            _ => {}
        }
    }
    let logo = logo.filter(|url| is_https(url))?;
    Some((logo, authority.filter(|url| is_https(url))))
}

fn is_https(url: &str) -> bool {
    url.len() > "https://".len()
        && url
            .get(..8)
            .is_some_and(|scheme| scheme.eq_ignore_ascii_case("https://"))
}

/// Domain of the first RFC 5322 From address.
pub fn author_domain(raw: &[u8]) -> Option<String> {
    let message = mail_parser::MessageParser::default().parse_headers(raw)?;
    let address = message.from()?.first()?.address()?;
    let (_, domain) = address.rsplit_once('@')?;
    Some(domain.trim_end_matches('.').to_ascii_lowercase())
}

/// BIMI for a message whose DMARC result is already known.
pub async fn lookup(txt: &dyn TxtLookup, domain: &str, auth: &AuthResults) -> Option<Bimi> {
    let enforced = matches!(auth.dmarc_policy.as_str(), "quarantine" | "reject");
    if auth.dmarc.result != "pass" || !enforced {
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
        domain: domain.to_string(),
        logo,
        authority,
        vmc,
    })
}
