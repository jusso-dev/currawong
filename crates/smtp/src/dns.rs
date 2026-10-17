//! DNS lookups used by routing and DNSBLs. Tests supply a map; production uses hickory.
use async_trait::async_trait;
use hickory_resolver::{
    lookup::Lookup,
    net::{DnsError, NetError},
    proto::{
        dnssec::Proof,
        op::ResponseCode,
        rr::{RData, RecordType},
    },
    TokioResolver,
};
use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    sync::Arc,
};

/// Why a delivery lookup failed. Only `NxDomain` is permanent.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LookupError {
    #[error("domain does not exist")]
    NxDomain,
    /// DNSSEC validation failed. Never treated as "no records".
    #[error("DNSSEC validation failed")]
    Bogus,
    #[error("DNS lookup failed: {0}")]
    Temp(String),
}

/// Records from a delivery lookup. An empty list means the name exists with
/// no records of that type (NODATA). `secure` is true only when a validating
/// resolver proved the answer (or its absence) with DNSSEC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer<T> {
    pub records: T,
    pub secure: bool,
}

impl<T> Answer<T> {
    pub fn insecure(records: T) -> Self {
        Self {
            records,
            secure: false,
        }
    }
}

/// One TLSA record (RFC 6698).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tlsa {
    pub usage: u8,
    pub selector: u8,
    pub matching: u8,
    pub data: Vec<u8>,
}

impl std::fmt::Display for Tlsa {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {} {} {}",
            self.usage,
            self.selector,
            self.matching,
            hex::encode(&self.data)
        )
    }
}

#[async_trait]
pub trait DnsLookup: Send + Sync {
    async fn lookup_ips(&self, name: &str) -> Result<Vec<IpAddr>, String>;
    async fn lookup_mx(&self, name: &str) -> Result<Vec<(u16, String)>, String>;

    /// MX lookup for delivery: NODATA is an empty answer, NXDOMAIN is distinct.
    async fn resolve_mx(&self, name: &str) -> Result<Answer<Vec<(u16, String)>>, LookupError> {
        self.lookup_mx(name)
            .await
            .map(Answer::insecure)
            .map_err(LookupError::Temp)
    }

    /// Address lookup for delivery, with the same NODATA and NXDOMAIN split.
    async fn resolve_ips(&self, name: &str) -> Result<Answer<Vec<IpAddr>>, LookupError> {
        self.lookup_ips(name)
            .await
            .map(Answer::insecure)
            .map_err(LookupError::Temp)
    }

    /// TLSA lookup for DANE. Without a validating resolver there are none.
    async fn resolve_tlsa(&self, _name: &str) -> Result<Answer<Vec<Tlsa>>, LookupError> {
        Ok(Answer::insecure(Vec::new()))
    }

    /// TXT strings, each record's character-strings joined.
    async fn lookup_txt(&self, _name: &str) -> Result<Vec<String>, LookupError> {
        Ok(Vec::new())
    }
}

#[derive(Default)]
pub struct MapDns {
    pub ips: HashMap<String, Vec<IpAddr>>,
    pub mx: HashMap<String, Vec<(u16, String)>>,
    pub tlsa: HashMap<String, Vec<Tlsa>>,
    pub txt: HashMap<String, Vec<String>>,
    /// Names that answer NXDOMAIN.
    pub nxdomain: HashSet<String>,
    /// Names whose answers count as DNSSEC-validated.
    pub secure: HashSet<String>,
    /// Names whose answers fail DNSSEC validation.
    pub bogus: HashSet<String>,
}

impl MapDns {
    pub fn new() -> Self {
        Self::default()
    }

    fn answer<T: Clone + Default>(
        &self,
        map: &HashMap<String, T>,
        name: &str,
    ) -> Result<Answer<T>, LookupError> {
        let name = normalise(name);
        if self.bogus.contains(&name) {
            return Err(LookupError::Bogus);
        }
        if self.nxdomain.contains(&name) {
            return Err(LookupError::NxDomain);
        }
        Ok(Answer {
            records: map.get(&name).cloned().unwrap_or_default(),
            secure: self.secure.contains(&name),
        })
    }
}

#[async_trait]
impl DnsLookup for MapDns {
    async fn lookup_ips(&self, name: &str) -> Result<Vec<IpAddr>, String> {
        Ok(self.ips.get(&normalise(name)).cloned().unwrap_or_default())
    }

    async fn lookup_mx(&self, name: &str) -> Result<Vec<(u16, String)>, String> {
        Ok(self.mx.get(&normalise(name)).cloned().unwrap_or_default())
    }

    async fn resolve_mx(&self, name: &str) -> Result<Answer<Vec<(u16, String)>>, LookupError> {
        self.answer(&self.mx, name)
    }

    async fn resolve_ips(&self, name: &str) -> Result<Answer<Vec<IpAddr>>, LookupError> {
        self.answer(&self.ips, name)
    }

    async fn resolve_tlsa(&self, name: &str) -> Result<Answer<Vec<Tlsa>>, LookupError> {
        self.answer(&self.tlsa, name)
    }

    async fn lookup_txt(&self, name: &str) -> Result<Vec<String>, LookupError> {
        match self.answer(&self.txt, name) {
            Ok(answer) => Ok(answer.records),
            Err(LookupError::NxDomain) => Ok(Vec::new()),
            Err(err) => Err(err),
        }
    }
}

#[async_trait]
impl DnsLookup for Arc<MapDns> {
    async fn lookup_ips(&self, name: &str) -> Result<Vec<IpAddr>, String> {
        self.as_ref().lookup_ips(name).await
    }

    async fn lookup_mx(&self, name: &str) -> Result<Vec<(u16, String)>, String> {
        self.as_ref().lookup_mx(name).await
    }

    async fn resolve_mx(&self, name: &str) -> Result<Answer<Vec<(u16, String)>>, LookupError> {
        self.as_ref().resolve_mx(name).await
    }

    async fn resolve_ips(&self, name: &str) -> Result<Answer<Vec<IpAddr>>, LookupError> {
        self.as_ref().resolve_ips(name).await
    }

    async fn resolve_tlsa(&self, name: &str) -> Result<Answer<Vec<Tlsa>>, LookupError> {
        self.as_ref().resolve_tlsa(name).await
    }

    async fn lookup_txt(&self, name: &str) -> Result<Vec<String>, LookupError> {
        self.as_ref().lookup_txt(name).await
    }
}

pub struct HickoryDns {
    resolver: TokioResolver,
    /// Validates DNSSEC itself from the root trust anchor. Used for delivery
    /// lookups when DANE is on; the system resolver must pass RRSIGs through.
    validating: Option<TokioResolver>,
}

impl HickoryDns {
    pub fn system() -> Result<Self, String> {
        Ok(Self {
            resolver: build(false)?,
            validating: None,
        })
    }

    /// System resolver plus a DNSSEC-validating one for delivery.
    pub fn validating() -> Result<Self, String> {
        Ok(Self {
            resolver: build(false)?,
            validating: Some(build(true)?),
        })
    }

    fn delivery(&self) -> &TokioResolver {
        self.validating.as_ref().unwrap_or(&self.resolver)
    }
}

fn build(validate: bool) -> Result<TokioResolver, String> {
    let mut builder =
        TokioResolver::builder_tokio().map_err(|err| format!("system DNS resolver: {err}"))?;
    builder.options_mut().validate = validate;
    builder
        .build()
        .map_err(|err| format!("system DNS resolver: {err}"))
}

#[async_trait]
impl DnsLookup for HickoryDns {
    async fn lookup_ips(&self, name: &str) -> Result<Vec<IpAddr>, String> {
        let lookup = self
            .resolver
            .lookup_ip(name)
            .await
            .map_err(|err| err.to_string())?;
        Ok(lookup.iter().collect())
    }

    async fn lookup_mx(&self, name: &str) -> Result<Vec<(u16, String)>, String> {
        match self.resolve_mx(name).await {
            Ok(answer) => Ok(answer.records),
            Err(LookupError::NxDomain) => Ok(Vec::new()),
            Err(err) => Err(err.to_string()),
        }
    }

    async fn resolve_mx(&self, name: &str) -> Result<Answer<Vec<(u16, String)>>, LookupError> {
        let found = present(self.delivery().mx_lookup(name).await)?;
        Ok(Answer {
            records: mx_records(found.lookup.as_ref()),
            secure: found.secure,
        })
    }

    async fn resolve_ips(&self, name: &str) -> Result<Answer<Vec<IpAddr>>, LookupError> {
        match self.delivery().lookup_ip(name).await {
            Ok(lookup) => Ok(Answer {
                records: lookup.iter().collect(),
                secure: all_secure(lookup.as_lookup()),
            }),
            Err(err) => {
                let found = present(Err(err))?;
                Ok(Answer {
                    records: Vec::new(),
                    secure: found.secure,
                })
            }
        }
    }

    async fn resolve_tlsa(&self, name: &str) -> Result<Answer<Vec<Tlsa>>, LookupError> {
        let Some(resolver) = &self.validating else {
            return Ok(Answer::insecure(Vec::new()));
        };
        let found = match present(resolver.lookup(name, RecordType::TLSA).await) {
            // A proven-absent name has no TLSA records either.
            Err(LookupError::NxDomain) => return Ok(Answer::insecure(Vec::new())),
            other => other?,
        };
        let records = found
            .lookup
            .iter()
            .flat_map(|lookup| lookup.answers())
            .filter_map(|record| match &record.data {
                RData::TLSA(tlsa) => Some(Tlsa {
                    usage: tlsa.cert_usage.into(),
                    selector: tlsa.selector.into(),
                    matching: tlsa.matching.into(),
                    data: tlsa.cert_data.clone(),
                }),
                _ => None,
            })
            .collect();
        Ok(Answer {
            records,
            secure: found.secure,
        })
    }

    async fn lookup_txt(&self, name: &str) -> Result<Vec<String>, LookupError> {
        let found = match present(self.resolver.txt_lookup(name).await) {
            Err(LookupError::NxDomain) => return Ok(Vec::new()),
            other => other?,
        };
        Ok(found
            .lookup
            .iter()
            .flat_map(|lookup| lookup.answers())
            .filter_map(|record| match &record.data {
                RData::TXT(txt) => Some(
                    txt.txt_data
                        .iter()
                        .map(|part| String::from_utf8_lossy(part).into_owned())
                        .collect::<String>(),
                ),
                _ => None,
            })
            .collect())
    }
}

struct Found {
    lookup: Option<Lookup>,
    secure: bool,
}

/// NODATA becomes an empty `Found`; NXDOMAIN, bogus answers and failures
/// become errors.
fn present(result: Result<Lookup, NetError>) -> Result<Found, LookupError> {
    match result {
        Ok(lookup) => Ok(Found {
            secure: all_secure(&lookup),
            lookup: Some(lookup),
        }),
        Err(err) if err.is_nx_domain() => Err(LookupError::NxDomain),
        Err(err) if err.is_no_records_found() => Ok(Found {
            lookup: None,
            secure: false,
        }),
        Err(NetError::Dns(DnsError::Nsec {
            response, proof, ..
        })) => {
            if proof == Proof::Bogus {
                Err(LookupError::Bogus)
            } else if response.response_code == ResponseCode::NXDomain {
                Err(LookupError::NxDomain)
            } else {
                Ok(Found {
                    lookup: None,
                    secure: proof == Proof::Secure,
                })
            }
        }
        Err(NetError::Dns(DnsError::DnssecBogus)) => Err(LookupError::Bogus),
        Err(NetError::Dns(DnsError::ResponseCode(code))) => {
            Err(LookupError::Temp(format!("DNS response {code}")))
        }
        Err(err) => Err(LookupError::Temp(err.to_string())),
    }
}

fn all_secure(lookup: &Lookup) -> bool {
    !lookup.answers().is_empty()
        && lookup
            .answers()
            .iter()
            .all(|record| record.proof == Proof::Secure)
}

fn mx_records(lookup: Option<&Lookup>) -> Vec<(u16, String)> {
    let mut records: Vec<(u16, String)> = lookup
        .map(|lookup| lookup.answers())
        .unwrap_or_default()
        .iter()
        .filter_map(|record| match &record.data {
            RData::MX(mx) => Some((mx.preference, mx.exchange.to_string())),
            _ => None,
        })
        .collect();
    records.sort_by_key(|item| item.0);
    records
}

pub fn normalise(name: &str) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_resolver::{net::NoRecords, proto::op::Query};

    fn no_records(code: ResponseCode) -> NetError {
        NetError::Dns(DnsError::NoRecordsFound(NoRecords::new(
            Query::default(),
            code,
        )))
    }

    #[test]
    fn nodata_is_an_empty_answer() {
        let found = present(Err(no_records(ResponseCode::NoError))).unwrap();
        assert!(mx_records(found.lookup.as_ref()).is_empty());
        assert!(!found.secure);
    }

    #[test]
    fn nxdomain_is_distinct() {
        assert_eq!(
            present(Err(no_records(ResponseCode::NXDomain))).err(),
            Some(LookupError::NxDomain)
        );
    }

    #[test]
    fn servfail_is_temporary_and_bogus_is_bogus() {
        let err = NetError::Dns(DnsError::ResponseCode(ResponseCode::ServFail));
        assert!(matches!(present(Err(err)), Err(LookupError::Temp(_))));
        let err = NetError::Dns(DnsError::DnssecBogus);
        assert!(matches!(present(Err(err)), Err(LookupError::Bogus)));
    }
}
