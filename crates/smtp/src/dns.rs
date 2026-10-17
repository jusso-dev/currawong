//! DNS lookups used by routing and DNSBLs. Tests supply a map; production uses hickory.
use async_trait::async_trait;
use hickory_resolver::{
    config::LookupIpStrategy,
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
    /// Where a CNAME chain ended, when it ended somewhere other than the name
    /// asked for. DANE looks for TLSA records there first (RFC 7672 2.2.2).
    pub canonical: Option<String>,
}

impl<T> Answer<T> {
    pub fn insecure(records: T) -> Self {
        Self {
            records,
            secure: false,
            canonical: None,
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
    /// Address lookups for a key follow the CNAME to its value.
    pub cname: HashMap<String, String>,
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
            canonical: None,
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
        let Some(target) = self.cname.get(&normalise(name)) else {
            return self.answer(&self.ips, name);
        };
        let alias = self.answer(&HashMap::<String, Vec<IpAddr>>::new(), name)?;
        let mut answer = self.answer(&self.ips, target)?;
        answer.secure &= alias.secure;
        answer.canonical = Some(normalise(target));
        Ok(answer)
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
    /// DNSBL checks and policy TXT records.
    resolver: TokioResolver,
    /// Delivery lookups: A and AAAA both, DNSSEC-validated when `validating`.
    delivery: TokioResolver,
    /// The delivery resolver validates DNSSEC itself from the root trust
    /// anchor; the system resolver must pass RRSIGs through.
    validating: bool,
}

impl HickoryDns {
    pub fn system() -> Result<Self, String> {
        Ok(Self {
            resolver: build(false, false)?,
            delivery: build(false, true)?,
            validating: false,
        })
    }

    /// System resolver plus a DNSSEC-validating one for delivery.
    pub fn validating() -> Result<Self, String> {
        Ok(Self {
            resolver: build(false, false)?,
            delivery: build(true, true)?,
            validating: true,
        })
    }
}

fn build(validate: bool, both_families: bool) -> Result<TokioResolver, String> {
    let mut builder =
        TokioResolver::builder_tokio().map_err(|err| format!("system DNS resolver: {err}"))?;
    builder.options_mut().validate = validate;
    if both_families {
        builder.options_mut().ip_strategy = LookupIpStrategy::Ipv4AndIpv6;
    }
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
        let found = present(self.delivery.mx_lookup(name).await, self.validating)?;
        Ok(Answer {
            records: mx_records(found.lookup.as_ref()),
            secure: found.secure,
            canonical: None,
        })
    }

    async fn resolve_ips(&self, name: &str) -> Result<Answer<Vec<IpAddr>>, LookupError> {
        match self.delivery.lookup_ip(name).await {
            Ok(lookup) => {
                let found = present(Ok(lookup.as_lookup().clone()), self.validating)?;
                Ok(Answer {
                    records: lookup.iter().collect(),
                    secure: found.secure,
                    canonical: found.lookup.as_ref().and_then(|l| canonical(l, name)),
                })
            }
            Err(err) => {
                let found = present(Err(err), self.validating)?;
                Ok(Answer {
                    records: Vec::new(),
                    secure: found.secure,
                    canonical: None,
                })
            }
        }
    }

    async fn resolve_tlsa(&self, name: &str) -> Result<Answer<Vec<Tlsa>>, LookupError> {
        if !self.validating {
            return Ok(Answer::insecure(Vec::new()));
        }
        let found = match present(self.delivery.lookup(name, RecordType::TLSA).await, true) {
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
            canonical: None,
        })
    }

    async fn lookup_txt(&self, name: &str) -> Result<Vec<String>, LookupError> {
        let found = match present(self.resolver.txt_lookup(name).await, false) {
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
/// become errors. From a validating resolver, an answer whose proof is
/// indeterminate counts as bogus, never as merely insecure.
fn present(result: Result<Lookup, NetError>, validating: bool) -> Result<Found, LookupError> {
    let doubtful =
        |proof: Proof| validating && matches!(proof, Proof::Bogus | Proof::Indeterminate);
    match result {
        Ok(lookup) if lookup.answers().iter().any(|record| doubtful(record.proof)) => {
            Err(LookupError::Bogus)
        }
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
            if proof == Proof::Bogus || doubtful(proof) {
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

/// The end of the CNAME chain in `lookup`, if it moved away from `name`.
fn canonical(lookup: &Lookup, name: &str) -> Option<String> {
    let target = lookup
        .answers()
        .iter()
        .rev()
        .find_map(|record| match &record.data {
            RData::CNAME(cname) => Some(normalise(&cname.0.to_string())),
            _ => None,
        })?;
    (target != normalise(name)).then_some(target)
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
        let found = present(Err(no_records(ResponseCode::NoError)), true).unwrap();
        assert!(mx_records(found.lookup.as_ref()).is_empty());
        assert!(!found.secure);
    }

    #[test]
    fn nxdomain_is_distinct() {
        assert_eq!(
            present(Err(no_records(ResponseCode::NXDomain)), true).err(),
            Some(LookupError::NxDomain)
        );
    }

    #[test]
    fn servfail_is_temporary_and_bogus_is_bogus() {
        let err = NetError::Dns(DnsError::ResponseCode(ResponseCode::ServFail));
        assert!(matches!(present(Err(err), true), Err(LookupError::Temp(_))));
        let err = NetError::Dns(DnsError::DnssecBogus);
        assert!(matches!(present(Err(err), true), Err(LookupError::Bogus)));
    }

    fn lookup(proof: Proof, cname: bool) -> Lookup {
        use hickory_resolver::proto::rr::{
            rdata::{A, CNAME},
            Name, Record,
        };
        let alias = Name::from_ascii("mx.example.test.").unwrap();
        let target = Name::from_ascii("host.provider.test.").unwrap();
        let mut answers = Vec::new();
        if cname {
            answers.push(Record::from_rdata(
                alias.clone(),
                60,
                RData::CNAME(CNAME(target.clone())),
            ));
        }
        answers.push(Record::from_rdata(
            target,
            60,
            RData::A(A::new(192, 0, 2, 1)),
        ));
        for record in &mut answers {
            record.proof = proof;
        }
        Lookup::new_with_max_ttl(Query::query(alias, RecordType::A), answers)
    }

    #[test]
    fn indeterminate_is_bogus_only_when_validating() {
        let doubtful = lookup(Proof::Indeterminate, false);
        assert!(matches!(
            present(Ok(doubtful.clone()), true),
            Err(LookupError::Bogus)
        ));
        let found = present(Ok(doubtful), false).unwrap();
        assert!(!found.secure);
        assert!(
            present(Ok(lookup(Proof::Secure, false)), true)
                .unwrap()
                .secure
        );
        assert!(
            !present(Ok(lookup(Proof::Insecure, false)), true)
                .unwrap()
                .secure
        );
    }

    #[test]
    fn cname_chain_end_is_canonical() {
        let chained = lookup(Proof::Secure, true);
        assert_eq!(
            canonical(&chained, "mx.example.test"),
            Some("host.provider.test".into())
        );
        assert_eq!(
            canonical(&lookup(Proof::Secure, false), "mx.example.test"),
            None
        );
    }
}
