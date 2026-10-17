//! DNS lookups used by routing and DNSBLs. Tests supply a map; production uses hickory.
use async_trait::async_trait;
use hickory_resolver::{
    lookup::Lookup,
    net::{DnsError, NetError},
    proto::rr::RData,
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
    #[error("DNS lookup failed: {0}")]
    Temp(String),
}

/// Records from a delivery lookup. An empty list means the name exists with
/// no records of that type (NODATA).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer<T> {
    pub records: T,
}

#[async_trait]
pub trait DnsLookup: Send + Sync {
    async fn lookup_ips(&self, name: &str) -> Result<Vec<IpAddr>, String>;
    async fn lookup_mx(&self, name: &str) -> Result<Vec<(u16, String)>, String>;

    /// MX lookup for delivery: NODATA is an empty answer, NXDOMAIN is distinct.
    async fn resolve_mx(&self, name: &str) -> Result<Answer<Vec<(u16, String)>>, LookupError> {
        self.lookup_mx(name)
            .await
            .map(|records| Answer { records })
            .map_err(LookupError::Temp)
    }

    /// Address lookup for delivery, with the same NODATA and NXDOMAIN split.
    async fn resolve_ips(&self, name: &str) -> Result<Answer<Vec<IpAddr>>, LookupError> {
        self.lookup_ips(name)
            .await
            .map(|records| Answer { records })
            .map_err(LookupError::Temp)
    }
}

#[derive(Default)]
pub struct MapDns {
    pub ips: HashMap<String, Vec<IpAddr>>,
    pub mx: HashMap<String, Vec<(u16, String)>>,
    /// Names that answer NXDOMAIN.
    pub nxdomain: HashSet<String>,
}

impl MapDns {
    pub fn new() -> Self {
        Self::default()
    }

    fn existing(&self, name: &str) -> Result<String, LookupError> {
        let name = normalise(name);
        if self.nxdomain.contains(&name) {
            return Err(LookupError::NxDomain);
        }
        Ok(name)
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
        let name = self.existing(name)?;
        Ok(Answer {
            records: self.mx.get(&name).cloned().unwrap_or_default(),
        })
    }

    async fn resolve_ips(&self, name: &str) -> Result<Answer<Vec<IpAddr>>, LookupError> {
        let name = self.existing(name)?;
        Ok(Answer {
            records: self.ips.get(&name).cloned().unwrap_or_default(),
        })
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
}

pub struct HickoryDns {
    resolver: TokioResolver,
}

impl HickoryDns {
    pub fn system() -> Result<Self, String> {
        let resolver = TokioResolver::builder_tokio()
            .map_err(|err| format!("system DNS resolver: {err}"))?
            .build()
            .map_err(|err| format!("system DNS resolver: {err}"))?;
        Ok(Self { resolver })
    }
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
        let lookup = present(self.resolver.mx_lookup(name).await)?;
        Ok(Answer {
            records: mx_records(lookup.as_ref()),
        })
    }

    async fn resolve_ips(&self, name: &str) -> Result<Answer<Vec<IpAddr>>, LookupError> {
        let records = match self.resolver.lookup_ip(name).await {
            Ok(lookup) => lookup.iter().collect(),
            Err(err) if err.is_nx_domain() => return Err(LookupError::NxDomain),
            Err(err) if err.is_no_records_found() => Vec::new(),
            Err(err) => return Err(LookupError::Temp(err.to_string())),
        };
        Ok(Answer { records })
    }
}

/// NODATA becomes `None`; NXDOMAIN and failures become errors.
fn present(result: Result<Lookup, NetError>) -> Result<Option<Lookup>, LookupError> {
    match result {
        Ok(lookup) => Ok(Some(lookup)),
        Err(err) if err.is_nx_domain() => Err(LookupError::NxDomain),
        Err(err) if err.is_no_records_found() => Ok(None),
        Err(NetError::Dns(DnsError::ResponseCode(code))) => {
            Err(LookupError::Temp(format!("DNS response {code}")))
        }
        Err(err) => Err(LookupError::Temp(err.to_string())),
    }
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
    use hickory_resolver::{
        net::NoRecords,
        proto::op::{Query, ResponseCode},
    };

    fn no_records(code: ResponseCode) -> NetError {
        NetError::Dns(DnsError::NoRecordsFound(NoRecords::new(
            Query::default(),
            code,
        )))
    }

    #[test]
    fn nodata_is_an_empty_answer() {
        let lookup = present(Err(no_records(ResponseCode::NoError))).unwrap();
        assert!(mx_records(lookup.as_ref()).is_empty());
    }

    #[test]
    fn nxdomain_is_distinct() {
        assert_eq!(
            present(Err(no_records(ResponseCode::NXDomain))).unwrap_err(),
            LookupError::NxDomain
        );
    }

    #[test]
    fn servfail_is_temporary() {
        let err = NetError::Dns(DnsError::ResponseCode(ResponseCode::ServFail));
        assert!(matches!(present(Err(err)), Err(LookupError::Temp(_))));
    }
}
