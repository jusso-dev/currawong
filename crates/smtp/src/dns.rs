//! DNS lookups used by routing and DNSBLs. Tests supply a map; production uses hickory.
use async_trait::async_trait;
use hickory_resolver::{proto::rr::RData, TokioResolver};
use std::{collections::HashMap, net::IpAddr, sync::Arc};

#[async_trait]
pub trait DnsLookup: Send + Sync {
    async fn lookup_ips(&self, name: &str) -> Result<Vec<IpAddr>, String>;
    async fn lookup_mx(&self, name: &str) -> Result<Vec<(u16, String)>, String>;
}

#[derive(Default)]
pub struct MapDns {
    pub ips: HashMap<String, Vec<IpAddr>>,
    pub mx: HashMap<String, Vec<(u16, String)>>,
}

impl MapDns {
    pub fn new() -> Self {
        Self::default()
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
}

#[async_trait]
impl DnsLookup for Arc<MapDns> {
    async fn lookup_ips(&self, name: &str) -> Result<Vec<IpAddr>, String> {
        self.as_ref().lookup_ips(name).await
    }

    async fn lookup_mx(&self, name: &str) -> Result<Vec<(u16, String)>, String> {
        self.as_ref().lookup_mx(name).await
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
        let lookup = self
            .resolver
            .mx_lookup(name)
            .await
            .map_err(|err| err.to_string())?;
        let mut records: Vec<(u16, String)> = lookup
            .answers()
            .iter()
            .filter_map(|record| match &record.data {
                RData::MX(mx) => Some((mx.preference, mx.exchange.to_string())),
                _ => None,
            })
            .collect();
        records.sort_by_key(|item| item.0);
        Ok(records)
    }
}

pub fn normalise(name: &str) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase()
}
