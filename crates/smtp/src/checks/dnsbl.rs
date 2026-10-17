//! DNSBL lookups. A hit is a `127.0.0.0/8` answer mapped from configuration.
use super::{CheckResult, ConnCtx, ConnectionCheck, RcptCtx};
use crate::dns::{normalise, DnsLookup};
use async_trait::async_trait;
use currawong_core::config::DnsblZone;
use std::{net::IpAddr, sync::Arc};

pub struct DnsblCheck {
    zones: Vec<DnsblZone>,
    dns: Arc<dyn DnsLookup>,
}

impl DnsblCheck {
    pub fn new(zones: Vec<DnsblZone>, dns: Arc<dyn DnsLookup>) -> Self {
        Self { zones, dns }
    }

    pub fn query_name(ip: IpAddr, zone: &DnsblZone) -> Option<String> {
        let reversed = reverse(ip)?;
        let zone_name = normalise(&zone.zone);
        if let Some(key) = &zone.dqs_key {
            Some(format!("{}.{reversed}.{zone_name}", key.expose()))
        } else {
            Some(format!("{reversed}.{zone_name}"))
        }
    }
}

fn reverse(ip: IpAddr) -> Option<String> {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            Some(format!("{}.{}.{}.{}", o[3], o[2], o[1], o[0]))
        }
        IpAddr::V6(_) => None,
    }
}

#[async_trait]
impl ConnectionCheck for DnsblCheck {
    async fn on_connect(&self, ctx: &ConnCtx) -> CheckResult {
        for zone in &self.zones {
            let Some(name) = Self::query_name(ctx.ip, zone) else {
                continue;
            };
            let ips = match self.dns.lookup_ips(&name).await {
                Ok(ips) => ips,
                Err(err) => {
                    tracing::debug!(%err, %name, "DNSBL lookup failed open");
                    continue;
                }
            };
            for answer in ips {
                let text = answer.to_string();
                if let Some(listing) = zone.listings.iter().find(|item| item.code == text) {
                    return CheckResult::Reject(format!("554 5.7.1 {}", listing.reason));
                }
                if text.starts_with("127.0.0.") {
                    return CheckResult::Reject(format!("554 5.7.1 listed by {}", zone.zone));
                }
            }
        }
        CheckResult::Pass
    }

    async fn on_rcpt(&self, _ctx: &RcptCtx) -> CheckResult {
        CheckResult::Pass
    }
}
