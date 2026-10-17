//! Cheap pre-DATA checks. Each one can be left unset to disable it.
mod dnsbl;
mod greylist;
mod ratelimit;
mod reputation;

pub use dnsbl::DnsblCheck;
pub use greylist::{GreylistCheck, GreylistDecision};
pub use ratelimit::RateLimitCheck;
pub use reputation::Reputation;

use crate::dns::DnsLookup;
use async_trait::async_trait;
use currawong_core::config::{ChecksConfig, Config};
use ipnet::IpNet;
use std::{net::IpAddr, sync::Arc};

#[derive(Debug, Clone)]
pub struct ConnCtx {
    pub ip: IpAddr,
    pub helo: String,
}

#[derive(Debug, Clone)]
pub struct RcptCtx {
    pub ip: IpAddr,
    pub mail_from: String,
    pub recipient: String,
}

#[derive(Debug, Clone)]
pub struct MailCtx {
    pub ip: IpAddr,
    pub mail_from: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CheckResult {
    Pass,
    Score(f32),
    TempFail(String),
    Reject(String),
}

#[async_trait]
pub trait ConnectionCheck: Send + Sync {
    async fn on_connect(&self, ctx: &ConnCtx) -> CheckResult;
    async fn on_rcpt(&self, ctx: &RcptCtx) -> CheckResult;
    async fn on_mail(&self, _ctx: &MailCtx) -> CheckResult {
        CheckResult::Pass
    }
}

pub struct CheckStack {
    pub dnsbl: Option<DnsblCheck>,
    pub rate: Option<RateLimitCheck>,
    pub greylist: Option<GreylistCheck>,
    pub reputation: Option<Reputation>,
    allow: Vec<IpNet>,
}

impl CheckStack {
    pub fn from_config(cfg: &Config, dns: Arc<dyn DnsLookup>) -> Result<Self, String> {
        Self::from_checks(&cfg.checks, dns)
    }

    pub fn from_checks(cfg: &ChecksConfig, dns: Arc<dyn DnsLookup>) -> Result<Self, String> {
        let allow = cfg
            .allow_cidrs
            .iter()
            .map(|cidr| {
                cidr.parse::<IpNet>()
                    .map_err(|err| format!("allow cidr {cidr}: {err}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let dnsbl = if cfg.dnsbl_enabled {
            Some(DnsblCheck::new(cfg.dnsbl.clone(), dns))
        } else {
            None
        };
        let rate = if cfg.ratelimit_enabled {
            Some(RateLimitCheck::new(cfg))
        } else {
            None
        };
        let greylist = if cfg.greylist_enabled {
            Some(
                GreylistCheck::open(&cfg.greylist_database, cfg.greylist_delay_secs)
                    .map_err(|err| err.to_string())?,
            )
        } else {
            None
        };
        let reputation = if cfg.reputation_enabled {
            Some(Reputation::new(
                cfg.reputation_reject_score,
                cfg.reputation_half_life_secs,
            ))
        } else {
            None
        };
        Ok(Self {
            dnsbl,
            rate,
            greylist,
            reputation,
            allow,
        })
    }

    pub fn disabled() -> Self {
        Self {
            dnsbl: None,
            rate: None,
            greylist: None,
            reputation: None,
            allow: Vec::new(),
        }
    }

    fn allowed(&self, ip: IpAddr) -> bool {
        self.allow.iter().any(|net| net.contains(&ip))
    }

    pub async fn on_connect(&self, ctx: &ConnCtx) -> CheckResult {
        if let Some(rate) = &self.rate {
            let result = rate.on_connect(ctx).await;
            if blocking(&result) {
                return result;
            }
        }
        if self.allowed(ctx.ip) {
            return CheckResult::Pass;
        }
        if let Some(rep) = &self.reputation {
            let result = rep.on_connect(ctx).await;
            if blocking(&result) {
                return result;
            }
        }
        if let Some(dnsbl) = &self.dnsbl {
            let result = dnsbl.on_connect(ctx).await;
            if blocking(&result) {
                return result;
            }
        }
        CheckResult::Pass
    }

    pub async fn on_mail(&self, ctx: &MailCtx) -> CheckResult {
        if let Some(rate) = &self.rate {
            return rate.on_mail(ctx).await;
        }
        CheckResult::Pass
    }

    pub async fn on_rcpt(&self, ctx: &RcptCtx) -> CheckResult {
        if self.allowed(ctx.ip) {
            return CheckResult::Pass;
        }
        if let Some(greylist) = &self.greylist {
            return greylist.on_rcpt(ctx).await;
        }
        CheckResult::Pass
    }
}

fn blocking(result: &CheckResult) -> bool {
    matches!(result, CheckResult::Reject(_) | CheckResult::TempFail(_))
}
