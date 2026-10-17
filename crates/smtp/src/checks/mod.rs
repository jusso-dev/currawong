//! Cheap pre-DATA checks. Each one can be left unset to disable it.
//! The session skips them for trusted tenant networks and authenticated
//! submission; `allow_cidrs` skips them for listed networks.
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
use currawong_core::{
    config::{ChecksConfig, Config},
    Verdict,
};
use ipnet::IpNet;
use std::{
    net::{IpAddr, Ipv6Addr},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

/// How often in-memory limiter keys, reputation entries and old greylist rows are pruned.
const HOUSEKEEPING_EVERY: Duration = Duration::from_secs(60);
/// Reputation changes fed back from pipeline verdicts.
const SCORE_DELIVERED: f32 = -5.0;
const SCORE_BLOCKED: f32 = 25.0;
const SCORE_MALWARE: f32 = 50.0;

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
    last_sweep: Mutex<Instant>,
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
            last_sweep: Mutex::new(Instant::now()),
        })
    }

    pub fn disabled() -> Self {
        Self {
            dnsbl: None,
            rate: None,
            greylist: None,
            reputation: None,
            allow: Vec::new(),
            last_sweep: Mutex::new(Instant::now()),
        }
    }

    fn allowed(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        self.allow.iter().any(|net| net.contains(&ip))
    }

    pub async fn on_connect(&self, ctx: &ConnCtx) -> CheckResult {
        self.maybe_housekeeping();
        if self.allowed(ctx.ip) {
            return CheckResult::Pass;
        }
        if let Some(rate) = &self.rate {
            let result = rate.on_connect(ctx).await;
            if blocking(&result) {
                return result;
            }
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
        if self.allowed(ctx.ip) {
            return CheckResult::Pass;
        }
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

    /// Feed a pipeline verdict back. Blocked mail raises the sending address's
    /// reputation score and delivered mail lowers it. A delivered message that
    /// passed aligned DMARC lets that sender domain skip greylisting from the
    /// same network.
    pub fn record_verdict(
        &self,
        ip: IpAddr,
        mail_from: &str,
        dmarc_pass: bool,
        malware: bool,
        verdict: &Verdict,
    ) {
        let delta = match verdict {
            Verdict::Deliver => SCORE_DELIVERED,
            Verdict::Defer { .. } => 0.0,
            _ if malware => SCORE_MALWARE,
            _ => SCORE_BLOCKED,
        };
        if let Some(rep) = &self.reputation {
            if delta != 0.0 {
                rep.record(ip, delta);
            }
        }
        if let (Some(greylist), Verdict::Deliver, true) = (&self.greylist, verdict, dmarc_pass) {
            if let Some((_, domain)) = mail_from.rsplit_once('@') {
                if let Err(err) = greylist.allow_aligned_dmarc(domain, ip) {
                    tracing::warn!(%err, "greylist DMARC allow-list update failed");
                }
            }
        }
    }

    /// Drop limiter keys whose buckets have refilled, reputation entries that
    /// have decayed to nothing, and expired greylist rows. Attacker-chosen
    /// addresses would otherwise grow these without bound.
    pub fn housekeeping(&self) {
        if let Some(rate) = &self.rate {
            rate.housekeeping();
        }
        if let Some(rep) = &self.reputation {
            rep.prune();
        }
        if let Some(greylist) = &self.greylist {
            let greylist = greylist.clone();
            let run = move || {
                if let Err(err) = greylist.expire() {
                    tracing::warn!(%err, "greylist expiry failed");
                }
            };
            match tokio::runtime::Handle::try_current() {
                Ok(handle) => {
                    handle.spawn_blocking(run);
                }
                Err(_) => run(),
            }
        }
    }

    fn maybe_housekeeping(&self) {
        let due = {
            let mut last = self.last_sweep.lock().expect("sweep clock");
            if last.elapsed() >= HOUSEKEEPING_EVERY {
                *last = Instant::now();
                true
            } else {
                false
            }
        };
        if due {
            self.housekeeping();
        }
    }
}

fn blocking(result: &CheckResult) -> bool {
    matches!(result, CheckResult::Reject(_) | CheckResult::TempFail(_))
}

/// IPv4 /24 or IPv6 /64. IPv4-mapped IPv6 addresses count as IPv4.
pub(crate) fn net_key(ip: IpAddr) -> String {
    match ip.to_canonical() {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.0/24", o[0], o[1], o[2])
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            let prefix = Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0);
            format!("{prefix}/64")
        }
    }
}
