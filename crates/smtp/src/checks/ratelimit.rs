//! Token-bucket limits per IP, per IPv4 /24 (or IPv6 /64) and per sender domain.
use super::{CheckResult, ConnCtx, ConnectionCheck, MailCtx, RcptCtx};
use async_trait::async_trait;
use currawong_core::config::ChecksConfig;
use governor::{Quota, RateLimiter};
use std::{
    net::{IpAddr, Ipv6Addr},
    num::NonZeroU32,
    sync::Arc,
};

type Limiter<K> = Arc<
    RateLimiter<
        K,
        governor::state::keyed::DefaultKeyedStateStore<K>,
        governor::clock::DefaultClock,
    >,
>;

pub struct RateLimitCheck {
    per_ip: Limiter<IpAddr>,
    per_net: Limiter<String>,
    per_sender: Limiter<String>,
}

impl RateLimitCheck {
    pub fn new(cfg: &ChecksConfig) -> Self {
        Self {
            per_ip: keyed(cfg.rate_per_minute_ip),
            per_net: keyed(cfg.rate_per_minute_net),
            per_sender: keyed(cfg.rate_per_minute_sender),
        }
    }
}

fn keyed<K: Eq + std::hash::Hash + Clone + Send + Sync + 'static>(per_minute: u32) -> Limiter<K> {
    let quota = Quota::per_minute(NonZeroU32::new(per_minute.max(1)).expect("non-zero"));
    Arc::new(RateLimiter::keyed(quota))
}

fn net_key(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.0/24", o[0], o[1], o[2])
        }
        IpAddr::V6(v6) => {
            let o = v6.octets();
            let prefix = Ipv6Addr::new(
                u16::from_be_bytes([o[0], o[1]]),
                u16::from_be_bytes([o[2], o[3]]),
                u16::from_be_bytes([o[4], o[5]]),
                u16::from_be_bytes([o[6], o[7]]),
                0,
                0,
                0,
                0,
            );
            format!("{prefix}/64")
        }
    }
}

fn limited() -> CheckResult {
    CheckResult::TempFail("421 4.7.0 rate limit exceeded, try again later".into())
}

#[async_trait]
impl ConnectionCheck for RateLimitCheck {
    async fn on_connect(&self, ctx: &ConnCtx) -> CheckResult {
        if self.per_ip.check_key(&ctx.ip).is_err()
            || self.per_net.check_key(&net_key(ctx.ip)).is_err()
        {
            return limited();
        }
        CheckResult::Pass
    }

    async fn on_mail(&self, ctx: &MailCtx) -> CheckResult {
        let domain = ctx
            .mail_from
            .rsplit_once('@')
            .map(|(_, domain)| domain.to_ascii_lowercase())
            .unwrap_or_else(|| ctx.mail_from.to_ascii_lowercase());
        if domain.is_empty() {
            return CheckResult::Pass;
        }
        if self.per_sender.check_key(&domain).is_err() {
            return limited();
        }
        CheckResult::Pass
    }

    async fn on_rcpt(&self, _ctx: &RcptCtx) -> CheckResult {
        CheckResult::Pass
    }
}
