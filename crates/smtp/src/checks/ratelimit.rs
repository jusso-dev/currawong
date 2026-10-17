//! Token-bucket limits per IP, per IPv4 /24 (or IPv6 /64) and per sender
//! domain from that network. MAIL FROM is unauthenticated, so the sender
//! bucket is keyed on (network, domain): a forger can only exhaust its own.
use super::{net_key, CheckResult, ConnCtx, ConnectionCheck, MailCtx, RcptCtx};
use async_trait::async_trait;
use currawong_core::config::ChecksConfig;
use governor::{Quota, RateLimiter};
use std::{net::IpAddr, num::NonZeroU32, sync::Arc};

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

    /// Forget keys whose buckets have refilled.
    pub fn housekeeping(&self) {
        self.per_ip.retain_recent();
        self.per_ip.shrink_to_fit();
        self.per_net.retain_recent();
        self.per_net.shrink_to_fit();
        self.per_sender.retain_recent();
        self.per_sender.shrink_to_fit();
    }

    /// Keys currently held across all three limiters.
    pub fn tracked_keys(&self) -> usize {
        self.per_ip.len() + self.per_net.len() + self.per_sender.len()
    }
}

fn keyed<K: Eq + std::hash::Hash + Clone + Send + Sync + 'static>(per_minute: u32) -> Limiter<K> {
    let quota = Quota::per_minute(NonZeroU32::new(per_minute.max(1)).expect("non-zero"));
    Arc::new(RateLimiter::keyed(quota))
}

fn limited() -> CheckResult {
    CheckResult::TempFail("421 4.7.0 rate limit exceeded, try again later".into())
}

#[async_trait]
impl ConnectionCheck for RateLimitCheck {
    async fn on_connect(&self, ctx: &ConnCtx) -> CheckResult {
        let ip = ctx.ip.to_canonical();
        if self.per_ip.check_key(&ip).is_err() || self.per_net.check_key(&net_key(ip)).is_err() {
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
        let key = format!("{}|{domain}", net_key(ctx.ip));
        if self.per_sender.check_key(&key).is_err() {
            return limited();
        }
        CheckResult::Pass
    }

    async fn on_rcpt(&self, _ctx: &RcptCtx) -> CheckResult {
        CheckResult::Pass
    }
}
