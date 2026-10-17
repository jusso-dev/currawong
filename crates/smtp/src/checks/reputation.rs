//! Local reputation with exponential decay. Higher scores are worse.
use super::{CheckResult, ConnCtx, ConnectionCheck, RcptCtx};
use async_trait::async_trait;
use dashmap::DashMap;
use std::{
    net::IpAddr,
    sync::{Arc, Mutex},
};

pub struct Reputation {
    scores: DashMap<IpAddr, (f32, i64)>,
    threshold: f32,
    half_life_secs: f32,
    now: Mutex<Arc<dyn Fn() -> i64 + Send + Sync>>,
}

impl Reputation {
    pub fn new(threshold: f32, half_life_secs: u64) -> Self {
        Self {
            scores: DashMap::new(),
            threshold,
            half_life_secs: half_life_secs.max(1) as f32,
            now: Mutex::new(Arc::new(|| {
                time::OffsetDateTime::now_utc().unix_timestamp()
            })),
        }
    }

    pub fn set_clock(&self, now: Arc<dyn Fn() -> i64 + Send + Sync>) {
        *self.now.lock().expect("clock") = now;
    }

    fn now(&self) -> i64 {
        (self.now.lock().expect("clock"))()
    }

    pub fn score(&self, ip: IpAddr) -> f32 {
        let now = self.now();
        self.scores
            .get(&ip)
            .map(|entry| decay(entry.0, entry.1, now, self.half_life_secs))
            .unwrap_or(0.0)
    }

    pub fn record(&self, ip: IpAddr, delta: f32) {
        let now = self.now();
        self.scores
            .entry(ip)
            .and_modify(|entry| {
                entry.0 = decay(entry.0, entry.1, now, self.half_life_secs) + delta;
                entry.1 = now;
            })
            .or_insert((delta.max(0.0), now));
    }
}

fn decay(score: f32, updated: i64, now: i64, half_life: f32) -> f32 {
    let elapsed = now.saturating_sub(updated).max(0) as f32;
    score * 0.5f32.powf(elapsed / half_life)
}

#[async_trait]
impl ConnectionCheck for Reputation {
    async fn on_connect(&self, ctx: &ConnCtx) -> CheckResult {
        let score = self.score(ctx.ip);
        if score >= self.threshold {
            CheckResult::Reject(format!(
                "554 5.7.1 reputation {score:.1} exceeds {:.1}",
                self.threshold
            ))
        } else if score > 0.0 {
            CheckResult::Score(score)
        } else {
            CheckResult::Pass
        }
    }

    async fn on_rcpt(&self, _ctx: &RcptCtx) -> CheckResult {
        CheckResult::Pass
    }
}
