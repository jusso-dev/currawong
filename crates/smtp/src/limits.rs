//! Per-IP and process-wide connection caps. The guard releases the slot on drop.
use dashmap::DashMap;
use std::{
    net::IpAddr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

#[derive(Debug)]
pub struct ConnectionLimits {
    max_global: usize,
    max_per_ip: u32,
    global: AtomicUsize,
    per_ip: DashMap<IpAddr, u32>,
}

pub struct ConnGuard {
    limits: Arc<ConnectionLimits>,
    ip: IpAddr,
}

impl ConnectionLimits {
    pub fn new(max_global: usize, max_per_ip: u32) -> Arc<Self> {
        Arc::new(Self {
            max_global,
            max_per_ip,
            global: AtomicUsize::new(0),
            per_ip: DashMap::new(),
        })
    }

    pub fn try_acquire(self: &Arc<Self>, ip: IpAddr) -> Option<ConnGuard> {
        let global = self.global.fetch_add(1, Ordering::AcqRel);
        if global >= self.max_global {
            self.global.fetch_sub(1, Ordering::AcqRel);
            return None;
        }
        let mut over = false;
        self.per_ip
            .entry(ip)
            .and_modify(|count| {
                if *count >= self.max_per_ip {
                    over = true;
                } else {
                    *count += 1;
                }
            })
            .or_insert_with(|| {
                if self.max_per_ip == 0 {
                    over = true;
                    0
                } else {
                    1
                }
            });
        if over {
            self.global.fetch_sub(1, Ordering::AcqRel);
            return None;
        }
        Some(ConnGuard {
            limits: Arc::clone(self),
            ip,
        })
    }
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.limits.global.fetch_sub(1, Ordering::AcqRel);
        let mut remove = false;
        if let Some(mut count) = self.limits.per_ip.get_mut(&self.ip) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                remove = true;
            }
        }
        if remove {
            self.limits.per_ip.remove(&self.ip);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn per_ip_cap_releases_on_drop() {
        let limits = ConnectionLimits::new(10, 1);
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
        let guard = limits.try_acquire(ip).unwrap();
        assert!(limits.try_acquire(ip).is_none());
        drop(guard);
        assert!(limits.try_acquire(ip).is_some());
    }
}
