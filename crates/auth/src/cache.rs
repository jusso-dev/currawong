//! Bounded TXT cache honouring DNS TTLs. Unit tests seed it so they never
//! query a DNS server.
use mail_auth::{DnsError, Error, ResolverCache, Txt};
use std::time::Instant;
use std::{borrow::Borrow, collections::HashMap, hash::Hash, sync::Mutex};

/// Enough for a busy gateway's working set; the oldest-expiring entry goes
/// when full.
const MAX_ENTRIES: usize = 16_384;

struct Entry {
    value: Txt,
    /// `None` for records seeded by tests or operators: they never expire.
    valid_until: Option<Instant>,
}

pub struct TxtCache {
    records: Mutex<HashMap<Box<str>, Entry>>,
    capacity: usize,
    /// When set, a cache miss is a permanent DNS error. Unit tests use this
    /// so a missing record never reaches a DNS server.
    offline: bool,
}

impl Default for TxtCache {
    fn default() -> Self {
        Self {
            records: Mutex::new(HashMap::new()),
            capacity: MAX_ENTRIES,
            offline: false,
        }
    }
}

impl TxtCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn offline() -> Self {
        Self {
            offline: true,
            ..Self::default()
        }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            ..Self::default()
        }
    }

    pub fn len(&self) -> usize {
        self.records.lock().expect("txt cache").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Seed a record that never expires.
    pub fn insert_record(&self, name: &str, value: Txt) {
        self.put(canonical(name).into_boxed_str(), value, None);
    }

    fn put(&self, key: Box<str>, value: Txt, valid_until: Option<Instant>) {
        let mut records = self.records.lock().expect("txt cache");
        if records.len() >= self.capacity && !records.contains_key(&key) {
            let now = Instant::now();
            records.retain(|_, entry| entry.valid_until.is_none_or(|until| until > now));
            if records.len() >= self.capacity {
                let victim = records
                    .iter()
                    .filter_map(|(key, entry)| entry.valid_until.map(|until| (until, key)))
                    .min_by_key(|(until, _)| *until)
                    .map(|(_, key)| key.clone())
                    .or_else(|| records.keys().next().cloned());
                if let Some(victim) = victim {
                    records.remove(&victim);
                }
            }
        }
        records.insert(key, Entry { value, valid_until });
    }
}

fn canonical(name: &str) -> String {
    let name = name.trim().trim_end_matches('.').to_ascii_lowercase();
    format!("{name}.")
}

impl ResolverCache<Box<str>, Txt> for TxtCache {
    fn get<Q>(&self, name: &Q) -> Option<Txt>
    where
        Box<str>: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let mut records = self.records.lock().expect("txt cache");
        if let Some(entry) = records.get(name) {
            if entry.valid_until.is_none_or(|until| until > Instant::now()) {
                return Some(entry.value.clone());
            }
            records.remove(name);
        }
        if self.offline {
            Some(Txt::Error(Error::Dns(DnsError::InvalidRecordType)))
        } else {
            None
        }
    }

    fn remove<Q>(&self, name: &Q) -> Option<Txt>
    where
        Box<str>: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.records
            .lock()
            .expect("txt cache")
            .remove(name)
            .map(|entry| entry.value)
    }

    fn insert(&self, key: Box<str>, value: Txt, valid_until: Instant) {
        self.put(key, value, Some(valid_until));
    }
}

#[cfg(test)]
mod tests {
    use super::TxtCache;
    use mail_auth::{DnsError, Error, ResolverCache, Txt};
    use std::time::{Duration, Instant};

    fn error() -> Txt {
        Txt::Error(Error::Dns(DnsError::InvalidRecordType))
    }

    #[test]
    fn expired_answers_are_not_served() {
        let cache = TxtCache::new();
        cache.insert("gone.example.test.".into(), error(), Instant::now());
        std::thread::sleep(Duration::from_millis(5));
        assert!(cache.get("gone.example.test.").is_none());
        cache.insert(
            "fresh.example.test.".into(),
            error(),
            Instant::now() + Duration::from_secs(60),
        );
        assert!(cache.get("fresh.example.test.").is_some());
    }

    #[test]
    fn cache_is_bounded() {
        let cache = TxtCache::with_capacity(4);
        for index in 0..20 {
            cache.insert(
                format!("host{index}.example.test.").into_boxed_str(),
                error(),
                Instant::now() + Duration::from_secs(60 + index),
            );
        }
        assert_eq!(cache.len(), 4);
        assert!(cache.get("host19.example.test.").is_some());
    }
}
