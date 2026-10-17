//! In-memory TXT cache so unit tests never query a DNS server.
use mail_auth::{DnsError, Error, ResolverCache, Txt};
use std::time::Instant;
use std::{borrow::Borrow, collections::HashMap, hash::Hash, sync::Mutex};

pub struct TxtCache {
    records: Mutex<HashMap<String, Txt>>,
    /// When set, a cache miss is a permanent DNS error. Unit tests use this
    /// so a missing record never reaches a DNS server.
    offline: bool,
}

impl Default for TxtCache {
    fn default() -> Self {
        Self {
            records: Mutex::new(HashMap::new()),
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

    pub fn insert_record(&self, name: &str, value: Txt) {
        let key = canonical(name);
        self.records.lock().expect("txt cache").insert(key, value);
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
        let records = self.records.lock().expect("txt cache");
        for (key, value) in records.iter() {
            let boxed: Box<str> = key.clone().into_boxed_str();
            let borrowed: &Q = boxed.borrow();
            if borrowed == name {
                return Some(value.clone());
            }
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
        let mut records = self.records.lock().expect("txt cache");
        let key = records
            .keys()
            .find(|key| {
                let boxed: Box<str> = (*key).clone().into_boxed_str();
                let borrowed: &Q = boxed.borrow();
                borrowed == name
            })
            .cloned();
        key.and_then(|key| records.remove(&key))
    }

    fn insert(&self, key: Box<str>, value: Txt, _valid_until: Instant) {
        self.insert_record(&key, value);
    }
}
