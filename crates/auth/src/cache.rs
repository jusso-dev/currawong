//! TXT caches for SPF, DKIM and DMARC. mail-auth keys its TXT cache by name
//! only, so a shared cache let one verifier's lookup answer another's: an
//! SPF `include:_dmarc.victim` cached a parse failure that DMARC then read as
//! "no record". Each verifier gets its own cache, each cache only stores its
//! own record type, and failures are never cached. Entries live for the DNS
//! TTL clamped to 30 s..1 h and are evicted least recently used.
use mail_auth::{DnsError, Error, ResolverCache, Txt};
use std::time::{Duration, Instant};
use std::{
    borrow::Borrow,
    collections::{BTreeMap, HashMap},
    hash::Hash,
    sync::Mutex,
};

const MAX_ENTRIES: usize = 16_384;
const MIN_TTL: Duration = Duration::from_secs(30);
const MAX_TTL: Duration = Duration::from_secs(60 * 60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordKind {
    Spf,
    DomainKey,
    Dmarc,
}

impl RecordKind {
    fn accepts(self, value: &Txt) -> bool {
        matches!(
            (self, value),
            (Self::Spf, Txt::Spf(_))
                | (Self::DomainKey, Txt::DomainKey(_))
                | (Self::Dmarc, Txt::Dmarc(_))
        )
    }
}

/// The three per-verifier caches.
pub struct TxtCache {
    pub(crate) spf: TypedCache,
    pub(crate) dkim: TypedCache,
    pub(crate) dmarc: TypedCache,
}

impl Default for TxtCache {
    fn default() -> Self {
        Self::build(MAX_ENTRIES, false)
    }
}

impl TxtCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// A cache miss is a permanent DNS error, so unit tests never reach DNS.
    pub fn offline() -> Self {
        Self::build(MAX_ENTRIES, true)
    }

    fn build(capacity: usize, offline: bool) -> Self {
        Self {
            spf: TypedCache::new(RecordKind::Spf, capacity, offline),
            dkim: TypedCache::new(RecordKind::DomainKey, capacity, offline),
            dmarc: TypedCache::new(RecordKind::Dmarc, capacity, offline),
        }
    }

    /// Seed a record that never expires. It goes to the cache for its type.
    pub fn insert_record(&self, name: &str, value: Txt) {
        let cache = match &value {
            Txt::Spf(_) => &self.spf,
            Txt::DomainKey(_) => &self.dkim,
            Txt::Dmarc(_) => &self.dmarc,
            _ => return,
        };
        cache.put(canonical(name).into_boxed_str(), value, None);
    }
}

struct Slot {
    value: Txt,
    /// `None` for seeded records.
    expires: Option<Instant>,
    tick: u64,
}

struct Lru {
    slots: HashMap<Box<str>, Slot>,
    order: BTreeMap<u64, Box<str>>,
    tick: u64,
}

impl Lru {
    fn touch(&mut self, key: &str) {
        self.tick += 1;
        let tick = self.tick;
        if let Some(slot) = self.slots.get_mut(key) {
            self.order.remove(&slot.tick);
            slot.tick = tick;
            self.order.insert(tick, key.into());
        }
    }

    fn remove<Q>(&mut self, key: &Q) -> Option<Slot>
    where
        Box<str>: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let slot = self.slots.remove(key)?;
        self.order.remove(&slot.tick);
        Some(slot)
    }
}

pub struct TypedCache {
    kind: RecordKind,
    inner: Mutex<Lru>,
    capacity: usize,
    offline: bool,
}

impl TypedCache {
    pub fn new(kind: RecordKind, capacity: usize, offline: bool) -> Self {
        Self {
            kind,
            inner: Mutex::new(Lru {
                slots: HashMap::new(),
                order: BTreeMap::new(),
                tick: 0,
            }),
            capacity: capacity.max(1),
            offline,
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.inner.lock().expect("txt cache").slots.len()
    }

    #[cfg(test)]
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn put(&self, key: Box<str>, value: Txt, expires: Option<Instant>) {
        if !self.kind.accepts(&value) {
            return;
        }
        let mut lru = self.inner.lock().expect("txt cache");
        lru.remove(&*key);
        while lru.slots.len() >= self.capacity {
            let Some((_, oldest)) = lru.order.pop_first() else {
                break;
            };
            lru.slots.remove(&oldest);
        }
        lru.tick += 1;
        let tick = lru.tick;
        lru.order.insert(tick, key.clone());
        lru.slots.insert(
            key,
            Slot {
                value,
                expires,
                tick,
            },
        );
    }
}

fn canonical(name: &str) -> String {
    let name = name.trim().trim_end_matches('.').to_ascii_lowercase();
    format!("{name}.")
}

impl ResolverCache<Box<str>, Txt> for TypedCache {
    fn get<Q>(&self, name: &Q) -> Option<Txt>
    where
        Box<str>: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let mut lru = self.inner.lock().expect("txt cache");
        let fresh = lru.slots.get_key_value(name).map(|(key, slot)| {
            (
                key.clone(),
                slot.expires.is_none_or(|at| at > Instant::now()),
            )
        });
        match fresh {
            Some((key, true)) => {
                lru.touch(&key);
                return lru.slots.get::<str>(&key).map(|slot| slot.value.clone());
            }
            Some((_, false)) => {
                lru.remove(name);
            }
            None => {}
        }
        self.offline
            .then(|| Txt::Error(Error::Dns(DnsError::InvalidRecordType)))
    }

    fn remove<Q>(&self, name: &Q) -> Option<Txt>
    where
        Box<str>: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.inner
            .lock()
            .expect("txt cache")
            .remove(name)
            .map(|slot| slot.value)
    }

    fn insert(&self, key: Box<str>, value: Txt, valid_until: Instant) {
        let now = Instant::now();
        let expires = valid_until.clamp(now + MIN_TTL, now + MAX_TTL);
        self.put(key, value, Some(expires));
    }
}

#[cfg(test)]
mod tests {
    use super::{RecordKind, TypedCache};
    use mail_auth::{
        common::parse::TxtRecordParser, dmarc::Dmarc, spf::Spf, DnsError, Error, ResolverCache, Txt,
    };
    use std::{
        sync::Arc,
        time::{Duration, Instant},
    };

    fn spf() -> Txt {
        Txt::Spf(Arc::new(Spf::parse(b"v=spf1 -all").unwrap()))
    }

    #[test]
    fn failures_and_other_record_types_are_never_cached() {
        let cache = TypedCache::new(RecordKind::Dmarc, 8, false);
        let soon = Instant::now() + Duration::from_secs(300);
        cache.insert(
            "_dmarc.victim.test.".into(),
            Txt::Error(Error::Dns(DnsError::InvalidRecordType)),
            soon,
        );
        cache.insert("_dmarc.victim.test.".into(), spf(), soon);
        assert!(cache.get("_dmarc.victim.test.").is_none());
        let dmarc = Txt::Dmarc(Arc::new(Dmarc::parse(b"v=DMARC1; p=reject").unwrap()));
        cache.insert("_dmarc.victim.test.".into(), dmarc, soon);
        assert!(matches!(
            cache.get("_dmarc.victim.test."),
            Some(Txt::Dmarc(_))
        ));
    }

    #[test]
    fn ttl_is_clamped_between_30_seconds_and_an_hour() {
        let cache = TypedCache::new(RecordKind::Spf, 8, false);
        // A zero TTL is still held for 30 s.
        cache.insert("short.test.".into(), spf(), Instant::now());
        assert!(cache.get("short.test.").is_some());
        // A week-long TTL is cut to an hour.
        let week = Instant::now() + Duration::from_secs(7 * 24 * 3600);
        cache.insert("long.test.".into(), spf(), week);
        let expires = cache
            .inner
            .lock()
            .unwrap()
            .slots
            .get("long.test.")
            .and_then(|slot| slot.expires)
            .unwrap();
        assert!(expires <= Instant::now() + Duration::from_secs(3600));
    }

    #[test]
    fn expired_answers_are_not_served() {
        let cache = TypedCache::new(RecordKind::Spf, 8, false);
        cache.put(
            "gone.test.".into(),
            spf(),
            Some(Instant::now() - Duration::from_secs(1)),
        );
        assert!(cache.get("gone.test.").is_none());
        assert!(cache.is_empty());
    }

    #[test]
    fn least_recently_used_entry_is_evicted() {
        let cache = TypedCache::new(RecordKind::Spf, 3, false);
        let soon = Instant::now() + Duration::from_secs(300);
        for name in ["a.test.", "b.test.", "c.test."] {
            cache.insert(name.into(), spf(), soon);
        }
        assert!(cache.get("a.test.").is_some());
        cache.insert("d.test.".into(), spf(), soon);
        assert_eq!(cache.len(), 3);
        assert!(cache.get("b.test.").is_none(), "b was least recently used");
        assert!(cache.get("a.test.").is_some());
        assert!(cache.get("d.test.").is_some());
    }
}
