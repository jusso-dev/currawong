//! MTA-STS (RFC 8461): discover a domain's policy from `_mta-sts` TXT and
//! `https://mta-sts.<domain>/.well-known/mta-sts.txt`, cache it in the
//! `mta_sts_policy` table for `max_age`, and say which MX hosts it allows.
use super::route::valid_domain;
use crate::dns::{normalise, DnsLookup};
use async_trait::async_trait;
use mail_auth::{
    common::parse::TxtRecordParser, mta_sts::MtaSts as StsRecord, report::tlsrpt::ResultType,
};
use rusqlite::Connection;
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex},
};

/// RFC 8461 section 3.2: max_age is at most one year.
const MAX_AGE_LIMIT: u64 = 31_557_600;
const MAX_POLICY_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Enforce,
    Testing,
    None,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    pub id: String,
    pub mode: Mode,
    pub mx: Vec<String>,
    pub max_age: u64,
    /// The policy body, for TLS-RPT `policy-string`.
    pub text: String,
}

impl Policy {
    /// RFC 8461 section 4.1: exact names, or `*.` matching one leftmost label.
    pub fn allows(&self, host: &str) -> bool {
        let host = normalise(host);
        self.mx.iter().any(|pattern| {
            let pattern = normalise(pattern);
            match pattern.strip_prefix("*.") {
                Some(suffix) => host
                    .split_once('.')
                    .is_some_and(|(label, rest)| !label.is_empty() && rest == suffix),
                None => host == pattern,
            }
        })
    }

    pub fn lines(&self) -> Vec<String> {
        self.text
            .lines()
            .map(|line| line.trim_end_matches('\r').to_string())
            .filter(|line| !line.is_empty())
            .collect()
    }
}

pub fn parse_policy(id: &str, text: &str) -> Result<Policy, String> {
    let mut version = None;
    let mut mode = None;
    let mut max_age = None;
    let mut mx = Vec::new();
    for line in text.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        match key.trim() {
            "version" => version = Some(value.to_string()),
            "mode" => {
                mode = Some(match value {
                    "enforce" => Mode::Enforce,
                    "testing" => Mode::Testing,
                    "none" => Mode::None,
                    other => return Err(format!("unknown mode {other:?}")),
                })
            }
            "max_age" => {
                let age: u64 = value
                    .parse()
                    .map_err(|_| format!("bad max_age {value:?}"))?;
                max_age = Some(age.min(MAX_AGE_LIMIT));
            }
            "mx" => mx.push(value.to_string()),
            _ => {}
        }
    }
    if version.as_deref() != Some("STSv1") {
        return Err("version is not STSv1".into());
    }
    let mode = mode.ok_or("no mode")?;
    let max_age = max_age.ok_or("no max_age")?;
    if mode != Mode::None && mx.is_empty() {
        return Err("no mx patterns".into());
    }
    Ok(Policy {
        id: id.to_string(),
        mode,
        mx,
        max_age,
        text: text.to_string(),
    })
}

#[async_trait]
pub trait PolicyFetcher: Send + Sync {
    /// The policy body for `domain`, or why it could not be fetched.
    async fn fetch(&self, domain: &str) -> Result<String, String>;
}

/// Fetches over HTTPS with WebPKI validation and no redirects.
pub struct HttpsFetcher {
    client: reqwest::Client,
}

impl HttpsFetcher {
    pub fn new(client: reqwest::Client) -> Self {
        Self { client }
    }
}

#[async_trait]
impl PolicyFetcher for HttpsFetcher {
    async fn fetch(&self, domain: &str) -> Result<String, String> {
        let url = format!("https://mta-sts.{domain}/.well-known/mta-sts.txt");
        let checked = super::outbound_tls::checked_url(&url)?;
        let mut response = self
            .client
            .get(checked)
            .send()
            .await
            .map_err(|err| format!("{url}: {err}"))?;
        if response.status() != reqwest::StatusCode::OK {
            return Err(format!("{url}: HTTP {}", response.status()));
        }
        let plain = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| {
                value
                    .split(';')
                    .next()
                    .is_some_and(|kind| kind.trim().eq_ignore_ascii_case("text/plain"))
            });
        if !plain {
            return Err(format!("{url}: content type is not text/plain"));
        }
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|err| format!("{url}: {err}"))?
        {
            body.extend_from_slice(&chunk);
            if body.len() > MAX_POLICY_BYTES {
                return Err(format!("{url}: policy larger than 64 KiB"));
            }
        }
        String::from_utf8(body).map_err(|_| format!("{url}: policy is not UTF-8"))
    }
}

/// What delivery should do for a domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Discovery {
    NoPolicy,
    Found(Arc<Policy>),
    /// A TXT record says a policy exists but none could be fetched or parsed,
    /// and nothing is cached. Delivery goes ahead without a policy; TLS-RPT
    /// reports the failure.
    Failed {
        result: ResultType,
        detail: String,
    },
}

/// How long a failed fetch is remembered before the next try.
const NEGATIVE_SECS: i64 = 300;

pub struct MtaSts {
    fetcher: Box<dyn PolicyFetcher>,
    db: PathBuf,
    /// One discovery per domain at a time; the others wait and use its result.
    inflight: dashmap::DashMap<String, Arc<tokio::sync::Mutex<()>>>,
    /// Recent fetch failures: until when, and what to report.
    failures: Mutex<HashMap<String, (i64, ResultType, String)>>,
}

impl MtaSts {
    pub fn new(fetcher: Box<dyn PolicyFetcher>, db: PathBuf) -> Self {
        Self {
            fetcher,
            db,
            inflight: dashmap::DashMap::new(),
            failures: Mutex::new(HashMap::new()),
        }
    }

    /// RFC 8461 section 5.1: a cached, unexpired policy wins unless the TXT
    /// id has changed. It is refreshed once half its max_age has passed, and
    /// a failed refresh keeps it.
    pub async fn discover(&self, domain: &str, dns: &dyn DnsLookup, now: i64) -> Discovery {
        let domain = normalise(domain);
        if !valid_domain(&domain) {
            return Discovery::NoPolicy;
        }
        let gate = Arc::clone(self.inflight.entry(domain.clone()).or_default().value());
        let held = gate.lock().await;
        let found = self.discover_one(&domain, dns, now).await;
        drop(held);
        // The map and `gate` are the only holders when nobody else waits.
        self.inflight
            .remove_if(&domain, |_, entry| Arc::strong_count(entry) <= 2);
        found
    }

    async fn discover_one(&self, domain: &str, dns: &dyn DnsLookup, now: i64) -> Discovery {
        let cached = match self.cached(domain, now).await {
            Ok(cached) => cached,
            Err(err) => {
                tracing::warn!(%err, %domain, "MTA-STS cache read failed");
                None
            }
        };
        let id = match dns.lookup_txt(&format!("_mta-sts.{domain}")).await {
            Ok(records) => txt_id(&records),
            Err(err) => {
                tracing::debug!(%err, %domain, "MTA-STS TXT lookup failed");
                None
            }
        };
        let Some(id) = id else {
            return found_or_none(cached.map(|(policy, _)| policy));
        };
        if let Some((policy, fetched_at)) = &cached {
            let fresh = now < fetched_at.saturating_add(policy.max_age as i64 / 2);
            if policy.id == id && fresh {
                return found_or_none(cached.map(|(policy, _)| policy));
            }
        }
        let recent_failure = self
            .failures
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .get(domain)
            .filter(|(until, _, _)| now < *until)
            .cloned();
        let fetched = match recent_failure {
            Some((_, result, detail)) => Err((result, detail)),
            None => {
                let fetched = match self.fetcher.fetch(domain).await {
                    Ok(text) => {
                        parse_policy(&id, &text).map_err(|err| (ResultType::StsPolicyInvalid, err))
                    }
                    Err(err) => Err((ResultType::StsPolicyFetchError, err)),
                };
                let mut failures = self.failures.lock().unwrap_or_else(|err| err.into_inner());
                match &fetched {
                    Ok(_) => {
                        failures.remove(domain);
                    }
                    Err((result, detail)) => {
                        tracing::info!(%domain, %detail, "MTA-STS policy unavailable");
                        failures.retain(|_, (until, _, _)| now < *until);
                        let until = now + NEGATIVE_SECS;
                        failures.insert(domain.to_string(), (until, *result, detail.clone()));
                    }
                }
                fetched
            }
        };
        match fetched {
            Ok(policy) => {
                if let Err(err) = self.store(domain, &policy, now).await {
                    tracing::warn!(%err, %domain, "MTA-STS cache write failed");
                }
                found_or_none(Some(policy))
            }
            Err((result, detail)) => match cached {
                Some((policy, _)) => found_or_none(Some(policy)),
                None => Discovery::Failed { result, detail },
            },
        }
    }

    /// The unexpired cached policy and when it was fetched.
    async fn cached(&self, domain: &str, now: i64) -> Result<Option<(Policy, i64)>, String> {
        let db = self.db.clone();
        let domain = domain.to_string();
        blocking(move || {
            let conn = open(&db)?;
            let row = conn.query_row(
                "SELECT id, policy, fetched_at FROM mta_sts_policy
                 WHERE domain = ?1 AND expires_at > ?2",
                rusqlite::params![domain, now],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            );
            match row {
                Ok((id, text, fetched_at)) => Ok(parse_policy(&id, &text)
                    .ok()
                    .map(|policy| (policy, fetched_at))),
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                Err(err) => Err(err.to_string()),
            }
        })
        .await
    }

    async fn store(&self, domain: &str, policy: &Policy, now: i64) -> Result<(), String> {
        let db = self.db.clone();
        let domain = domain.to_string();
        let policy = policy.clone();
        blocking(move || {
            let conn = open(&db)?;
            conn.execute(
                "INSERT INTO mta_sts_policy (domain, id, policy, fetched_at, expires_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(domain) DO UPDATE SET id = excluded.id, policy = excluded.policy,
                   fetched_at = excluded.fetched_at, expires_at = excluded.expires_at",
                rusqlite::params![
                    domain,
                    policy.id,
                    policy.text,
                    now,
                    now.saturating_add(policy.max_age as i64)
                ],
            )
            .map_err(|err| err.to_string())?;
            Ok(())
        })
        .await
    }
}

fn found_or_none(policy: Option<Policy>) -> Discovery {
    match policy {
        Some(policy) if policy.mode != Mode::None => Discovery::Found(Arc::new(policy)),
        _ => Discovery::NoPolicy,
    }
}

/// RFC 8461 section 3.1: exactly one `v=STSv1` record, else no policy.
fn txt_id(records: &[String]) -> Option<String> {
    let mut ids = records
        .iter()
        .filter(|record| record.starts_with("v=STSv1"))
        .filter_map(|record| StsRecord::parse(record.as_bytes()).ok())
        .map(|record| record.id);
    let id = ids.next()?;
    ids.next().is_none().then_some(id)
}

fn open(db: &std::path::Path) -> Result<Connection, String> {
    if let Some(parent) = db.parent() {
        std::fs::create_dir_all(parent).map_err(|err| err.to_string())?;
    }
    let conn = Connection::open(db).map_err(|err| err.to_string())?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS mta_sts_policy (
            domain TEXT PRIMARY KEY,
            id TEXT NOT NULL,
            policy TEXT NOT NULL,
            fetched_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL
        );",
    )
    .map_err(|err| err.to_string())?;
    Ok(conn)
}

async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, String> + Send + 'static,
) -> Result<T, String> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|err| err.to_string())?
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::MapDns;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex,
    };

    const POLICY: &str =
        "version: STSv1\r\nmode: enforce\r\nmx: mx.example.test\r\nmx: *.backup.example.test\r\nmax_age: 600\r\n";

    struct Fake {
        body: Mutex<Result<String, String>>,
        calls: AtomicUsize,
    }

    #[async_trait]
    impl PolicyFetcher for Arc<Fake> {
        async fn fetch(&self, _domain: &str) -> Result<String, String> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.body.lock().unwrap().clone()
        }
    }

    fn fake(body: Result<&str, &str>) -> Arc<Fake> {
        Arc::new(Fake {
            body: Mutex::new(body.map(str::to_string).map_err(str::to_string)),
            calls: AtomicUsize::new(0),
        })
    }

    fn dns(id: &str) -> MapDns {
        let mut dns = MapDns::new();
        dns.txt.insert(
            "_mta-sts.example.test".into(),
            vec![format!("v=STSv1; id={id};")],
        );
        dns
    }

    #[test]
    fn policy_parse_and_mx_patterns() {
        let policy = parse_policy("1", POLICY).unwrap();
        assert_eq!(policy.mode, Mode::Enforce);
        assert_eq!(policy.max_age, 600);
        assert!(policy.allows("MX.example.test."));
        assert!(policy.allows("a.backup.example.test"));
        assert!(!policy.allows("a.b.backup.example.test"));
        assert!(!policy.allows("backup.example.test"));
        assert!(!policy.allows("evil.test"));
        assert!(parse_policy("1", "version: STSv1\nmode: enforce\nmax_age: 1\n").is_err());
        assert!(parse_policy("1", "version: STSv2\nmode: none\nmax_age: 1\n").is_err());
        let capped = parse_policy("1", "version: STSv1\nmode: none\nmax_age: 99999999999\n");
        assert_eq!(capped.unwrap().max_age, MAX_AGE_LIMIT);
    }

    #[test]
    fn two_txt_records_mean_no_policy() {
        assert_eq!(txt_id(&["v=STSv1; id=a;".into()]), Some("a".into()));
        assert_eq!(
            txt_id(&["v=STSv1; id=a;".into(), "v=STSv1; id=b;".into()]),
            None
        );
        assert_eq!(txt_id(&["something else".into()]), None);
    }

    #[tokio::test]
    async fn cache_honours_max_age_and_id_changes() {
        let dir = tempfile::tempdir().unwrap();
        let fetcher = fake(Ok(POLICY));
        let sts = MtaSts::new(
            Box::new(Arc::clone(&fetcher)),
            dir.path().join("tls.sqlite"),
        );
        let found = sts.discover("example.test", &dns("1"), 1_000).await;
        assert!(matches!(found, Discovery::Found(_)), "{found:?}");
        let again = sts.discover("example.test", &dns("1"), 1_200).await;
        assert_eq!(again, found);
        assert_eq!(fetcher.calls.load(Ordering::SeqCst), 1, "cached");
        // Past half of max_age (300 s) the same id is refreshed early.
        sts.discover("example.test", &dns("1"), 1_301).await;
        assert_eq!(fetcher.calls.load(Ordering::SeqCst), 2, "refreshed");
        // TXT gone: the cached policy still applies until it expires.
        let gone = sts.discover("example.test", &MapDns::new(), 1_850).await;
        assert!(matches!(gone, Discovery::Found(_)));
        assert_eq!(
            sts.discover("example.test", &MapDns::new(), 1_902).await,
            Discovery::NoPolicy
        );
        // New id: fetched again.
        sts.discover("example.test", &dns("2"), 2_000).await;
        assert_eq!(fetcher.calls.load(Ordering::SeqCst), 3);
        // A failed refresh keeps the cached policy, and is not retried at
        // once.
        *fetcher.body.lock().unwrap() = Err("down".into());
        let kept = sts.discover("example.test", &dns("3"), 2_100).await;
        assert!(
            matches!(kept, Discovery::Found(ref p) if p.id == "2"),
            "{kept:?}"
        );
        sts.discover("example.test", &dns("3"), 2_200).await;
        assert_eq!(fetcher.calls.load(Ordering::SeqCst), 4, "negative cache");
        sts.discover("example.test", &dns("3"), 2_401).await;
        assert_eq!(fetcher.calls.load(Ordering::SeqCst), 5);
    }

    #[tokio::test]
    async fn concurrent_discoveries_fetch_once() {
        let dir = tempfile::tempdir().unwrap();
        let fetcher = fake(Ok(POLICY));
        let sts = MtaSts::new(
            Box::new(Arc::clone(&fetcher)),
            dir.path().join("tls.sqlite"),
        );
        let dns = dns("1");
        let runs = (0..8).map(|_| sts.discover("example.test", &dns, 1_000));
        let found = futures::future::join_all(runs).await;
        assert!(found.iter().all(|d| matches!(d, Discovery::Found(_))));
        assert_eq!(fetcher.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn fetch_failure_without_cache_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        let sts = MtaSts::new(
            Box::new(fake(Err("refused"))),
            dir.path().join("tls.sqlite"),
        );
        let found = sts.discover("example.test", &dns("1"), 1_000).await;
        assert!(matches!(
            found,
            Discovery::Failed {
                result: ResultType::StsPolicyFetchError,
                ..
            }
        ));
        let sts = MtaSts::new(Box::new(fake(Ok("junk"))), dir.path().join("tls.sqlite"));
        let found = sts.discover("example.test", &dns("1"), 1_000).await;
        assert!(matches!(
            found,
            Discovery::Failed {
                result: ResultType::StsPolicyInvalid,
                ..
            }
        ));
    }
}
