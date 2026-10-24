//! RFC 9224 bootstrap and RFC 9083 registration events; no message content.
use crate::{
    host_matches,
    http::{Http, SafeHttp},
    registrable,
};
use currawong_core::config::RdapConfig;
use rusqlite::{params, Connection, OptionalExtension};
use serde::Deserialize;
use std::{
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use tokio::sync::{Mutex as AsyncMutex, Semaphore};
use url::Url;

#[derive(Debug, Clone, Deserialize)]
struct Bootstrap {
    services: Vec<(Vec<String>, Vec<String>)>,
}
impl Bootstrap {
    fn endpoint(&self, domain: &str) -> Option<Url> {
        self.services
            .iter()
            .flat_map(|(names, urls)| names.iter().map(move |name| (name, urls)))
            .filter(|(name, _)| host_matches(domain, name))
            .max_by_key(|(name, _)| name.len())
            .and_then(|(_, urls)| {
                urls.iter()
                    .filter_map(|u| Url::parse(u).ok())
                    .find(|u| u.scheme() == "https")
            })
    }
}
pub struct Rdap {
    cfg: RdapConfig,
    db: Mutex<Connection>,
    http: Arc<dyn Http>,
    slots: Semaphore,
    bootstrap_lock: AsyncMutex<()>,
}
impl Rdap {
    pub fn open(cfg: &RdapConfig) -> Result<Self, String> {
        Self::init(
            cfg,
            Connection::open(&cfg.database).map_err(|e| e.to_string())?,
            Arc::new(SafeHttp::new(vec![443], cfg.timeout_secs)),
        )
    }
    fn init(cfg: &RdapConfig, db: Connection, http: Arc<dyn Http>) -> Result<Self, String> {
        db.busy_timeout(Duration::from_millis(100))
            .map_err(|e| e.to_string())?;
        db.execute_batch("PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS rdap_cache (key TEXT PRIMARY KEY, registered INTEGER, expires INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS rdap_bootstrap (url TEXT PRIMARY KEY, json TEXT NOT NULL, expires INTEGER NOT NULL);").map_err(|e| e.to_string())?;
        Ok(Self {
            cfg: cfg.clone(),
            db: Mutex::new(db),
            http,
            slots: Semaphore::new(cfg.concurrency),
            bootstrap_lock: AsyncMutex::new(()),
        })
    }
    /// Own domains and all their subdomains are skipped before DNS or cache access.
    /// `None` means unknown, never old or safe. Errors do not fabricate an age.
    pub async fn age_days(&self, host: &str, own: &[String]) -> Result<Option<u64>, String> {
        self.age_days_until(
            host,
            own,
            tokio::time::Instant::now() + Duration::from_secs(self.cfg.timeout_secs),
        )
        .await
    }
    /// A caller's shorter whole-pass deadline still permits a negative-cache
    /// write after the timed-out network future is dropped.
    pub async fn age_days_until(
        &self,
        host: &str,
        own: &[String],
        deadline: tokio::time::Instant,
    ) -> Result<Option<u64>, String> {
        if !self.cfg.enabled
            || own.iter().any(|d| {
                host_matches(host, d)
                    || registrable(host).is_some_and(|h| registrable(d).as_ref() == Some(&h))
            })
        {
            return Ok(None);
        }
        let Some(domain) = registrable(host) else {
            return Ok(None);
        };
        let deadline =
            deadline.min(tokio::time::Instant::now() + Duration::from_secs(self.cfg.timeout_secs));
        let _slot = tokio::time::timeout_at(deadline, self.slots.acquire())
            .await
            .map_err(|_| "RDAP concurrency deadline exceeded")?
            .map_err(|_| "RDAP stopped")?;
        let key = format!("{}|{domain}", self.cfg.bootstrap_url);
        let now = now();
        let cached: Option<Option<i64>> = self
            .db
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .query_row(
                "SELECT registered FROM rdap_cache WHERE key=?1 AND expires>?2",
                params![key, now],
                |r| r.get(0),
            )
            .optional()
            .map_err(|e| e.to_string())?;
        if let Some(date) = cached {
            return Ok(age(date, now));
        }
        let result = tokio::time::timeout_at(deadline, self.lookup(&domain, now))
            .await
            .unwrap_or_else(|_| Err("RDAP deadline exceeded".into()));
        let date = result.as_ref().ok().copied().flatten();
        let ttl = if date.is_some() {
            self.cfg.positive_ttl_days * 86400
        } else {
            self.cfg.negative_ttl_hours * 3600
        };
        let db = self.db.lock().unwrap_or_else(|p| p.into_inner());
        db.execute("DELETE FROM rdap_cache WHERE expires<=?1", [now])
            .map_err(|e| e.to_string())?;
        db.execute(
            "INSERT OR REPLACE INTO rdap_cache(key,registered,expires) VALUES(?1,?2,?3)",
            params![key, date, now.saturating_add(ttl as i64)],
        )
        .map_err(|e| e.to_string())?;
        result.map(|d| age(d, now))
    }
    async fn bootstrap(&self, now: i64) -> Result<Bootstrap, String> {
        let _refresh = self.bootstrap_lock.lock().await;
        let cached: Option<String> = self
            .db
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .query_row(
                "SELECT json FROM rdap_bootstrap WHERE url=?1 AND expires>?2",
                params![self.cfg.bootstrap_url, now],
                |r| r.get(0),
            )
            .optional()
            .map_err(|e| e.to_string())?;
        if let Some(json) = cached {
            return serde_json::from_str(&json).map_err(|e| e.to_string());
        }
        let response = self
            .http
            .get(
                &Url::parse(&self.cfg.bootstrap_url).map_err(|e| e.to_string())?,
                1024 * 1024,
            )
            .await?;
        if response.status != 200 {
            return Err(format!("RDAP bootstrap HTTP {}", response.status));
        }
        let json = String::from_utf8(response.body).map_err(|_| "RDAP bootstrap is not UTF-8")?;
        let bootstrap: Bootstrap = serde_json::from_str(&json).map_err(|e| e.to_string())?;
        if bootstrap.services.is_empty() {
            return Err("RDAP bootstrap has no services".into());
        }
        self.db
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .execute(
                "INSERT OR REPLACE INTO rdap_bootstrap(url,json,expires) VALUES(?1,?2,?3)",
                params![
                    self.cfg.bootstrap_url,
                    json,
                    now + (self.cfg.bootstrap_ttl_hours * 3600) as i64
                ],
            )
            .map_err(|e| e.to_string())?;
        Ok(bootstrap)
    }
    async fn lookup(&self, domain: &str, now: i64) -> Result<Option<i64>, String> {
        let bootstrap = self.bootstrap(now).await?;
        let Some(mut base) = bootstrap.endpoint(domain) else {
            return Ok(None);
        };
        // The base can include a path (e.g. /rdap/). Never replace that prefix.
        base.set_query(None);
        base.set_fragment(None);
        base.path_segments_mut()
            .map_err(|_| "invalid RDAP base")?
            .pop_if_empty()
            .push("domain")
            .push(domain);
        let response = self.http.get(&base, 1024 * 1024).await?;
        if response.status == 404 {
            return Ok(None);
        }
        if response.status != 200 {
            return Err(format!("RDAP HTTP {}", response.status));
        }
        registration(&response.body, domain, now)
    }
}
fn age(date: Option<i64>, now: i64) -> Option<u64> {
    date.filter(|d| *d <= now)
        .map(|d| ((now - d) / 86400) as u64)
}
fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}
fn registration(body: &[u8], domain: &str, now: i64) -> Result<Option<i64>, String> {
    #[derive(Deserialize)]
    struct Domain {
        #[serde(rename = "ldhName")]
        name: String,
        #[serde(default)]
        events: Vec<Event>,
    }
    #[derive(Deserialize)]
    struct Event {
        #[serde(rename = "eventAction")]
        action: String,
        #[serde(rename = "eventDate")]
        date: String,
    }
    let value: Domain = serde_json::from_slice(body).map_err(|e| e.to_string())?;
    if !value
        .name
        .trim_end_matches('.')
        .eq_ignore_ascii_case(domain)
    {
        return Err("RDAP returned another domain".into());
    }
    Ok(value
        .events
        .iter()
        .filter(|e| e.action == "registration")
        .filter_map(|e| {
            OffsetDateTime::parse(&e.date, &Rfc3339)
                .ok()
                .map(|d| d.unix_timestamp())
        })
        .filter(|d| *d <= now)
        .min())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::tests::{local_http, server};
    #[test]
    fn bootstrap_real_shape_longest_match_and_registration_only() {
        let bootstrap: Bootstrap = serde_json::from_str(r#"{"version":"1.0","services":[[["au"],["http://insecure.test/","https://rdap.test/rdap/"]],[["com.au"],["https://specific.test/"]]]}"#).unwrap();
        assert_eq!(
            bootstrap.endpoint("sub.example.com.au").unwrap().host_str(),
            Some("specific.test")
        );
        assert!(bootstrap.endpoint("notau").is_none());
        assert_eq!(
            registrable("www.example.com.au"),
            Some("example.com.au".into())
        );
        assert_eq!(registration(br#"{"ldhName":"example.com","events":[{"eventAction":"last changed","eventDate":"2020-01-01T00:00:00Z"}]}"#, "example.com", now()).unwrap(), None);
        assert!(registration(br#"{"ldhName":"other.com"}"#, "example.com", now()).is_err());
    }
    // Transport maps the HTTPS bootstrap-selected base onto the local fake.
    struct FakeHttp {
        local: Arc<dyn Http>,
        base: Url,
        bootstrap: Vec<u8>,
        calls: std::sync::atomic::AtomicUsize,
    }
    #[async_trait::async_trait]
    impl Http for FakeHttp {
        async fn get(&self, url: &Url, cap: usize) -> Result<crate::http::Reply, String> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if url.path().ends_with("/dns.json") {
                return Ok(crate::http::Reply {
                    status: 200,
                    location: None,
                    body: self.bootstrap.clone(),
                });
            }
            assert!(url.path().starts_with("/rdap/domain/"));
            self.local
                .get(&self.base.join(url.path()).unwrap(), cap)
                .await
        }
    }
    #[tokio::test]
    async fn fake_rdap_positive_negative_cache_own_domain_and_refresh() {
        let date = OffsetDateTime::now_utc() - time::Duration::days(3);
        let body = serde_json::json!({"ldhName":"example.com.au","events":[{"eventAction":"registration","eventDate":date.format(&Rfc3339).unwrap()}]}).to_string();
        let (addr, task) = server(body).await;
        let http = Arc::new(FakeHttp {
            local: Arc::new(local_http(addr)),
            base: Url::parse(&format!("http://{addr}/")).unwrap(),
            bootstrap: br#"{"services":[[["au"],["https://rdap.invalid/rdap/"]]]}"#.to_vec(),
            calls: 0.into(),
        });
        let cfg = RdapConfig {
            enabled: true,
            ..Default::default()
        };
        let rdap = Rdap::init(&cfg, Connection::open_in_memory().unwrap(), http.clone()).unwrap();
        assert_eq!(
            rdap.age_days("www.own.com.au", &["own.com.au".into()])
                .await
                .unwrap(),
            None
        );
        assert_eq!(http.calls.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(
            rdap.age_days("www.example.com.au", &[]).await.unwrap(),
            Some(3)
        );
        assert_eq!(rdap.age_days("example.com.au", &[]).await.unwrap(), Some(3));
        assert_eq!(rdap.age_days("missing.net", &[]).await.unwrap(), None);
        assert_eq!(rdap.age_days("missing.net", &[]).await.unwrap(), None);
        assert_eq!(http.calls.load(std::sync::atomic::Ordering::SeqCst), 2);
        rdap.db
            .lock()
            .unwrap()
            .execute_batch("UPDATE rdap_bootstrap SET expires=0; UPDATE rdap_cache SET expires=0;")
            .unwrap();
        assert_eq!(rdap.age_days("example.com.au", &[]).await.unwrap(), Some(3));
        assert_eq!(http.calls.load(std::sync::atomic::Ordering::SeqCst), 4);
        task.abort();
    }
    struct SlowHttp {
        active: std::sync::atomic::AtomicUsize,
        maximum: std::sync::atomic::AtomicUsize,
        calls: std::sync::atomic::AtomicUsize,
        hang: bool,
    }
    #[async_trait::async_trait]
    impl Http for SlowHttp {
        async fn get(&self, url: &Url, _: usize) -> Result<crate::http::Reply, String> {
            use std::sync::atomic::Ordering::SeqCst;
            self.calls.fetch_add(1, SeqCst);
            if self.hang {
                std::future::pending::<()>().await;
            }
            let reply = if url.path().ends_with("/dns.json") {
                br#"{"services":[[["com"],["https://rdap.invalid/"]]]}"#.to_vec()
            } else {
                let active = self.active.fetch_add(1, SeqCst) + 1;
                self.maximum.fetch_max(active, SeqCst);
                tokio::time::sleep(Duration::from_millis(10)).await;
                self.active.fetch_sub(1, SeqCst);
                let domain = url.path().rsplit('/').next().unwrap();
                serde_json::json!({"ldhName":domain,"events":[{"eventAction":"registration","eventDate":"2020-01-01T00:00:00Z"}]}).to_string().into_bytes()
            };
            Ok(crate::http::Reply {
                status: 200,
                location: None,
                body: reply,
            })
        }
    }
    #[tokio::test]
    async fn rdap_concurrency_and_timeout_negative_cache() {
        use std::sync::atomic::Ordering::SeqCst;
        let cfg = RdapConfig {
            enabled: true,
            concurrency: 1,
            timeout_secs: 1,
            ..Default::default()
        };
        let http = Arc::new(SlowHttp {
            active: 0.into(),
            maximum: 0.into(),
            calls: 0.into(),
            hang: false,
        });
        let rdap = Arc::new(
            Rdap::init(&cfg, Connection::open_in_memory().unwrap(), http.clone()).unwrap(),
        );
        let mut tasks = Vec::new();
        for i in 0..4 {
            let rdap = rdap.clone();
            tasks.push(tokio::spawn(async move {
                rdap.age_days(&format!("example{i}.com"), &[])
                    .await
                    .unwrap()
            }));
        }
        for task in tasks {
            assert!(task.await.unwrap().is_some());
        }
        assert_eq!(http.maximum.load(SeqCst), 1);
        let http = Arc::new(SlowHttp {
            active: 0.into(),
            maximum: 0.into(),
            calls: 0.into(),
            hang: true,
        });
        let rdap = Rdap::init(&cfg, Connection::open_in_memory().unwrap(), http.clone()).unwrap();
        assert!(rdap
            .age_days_until(
                "timeout.com",
                &[],
                tokio::time::Instant::now() + Duration::from_millis(50)
            )
            .await
            .unwrap_err()
            .contains("deadline"));
        assert_eq!(rdap.age_days("timeout.com", &[]).await.unwrap(), None);
        assert_eq!(http.calls.load(SeqCst), 1);
    }
}
