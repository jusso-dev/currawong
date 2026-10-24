//! Feed downloads. HTTPS only, redirects only to HTTPS, a size cap before
//! and after decompression, a whole-download timeout, and conditional GET
//! (ETag, Last-Modified). Nothing about any message is sent: a request
//! carries the feed key, if any, and our user agent.
//!
//! A failed download, a body that does not parse, or one with no usable
//! indicators keeps the feed's previous data and records the error.
use crate::{formats, read_key, store::Store, Kind};
use currawong_core::config::{FeedFormat, IntelConfig, IntelFeedConfig};
use reqwest::{
    header::{HeaderMap, HeaderName, HeaderValue},
    StatusCode,
};
use std::{io::Read, path::Path, sync::Arc, time::Duration};

/// TAXII pages followed per sync.
const MAX_TAXII_PAGES: usize = 100;
/// Failed feeds are tried again after at most this long.
const RETRY_SECS: u64 = 300;
const USER_AGENT: &str = concat!(
    "currawong/",
    env!("CARGO_PKG_VERSION"),
    " (+https://github.com/jusso-dev/currawong)"
);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncOutcome {
    Updated { indicators: usize, rejected: usize },
    NotModified,
}

pub struct Syncer {
    client: reqwest::Client,
    store: Arc<Store>,
    cfg: IntelConfig,
}

enum Fetched {
    NotModified,
    Body {
        bytes: Vec<u8>,
        etag: Option<String>,
        last_modified: Option<String>,
    },
}

impl Syncer {
    pub fn new(cfg: &IntelConfig, store: Arc<Store>) -> Result<Self, String> {
        Ok(Self {
            client: http_client(cfg.ca_file.as_deref(), cfg.timeout_secs)?,
            store,
            cfg: cfg.clone(),
        })
    }

    pub fn store(&self) -> &Arc<Store> {
        &self.store
    }

    /// Sync every enabled feed that is due (all of them when `force`), after
    /// dropping feeds no longer configured. One feed's failure does not stop
    /// the others.
    pub async fn sync_due(&self, force: bool) -> Vec<(String, Result<SyncOutcome, String>)> {
        let keep: Vec<&str> = self
            .cfg
            .feeds
            .iter()
            .filter(|feed| feed.enabled)
            .map(|feed| feed.name.as_str())
            .collect();
        let store = Arc::clone(&self.store);
        let keep_owned: Vec<String> = keep.iter().map(|s| s.to_string()).collect();
        let retained = tokio::task::spawn_blocking(move || {
            let keep: Vec<&str> = keep_owned.iter().map(String::as_str).collect();
            store.retain_sources(&keep)
        })
        .await;
        match retained {
            Ok(Ok(0)) => {}
            Ok(Ok(removed)) => {
                tracing::info!(removed, "intel: indicators of removed feeds dropped")
            }
            Ok(Err(err)) => tracing::warn!(%err, "intel: removed feeds not cleared"),
            Err(err) => tracing::warn!(%err, "intel: removed feeds not cleared"),
        }
        let mut results = Vec::new();
        for feed in self.cfg.feeds.iter().filter(|feed| feed.enabled) {
            let now = crate::now();
            if !force && !self.due(feed, now) {
                continue;
            }
            let result = self.sync_feed(feed, now).await;
            results.push((feed.name.clone(), result));
        }
        results
    }

    fn due(&self, feed: &IntelFeedConfig, now: i64) -> bool {
        let Ok(Some(status)) = self.store.status(&feed.name) else {
            return true;
        };
        let Some(attempt) = status.last_attempt else {
            return true;
        };
        let wait = if status.last_error.is_some() {
            feed.refresh_secs.min(RETRY_SECS)
        } else {
            feed.refresh_secs
        };
        now - attempt >= wait as i64
    }

    /// Enabled feeds with no good sync for `stale_after_refreshes` refresh
    /// periods, with the time of their last good sync.
    pub fn stale_feeds(&self, now: i64) -> Vec<(String, Option<i64>)> {
        let periods = i64::from(self.cfg.stale_after_refreshes.max(1));
        self.cfg
            .feeds
            .iter()
            .filter(|feed| feed.enabled)
            .filter_map(|feed| {
                let last = self
                    .store
                    .status(&feed.name)
                    .ok()
                    .flatten()
                    .and_then(|status| status.last_success);
                let limit = feed.refresh_secs as i64 * periods;
                last.is_none_or(|at| now - at > limit)
                    .then(|| (feed.name.clone(), last))
            })
            .collect()
    }

    /// Download, parse and store one feed. Failures are recorded on the
    /// feed and leave its indicators as they were.
    pub async fn sync_feed(&self, feed: &IntelFeedConfig, now: i64) -> Result<SyncOutcome, String> {
        let result = self.try_sync(feed, now).await;
        let store = Arc::clone(&self.store);
        let name = feed.name.clone();
        match &result {
            Ok(SyncOutcome::Updated {
                indicators,
                rejected,
            }) => {
                tracing::info!(feed = %name, indicators, rejected, "intel feed synced")
            }
            Ok(SyncOutcome::NotModified) => {
                let _ = tokio::task::spawn_blocking(move || store.record_not_modified(&name, now))
                    .await;
                tracing::debug!(feed = %feed.name, "intel feed not modified");
            }
            Err(err) => {
                tracing::warn!(feed = %name, %err, "intel feed sync failed, keeping the previous data");
                let err = err.clone();
                let _ = tokio::task::spawn_blocking(move || store.record_failure(&name, now, &err))
                    .await;
            }
        }
        result
    }

    async fn try_sync(&self, feed: &IntelFeedConfig, now: i64) -> Result<SyncOutcome, String> {
        let key = read_key(feed.key_env.as_deref(), feed.key_file.as_deref())
            .map_err(|err| format!("feed key: {err}"))?;
        let url = match &key {
            Some(key) if feed.url.contains("{key}") => {
                if !key
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b))
                {
                    return Err("feed key has characters that cannot go in a URL".into());
                }
                feed.url.replace("{key}", key)
            }
            _ => feed.url.clone(),
        };
        let mut headers = HeaderMap::new();
        if let (Some(name), Some(key)) = (&feed.auth_header, &key) {
            let name = HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| "auth_header is not a header name".to_string())?;
            let mut value = HeaderValue::from_str(key)
                .map_err(|_| "feed key is not a valid header value".to_string())?;
            value.set_sensitive(true);
            headers.insert(name, value);
        }
        let kind = feed.kind.as_deref().and_then(Kind::parse);
        let threat = feed.threat.clone();
        let format = feed.format;
        let (parsed, etag, last_modified) = if format == FeedFormat::Taxii {
            let parsed = self.fetch_taxii(&url, headers, threat.clone(), now).await?;
            (parsed, None, None)
        } else {
            let status = {
                let store = Arc::clone(&self.store);
                let name = feed.name.clone();
                tokio::task::spawn_blocking(move || store.status(&name))
                    .await
                    .map_err(|err| err.to_string())??
            };
            if let Some(status) = status.filter(|s| s.indicators > 0) {
                if let Some(etag) = status.etag.and_then(|v| HeaderValue::from_str(&v).ok()) {
                    headers.insert(reqwest::header::IF_NONE_MATCH, etag);
                }
                if let Some(since) = status
                    .last_modified
                    .and_then(|v| HeaderValue::from_str(&v).ok())
                {
                    headers.insert(reqwest::header::IF_MODIFIED_SINCE, since);
                }
            }
            let (bytes, etag, last_modified) = match self.fetch(&url, headers).await? {
                Fetched::NotModified => return Ok(SyncOutcome::NotModified),
                Fetched::Body {
                    bytes,
                    etag,
                    last_modified,
                } => (bytes, etag, last_modified),
            };
            let max = self.cfg.max_download_bytes;
            let parsed = tokio::task::spawn_blocking(move || {
                let body = decompress(bytes, max)?;
                formats::parse(format, &body, kind, threat.as_deref(), now)
            })
            .await
            .map_err(|err| err.to_string())??;
            (parsed, etag, last_modified)
        };
        let accepted = parsed.indicators.len();
        if parsed.rejected > accepted {
            return Err(format!(
                "{} of {} records are not indicators; keeping the previous data",
                parsed.rejected,
                parsed.rejected + accepted
            ));
        }
        if accepted == 0 && !matches!(format, FeedFormat::Taxii | FeedFormat::StixBundle) {
            return Err("feed returned no indicators; keeping the previous data".into());
        }
        let store = Arc::clone(&self.store);
        let name = feed.name.clone();
        let rejected = parsed.rejected;
        let stored = tokio::task::spawn_blocking(move || {
            store.replace_source(
                &name,
                &parsed.indicators,
                now,
                etag.as_deref(),
                last_modified.as_deref(),
            )
        })
        .await
        .map_err(|err| err.to_string())??;
        Ok(SyncOutcome::Updated {
            indicators: stored,
            rejected,
        })
    }

    /// One GET, capped at `max_download_bytes`.
    async fn fetch(&self, url: &str, headers: HeaderMap) -> Result<Fetched, String> {
        let response = self
            .client
            .get(url)
            .headers(headers)
            .send()
            .await
            .map_err(describe)?;
        let status = response.status();
        if status == StatusCode::NOT_MODIFIED {
            return Ok(Fetched::NotModified);
        }
        if !status.is_success() {
            return Err(format!("HTTP {status}"));
        }
        let header = |name: reqwest::header::HeaderName| {
            response
                .headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        };
        let etag = header(reqwest::header::ETAG);
        let last_modified = header(reqwest::header::LAST_MODIFIED);
        let max = self.cfg.max_download_bytes;
        if response.content_length().is_some_and(|len| len > max) {
            return Err(format!("download is larger than {max} bytes"));
        }
        let mut response = response;
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(describe)? {
            if bytes.len() as u64 + chunk.len() as u64 > max {
                return Err(format!("download is larger than {max} bytes"));
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(Fetched::Body {
            bytes,
            etag,
            last_modified,
        })
    }

    /// A TAXII 2.1 collection's objects, following `next` while `more` is
    /// set. The size cap covers all pages together.
    async fn fetch_taxii(
        &self,
        url: &str,
        mut headers: HeaderMap,
        threat: Option<String>,
        now: i64,
    ) -> Result<formats::Parsed, String> {
        headers.insert(
            reqwest::header::ACCEPT,
            HeaderValue::from_static("application/taxii+json;version=2.1"),
        );
        let base = url::Url::parse(url).map_err(|_| "TAXII url is not a URL".to_string())?;
        let mut parsed = formats::Parsed::default();
        let mut next: Option<String> = None;
        let mut total = 0u64;
        for _ in 0..MAX_TAXII_PAGES {
            let mut page_url = base.clone();
            if let Some(next) = &next {
                let kept: Vec<(String, String)> = base
                    .query_pairs()
                    .filter(|(k, _)| k != "next")
                    .map(|(k, v)| (k.into_owned(), v.into_owned()))
                    .collect();
                page_url.query_pairs_mut().clear().extend_pairs(kept);
                page_url.query_pairs_mut().append_pair("next", next);
            }
            let bytes = match self.fetch(page_url.as_str(), headers.clone()).await? {
                Fetched::Body { bytes, .. } => bytes,
                Fetched::NotModified => return Err("TAXII server answered 304".into()),
            };
            total += bytes.len() as u64;
            if total > self.cfg.max_download_bytes {
                return Err(format!(
                    "TAXII collection is larger than {} bytes",
                    self.cfg.max_download_bytes
                ));
            }
            next = formats::taxii_next(&bytes);
            let threat = threat.clone();
            let page = tokio::task::spawn_blocking(move || {
                formats::parse(FeedFormat::Taxii, &bytes, None, threat.as_deref(), now)
            })
            .await
            .map_err(|err| err.to_string())??;
            parsed.indicators.extend(page.indicators);
            parsed.rejected += page.rejected;
            if next.is_none() {
                return Ok(parsed);
            }
        }
        Err(format!(
            "TAXII collection has more than {MAX_TAXII_PAGES} pages"
        ))
    }
}

/// The error without its URL, which may hold a feed key.
fn describe(err: reqwest::Error) -> String {
    let err = err.without_url();
    let mut text = err.to_string();
    let mut source = std::error::Error::source(&err);
    while let Some(cause) = source {
        text.push_str(": ");
        text.push_str(&cause.to_string());
        source = cause.source();
    }
    text
}

/// gzip and zip (the first file) bodies are unpacked, within the same cap.
fn decompress(bytes: Vec<u8>, max: u64) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let read = if bytes.starts_with(&[0x1f, 0x8b]) {
        flate2::read::MultiGzDecoder::new(bytes.as_slice())
            .take(max + 1)
            .read_to_end(&mut out)
            .map_err(|err| format!("gzip: {err}"))?
    } else if bytes.starts_with(b"PK\x03\x04") {
        let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes))
            .map_err(|err| format!("zip: {err}"))?;
        let file = archive.by_index(0).map_err(|err| format!("zip: {err}"))?;
        let read = file
            .take(max + 1)
            .read_to_end(&mut out)
            .map_err(|err| format!("zip: {err}"))?;
        read
    } else {
        return Ok(bytes);
    };
    if read as u64 > max {
        return Err(format!("feed unpacks to more than {max} bytes"));
    }
    Ok(out)
}

/// HTTPS with public web roots plus an optional private CA (PEM). No
/// redirects except to HTTPS, at most five.
pub fn http_client(ca_file: Option<&Path>, timeout_secs: u64) -> Result<reqwest::Client, String> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(path) = ca_file {
        let pem = std::fs::read(path).map_err(|err| format!("{}: {err}", path.display()))?;
        for cert in rustls_pemfile::certs(&mut pem.as_slice()) {
            let cert = cert.map_err(|err| format!("{}: {err}", path.display()))?;
            roots
                .add(cert)
                .map_err(|err| format!("{}: {err}", path.display()))?;
        }
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|err| err.to_string())?
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    let policy = reqwest::redirect::Policy::custom(|attempt| {
        if attempt.previous().len() >= 5 {
            attempt.error("too many redirects")
        } else if attempt.url().scheme() != "https" {
            attempt.error("redirect to a non-https URL refused")
        } else {
            attempt.follow()
        }
    });
    reqwest::Client::builder()
        .tls_backend_preconfigured(tls)
        .https_only(true)
        .redirect(policy)
        .user_agent(USER_AGENT)
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(timeout_secs.max(1)))
        .build()
        .map_err(|err| err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn intel_decompress_caps_gzip_and_zip() {
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(&[b'a'; 4096]).unwrap();
        let gz = gz.finish().unwrap();
        assert_eq!(decompress(gz.clone(), 4096).unwrap().len(), 4096);
        assert!(decompress(gz, 4095).unwrap_err().contains("more than"));

        let mut zipped = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        zipped
            .start_file("full.csv", zip::write::SimpleFileOptions::default())
            .unwrap();
        zipped.write_all(b"url\nhttps://x.example/\n").unwrap();
        let zipped = zipped.finish().unwrap().into_inner();
        assert_eq!(
            decompress(zipped, 1024).unwrap(),
            b"url\nhttps://x.example/\n"
        );
        assert_eq!(decompress(b"plain".to_vec(), 1024).unwrap(), b"plain");
    }
}
