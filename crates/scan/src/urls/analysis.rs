//! Optional layered click analysis. Every wrapper/fetch hop is checked live.
use super::{CheckedUrl, Reputation, UrlReputation};
use async_trait::async_trait;
use currawong_core::{config::ClickConfig, ResidencyGuard};
use currawong_link::{
    host_matches,
    http::{self, Http, SafeHttp},
    rdap::Rdap,
    registrable,
    unwrap::unwrap,
};
use lol_html::{element, rewrite_str, RewriteStrSettings};
use serde::Deserialize;
use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, Instant},
};
use tokio::sync::Semaphore;
use url::Url;

#[derive(Clone)]
struct Cached {
    at: Instant,
    checked: CheckedUrl,
    hops: Vec<String>,
}
pub struct ClickAnalysis {
    cfg: ClickConfig,
    reputation: Arc<dyn UrlReputation>,
    http: Arc<dyn Http>,
    rdap: Option<Arc<Rdap>>,
    own: Vec<String>,
    new_domain_days: u64,
    guard: Arc<ResidencyGuard>,
    cache: Mutex<HashMap<String, Cached>>,
    slots: Semaphore,
}
impl ClickAnalysis {
    pub fn new(
        cfg: &ClickConfig,
        reputation: Arc<dyn UrlReputation>,
        guard: Arc<ResidencyGuard>,
    ) -> Self {
        Self {
            cfg: cfg.clone(),
            reputation,
            http: Arc::new(SafeHttp::new(
                cfg.fetch.ports.clone(),
                cfg.fetch.timeout_secs,
            )),
            rdap: None,
            own: Vec::new(),
            new_domain_days: 30,
            guard,
            cache: Mutex::new(HashMap::new()),
            slots: Semaphore::new(cfg.fetch.concurrency),
        }
    }
    pub fn with_rdap(mut self, rdap: Arc<Rdap>, own: Vec<String>, new_domain_days: u64) -> Self {
        self.rdap = Some(rdap);
        self.own = own;
        self.new_domain_days = new_domain_days;
        self
    }
    async fn run(&self, original: &str, deadline: tokio::time::Instant) -> Cached {
        let mut verdict = Findings::default();
        let mut hops = Vec::new();
        let mut current = match Url::parse(original) {
            Ok(url) => url,
            Err(_) => return cached(original, verdict.block("invalid URL"), hops),
        };
        let mut seen = HashSet::new();
        let mut html = Vec::new();
        let mut remaining = self.cfg.fetch.max_bytes;
        // One common budget covers unwrapping, HTTP redirects and meta refresh.
        for hop in 0..=self.cfg.max_hops {
            let raw = current.as_str().to_string();
            if raw.len() > super::token::MAX_TOKEN_BYTES {
                return cached(&raw, verdict.block("redirect URL exceeds size limit"), hops);
            }
            if !seen.insert(raw.clone()) {
                return cached(&raw, verdict.block("redirect loop"), hops);
            }
            hops.push(raw.clone());
            if !matches!(current.scheme(), "http" | "https")
                || !current.username().is_empty()
                || current.password().is_some()
                || current.host_str().is_none()
            {
                return cached(
                    &raw,
                    verdict.block("unsafe link scheme or credentials"),
                    hops,
                );
            }
            match tokio::time::timeout_at(deadline, self.reputation.check(&raw)).await {
                Ok(result) => verdict.add(result),
                Err(_) => return cached(&raw, verdict.block("reputation deadline exceeded"), hops),
            }
            if verdict.blocked {
                return cached(&raw, verdict, hops);
            }
            let next = if self.cfg.unwrap {
                match unwrap(&current, &self.cfg.redirector_domains) {
                    Ok(next) => next,
                    Err(error) => {
                        return cached(
                            &raw,
                            verdict.block(&format!("wrapper could not be checked: {error}")),
                            hops,
                        )
                    }
                }
            } else {
                None
            };
            if let Some(next) = next {
                if hop == self.cfg.max_hops {
                    return cached(&raw, verdict.block("redirect hop limit reached"), hops);
                }
                current = next;
                continue;
            }
            if let Some(rdap) = &self.rdap {
                if let Some(host) = current.host_str() {
                    match rdap.age_days_until(host, &self.own, deadline).await {
                        Ok(Some(days)) if days < self.new_domain_days => {
                            verdict.warn(&format!("domain registered {days} days ago"))
                        }
                        Err(_) => verdict.warn("domain registration age unavailable"),
                        _ => {}
                    }
                }
            }
            if !self.cfg.fetch.enabled {
                break;
            }
            if let Err(error) = http::validate_url(&current, &self.cfg.fetch.ports) {
                return cached(&raw, verdict.block(&error), hops);
            }
            let result = tokio::time::timeout_at(deadline, self.http.get(&current, remaining))
                .await
                .unwrap_or_else(|_| Err("page deadline exceeded".into()));
            let reply = match result {
                Ok(reply) => reply,
                Err(error) if error.contains("SSRF") => {
                    return cached(&raw, verdict.block(&error), hops)
                }
                Err(error) => {
                    verdict.warn(&format!("page could not be checked: {error}"));
                    break;
                }
            };
            remaining = remaining.saturating_sub(reply.body.len());
            if matches!(reply.status, 301 | 302 | 303 | 307 | 308) {
                let next = reply
                    .location
                    .as_deref()
                    .ok_or("redirect has no location")
                    .and_then(|l| current.join(l).map_err(|_| "invalid redirect"));
                match next {
                    Ok(next) if hop < self.cfg.max_hops => {
                        current = next;
                        continue;
                    }
                    Ok(_) => {
                        return cached(&raw, verdict.block("redirect hop limit reached"), hops)
                    }
                    Err(error) => return cached(&raw, verdict.block(error), hops),
                }
            }
            if !(200..300).contains(&reply.status) {
                verdict.warn(&format!("landing page HTTP {}", reply.status));
                break;
            }
            html = reply.body;
            let page = analyse_html(&current, &html, &self.cfg);
            verdict.blocked |= page.blocked;
            for reason in page.reasons {
                verdict.warn(&reason);
            }
            if verdict.blocked {
                return cached(&raw, verdict, hops);
            }
            if let Some(next) = page.refresh {
                if hop == self.cfg.max_hops {
                    return cached(&raw, verdict.block("redirect hop limit reached"), hops);
                }
                current = next;
                continue;
            }
            break;
        }
        if !self.cfg.analyser.url.is_empty() {
            let result = tokio::time::timeout_at(
                deadline,
                self.analyse_external(original, current.as_str(), &html),
            )
            .await
            .unwrap_or_else(|_| Err("analyser deadline exceeded".into()));
            match result {
                Ok(external) => {
                    if let Some(brand) = external.brand {
                        if external.verdict != "clean" {
                            verdict.warn(&format!("analyser brand: {brand}"));
                        }
                    }
                    for reason in external.reasons {
                        verdict.warn(&format!("analyser: {reason}"));
                    }
                    match external.verdict.as_str() {
                        "blocked" | "block" => {
                            verdict.blocked = true;
                            verdict.warn("external analyser blocked this page");
                        }
                        "warn" => verdict.warn("external analyser warned about this page"),
                        _ => {}
                    }
                }
                Err(error) if self.cfg.analyser.required => {
                    verdict = verdict.block(&format!("required analyser unavailable: {error}"))
                }
                Err(error) => verdict.warn(&format!("optional analyser unavailable: {error}")),
            }
        }
        cached(current.as_str(), verdict, hops)
    }
    async fn analyse_external(
        &self,
        original: &str,
        final_url: &str,
        html: &[u8],
    ) -> Result<External, String> {
        let endpoint = Url::parse(&self.cfg.analyser.url).map_err(|_| "invalid analyser URL")?;
        let excerpt = if self.cfg.analyser.include_html {
            Some(
                String::from_utf8_lossy(
                    &html[..html.len().min(self.cfg.analyser.max_excerpt_bytes)],
                )
                .into_owned(),
            )
        } else {
            None
        };
        let body = serde_json::to_vec(
            &serde_json::json!({"url":original, "final_url":final_url, "html":excerpt}),
        )
        .map_err(|e| e.to_string())?;
        let reply = http::post_analyser(
            &self.guard,
            &endpoint,
            body,
            Duration::from_secs(self.cfg.fetch.timeout_secs),
        )
        .await?;
        if reply.status != 200 {
            return Err(format!("HTTP {}", reply.status));
        }
        let result: External =
            serde_json::from_slice(&reply.body).map_err(|_| "invalid analyser JSON")?;
        if !matches!(
            result.verdict.as_str(),
            "clean" | "warn" | "block" | "blocked"
        ) || !result.score.is_finite()
            || !(0.0..=1.0).contains(&result.score)
            || result.reasons.len() > 64
        {
            return Err("invalid analyser verdict, score or reasons".into());
        }
        Ok(result)
    }
}
#[derive(Deserialize)]
struct External {
    verdict: String,
    brand: Option<String>,
    score: f64,
    #[serde(default)]
    reasons: Vec<String>,
}
#[async_trait]
impl UrlReputation for ClickAnalysis {
    async fn check(&self, url: &str) -> Reputation {
        self.inspect(url).await.reputation
    }
    async fn inspect(&self, url: &str) -> CheckedUrl {
        let deadline =
            tokio::time::Instant::now() + Duration::from_secs(self.cfg.fetch.timeout_secs);
        let existing = {
            self.cache
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .get(url)
                .filter(|c| c.at.elapsed() < Duration::from_secs(self.cfg.cache_ttl_secs))
                .cloned()
        };
        if let Some(mut cached) = existing {
            let mut findings = Findings::default();
            findings.add(cached.checked.reputation);
            // Cached page analysis must never mask a newly listed hop.
            for hop in cached.hops {
                match tokio::time::timeout_at(deadline, self.reputation.check(&hop)).await {
                    Ok(result) => findings.add(result),
                    Err(_) => {
                        findings = findings.block("reputation deadline exceeded");
                        break;
                    }
                }
            }
            cached.checked.reputation = findings.verdict();
            return cached.checked;
        }
        let cached = match tokio::time::timeout_at(deadline, self.slots.acquire()).await {
            Ok(Ok(_slot)) => self.run(url, deadline).await,
            _ => cached(
                url,
                Findings::default().block("click analysis deadline exceeded"),
                Vec::new(),
            ),
        };
        let mut cache = self.cache.lock().unwrap_or_else(|p| p.into_inner());
        cache.retain(|_, c| c.at.elapsed() < Duration::from_secs(self.cfg.cache_ttl_secs));
        if cache.len() >= self.cfg.cache_entries {
            cache.clear();
        }
        cache.insert(url.into(), cached.clone());
        cached.checked
    }
}
#[derive(Default)]
struct Findings {
    blocked: bool,
    reasons: Vec<String>,
}
impl Findings {
    fn warn(&mut self, reason: &str) {
        if !self.reasons.iter().any(|r| r == reason) {
            self.reasons.push(reason.into());
        }
    }
    fn block(mut self, reason: &str) -> Self {
        self.blocked = true;
        self.warn(reason);
        self
    }
    fn add(&mut self, reputation: Reputation) {
        match reputation {
            Reputation::Clean => {}
            Reputation::Warn { reason } => {
                for line in reason.lines() {
                    self.warn(line);
                }
            }
            Reputation::Blocked { reason } => {
                self.blocked = true;
                for line in reason.lines() {
                    self.warn(line);
                }
            }
        }
    }
    fn verdict(self) -> Reputation {
        if self.blocked {
            Reputation::Blocked {
                reason: self.reasons.join("\n"),
            }
        } else if self.reasons.is_empty() {
            Reputation::Clean
        } else {
            Reputation::Warn {
                reason: self.reasons.join("\n"),
            }
        }
    }
}
fn cached(url: &str, findings: Findings, hops: Vec<String>) -> Cached {
    Cached {
        at: Instant::now(),
        checked: CheckedUrl {
            url: url.into(),
            reputation: findings.verdict(),
        },
        hops,
    }
}

#[derive(Default)]
struct Page {
    blocked: bool,
    reasons: Vec<String>,
    refresh: Option<Url>,
}
fn analyse_html(url: &Url, bytes: &[u8], cfg: &ClickConfig) -> Page {
    let mut page = Page::default();
    let Ok(html) = std::str::from_utf8(bytes) else {
        page.reasons
            .push("page encoding could not be checked".into());
        return page;
    };
    #[derive(Default)]
    struct Markup {
        password: bool,
        identity: bool,
        login_form: bool,
        forms: Vec<String>,
        base: Option<String>,
        refresh: Vec<String>,
    }
    let markup = RefCell::new(Markup::default());
    let parsed = rewrite_str(
        html,
        RewriteStrSettings::new()
            .append_element_content_handler(element!("input", |el| {
                let kind = el
                    .get_attribute("type")
                    .unwrap_or_default()
                    .to_ascii_lowercase();
                let mut m = markup.borrow_mut();
                m.password |= kind == "password";
                m.identity |= matches!(kind.as_str(), "email" | "password")
                    || el.get_attribute("name").is_some_and(|name| {
                        matches!(
                            name.to_ascii_lowercase().as_str(),
                            "username" | "email" | "login"
                        )
                    });
                Ok(())
            }))
            .append_element_content_handler(element!("form", |el| {
                let action = el.get_attribute("action").unwrap_or_default();
                let marker = format!(
                    "{} {} {}",
                    action,
                    el.get_attribute("id").unwrap_or_default(),
                    el.get_attribute("name").unwrap_or_default()
                )
                .to_ascii_lowercase();
                let mut m = markup.borrow_mut();
                m.login_form |= ["login", "signin", "sign-in", "log-in"]
                    .iter()
                    .any(|word| marker.contains(word));
                m.forms.push(action);
                Ok(())
            }))
            .append_element_content_handler(element!(
                "input[formaction], button[formaction]",
                |el| {
                    if let Some(action) = el.get_attribute("formaction") {
                        markup.borrow_mut().forms.push(action);
                    }
                    Ok(())
                }
            ))
            .append_element_content_handler(element!("base[href]", |el| {
                let mut m = markup.borrow_mut();
                if m.base.is_none() {
                    m.base = el.get_attribute("href");
                }
                Ok(())
            }))
            .append_element_content_handler(element!("meta[http-equiv]", |el| {
                if el
                    .get_attribute("http-equiv")
                    .is_some_and(|v| v.eq_ignore_ascii_case("refresh"))
                {
                    if let Some(content) = el.get_attribute("content") {
                        markup.borrow_mut().refresh.push(content);
                    }
                }
                Ok(())
            })),
    );
    if parsed.is_err() {
        page.reasons.push("HTML could not be fully checked".into());
    }
    let m = markup.into_inner();
    let lower = html.to_ascii_lowercase();
    let login = m.password || m.login_form || (m.identity && !m.forms.is_empty());
    if m.password {
        page.reasons.push("password input on landing page".into());
    }
    if login && !m.forms.is_empty() {
        page.reasons.push("login form on landing page".into());
    }
    let base = m
        .base
        .as_deref()
        .and_then(|b| url.join(b).ok())
        .unwrap_or_else(|| url.clone());
    if login {
        for action in &m.forms {
            let target = if action.is_empty() {
                Some(url.clone())
            } else {
                base.join(action).ok()
            };
            if target.as_ref().is_none_or(|target| {
                !matches!(target.scheme(), "http" | "https")
                    || !target.username().is_empty()
                    || target.password().is_some()
                    || site(target) != site(url)
                    || (url.scheme() == "https" && target.scheme() == "http")
            }) {
                page.blocked = true;
                page.reasons.push(
                    "login form sends credentials to another domain or unsafe destination".into(),
                );
                break;
            }
        }
        let visible = mail_parser::decoders::html::html_to_text(html).to_lowercase();
        for brand in &cfg.brands {
            if contains_brand(&visible, &brand.name.to_lowercase())
                && !brand
                    .domains
                    .iter()
                    .any(|d| host_matches(url.host_str().unwrap_or(""), d))
            {
                page.blocked = true;
                page.reasons.push(format!(
                    "{} login outside its legitimate domains",
                    brand.name
                ));
            }
        }
    }
    if lower.contains("challenges.cloudflare.com")
        || lower.contains("cf-turnstile")
        || lower.contains("g-recaptcha")
        || lower.contains("h-captcha")
    {
        page.reasons.push(
            if login {
                "captcha gate in front of a login"
            } else {
                "captcha gate prevents full landing-page analysis"
            }
            .into(),
        );
    }
    static JS: OnceLock<regex::Regex> = OnceLock::new();
    let js = JS.get_or_init(|| regex::Regex::new(r"(?i)(?:window\s*\.\s*|document\s*\.\s*)?location\s*(?:\.\s*(?:href|assign|replace))?\s*(?:=|\()").unwrap());
    if js.is_match(html) {
        page.reasons
            .push("JavaScript location redirect was not executed".into());
    }
    if currawong_parser::html_smuggling::flagged(bytes) {
        page.blocked = true;
        page.reasons.push(format!(
            "HTML smuggling score {:.2}",
            currawong_parser::html_smuggling::score(bytes)
        ));
    }
    for refresh in m.refresh {
        let Some((_, value)) = refresh.split_once(';') else {
            continue;
        };
        let Some((key, target)) = value.split_once('=') else {
            continue;
        };
        if !key.trim().eq_ignore_ascii_case("url") {
            continue;
        }
        match base.join(target.trim().trim_matches(['\'', '"'])) {
            Ok(next) => {
                page.reasons.push("meta refresh redirect".into());
                page.refresh = Some(next);
            }
            Err(_) => {
                page.blocked = true;
                page.reasons.push("invalid meta refresh target".into());
            }
        }
        break;
    }
    page
}
fn site(url: &Url) -> String {
    let host = url.host_str().unwrap_or("");
    registrable(host).unwrap_or_else(|| host.trim_end_matches('.').to_ascii_lowercase())
}
fn contains_brand(text: &str, name: &str) -> bool {
    text.match_indices(name).any(|(start, _)| {
        let end = start + name.len();
        text[..start]
            .chars()
            .next_back()
            .is_none_or(|c| !c.is_alphanumeric())
            && text[end..]
                .chars()
                .next()
                .is_none_or(|c| !c.is_alphanumeric())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::urls::LocalBlocklist;
    use currawong_core::config::ResidencyConfig;
    use currawong_link::http::Reply;
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Pages {
        calls: AtomicUsize,
    }
    #[async_trait]
    impl Http for Pages {
        async fn get(&self, url: &Url, cap: usize) -> Result<Reply, String> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if url.path() == "/redirect" {
                return Ok(Reply {
                    status: 302,
                    location: Some("/meta".into()),
                    body: vec![],
                });
            }
            if url.path() == "/loop" {
                return Ok(Reply {
                    status: 302,
                    location: Some("/loop".into()),
                    body: vec![],
                });
            }
            if url.path() == "/private" {
                return Ok(Reply {
                    status: 302,
                    location: Some("http://169.254.169.254/latest".into()),
                    body: vec![],
                });
            }
            if url.host_str() == Some("169.254.169.254") {
                return Err("SSRF: destination is not public".into());
            }
            let body = if url.path() == "/meta" {
                "<meta http-equiv='Refresh' content='0; URL=/login'>"
            } else {
                "<title>Microsoft</title><form action='https://collector.test/x'><input type=password></form>"
            };
            if body.len() > cap {
                return Err("HTTP body exceeds byte cap".into());
            }
            Ok(Reply {
                status: 200,
                location: None,
                body: body.as_bytes().to_vec(),
            })
        }
    }
    fn analysis() -> ClickAnalysis {
        let mut cfg = ClickConfig::default();
        cfg.fetch.enabled = true;
        let mut analysis = ClickAnalysis::new(
            &cfg,
            Arc::new(LocalBlocklist::from_entries("")),
            Arc::new(ResidencyGuard::from_config(&ResidencyConfig::default()).unwrap()),
        );
        analysis.http = Arc::new(Pages { calls: 0.into() });
        analysis
    }
    #[test]
    fn generated_login_brand_captcha_forms_and_base() {
        let url = Url::parse("https://outside.test/login").unwrap();
        let cfg = ClickConfig::default();
        let p = analyse_html(&url, b"<title>Microsoft Office 365</title><form><input type='PASSWORD'></form><div class=cf-turnstile></div>", &cfg);
        assert!(p.blocked);
        assert!(p.reasons.iter().any(|r| r.contains("captcha gate")));
        let p = analyse_html(
            &Url::parse("https://login.microsoftonline.com/").unwrap(),
            b"<title>Microsoft</title><form><input type=password></form>",
            &cfg,
        );
        assert!(!p.blocked);
        let p = analyse_html(&url, b"<base href='https://collector.test/'><form action='collect'><input type=password></form>", &cfg);
        assert!(p.blocked);
        let p = analyse_html(&url, b"<p>Read our Microsoft news</p>", &cfg);
        assert!(p.reasons.is_empty());
        assert!(!p.blocked);
        let p = analyse_html(
            &url,
            b"<script>window.location.replace('/login')</script>",
            &cfg,
        );
        assert!(p.reasons.iter().any(|r| r.contains("not executed")));
        assert!(p.refresh.is_none());
    }
    #[test]
    fn encoded_brand_form_overrides_and_smuggling_score_are_checked() {
        let cfg = ClickConfig::default();
        let url = Url::parse("https://outside.test/").unwrap();
        assert!(
            analyse_html(
                &url,
                b"<title>Micro&#115;oft</title><form><input type=password></form>",
                &cfg
            )
            .blocked
        );
        assert!(analyse_html(&url, b"<form><input type=password><button formaction='https://collector.test/'>Go</button></form>", &cfg).blocked);
        assert!(
            analyse_html(
                &Url::parse("https://1.1.1.1/").unwrap(),
                b"<form action='https://8.8.8.8/'><input type=password></form>",
                &cfg
            )
            .blocked
        );
        // Generated benign markers only; no payload or script is executed.
        let html = format!(
            "<script>/* {} */ /* new Blob( createObjectURL( atob( */</script>",
            "A".repeat(9000)
        );
        let page = analyse_html(&url, html.as_bytes(), &cfg);
        assert!(page.blocked);
        assert!(page
            .reasons
            .iter()
            .any(|r| r.starts_with("HTML smuggling score")));
    }

    #[tokio::test]
    async fn chain_meta_cache_and_fresh_reputation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blocklist");
        std::fs::write(&path, "").unwrap();
        let mut engine = analysis();
        engine.reputation = Arc::new(LocalBlocklist::from_file(&path));
        let first = engine.inspect("https://outside.test/redirect").await;
        assert!(matches!(first.reputation, Reputation::Blocked { .. }));
        assert_eq!(first.url, "https://outside.test/login");
        // On cached fetch results a newly listed intermediate hop still wins.
        let mut clean = analysis();
        clean.cfg.fetch.enabled = false;
        clean.reputation = Arc::new(LocalBlocklist::from_file(&path));
        let wrapped = "https://google.com/url?q=https%3A%2F%2Foutside.test%2F";
        assert_eq!(clean.inspect(wrapped).await.reputation, Reputation::Clean);
        std::fs::write(&path, "google.com\n").unwrap();
        assert!(matches!(
            clean.inspect(wrapped).await.reputation,
            Reputation::Blocked { .. }
        ));
    }
    #[tokio::test]
    async fn loops_hop_limit_private_redirect_and_body_cap() {
        let mut analysis = analysis();
        assert!(matches!(
            analysis
                .inspect("https://outside.test/loop")
                .await
                .reputation,
            Reputation::Blocked { .. }
        ));
        assert!(matches!(
            analysis
                .inspect("https://outside.test/private")
                .await
                .reputation,
            Reputation::Blocked { .. }
        ));
        analysis.cfg.max_hops = 1;
        assert!(matches!(
            analysis
                .inspect("https://outside.test/redirect")
                .await
                .reputation,
            Reputation::Blocked { .. }
        ));
        analysis.cfg.fetch.max_bytes = 2;
        assert!(matches!(
            analysis
                .inspect("https://outside.test/login")
                .await
                .reputation,
            Reputation::Warn { .. }
        ));
    }
    #[tokio::test]
    async fn no_network_defaults_and_every_wrapper_hop_checked() {
        let cfg = ClickConfig::default();
        let analysis = ClickAnalysis::new(
            &cfg,
            Arc::new(LocalBlocklist::from_entries("evil.test")),
            Arc::new(ResidencyGuard::from_config(&ResidencyConfig::default()).unwrap()),
        );
        assert!(matches!(
            analysis
                .inspect("https://google.com/url?q=https://evil.test/x")
                .await
                .reputation,
            Reputation::Blocked { .. }
        ));
        let result = analysis.inspect("https://example.com/").await;
        assert_eq!(result.reputation, Reputation::Clean);
    }
    struct StalledPage;
    #[async_trait]
    impl Http for StalledPage {
        async fn get(&self, _: &Url, _: usize) -> Result<Reply, String> {
            std::future::pending().await
        }
    }
    #[tokio::test]
    async fn optional_fetch_deadline_warns_after_reputation_has_been_checked() {
        let mut engine = analysis();
        engine.http = Arc::new(StalledPage);
        let result = engine
            .run(
                "https://example.com/",
                tokio::time::Instant::now() + Duration::from_millis(50),
            )
            .await;
        assert!(matches!(result.checked.reputation, Reputation::Warn { .. }));
        assert_eq!(result.checked.url, "https://example.com/");
    }
    #[tokio::test]
    async fn analyser_contract_excerpt_and_required_failure() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buf = [0u8; 4096];
            let (end, length) = loop {
                let n = stream.read(&mut buf).await.unwrap();
                assert!(n > 0);
                request.extend_from_slice(&buf[..n]);
                if let Some(end) = request.windows(4).position(|v| v == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&request[..end]);
                    let length = headers
                        .lines()
                        .find_map(|line| {
                            line.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(|v| v.trim().parse::<usize>().unwrap())
                        })
                        .unwrap();
                    break (end + 4, length);
                }
            };
            while request.len() < end + length {
                let n = stream.read(&mut buf).await.unwrap();
                assert!(n > 0);
                request.extend_from_slice(&buf[..n]);
            }
            let payload: serde_json::Value =
                serde_json::from_slice(&request[end..end + length]).unwrap();
            assert_eq!(payload["url"], "https://example.com/original");
            assert_eq!(payload["final_url"], "https://example.com/final");
            assert_eq!(payload["html"], "abcd");
            let body =
                r#"{"verdict":"warn","brand":"Example","score":0.7,"reasons":["test evidence"]}"#;
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
        });
        let mut engine = analysis();
        engine.cfg.analyser.url = format!("http://{addr}/analyse");
        engine.cfg.analyser.include_html = true;
        engine.cfg.analyser.max_excerpt_bytes = 4;
        let external = engine
            .analyse_external(
                "https://example.com/original",
                "https://example.com/final",
                b"abcdefgh",
            )
            .await
            .unwrap();
        assert_eq!(external.verdict, "warn");
        assert_eq!(external.reasons, ["test evidence"]);
        task.await.unwrap();
        // Listener is closed. Optional failure warns; required failure blocks.
        engine.cfg.fetch.enabled = false;
        assert!(matches!(
            engine
                .inspect("https://example.com/optional")
                .await
                .reputation,
            Reputation::Warn { .. }
        ));
        engine.cfg.analyser.required = true;
        assert!(matches!(
            engine
                .inspect("https://example.com/required")
                .await
                .reputation,
            Reputation::Blocked { .. }
        ));
    }
}
