//! Click-time URL reputation. A threat-intel feed implements the same trait.
use async_trait::async_trait;
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    sync::Mutex,
    time::{Duration, Instant, SystemTime},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reputation {
    Clean,
    /// Show an interstitial; the user may continue.
    Warn {
        reason: String,
    },
    Blocked {
        reason: String,
    },
}

#[async_trait]
pub trait UrlReputation: Send + Sync {
    async fn check(&self, url: &str) -> Reputation;
}

/// The file is read again at least this often, even when its time and size
/// look unchanged.
const REREAD: Duration = Duration::from_secs(5);

/// Operator list, one entry per line: a domain (which also covers its
/// subdomains) or a URL prefix starting with `http://` or `https://`. A bare
/// entry blocks; `warn <entry>` shows the warning page; `allow <entry>`
/// marks a known site when unknown sites get the warning page. `#` starts a
/// comment. Domains are IDNA-normalised. The file is read again when it
/// changes, so a link blocked after delivery is refused on its next click.
/// A missing file lists nothing.
pub struct LocalBlocklist {
    path: Option<PathBuf>,
    warn_unknown: bool,
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    stamp: Option<(SystemTime, u64)>,
    read_at: Option<Instant>,
    digest: [u8; 32],
    entries: Entries,
}

#[derive(Default)]
struct Entries {
    block: List,
    warn: List,
    allow: List,
}

#[derive(Default)]
struct List {
    domains: Vec<String>,
    prefixes: Vec<String>,
}

impl List {
    fn matches(&self, host: &str, url: &str) -> Option<String> {
        if let Some(domain) = self.domains.iter().find(|d| host_matches(host, d)) {
            return Some(domain.clone());
        }
        self.prefixes
            .iter()
            .any(|prefix| url.starts_with(prefix.as_str()))
            .then(|| "this link".to_string())
    }

    fn push(&mut self, entry: &str) {
        let lower = entry.to_ascii_lowercase();
        if lower.starts_with("http://") || lower.starts_with("https://") {
            let url = url::Url::parse(entry).map(|url| url.as_str().to_string());
            self.prefixes.push(url.unwrap_or(lower));
        } else if let Some(domain) = normalise_domain(entry) {
            self.domains.push(domain);
        }
    }
}

impl LocalBlocklist {
    pub fn from_file(path: &Path) -> Self {
        Self {
            path: Some(path.to_path_buf()),
            warn_unknown: false,
            state: Mutex::new(State::default()),
        }
    }

    /// A fixed list, for tests and callers that hold entries in memory.
    pub fn from_entries(text: &str) -> Self {
        Self {
            path: None,
            warn_unknown: false,
            state: Mutex::new(State {
                entries: parse(text),
                ..State::default()
            }),
        }
    }

    /// Links to sites not on an `allow` line get the warning page.
    pub fn with_warn_unknown(mut self, warn: bool) -> Self {
        self.warn_unknown = warn;
        self
    }

    /// Re-read the file without blocking the runtime. The lock is never
    /// held across an await.
    async fn reload(&self) {
        let Some(path) = &self.path else {
            return;
        };
        let stamp = tokio::fs::metadata(path)
            .await
            .and_then(|meta| Ok((meta.modified()?, meta.len())))
            .ok();
        {
            let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            let fresh = state.read_at.is_some_and(|at| at.elapsed() < REREAD);
            if stamp.is_some() && stamp == state.stamp && fresh {
                return;
            }
        }
        let read = tokio::fs::read(path).await;
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        match read {
            Ok(bytes) => {
                let digest: [u8; 32] = Sha256::digest(&bytes).into();
                if digest != state.digest || state.read_at.is_none() {
                    state.entries = parse(&String::from_utf8_lossy(&bytes));
                    state.digest = digest;
                }
                state.stamp = stamp;
                state.read_at = Some(Instant::now());
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => *state = State::default(),
            // Keep the last good list rather than unblocking everything.
            Err(err) => tracing::error!(path = %path.display(), %err, "URL block list unreadable"),
        }
    }
}

fn parse(text: &str) -> Entries {
    let mut entries = Entries::default();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        match line.split_once(char::is_whitespace) {
            Some(("warn", rest)) => entries.warn.push(rest.trim()),
            Some(("allow", rest)) => entries.allow.push(rest.trim()),
            _ => entries.block.push(line),
        }
    }
    entries
}

/// Lower-case ASCII (punycode) form of a domain, as `url` gives hosts.
pub fn normalise_domain(domain: &str) -> Option<String> {
    let domain = domain.trim().trim_end_matches('.');
    if domain.is_empty() {
        return None;
    }
    url::Host::parse(domain)
        .ok()
        .map(|host| host.to_string().to_ascii_lowercase())
}

/// True when `host` is `domain` or one of its subdomains.
pub fn host_matches(host: &str, domain: &str) -> bool {
    let host = host.trim_end_matches('.');
    host.eq_ignore_ascii_case(domain)
        || (host.len() > domain.len()
            && host.as_bytes()[host.len() - domain.len() - 1] == b'.'
            && host[host.len() - domain.len()..].eq_ignore_ascii_case(domain))
}

#[async_trait]
impl UrlReputation for LocalBlocklist {
    async fn check(&self, url: &str) -> Reputation {
        let Some(parsed) = url::Url::parse(url).ok() else {
            return Reputation::Blocked {
                reason: "link is not a valid URL".into(),
            };
        };
        self.reload().await;
        let host = parsed.host_str().unwrap_or("").to_ascii_lowercase();
        let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let entries = &state.entries;
        if let Some(what) = entries.block.matches(&host, parsed.as_str()) {
            return Reputation::Blocked {
                reason: format!("{what} is on the block list"),
            };
        }
        if let Some(what) = entries.warn.matches(&host, parsed.as_str()) {
            return Reputation::Warn {
                reason: format!("{what} is on the watch list"),
            };
        }
        if self.warn_unknown && entries.allow.matches(&host, parsed.as_str()).is_none() {
            return Reputation::Warn {
                reason: "this site has not been checked yet".into(),
            };
        }
        Reputation::Clean
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn urls_blocklist_matches_domains_and_prefixes() {
        let list = LocalBlocklist::from_entries(
            "# comment\nbad.test\nHTTPS://Files.Example.com/evil # inline\nwarn odd.test\nbücher.example\n",
        );
        for url in [
            "https://bad.test/",
            "http://www.BAD.test./x",
            "https://files.example.com/evil/payload",
            "https://www.xn--bcher-kva.example/",
            "https://shop.bücher.example/",
        ] {
            assert!(
                matches!(list.check(url).await, Reputation::Blocked { .. }),
                "{url}"
            );
        }
        assert!(matches!(
            list.check("https://odd.test/").await,
            Reputation::Warn { .. }
        ));
        for url in [
            "https://notbad.test/",
            "https://bad.test.example/",
            "https://files.example.com/good",
        ] {
            assert_eq!(list.check(url).await, Reputation::Clean, "{url}");
        }
    }

    #[tokio::test]
    async fn urls_unknown_sites_warn_when_asked() {
        let list = LocalBlocklist::from_entries("allow example.org\n").with_warn_unknown(true);
        assert_eq!(
            list.check("https://www.example.org/").await,
            Reputation::Clean
        );
        assert!(matches!(
            list.check("https://new.example.net/").await,
            Reputation::Warn { .. }
        ));
    }

    #[tokio::test]
    async fn urls_blocklist_sees_a_same_size_edit() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("list.txt");
        std::fs::write(&path, "aaa.test\n").unwrap();
        let list = LocalBlocklist::from_file(&path);
        assert!(matches!(
            list.check("https://aaa.test/").await,
            Reputation::Blocked { .. }
        ));
        // Same length, and on a coarse clock possibly the same mtime.
        std::fs::write(&path, "bbb.test\n").unwrap();
        list.state.lock().unwrap().read_at = Some(Instant::now() - REREAD);
        assert_eq!(list.check("https://aaa.test/").await, Reputation::Clean);
        assert!(matches!(
            list.check("https://bbb.test/").await,
            Reputation::Blocked { .. }
        ));
    }
}
