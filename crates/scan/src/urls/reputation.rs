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
/// A file that has never been read lists nothing; once a list has loaded, a
/// missing or zero-byte file keeps it.
pub struct LocalBlocklist {
    path: Option<PathBuf>,
    warn_unknown: bool,
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    /// A list has been read from the file at least once.
    loaded: bool,
    /// The file was missing and that was logged.
    missing: bool,
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

    /// `false` when the entry is neither a URL nor a domain. A leading `*.`
    /// is accepted and means the same as the bare domain.
    fn push(&mut self, entry: &str) -> bool {
        let lower = entry.to_ascii_lowercase();
        if lower.starts_with("http://") || lower.starts_with("https://") {
            match url::Url::parse(entry) {
                Ok(url) => self.prefixes.push(url.as_str().to_string()),
                Err(_) => return false,
            }
        } else {
            let domain = entry.strip_prefix("*.").unwrap_or(entry);
            match normalise_domain(domain) {
                Some(domain) => self.domains.push(domain),
                None => return false,
            }
        }
        true
    }

    fn is_empty(&self) -> bool {
        self.domains.is_empty() && self.prefixes.is_empty()
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
                entries: parse(text).0,
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
        // Fail closed: a missing or truncated file after a good load keeps
        // the last good list, so a delete-and-recreate or a half-written file
        // never unblocks everything.
        match read {
            Ok(bytes) if bytes.is_empty() && state.loaded && !state.entries.is_empty() => {
                tracing::error!(path = %path.display(), "URL block list is empty, keeping the last good list");
                state.stamp = stamp;
                state.read_at = Some(Instant::now());
            }
            Ok(bytes) => {
                let digest: [u8; 32] = Sha256::digest(&bytes).into();
                if digest != state.digest || !state.loaded {
                    let (entries, rejected) = parse(&String::from_utf8_lossy(&bytes));
                    if !rejected.is_empty() {
                        tracing::warn!(path = %path.display(), count = rejected.len(), first = %rejected[0], "URL block list entries ignored: not a domain or http(s) URL");
                    }
                    state.entries = entries;
                    state.digest = digest;
                }
                state.loaded = true;
                state.missing = false;
                state.stamp = stamp;
                state.read_at = Some(Instant::now());
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                if !state.missing {
                    tracing::error!(path = %path.display(), kept = state.loaded, "URL block list missing");
                    state.missing = true;
                }
                state.read_at = Some(Instant::now());
            }
            Err(err) => tracing::error!(path = %path.display(), %err, "URL block list unreadable"),
        }
    }
}

impl Entries {
    fn is_empty(&self) -> bool {
        self.block.is_empty() && self.warn.is_empty() && self.allow.is_empty()
    }
}

/// The entries, and the lines that were not understood.
fn parse(text: &str) -> (Entries, Vec<String>) {
    let mut entries = Entries::default();
    let mut rejected = Vec::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let ok = match line.split_once(char::is_whitespace) {
            Some(("warn", rest)) => entries.warn.push(rest.trim()),
            Some(("allow", rest)) => entries.allow.push(rest.trim()),
            _ => entries.block.push(line),
        };
        if !ok {
            rejected.push(line.to_string());
        }
    }
    (entries, rejected)
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

    #[test]
    fn urls_blocklist_reports_entries_it_cannot_use() {
        let (entries, rejected) =
            parse("*.evil.test\nevil.test:8080\nevil.test/path\nhttps://[bad\nok.test\n");
        assert_eq!(entries.block.domains, ["evil.test", "ok.test"]);
        assert_eq!(
            rejected,
            ["evil.test:8080", "evil.test/path", "https://[bad"]
        );
    }

    #[tokio::test]
    async fn urls_blocklist_keeps_the_last_good_list() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("list.txt");
        let list = LocalBlocklist::from_file(&path);
        assert_eq!(list.check("https://bad.test/").await, Reputation::Clean);
        std::fs::write(&path, "bad.test\n").unwrap();
        assert!(matches!(
            list.check("https://bad.test/").await,
            Reputation::Blocked { .. }
        ));
        let stale = || list.state.lock().unwrap().read_at = Some(Instant::now() - REREAD);
        // Truncated by a non-atomic write.
        std::fs::write(&path, "").unwrap();
        stale();
        assert!(matches!(
            list.check("https://bad.test/").await,
            Reputation::Blocked { .. }
        ));
        // Deleted before being recreated.
        std::fs::remove_file(&path).unwrap();
        stale();
        assert!(matches!(
            list.check("https://bad.test/").await,
            Reputation::Blocked { .. }
        ));
        // A deliberate clear is a file with no entries, for example a comment.
        std::fs::write(&path, "# nothing blocked\n").unwrap();
        stale();
        assert_eq!(list.check("https://bad.test/").await, Reputation::Clean);
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
