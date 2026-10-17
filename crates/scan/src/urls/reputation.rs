//! Click-time URL reputation. A threat-intel feed implements the same trait.
use async_trait::async_trait;
use std::{
    path::{Path, PathBuf},
    sync::Mutex,
    time::SystemTime,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reputation {
    Clean,
    Blocked { reason: String },
}

#[async_trait]
pub trait UrlReputation: Send + Sync {
    async fn check(&self, url: &str) -> Reputation;
}

/// Operator block list, one entry per line: a domain (which also blocks its
/// subdomains) or a URL prefix starting with `http://` or `https://`. `#`
/// starts a comment. The file is read again when it changes, so a link
/// blocked after delivery is refused on its next click. A missing file
/// blocks nothing.
pub struct LocalBlocklist {
    path: Option<PathBuf>,
    state: Mutex<(Option<Stamp>, Entries)>,
}

/// Modification time and length: a rewrite inside one mtime tick still
/// changes the length in practice.
type Stamp = (SystemTime, u64);

#[derive(Default)]
struct Entries {
    domains: Vec<String>,
    prefixes: Vec<String>,
}

impl LocalBlocklist {
    pub fn from_file(path: &Path) -> Self {
        Self {
            path: Some(path.to_path_buf()),
            state: Mutex::new((None, Entries::default())),
        }
    }

    /// A fixed list, for tests and callers that hold entries in memory.
    pub fn from_entries(text: &str) -> Self {
        Self {
            path: None,
            state: Mutex::new((None, parse(text))),
        }
    }

    fn reload(&self, state: &mut (Option<Stamp>, Entries)) {
        let Some(path) = &self.path else {
            return;
        };
        let modified = std::fs::metadata(path)
            .and_then(|meta| Ok((meta.modified()?, meta.len())))
            .ok();
        if modified.is_some() && modified == state.0 {
            return;
        }
        match std::fs::read_to_string(path) {
            Ok(text) => *state = (modified, parse(&text)),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                *state = (None, Entries::default())
            }
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
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("http://") || lower.starts_with("https://") {
            entries.prefixes.push(normalise(line).unwrap_or(lower));
        } else {
            entries
                .domains
                .push(lower.trim_end_matches('.').to_string());
        }
    }
    entries
}

fn normalise(url: &str) -> Option<String> {
    url::Url::parse(url)
        .ok()
        .map(|url| url.as_str().to_string())
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
        let host = parsed.host_str().unwrap_or("").to_ascii_lowercase();
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        self.reload(&mut state);
        let entries = &state.1;
        if let Some(domain) = entries.domains.iter().find(|d| host_matches(&host, d)) {
            return Reputation::Blocked {
                reason: format!("{domain} is on the block list"),
            };
        }
        if entries
            .prefixes
            .iter()
            .any(|prefix| parsed.as_str().starts_with(prefix.as_str()))
        {
            return Reputation::Blocked {
                reason: "link is on the block list".into(),
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
            "# comment\nbad.test\nHTTPS://Files.Example.com/evil # inline\n",
        );
        for url in [
            "https://bad.test/",
            "http://www.BAD.test./x",
            "https://files.example.com/evil/payload",
        ] {
            assert!(
                matches!(list.check(url).await, Reputation::Blocked { .. }),
                "{url}"
            );
        }
        for url in [
            "https://notbad.test/",
            "https://bad.test.example/",
            "https://files.example.com/good",
        ] {
            assert_eq!(list.check(url).await, Reputation::Clean, "{url}");
        }
    }
}
