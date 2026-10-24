//! One canonical form per indicator, so a feed entry and a link in a message
//! compare as equal strings.
//!
//! - `sha256`: 64 lower-case hex digits.
//! - `url`: lower-case scheme and host (IDNA to punycode), default port and
//!   fragment removed, path and query kept as they are.
//! - `domain`: lower-case punycode, no trailing dot or leading `*.`.
//! - `ip`: the address without a port, IPv4-mapped IPv6 as IPv4.
use crate::Kind;
use std::net::{IpAddr, SocketAddr};

pub fn normalise(kind: Kind, value: &str) -> Option<String> {
    let value = value.trim();
    match kind {
        Kind::Sha256 => (value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit()))
            .then(|| value.to_ascii_lowercase()),
        Kind::Url => {
            let mut url = url::Url::parse(value).ok()?;
            if !matches!(url.scheme(), "http" | "https" | "ftp") || url.host().is_none() {
                return None;
            }
            url.set_fragment(None);
            Some(url.to_string())
        }
        Kind::Domain => {
            let domain = value.strip_prefix("*.").unwrap_or(value);
            let domain = domain.trim_end_matches('.');
            match url::Host::parse(domain).ok()? {
                url::Host::Domain(domain) if domain.contains('.') => {
                    Some(domain.to_ascii_lowercase())
                }
                _ => None,
            }
        }
        Kind::Ip => parse_ip(value).map(|ip| ip.to_string()),
    }
}

/// An address, with or without a port (`1.2.3.4:443`, `[2001:db8::1]:443`).
fn parse_ip(value: &str) -> Option<IpAddr> {
    let ip = value
        .parse::<IpAddr>()
        .ok()
        .or_else(|| value.parse::<SocketAddr>().ok().map(|addr| addr.ip()))?;
    Some(ip.to_canonical())
}

/// The kind of a bare indicator: a hash, a URL, an address or a domain.
pub fn guess_kind(value: &str) -> Option<Kind> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    if value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit()) {
        Some(Kind::Sha256)
    } else if value.contains("://") {
        Some(Kind::Url)
    } else if parse_ip(value).is_some() {
        Some(Kind::Ip)
    } else {
        Some(Kind::Domain)
    }
}

/// What a link is looked up as: the URL itself, then its host and each
/// parent domain down to the registrable domain (never a public suffix),
/// or the address when the host is an IP.
pub fn url_candidates(url: &str) -> Vec<(Kind, String)> {
    let Some(normal) = normalise(Kind::Url, url) else {
        return Vec::new();
    };
    let mut out = vec![(Kind::Url, normal.clone())];
    let Ok(parsed) = url::Url::parse(&normal) else {
        return out;
    };
    match parsed.host() {
        Some(url::Host::Domain(host)) => {
            let host = host.trim_end_matches('.').to_string();
            let registrable = psl::domain_str(&host).map(str::to_string);
            let mut current = host.as_str();
            loop {
                out.push((Kind::Domain, current.to_string()));
                if registrable.as_deref().is_none_or(|r| r == current) {
                    break;
                }
                match current.split_once('.') {
                    Some((_, parent)) => current = parent,
                    None => break,
                }
            }
        }
        Some(url::Host::Ipv4(ip)) => out.push((Kind::Ip, IpAddr::V4(ip).to_string())),
        Some(url::Host::Ipv6(ip)) => {
            out.push((Kind::Ip, IpAddr::V6(ip).to_canonical().to_string()))
        }
        None => {}
    }
    out
}

/// The registrable domain of a host (`a.b.example.com.au` gives
/// `example.com.au`), or the host when it has no public suffix.
pub fn registrable(host: &str) -> String {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    psl::domain_str(&host).unwrap_or(&host).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intel_normalises_each_kind() {
        let hash = "AB".repeat(32);
        assert_eq!(normalise(Kind::Sha256, &hash), Some("ab".repeat(32)));
        assert_eq!(normalise(Kind::Sha256, "abc"), None);
        assert_eq!(
            normalise(Kind::Url, "HTTPS://Evil.EXAMPLE:443/Path/x?Q=1#frag").as_deref(),
            Some("https://evil.example/Path/x?Q=1")
        );
        assert_eq!(
            normalise(Kind::Url, "http://bücher.example:8080").as_deref(),
            Some("http://xn--bcher-kva.example:8080/")
        );
        assert_eq!(normalise(Kind::Url, "mailto:a@b.example"), None);
        assert_eq!(
            normalise(Kind::Domain, "*.Evil.Example.").as_deref(),
            Some("evil.example")
        );
        assert_eq!(normalise(Kind::Domain, "localhost"), None);
        assert_eq!(normalise(Kind::Domain, "1.2.3.4"), None);
        assert_eq!(
            normalise(Kind::Ip, "192.0.2.7:443").as_deref(),
            Some("192.0.2.7")
        );
        assert_eq!(
            normalise(Kind::Ip, "::ffff:192.0.2.7").as_deref(),
            Some("192.0.2.7")
        );
    }

    #[test]
    fn intel_guesses_kinds() {
        assert_eq!(guess_kind(&"0".repeat(64)), Some(Kind::Sha256));
        assert_eq!(guess_kind("https://x.example/"), Some(Kind::Url));
        assert_eq!(guess_kind("198.51.100.1:8080"), Some(Kind::Ip));
        assert_eq!(guess_kind("x.example"), Some(Kind::Domain));
    }

    #[test]
    fn intel_url_candidates_stop_at_the_registrable_domain() {
        let found = url_candidates("https://a.b.evil.com.au/login#x");
        assert_eq!(
            found,
            vec![
                (Kind::Url, "https://a.b.evil.com.au/login".to_string()),
                (Kind::Domain, "a.b.evil.com.au".to_string()),
                (Kind::Domain, "b.evil.com.au".to_string()),
                (Kind::Domain, "evil.com.au".to_string()),
            ]
        );
        assert_eq!(
            url_candidates("http://192.0.2.9:8080/x")[1],
            (Kind::Ip, "192.0.2.9".to_string())
        );
        assert!(url_candidates("not a url").is_empty());
    }
}
