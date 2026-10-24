//! Resolve, validate every DNS answer, then connect only to pinned addresses.
use async_trait::async_trait;
use currawong_core::ResidencyGuard;
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use url::{Host, Url};

pub fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, c, d] = ip.octets();
            !(matches!(a, 0 | 10 | 127 | 224..=255)
                || (a == 100 && (64..=127).contains(&b))
                || (a == 169 && b == 254)
                || (a == 172 && (16..=31).contains(&b))
                || (a == 192
                    && (b == 168 || (b == 0 && (c == 0 || c == 2)) || (b == 88 && c == 99)))
                || (a == 198 && (b == 18 || b == 19 || (b == 51 && c == 100)))
                || (a == 203 && b == 0 && c == 113)
                || [a, b, c, d] == [168, 63, 129, 16])
        }
        IpAddr::V6(ip) => {
            // Only global unicast; refuse mapped/compatible IPv4, NAT64,
            // Teredo, 6to4, documentation and special-use protocol space.
            let s = ip.segments();
            (s[0] & 0xe000) == 0x2000
                && s[0] != 0x2002
                && !(s[0] == 0x2001 && (s[1] <= 0x1ff || s[1] == 0xdb8))
                && !(s[0] == 0x3fff && s[1] < 0x1000)
        }
    }
}
pub fn on_box(ip: IpAddr) -> bool {
    ip.is_loopback()
}
pub fn validate_url(url: &Url, ports: &[u16]) -> Result<(), String> {
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || !url
            .port_or_known_default()
            .is_some_and(|p| ports.contains(&p))
    {
        return Err("URL scheme, credentials or port refused".into());
    }
    Ok(())
}
#[async_trait]
pub trait Resolver: Send + Sync {
    async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, String>;
}
pub struct SystemResolver;
#[async_trait]
impl Resolver for SystemResolver {
    async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, String> {
        tokio::net::lookup_host((host, port))
            .await
            .map(|v| v.collect())
            .map_err(|e| e.to_string())
    }
}
#[derive(Debug, Clone)]
pub struct Reply {
    pub status: u16,
    pub location: Option<String>,
    pub body: Vec<u8>,
}
#[async_trait]
pub trait Http: Send + Sync {
    async fn get(&self, url: &Url, cap: usize) -> Result<Reply, String>;
}
/// Public requests never carry cookies, credentials, message headers or a referrer.
/// A fresh client per hop also prevents stale pooled sockets bypassing validation.
pub struct SafeHttp {
    ports: Vec<u16>,
    timeout: Duration,
    resolver: Arc<dyn Resolver>,
    #[cfg(test)]
    allow: Vec<SocketAddr>,
}
impl SafeHttp {
    pub fn new(ports: Vec<u16>, timeout_secs: u64) -> Self {
        Self {
            ports,
            timeout: Duration::from_secs(timeout_secs),
            resolver: Arc::new(SystemResolver),
            #[cfg(test)]
            allow: Vec::new(),
        }
    }
    pub fn with_resolver(mut self, resolver: Arc<dyn Resolver>) -> Self {
        self.resolver = resolver;
        self
    }
    async fn peers(&self, url: &Url) -> Result<Vec<SocketAddr>, String> {
        validate_url(url, &self.ports)?;
        let port = url.port_or_known_default().ok_or("URL has no port")?;
        let peers = match url.host() {
            Some(Host::Ipv4(ip)) => vec![SocketAddr::new(ip.into(), port)],
            Some(Host::Ipv6(ip)) => vec![SocketAddr::new(ip.into(), port)],
            Some(Host::Domain(host)) => self.resolver.resolve(host, port).await?,
            None => return Err("URL has no host".into()),
        };
        if peers.is_empty() {
            return Err("DNS returned no addresses".into());
        }
        for peer in &peers {
            #[cfg(test)]
            if self.allow.contains(peer) {
                continue;
            }
            if peer.port() != port || !public_ip(peer.ip()) {
                return Err("SSRF: destination is not public".into());
            }
        }
        Ok(peers)
    }
}
#[async_trait]
impl Http for SafeHttp {
    async fn get(&self, url: &Url, cap: usize) -> Result<Reply, String> {
        tokio::time::timeout(self.timeout, async {
            let peers = self.peers(url).await?;
            let client = client(url, &peers, self.timeout)?;
            let response = client
                .get(url.clone())
                .send()
                .await
                .map_err(|e| e.to_string())?;
            bounded(response, cap).await
        })
        .await
        .map_err(|_| "HTTP deadline exceeded".to_string())?
    }
}
fn client(url: &Url, peers: &[SocketAddr], timeout: Duration) -> Result<reqwest::Client, String> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .user_agent("Currawong-Link-Analysis/1.0")
        .timeout(timeout)
        .resolve_to_addrs(url.host_str().ok_or("URL has no host")?, peers)
        .build()
        .map_err(|e| e.to_string())
}
pub async fn bounded(mut response: reqwest::Response, cap: usize) -> Result<Reply, String> {
    if response.content_length().is_some_and(|n| n > cap as u64) {
        return Err("HTTP body exceeds byte cap".into());
    }
    let status = response.status().as_u16();
    let location = response
        .headers()
        .get(reqwest::header::LOCATION)
        .map(|h| h.to_str().map(str::to_owned))
        .transpose()
        .map_err(|_| "invalid redirect header")?;
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|e| e.to_string())? {
        if chunk.len() > cap.saturating_sub(body.len()) {
            return Err("HTTP body exceeds byte cap".into());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(Reply {
        status,
        location,
        body,
    })
}
/// The analyser receives URLs and optionally HTML. Both residency and on-box
/// checks apply even when an operator has a residency override.
pub async fn post_analyser(
    guard: &ResidencyGuard,
    url: &Url,
    body: Vec<u8>,
    timeout: Duration,
) -> Result<Reply, String> {
    tokio::time::timeout(timeout, async {
        validate_url(
            url,
            &[url.port_or_known_default().ok_or("analyser has no port")?],
        )?;
        guard.check_request(url).map_err(|e| e.to_string())?;
        let port = url.port_or_known_default().ok_or("analyser has no port")?;
        let peers: Vec<_> = match url.host() {
            Some(Host::Ipv4(ip)) => vec![SocketAddr::new(ip.into(), port)],
            Some(Host::Ipv6(ip)) => vec![SocketAddr::new(ip.into(), port)],
            Some(Host::Domain(host)) => tokio::net::lookup_host((host, port))
                .await
                .map_err(|e| e.to_string())?
                .collect(),
            None => return Err("analyser has no host".into()),
        };
        if peers.is_empty() || peers.iter().any(|p| !on_box(p.ip())) {
            return Err("analyser must resolve only on-box".into());
        }
        let pinned = guard.pin(url, &peers).map_err(|e| e.to_string())?;
        let response = client(url, &[pinned], timeout)?
            .post(url.clone())
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if response.status().is_redirection() {
            if let Some(location) = response
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|v| v.to_str().ok())
            {
                guard
                    .check_redirect(url, location)
                    .map_err(|e| e.to_string())?;
            }
            return Err("analyser redirects refused".into());
        }
        bounded(response, 65536).await
    })
    .await
    .map_err(|_| "analyser deadline exceeded".to_string())?
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    pub async fn server(body: String) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let body = body.clone();
                tokio::spawn(async move {
                    let mut data = [0; 4096];
                    let n = stream.read(&mut data).await.unwrap();
                    let request = String::from_utf8_lossy(&data[..n]);
                    assert!(!request.to_ascii_lowercase().contains("cookie:"));
                    assert!(!request.to_ascii_lowercase().contains("referer:"));
                    let response = if request.starts_with("GET /redirect ")
                        || request.starts_with("POST /redirect ")
                    {
                        "HTTP/1.1 302 Found\r\nLocation: /landing\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string()
                    } else {
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        )
                    };
                    stream.write_all(response.as_bytes()).await.unwrap();
                });
            }
        });
        (addr, task)
    }
    pub fn local_http(addr: SocketAddr) -> SafeHttp {
        let mut http = SafeHttp::new(vec![addr.port()], 2);
        http.allow.push(addr);
        http
    }
    #[test]
    fn ssrf_special_ranges_denied() {
        for ip in [
            "127.0.0.1",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.100.100.200",
            "224.1.1.1",
            "0.0.0.0",
            "168.63.129.16",
            "::1",
            "fd00::1",
            "fe80::1",
            "ff02::1",
            "::ffff:127.0.0.1",
            "64:ff9b::a00:1",
            "2002:a00:1::",
            "2001::1",
            "2001:db8::1",
        ] {
            assert!(!public_ip(ip.parse().unwrap()), "{ip}");
        }
        assert!(public_ip("8.8.8.8".parse().unwrap()));
        assert!(public_ip("2606:4700::1111".parse().unwrap()));
        for url in [
            "file:///etc/passwd",
            "http://user:pass@example.com/",
            "http://example.com:22/",
        ] {
            assert!(validate_url(&Url::parse(url).unwrap(), &[80, 443]).is_err());
        }
    }
    struct MixedDns;
    #[async_trait]
    impl Resolver for MixedDns {
        async fn resolve(&self, _: &str, port: u16) -> Result<Vec<SocketAddr>, String> {
            Ok(vec![
                SocketAddr::new("8.8.8.8".parse().unwrap(), port),
                SocketAddr::new("127.0.0.1".parse().unwrap(), port),
            ])
        }
    }
    #[tokio::test]
    async fn all_dns_answers_checked_and_on_box_never_accepts_public_hosts() {
        let http = SafeHttp::new(vec![443], 1).with_resolver(Arc::new(MixedDns));
        let url = Url::parse("https://mixed.invalid/").unwrap();
        assert!(http.get(&url, 10).await.unwrap_err().contains("SSRF"));
        let guard =
            ResidencyGuard::from_config(&currawong_core::config::ResidencyConfig::default())
                .unwrap();
        assert!(post_analyser(
            &guard,
            &Url::parse("https://8.8.8.8/").unwrap(),
            b"{}".to_vec(),
            Duration::from_secs(1)
        )
        .await
        .is_err());
    }
    #[tokio::test]
    async fn analyser_post_and_redirect_refusal() {
        let (addr, task) =
            server(r#"{"verdict":"warn","brand":"Test","score":0.5,"reasons":["test"]}"#.into())
                .await;
        let guard =
            ResidencyGuard::from_config(&currawong_core::config::ResidencyConfig::default())
                .unwrap();
        let reply = post_analyser(
            &guard,
            &Url::parse(&format!("http://{addr}/analyse")).unwrap(),
            br#"{"url":"https://example.com/","final_url":"https://example.com/","html":null}"#
                .to_vec(),
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        assert_eq!(reply.status, 200);
        assert!(post_analyser(
            &guard,
            &Url::parse(&format!("http://{addr}/redirect")).unwrap(),
            b"{}".to_vec(),
            Duration::from_secs(2)
        )
        .await
        .unwrap_err()
        .contains("redirects refused"));
        assert!(serde_json::from_slice::<serde_json::Value>(&reply.body)
            .unwrap()
            .get("verdict")
            .is_some());
        task.abort();
    }
    struct OnceDns {
        addr: SocketAddr,
        calls: std::sync::atomic::AtomicUsize,
    }
    #[async_trait]
    impl Resolver for OnceDns {
        async fn resolve(&self, _: &str, _: u16) -> Result<Vec<SocketAddr>, String> {
            assert_eq!(
                self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst),
                0,
                "DNS resolved twice"
            );
            Ok(vec![self.addr])
        }
    }
    #[tokio::test]
    async fn dns_pin_redirect_and_byte_cap() {
        let (addr, task) = server("landing".into()).await;
        let dns = Arc::new(OnceDns {
            addr,
            calls: 0.into(),
        });
        let http = local_http(addr).with_resolver(dns.clone());
        let url = Url::parse(&format!("http://rebind.invalid:{}/landing", addr.port())).unwrap();
        assert_eq!(http.get(&url, 100).await.unwrap().body, b"landing");
        assert_eq!(dns.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        let http = local_http(addr);
        let first = Url::parse(&format!("http://{addr}/redirect")).unwrap();
        let reply = http.get(&first, 100).await.unwrap();
        assert_eq!(reply.status, 302);
        assert_eq!(
            http.get(&first.join(&reply.location.unwrap()).unwrap(), 100)
                .await
                .unwrap()
                .body,
            b"landing"
        );
        assert!(http.get(&first.join("/landing").unwrap(), 2).await.is_err());
        let denied = SafeHttp::new(vec![addr.port()], 1);
        assert!(denied.get(&first, 100).await.unwrap_err().contains("SSRF"));
        task.abort();
    }
}
