//! TLS client settings for outbound SMTP and policy fetches. Certificates are
//! always verified: against WebPKI roots, or against DANE TLSA records.
use super::{
    dane::DaneVerifier,
    route::{is_public, valid_domain},
};
use crate::dns::Tlsa;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use rustls::{
    crypto::CryptoProvider,
    pki_types::ServerName,
    version::{TLS12, TLS13},
    ClientConfig, RootCertStore,
};
use std::net::SocketAddr;
use std::{sync::Arc, time::Duration};

#[derive(Clone)]
pub struct OutboundTls {
    roots: Arc<RootCertStore>,
    provider: Arc<CryptoProvider>,
}

impl OutboundTls {
    /// The Mozilla root programme, as shipped in `webpki-roots`.
    pub fn webpki() -> Self {
        Self::with_roots(RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        })
    }

    /// A different trust store, for private PKI or tests.
    pub fn with_roots(roots: RootCertStore) -> Self {
        Self {
            roots: Arc::new(roots),
            provider: Arc::new(rustls::crypto::ring::default_provider()),
        }
    }

    /// WebPKI: the chain must lead to a trusted root and name the host.
    pub fn webpki_config(&self) -> Result<Arc<ClientConfig>, String> {
        let config = ClientConfig::builder_with_provider(Arc::clone(&self.provider))
            .with_protocol_versions(&[&TLS13, &TLS12])
            .map_err(|err| err.to_string())?
            .with_root_certificates(Arc::clone(&self.roots))
            .with_no_client_auth();
        Ok(Arc::new(config))
    }

    /// DANE: the chain must match one of `records` (already filtered to the
    /// usable ones).
    pub fn dane_config(
        &self,
        records: Vec<Tlsa>,
        names: Vec<ServerName<'static>>,
    ) -> Result<Arc<ClientConfig>, String> {
        let verifier = DaneVerifier::new(records, names, Arc::clone(&self.provider));
        let config = ClientConfig::builder_with_provider(Arc::clone(&self.provider))
            .with_protocol_versions(&[&TLS13, &TLS12])
            .map_err(|err| err.to_string())?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth();
        Ok(Arc::new(config))
    }

    /// HTTPS client for MTA-STS policies and TLS-RPT uploads. No redirects
    /// (RFC 8461 section 3.3), the same WebPKI roots, and names resolve only
    /// to public addresses unless `allow_private` (`delivery.allow_private_mx`).
    pub fn http_client(&self, allow_private: bool) -> Result<reqwest::Client, String> {
        let mut config = (*self.webpki_config()?).clone();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        reqwest::Client::builder()
            .use_preconfigured_tls(config)
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .dns_resolver(PublicResolver { allow_private })
            .connect_timeout(Duration::from_secs(30))
            .timeout(Duration::from_secs(60))
            .build()
            .map_err(|err| err.to_string())
    }
}

/// Resolves with the system resolver, then drops loopback, private and other
/// non-public addresses, so a policy or report host cannot aim us inward.
struct PublicResolver {
    allow_private: bool,
}

impl Resolve for PublicResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let allow_private = self.allow_private;
        let host = name.as_str().to_string();
        Box::pin(async move {
            let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), 443))
                .await?
                .filter(|addr| allow_private || is_public(&addr.ip()))
                .collect();
            if addrs.is_empty() {
                return Err(format!("{host} has no public address").into());
            }
            let addrs: Addrs = Box::new(addrs.into_iter());
            Ok(addrs)
        })
    }
}

/// The only URLs policy fetches and report uploads may use: `https`, a plain
/// host name (no address literal, user or odd port) and port 443.
pub fn checked_url(url: &str) -> Result<reqwest::Url, String> {
    let parsed = reqwest::Url::parse(url).map_err(|err| format!("{url}: {err}"))?;
    let host_ok = matches!(parsed.host(), Some(url::Host::Domain(host)) if valid_domain(host));
    if parsed.scheme() != "https"
        || !host_ok
        || parsed.port().is_some_and(|port| port != 443)
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        return Err(format!(
            "{url}: not an https URL on port 443 of a host name"
        ));
    }
    residency_check(&parsed)?;
    Ok(parsed)
}

/// RESIDENCY: the single call site for the core residency guard on outbound
/// HTTP (MTA-STS policy fetches and TLS-RPT uploads). Wire
/// `ResidencyGuard::check_request` here when it lands on main.
fn residency_check(_url: &reqwest::Url) -> Result<(), String> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_https_host_names_on_443() {
        assert!(checked_url("https://mta-sts.example.test/.well-known/mta-sts.txt").is_ok());
        assert!(checked_url("https://reports.example.test:443/tlsrpt").is_ok());
        for bad in [
            "http://reports.example.test/",
            "https://127.0.0.1/",
            "https://[::1]/",
            "https://reports.example.test:8443/",
            "https://user:pw@reports.example.test/",
            "https://169.254.169.254/latest",
        ] {
            assert!(checked_url(bad).is_err(), "{bad}");
        }
    }

    #[tokio::test]
    async fn the_http_resolver_drops_private_addresses() {
        let name: Name = "localhost".parse().unwrap();
        assert!(PublicResolver {
            allow_private: false
        }
        .resolve(name)
        .await
        .is_err());
        let name: Name = "localhost".parse().unwrap();
        let addrs: Vec<_> = PublicResolver {
            allow_private: true,
        }
        .resolve(name)
        .await
        .unwrap()
        .collect();
        assert!(!addrs.is_empty());
    }
}
