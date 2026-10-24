//! Domain-only RDAP enrichment and bounded, pinned HTTP (ADR 0012).
pub mod http;
pub mod rdap;
pub mod unwrap;

/// The bundled public suffix list, also used by classify's lookalike scorer.
pub fn registrable(host: &str) -> Option<String> {
    let url::Host::Domain(host) = url::Host::parse(host.trim_end_matches('.')).ok()? else {
        return None;
    };
    psl::domain_str(&host).map(str::to_ascii_lowercase)
}
pub fn host_matches(host: &str, domain: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let domain = domain.trim_end_matches('.').to_ascii_lowercase();
    host == domain || host.ends_with(&format!(".{domain}"))
}
