//! Spamhaus Data Query Service over DNS (opt-in, needs a DQS key).
//!
//! - DBL: `<domain>.<key>.dbl.dq.spamhaus.net` for each link's registrable
//!   domain. Phishing, malware and botnet codes are intel hits; low
//!   reputation and abused-redirector codes only set
//!   `intel.dbl_low_reputation`.
//! - HBL: `<base32(sha256)>._file.<key>.hbl.dq.spamhaus.net` for each part
//!   hash (RFC 4648 Base32 of the 32 digest bytes, no padding).
//!
//! The domain or hash, and the key, go to Spamhaus through the resolver.
//! No message content does. NXDOMAIN means not listed; codes in
//! 127.255.255.0/24 (and 127.0.1.255, 127.0.3.255) are errors such as a bad
//! key or a public resolver; answers outside 127.0.0.0/8 are discarded.
use crate::normalise::registrable;
use async_trait::async_trait;
use currawong_core::IntelHit;
use std::{net::IpAddr, sync::Arc};

pub const DBL_SOURCE: &str = "spamhaus-dbl";
pub const HBL_SOURCE: &str = "spamhaus-hbl";
pub const DBL_LOW_REPUTATION: &str = "intel.dbl_low_reputation";

/// A-record lookups. `Ok(vec![])` for NXDOMAIN or no records.
#[async_trait]
pub trait DqsResolver: Send + Sync {
    async fn lookup_a(&self, name: &str) -> Result<Vec<IpAddr>, String>;
}

pub struct Dqs {
    key: String,
    dbl: bool,
    hbl: bool,
    max_queries: usize,
    resolver: Arc<dyn DqsResolver>,
}

#[derive(Debug, Default, PartialEq)]
pub struct DqsResult {
    pub hits: Vec<IntelHit>,
    pub flags: Vec<String>,
    pub notes: Vec<String>,
}

enum Listing {
    Hit(&'static str),
    LowReputation,
    Error,
    Ignore,
}

impl Dqs {
    /// The key is a DNS label: letters and digits only.
    pub fn new(
        key: &str,
        dbl: bool,
        hbl: bool,
        max_queries: usize,
        resolver: Arc<dyn DqsResolver>,
    ) -> Result<Self, String> {
        if key.is_empty() || !key.bytes().all(|b| b.is_ascii_alphanumeric()) || key.len() > 63 {
            return Err("DQS key must be letters and digits".into());
        }
        Ok(Self {
            key: key.to_ascii_lowercase(),
            dbl,
            hbl,
            max_queries,
            resolver,
        })
    }

    pub fn dbl_name(&self, domain: &str) -> String {
        format!("{domain}.{}.dbl.dq.spamhaus.net", self.key)
    }

    /// `None` when `sha256` is not 64 hex digits.
    pub fn hbl_name(&self, sha256: &str) -> Option<String> {
        let bytes = decode_hex(sha256)?;
        Some(format!(
            "{}._file.{}.hbl.dq.spamhaus.net",
            base32(&bytes),
            self.key
        ))
    }

    /// Link hosts (any case) and part hashes; domains are queried first.
    pub async fn check(&self, hosts: &[String], hashes: &[String]) -> DqsResult {
        let mut queries: Vec<(&'static str, String, String)> = Vec::new();
        if self.dbl {
            let mut domains: Vec<String> = hosts.iter().map(|h| registrable(h)).collect();
            domains.sort();
            domains.dedup();
            for domain in domains.into_iter().filter(|d| d.contains('.')) {
                queries.push((DBL_SOURCE, self.dbl_name(&domain), domain));
            }
        }
        if self.hbl {
            for hash in hashes {
                if let Some(name) = self.hbl_name(hash) {
                    queries.push((HBL_SOURCE, name, hash.to_ascii_lowercase()));
                }
            }
        }
        let mut result = DqsResult::default();
        if queries.len() > self.max_queries {
            result.notes.push(format!(
                "spamhaus dqs: {} of {} lookups skipped (intel.dqs.max_queries_per_message)",
                queries.len() - self.max_queries,
                queries.len()
            ));
            queries.truncate(self.max_queries);
        }
        let answers = futures::future::join_all(
            queries
                .iter()
                .map(|(_, name, _)| self.resolver.lookup_a(name)),
        )
        .await;
        let mut errors = 0;
        for ((source, _, value), answer) in queries.iter().zip(answers) {
            let ips = match answer {
                Ok(ips) => ips,
                Err(err) => {
                    tracing::debug!(%err, source, "spamhaus dqs lookup failed");
                    errors += 1;
                    continue;
                }
            };
            let (kind, mut hit, mut low) = (
                if *source == DBL_SOURCE {
                    "domain"
                } else {
                    "sha256"
                },
                None,
                false,
            );
            for ip in ips {
                match classify(source, ip) {
                    Listing::Hit(threat) => hit = Some(threat),
                    Listing::LowReputation => low = true,
                    Listing::Error => errors += 1,
                    Listing::Ignore => {}
                }
            }
            if let Some(threat) = hit {
                result.hits.push(IntelHit {
                    kind: kind.into(),
                    value: value.clone(),
                    source: (*source).into(),
                    threat: threat.into(),
                });
            } else if low {
                if !result.flags.iter().any(|f| f == DBL_LOW_REPUTATION) {
                    result.flags.push(DBL_LOW_REPUTATION.into());
                }
                result
                    .notes
                    .push(format!("spamhaus dbl: {value} has a low reputation"));
            }
        }
        if errors > 0 {
            tracing::warn!(
                errors,
                "spamhaus dqs lookups failed or returned an error code (check the key and that the resolver is not a public one)"
            );
            result
                .notes
                .push(format!("spamhaus dqs: {errors} lookups failed"));
        }
        result
    }
}

fn classify(source: &str, ip: IpAddr) -> Listing {
    let IpAddr::V4(ip) = ip else {
        return Listing::Ignore;
    };
    let [a, b, c, d] = ip.octets();
    if a != 127 {
        tracing::warn!(%ip, "spamhaus dqs answer outside 127.0.0.0/8 discarded");
        return Listing::Ignore;
    }
    if (b, c) == (255, 255) || d == 255 {
        return Listing::Error;
    }
    match (source, b, c, d) {
        (DBL_SOURCE, 0, 1, 4 | 104) => Listing::Hit("phishing"),
        (DBL_SOURCE, 0, 1, 5 | 105) => Listing::Hit("malware"),
        (DBL_SOURCE, 0, 1, 6 | 106) => Listing::Hit("botnet_cc"),
        (DBL_SOURCE, 0, 1, 2 | 102 | 103) => Listing::LowReputation,
        (HBL_SOURCE, 0, 3, 10) => Listing::Hit("malware"),
        (HBL_SOURCE, 0, 3, 15) => Listing::Hit("suspicious"),
        _ => Listing::Ignore,
    }
}

fn decode_hex(text: &str) -> Option<Vec<u8>> {
    if text.len() != 64 {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok())
        .collect()
}

/// RFC 4648 Base32, upper case, no padding.
pub fn base32(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
    let (mut buffer, mut bits) = (0u32, 0u32);
    for &byte in bytes {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buffer >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buffer << (5 - bits)) & 31) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn intel_base32_matches_rfc_4648_vectors() {
        for (input, expected) in [
            ("", ""),
            ("f", "MY"),
            ("fo", "MZXQ"),
            ("foo", "MZXW6"),
            ("foob", "MZXW6YQ"),
            ("fooba", "MZXW6YTB"),
            ("foobar", "MZXW6YTBOI"),
        ] {
            assert_eq!(base32(input.as_bytes()), expected);
        }
        // A 32-byte digest is 52 characters, as in Spamhaus's example.
        assert_eq!(base32(&[0u8; 32]).len(), 52);
    }

    struct FakeDns(HashMap<String, Vec<IpAddr>>);

    #[async_trait]
    impl DqsResolver for FakeDns {
        async fn lookup_a(&self, name: &str) -> Result<Vec<IpAddr>, String> {
            if name.starts_with("broken.") {
                return Err("SERVFAIL".into());
            }
            Ok(self.0.get(name).cloned().unwrap_or_default())
        }
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[tokio::test]
    async fn intel_dqs_maps_dbl_and_hbl_answers() {
        let hash = "00".repeat(32);
        let hbl = format!("{}._file.abc123.hbl.dq.spamhaus.net", "A".repeat(52));
        let dns = FakeDns(HashMap::from([
            (
                "phish.example.abc123.dbl.dq.spamhaus.net".into(),
                vec![ip("127.0.1.4")],
            ),
            (
                "spammy.example.abc123.dbl.dq.spamhaus.net".into(),
                vec![ip("127.0.1.2")],
            ),
            (
                "badkey.example.abc123.dbl.dq.spamhaus.net".into(),
                vec![ip("127.255.255.250")],
            ),
            (
                "hijack.example.abc123.dbl.dq.spamhaus.net".into(),
                vec![ip("10.0.0.1")],
            ),
            (hbl, vec![ip("127.0.3.10")]),
        ]));
        let dqs = Dqs::new("ABC123", true, true, 10, Arc::new(dns)).unwrap();
        let hosts: Vec<String> = [
            "www.Phish.example",
            "login.phish.example",
            "spammy.example",
            "badkey.example",
            "hijack.example",
            "clean.example",
            "broken.example",
        ]
        .map(String::from)
        .to_vec();
        let result = dqs.check(&hosts, std::slice::from_ref(&hash)).await;
        assert_eq!(
            result.hits,
            [
                IntelHit {
                    kind: "domain".into(),
                    value: "phish.example".into(),
                    source: DBL_SOURCE.into(),
                    threat: "phishing".into(),
                },
                IntelHit {
                    kind: "sha256".into(),
                    value: hash.clone(),
                    source: HBL_SOURCE.into(),
                    threat: "malware".into(),
                },
            ]
        );
        assert_eq!(result.flags, [DBL_LOW_REPUTATION]);
        assert!(
            result.notes.iter().any(|n| n.contains("2 lookups failed")),
            "{result:?}"
        );

        let capped = Dqs::new("abc123", true, true, 1, Arc::new(FakeDns(HashMap::new()))).unwrap();
        let result = capped.check(&hosts, &[hash]).await;
        assert!(
            result.notes[0].contains("6 of 7 lookups skipped"),
            "{result:?}"
        );
        assert!(Dqs::new("bad.key", true, true, 1, Arc::new(FakeDns(HashMap::new()))).is_err());
    }
}
