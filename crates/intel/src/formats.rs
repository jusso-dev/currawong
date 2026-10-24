//! Feed parsers. Each returns normalised indicators and a count of records
//! it could not use, so a sync can tell a changed or broken feed (an HTML
//! error page, a renamed column) from a good one and keep the old data.
use crate::{guess_kind, normalise, Indicator, Kind};
use currawong_core::config::FeedFormat;
use regex::Regex;
use serde_json::Value;
use std::sync::OnceLock;

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Parsed {
    pub indicators: Vec<Indicator>,
    /// Records that looked like indicators but did not normalise.
    pub rejected: usize,
}

impl Parsed {
    fn push(&mut self, kind: Kind, value: &str, threat: &str) {
        self.push_with(kind, value, threat, None);
    }

    fn push_with(&mut self, kind: Kind, value: &str, threat: &str, expires: Option<i64>) {
        match normalise(kind, value) {
            Some(value) => self.indicators.push(Indicator {
                kind,
                value,
                threat: if threat.trim().is_empty() {
                    "listed".into()
                } else {
                    threat.trim().to_string()
                },
                first_seen: None,
                expires,
            }),
            None => self.rejected += 1,
        }
    }
}

/// Parse one downloaded (and decompressed) feed body. `kind` forces the
/// kind of every `lines` entry; `threat` labels entries the feed does not.
pub fn parse(
    format: FeedFormat,
    body: &[u8],
    kind: Option<Kind>,
    threat: Option<&str>,
    now: i64,
) -> Result<Parsed, String> {
    let text = String::from_utf8_lossy(body);
    match format {
        FeedFormat::Lines => Ok(lines(&text, kind, threat.unwrap_or("listed"))),
        FeedFormat::MalwarebazaarSha256 => Ok(lines(
            &text,
            Some(Kind::Sha256),
            threat.unwrap_or("malware"),
        )),
        FeedFormat::Openphish => Ok(lines(&text, Some(Kind::Url), threat.unwrap_or("phishing"))),
        FeedFormat::Csv => csv(&text, threat),
        FeedFormat::ThreatfoxJson => threatfox(&text),
        FeedFormat::PhishtankJson => phishtank(&text, threat.unwrap_or("phishing")),
        FeedFormat::StixBundle | FeedFormat::Taxii => {
            let doc: Value =
                serde_json::from_str(&text).map_err(|err| format!("not JSON: {err}"))?;
            let objects = doc
                .get("objects")
                .and_then(Value::as_array)
                .ok_or("no \"objects\" array")?;
            Ok(stix(objects, threat, now))
        }
    }
}

/// One indicator per line. `#` starts a comment line. Hosts-file lines
/// (`0.0.0.0 evil.example`) give the name.
fn lines(text: &str, kind: Option<Kind>, threat: &str) -> Parsed {
    let mut parsed = Parsed::default();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
            continue;
        }
        let mut words = line.split_whitespace();
        let first = words.next().unwrap_or("");
        let entry = match (first, words.next()) {
            ("0.0.0.0" | "127.0.0.1" | "::", Some(name)) => name,
            _ => first,
        };
        match kind.or_else(|| guess_kind(entry)) {
            Some(kind) => parsed.push(kind, entry, threat),
            None => parsed.rejected += 1,
        }
    }
    parsed
}

/// One CSV record. Quoted fields may hold commas and `""`; space around
/// fields (ThreatFox writes `", "`) is dropped.
fn csv_fields(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut field = String::new();
    let mut quoted = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if quoted && chars.peek() == Some(&'"') => {
                field.push('"');
                chars.next();
            }
            '"' => quoted = !quoted,
            ',' if !quoted => fields.push(std::mem::take(&mut field).trim().to_string()),
            _ => field.push(c),
        }
    }
    fields.push(field.trim().to_string());
    fields
}

/// abuse.ch CSV: URLhaus (`url`, `threat`), ThreatFox (`ioc_value`,
/// `ioc_type`, `threat_type`) and MalwareBazaar (`sha256_hash`,
/// `signature`). The header is the last `#` comment line with commas before
/// the data, or the first line.
fn csv(text: &str, default_threat: Option<&str>) -> Result<Parsed, String> {
    let mut header: Option<Vec<String>> = None;
    let mut columns: Option<Columns> = None;
    let mut parsed = Parsed::default();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(comment) = line.strip_prefix('#') {
            if columns.is_none() && comment.contains(',') {
                header = Some(csv_fields(comment));
            }
            continue;
        }
        let fields = csv_fields(line);
        if columns.is_none() {
            // Without a `#` header line, this first line is the header.
            let from_comment = header.is_some();
            let names = header.take().unwrap_or_else(|| fields.clone());
            columns = Some(
                Columns::find(&names)
                    .ok_or("CSV header has no url, ioc_value or sha256_hash column")?,
            );
            if !from_comment {
                continue;
            }
        }
        let Some(cols) = &columns else { continue };
        let Some(value) = fields.get(cols.value) else {
            parsed.rejected += 1;
            continue;
        };
        let threat = cols
            .threat
            .and_then(|i| fields.get(i))
            .map(String::as_str)
            .filter(|t| !t.is_empty())
            .or(default_threat)
            .unwrap_or("listed");
        let kind = match cols.kind {
            ColumnKind::Fixed(kind) => Some(kind),
            ColumnKind::Typed(i) => match fields.get(i).map(|t| threatfox_kind(t)) {
                Some(Some(kind)) => Some(kind),
                // A type the store does not keep, such as md5_hash.
                Some(None) => continue,
                None => None,
            },
            ColumnKind::Guess => guess_kind(value),
        };
        match kind {
            Some(kind) => parsed.push(kind, value, threat),
            None => parsed.rejected += 1,
        }
    }
    Ok(parsed)
}

enum ColumnKind {
    Fixed(Kind),
    /// A ThreatFox `ioc_type` column.
    Typed(usize),
    Guess,
}

struct Columns {
    value: usize,
    kind: ColumnKind,
    threat: Option<usize>,
}

impl Columns {
    fn find(names: &[String]) -> Option<Self> {
        let index = |name: &str| names.iter().position(|n| n.eq_ignore_ascii_case(name));
        let (value, kind) = if let Some(i) = index("ioc_value") {
            (
                i,
                index("ioc_type").map_or(ColumnKind::Guess, ColumnKind::Typed),
            )
        } else if let Some(i) = index("url") {
            (i, ColumnKind::Fixed(Kind::Url))
        } else if let Some(i) = index("sha256_hash") {
            (i, ColumnKind::Fixed(Kind::Sha256))
        } else {
            (index("domain")?, ColumnKind::Fixed(Kind::Domain))
        };
        let threat = ["threat", "threat_type", "signature"]
            .into_iter()
            .find_map(index);
        Some(Self {
            value,
            kind,
            threat,
        })
    }
}

/// ThreatFox `ioc_type` values the store keeps.
fn threatfox_kind(ioc_type: &str) -> Option<Kind> {
    match ioc_type {
        "url" => Some(Kind::Url),
        "domain" => Some(Kind::Domain),
        "ip:port" => Some(Kind::Ip),
        "sha256_hash" => Some(Kind::Sha256),
        _ => None,
    }
}

/// ThreatFox JSON export: an object of IOC id to a list of records, or the
/// API's `{"data": [...]}`, or a plain list.
fn threatfox(text: &str) -> Result<Parsed, String> {
    let doc: Value = serde_json::from_str(text).map_err(|err| format!("not JSON: {err}"))?;
    let records: Vec<&Value> = match &doc {
        Value::Array(items) => items.iter().collect(),
        Value::Object(map) => match map.get("data") {
            Some(Value::Array(items)) => items.iter().collect(),
            _ => map
                .values()
                .flat_map(|value| match value {
                    Value::Array(items) => items.iter().collect::<Vec<_>>(),
                    other => vec![other],
                })
                .collect(),
        },
        _ => return Err("expected a JSON object or list".into()),
    };
    let mut parsed = Parsed::default();
    for record in records {
        let field = |name: &str| record.get(name).and_then(Value::as_str).unwrap_or("");
        let Some(kind) = threatfox_kind(field("ioc_type")) else {
            if field("ioc_value").is_empty() {
                parsed.rejected += 1;
            }
            continue;
        };
        let threat = match (field("threat_type"), field("malware_printable")) {
            ("", malware) => malware.to_string(),
            (threat, "") => threat.to_string(),
            (threat, malware) => format!("{threat}: {malware}"),
        };
        parsed.push(kind, field("ioc_value"), &threat);
    }
    Ok(parsed)
}

/// PhishTank `online-valid.json`: a list of `{ "url": ..., "target": ... }`.
fn phishtank(text: &str, threat: &str) -> Result<Parsed, String> {
    let doc: Value = serde_json::from_str(text).map_err(|err| format!("not JSON: {err}"))?;
    let items = doc.as_array().ok_or("expected a JSON list")?;
    let mut parsed = Parsed::default();
    for item in items {
        match item.get("url").and_then(Value::as_str) {
            Some(url) => parsed.push(Kind::Url, url, threat),
            None => parsed.rejected += 1,
        }
    }
    Ok(parsed)
}

/// STIX comparison expressions the store can use: equality on a SHA-256
/// hash, a URL, a domain name or an address.
fn pattern_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?x)
            (file:hashes\.(?:'SHA-256'|"SHA-256"|SHA256|'SHA256')|url:value|domain-name:value|ipv4-addr:value|ipv6-addr:value)
            \s*=\s*'((?:[^'\\]|\\.)*)'"#,
        )
        .expect("STIX pattern regex")
    })
}

/// STIX 2.1 `indicator` objects with a `stix` pattern. Revoked indicators
/// and those past `valid_until` are skipped; `valid_until` becomes the
/// stored expiry. Observables without an indicator are not used: MISP and
/// CTIS mark what is to be acted on as indicators.
fn stix(objects: &[Value], default_threat: Option<&str>, now: i64) -> Parsed {
    let mut parsed = Parsed::default();
    for object in objects {
        if object.get("type").and_then(Value::as_str) != Some("indicator") {
            continue;
        }
        if object.get("revoked").and_then(Value::as_bool) == Some(true) {
            continue;
        }
        if object
            .get("pattern_type")
            .and_then(Value::as_str)
            .is_some_and(|t| t != "stix")
        {
            continue;
        }
        let expires = object
            .get("valid_until")
            .and_then(Value::as_str)
            .and_then(|text| {
                time::OffsetDateTime::parse(text, &time::format_description::well_known::Rfc3339)
                    .ok()
            })
            .map(|at| at.unix_timestamp());
        if expires.is_some_and(|at| at <= now) {
            continue;
        }
        let first = |name: &str| {
            object
                .get(name)
                .and_then(Value::as_array)
                .and_then(|list| list.first())
                .and_then(Value::as_str)
                .map(str::to_string)
        };
        let threat = first("indicator_types")
            .or_else(|| first("labels"))
            .or_else(|| default_threat.map(str::to_string))
            .or_else(|| {
                object
                    .get("name")
                    .and_then(Value::as_str)
                    .map(str::to_string)
            })
            .unwrap_or_else(|| "listed".into());
        let pattern = object.get("pattern").and_then(Value::as_str).unwrap_or("");
        let mut any = false;
        for found in pattern_regex().captures_iter(pattern) {
            let kind = match &found[1] {
                "url:value" => Kind::Url,
                "domain-name:value" => Kind::Domain,
                "ipv4-addr:value" | "ipv6-addr:value" => Kind::Ip,
                _ => Kind::Sha256,
            };
            let value = found[2].replace("\\'", "'").replace("\\\\", "\\");
            parsed.push_with(kind, &value, &threat, expires);
            any = true;
        }
        if !any && pattern.is_empty() {
            parsed.rejected += 1;
        }
    }
    parsed
}

/// A TAXII 2.1 envelope's paging fields: `more` and `next`.
pub fn taxii_next(body: &[u8]) -> Option<String> {
    let doc: Value = serde_json::from_slice(body).ok()?;
    if doc.get("more").and_then(Value::as_bool) != Some(true) {
        return None;
    }
    doc.get("next").and_then(Value::as_str).map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn values(parsed: &Parsed) -> Vec<(Kind, &str, &str)> {
        parsed
            .indicators
            .iter()
            .map(|i| (i.kind, i.value.as_str(), i.threat.as_str()))
            .collect()
    }

    #[test]
    fn intel_parses_line_lists() {
        let text =
            "# comment\n\nhttps://Evil.example/a\n0.0.0.0 bad.example\n198.51.100.4\n<html>\n";
        let parsed = parse(FeedFormat::Lines, text.as_bytes(), None, None, 0).unwrap();
        assert_eq!(
            values(&parsed),
            [
                (Kind::Url, "https://evil.example/a", "listed"),
                (Kind::Domain, "bad.example", "listed"),
                (Kind::Ip, "198.51.100.4", "listed"),
            ]
        );
        assert_eq!(parsed.rejected, 1);
        let hashes = format!("# MalwareBazaar\n{}\nnot-a-hash\n", "AB".repeat(32));
        let parsed = parse(
            FeedFormat::MalwarebazaarSha256,
            hashes.as_bytes(),
            None,
            None,
            0,
        )
        .unwrap();
        assert_eq!(
            values(&parsed),
            [(Kind::Sha256, "ab".repeat(32).as_str(), "malware")]
        );
        assert_eq!(parsed.rejected, 1);
        let openphish = "https://login.phish.example/x\n";
        let parsed = parse(FeedFormat::Openphish, openphish.as_bytes(), None, None, 0).unwrap();
        assert_eq!(
            values(&parsed),
            [(Kind::Url, "https://login.phish.example/x", "phishing")]
        );
    }

    #[test]
    fn intel_parses_abuse_ch_csv() {
        let urlhaus = "################\n# abuse.ch URLhaus Database Dump (CSV)\n#\n# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter\n\"1\",\"2026-10-01 00:00:00\",\"http://198.51.100.9/bins/x.arm\",\"online\",\"2026-10-01 00:00:00\",\"malware_download\",\"elf,mirai\",\"https://urlhaus.abuse.ch/url/1/\",\"r\"\n";
        let parsed = parse(FeedFormat::Csv, urlhaus.as_bytes(), None, None, 0).unwrap();
        assert_eq!(
            values(&parsed),
            [(
                Kind::Url,
                "http://198.51.100.9/bins/x.arm",
                "malware_download"
            )]
        );
        let threatfox = "# \"first_seen_utc\",\"ioc_id\",\"ioc_value\",\"ioc_type\",\"threat_type\",\"fk_malware\"\n\"2026-10-01 00:00:00\", \"1\", \"c2.example\", \"domain\", \"botnet_cc\", \"win.x\"\n\"2026-10-01 00:00:00\", \"2\", \"203.0.113.5:443\", \"ip:port\", \"botnet_cc\", \"win.x\"\n\"2026-10-01 00:00:00\", \"3\", \"d41d8cd98f00b204e9800998ecf8427e\", \"md5_hash\", \"payload\", \"win.x\"\n";
        let parsed = parse(FeedFormat::Csv, threatfox.as_bytes(), None, None, 0).unwrap();
        assert_eq!(
            values(&parsed),
            [
                (Kind::Domain, "c2.example", "botnet_cc"),
                (Kind::Ip, "203.0.113.5", "botnet_cc"),
            ]
        );
        let bazaar = format!(
            "first_seen_utc,sha256_hash,md5_hash,signature\n2026-10-01,{},x,AgentTesla\n",
            "c".repeat(64)
        );
        let parsed = parse(FeedFormat::Csv, bazaar.as_bytes(), None, None, 0).unwrap();
        assert_eq!(
            values(&parsed),
            [(Kind::Sha256, "c".repeat(64).as_str(), "AgentTesla")]
        );
        assert!(parse(FeedFormat::Csv, b"a,b,c\n1,2,3\n", None, None, 0).is_err());
    }

    #[test]
    fn intel_parses_threatfox_and_phishtank_json() {
        let threatfox = r#"{"1": [{"ioc_value": "https://pay.example/x", "ioc_type": "url", "threat_type": "payload_delivery", "malware_printable": "Emotet"}],
            "2": [{"ioc_value": "aa", "ioc_type": "md5_hash"}]}"#;
        let parsed = parse(
            FeedFormat::ThreatfoxJson,
            threatfox.as_bytes(),
            None,
            None,
            0,
        )
        .unwrap();
        assert_eq!(
            values(&parsed),
            [(
                Kind::Url,
                "https://pay.example/x",
                "payload_delivery: Emotet"
            )]
        );
        let api = r#"{"query_status": "ok", "data": [{"ioc_value": "evil.example", "ioc_type": "domain", "threat_type": "botnet_cc"}]}"#;
        let parsed = parse(FeedFormat::ThreatfoxJson, api.as_bytes(), None, None, 0).unwrap();
        assert_eq!(
            values(&parsed),
            [(Kind::Domain, "evil.example", "botnet_cc")]
        );
        let phishtank = r#"[{"phish_id": 1, "url": "http://phish.example/login", "target": "Other"}, {"phish_id": 2}]"#;
        let parsed = parse(
            FeedFormat::PhishtankJson,
            phishtank.as_bytes(),
            None,
            None,
            0,
        )
        .unwrap();
        assert_eq!(
            values(&parsed),
            [(Kind::Url, "http://phish.example/login", "phishing")]
        );
        assert_eq!(parsed.rejected, 1);
        assert!(parse(FeedFormat::PhishtankJson, b"<html>", None, None, 0).is_err());
    }

    #[test]
    fn intel_parses_stix_indicators() {
        let hash = "e".repeat(64);
        let bundle = format!(
            r#"{{"type": "bundle", "id": "bundle--1", "objects": [
            {{"type": "indicator", "spec_version": "2.1", "pattern_type": "stix",
              "indicator_types": ["malicious-activity"],
              "pattern": "[file:hashes.'SHA-256' = '{hash}'] OR [url:value = 'https://ctis.example/a\\'b']",
              "valid_until": "2099-01-01T00:00:00Z"}},
            {{"type": "indicator", "pattern_type": "stix", "revoked": true,
              "pattern": "[domain-name:value = 'revoked.example']"}},
            {{"type": "indicator", "pattern_type": "stix", "valid_until": "2000-01-01T00:00:00Z",
              "pattern": "[domain-name:value = 'expired.example']"}},
            {{"type": "indicator", "pattern_type": "sigma", "pattern": "title: x"}},
            {{"type": "indicator", "pattern_type": "stix", "labels": ["phishing"],
              "pattern": "[domain-name:value = 'misp.example' AND ipv4-addr:value = '192.0.2.1']"}},
            {{"type": "domain-name", "value": "observed-only.example"}}
        ]}}"#
        );
        let parsed = parse(
            FeedFormat::StixBundle,
            bundle.as_bytes(),
            None,
            None,
            2_000_000_000,
        )
        .unwrap();
        assert_eq!(
            values(&parsed),
            [
                (Kind::Sha256, hash.as_str(), "malicious-activity"),
                (Kind::Url, "https://ctis.example/a'b", "malicious-activity"),
                (Kind::Domain, "misp.example", "phishing"),
                (Kind::Ip, "192.0.2.1", "phishing"),
            ]
        );
        assert_eq!(parsed.indicators[0].expires, Some(4_070_908_800));
        assert!(parse(FeedFormat::Taxii, b"{}", None, None, 0).is_err());
        assert_eq!(
            taxii_next(br#"{"more": true, "next": "p2", "objects": []}"#).as_deref(),
            Some("p2")
        );
        assert_eq!(taxii_next(br#"{"more": false, "next": "p2"}"#), None);
    }
}
