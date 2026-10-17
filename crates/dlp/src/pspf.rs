//! PSPF protective markings: the `X-Protective-Marking` header and the
//! `[SEC=...]` subject marking from the Australian Government Email
//! Protective Marking Standard (see `docs/pspf.md` for the version followed).
//!
//! Header syntax, fields in this order, `, ` separated:
//! `VER=<version>, NS=<namespace>, SEC=<classification>, CAVEAT=<type>:<value>
//! (repeatable), EXPIRES=<date|event>, DOWNTO=<classification>,
//! ACCESS=<information management marker> (repeatable), NOTE=<comment>,
//! ORIGIN=<author email>`. `VER`, `NS` and `SEC` are required.
//!
//! Subject syntax: `[SEC=<classification>(, CAVEAT=...)*(, ACCESS=...)*]`,
//! normally at the end of the subject.
use currawong_core::{Classification, MarkingReport};
use mail_parser::MessageParser;

/// Longer header or subject markings are refused rather than parsed.
const MAX_MARKING_LEN: usize = 2048;
/// Only the header section is parsed; it is cut at this size.
const MAX_HEADER_BYTES: usize = 256 * 1024;

/// Information management markers allowed after `ACCESS=`.
const ACCESS_MARKERS: [&str; 3] = ["Legal-Privilege", "Legislative-Secrecy", "Personal-Privacy"];

/// Header fields in the order the standard requires.
const HEADER_ORDER: [&str; 9] = [
    "VER", "NS", "SEC", "CAVEAT", "EXPIRES", "DOWNTO", "ACCESS", "NOTE", "ORIGIN",
];
const REPEATABLE: [&str; 2] = ["CAVEAT", "ACCESS"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectiveMarking {
    pub version: Option<String>,
    pub namespace: Option<String>,
    pub sec: Classification,
    pub caveats: Vec<String>,
    pub expires: Option<String>,
    pub downto: Option<Classification>,
    pub access: Vec<String>,
    pub note: Option<String>,
    pub origin: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PspfError(pub String);

impl std::fmt::Display for PspfError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

fn err(msg: impl Into<String>) -> PspfError {
    PspfError(msg.into())
}

/// Parse an `X-Protective-Marking` header value (with or without the name).
pub fn parse_header(value: &str) -> Result<ProtectiveMarking, PspfError> {
    let value = value.trim();
    let value = strip_name(value).unwrap_or(value).trim();
    let fields = fields(value, &HEADER_ORDER)?;
    let mut last = 0;
    let mut seen: Vec<&str> = Vec::new();
    for (key, _) in &fields {
        let rank = HEADER_ORDER.iter().position(|k| k == key).unwrap_or(0);
        if rank < last || (seen.contains(key) && !REPEATABLE.contains(key)) {
            return Err(err(format!("{key} is out of order or repeated")));
        }
        last = rank;
        seen.push(key);
    }
    for required in ["VER", "NS", "SEC"] {
        if !seen.contains(&required) {
            return Err(err(format!("{required} is required")));
        }
    }
    let mut marking = build(&fields)?;
    let version = marking.version.as_deref().unwrap_or("");
    if !is_version(version) {
        return Err(err(format!("VER {version:?} is not a standard version")));
    }
    let namespace = marking.namespace.as_deref().unwrap_or("");
    if !is_domain(namespace) {
        return Err(err(format!("NS {namespace:?} is not a domain")));
    }
    if let Some(origin) = &marking.origin {
        if !is_email(origin) {
            return Err(err("ORIGIN is not an email address"));
        }
    }
    match (&marking.expires, marking.downto) {
        (Some(_), Some(downto)) if downto >= marking.sec => {
            return Err(err("DOWNTO must be lower than SEC"));
        }
        (Some(_), None) | (None, Some(_)) => {
            return Err(err("EXPIRES and DOWNTO go together"));
        }
        _ => {}
    }
    marking.namespace = marking.namespace.map(|ns| ns.to_ascii_lowercase());
    Ok(marking)
}

/// The last `[SEC=...]` marking in a subject. `None` when there is none;
/// `Some(Err)` when one is present but malformed.
pub fn parse_subject(subject: &str) -> Option<Result<ProtectiveMarking, PspfError>> {
    let upper = subject.to_ascii_uppercase();
    let start = upper.rfind("[SEC=")?;
    let rest = &subject[start + 1..];
    let Some(end) = rest.find(']') else {
        return Some(Err(err("subject marking is not closed")));
    };
    let inner = &rest[..end];
    let parsed = fields(inner, &["SEC", "CAVEAT", "ACCESS"]).and_then(|fields| {
        if fields.first().map(|(k, _)| *k) != Some("SEC")
            || fields.iter().filter(|(k, _)| *k == "SEC").count() != 1
        {
            return Err(err("subject marking must start with exactly one SEC"));
        }
        let mut last = 0;
        for (key, _) in &fields {
            let rank = ["SEC", "CAVEAT", "ACCESS"]
                .iter()
                .position(|k| k == key)
                .unwrap_or(0);
            if rank < last {
                return Err(err(format!("{key} is out of order")));
            }
            last = rank;
        }
        build(&fields)
    });
    Some(parsed)
}

/// Every `[SEC=...]` marking in a subject, in order.
pub fn parse_subject_all(subject: &str) -> Vec<Result<ProtectiveMarking, PspfError>> {
    let mut found = Vec::new();
    let mut rest = subject;
    while let Some(marking) = parse_subject(rest) {
        found.push(marking);
        let upper = rest.to_ascii_uppercase();
        match upper.rfind("[SEC=") {
            Some(at) => rest = &rest[..at],
            None => break,
        }
    }
    found.reverse();
    found
}

/// The `SEC=` level in a marking that failed to parse, so a broken marking
/// still counts at the level it claims.
fn salvage_sec(value: &str) -> Option<Classification> {
    let upper = value.to_ascii_uppercase();
    let at = upper.find("SEC=")? + 4;
    let tail = &value[at..];
    let end = tail.find([',', ']']).unwrap_or(tail.len());
    Classification::parse(&tail[..end])
}

/// Read both markings from a raw message and compare them. The effective
/// classification is the highest level found anywhere, so a lower marking
/// elsewhere can never lower enforcement.
pub fn inspect(raw: &[u8]) -> MarkingReport {
    let mut report = MarkingReport::default();
    let end = header_end(raw);
    if end.is_none() && raw.len() > MAX_HEADER_BYTES {
        report.invalid = true;
        report
            .errors
            .push("header section too large to inspect".into());
        return report;
    }
    let head = &raw[..end.unwrap_or(raw.len())];
    let Some(message) = MessageParser::new().parse_headers(head) else {
        return report;
    };
    let mut levels: Vec<Classification> = Vec::new();
    let headers: Vec<String> = message
        .headers_raw()
        .filter(|(name, _)| name.eq_ignore_ascii_case("X-Protective-Marking"))
        .map(|(_, value)| unfold(value))
        .collect();
    let mut header_marking = None;
    for value in &headers {
        match parse_header(value) {
            Ok(marking) => {
                levels.push(marking.sec);
                header_marking.get_or_insert(marking);
            }
            Err(e) => {
                report.invalid = true;
                report.errors.push(format!("header: {e}"));
                levels.extend(salvage_sec(value));
            }
        }
    }
    if headers.len() > 1 {
        report.invalid = true;
        report
            .errors
            .push("header: more than one X-Protective-Marking".into());
    }
    // Every Subject header, raw, plus the decoded one, so encoded words and
    // a second Subject header are both seen.
    let mut subjects: Vec<String> = message
        .headers_raw()
        .filter(|(name, _)| name.eq_ignore_ascii_case("Subject"))
        .map(|(_, value)| unfold(value))
        .collect();
    if subjects.len() > 1 {
        report.invalid = true;
        report.errors.push("more than one Subject header".into());
    }
    let mut subject_marking: Option<ProtectiveMarking> = None;
    subjects.extend(message.subject().map(str::to_string));
    for subject in &subjects {
        for found in parse_subject_all(subject) {
            match found {
                Ok(marking) => {
                    levels.push(marking.sec);
                    if let Some(first) = &subject_marking {
                        if first.sec != marking.sec || first.access != marking.access {
                            report.mismatch = true;
                        }
                    }
                    // Keep the highest subject marking.
                    if subject_marking.as_ref().is_none_or(|m| marking.sec > m.sec) {
                        subject_marking = Some(marking);
                    }
                }
                Err(e) => {
                    report.invalid = true;
                    report.errors.push(format!("subject: {e}"));
                    levels.extend(salvage_sec(subject));
                }
            }
        }
    }
    report.header = header_marking.as_ref().map(|m| m.sec);
    report.subject = subject_marking.as_ref().map(|m| m.sec);
    if let (Some(h), Some(s)) = (&header_marking, &subject_marking) {
        let mut hc = h.caveats.clone();
        let mut sc = s.caveats.clone();
        hc.sort();
        sc.sort();
        report.mismatch |= h.sec != s.sec || h.access != s.access || hc != sc;
    }
    report.classification = levels.into_iter().max();
    let mut caveats: Vec<String> = Vec::new();
    let mut access: Vec<String> = Vec::new();
    for marking in header_marking.iter().chain(subject_marking.iter()) {
        caveats.extend(marking.caveats.iter().cloned());
        access.extend(marking.access.iter().cloned());
    }
    caveats.sort();
    caveats.dedup();
    access.sort();
    access.dedup();
    report.caveats = caveats;
    report.access = access;
    report
}

/// Split `KEY=value, KEY=value` on the known keys only, so commas inside
/// a value (for example a NOTE) do not split it.
fn fields<'k>(value: &str, keys: &[&'k str]) -> Result<Vec<(&'k str, String)>, PspfError> {
    if value.len() > MAX_MARKING_LEN {
        return Err(err("marking is too long"));
    }
    if value.chars().any(|c| c.is_control()) {
        return Err(err("marking contains control characters"));
    }
    let upper = value.to_ascii_uppercase();
    // Start of every `KEY=` that begins the value or follows a comma.
    let mut starts: Vec<(usize, &'k str)> = Vec::new();
    for key in keys {
        let needle = format!("{key}=");
        let mut from = 0;
        while let Some(pos) = upper[from..].find(&needle) {
            let at = from + pos;
            let boundary =
                upper[..at].trim_end().is_empty() || upper[..at].trim_end().ends_with(',');
            if boundary {
                starts.push((at, key));
            }
            from = at + needle.len();
        }
    }
    starts.sort_by_key(|(at, _)| *at);
    if starts.first().map(|(at, _)| upper[..*at].trim().is_empty()) != Some(true) {
        return Err(err("marking does not start with a known field"));
    }
    let mut out = Vec::new();
    for (i, (at, key)) in starts.iter().enumerate() {
        let end = starts
            .get(i + 1)
            .map(|(next, _)| *next)
            .unwrap_or(value.len());
        let raw = value[at + key.len() + 1..end].trim();
        let raw = raw.strip_suffix(',').unwrap_or(raw).trim();
        if raw.is_empty() {
            return Err(err(format!("{key} is empty")));
        }
        out.push((*key, raw.to_string()));
    }
    Ok(out)
}

fn build(fields: &[(&str, String)]) -> Result<ProtectiveMarking, PspfError> {
    let mut sec = None;
    let mut marking = ProtectiveMarking {
        version: None,
        namespace: None,
        sec: Classification::Unofficial,
        caveats: Vec::new(),
        expires: None,
        downto: None,
        access: Vec::new(),
        note: None,
        origin: None,
    };
    for (key, value) in fields {
        match *key {
            "VER" => marking.version = Some(value.clone()),
            "NS" => marking.namespace = Some(value.clone()),
            "SEC" => {
                sec = Some(
                    Classification::parse(value)
                        .ok_or_else(|| err(format!("SEC {value:?} is not a classification")))?,
                )
            }
            "CAVEAT" => marking.caveats.push(caveat(value)?),
            "EXPIRES" => marking.expires = Some(value.clone()),
            "DOWNTO" => {
                marking.downto = Some(
                    Classification::parse(value)
                        .ok_or_else(|| err(format!("DOWNTO {value:?} is not a classification")))?,
                )
            }
            "ACCESS" => marking.access.push(access(value)?),
            "NOTE" => marking.note = Some(value.clone()),
            "ORIGIN" => marking.origin = Some(value.clone()),
            _ => return Err(err(format!("unknown field {key}"))),
        }
    }
    marking.sec = sec.ok_or_else(|| err("SEC is required"))?;
    Ok(marking)
}

/// `TYPE:VALUE`, for example `SH:CABINET` or `RI:REL AUS/USA`.
fn caveat(value: &str) -> Result<String, PspfError> {
    let (kind, text) = value
        .split_once(':')
        .ok_or_else(|| err("CAVEAT must be TYPE:VALUE"))?;
    let kind_ok = (1..=4).contains(&kind.len()) && kind.chars().all(|c| c.is_ascii_uppercase());
    let text_ok = !text.is_empty()
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '-' | '/' | '_' | ':' | '.'));
    if kind_ok && text_ok {
        Ok(value.to_string())
    } else {
        Err(err(format!("CAVEAT {value:?} is malformed")))
    }
}

fn access(value: &str) -> Result<String, PspfError> {
    ACCESS_MARKERS
        .iter()
        .find(|m| m.eq_ignore_ascii_case(value))
        .map(|m| m.to_string())
        .ok_or_else(|| {
            err(format!(
                "ACCESS {value:?} is not an information management marker"
            ))
        })
}

fn is_version(v: &str) -> bool {
    let mut parts = v.split('.');
    let year = parts.next().unwrap_or("");
    let minor = parts.next().unwrap_or("");
    year.len() == 4
        && year.chars().all(|c| c.is_ascii_digit())
        && !minor.is_empty()
        && minor.len() <= 3
        && minor.chars().all(|c| c.is_ascii_digit())
        && parts.next().is_none()
}

fn is_domain(d: &str) -> bool {
    d.contains('.')
        && d.len() <= 253
        && d.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
}

fn is_email(e: &str) -> bool {
    match e.rsplit_once('@') {
        Some((local, domain)) => {
            !local.is_empty()
                && local.len() <= 64
                && !local
                    .chars()
                    .any(|c| c.is_whitespace() || matches!(c, ',' | '<' | '>'))
                && is_domain(domain)
        }
        None => false,
    }
}

fn strip_name(value: &str) -> Option<&str> {
    let (name, rest) = value.split_once(':')?;
    name.trim()
        .eq_ignore_ascii_case("X-Protective-Marking")
        .then_some(rest)
}

fn unfold(value: &str) -> String {
    value
        .split(['\r', '\n'])
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

/// Offset just past the blank line ending the header section, if it is
/// within `MAX_HEADER_BYTES`.
fn header_end(raw: &[u8]) -> Option<usize> {
    let limit = raw.len().min(MAX_HEADER_BYTES);
    raw[..limit]
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 4)
        .or_else(|| {
            raw[..limit]
                .windows(2)
                .position(|w| w == b"\n\n")
                .map(|p| p + 2)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pspf_valid_header_examples_parse() {
        let cases = [
            ("VER=2018.6, NS=gov.au, SEC=OFFICIAL, ORIGIN=jane.citizen@agency.gov.au", Classification::Official),
            ("VER=2024.1, NS=gov.au, SEC=OFFICIAL:Sensitive", Classification::OfficialSensitive),
            ("VER=2024.1, NS=gov.au, SEC=OFFICIAL:Sensitive, ACCESS=Legal-Privilege", Classification::OfficialSensitive),
            ("VER=2018.6, NS=gov.au, SEC=PROTECTED, CAVEAT=SH:CABINET, ORIGIN=a@b.gov.au", Classification::Protected),
            ("X-Protective-Marking: VER=2018.6, NS=gov.au, SEC=UNOFFICIAL", Classification::Unofficial),
            ("VER=2018.6, NS=vic.gov.au, SEC=OFFICIAL:Sensitive, ACCESS=Personal-Privacy, ACCESS=Legislative-Secrecy", Classification::OfficialSensitive),
            ("VER=2018.6, NS=gov.au, SEC=PROTECTED, EXPIRES=2027-01-01, DOWNTO=OFFICIAL, NOTE=reviewed, see file 12, ORIGIN=a@b.gov.au", Classification::Protected),
        ];
        for (value, sec) in cases {
            let marking = parse_header(value).unwrap_or_else(|e| panic!("{value}: {e}"));
            assert_eq!(marking.sec, sec, "{value}");
        }
        let note = parse_header(cases[6].0).unwrap();
        assert_eq!(note.note.as_deref(), Some("reviewed, see file 12"));
        assert_eq!(note.downto, Some(Classification::Official));
    }

    #[test]
    fn pspf_malformed_headers_error() {
        for value in [
            "",
            "SEC=OFFICIAL",
            "VER=2018.6, SEC=OFFICIAL",
            "NS=gov.au, VER=2018.6, SEC=OFFICIAL",
            "VER=2018.6, NS=gov.au, SEC=CONFIDENTIAL",
            "VER=2018.6, NS=gov.au, SEC=OFFICIAL, SEC=PROTECTED",
            "VER=latest, NS=gov.au, SEC=OFFICIAL",
            "VER=2018.6, NS=gov, SEC=OFFICIAL",
            "VER=2018.6, NS=gov.au, SEC=OFFICIAL, ACCESS=Secret-Squirrel",
            "VER=2018.6, NS=gov.au, SEC=OFFICIAL, CAVEAT=CABINET",
            "VER=2018.6, NS=gov.au, SEC=OFFICIAL, ORIGIN=not-an-address",
            "VER=2018.6, NS=gov.au, SEC=PROTECTED, DOWNTO=OFFICIAL",
            "VER=2018.6, NS=gov.au, SEC=OFFICIAL, EXPIRES=2027-01-01, DOWNTO=PROTECTED",
            "VER=2018.6, NS=gov.au, SEC=OFFICIAL\u{7}",
            "junk VER=2018.6, NS=gov.au, SEC=OFFICIAL",
        ] {
            assert!(parse_header(value).is_err(), "{value:?} should be rejected");
        }
        assert!(parse_header(&format!(
            "VER=2018.6, NS=gov.au, SEC=OFFICIAL, NOTE={}",
            "x".repeat(4000)
        ))
        .is_err());
    }

    #[test]
    fn pspf_subject_markings_parse() {
        let found = parse_subject("Budget papers [SEC=OFFICIAL:Sensitive]")
            .unwrap()
            .unwrap();
        assert_eq!(found.sec, Classification::OfficialSensitive);
        let found =
            parse_subject("Re: brief [SEC=PROTECTED, CAVEAT=SH:CABINET, ACCESS=Legal-Privilege]")
                .unwrap()
                .unwrap();
        assert_eq!(found.sec, Classification::Protected);
        assert_eq!(found.caveats, vec!["SH:CABINET"]);
        assert_eq!(found.access, vec!["Legal-Privilege"]);
        assert!(parse_subject("No marking here").is_none());
        assert!(parse_subject("Bad [SEC=WHATEVER]").unwrap().is_err());
        assert!(parse_subject("Open [SEC=OFFICIAL").unwrap().is_err());
    }

    #[test]
    fn pspf_protected_header_with_official_subject_is_a_mismatch() {
        let raw = b"From: a@agency.gov.au\r\nTo: b@other.gov.au\r\n\
X-Protective-Marking: VER=2018.6, NS=gov.au, SEC=PROTECTED,\r\n ORIGIN=a@agency.gov.au\r\n\
Subject: Briefing [SEC=OFFICIAL]\r\n\r\nbody\r\n";
        let report = inspect(raw);
        assert!(report.mismatch);
        assert!(!report.invalid);
        assert_eq!(report.header, Some(Classification::Protected));
        assert_eq!(report.subject, Some(Classification::Official));
        assert_eq!(report.classification, Some(Classification::Protected));
    }

    #[test]
    fn pspf_inspect_flags_invalid_and_duplicate_headers() {
        let raw = b"X-Protective-Marking: SEC=PROTECTED\r\nSubject: hi\r\n\r\n";
        let report = inspect(raw);
        assert!(report.invalid);
        // A broken marking still counts at the level it claims.
        assert_eq!(report.classification, Some(Classification::Protected));
        let raw = b"X-Protective-Marking: VER=2018.6, NS=gov.au, SEC=OFFICIAL\r\n\
X-Protective-Marking: VER=2018.6, NS=gov.au, SEC=PROTECTED\r\nSubject: hi\r\n\r\n";
        assert!(inspect(raw).invalid);
        let unmarked = inspect(b"Subject: hello\r\n\r\nbody");
        assert_eq!(unmarked, MarkingReport::default());
    }

    #[test]
    fn pspf_padding_cannot_hide_a_marking() {
        let mut raw = Vec::new();
        for i in 0..4000 {
            raw.extend_from_slice(format!("X-Pad-{i}: {}\r\n", "x".repeat(70)).as_bytes());
        }
        raw.extend_from_slice(b"X-Protective-Marking: VER=2018.6, NS=gov.au, SEC=PROTECTED\r\nSubject: hi\r\n\r\nbody");
        let report = inspect(&raw);
        assert!(report.invalid, "{report:?}");
    }

    #[test]
    fn pspf_the_highest_marking_wins_and_conflicts_are_flagged() {
        // Header OFFICIAL, subject PROTECTED: enforced as PROTECTED.
        let raw = b"X-Protective-Marking: VER=2018.6, NS=gov.au, SEC=OFFICIAL\r\nSubject: Brief [SEC=PROTECTED]\r\n\r\n";
        let report = inspect(raw);
        assert_eq!(report.classification, Some(Classification::Protected));
        assert!(report.mismatch);
        // Two subject markings: the higher counts and the conflict is flagged.
        let raw = b"Subject: Brief [SEC=PROTECTED] and [SEC=OFFICIAL]\r\n\r\n";
        let report = inspect(raw);
        assert_eq!(report.classification, Some(Classification::Protected));
        assert!(report.mismatch);
        // A broken header still counts at the level it claims.
        let raw = b"X-Protective-Marking: VER=2018.6, NS=gov.au, SEC=SECRET, ORIGIN=bad\r\nSubject: x [SEC=OFFICIAL]\r\n\r\n";
        let report = inspect(raw);
        assert!(report.invalid);
        assert_eq!(report.classification, Some(Classification::Secret));
        // Duplicate Subject headers are invalid.
        let raw = b"Subject: a [SEC=PROTECTED]\r\nSubject: b [SEC=OFFICIAL]\r\n\r\n";
        let report = inspect(raw);
        assert!(report.invalid);
        assert_eq!(report.classification, Some(Classification::Protected));
        // Caveats that differ between header and subject are a mismatch.
        let raw = b"X-Protective-Marking: VER=2018.6, NS=gov.au, SEC=PROTECTED, CAVEAT=SH:CABINET\r\nSubject: x [SEC=PROTECTED]\r\n\r\n";
        let report = inspect(raw);
        assert!(report.mismatch);
        assert_eq!(report.caveats, vec!["SH:CABINET"]);
    }

    #[test]
    fn pspf_encoded_subject_marking_is_read() {
        // "Update [SEC=PROTECTED]" as a base64 encoded word.
        let raw = b"Subject: =?UTF-8?B?VXBkYXRlIFtTRUM9UFJPVEVDVEVEXQ==?=\r\n\r\n";
        assert_eq!(inspect(raw).classification, Some(Classification::Protected));
    }
}
