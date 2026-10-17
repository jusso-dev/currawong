//! Identifier and protective-marking parsers used by the fuzzer.
//! Blocking on these findings is an M2 policy. M1 only recognises them.
//!
//! `123456782` is a published TFN checksum sample, not a real identifier.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectiveMarking {
    Official,
    OfficialSensitive,
    Protected,
}

pub fn parse_pspf(value: &str) -> Option<ProtectiveMarking> {
    let value = value.trim();
    let value = value
        .strip_prefix("X-Protective-Marking:")
        .unwrap_or(value)
        .trim();
    match value.to_ascii_lowercase().as_str() {
        "official" => Some(ProtectiveMarking::Official),
        "official: sensitive" | "official:sensitive" => Some(ProtectiveMarking::OfficialSensitive),
        "protected" => Some(ProtectiveMarking::Protected),
        _ => None,
    }
}

/// ATO modulus-11 check. Weights are 1, 4, 3, 7, 5, 8, 6, 9, 10.
pub fn tfn_checksum(digits: &[u8; 9]) -> bool {
    const WEIGHTS: [u32; 9] = [1, 4, 3, 7, 5, 8, 6, 9, 10];
    let sum: u32 = digits
        .iter()
        .zip(WEIGHTS)
        .map(|(digit, weight)| u32::from(*digit) * weight)
        .sum();
    sum.is_multiple_of(11)
}

pub fn find_tfns(text: &str) -> Vec<String> {
    let bytes = text.as_bytes();
    let limit = bytes.len().min(256 * 1024);
    let mut digits = Vec::with_capacity(9);
    let mut found = Vec::new();
    let mut i = 0;
    while i < limit && found.len() < 16 {
        let b = bytes[i];
        if b.is_ascii_digit() {
            digits.push(b - b'0');
            if digits.len() == 9 {
                let mut array = [0u8; 9];
                array.copy_from_slice(&digits);
                if tfn_checksum(&array) {
                    found.push(digits.iter().map(|d| char::from(b'0' + d)).collect());
                }
                digits.remove(0);
            }
            i += 1;
            continue;
        }
        if b == b' ' || b == b'-' {
            i += 1;
            continue;
        }
        digits.clear();
        i += 1;
    }
    found
}

pub fn fuzz_scan(data: &[u8]) {
    let end = data.len().min(64 * 1024);
    let text = String::from_utf8_lossy(&data[..end]);
    let _ = find_tfns(&text);
    let _ = parse_pspf(&text);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn published_tfn_sample_passes_and_pspf_values_parse() {
        assert!(tfn_checksum(&[1, 2, 3, 4, 5, 6, 7, 8, 2]));
        assert!(!tfn_checksum(&[1, 2, 3, 4, 5, 6, 7, 8, 3]));
        assert_eq!(
            find_tfns("sample 123456782 only"),
            vec!["123456782".to_string()]
        );
        assert_eq!(
            parse_pspf("OFFICIAL: Sensitive"),
            Some(ProtectiveMarking::OfficialSensitive)
        );
        assert_eq!(parse_pspf("PROTECTED"), Some(ProtectiveMarking::Protected));
        assert_eq!(parse_pspf("SECRET"), None);
    }
}
