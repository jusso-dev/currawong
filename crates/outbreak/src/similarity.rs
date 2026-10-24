//! TLSH confirms similarity (distance <=100 including length) after indexed
//! MinHash retrieval: 16 minima of five-byte shingles, eight LSH bands.
//! Short/low-entropy inputs use eight equal minima. This is a hint, not AV.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Digest {
    minhash: [u64; 16],
    tlsh: Option<String>,
}

fn mix(mut n: u64) -> u64 {
    n = (n ^ (n >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    n = (n ^ (n >> 27)).wrapping_mul(0x94d049bb133111eb);
    n ^ (n >> 31)
}

pub fn digest(bytes: &[u8]) -> Option<Digest> {
    if bytes.len() < 32 {
        return None;
    }
    let mut out = [u64::MAX; 16];
    for shingle in bytes[..bytes.len().min(256 * 1024)].windows(5) {
        let mut hash = 0xcbf29ce484222325_u64;
        for b in shingle {
            hash = (hash ^ u64::from(*b)).wrapping_mul(0x100000001b3);
        }
        for (i, value) in out.iter_mut().enumerate() {
            *value = (*value).min(mix(hash ^ mix(i as u64 + 1)));
        }
    }
    let tlsh = tlsh2::TlshDefaultBuilder::build_from(&bytes[..bytes.len().min(256 * 1024)])
        .map(|d| String::from_utf8(d.hash().to_vec()).expect("TLSH is ASCII"));
    Some(Digest { minhash: out, tlsh })
}

pub fn similar(a: &Digest, b: &Digest) -> bool {
    if let (Some(a), Some(b)) = (&a.tlsh, &b.tlsh) {
        let (Ok(a), Ok(b)) = (
            a.parse::<tlsh2::TlshDefault>(),
            b.parse::<tlsh2::TlshDefault>(),
        ) else {
            return false;
        };
        a.diff(&b, true) <= 100
    } else {
        a.minhash
            .iter()
            .zip(&b.minhash)
            .filter(|(a, b)| a == b)
            .count()
            >= 8
    }
}

pub fn bands(digest: &Digest) -> impl Iterator<Item = String> + '_ {
    digest
        .minhash
        .as_chunks::<2>()
        .0
        .iter()
        .enumerate()
        .map(|(i, pair)| format!("{i}:{:016x}{:016x}", pair[0], pair[1]))
}

/// Strip URLs, numbers, tracking tokens and whitespace runs. Bound work even
/// if the caller supplies a large decoded MIME body.
pub fn normalise_body(text: &str) -> String {
    let mut out = String::new();
    for token in text.split_whitespace().take(32_768) {
        if token.len() > 40 {
            continue;
        }
        let token = token.to_lowercase();
        if token.contains("://")
            || token.starts_with("www.")
            || token.len() > 40
            || token.contains("utm_")
            || token.starts_with("cid:")
        {
            continue;
        }
        let token: String = token.chars().filter(|c| !c.is_numeric()).collect();
        if !token.is_empty() {
            if !out.is_empty() {
                out.push(' ');
            }
            out.push_str(&token);
        }
        if out.len() >= 256 * 1024 {
            break;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn normalisation_and_near_matches() {
        let a = normalise_body("PAY invoice 123   today https://a.test/?id=2 utm_id=abc");
        let b = normalise_body("pay INVOICE 456 today https://b.test/?id=9");
        assert_eq!(a, b);
        let text = "Please review the attached invoice for last months services and confirm payment with your usual account manager. ".repeat(20);
        let changed = text.replace("last months", "this months");
        let a = digest(text.as_bytes()).unwrap();
        let b = digest(changed.as_bytes()).unwrap();
        assert!(similar(&a, &b));
        assert!(bands(&a).any(|a| bands(&b).any(|b| a == b)));
        assert!(!similar(
            &a,
            &digest(b"The quick brown fox jumped over the sleeping dog in the garden").unwrap()
        ));
        assert!(digest(b"ok").is_none());
    }
}
