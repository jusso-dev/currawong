//! Lookalike, cousin and homoglyph domains.
//!
//! A candidate is compared with each protected domain on its registrable
//! domain (public suffix list): UTS 39 confusable skeletons, edit distance on
//! the label, suffix swaps (`com.au`, `net.au`, `au`) and cousin names that
//! embed the protected label. The protected domain itself and its subdomains
//! are never flagged.
use currawong_core::report::LookalikeTechnique;

/// The built-in Australian brand list.
pub const BRANDS_AU: &str = include_str!("../../../rules/brands-au.txt");

#[derive(Debug, Clone, PartialEq)]
pub struct Lookalike {
    pub target: String,
    pub technique: LookalikeTechnique,
    pub score: f64,
}

/// Domains from a brand list. Each line is `Name: domain domain ...`.
pub fn parse_brands(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter_map(|line| line.split_once(':').map(|(_, domains)| domains))
        .flat_map(str::split_whitespace)
        .map(str::to_ascii_lowercase)
        .collect()
}

/// The strongest imitation of a protected domain, if any.
pub fn score(candidate: &str, protected: &[String]) -> Option<Lookalike> {
    let candidate = Domain::new(candidate)?;
    let targets: Vec<Domain> = protected.iter().filter_map(|d| Domain::new(d)).collect();
    if targets
        .iter()
        .any(|target| target.registrable == candidate.registrable)
    {
        return None;
    }
    targets
        .iter()
        .filter_map(|target| compare(&candidate, target))
        .max_by(|a, b| a.score.total_cmp(&b.score))
}

fn compare(candidate: &Domain, target: &Domain) -> Option<Lookalike> {
    let found = |technique, score| {
        Some(Lookalike {
            target: target.registrable.clone(),
            technique,
            score,
        })
    };
    if candidate.label != target.label && candidate.skeleton == target.skeleton {
        return found(LookalikeTechnique::Homoglyph, 0.95);
    }
    if candidate.label == target.label {
        return found(LookalikeTechnique::SuffixSwap, 0.8);
    }
    // Short labels such as `ato` or `nab` are a single edit from ordinary
    // words, so they only match on skeletons, suffixes and cousins.
    let length = target.label.chars().count();
    let max_edits = match length {
        0..=4 => 0,
        5..=8 => 1,
        _ => 2,
    };
    if max_edits > 0 {
        let edits = strsim::damerau_levenshtein(&candidate.skeleton, &target.skeleton);
        if edits <= max_edits {
            return found(
                LookalikeTechnique::EditDistance,
                0.85 - 0.1 * (edits as f64 - 1.0),
            );
        }
    }
    let nested = format!("{}.", target.registrable);
    if candidate.host.starts_with(&nested) || candidate.host.contains(&format!(".{nested}")) {
        return found(LookalikeTechnique::Cousin, 0.7);
    }
    if candidate.label.split('-').any(|part| part == target.label)
        || (length >= 5 && candidate.label.contains(&target.label))
    {
        return found(LookalikeTechnique::Cousin, 0.6);
    }
    None
}

#[derive(Debug)]
struct Domain {
    /// Lowercase Unicode form of the whole host.
    host: String,
    registrable: String,
    /// The registrable domain without its public suffix.
    label: String,
    skeleton: String,
}

impl Domain {
    fn new(name: &str) -> Option<Self> {
        let name = name.trim().trim_end_matches('.');
        if name.is_empty() {
            return None;
        }
        let (unicode, result) = idna::domain_to_unicode(name);
        let host = if result.is_ok() {
            unicode
        } else {
            name.to_lowercase()
        };
        let registrable = psl::domain_str(&host)?.to_string();
        let suffix = psl::suffix_str(&host)?;
        let label = registrable
            .strip_suffix(suffix)?
            .trim_end_matches('.')
            .to_string();
        if label.is_empty() {
            return None;
        }
        let skeleton = skeleton(&label);
        Some(Self {
            host,
            registrable,
            label,
            skeleton,
        })
    }
}

/// UTS 39 skeleton, then lowercase, so `0` and `O` meet `o`.
fn skeleton(text: &str) -> String {
    unicode_security::skeleton(text)
        .collect::<String>()
        .to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn brand_list_parses() {
        let brands = parse_brands(BRANDS_AU);
        assert!(brands.contains(&"ato.gov.au".to_string()));
        assert!(brands.contains(&"mygov.au".to_string()));
        assert!(!brands.iter().any(|d| d.contains(' ') || d.contains(':')));
    }
}
