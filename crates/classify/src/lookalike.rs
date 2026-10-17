//! Lookalike, cousin and homoglyph domains.
//!
//! A candidate is compared with each protected domain on its registrable
//! domain (public suffix list): UTS 39 confusable skeletons of the label and
//! of the whole host, edit distance on the label, suffix swaps (`com.au`,
//! `net.au`, `au`) and cousin names that embed the protected name. The
//! protected domain itself and its subdomains are never flagged.
use currawong_core::report::LookalikeTechnique;

/// The built-in Australian brand list.
pub const BRANDS_AU: &str = include_str!("../../../rules/brands-au.txt");

/// RFC 1035 limits. Longer names are not real hosts and are not compared,
/// which also bounds the edit distance work per candidate.
const MAX_HOST_BYTES: usize = 253;
const MAX_LABEL_CHARS: usize = 63;
/// Labels shorter than this only swap between Australian suffixes, so
/// `my.com` or `anz.co.nz` are not lookalikes of `my.gov.au` or `anz.com`.
const MIN_FREE_SWAP_LABEL: usize = 5;
const AU_SUFFIXES: &[&str] = &[
    "au", "com.au", "net.au", "org.au", "gov.au", "asn.au", "id.au",
];

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
    Protected::new(protected).score(candidate)
}

/// Protected domains, normalised once.
#[derive(Debug, Clone, Default)]
pub struct Protected {
    domains: Vec<Domain>,
}

impl Protected {
    pub fn new(names: &[String]) -> Self {
        let mut protected = Self::default();
        protected.extend(names);
        protected
    }

    pub fn extend(&mut self, names: &[String]) {
        for domain in names.iter().filter_map(|name| Domain::new(name)) {
            if !self
                .domains
                .iter()
                .any(|known| known.registrable == domain.registrable)
            {
                self.domains.push(domain);
            }
        }
    }

    pub fn score(&self, candidate: &str) -> Option<Lookalike> {
        let candidate = Domain::new(candidate)?;
        if self
            .domains
            .iter()
            .any(|target| target.registrable == candidate.registrable)
        {
            return None;
        }
        self.domains
            .iter()
            .filter_map(|target| compare(&candidate, target))
            .max_by(|a, b| a.score.total_cmp(&b.score))
    }
}

fn compare(candidate: &Domain, target: &Domain) -> Option<Lookalike> {
    let found = |technique, score| {
        Some(Lookalike {
            target: target.registrable.clone(),
            technique,
            score,
        })
    };
    let label_homoglyph = candidate.label != target.label && candidate.skeleton == target.skeleton;
    // Confusables in the suffix (`ato.gоv.au` with a Cyrillic о) move the
    // registrable domain, so compare the whole host's skeleton as well.
    let host_homoglyph = candidate.host_skeleton == target.registrable_skeleton
        || candidate
            .host_skeleton
            .ends_with(&format!(".{}", target.registrable_skeleton));
    if label_homoglyph || host_homoglyph {
        return found(LookalikeTechnique::Homoglyph, 0.95);
    }
    let length = target.label.chars().count();
    if candidate.label == target.label
        && (length >= MIN_FREE_SWAP_LABEL
            || (AU_SUFFIXES.contains(&candidate.suffix.as_str())
                && AU_SUFFIXES.contains(&target.suffix.as_str())))
    {
        return found(LookalikeTechnique::SuffixSwap, 0.8);
    }
    // Short labels such as `ato` or `nab` are a single edit from ordinary
    // words, so they only match on skeletons, suffixes and cousins.
    let max_edits = match length {
        0..=4 => 0,
        5..=8 => 1,
        _ => 2,
    };
    if max_edits > 0
        && candidate
            .skeleton
            .chars()
            .count()
            .abs_diff(target.skeleton.chars().count())
            <= max_edits
    {
        let edits = strsim::damerau_levenshtein(&candidate.skeleton, &target.skeleton);
        if edits <= max_edits {
            return found(
                LookalikeTechnique::EditDistance,
                0.85 - 0.1 * (edits as f64 - 1.0),
            );
        }
    }
    if embeds(&candidate.host, &target.registrable) {
        return found(LookalikeTechnique::Cousin, 0.7);
    }
    // A hyphenated label with the protected name as one part. An equal label
    // under a foreign suffix was already left to the suffix rule above.
    if length >= 3
        && candidate.label.contains('-')
        && candidate.label.split('-').any(|part| part == target.label)
    {
        return found(LookalikeTechnique::Cousin, 0.6);
    }
    None
}

/// `host` contains `name` between dots, hyphens or the ends, for example
/// `ato.gov.au.example.net`, `login-ato.gov.au.example.net` or `ato.gov.au-secure.com`.
fn embeds(host: &str, name: &str) -> bool {
    host.match_indices(name).any(|(start, _)| {
        let before = host[..start].chars().next_back();
        let after = host[start + name.len()..].chars().next();
        matches!(before, None | Some('.' | '-')) && matches!(after, None | Some('.' | '-'))
    })
}

#[derive(Debug, Clone)]
struct Domain {
    /// Lowercase Unicode form of the whole host.
    host: String,
    registrable: String,
    /// The registrable domain without its public suffix.
    label: String,
    suffix: String,
    skeleton: String,
    host_skeleton: String,
    registrable_skeleton: String,
}

impl Domain {
    fn new(name: &str) -> Option<Self> {
        let name = name.trim().trim_end_matches('.');
        if name.is_empty() || name.len() > MAX_HOST_BYTES {
            return None;
        }
        let (unicode, result) = idna::domain_to_unicode(name);
        let host = if result.is_ok() {
            unicode
        } else {
            name.to_lowercase()
        };
        if host
            .split('.')
            .any(|label| label.is_empty() || label.chars().count() > MAX_LABEL_CHARS)
        {
            return None;
        }
        let registrable = psl::domain_str(&host)?.to_string();
        let suffix = psl::suffix_str(&host)?.to_string();
        let label = registrable
            .strip_suffix(&suffix)?
            .trim_end_matches('.')
            .to_string();
        if label.is_empty() {
            return None;
        }
        Some(Self {
            skeleton: skeleton(&label),
            host_skeleton: skeleton(&host),
            registrable_skeleton: skeleton(&registrable),
            host,
            registrable,
            label,
            suffix,
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

    #[test]
    fn embedded_names_need_a_boundary() {
        assert!(embeds("ato.gov.au-secure.com", "ato.gov.au"));
        assert!(embeds("login-ato.gov.au.example.net", "ato.gov.au"));
        assert!(!embeds("plato.gov.au.example.net", "ato.gov.au"));
    }
}
