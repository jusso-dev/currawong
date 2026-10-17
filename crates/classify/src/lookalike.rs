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
/// A suffix swap is an Australian suffix, or for labels of at least
/// `MIN_GENERIC_SWAP_LABEL` characters a generic one. Other country suffixes
/// (`westpac.co.nz`, `anz.com.sg`) are usually the brand's own sites, and short
/// ordinary words (`my.com`, `word.org`) are usually someone else's.
const MIN_GENERIC_SWAP_LABEL: usize = 6;
const AU_SUFFIXES: &[&str] = &[
    "au", "com.au", "net.au", "org.au", "gov.au", "asn.au", "id.au",
];
const GENERIC_SUFFIXES: &[&str] = &["com", "net", "org", "co", "info", "biz"];
/// Edit distance needs a label this long; `opus` is one edit from `optus`.
const MIN_EDIT_LABEL: usize = 6;
/// Hosting and CDN domains whose customer hosts often embed the customer's
/// own name (`ato.gov.au.cdn.cloudflare.net`). They are not cousins.
const CDN_DOMAINS: &[&str] = &[
    "akamai.net",
    "akamaiedge.net",
    "akamaihd.net",
    "azureedge.net",
    "azurefd.net",
    "cloudflare.net",
    "cloudfront.net",
    "edgekey.net",
    "edgesuite.net",
    "fastly.net",
    "trafficmanager.net",
];

#[derive(Debug, Clone, PartialEq)]
pub struct Lookalike {
    pub target: String,
    pub technique: LookalikeTechnique,
    pub score: f64,
}

/// Protected domains from a brand list. Each line is
/// `Name: domain domain ... !sibling ...`; `!` marks the brand's own sites
/// elsewhere (`!anz.co.nz`), which are never flagged and are not targets.
pub fn parse_brands(text: &str) -> Vec<String> {
    brand_entries(text)
        .filter(|entry| !entry.starts_with('!'))
        .collect()
}

/// The `!sibling` domains from a brand list.
pub fn parse_brand_siblings(text: &str) -> Vec<String> {
    brand_entries(text)
        .filter_map(|entry| entry.strip_prefix('!').map(str::to_string))
        .collect()
}

fn brand_entries(text: &str) -> impl Iterator<Item = String> + '_ {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter_map(|line| line.split_once(':').map(|(_, domains)| domains))
        .flat_map(str::split_whitespace)
        .map(str::to_ascii_lowercase)
}

/// The strongest imitation of a protected domain, if any.
pub fn score(candidate: &str, protected: &[String]) -> Option<Lookalike> {
    Protected::new(protected).score(candidate)
}

/// Protected domains, normalised once, and allowed domains that are never flagged.
#[derive(Debug, Clone, Default)]
pub struct Protected {
    domains: Vec<Domain>,
    allowed: Vec<String>,
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

    /// Registrable domains that are never lookalikes, such as a brand's
    /// sibling sites or a tenant's partners.
    pub fn allow(&mut self, names: &[String]) {
        for domain in names.iter().filter_map(|name| Domain::new(name)) {
            if !self.allowed.contains(&domain.registrable) {
                self.allowed.push(domain.registrable);
            }
        }
    }

    pub fn score(&self, candidate: &str) -> Option<Lookalike> {
        let candidate = Domain::new(candidate)?;
        if self.allowed.contains(&candidate.registrable)
            || self
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
    let suffix = candidate.suffix.as_str();
    if candidate.label == target.label
        && (AU_SUFFIXES.contains(&suffix)
            || (length >= MIN_GENERIC_SWAP_LABEL && GENERIC_SUFFIXES.contains(&suffix)))
    {
        return found(LookalikeTechnique::SuffixSwap, 0.8);
    }
    // Short labels such as `ato`, `nab` or `optus` are a single edit from
    // ordinary words, so they only match on skeletons, suffixes and cousins.
    let max_edits = match length {
        0..MIN_EDIT_LABEL => 0,
        MIN_EDIT_LABEL..=8 => 1,
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
    // The protected name must sit in front of the candidate's own suffix:
    // `xero.com.au` is `xero` under `com.au`, not `xero.com` embedded.
    let before_suffix = &candidate.host[..candidate.host.len() - candidate.suffix.len() - 1];
    // CDN names can be public suffixes themselves (`cdn.cloudflare.net`), so
    // match on the host.
    let on_cdn = CDN_DOMAINS
        .iter()
        .any(|cdn| candidate.host.ends_with(&format!(".{cdn}")));
    if embeds(before_suffix, &target.registrable) && !on_cdn {
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
