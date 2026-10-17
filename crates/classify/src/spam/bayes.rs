//! Per-tenant Robinson-Fisher naive Bayes.
//!
//! Tokens are body words, header-prefixed words and URL hosts. Counts live in
//! `bayes_tokens(tenant_id, token_hash, spam, ham)`; only a hash of each token
//! is stored. Token probabilities use Robinson's f(w) and are combined with
//! Fisher's chi-squared method, as in SpamBayes.
use super::SpamError;
use crate::message::{address_domain, url_host, MessageView};
use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, path::Path, sync::Mutex};

const MAX_TOKENS: usize = 2000;
/// Robinson's strength and assumed probability for rare tokens.
const STRENGTH: f64 = 1.0;
const UNKNOWN: f64 = 0.5;
/// Tokens closer to 0.5 than this carry no evidence.
const MIN_DEVIATION: f64 = 0.1;
const MAX_DISCRIMINATORS: usize = 150;
/// Header words that become `name:word` tokens.
const PREFIXED_HEADERS: &[&str] = &[
    "subject",
    "from",
    "reply-to",
    "to",
    "x-mailer",
    "content-type",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Label {
    Spam,
    Ham,
}

pub struct Bayes {
    conn: Mutex<Connection>,
}

impl Bayes {
    /// Open or create the store. The directory must already exist.
    pub fn open(path: &Path) -> Result<Self, SpamError> {
        Self::init(Connection::open(path)?)
    }

    pub fn in_memory() -> Result<Self, SpamError> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Self, SpamError> {
        // Token counts can be retrained, so trade fsync per message for speed.
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS bayes_tokens (
                tenant_id TEXT NOT NULL,
                token_hash INTEGER NOT NULL,
                spam INTEGER NOT NULL DEFAULT 0,
                ham INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (tenant_id, token_hash)
            );
            CREATE TABLE IF NOT EXISTS bayes_messages (
                tenant_id TEXT PRIMARY KEY,
                spam INTEGER NOT NULL DEFAULT 0,
                ham INTEGER NOT NULL DEFAULT 0
            );",
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Count one message's tokens as spam or ham for a tenant.
    pub fn train(&self, tenant: &str, tokens: &[String], label: Label) -> Result<(), SpamError> {
        let (spam, ham) = match label {
            Label::Spam => (1, 0),
            Label::Ham => (0, 1),
        };
        let mut conn = self.conn.lock().map_err(|_| poisoned())?;
        let tx = conn.transaction()?;
        {
            let mut upsert = tx.prepare_cached(
                "INSERT INTO bayes_tokens (tenant_id, token_hash, spam, ham) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT (tenant_id, token_hash)
                 DO UPDATE SET spam = spam + excluded.spam, ham = ham + excluded.ham",
            )?;
            for token in tokens {
                upsert.execute(params![tenant, token_hash(token), spam, ham])?;
            }
        }
        tx.execute(
            "INSERT INTO bayes_messages (tenant_id, spam, ham) VALUES (?1, ?2, ?3)
             ON CONFLICT (tenant_id)
             DO UPDATE SET spam = spam + excluded.spam, ham = ham + excluded.ham",
            params![tenant, spam, ham],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Spam probability from 0 to 1. 0.5 until the tenant has trained both classes.
    pub fn score(&self, tenant: &str, tokens: &[String]) -> Result<f64, SpamError> {
        let conn = self.conn.lock().map_err(|_| poisoned())?;
        let totals: Option<(i64, i64)> = conn
            .query_row(
                "SELECT spam, ham FROM bayes_messages WHERE tenant_id = ?1",
                params![tenant],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let Some((spam_total, ham_total)) = totals else {
            return Ok(0.5);
        };
        if spam_total == 0 || ham_total == 0 {
            return Ok(0.5);
        }
        let mut lookup = conn.prepare_cached(
            "SELECT spam, ham FROM bayes_tokens WHERE tenant_id = ?1 AND token_hash = ?2",
        )?;
        let mut probabilities = Vec::new();
        for token in tokens {
            let counts: Option<(i64, i64)> = lookup
                .query_row(params![tenant, token_hash(token)], |row| {
                    Ok((row.get(0)?, row.get(1)?))
                })
                .optional()?;
            let Some((spam, ham)) = counts else { continue };
            let f = robinson(spam, ham, spam_total, ham_total);
            if (f - 0.5).abs() >= MIN_DEVIATION {
                probabilities.push(f);
            }
        }
        probabilities.sort_by(|a, b| (b - 0.5).abs().total_cmp(&(a - 0.5).abs()));
        probabilities.truncate(MAX_DISCRIMINATORS);
        Ok(fisher(&probabilities))
    }
}

/// Robinson's f(w): the token's spam ratio pulled towards 0.5 when it is rare.
fn robinson(spam: i64, ham: i64, spam_total: i64, ham_total: i64) -> f64 {
    let spam_ratio = spam as f64 / spam_total as f64;
    let ham_ratio = ham as f64 / ham_total as f64;
    let p = if spam_ratio + ham_ratio == 0.0 {
        UNKNOWN
    } else {
        spam_ratio / (spam_ratio + ham_ratio)
    };
    let n = (spam + ham) as f64;
    ((STRENGTH * UNKNOWN + n * p) / (STRENGTH + n)).clamp(0.01, 0.99)
}

/// Fisher's method: combine with inverse chi-squared in both directions.
fn fisher(probabilities: &[f64]) -> f64 {
    if probabilities.is_empty() {
        return 0.5;
    }
    let n = probabilities.len();
    let ln_spam: f64 = probabilities.iter().map(|p| (1.0 - p).ln()).sum();
    let ln_ham: f64 = probabilities.iter().map(|p| p.ln()).sum();
    let spamminess = 1.0 - chi2q(-2.0 * ln_spam, 2 * n);
    let hamminess = 1.0 - chi2q(-2.0 * ln_ham, 2 * n);
    (spamminess - hamminess + 1.0) / 2.0
}

/// Upper tail of the chi-squared distribution for even degrees of freedom.
fn chi2q(x2: f64, freedom: usize) -> f64 {
    let m = x2 / 2.0;
    let mut term = (-m).exp();
    let mut sum = term;
    for i in 1..freedom / 2 {
        term *= m / i as f64;
        sum += term;
    }
    sum.min(1.0)
}

fn token_hash(token: &str) -> i64 {
    let digest = Sha256::digest(token.as_bytes());
    i64::from_be_bytes(digest[..8].try_into().expect("eight bytes"))
}

fn poisoned() -> SpamError {
    SpamError::Store("bayes store lock poisoned".into())
}

/// Unique tokens for one message: body words, `header:word` tokens, header
/// names, sender domains and URL hosts.
pub fn tokens(view: &MessageView, urls: &[String]) -> Vec<String> {
    let mut out = BTreeSet::new();
    for word in words(&view.body) {
        out.insert(word);
    }
    for (name, value) in &view.headers {
        let name = name.to_ascii_lowercase();
        out.insert(format!("header:{name}"));
        if PREFIXED_HEADERS.contains(&name.as_str()) {
            for word in words(value) {
                out.insert(format!("{name}:{word}"));
            }
        }
    }
    for address in view.from.iter().chain(&view.reply_to) {
        if let Some(domain) = address_domain(address) {
            out.insert(format!("sender:{}", domain.to_ascii_lowercase()));
        }
    }
    for link in view.urls.iter().chain(urls) {
        if let Some(host) = url_host(link) {
            out.insert(format!("url:{host}"));
        }
    }
    out.into_iter().take(MAX_TOKENS).collect()
}

fn words(text: &str) -> impl Iterator<Item = String> + '_ {
    text.split(|ch: char| !ch.is_alphanumeric())
        .filter(|word| (3..=20).contains(&word.chars().count()))
        .map(str::to_lowercase)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn untrained_tenant_scores_one_half() {
        let bayes = Bayes::in_memory().unwrap();
        let tokens = vec!["anything".to_string()];
        assert_eq!(bayes.score("t1", &tokens).unwrap(), 0.5);
        bayes.train("t1", &tokens, Label::Spam).unwrap();
        assert_eq!(bayes.score("t1", &tokens).unwrap(), 0.5);
    }

    #[test]
    fn tenants_are_trained_separately() {
        let bayes = Bayes::in_memory().unwrap();
        let spam = vec!["casino".to_string(), "bonus".to_string()];
        let ham = vec!["roster".to_string(), "minutes".to_string()];
        for _ in 0..5 {
            bayes.train("t1", &spam, Label::Spam).unwrap();
            bayes.train("t1", &ham, Label::Ham).unwrap();
        }
        assert!(bayes.score("t1", &spam).unwrap() > 0.9);
        assert!(bayes.score("t1", &ham).unwrap() < 0.1);
        assert_eq!(bayes.score("t2", &spam).unwrap(), 0.5);
    }

    #[test]
    fn chi2q_matches_known_values() {
        assert!((chi2q(0.0, 2) - 1.0).abs() < 1e-12);
        // P(X > 2) for 2 degrees of freedom is e^-1.
        assert!((chi2q(2.0, 2) - (-1.0f64).exp()).abs() < 1e-12);
    }
}
