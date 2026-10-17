//! Per-tenant Robinson-Fisher naive Bayes.
//!
//! Tokens are body words, header-prefixed words, sender domains and URL hosts.
//! Counts live in `bayes_tokens(tenant_id, token_hash, spam, ham)`; only a
//! hash of each token is stored. Token probabilities use Robinson's f(w) and
//! are combined with Fisher's chi-squared method, as in SpamBayes. Every
//! token in a message is looked up and the strongest discriminators are used,
//! so padding a message with unknown words does not dilute it.
use super::SpamError;
use crate::message::{address_domain, url_host, MessageView};
use rusqlite::{params, params_from_iter, types::Value, Connection, OptionalExtension};
use sha2::{Digest, Sha256};
use std::{collections::HashSet, path::Path, sync::Mutex};

/// Header, sender and URL tokens come first, then body words in order.
/// The body is already capped by `MessageView`, so this is a backstop.
const MAX_TOKENS: usize = 20_000;
/// Robinson's strength and assumed probability for rare tokens.
const STRENGTH: f64 = 1.0;
const UNKNOWN: f64 = 0.5;
/// Tokens closer to 0.5 than this carry no evidence.
const MIN_DEVIATION: f64 = 0.1;
const MAX_DISCRIMINATORS: usize = 150;
/// Hashes per `IN (...)` lookup.
const LOOKUP_CHUNK: usize = 500;
/// Token rows kept per tenant. Training beyond this evicts the rarest tokens.
pub const DEFAULT_MAX_TOKENS_PER_TENANT: usize = 500_000;
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

impl Label {
    fn counts(self) -> (i64, i64) {
        match self {
            Self::Spam => (1, 0),
            Self::Ham => (0, 1),
        }
    }

    fn code(self) -> i64 {
        match self {
            Self::Spam => 1,
            Self::Ham => 0,
        }
    }
}

/// What `train` did with a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trained {
    New,
    /// Already trained with this label. Nothing changed.
    Unchanged,
    /// Trained before with the other label, which was reversed first.
    Relabelled,
}

pub struct Bayes {
    conn: Mutex<Connection>,
    max_tokens: usize,
}

impl Bayes {
    /// Open or create the store. The directory must already exist.
    pub fn open(path: &Path) -> Result<Self, SpamError> {
        Self::init(Connection::open(path)?)
    }

    pub fn in_memory() -> Result<Self, SpamError> {
        Self::init(Connection::open_in_memory()?)
    }

    /// Token rows kept per tenant before the rarest are evicted.
    pub fn with_max_tokens(mut self, max_tokens: usize) -> Self {
        self.max_tokens = max_tokens.max(1);
        self
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
            );
            CREATE TABLE IF NOT EXISTS bayes_trained (
                tenant_id TEXT NOT NULL,
                message_id TEXT NOT NULL,
                label INTEGER NOT NULL,
                PRIMARY KEY (tenant_id, message_id)
            );",
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
            max_tokens: DEFAULT_MAX_TOKENS_PER_TENANT,
        })
    }

    /// Count one message's tokens as spam or ham for a tenant. Training the
    /// same message again is a no-op; training it with the other label
    /// reverses the first label.
    pub fn train(
        &self,
        tenant: &str,
        message_id: &str,
        tokens: &[String],
        label: Label,
    ) -> Result<Trained, SpamError> {
        let mut conn = self.conn.lock().map_err(|_| poisoned())?;
        let tx = conn.transaction()?;
        let previous: Option<i64> = tx
            .query_row(
                "SELECT label FROM bayes_trained WHERE tenant_id = ?1 AND message_id = ?2",
                params![tenant, message_id],
                |row| row.get(0),
            )
            .optional()?;
        let outcome = match previous {
            Some(code) if code == label.code() => return Ok(Trained::Unchanged),
            Some(_) => Trained::Relabelled,
            None => Trained::New,
        };
        let (spam, ham) = label.counts();
        if outcome == Trained::Relabelled {
            // The old label is the other one: take its counts back off.
            let mut forget = tx.prepare_cached(
                "UPDATE bayes_tokens SET spam = MAX(spam - ?3, 0), ham = MAX(ham - ?4, 0)
                 WHERE tenant_id = ?1 AND token_hash = ?2",
            )?;
            for token in tokens {
                forget.execute(params![tenant, token_hash(token), ham, spam])?;
            }
            tx.execute(
                "UPDATE bayes_messages SET spam = MAX(spam - ?2, 0), ham = MAX(ham - ?3, 0)
                 WHERE tenant_id = ?1",
                params![tenant, ham, spam],
            )?;
        }
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
        tx.execute(
            "INSERT INTO bayes_trained (tenant_id, message_id, label) VALUES (?1, ?2, ?3)
             ON CONFLICT (tenant_id, message_id) DO UPDATE SET label = excluded.label",
            params![tenant, message_id, label.code()],
        )?;
        let rows: i64 = tx.query_row(
            "SELECT COUNT(*) FROM bayes_tokens WHERE tenant_id = ?1",
            params![tenant],
            |row| row.get(0),
        )?;
        let max = self.max_tokens as i64;
        if rows > max {
            // Evict down to 90% so the next message does not prune again.
            tx.execute(
                "DELETE FROM bayes_tokens WHERE rowid IN (
                    SELECT rowid FROM bayes_tokens WHERE tenant_id = ?1
                    ORDER BY spam + ham ASC, rowid ASC LIMIT ?2)",
                params![tenant, rows - max * 9 / 10],
            )?;
        }
        tx.commit()?;
        Ok(outcome)
    }

    /// Trained spam and ham message counts for a tenant.
    pub fn totals(&self, tenant: &str) -> Result<(i64, i64), SpamError> {
        let conn = self.conn.lock().map_err(|_| poisoned())?;
        Ok(conn
            .query_row(
                "SELECT spam, ham FROM bayes_messages WHERE tenant_id = ?1",
                params![tenant],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?
            .unwrap_or((0, 0)))
    }

    /// Token rows stored for a tenant.
    pub fn token_rows(&self, tenant: &str) -> Result<i64, SpamError> {
        let conn = self.conn.lock().map_err(|_| poisoned())?;
        Ok(conn.query_row(
            "SELECT COUNT(*) FROM bayes_tokens WHERE tenant_id = ?1",
            params![tenant],
            |row| row.get(0),
        )?)
    }

    /// Spam probability from 0 to 1. 0.5 until the tenant has trained both classes.
    pub fn score(&self, tenant: &str, tokens: &[String]) -> Result<f64, SpamError> {
        let (spam_total, ham_total) = self.totals(tenant)?;
        if spam_total == 0 || ham_total == 0 {
            return Ok(0.5);
        }
        let hashes: Vec<i64> = tokens
            .iter()
            .map(|token| token_hash(token))
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        let conn = self.conn.lock().map_err(|_| poisoned())?;
        let mut probabilities = Vec::new();
        for chunk in hashes.chunks(LOOKUP_CHUNK) {
            let placeholders = (0..chunk.len())
                .map(|i| format!("?{}", i + 2))
                .collect::<Vec<_>>()
                .join(",");
            let mut lookup = conn.prepare_cached(&format!(
                "SELECT spam, ham FROM bayes_tokens WHERE tenant_id = ?1 AND token_hash IN ({placeholders})"
            ))?;
            let values = std::iter::once(Value::Text(tenant.to_string()))
                .chain(chunk.iter().map(|hash| Value::Integer(*hash)));
            let rows = lookup.query_map(params_from_iter(values), |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
            })?;
            for row in rows {
                let (spam, ham) = row?;
                let f = robinson(spam, ham, spam_total, ham_total);
                if (f - 0.5).abs() >= MIN_DEVIATION {
                    probabilities.push(f);
                }
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

/// Unique tokens for one message. Header names, `header:word` tokens, sender
/// domains and URL hosts come first so a long body cannot push them out;
/// body words follow in order of appearance.
pub fn tokens(view: &MessageView, urls: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let mut push = |token: String| {
        if out.len() < MAX_TOKENS && seen.insert(token.clone()) {
            out.push(token);
        }
    };
    for (name, value) in &view.headers {
        let name = name.to_ascii_lowercase();
        push(format!("header:{name}"));
        if PREFIXED_HEADERS.contains(&name.as_str()) {
            for word in words(value) {
                push(format!("{name}:{word}"));
            }
        }
    }
    for address in view.from.iter().chain(&view.reply_to) {
        if let Some(domain) = address_domain(address) {
            push(format!("sender:{}", domain.to_ascii_lowercase()));
        }
    }
    for host in view
        .hosts
        .iter()
        .cloned()
        .chain(urls.iter().filter_map(|link| url_host(link)))
    {
        push(format!("url:{host}"));
    }
    for word in words(&view.body) {
        push(word);
    }
    out
}

fn words(text: &str) -> impl Iterator<Item = String> + '_ {
    text.split(|ch: char| !ch.is_alphanumeric())
        .filter(|word| (3..=20).contains(&word.chars().count()))
        .map(str::to_lowercase)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(words: &[&str]) -> Vec<String> {
        words.iter().map(|word| word.to_string()).collect()
    }

    #[test]
    fn untrained_tenant_scores_one_half() {
        let bayes = Bayes::in_memory().unwrap();
        let tokens = strings(&["anything"]);
        assert_eq!(bayes.score("t1", &tokens).unwrap(), 0.5);
        bayes.train("t1", "m1", &tokens, Label::Spam).unwrap();
        assert_eq!(bayes.score("t1", &tokens).unwrap(), 0.5);
    }

    #[test]
    fn tenants_are_trained_separately() {
        let bayes = Bayes::in_memory().unwrap();
        let spam = strings(&["casino", "bonus"]);
        let ham = strings(&["roster", "minutes"]);
        for i in 0..5 {
            bayes
                .train("t1", &format!("s{i}"), &spam, Label::Spam)
                .unwrap();
            bayes
                .train("t1", &format!("h{i}"), &ham, Label::Ham)
                .unwrap();
        }
        assert!(bayes.score("t1", &spam).unwrap() > 0.9);
        assert!(bayes.score("t1", &ham).unwrap() < 0.1);
        assert_eq!(bayes.score("t2", &spam).unwrap(), 0.5);
    }

    #[test]
    fn retraining_is_idempotent_and_relabelling_reverses() {
        let bayes = Bayes::in_memory().unwrap();
        let tokens = strings(&["invoice", "overdue"]);
        assert_eq!(
            bayes.train("t", "m1", &tokens, Label::Spam).unwrap(),
            Trained::New
        );
        assert_eq!(
            bayes.train("t", "m1", &tokens, Label::Spam).unwrap(),
            Trained::Unchanged
        );
        assert_eq!(bayes.totals("t").unwrap(), (1, 0));
        assert_eq!(
            bayes.train("t", "m1", &tokens, Label::Ham).unwrap(),
            Trained::Relabelled
        );
        assert_eq!(bayes.totals("t").unwrap(), (0, 1));
        // The spam counts were taken back off: a fresh spam message plus this
        // ham one leave the shared tokens exactly neutral.
        bayes.train("t", "m2", &tokens, Label::Spam).unwrap();
        assert_eq!(bayes.score("t", &tokens).unwrap(), 0.5);
    }

    #[test]
    fn token_rows_are_capped_per_tenant() {
        let bayes = Bayes::in_memory().unwrap().with_max_tokens(50);
        for i in 0..20 {
            let tokens: Vec<String> = (0..10).map(|j| format!("w{i}x{j}")).collect();
            bayes
                .train("t", &format!("m{i}"), &tokens, Label::Spam)
                .unwrap();
        }
        assert!(bayes.token_rows("t").unwrap() <= 50);
        bayes
            .train("other", "m", &strings(&["kept"]), Label::Ham)
            .unwrap();
        assert_eq!(bayes.token_rows("other").unwrap(), 1);
    }

    #[test]
    fn lookups_span_chunks() {
        let bayes = Bayes::in_memory().unwrap();
        let spam: Vec<String> = (0..1200).map(|i| format!("spam{i}")).collect();
        bayes.train("t", "s", &spam, Label::Spam).unwrap();
        bayes
            .train("t", "h", &strings(&["hello"]), Label::Ham)
            .unwrap();
        // Only the last chunk holds trained tokens.
        let mut probe: Vec<String> = (0..1100).map(|i| format!("unknown{i}")).collect();
        probe.extend(spam[..3].iter().cloned());
        assert!(bayes.score("t", &probe).unwrap() > 0.5);
    }

    #[test]
    fn chi2q_matches_known_values() {
        assert!((chi2q(0.0, 2) - 1.0).abs() < 1e-12);
        // P(X > 2) for 2 degrees of freedom is e^-1.
        assert!((chi2q(2.0, 2) - (-1.0f64).exp()).abs() < 1e-12);
    }
}
