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
use rusqlite::{params, params_from_iter, types::Value, Connection, OpenFlags, OptionalExtension};
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
/// Rows evicted per training call, so one call never holds the writer long.
const EVICT_BATCH: i64 = 10_000;
/// Trained-message records are kept this long for relabelling. Feedback on
/// an older message counts as new.
pub const DEFAULT_TRAINED_TTL_SECS: i64 = 180 * 24 * 60 * 60;
const EXPIRE_BATCH: i64 = 1_000;
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

/// Training writes through one connection and scoring reads through another
/// (WAL), so a training transaction does not hold up scoring.
pub struct Bayes {
    writer: Mutex<Connection>,
    /// `None` for an in-memory store, which scores through the writer.
    reader: Option<Mutex<Connection>>,
    max_tokens: i64,
    trained_ttl_secs: i64,
}

impl Bayes {
    /// Open or create the store. The directory must already exist.
    pub fn open(path: &Path) -> Result<Self, SpamError> {
        let mut bayes = Self::init(Connection::open(path)?)?;
        let reader = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        bayes.reader = Some(Mutex::new(reader));
        Ok(bayes)
    }

    pub fn in_memory() -> Result<Self, SpamError> {
        Self::init(Connection::open_in_memory()?)
    }

    /// Token rows kept per tenant before the rarest are evicted.
    pub fn with_max_tokens(mut self, max_tokens: usize) -> Self {
        self.max_tokens = max_tokens.max(1) as i64;
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
            CREATE INDEX IF NOT EXISTS bayes_tokens_weight
                ON bayes_tokens (tenant_id, spam + ham);
            CREATE TABLE IF NOT EXISTS bayes_messages (
                tenant_id TEXT PRIMARY KEY,
                spam INTEGER NOT NULL DEFAULT 0,
                ham INTEGER NOT NULL DEFAULT 0,
                tokens INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS bayes_trained (
                tenant_id TEXT NOT NULL,
                message_id TEXT NOT NULL,
                label INTEGER NOT NULL,
                token_hashes BLOB NOT NULL,
                trained_at INTEGER NOT NULL,
                PRIMARY KEY (tenant_id, message_id)
            );
            CREATE INDEX IF NOT EXISTS bayes_trained_age ON bayes_trained (trained_at);",
        )?;
        Ok(Self {
            writer: Mutex::new(conn),
            reader: None,
            max_tokens: DEFAULT_MAX_TOKENS_PER_TENANT as i64,
            trained_ttl_secs: DEFAULT_TRAINED_TTL_SECS,
        })
    }

    /// Count one message's tokens as spam or ham for a tenant. Training the
    /// same message again is a no-op; training it with the other label
    /// reverses exactly the tokens recorded the first time.
    pub fn train(
        &self,
        tenant: &str,
        message_id: &str,
        tokens: &[String],
        label: Label,
    ) -> Result<Trained, SpamError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_secs() as i64)
            .unwrap_or_default();
        let mut conn = self.writer.lock().map_err(|_| poisoned())?;
        let tx = conn.transaction()?;
        tx.execute(
            "DELETE FROM bayes_trained WHERE rowid IN (
                SELECT rowid FROM bayes_trained WHERE trained_at < ?1 LIMIT ?2)",
            params![now - self.trained_ttl_secs, EXPIRE_BATCH],
        )?;
        let previous: Option<(i64, Vec<u8>)> = tx
            .query_row(
                "SELECT label, token_hashes FROM bayes_trained
                 WHERE tenant_id = ?1 AND message_id = ?2",
                params![tenant, message_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let (spam, ham) = label.counts();
        let outcome = match previous {
            Some((code, _)) if code == label.code() => {
                tx.commit()?;
                return Ok(Trained::Unchanged);
            }
            Some((_, recorded)) => {
                // The old label is the other one: take its counts back off.
                let mut forget = tx.prepare_cached(
                    "UPDATE bayes_tokens SET spam = MAX(spam - ?3, 0), ham = MAX(ham - ?4, 0)
                     WHERE tenant_id = ?1 AND token_hash = ?2",
                )?;
                for hash in decode_hashes(&recorded) {
                    forget.execute(params![tenant, hash, ham, spam])?;
                }
                tx.execute(
                    "UPDATE bayes_messages SET spam = MAX(spam - ?2, 0), ham = MAX(ham - ?3, 0)
                     WHERE tenant_id = ?1",
                    params![tenant, ham, spam],
                )?;
                Trained::Relabelled
            }
            None => Trained::New,
        };
        let hashes = unique_hashes(tokens);
        let mut added = 0i64;
        {
            let mut insert = tx.prepare_cached(
                "INSERT OR IGNORE INTO bayes_tokens (tenant_id, token_hash, spam, ham)
                 VALUES (?1, ?2, ?3, ?4)",
            )?;
            let mut update = tx.prepare_cached(
                "UPDATE bayes_tokens SET spam = spam + ?3, ham = ham + ?4
                 WHERE tenant_id = ?1 AND token_hash = ?2",
            )?;
            for hash in &hashes {
                if insert.execute(params![tenant, hash, spam, ham])? == 1 {
                    added += 1;
                } else {
                    update.execute(params![tenant, hash, spam, ham])?;
                }
            }
        }
        tx.execute(
            "INSERT INTO bayes_messages (tenant_id, spam, ham, tokens) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT (tenant_id) DO UPDATE SET spam = spam + excluded.spam,
                 ham = ham + excluded.ham, tokens = tokens + excluded.tokens",
            params![tenant, spam, ham, added],
        )?;
        tx.execute(
            "INSERT INTO bayes_trained (tenant_id, message_id, label, token_hashes, trained_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT (tenant_id, message_id) DO UPDATE SET label = excluded.label,
                 token_hashes = excluded.token_hashes, trained_at = excluded.trained_at",
            params![
                tenant,
                message_id,
                label.code(),
                encode_hashes(&hashes),
                now
            ],
        )?;
        let rows: i64 = tx.query_row(
            "SELECT tokens FROM bayes_messages WHERE tenant_id = ?1",
            params![tenant],
            |row| row.get(0),
        )?;
        if rows > self.max_tokens {
            // Evict the rarest towards 90% of the cap, one bounded batch per call.
            let excess = (rows - self.max_tokens * 9 / 10).min(EVICT_BATCH);
            let evicted = tx.execute(
                "DELETE FROM bayes_tokens WHERE rowid IN (
                    SELECT rowid FROM bayes_tokens WHERE tenant_id = ?1
                    ORDER BY spam + ham ASC LIMIT ?2)",
                params![tenant, excess],
            )? as i64;
            tx.execute(
                "UPDATE bayes_messages SET tokens = MAX(tokens - ?2, 0) WHERE tenant_id = ?1",
                params![tenant, evicted],
            )?;
        }
        tx.commit()?;
        Ok(outcome)
    }

    fn read<T>(
        &self,
        query: impl FnOnce(&Connection) -> Result<T, SpamError>,
    ) -> Result<T, SpamError> {
        let lock = self.reader.as_ref().unwrap_or(&self.writer);
        let conn = lock.lock().map_err(|_| poisoned())?;
        query(&conn)
    }

    /// Trained spam and ham message counts for a tenant.
    pub fn totals(&self, tenant: &str) -> Result<(i64, i64), SpamError> {
        self.read(|conn| totals(conn, tenant))
    }

    /// Token rows stored for a tenant.
    pub fn token_rows(&self, tenant: &str) -> Result<i64, SpamError> {
        self.read(|conn| {
            Ok(conn.query_row(
                "SELECT COUNT(*) FROM bayes_tokens WHERE tenant_id = ?1",
                params![tenant],
                |row| row.get(0),
            )?)
        })
    }

    /// Spam probability from 0 to 1. 0.5 until the tenant has trained both classes.
    pub fn score(&self, tenant: &str, tokens: &[String]) -> Result<f64, SpamError> {
        self.read(|conn| {
            let (spam_total, ham_total) = totals(conn, tenant)?;
            if spam_total == 0 || ham_total == 0 {
                return Ok(0.5);
            }
            let hashes = unique_hashes(tokens);
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
        })
    }
}

fn totals(conn: &Connection, tenant: &str) -> Result<(i64, i64), SpamError> {
    Ok(conn
        .query_row(
            "SELECT spam, ham FROM bayes_messages WHERE tenant_id = ?1",
            params![tenant],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?
        .unwrap_or((0, 0)))
}

fn unique_hashes(tokens: &[String]) -> Vec<i64> {
    let mut seen = HashSet::new();
    tokens
        .iter()
        .map(|token| token_hash(token))
        .filter(|hash| seen.insert(*hash))
        .collect()
}

fn encode_hashes(hashes: &[i64]) -> Vec<u8> {
    hashes.iter().flat_map(|hash| hash.to_be_bytes()).collect()
}

fn decode_hashes(bytes: &[u8]) -> impl Iterator<Item = i64> + '_ {
    bytes
        .chunks_exact(8)
        .map(|chunk| i64::from_be_bytes(chunk.try_into().expect("eight bytes")))
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
    use std::{sync::mpsc, time::Duration};

    fn strings(words: &[&str]) -> Vec<String> {
        words.iter().map(|word| word.to_string()).collect()
    }

    fn counts(bayes: &Bayes, tenant: &str, token: &str) -> (i64, i64) {
        let conn = bayes.writer.lock().unwrap();
        conn.query_row(
            "SELECT spam, ham FROM bayes_tokens WHERE tenant_id = ?1 AND token_hash = ?2",
            params![tenant, token_hash(token)],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .unwrap()
        .unwrap_or((0, 0))
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
        assert_eq!(counts(&bayes, "t", "invoice"), (0, 1));
    }

    #[test]
    fn relabelling_reverses_the_recorded_tokens() {
        let bayes = Bayes::in_memory().unwrap();
        bayes
            .train("t", "m1", &strings(&["alpha", "bravo"]), Label::Spam)
            .unwrap();
        // The second report tokenises differently (say, a rule or parser
        // change); the first label's tokens are still reversed exactly.
        bayes
            .train("t", "m1", &strings(&["charlie"]), Label::Ham)
            .unwrap();
        assert_eq!(counts(&bayes, "t", "alpha"), (0, 0));
        assert_eq!(counts(&bayes, "t", "bravo"), (0, 0));
        assert_eq!(counts(&bayes, "t", "charlie"), (0, 1));
    }

    #[test]
    fn trained_records_expire() {
        let bayes = Bayes::in_memory().unwrap();
        let tokens = strings(&["invoice"]);
        bayes.train("t", "m1", &tokens, Label::Spam).unwrap();
        bayes
            .writer
            .lock()
            .unwrap()
            .execute("UPDATE bayes_trained SET trained_at = 0", [])
            .unwrap();
        // The old record has expired, so this is new feedback, not a relabel.
        assert_eq!(
            bayes.train("t", "m1", &tokens, Label::Ham).unwrap(),
            Trained::New
        );
        assert_eq!(bayes.totals("t").unwrap(), (1, 1));
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
        let rows = bayes.token_rows("t").unwrap();
        assert!(rows <= 50, "{rows}");
        // The tracked count matches the table.
        let tracked: i64 = bayes
            .writer
            .lock()
            .unwrap()
            .query_row(
                "SELECT tokens FROM bayes_messages WHERE tenant_id = 't'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(tracked, rows);
        bayes
            .train("other", "m", &strings(&["kept"]), Label::Ham)
            .unwrap();
        assert_eq!(bayes.token_rows("other").unwrap(), 1);
    }

    #[test]
    fn scoring_does_not_wait_for_the_writer() {
        let dir = tempfile::tempdir().unwrap();
        let bayes = std::sync::Arc::new(Bayes::open(&dir.path().join("bayes.sqlite")).unwrap());
        let spam = strings(&["casino"]);
        bayes.train("t", "s", &spam, Label::Spam).unwrap();
        bayes
            .train("t", "h", &strings(&["roster"]), Label::Ham)
            .unwrap();
        // Hold the writer as a long training transaction would.
        let _writer = bayes.writer.lock().unwrap();
        let (sent, received) = mpsc::channel();
        let scorer = std::sync::Arc::clone(&bayes);
        std::thread::spawn(move || {
            let _ = sent.send(scorer.score("t", &spam));
        });
        let score = received
            .recv_timeout(Duration::from_secs(5))
            .expect("scoring waited for the writer")
            .unwrap();
        assert!(score > 0.5);
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
