//! Business email compromise heuristics: borrowed staff names, look-alike
//! senders, replies diverted to free mail, and payment or gift-card requests,
//! with first-time senders and DMARC failures as supporting evidence.
//!
//! Each reason adds a fixed weight; the score is capped at 1. The default
//! policy pack quarantines inbound mail at `bec >= 0.6`.
use crate::message::{address_domain, MessageView};
use crate::TenantContext;
use currawong_core::directory::{fold, Directory};
use currawong_core::{BecReason, BecReport};
use regex::Regex;
use rusqlite::{params, Connection, OpenFlags};
use serde::Deserialize;
use std::path::Path;
use std::sync::{Mutex, OnceLock};

pub const LEXICON_EN_AU: &str = include_str!("../../../rules/bec-lexicon-en-au.toml");

/// Mail providers anyone can sign up to.
const FREE_MAIL: &[&str] = &[
    "gmail.com",
    "googlemail.com",
    "outlook.com",
    "hotmail.com",
    "live.com",
    "msn.com",
    "yahoo.com",
    "yahoo.com.au",
    "ymail.com",
    "icloud.com",
    "me.com",
    "aol.com",
    "bigpond.com",
    "bigpond.net.au",
    "optusnet.com.au",
    "protonmail.com",
    "proton.me",
    "gmx.com",
    "mail.com",
    "zoho.com",
    "yandex.com",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    /// Asks to change bank or payment details.
    PaymentChange,
    /// Invoice and remittance language: supporting evidence only.
    Invoice,
    GiftCard,
    Urgency,
    Secrecy,
}

#[derive(Debug, Clone, Deserialize)]
struct Phrase {
    text: String,
    category: Category,
}

#[derive(Debug, Clone, Deserialize)]
struct LexiconFile {
    #[serde(default)]
    phrase: Vec<Phrase>,
}

#[derive(Debug, Clone)]
pub struct Lexicon {
    phrases: Vec<(String, Category)>,
}

impl Lexicon {
    pub fn parse(text: &str) -> Result<Self, String> {
        let file: LexiconFile = toml::from_str(text).map_err(|e| e.to_string())?;
        let phrases = file
            .phrase
            .into_iter()
            .map(|p| (fold(&p.text), p.category))
            .filter(|(text, _)| !text.trim().is_empty())
            .collect();
        Ok(Self { phrases })
    }

    pub fn builtin() -> &'static Self {
        static LEXICON: OnceLock<Lexicon> = OnceLock::new();
        LEXICON.get_or_init(|| Self::parse(LEXICON_EN_AU).expect("built-in BEC lexicon is valid"))
    }

    /// `text` must already be folded with `currawong_core::directory::fold`.
    fn hits(&self, text: &str, category: Category) -> usize {
        self.phrases
            .iter()
            .filter(|(phrase, c)| *c == category && contains_words(text, phrase))
            .count()
    }
}

/// What the gateway knows about the message beyond its content.
#[derive(Debug, Clone, Default)]
pub struct BecContext {
    pub dmarc_failed: bool,
    /// A strong lookalike finding on the From, Reply-To or envelope sender.
    pub lookalike_sender: bool,
    /// `Some(true)` when no authenticated mail from this sender has been
    /// delivered to the tenant before; `None` when the history is unavailable.
    pub first_time: Option<bool>,
}

pub fn analyse(
    view: &MessageView,
    tenant: &TenantContext,
    ctx: &BecContext,
    directory: Option<&dyn Directory>,
    lexicon: &Lexicon,
) -> BecReport {
    let mut reasons: Vec<(BecReason, f64, String)> = Vec::new();
    let in_tenant = |domain: &str| {
        let domain = domain.trim_end_matches('.').to_ascii_lowercase();
        tenant.domains.iter().any(|owned| {
            let owned = owned.trim_end_matches('.').to_ascii_lowercase();
            domain == owned || domain.ends_with(&format!(".{owned}"))
        })
    };

    for (name, address) in view.from_names.iter().zip(&view.from) {
        let from_domain = address_domain(address).unwrap_or("");
        if name.trim().is_empty() || in_tenant(from_domain) {
            continue;
        }
        // A tenant address written into the display name, a classic trick.
        let embedded = name
            .split(|c: char| c.is_whitespace() || matches!(c, '<' | '>' | '(' | ')' | '"'))
            .filter_map(address_domain)
            .any(&in_tenant);
        let colleagues: Vec<_> = directory
            .map(|dir| dir.by_name(name))
            .unwrap_or_default()
            .into_iter()
            .filter(|person| {
                address_domain(&person.email).is_some_and(in_tenant)
                    && !person.email.eq_ignore_ascii_case(address)
            })
            .collect();
        if embedded || !colleagues.is_empty() {
            let vip = colleagues.iter().any(|person| person.vip);
            // A VIP's name on an outside address is enough to hold the mail.
            let weight = if vip { 0.6 } else { 0.5 };
            reasons.push((
                BecReason::DisplayNameSpoof,
                weight,
                format!(
                    "display name of a {} on an outside address",
                    if vip { "VIP colleague" } else { "colleague" }
                ),
            ));
            break;
        }
    }

    if ctx.lookalike_sender {
        reasons.push((
            BecReason::LookalikeSender,
            0.4,
            "sender domain imitates a protected domain".into(),
        ));
    }

    let from_domains: Vec<&str> = view.from.iter().filter_map(|a| address_domain(a)).collect();
    for reply in &view.reply_to {
        let same_address = view
            .from
            .iter()
            .any(|from| from.eq_ignore_ascii_case(reply));
        let Some(domain) = address_domain(reply) else {
            continue;
        };
        let same_domain = from_domains.iter().any(|f| f.eq_ignore_ascii_case(domain));
        if !same_address && is_free_mail(domain) {
            reasons.push((
                BecReason::ReplyToMismatch,
                0.25,
                "replies go to a different free mail address".into(),
            ));
            break;
        }
        if !same_domain {
            reasons.push((
                BecReason::ReplyToMismatch,
                0.15,
                "replies go to another domain".into(),
            ));
            break;
        }
    }

    let subject = view.header("Subject").next().unwrap_or("");
    let text = fold(&format!("{subject}\n{}\n{}", view.body, view.body_tail));
    let change = lexicon.hits(&text, Category::PaymentChange);
    let invoice = lexicon.hits(&text, Category::Invoice);
    let (bsb, account) = bank_details(&text);
    if change > 0 && (bsb || account) {
        // A change request quoting new bank details is the costliest BEC.
        reasons.push((
            BecReason::PaymentChange,
            0.6,
            "asks to pay new bank details".into(),
        ));
    } else if change >= 2 || (change == 1 && invoice > 0) {
        reasons.push((
            BecReason::PaymentChange,
            0.4,
            "asks to change payment details".into(),
        ));
    }
    let payment = reasons
        .iter()
        .any(|(r, _, _)| *r == BecReason::PaymentChange);
    let gift = lexicon.hits(&text, Category::GiftCard) > 0;
    if gift {
        reasons.push((BecReason::GiftCard, 0.3, "asks for gift cards".into()));
    }
    if lexicon.hits(&text, Category::Urgency) > 0 {
        reasons.push((BecReason::Urgency, 0.1, "urgent language".into()));
    }
    if lexicon.hits(&text, Category::Secrecy) > 0 {
        reasons.push((
            BecReason::Secrecy,
            0.1,
            "asks for secrecy or avoids a call".into(),
        ));
    }
    if ctx.first_time == Some(true) && (payment || gift) {
        reasons.push((
            BecReason::FirstTimeSender,
            0.1,
            "first message from this sender".into(),
        ));
    }
    if ctx.dmarc_failed {
        reasons.push((
            BecReason::AuthFailure,
            0.2,
            "DMARC failed for the From domain".into(),
        ));
    }

    let score = reasons
        .iter()
        .fold(0.0_f64, |sum, (_, w, _)| sum + w)
        .min(1.0);
    BecReport {
        score,
        reasons: reasons.iter().map(|(r, _, _)| *r).collect(),
        explanation: reasons.into_iter().map(|(_, _, e)| e).collect(),
    }
}

fn is_free_mail(domain: &str) -> bool {
    let domain = domain.trim_end_matches('.').to_ascii_lowercase();
    FREE_MAIL.contains(&domain.as_str())
}

/// Whole-word match on folded text (single spaces, lower case).
fn contains_words(text: &str, phrase: &str) -> bool {
    if phrase.is_empty() {
        return false;
    }
    let mut from = 0;
    while let Some(pos) = text[from..].find(phrase) {
        let start = from + pos;
        let end = start + phrase.len();
        let before = start == 0 || text.as_bytes()[start - 1] == b' ';
        let after = end == text.len() || text.as_bytes()[end] == b' ';
        if before && after {
            return true;
        }
        from = start + phrase.chars().next().map_or(1, char::len_utf8);
    }
    false
}

/// (BSB present, account number present) in folded text, for example
/// `bsb 000 000`, `bsb number 062000` and `account number 0000 0000`.
fn bank_details(text: &str) -> (bool, bool) {
    static BSB: OnceLock<Regex> = OnceLock::new();
    static ACCOUNT: OnceLock<Regex> = OnceLock::new();
    let bsb = BSB.get_or_init(|| Regex::new(r"\bbsb( no| number| num)? \d{3} ?\d{3}\b").unwrap());
    let account = ACCOUNT.get_or_init(|| {
        Regex::new(r"\b(account|acct|acc|a c)( no| number| num)? \d(?: ?\d){5,9}\b").unwrap()
    });
    (bsb.is_match(text), account.is_match(text))
}

/// Who has had mail delivered to whom, per tenant.
pub struct SenderHistory {
    conn: Mutex<Connection>,
}

#[derive(Debug, thiserror::Error)]
#[error("sender history: {0}")]
pub struct HistoryError(#[from] rusqlite::Error);

impl SenderHistory {
    pub fn open(path: &Path) -> Result<Self, HistoryError> {
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        Self::init(conn)
    }

    pub fn in_memory() -> Result<Self, HistoryError> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Self, HistoryError> {
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             CREATE TABLE IF NOT EXISTS sender_history (
                 tenant_id TEXT NOT NULL,
                 sender TEXT NOT NULL,
                 recipient TEXT NOT NULL,
                 first_seen INTEGER NOT NULL,
                 last_seen INTEGER NOT NULL DEFAULT 0,
                 count INTEGER NOT NULL,
                 PRIMARY KEY (tenant_id, sender, recipient)
             );",
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// True when mail from `sender` has been delivered to anyone in the tenant.
    pub fn seen(&self, tenant: &str, sender: &str) -> Result<bool, HistoryError> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let found: Option<i64> = conn
            .query_row(
                "SELECT 1 FROM sender_history WHERE tenant_id = ?1 AND sender = ?2 LIMIT 1",
                params![tenant, sender.to_ascii_lowercase()],
                |row| row.get(0),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                e => Err(e),
            })?;
        Ok(found.is_some())
    }

    /// Record a delivery. Called once per delivered recipient group.
    pub fn record(
        &self,
        tenant: &str,
        sender: &str,
        recipients: &[String],
        now: i64,
    ) -> Result<(), HistoryError> {
        if sender.is_empty() {
            return Ok(());
        }
        let mut conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let tx = conn.transaction()?;
        for recipient in recipients {
            tx.execute(
                "INSERT INTO sender_history (tenant_id, sender, recipient, first_seen, last_seen, count)
                 VALUES (?1, ?2, ?3, ?4, ?4, 1)
                 ON CONFLICT (tenant_id, sender, recipient)
                 DO UPDATE SET count = count + 1, last_seen = ?4",
                params![
                    tenant,
                    sender.to_ascii_lowercase(),
                    recipient.to_ascii_lowercase(),
                    now
                ],
            )?;
        }
        // Senders not seen for a year are forgotten, and each tenant keeps
        // at most MAX_HISTORY_ROWS pairs (the least recently seen go first).
        tx.execute(
            "DELETE FROM sender_history WHERE last_seen < ?1",
            params![now - HISTORY_TTL_SECS],
        )?;
        tx.execute(
            "DELETE FROM sender_history WHERE tenant_id = ?1 AND rowid IN (
                 SELECT rowid FROM sender_history WHERE tenant_id = ?1
                 ORDER BY last_seen DESC LIMIT -1 OFFSET ?2)",
            params![tenant, MAX_HISTORY_ROWS],
        )?;
        tx.commit()?;
        Ok(())
    }
}

const HISTORY_TTL_SECS: i64 = 365 * 24 * 3600;
const MAX_HISTORY_ROWS: i64 = 200_000;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bec_bank_detail_patterns_and_whole_words() {
        let bd = |t: &str| bank_details(&fold(t));
        assert_eq!(
            bd("new bsb: 000-000 account number: 00000000"),
            (true, true)
        );
        assert_eq!(bd("bsb 000 000"), (true, false));
        assert_eq!(bd("BSB number: 062000 acc 12345678"), (true, true));
        assert_eq!(bd("acct # 1234 5678"), (false, true));
        assert_eq!(bd("phone 0400 000 000"), (false, false));
        assert!(contains_words(&fold("this is urgent!"), "urgent"));
        assert!(!contains_words(&fold("detergent sale"), "urgent"));
        assert!(!contains_words(&fold("urgently"), "urgent"));
        assert!(contains_words(
            &fold("new bank\r\n  details"),
            &fold("new bank details")
        ));
        assert!(contains_words(
            &fold("b\u{0430}nk\u{00A0}details"),
            &fold("bank details")
        ));
    }

    #[test]
    fn bec_sender_history_records_and_reports_first_time_senders() {
        let history = SenderHistory::in_memory().unwrap();
        assert!(!history.seen("tenant:acme", "Supplier@vendor.test").unwrap());
        history
            .record(
                "tenant:acme",
                "supplier@vendor.test",
                &["ap@acme.test".into()],
                1,
            )
            .unwrap();
        assert!(history.seen("tenant:acme", "SUPPLIER@vendor.test").unwrap());
        assert!(!history
            .seen("tenant:other", "supplier@vendor.test")
            .unwrap());
    }
}
