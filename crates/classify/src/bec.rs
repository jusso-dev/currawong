//! Business email compromise heuristics: borrowed staff names, look-alike
//! senders, replies diverted to free mail, and payment or gift-card requests,
//! with first-time senders and DMARC failures as supporting evidence.
//!
//! Each reason adds a fixed weight; the score is capped at 1. The default
//! policy pack quarantines inbound mail at `bec >= 0.6`.
use crate::message::{address_domain, MessageView};
use crate::TenantContext;
use currawong_core::directory::Directory;
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

fn weight(reason: BecReason) -> f64 {
    match reason {
        BecReason::DisplayNameSpoof => 0.5,
        BecReason::LookalikeSender => 0.4,
        BecReason::PaymentChange => 0.4,
        BecReason::GiftCard => 0.3,
        BecReason::ReplyToMismatch => 0.25,
        BecReason::AuthFailure => 0.2,
        BecReason::Urgency | BecReason::Secrecy | BecReason::FirstTimeSender => 0.1,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    PaymentChange,
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
            .map(|p| (p.text.to_lowercase(), p.category))
            .filter(|(text, _)| !text.trim().is_empty())
            .collect();
        Ok(Self { phrases })
    }

    pub fn builtin() -> &'static Self {
        static LEXICON: OnceLock<Lexicon> = OnceLock::new();
        LEXICON.get_or_init(|| Self::parse(LEXICON_EN_AU).expect("built-in BEC lexicon is valid"))
    }

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
    /// A lookalike finding on the From, Reply-To or envelope sender.
    pub lookalike_sender: bool,
    /// `Some(true)` when no mail from this sender has been delivered to the
    /// tenant before; `None` when the history is unavailable.
    pub first_time: Option<bool>,
}

pub fn analyse(
    view: &MessageView,
    tenant: &TenantContext,
    ctx: &BecContext,
    directory: Option<&dyn Directory>,
    lexicon: &Lexicon,
) -> BecReport {
    let mut reasons: Vec<(BecReason, String)> = Vec::new();
    let in_tenant = |domain: &str| {
        tenant
            .domains
            .iter()
            .any(|d| d.eq_ignore_ascii_case(domain.trim_end_matches('.')))
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
            .any(in_tenant);
        let colleague = directory.is_some_and(|dir| {
            dir.by_name(name).iter().any(|person| {
                address_domain(&person.email).is_some_and(in_tenant)
                    && !person.email.eq_ignore_ascii_case(address)
            })
        });
        if embedded || colleague {
            reasons.push((
                BecReason::DisplayNameSpoof,
                format!(
                    "display name of a {} colleague on an outside address",
                    if colleague { "directory" } else { "tenant" }
                ),
            ));
            break;
        }
    }

    if ctx.lookalike_sender {
        reasons.push((
            BecReason::LookalikeSender,
            "sender domain imitates a protected domain".into(),
        ));
    }

    let from_domains: Vec<&str> = view.from.iter().filter_map(|a| address_domain(a)).collect();
    if let Some(reply) = view
        .reply_to
        .iter()
        .filter_map(|a| address_domain(a))
        .find(|reply| !from_domains.iter().any(|f| f.eq_ignore_ascii_case(reply)))
    {
        if is_free_mail(reply) {
            reasons.push((
                BecReason::ReplyToMismatch,
                "replies go to a free mail address".into(),
            ));
        }
    }

    let subject = view.header("Subject").next().unwrap_or("");
    let text = format!("{subject}\n{}", view.body).to_lowercase();
    let payment_phrases = lexicon.hits(&text, Category::PaymentChange);
    let (bsb, account) = bank_details(&text);
    let payment =
        (payment_phrases > 0 && (bsb || account)) || payment_phrases >= 2 || (bsb && account);
    if payment {
        reasons.push((
            BecReason::PaymentChange,
            "asks to change or use new bank details".into(),
        ));
    }
    let gift = lexicon.hits(&text, Category::GiftCard) > 0;
    if gift {
        reasons.push((BecReason::GiftCard, "asks for gift cards".into()));
    }
    if lexicon.hits(&text, Category::Urgency) > 0 {
        reasons.push((BecReason::Urgency, "urgent language".into()));
    }
    if lexicon.hits(&text, Category::Secrecy) > 0 {
        reasons.push((
            BecReason::Secrecy,
            "asks for secrecy or avoids a call".into(),
        ));
    }
    if ctx.first_time == Some(true) && (payment || gift) {
        reasons.push((
            BecReason::FirstTimeSender,
            "first message from this sender".into(),
        ));
    }
    if ctx.dmarc_failed {
        reasons.push((
            BecReason::AuthFailure,
            "DMARC failed for the From domain".into(),
        ));
    }

    let score = reasons
        .iter()
        .map(|(r, _)| weight(*r))
        .sum::<f64>()
        .min(1.0);
    BecReport {
        score,
        reasons: reasons.iter().map(|(r, _)| *r).collect(),
        explanation: reasons.into_iter().map(|(_, e)| e).collect(),
    }
}

fn is_free_mail(domain: &str) -> bool {
    let domain = domain.trim_end_matches('.').to_ascii_lowercase();
    FREE_MAIL.contains(&domain.as_str())
}

/// Whole-word, case-insensitive (callers pass lower-case text).
fn contains_words(text: &str, phrase: &str) -> bool {
    let mut from = 0;
    while let Some(pos) = text[from..].find(phrase) {
        let start = from + pos;
        let end = start + phrase.len();
        let before = text[..start]
            .chars()
            .next_back()
            .is_none_or(|c| !c.is_alphanumeric());
        let after = text[end..]
            .chars()
            .next()
            .is_none_or(|c| !c.is_alphanumeric());
        if before && after {
            return true;
        }
        from = start + phrase.chars().next().map_or(1, char::len_utf8);
    }
    false
}

/// (BSB present, account number present), for example `BSB: 000-000` and
/// `account number 00000000`.
fn bank_details(text: &str) -> (bool, bool) {
    static BSB: OnceLock<Regex> = OnceLock::new();
    static ACCOUNT: OnceLock<Regex> = OnceLock::new();
    let bsb = BSB.get_or_init(|| Regex::new(r"\bbsb\b[\s:#.-]{0,4}\d{3}[\s-]?\d{3}\b").unwrap());
    let account = ACCOUNT.get_or_init(|| {
        Regex::new(r"\b(account|acct|a/c)\b(\s*(no|number|num|#))?[\s:#.-]{0,4}\d{6,10}\b").unwrap()
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
                "INSERT INTO sender_history (tenant_id, sender, recipient, first_seen, count)
                 VALUES (?1, ?2, ?3, ?4, 1)
                 ON CONFLICT (tenant_id, sender, recipient) DO UPDATE SET count = count + 1",
                params![
                    tenant,
                    sender.to_ascii_lowercase(),
                    recipient.to_ascii_lowercase(),
                    now
                ],
            )?;
        }
        tx.commit()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bec_bank_detail_patterns_and_whole_words() {
        assert_eq!(
            bank_details("new bsb: 000-000 account number: 00000000"),
            (true, true)
        );
        assert_eq!(bank_details("bsb 000 000"), (true, false));
        assert_eq!(bank_details("acct # 1234567"), (false, true));
        assert_eq!(bank_details("phone 0400 000 000"), (false, false));
        assert!(contains_words("this is urgent!", "urgent"));
        assert!(!contains_words("detergent sale", "urgent"));
        assert!(!contains_words("urgently", "urgent"));
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
