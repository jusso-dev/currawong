//! Daily DMARC aggregate (RUA) reports, RFC 9990. Each inbound message adds
//! one row to `dmarc_events`, keyed by the day it was received. An hour after
//! a UTC day ends, rows are grouped per policy domain into one gzipped XML
//! report. `dmarc_reports_sent` records each (day, domain) once reported, so
//! late rows and retries never produce a second report. Failure (RUF)
//! reports are never sent.
use crate::AuthChecker;
use currawong_core::config::DmarcReportConfig;
use currawong_spool::Envelope;
use mail_auth::{
    dmarc::{Dmarc, URI},
    report::{PolicyPublished, Record, Report, SPFDomainScope},
    DkimOutput, DmarcOutput, SpfOutput,
};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::{
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};

pub const DAY_SECS: u64 = 86_400;
/// Mail received just before midnight can be classified just after it.
pub const GRACE_SECS: u64 = 60 * 60;
/// mail-auth's DMARC tree walk makes at most eight queries.
const MAX_WALK: usize = 8;
const DNS_TIMEOUT: Duration = Duration::from_secs(10);
const SENT_RETENTION_DAYS: u64 = 60;

/// One DMARC evaluation, kept until its day has been reported.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DmarcEvent {
    pub message_id: String,
    pub tenant_id: Option<String>,
    /// Domain the DMARC record was published at.
    pub policy_domain: String,
    pub received_at: u64,
    pub policy: PolicyPublished,
    /// `rua` destinations, without the `mailto:` scheme.
    pub rua: Vec<URI>,
    pub record: Record,
}

/// Everything recorded for one policy domain on one day.
#[derive(Debug, Clone)]
pub struct DomainDay {
    pub day: u64,
    pub domain: String,
    pub policy: PolicyPublished,
    pub rua: Vec<URI>,
    /// Distinct rows, largest first, and how many messages each covers.
    pub rows: Vec<(Record, u32)>,
    /// Rows and messages left out by `max_rows_per_report`.
    pub omitted_rows: u64,
    pub omitted_messages: u64,
}

/// A rendered report message and the destinations it is addressed to.
#[derive(Debug, Clone)]
pub struct OutgoingReport {
    pub domain: String,
    pub from: String,
    pub to: Vec<String>,
    pub message: Vec<u8>,
}

/// One persistent connection in WAL mode, shared by the pipeline (inserts)
/// and the report task.
#[derive(Clone)]
pub struct DmarcEventStore {
    conn: Arc<Mutex<Connection>>,
    max_rua: usize,
    max_domains: usize,
    max_rows: usize,
    retention_days: u64,
}

impl DmarcEventStore {
    pub fn open(cfg: &DmarcReportConfig) -> Result<Self, String> {
        Self::open_at(&cfg.database, cfg)
    }

    pub fn open_at(path: &Path, cfg: &DmarcReportConfig) -> Result<Self, String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|err| err.to_string())?;
        }
        let conn = Connection::open(path).map_err(|err| err.to_string())?;
        conn.busy_timeout(Duration::from_secs(5))
            .map_err(|err| err.to_string())?;
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
            CREATE TABLE IF NOT EXISTS dmarc_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message_id TEXT NOT NULL UNIQUE,
                tenant_id TEXT,
                policy_domain TEXT NOT NULL,
                day INTEGER NOT NULL,
                received_at INTEGER NOT NULL,
                policy_json TEXT NOT NULL,
                rua_json TEXT NOT NULL,
                record_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS dmarc_events_day ON dmarc_events (day, policy_domain);
            CREATE TABLE IF NOT EXISTS dmarc_reports_sent (
                day INTEGER NOT NULL,
                policy_domain TEXT NOT NULL,
                spool_id TEXT,
                done INTEGER NOT NULL,
                PRIMARY KEY (day, policy_domain)
            );",
        )
        .map_err(|err| err.to_string())?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            max_rua: cfg.max_rua_per_record,
            max_domains: cfg.max_domains_per_day,
            max_rows: cfg.max_rows_per_report,
            retention_days: cfg.retention_days,
        })
    }

    /// Store an evaluation. A message is recorded once, however often it is
    /// classified. Returns false when the row was dropped: already recorded,
    /// its day already reported for that domain, or the daily domain cap.
    pub fn record(&self, event: &DmarcEvent) -> Result<bool, String> {
        let mut policy = serde_json::to_value(&event.policy).map_err(|err| err.to_string())?;
        let mut record = serde_json::to_value(&event.record).map_err(|err| err.to_string())?;
        sanitise_json(&mut policy);
        sanitise_json(&mut record);
        let rua: Vec<&URI> = event
            .rua
            .iter()
            .take(self.max_rua)
            .filter(|uri| valid_address(uri.uri()))
            .collect();
        let rua = serde_json::to_string(&rua).map_err(|err| err.to_string())?;
        let domain = xml_safe(&event.policy_domain);
        let day = (event.received_at / DAY_SECS) as i64;
        self.with_tx(|tx| {
            let reported: Option<i64> = tx
                .query_row(
                    "SELECT 1 FROM dmarc_reports_sent WHERE day = ?1 AND policy_domain = ?2",
                    params![day, domain],
                    |row| row.get(0),
                )
                .optional()?;
            if reported.is_some() {
                return Ok(false);
            }
            let known: Option<i64> = tx
                .query_row(
                    "SELECT 1 FROM dmarc_events WHERE day = ?1 AND policy_domain = ?2 LIMIT 1",
                    params![day, domain],
                    |row| row.get(0),
                )
                .optional()?;
            if known.is_none() {
                let domains: i64 = tx.query_row(
                    "SELECT COUNT(DISTINCT policy_domain) FROM dmarc_events WHERE day = ?1",
                    params![day],
                    |row| row.get(0),
                )?;
                if domains as usize >= self.max_domains {
                    return Ok(false);
                }
            }
            let inserted = tx.execute(
                "INSERT OR IGNORE INTO dmarc_events (message_id, tenant_id, policy_domain, day, received_at, policy_json, rua_json, record_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    event.message_id,
                    event.tenant_id,
                    domain,
                    day,
                    event.received_at as i64,
                    policy.to_string(),
                    rua,
                    record.to_string()
                ],
            )?;
            Ok(inserted == 1)
        })
    }

    /// Days whose reports are due: ended at least [`GRACE_SECS`] ago, still
    /// holding events. Events past the retention period are dropped first.
    pub fn pending_days(&self, now: u64) -> Result<Vec<u64>, String> {
        let today = now / DAY_SECS;
        let oldest = today.saturating_sub(self.retention_days) as i64;
        let sent_oldest = today.saturating_sub(SENT_RETENTION_DAYS) as i64;
        let due = (now.saturating_sub(GRACE_SECS) / DAY_SECS) as i64;
        self.with_tx(|tx| {
            tx.execute("DELETE FROM dmarc_events WHERE day < ?1", params![oldest])?;
            tx.execute(
                "DELETE FROM dmarc_reports_sent WHERE day < ?1",
                params![sent_oldest],
            )?;
            let mut stmt =
                tx.prepare("SELECT DISTINCT day FROM dmarc_events WHERE day < ?1 ORDER BY day")?;
            let days = stmt
                .query_map(params![due], |row| row.get::<_, i64>(0))?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(days.into_iter().map(|day| day as u64).collect())
        })
    }

    /// Policy domains with unreported events on `day`.
    pub fn domains(&self, day: u64) -> Result<Vec<String>, String> {
        self.with_tx(|tx| {
            let mut stmt = tx.prepare(
                "SELECT DISTINCT policy_domain FROM dmarc_events WHERE day = ?1 ORDER BY policy_domain",
            )?;
            let domains = stmt
                .query_map(params![day as i64], |row| row.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(domains)
        })
    }

    /// Rows for one domain and day. Rows that do not parse are logged and
    /// skipped, so one bad row cannot block the report.
    pub fn load(&self, day: u64, domain: &str) -> Result<Option<DomainDay>, String> {
        let (head, rows, total) = self.with_tx(|tx| {
            let head: Option<(String, String)> = tx
                .query_row(
                    "SELECT policy_json, rua_json FROM dmarc_events
                     WHERE day = ?1 AND policy_domain = ?2 ORDER BY id DESC LIMIT 1",
                    params![day as i64, domain],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;
            let mut stmt = tx.prepare(
                "SELECT record_json, COUNT(*) FROM dmarc_events
                 WHERE day = ?1 AND policy_domain = ?2
                 GROUP BY record_json ORDER BY COUNT(*) DESC, MIN(id)",
            )?;
            let rows = stmt
                .query_map(params![day as i64, domain], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
                })?
                .collect::<Result<Vec<_>, _>>()?;
            let total: i64 = tx.query_row(
                "SELECT COUNT(*) FROM dmarc_events WHERE day = ?1 AND policy_domain = ?2",
                params![day as i64, domain],
                |row| row.get(0),
            )?;
            Ok((head, rows, total))
        })?;
        let Some((policy, rua)) = head else {
            return Ok(None);
        };
        let policy: PolicyPublished = match serde_json::from_str(&policy) {
            Ok(policy) => policy,
            Err(err) => {
                tracing::warn!(%domain, %err, "unreadable dmarc policy row");
                PolicyPublished {
                    domain: domain.to_string(),
                    ..PolicyPublished::default()
                }
            }
        };
        let rua: Vec<URI> = serde_json::from_str(&rua).unwrap_or_default();
        let mut parsed = Vec::new();
        let mut omitted_rows = 0;
        let mut included = 0;
        for (json, count) in rows {
            if parsed.len() >= self.max_rows {
                omitted_rows += 1;
                continue;
            }
            match serde_json::from_str::<Record>(&json) {
                Ok(record) => {
                    included += count;
                    parsed.push((record, count.min(u32::MAX as i64) as u32));
                }
                Err(err) => tracing::warn!(%domain, %err, "unreadable dmarc event row skipped"),
            }
        }
        Ok(Some(DomainDay {
            day,
            domain: domain.to_string(),
            policy,
            rua,
            rows: parsed,
            omitted_rows,
            omitted_messages: (total - included).max(0) as u64,
        }))
    }

    /// The spool id for this domain-day's report, created once. Retrying
    /// after a crash reuses it, so a report already spooled is not queued again.
    pub fn spool_id(&self, day: u64, domain: &str, fresh: &str) -> Result<String, String> {
        self.with_tx(|tx| {
            tx.execute(
                "INSERT OR IGNORE INTO dmarc_reports_sent (day, policy_domain, spool_id, done)
                 VALUES (?1, ?2, ?3, 0)",
                params![day as i64, domain, fresh],
            )?;
            tx.query_row(
                "SELECT spool_id FROM dmarc_reports_sent WHERE day = ?1 AND policy_domain = ?2",
                params![day as i64, domain],
                |row| row.get::<_, Option<String>>(0),
            )
            .map(|id| id.unwrap_or_else(|| fresh.to_string()))
        })
    }

    /// Mark a domain-day reported (or definitively unreportable) and drop its
    /// rows in one transaction.
    pub fn finish(&self, day: u64, domain: &str) -> Result<(), String> {
        self.with_tx(|tx| {
            tx.execute(
                "INSERT INTO dmarc_reports_sent (day, policy_domain, spool_id, done)
                 VALUES (?1, ?2, NULL, 1)
                 ON CONFLICT (day, policy_domain) DO UPDATE SET done = 1",
                params![day as i64, domain],
            )?;
            tx.execute(
                "DELETE FROM dmarc_events WHERE day = ?1 AND policy_domain = ?2",
                params![day as i64, domain],
            )?;
            Ok(())
        })
    }

    fn with_tx<T>(
        &self,
        f: impl FnOnce(&rusqlite::Transaction<'_>) -> rusqlite::Result<T>,
    ) -> Result<T, String> {
        let mut conn = self
            .conn
            .lock()
            .map_err(|_| "dmarc store lock poisoned".to_string())?;
        let tx = conn.transaction().map_err(|err| err.to_string())?;
        let value = f(&tx).map_err(|err| err.to_string())?;
        tx.commit().map_err(|err| err.to_string())?;
        Ok(value)
    }
}

/// Replace characters outside the XML 1.0 `Char` production. mail-auth
/// escapes `<>&'"` but passes control characters through, and one of those
/// makes a receiver reject the whole report.
pub fn xml_safe(value: &str) -> String {
    value
        .chars()
        .map(|ch| match ch {
            '\t' | '\n' | '\r' => ch,
            '\u{0}'..='\u{1f}' | '\u{fffe}' | '\u{ffff}' => '?',
            _ => ch,
        })
        .collect()
}

fn sanitise_json(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(text) => *text = xml_safe(text),
        serde_json::Value::Array(items) => items.iter_mut().for_each(sanitise_json),
        serde_json::Value::Object(map) => map.values_mut().for_each(sanitise_json),
        _ => {}
    }
}

/// A plain `local@domain` report address: ASCII, no controls, quotes or
/// brackets, a DNS host name with at least two labels and not an IP literal.
pub fn valid_address(address: &str) -> bool {
    let Some((local, domain)) = address.rsplit_once('@') else {
        return false;
    };
    let local_ok = !local.is_empty()
        && local.len() <= 64
        && !local.starts_with('.')
        && !local.ends_with('.')
        && !local.contains("..")
        && local
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || "!#$%&'*+-/=?^_`{|}~.".contains(ch));
    local_ok && address.len() <= 254 && valid_host(domain)
}

pub(crate) fn valid_host(domain: &str) -> bool {
    let labels: Vec<&str> = domain.split('.').collect();
    domain.len() <= 253
        && labels.len() >= 2
        && labels.iter().all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
        })
        // An all-digit last label means an IPv4 literal such as 10.0.0.1.
        && !labels
            .last()
            .is_some_and(|tld| tld.chars().all(|ch| ch.is_ascii_digit()))
}

fn domain_of(address: &str) -> String {
    address
        .rsplit_once('@')
        .map(|(_, domain)| domain.trim_end_matches('.').to_ascii_lowercase())
        .unwrap_or_default()
}

/// Report submitter: the domain of the configured report address.
pub fn submitter(cfg: &DmarcReportConfig) -> &str {
    cfg.email
        .rsplit_once('@')
        .map(|(_, domain)| domain)
        .unwrap_or(&cfg.email)
}

/// The RFC 9990 aggregate report for one policy domain and day.
pub fn build_report(cfg: &DmarcReportConfig, data: &DomainDay) -> Report {
    let begin = data.day * DAY_SECS;
    let mut report = Report::new()
        .with_version(1.0)
        .with_org_name(&cfg.org_name)
        .with_email(&cfg.email)
        .with_report_id(format!("{begin}.{}@{}", data.domain, submitter(cfg)))
        .with_date_range_begin(begin)
        .with_date_range_end(begin + DAY_SECS - 1)
        .with_generator(concat!("Currawong ", env!("CARGO_PKG_VERSION")))
        .with_policy_published(data.policy.clone());
    if data.omitted_rows > 0 {
        report = report.with_error(format!(
            "{} rows covering {} messages omitted by the report size limit",
            data.omitted_rows, data.omitted_messages
        ));
    }
    for (record, count) in &data.rows {
        report.add_record(record.clone().with_count(*count));
    }
    report
}

/// Render the report for `to`. Addresses whose `!size` limit is below the
/// rendered size are dropped and the message is rendered again, so the To
/// header always matches the envelope. `None` when nothing is left.
pub fn render_report(
    cfg: &DmarcReportConfig,
    data: &DomainDay,
    to: &[URI],
) -> Result<Option<OutgoingReport>, String> {
    let report = build_report(cfg, data);
    let mut to: Vec<&URI> = to.iter().collect();
    loop {
        if to.is_empty() {
            return Ok(None);
        }
        let mut message = Vec::new();
        report
            .write_rfc5322(
                submitter(cfg),
                cfg.email.as_str(),
                to.iter().map(|uri| uri.uri()),
                &mut message,
            )
            .map_err(|err| err.to_string())?;
        if message.len() > cfg.max_report_bytes {
            tracing::warn!(domain = %data.domain, bytes = message.len(), "dmarc report over max_report_bytes, not sent");
            return Ok(None);
        }
        // A `!0` limit parses as 0, the same as no limit.
        let fits = |uri: &&URI| uri.max_size() == 0 || message.len() <= uri.max_size();
        if to.iter().all(fits) {
            return Ok(Some(OutgoingReport {
                domain: data.domain.clone(),
                from: cfg.email.clone(),
                to: to.iter().map(|uri| uri.uri().to_string()).collect(),
                message,
            }));
        }
        to.retain(fits);
    }
}

impl AuthChecker {
    pub(crate) async fn dmarc_event(
        &self,
        env: &Envelope,
        envelope_from: &str,
        dkim: &[DkimOutput<'_>],
        spf: &SpfOutput,
        dmarc: &DmarcOutput,
    ) -> Option<DmarcEvent> {
        let record = dmarc.dmarc_record()?;
        let policy_domain = self.policy_domain(dmarc.domain(), record).await;
        let row = Record::new()
            .with_dkim_output(dkim)
            .with_spf_output(spf, SPFDomainScope::MailFrom)
            .with_dmarc_output(dmarc)
            .with_source_ip(env.remote_ip)
            .with_count(1)
            .with_envelope_from(envelope_from.to_ascii_lowercase())
            .with_header_from(dmarc.domain());
        Some(DmarcEvent {
            message_id: env.id.as_str().to_string(),
            tenant_id: env.tenant_id.clone(),
            policy: PolicyPublished::from_record(&policy_domain, record),
            policy_domain,
            received_at: env.received_at.unix_timestamp().max(0) as u64,
            rua: record.rua.clone(),
            record: row,
        })
    }

    /// The domain at which the applied record was found: the author domain,
    /// or a parent reached by the DMARC tree walk. The walk's answers are
    /// already cached, and the walk is capped at mail-auth's eight queries.
    async fn policy_domain(&self, author: &str, record: &Dmarc) -> String {
        let mut name = author;
        for _ in 0..MAX_WALK {
            let key = format!("_dmarc.{name}");
            if let Ok(found) = self
                .resolver
                .txt_lookup::<Dmarc>(key, Some(&self.cache))
                .await
            {
                if *found == *record {
                    return name.to_string();
                }
            }
            match name.split_once('.') {
                Some((_, parent)) if parent.contains('.') => name = parent,
                _ => break,
            }
        }
        author.to_string()
    }

    /// `rua` destinations the report may go to. Malformed addresses, IP
    /// literals and the gateway's own domains are refused. A destination
    /// outside the policy domain needs `<domain>._report._dmarc.<host>`
    /// (RFC 9990 section 4, formerly RFC 7489 section 7.1). `None` is a DNS
    /// failure or timeout: keep the rows and try again later.
    pub async fn authorised_rua(
        &self,
        domain: &str,
        rua: &[URI],
        local_domains: &[String],
    ) -> Option<Vec<URI>> {
        let candidates: Vec<&URI> = rua
            .iter()
            .filter(|uri| valid_address(uri.uri()))
            .filter(|uri| !is_local(&domain_of(uri.uri()), local_domains))
            .collect();
        let uris: Vec<&str> = candidates.iter().map(|uri| uri.uri()).collect();
        let verify = self
            .resolver
            .verify_dmarc_report_address(domain, &uris, Some(&self.cache));
        let allowed = tokio::time::timeout(DNS_TIMEOUT, verify).await.ok()??;
        Some(
            candidates
                .into_iter()
                .filter(|uri| allowed.contains(&&uri.uri()))
                .cloned()
                .collect(),
        )
    }
}

fn is_local(domain: &str, local_domains: &[String]) -> bool {
    local_domains.iter().any(|local| {
        let local = local.trim_end_matches('.').to_ascii_lowercase();
        domain == local || domain.ends_with(&format!(".{local}"))
    })
}
