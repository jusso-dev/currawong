//! Daily DMARC aggregate (RUA) reports, RFC 9990. Each evaluation is a row in
//! `dmarc_events`. Once a UTC day has ended, rows are grouped per policy domain
//! into one gzipped XML report. Failure (RUF) reports are never sent.
use crate::AuthChecker;
use currawong_core::config::DmarcReportConfig;
use currawong_spool::Envelope;
use mail_auth::{
    dmarc::{Dmarc, URI},
    report::{PolicyPublished, Record, Report, SPFDomainScope},
    DkimOutput, DmarcOutput, SpfOutput,
};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const DAY_SECS: u64 = 86_400;

/// One DMARC evaluation, kept until its day has been reported.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DmarcEvent {
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
    pub domain: String,
    pub policy: PolicyPublished,
    pub rua: Vec<URI>,
    /// Distinct rows and how many messages each covers.
    pub rows: Vec<(Record, u32)>,
}

/// A rendered report message and the destinations allowed to receive it.
#[derive(Debug, Clone)]
pub struct OutgoingReport {
    pub domain: String,
    pub from: String,
    pub to: Vec<String>,
    pub message: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct DmarcEventStore {
    path: PathBuf,
}

impl DmarcEventStore {
    pub fn open(path: &Path) -> Result<Self, String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|err| err.to_string())?;
        }
        let store = Self {
            path: path.to_path_buf(),
        };
        store.with_conn(|conn| {
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS dmarc_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tenant_id TEXT,
                    policy_domain TEXT NOT NULL,
                    day INTEGER NOT NULL,
                    received_at INTEGER NOT NULL,
                    policy_json TEXT NOT NULL,
                    rua_json TEXT NOT NULL,
                    record_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS dmarc_events_day ON dmarc_events (day, policy_domain);",
            )
            .map_err(|err| err.to_string())
        })?;
        Ok(store)
    }

    pub fn record(&self, event: &DmarcEvent) -> Result<(), String> {
        let policy = serde_json::to_string(&event.policy).map_err(|err| err.to_string())?;
        let rua = serde_json::to_string(&event.rua).map_err(|err| err.to_string())?;
        let record = serde_json::to_string(&event.record).map_err(|err| err.to_string())?;
        self.with_conn(|conn| {
            conn.execute(
                "INSERT INTO dmarc_events (tenant_id, policy_domain, day, received_at, policy_json, rua_json, record_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    event.tenant_id,
                    event.policy_domain,
                    (event.received_at / DAY_SECS) as i64,
                    event.received_at as i64,
                    policy,
                    rua,
                    record
                ],
            )
            .map_err(|err| err.to_string())?;
            Ok(())
        })
    }

    /// Days, as `unix_secs / 86400`, that have ended and still hold events.
    pub fn pending_days(&self, now: u64) -> Result<Vec<u64>, String> {
        let today = (now / DAY_SECS) as i64;
        self.with_conn(|conn| {
            let mut stmt = conn
                .prepare("SELECT DISTINCT day FROM dmarc_events WHERE day < ?1 ORDER BY day")
                .map_err(|err| err.to_string())?;
            let rows = stmt
                .query_map(params![today], |row| row.get::<_, i64>(0))
                .map_err(|err| err.to_string())?;
            rows.map(|row| row.map(|day| day as u64).map_err(|err| err.to_string()))
                .collect()
        })
    }

    pub fn day(&self, day: u64) -> Result<Vec<DomainDay>, String> {
        self.with_conn(|conn| {
            let mut latest = conn
                .prepare(
                    "SELECT policy_domain, policy_json, rua_json FROM dmarc_events
                     WHERE id IN (SELECT MAX(id) FROM dmarc_events WHERE day = ?1 GROUP BY policy_domain)
                     ORDER BY policy_domain",
                )
                .map_err(|err| err.to_string())?;
            let heads = latest
                .query_map(params![day as i64], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                })
                .map_err(|err| err.to_string())?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|err| err.to_string())?;
            let mut grouped = conn
                .prepare(
                    "SELECT record_json, COUNT(*) FROM dmarc_events
                     WHERE day = ?1 AND policy_domain = ?2
                     GROUP BY record_json ORDER BY MIN(id)",
                )
                .map_err(|err| err.to_string())?;
            let mut out = Vec::new();
            for (domain, policy, rua) in heads {
                let rows = grouped
                    .query_map(params![day as i64, domain], |row| {
                        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
                    })
                    .map_err(|err| err.to_string())?
                    .map(|row| {
                        let (json, count) = row.map_err(|err| err.to_string())?;
                        let record: Record =
                            serde_json::from_str(&json).map_err(|err| err.to_string())?;
                        Ok((record, count as u32))
                    })
                    .collect::<Result<Vec<_>, String>>()?;
                out.push(DomainDay {
                    domain,
                    policy: serde_json::from_str(&policy).map_err(|err| err.to_string())?,
                    rua: serde_json::from_str(&rua).map_err(|err| err.to_string())?,
                    rows,
                });
            }
            Ok(out)
        })
    }

    /// Drop a reported day.
    pub fn finish_day(&self, day: u64) -> Result<(), String> {
        self.with_conn(|conn| {
            conn.execute(
                "DELETE FROM dmarc_events WHERE day = ?1",
                params![day as i64],
            )
            .map_err(|err| err.to_string())?;
            Ok(())
        })
    }

    fn with_conn<T>(&self, f: impl FnOnce(&Connection) -> Result<T, String>) -> Result<T, String> {
        let conn = Connection::open(&self.path).map_err(|err| err.to_string())?;
        f(&conn)
    }
}

/// Report submitter: the domain of the configured report address.
pub fn submitter(cfg: &DmarcReportConfig) -> &str {
    cfg.email
        .rsplit_once('@')
        .map(|(_, domain)| domain)
        .unwrap_or(&cfg.email)
}

/// The RFC 9990 aggregate report for one policy domain and day.
pub fn build_report(cfg: &DmarcReportConfig, day: u64, data: &DomainDay) -> Report {
    let begin = day * DAY_SECS;
    let mut report = Report::new()
        .with_version(1.0)
        .with_org_name(&cfg.org_name)
        .with_email(&cfg.email)
        .with_report_id(format!("{begin}.{}@{}", data.domain, submitter(cfg)))
        .with_date_range_begin(begin)
        .with_date_range_end(begin + DAY_SECS - 1)
        .with_generator(concat!("Currawong ", env!("CARGO_PKG_VERSION")))
        .with_policy_published(data.policy.clone());
    for (record, count) in &data.rows {
        report.add_record(record.clone().with_count(*count));
    }
    report
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
            tenant_id: env.tenant_id.clone(),
            policy: PolicyPublished::from_record(&policy_domain, record),
            policy_domain,
            received_at: env.received_at.unix_timestamp().max(0) as u64,
            rua: record.rua.clone(),
            record: row,
        })
    }

    /// The domain at which the applied record was found: the author domain,
    /// or a parent reached by the DMARC tree walk.
    async fn policy_domain(&self, author: &str, record: &Dmarc) -> String {
        let mut name = author;
        loop {
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
                _ => return author.to_string(),
            }
        }
    }

    /// `rua` destinations the report may go to. A destination outside the
    /// policy domain needs `<domain>._report._dmarc.<host>` (RFC 9990
    /// section 4, formerly RFC 7489 section 7.1). `None` is a DNS failure.
    pub async fn authorised_rua(&self, domain: &str, rua: &[URI]) -> Option<Vec<URI>> {
        let uris: Vec<&str> = rua.iter().map(URI::uri).collect();
        let allowed = self
            .resolver
            .verify_dmarc_report_address(domain, &uris, Some(&self.cache))
            .await?;
        Some(
            rua.iter()
                .filter(|uri| allowed.contains(&&uri.uri()))
                .cloned()
                .collect(),
        )
    }

    /// Rendered reports for every domain seen on `day`. Domains with no
    /// authorised destination are skipped and logged.
    pub async fn dmarc_reports(
        &self,
        store: &DmarcEventStore,
        cfg: &DmarcReportConfig,
        day: u64,
    ) -> Result<Vec<OutgoingReport>, String> {
        let submitter = submitter(cfg);
        let mut out = Vec::new();
        for data in store.day(day)? {
            let Some(allowed) = self.authorised_rua(&data.domain, &data.rua).await else {
                tracing::warn!(domain = %data.domain, "rua verification failed, report skipped");
                continue;
            };
            if allowed.is_empty() {
                if !data.rua.is_empty() {
                    tracing::info!(domain = %data.domain, "rua destination not authorised, report not sent");
                }
                continue;
            }
            let report = build_report(cfg, day, &data);
            let to: Vec<&str> = allowed.iter().map(URI::uri).collect();
            let mut message = Vec::new();
            report
                .write_rfc5322(
                    submitter,
                    cfg.email.as_str(),
                    to.iter().copied(),
                    &mut message,
                )
                .map_err(|err| err.to_string())?;
            // `!10m` style size limits on the rua URI.
            let to = allowed
                .iter()
                .filter(|uri| uri.max_size() == 0 || message.len() <= uri.max_size())
                .map(|uri| uri.uri().to_string())
                .collect::<Vec<_>>();
            if to.is_empty() {
                continue;
            }
            out.push(OutgoingReport {
                domain: data.domain,
                from: cfg.email.clone(),
                to,
                message,
            });
        }
        Ok(out)
    }
}
