//! TLS-RPT (RFC 8460). Delivery records the TLS outcome of each session made
//! under a DANE or MTA-STS policy; once a UTC day is over, each policy domain
//! that publishes `_smtp._tls` gets one JSON report at its `rua`.
use crate::dns::{normalise, DnsLookup};
use currawong_core::{config::Config, Direction};
use currawong_spool::{Envelope, Spool, SpoolState};
use mail_auth::{
    common::parse::TxtRecordParser,
    flate2::{write::GzEncoder, Compression},
    mta_sts::{ReportUri, TlsRpt as TlsRptRecord},
    report::tlsrpt::{
        DateRange, FailureDetails, Policy, PolicyDetails, ResultType, Summary, TlsReport,
    },
};
use rusqlite::Connection;
use std::{collections::BTreeMap, io::Write, net::IpAddr, path::PathBuf};
use time::{macros::format_description, Date};

/// One failed session, for `failure-details`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    pub result: ResultType,
    pub receiving_mx: String,
    pub receiving_ip: Option<IpAddr>,
}

pub struct TlsRpt {
    db: PathBuf,
}

impl TlsRpt {
    pub fn new(db: PathBuf) -> Self {
        Self { db }
    }

    /// Count one session. `failure` is `None` for a successful session.
    pub async fn record(
        &self,
        day: Date,
        policy: &PolicyDetails,
        failure: Option<&Failure>,
    ) -> Result<(), String> {
        let db = self.db.clone();
        let domain = normalise(&policy.policy_domain);
        let policy = serde_json::to_string(policy).map_err(|err| err.to_string())?;
        let (result, mx, ip) = match failure {
            Some(failure) => (
                serde_json::to_string(&failure.result).map_err(|err| err.to_string())?,
                failure.receiving_mx.clone(),
                failure
                    .receiving_ip
                    .map(|ip| ip.to_string())
                    .unwrap_or_default(),
            ),
            None => (String::new(), String::new(), String::new()),
        };
        blocking(move || {
            open(&db)?
                .execute(
                    "INSERT INTO tlsrpt_result
                       (day, domain, policy, result, receiving_mx, receiving_ip, count)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1)
                     ON CONFLICT(day, domain, policy, result, receiving_mx, receiving_ip)
                     DO UPDATE SET count = count + 1",
                    rusqlite::params![day.to_string(), domain, policy, result, mx, ip],
                )
                .map_err(|err| err.to_string())?;
            Ok(())
        })
        .await
    }

    /// The report for `domain` covering `day`, if anything was recorded.
    pub async fn report(
        &self,
        day: Date,
        domain: &str,
        organisation: &str,
        contact: &str,
        submitter: &str,
    ) -> Result<Option<TlsReport>, String> {
        let db = self.db.clone();
        let key = (day.to_string(), normalise(domain));
        let rows = blocking(move || {
            let conn = open(&db)?;
            let mut stmt = conn
                .prepare(
                    "SELECT policy, result, receiving_mx, receiving_ip, count FROM tlsrpt_result
                     WHERE day = ?1 AND domain = ?2",
                )
                .map_err(|err| err.to_string())?;
            let rows = stmt
                .query_map(rusqlite::params![key.0, key.1], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, u32>(4)?,
                    ))
                })
                .map_err(|err| err.to_string())?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|err| err.to_string())?;
            Ok(rows)
        })
        .await?;
        if rows.is_empty() {
            return Ok(None);
        }
        let mut policies: BTreeMap<String, Policy> = BTreeMap::new();
        for (policy_json, result, mx, ip, count) in rows {
            let entry = match policies.entry(policy_json) {
                std::collections::btree_map::Entry::Occupied(entry) => entry.into_mut(),
                std::collections::btree_map::Entry::Vacant(entry) => {
                    let details: PolicyDetails =
                        serde_json::from_str(entry.key()).map_err(|err| err.to_string())?;
                    entry.insert(Policy {
                        policy: details,
                        summary: Summary {
                            total_success: 0,
                            total_failure: 0,
                        },
                        failure_details: Vec::new(),
                    })
                }
            };
            if result.is_empty() {
                entry.summary.total_success += count;
                continue;
            }
            entry.summary.total_failure += count;
            let result_type: ResultType =
                serde_json::from_str(&result).map_err(|err| err.to_string())?;
            let mut detail = FailureDetails::new(result_type);
            detail.failed_session_count = count;
            if !mx.is_empty() {
                detail = detail.with_receiving_mx_hostname(mx);
            }
            if let Ok(ip) = ip.parse() {
                detail = detail.with_receiving_ip(ip);
            }
            entry.failure_details.push(detail);
        }
        let start = day.midnight().assume_utc().unix_timestamp();
        Ok(Some(TlsReport {
            organization_name: Some(organisation.to_string()),
            date_range: DateRange::from_timestamps(start, start + 86_399),
            contact_info: Some(contact.to_string()),
            report_id: format!("{day}.{}@{submitter}", normalise(domain)),
            policies: policies.into_values().collect(),
        }))
    }

    /// Days before `today` with results not yet reported, per domain.
    async fn pending(&self, today: Date) -> Result<Vec<(Date, String)>, String> {
        let db = self.db.clone();
        let today = today.to_string();
        let rows = blocking(move || {
            let conn = open(&db)?;
            let mut stmt = conn
                .prepare(
                    "SELECT DISTINCT r.day, r.domain FROM tlsrpt_result r
                     LEFT JOIN tlsrpt_sent s ON s.day = r.day AND s.domain = r.domain
                     WHERE r.day < ?1 AND s.day IS NULL",
                )
                .map_err(|err| err.to_string())?;
            let rows = stmt
                .query_map([today], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })
                .map_err(|err| err.to_string())?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|err| err.to_string())?;
            Ok(rows)
        })
        .await?;
        Ok(rows
            .into_iter()
            .filter_map(|(day, domain)| {
                Date::parse(&day, format_description!("[year]-[month]-[day]"))
                    .ok()
                    .map(|day| (day, domain))
            })
            .collect())
    }

    async fn mark_sent(&self, day: Date, domain: &str) -> Result<(), String> {
        let db = self.db.clone();
        let domain = domain.to_string();
        let old = (day - time::Duration::days(31)).to_string();
        blocking(move || {
            let conn = open(&db)?;
            conn.execute(
                "INSERT OR IGNORE INTO tlsrpt_sent (day, domain) VALUES (?1, ?2)",
                rusqlite::params![day.to_string(), domain],
            )
            .map_err(|err| err.to_string())?;
            conn.execute("DELETE FROM tlsrpt_result WHERE day < ?1", [&old])
                .map_err(|err| err.to_string())?;
            conn.execute("DELETE FROM tlsrpt_sent WHERE day < ?1", [&old])
                .map_err(|err| err.to_string())?;
            Ok(())
        })
        .await
    }

    /// Send every finished day's reports. Mail `rua`s are queued in the
    /// spool from the null sender; HTTPS `rua`s are posted when `http` is
    /// given. Returns the number of reports sent.
    pub async fn send_due(
        &self,
        cfg: &Config,
        dns: &dyn DnsLookup,
        spool: &Spool,
        http: Option<&reqwest::Client>,
        today: Date,
    ) -> Result<usize, String> {
        let hostname = &cfg.gateway.hostname;
        let contact = if cfg.delivery.tls_rpt.contact.is_empty() {
            format!("postmaster@{hostname}")
        } else {
            cfg.delivery.tls_rpt.contact.clone()
        };
        let mut sent = 0;
        for (day, domain) in self.pending(today).await? {
            let rua = match dns.lookup_txt(&format!("_smtp._tls.{domain}")).await {
                Ok(records) => records
                    .iter()
                    .filter(|record| record.starts_with("v=TLSRPTv1"))
                    .filter_map(|record| TlsRptRecord::parse(record.as_bytes()).ok())
                    .flat_map(|record| record.rua)
                    .collect::<Vec<_>>(),
                Err(err) => {
                    // Try again on the next pass.
                    tracing::debug!(%err, %domain, "TLS-RPT TXT lookup failed");
                    continue;
                }
            };
            if !rua.is_empty() {
                if let Some(report) = self
                    .report(
                        day,
                        &domain,
                        &cfg.delivery.tls_rpt.organisation,
                        &contact,
                        hostname,
                    )
                    .await?
                {
                    deliver_report(&report, &domain, &rua, hostname, spool, http).await?;
                    sent += 1;
                }
            }
            self.mark_sent(day, &domain).await?;
        }
        Ok(sent)
    }
}

async fn deliver_report(
    report: &TlsReport,
    domain: &str,
    rua: &[ReportUri],
    hostname: &str,
    spool: &Spool,
    http: Option<&reqwest::Client>,
) -> Result<(), String> {
    let mail: Vec<&str> = rua
        .iter()
        .filter_map(|uri| match uri {
            ReportUri::Mail(addr) => Some(addr.as_str()),
            ReportUri::Http(_) => None,
        })
        .collect();
    if !mail.is_empty() {
        let from = format!("tlsrpt-noreply@{hostname}");
        let message = report
            .to_rfc5322(
                domain,
                hostname,
                ("TLS reports", from.as_str()),
                mail.iter().copied(),
            )
            .map_err(|err| err.to_string())?;
        let env = Envelope {
            id: Envelope::new_id(),
            tenant_id: None,
            mail_from: String::new(),
            rcpt_to: mail.iter().map(|addr| addr.to_string()).collect(),
            received_at: time::OffsetDateTime::now_utc(),
            remote_ip: IpAddr::from([127, 0, 0, 1]),
            helo: hostname.to_string(),
            attempts: 0,
            next_attempt_at: None,
            state: SpoolState::Incoming,
            direction: Direction::Outbound,
            tls_version: None,
            tls_cipher: None,
            rcpt_status: Vec::new(),
            prepend_headers: Vec::new(),
            dsn_sent: true,
            pipeline: "pending".into(),
        };
        spool
            .accept(env, std::io::Cursor::new(message.into_bytes()))
            .await
            .map_err(|err| err.to_string())?;
    }
    if let Some(client) = http {
        for uri in rua {
            let ReportUri::Http(url) = uri else {
                continue;
            };
            let mut gz = GzEncoder::new(Vec::new(), Compression::default());
            gz.write_all(report.to_json().as_bytes())
                .map_err(|err| err.to_string())?;
            let body = gz.finish().map_err(|err| err.to_string())?;
            let response = client
                .post(url)
                .header(reqwest::header::CONTENT_TYPE, "application/tlsrpt+gzip")
                .body(body)
                .send()
                .await;
            match response {
                Ok(response) if response.status().is_success() => {}
                Ok(response) => {
                    tracing::warn!(%url, status = %response.status(), "TLS-RPT upload refused")
                }
                Err(err) => tracing::warn!(%url, %err, "TLS-RPT upload failed"),
            }
        }
    }
    Ok(())
}

fn open(db: &std::path::Path) -> Result<Connection, String> {
    if let Some(parent) = db.parent() {
        std::fs::create_dir_all(parent).map_err(|err| err.to_string())?;
    }
    let conn = Connection::open(db).map_err(|err| err.to_string())?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS tlsrpt_result (
            day TEXT NOT NULL,
            domain TEXT NOT NULL,
            policy TEXT NOT NULL,
            result TEXT NOT NULL,
            receiving_mx TEXT NOT NULL,
            receiving_ip TEXT NOT NULL,
            count INTEGER NOT NULL,
            PRIMARY KEY (day, domain, policy, result, receiving_mx, receiving_ip)
        );
        CREATE TABLE IF NOT EXISTS tlsrpt_sent (
            day TEXT NOT NULL,
            domain TEXT NOT NULL,
            PRIMARY KEY (day, domain)
        );",
    )
    .map_err(|err| err.to_string())?;
    Ok(conn)
}

async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, String> + Send + 'static,
) -> Result<T, String> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|err| err.to_string())?
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::MapDns;
    use mail_auth::report::tlsrpt::PolicyType;

    fn sts_policy() -> PolicyDetails {
        let mut policy = PolicyDetails::new(PolicyType::Sts, "example.test");
        policy.policy_string = vec!["version: STSv1".into(), "mode: enforce".into()];
        policy.mx_host = vec!["mx.example.test".into()];
        policy
    }

    fn mismatch() -> Failure {
        Failure {
            result: ResultType::CertificateHostMismatch,
            receiving_mx: "mx.example.test".into(),
            receiving_ip: Some("192.0.2.25".parse().unwrap()),
        }
    }

    #[tokio::test]
    async fn tlsrpt_json_has_every_rfc8460_required_field() {
        let dir = tempfile::tempdir().unwrap();
        let store = TlsRpt::new(dir.path().join("tls.sqlite"));
        let day = Date::from_calendar_date(2026, time::Month::October, 16).unwrap();
        store.record(day, &sts_policy(), None).await.unwrap();
        store.record(day, &sts_policy(), None).await.unwrap();
        store
            .record(day, &sts_policy(), Some(&mismatch()))
            .await
            .unwrap();
        let report = store
            .report(
                day,
                "example.test",
                "Example Pty Ltd",
                "mailto:tls@gw.test",
                "gw.test",
            )
            .await
            .unwrap()
            .unwrap();
        let json: serde_json::Value = serde_json::from_str(&report.to_json()).unwrap();
        assert_eq!(json["organization-name"], "Example Pty Ltd");
        assert_eq!(json["contact-info"], "mailto:tls@gw.test");
        assert!(json["report-id"].as_str().unwrap().contains("example.test"));
        assert_eq!(json["date-range"]["start-datetime"], "2026-10-16T00:00:00Z");
        assert_eq!(json["date-range"]["end-datetime"], "2026-10-16T23:59:59Z");
        let policy = &json["policies"][0];
        assert_eq!(policy["policy"]["policy-type"], "sts");
        assert_eq!(policy["policy"]["policy-domain"], "example.test");
        assert_eq!(policy["policy"]["policy-string"][1], "mode: enforce");
        assert_eq!(policy["policy"]["mx-host"][0], "mx.example.test");
        assert_eq!(policy["summary"]["total-successful-session-count"], 2);
        assert_eq!(policy["summary"]["total-failure-session-count"], 1);
        let failure = &policy["failure-details"][0];
        assert_eq!(failure["result-type"], "certificate-host-mismatch");
        assert_eq!(failure["failed-session-count"], 1);
        assert_eq!(failure["receiving-mx-hostname"], "mx.example.test");
        assert_eq!(failure["receiving-ip"], "192.0.2.25");
    }

    #[tokio::test]
    async fn tlsrpt_daily_report_is_mailed_once_to_rua() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = Config::default();
        cfg.gateway.hostname = "gw.test".into();
        let spool = Spool::open(dir.path().join("spool")).await.unwrap();
        let store = TlsRpt::new(dir.path().join("tls.sqlite"));
        let today = Date::from_calendar_date(2026, time::Month::October, 17).unwrap();
        let yesterday = today.previous_day().unwrap();
        store
            .record(yesterday, &sts_policy(), Some(&mismatch()))
            .await
            .unwrap();
        store.record(today, &sts_policy(), None).await.unwrap();
        let mut dns = MapDns::new();
        dns.txt.insert(
            "_smtp._tls.example.test".into(),
            vec!["v=TLSRPTv1; rua=mailto:tlsrpt@example.test".into()],
        );
        let sent = store
            .send_due(&cfg, &dns, &spool, None, today)
            .await
            .unwrap();
        assert_eq!(sent, 1, "only the finished day is reported");
        let queued = spool.list(SpoolState::Incoming).await.unwrap();
        assert_eq!(queued.len(), 1);
        assert_eq!(queued[0].rcpt_to, vec!["tlsrpt@example.test".to_string()]);
        assert!(queued[0].mail_from.is_empty());
        let body = String::from_utf8(spool.read_body(&queued[0].id).await.unwrap()).unwrap();
        assert!(body.contains("TLS-Report-Domain: example.test"), "{body}");
        assert!(body.contains("application/tlsrpt+gzip"), "{body}");
        let again = store
            .send_due(&cfg, &dns, &spool, None, today)
            .await
            .unwrap();
        assert_eq!(again, 0);
    }
}
