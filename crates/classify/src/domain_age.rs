//! Bounded optional RDAP enrichment for scan-time callers.
use crate::message::{address_domain, MessageView};
use currawong_core::{config::RdapConfig, ScanReport};
use currawong_link::{rdap::Rdap, registrable};
use std::collections::BTreeMap;

pub async fn assess(
    rdap: &Rdap,
    cfg: &RdapConfig,
    own: &[String],
    view: &MessageView,
    report: &mut ScanReport,
) {
    let mut domains: BTreeMap<String, Vec<&str>> = BTreeMap::new();
    for (source, addresses) in [("sender", &view.from), ("reply_to", &view.reply_to)] {
        for domain in addresses
            .iter()
            .filter_map(|a| address_domain(a))
            .filter_map(registrable)
        {
            domains.entry(domain).or_default().push(source);
        }
    }
    if cfg.scan_urls {
        for domain in view
            .hosts
            .iter()
            .cloned()
            .chain(
                report
                    .urls
                    .iter()
                    .filter_map(|u| url::Url::parse(u).ok())
                    .filter_map(|u| u.host_str().map(str::to_string)),
            )
            .filter_map(|d| registrable(&d))
        {
            domains.entry(domain).or_default().push("url");
        }
    }
    // Prioritise address domains over URL domains so attacker-supplied links
    // cannot exhaust the lookup budget before From and Reply-To are checked.
    let mut domains: Vec<_> = domains.into_iter().collect();
    domains.sort_by_key(|(_, sources)| !sources.iter().any(|s| *s != "url"));
    if domains.len() > cfg.max_domains {
        report
            .notes
            .push("RDAP domain limit reached; remaining ages unknown".into());
    }
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(cfg.timeout_secs);
    for (domain, sources) in domains.into_iter().take(cfg.max_domains) {
        if tokio::time::Instant::now() >= deadline {
            report
                .notes
                .push("RDAP scan deadline reached; remaining ages unknown".into());
            break;
        }
        let result = rdap.age_days_until(&domain, own, deadline).await;
        match result {
            Ok(Some(days)) => {
                report.domain_youngest_days = Some(
                    report
                        .domain_youngest_days
                        .map_or(days, |old| old.min(days)),
                );
                if days < cfg.new_domain_days {
                    for source in sources {
                        let flag = format!("domain.new_{source}");
                        if !report.flags.contains(&flag) {
                            report.flags.push(flag);
                        }
                    }
                }
            }
            Ok(None) => report
                .notes
                .push(format!("RDAP age unknown or own domain skipped: {domain}")),
            Err(error) => report
                .notes
                .push(format!("RDAP unavailable for {domain}: {error}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use currawong_core::MessageId;
    #[tokio::test]
    async fn cached_scan_age_flags_counts_own_domains_and_url_opt_in() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = RdapConfig {
            enabled: true,
            database: dir.path().join("rdap.sqlite3"),
            ..Default::default()
        };
        let rdap = Rdap::open(&cfg).unwrap();
        let db = rusqlite::Connection::open(&cfg.database).unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        for (domain, days) in [
            ("sender.com", 3),
            ("reply.net", 2),
            ("target.org", 1),
            ("own.com", 0),
        ] {
            db.execute(
                "INSERT INTO rdap_cache(key,registered,expires) VALUES(?1,?2,?3)",
                rusqlite::params![
                    format!("{}|{domain}", cfg.bootstrap_url),
                    now - days * 86400,
                    now + 3600
                ],
            )
            .unwrap();
        }
        let view = MessageView::parse(b"From: a@sender.com\r\nReply-To: b@reply.net\r\nSubject: hi\r\n\r\nhttps://target.org/ https://own.com/");
        let mut report = ScanReport::new(MessageId("test".into()));
        assess(&rdap, &cfg, &["own.com".into()], &view, &mut report).await;
        assert!(report.flags.contains(&"domain.new_sender".into()));
        assert!(report.flags.contains(&"domain.new_reply_to".into()));
        assert!(!report.flags.contains(&"domain.new_url".into()));
        assert_eq!(report.domain_youngest_days, Some(2));
        cfg.scan_urls = true;
        assess(&rdap, &cfg, &["own.com".into()], &view, &mut report).await;
        assert!(report.flags.contains(&"domain.new_url".into()));
        assert_eq!(report.domain_youngest_days, Some(1));
    }
}
