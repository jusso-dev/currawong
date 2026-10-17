//! Daily DMARC aggregate reports into the outbound spool, and BIMI logos for
//! quarantined mail.
use currawong_auth::{
    bimi::{self, TxtLookup},
    AuthChecker, DmarcEventStore,
};
use currawong_core::{config::DmarcReportConfig, Direction, ScanReport};
use currawong_quarantine::QuarantineStore;
use currawong_spool::{Envelope, Spool, SpoolState};
use std::net::{IpAddr, Ipv4Addr};
use time::OffsetDateTime;

/// Queue reports for every finished UTC day. Returns how many were queued.
/// A day's events are dropped only after all its reports are spooled.
pub async fn send_dmarc_reports(
    spool: &Spool,
    auth: &AuthChecker,
    store: &DmarcEventStore,
    cfg: &DmarcReportConfig,
    now: OffsetDateTime,
) -> Result<usize, String> {
    let mut queued = 0;
    for day in store.pending_days(now.unix_timestamp().max(0) as u64)? {
        for report in auth.dmarc_reports(store, cfg, day).await? {
            // Generated here, so there is nothing to scan: mark it deliverable.
            let env = Envelope {
                id: Envelope::new_id(),
                tenant_id: None,
                mail_from: report.from.clone(),
                rcpt_to: report.to.clone(),
                received_at: now,
                remote_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                helo: currawong_auth::dmarc_report::submitter(cfg).to_string(),
                attempts: 0,
                next_attempt_at: None,
                state: SpoolState::Incoming,
                direction: Direction::Outbound,
                tls_version: None,
                tls_cipher: None,
                rcpt_status: Vec::new(),
                prepend_headers: Vec::new(),
                dsn_sent: false,
                pipeline: "deliver".into(),
            };
            spool
                .accept(env, report.message.as_slice())
                .await
                .map_err(|err| err.to_string())?;
            tracing::info!(domain = %report.domain, rcpts = report.to.len(), "dmarc aggregate report queued");
            queued += 1;
        }
        store.finish_day(day)?;
    }
    Ok(queued)
}

/// Store the BIMI logo and VMC status beside a quarantined message.
pub async fn annotate_bimi(
    txt: &dyn TxtLookup,
    quarantine: &QuarantineStore,
    report: &ScanReport,
    raw: &[u8],
) {
    let (Some(auth), Some(domain)) = (&report.auth, bimi::author_domain(raw)) else {
        return;
    };
    let Some(found) = bimi::lookup(txt, &domain, auth).await else {
        return;
    };
    let id = report.message_id.as_str();
    let result = serde_json::to_string(&found)
        .map_err(|err| err.to_string())
        .and_then(|json| {
            quarantine
                .set_bimi(id, &json)
                .map_err(|err| err.to_string())
        });
    if let Err(err) = result {
        tracing::warn!(%id, %err, "BIMI not stored");
    }
}
