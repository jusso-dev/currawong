//! M1 policy. Spam, phishing and BEC blocking stay in M2.
//! A message is quarantined for malware, active content, a fail-closed scan,
//! a DMARC `p=reject` failure, or a DLP review threshold. Anything else is
//! delivered.
use currawong_core::{ScanReport, Verdict};

pub fn decide(report: &ScanReport) -> Verdict {
    if report.malware {
        return Verdict::Quarantine {
            reason: "malware".into(),
        };
    }
    if report.defer {
        let reason = report
            .notes
            .iter()
            .find(|note| note.contains("unreachable"))
            .cloned()
            .unwrap_or_else(|| "required scanner is unreachable".into());
        return Verdict::Defer { reason };
    }
    if report.active_content {
        return Verdict::Quarantine {
            reason: "active content".into(),
        };
    }
    if report.fail_closed {
        return Verdict::Quarantine {
            reason: "scan failed closed".into(),
        };
    }
    if let Some(auth) = &report.auth {
        if auth.dmarc.result == "fail" && auth.dmarc_policy == "reject" {
            return Verdict::Quarantine {
                reason: "dmarc p=reject".into(),
            };
        }
    }
    // Default DLP rule: hold for review once a kind reaches its threshold, or
    // when some text could not be scanned. The reason carries counts only.
    if let Some(dlp) = report
        .dlp
        .as_ref()
        .filter(|dlp| !dlp.review.is_empty() || dlp.incomplete)
    {
        let mut kinds: Vec<String> = dlp
            .review
            .iter()
            .map(|kind| format!("{} x{}", kind.as_str(), dlp.counts.get(kind).unwrap_or(&0)))
            .collect();
        if dlp.incomplete {
            kinds.push("scan incomplete".into());
        }
        return Verdict::Quarantine {
            reason: format!("dlp review: {}", kinds.join(", ")),
        };
    }
    Verdict::Deliver
}

#[cfg(test)]
mod tests {
    use super::decide;
    use currawong_core::{AuthMethodResult, AuthResults, MessageId, ScanReport, Verdict};

    fn report() -> ScanReport {
        ScanReport::new(MessageId("01ARZ3NDEKTSV4RRFFQ69G5FAV".into()))
    }

    #[test]
    fn dmarc_reject_is_quarantined_and_unscored_mail_is_delivered() {
        let mut spoof = report();
        spoof.auth = Some(AuthResults {
            spf: AuthMethodResult {
                result: "fail".into(),
                detail: String::new(),
            },
            dkim: Vec::new(),
            dmarc: AuthMethodResult {
                result: "fail".into(),
                detail: String::new(),
            },
            arc: AuthMethodResult::none(),
            dmarc_policy: "reject".into(),
            header: String::new(),
        });
        assert!(matches!(decide(&spoof), Verdict::Quarantine { .. }));

        let mut clean = report();
        clean
            .notes
            .push("corpus sample labelled spam is not scored in M1".into());
        assert!(matches!(decide(&clean), Verdict::Deliver));
    }

    #[test]
    fn malware_and_unreachable_engine_take_priority() {
        let mut infected = report();
        infected.malware = true;
        assert!(matches!(decide(&infected), Verdict::Quarantine { reason } if reason == "malware"));
        let mut deferred = report();
        deferred.defer = true;
        assert!(matches!(decide(&deferred), Verdict::Defer { .. }));
        let mut both = report();
        both.defer = true;
        both.malware = true;
        assert!(matches!(decide(&both), Verdict::Quarantine { .. }));
    }

    #[test]
    fn dlp_review_and_incomplete_scans_are_held() {
        use currawong_core::{DlpKind, DlpReport};
        let mut found = report();
        found.dlp = Some(DlpReport::default());
        assert!(matches!(decide(&found), Verdict::Deliver));
        let dlp = found.dlp.as_mut().unwrap();
        dlp.counts.insert(DlpKind::Tfn, 5);
        assert!(matches!(decide(&found), Verdict::Deliver));
        found.dlp.as_mut().unwrap().review = vec![DlpKind::Tfn];
        assert!(
            matches!(decide(&found), Verdict::Quarantine { reason } if reason == "dlp review: tfn x5")
        );
        let mut partial = report();
        partial.dlp = Some(DlpReport {
            incomplete: true,
            ..DlpReport::default()
        });
        assert!(
            matches!(decide(&partial), Verdict::Quarantine { reason } if reason == "dlp review: scan incomplete")
        );
    }
}
