//! The `currawong.event.v1` event schema. Field meanings are in `docs/events.md`.
use currawong_core::{Direction, MessageId, Verdict};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

pub const SCHEMA: &str = "currawong.event.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    pub schema: String,
    /// ULID, unique per event.
    pub id: String,
    #[serde(with = "time::serde::rfc3339")]
    pub time: OffsetDateTime,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    #[serde(flatten)]
    pub kind: EventKind,
}

/// One event, tagged by `type`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EventKind {
    MessageVerdict {
        message_id: String,
        /// `inbound` or `outbound`.
        direction: String,
        mail_from: String,
        rcpt_to: Vec<String>,
        /// `deliver`, `quarantine`, `reject`, `discard` or `defer`.
        verdict: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    UrlClick {
        message_id: String,
        recipient: String,
        url: String,
        #[serde(default)]
        verdict: String,
        #[serde(default)]
        reasons: Vec<String>,
        #[serde(default)]
        final_url: String,
        /// `allowed`, `warned` or `blocked`.
        action: String,
    },
    QuarantineRelease {
        message_id: String,
        released_by: String,
        rcpt_to: Vec<String>,
    },
    AdminAction {
        actor: String,
        action: String,
        target: String,
    },
    VerdictChanged {
        message_id: String,
        from: String,
        to: String,
        changed_by: String,
    },
}

impl Event {
    pub fn new(tenant_id: Option<&str>, kind: EventKind) -> Self {
        Self {
            schema: SCHEMA.into(),
            id: ulid::Ulid::new().to_string(),
            time: OffsetDateTime::now_utc(),
            tenant_id: tenant_id.map(str::to_string),
            kind,
        }
    }

    /// The event for a verdict the scheduler has just applied.
    pub fn message_verdict(
        tenant_id: Option<&str>,
        message_id: &MessageId,
        direction: Direction,
        mail_from: &str,
        rcpt_to: &[String],
        verdict: &Verdict,
    ) -> Self {
        let (name, reason) = verdict_parts(verdict);
        Self::new(
            tenant_id,
            EventKind::MessageVerdict {
                message_id: message_id.to_string(),
                direction: match direction {
                    Direction::Inbound => "inbound",
                    Direction::Outbound => "outbound",
                }
                .into(),
                mail_from: mail_from.into(),
                rcpt_to: rcpt_to.to_vec(),
                verdict: name.into(),
                reason,
            },
        )
    }

    pub fn type_name(&self) -> &'static str {
        match self.kind {
            EventKind::MessageVerdict { .. } => "message_verdict",
            EventKind::UrlClick { .. } => "url_click",
            EventKind::QuarantineRelease { .. } => "quarantine_release",
            EventKind::AdminAction { .. } => "admin_action",
            EventKind::VerdictChanged { .. } => "verdict_changed",
        }
    }

    /// CEF severity, 0 to 10. Syslog severity is derived from it.
    pub fn severity(&self) -> u8 {
        match &self.kind {
            EventKind::MessageVerdict { verdict, .. } => match verdict.as_str() {
                "deliver" => 1,
                "defer" => 3,
                "discard" => 5,
                "quarantine" => 7,
                "reject" => 8,
                _ => 5,
            },
            EventKind::UrlClick { action, .. } if action == "blocked" => 7,
            EventKind::UrlClick { .. } => 3,
            EventKind::QuarantineRelease { .. } | EventKind::VerdictChanged { .. } => 5,
            EventKind::AdminAction { .. } => 3,
        }
    }

    pub fn unix_millis(&self) -> i128 {
        self.time.unix_timestamp_nanos() / 1_000_000
    }
}

fn verdict_parts(verdict: &Verdict) -> (&'static str, Option<String>) {
    match verdict {
        Verdict::Deliver => ("deliver", None),
        Verdict::Quarantine { reason } => ("quarantine", Some(reason.clone())),
        Verdict::Reject { reason, .. } => ("reject", Some(reason.clone())),
        Verdict::Discard => ("discard", None),
        Verdict::Defer { reason } => ("defer", Some(reason.clone())),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Fixed events for golden files. Addresses use reserved example domains.
    pub fn samples() -> Vec<Event> {
        let at = |secs| OffsetDateTime::from_unix_timestamp(secs).unwrap();
        let mk = |id: &str, secs, kind| Event {
            schema: SCHEMA.into(),
            id: id.into(),
            time: at(secs),
            tenant_id: Some("tenant-a".into()),
            kind,
        };
        vec![
            mk(
                "01JA0000000000000000000001",
                1_792_195_200,
                EventKind::MessageVerdict {
                    message_id: "01JA00000000000000000000M1".into(),
                    direction: "inbound".into(),
                    mail_from: "billing@example.net".into(),
                    rcpt_to: vec!["ap@example.com.au".into(), "cfo@example.com.au".into()],
                    verdict: "quarantine".into(),
                    reason: Some("malware=Eicar|Test\\Sig a=b\nnext".into()),
                },
            ),
            mk(
                "01JA0000000000000000000002",
                1_792_195_260,
                EventKind::UrlClick {
                    message_id: "01JA00000000000000000000M1".into(),
                    recipient: "ap@example.com.au".into(),
                    url: "https://login.example.net/a?b=c|d".into(),
                    action: "blocked".into(),
                    verdict: "blocked".into(),
                    reasons: vec!["listed threat".into()],
                    final_url: "https://login.example.net/a?b=c|d".into(),
                },
            ),
            mk(
                "01JA0000000000000000000003",
                1_792_195_320,
                EventKind::QuarantineRelease {
                    message_id: "01JA00000000000000000000M1".into(),
                    released_by: "admin@example.com.au".into(),
                    rcpt_to: vec!["ap@example.com.au".into()],
                },
            ),
            mk(
                "01JA0000000000000000000004",
                1_792_195_380,
                EventKind::AdminAction {
                    actor: "admin@example.com.au".into(),
                    action: "policy.update".into(),
                    target: "domain=example.com.au".into(),
                },
            ),
            mk(
                "01JA0000000000000000000005",
                1_792_195_440,
                EventKind::VerdictChanged {
                    message_id: "01JA00000000000000000000M1".into(),
                    from: "quarantine".into(),
                    to: "deliver".into(),
                    changed_by: "admin@example.com.au".into(),
                },
            ),
        ]
    }

    #[test]
    fn events_are_tagged_by_type_and_round_trip() {
        for event in samples() {
            let json = serde_json::to_value(&event).unwrap();
            assert_eq!(json["type"], event.type_name());
            assert_eq!(json["schema"], SCHEMA);
            let back: Event = serde_json::from_value(json).unwrap();
            assert_eq!(back, event);
        }
    }

    #[test]
    fn verdict_event_carries_the_applied_verdict() {
        let event = Event::message_verdict(
            None,
            &MessageId("m1".into()),
            Direction::Outbound,
            "a@example.com.au",
            &["b@example.net".into()],
            &Verdict::Reject {
                code: 550,
                reason: "dlp".into(),
            },
        );
        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["type"], "message_verdict");
        assert_eq!(json["verdict"], "reject");
        assert_eq!(json["direction"], "outbound");
        assert_eq!(json["reason"], "dlp");
        assert!(json.get("tenant_id").is_none());
    }
}
