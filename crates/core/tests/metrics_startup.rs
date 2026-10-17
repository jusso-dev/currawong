//! Own process: nothing has incremented a counter yet.
use currawong_core::telemetry::{
    metrics_body, MESSAGES_ACCEPTED_TOTAL, MESSAGES_REJECTED_TOTAL, SMTP_CONNECTIONS_TOTAL,
    SPOOL_DEPTH,
};

#[test]
fn metrics_list_every_counter_before_the_first_connection() {
    let body = metrics_body();
    for name in [
        SMTP_CONNECTIONS_TOTAL,
        MESSAGES_ACCEPTED_TOTAL,
        MESSAGES_REJECTED_TOTAL,
        SPOOL_DEPTH,
    ] {
        assert!(
            body.lines()
                .any(|line| line.starts_with(&format!("{name} 0"))),
            "{name} missing from fresh /metrics:\n{body}"
        );
    }
}
