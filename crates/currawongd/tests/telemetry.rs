use currawong_auth::AuthChecker;
use currawong_core::{
    config::{Config, LogConfig},
    telemetry::{metrics_body, subscriber, ReadinessCheck},
    Direction,
};
use currawong_spool::{Envelope, Spool, SpoolState};
use currawongd::{record_spool_depth, Pipeline, SpoolWritable};
use std::{
    io::{self, Cursor, Write},
    sync::{Arc, Mutex},
};
use time::OffsetDateTime;
use tracing_subscriber::fmt::MakeWriter;

#[derive(Clone)]
struct MemWriter(Arc<Mutex<Vec<u8>>>);

impl Write for MemWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for MemWriter {
    type Writer = MemWriter;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

fn envelope(id: &str) -> Envelope {
    Envelope {
        id: currawong_core::MessageId(id.into()),
        tenant_id: None,
        authenticated_as: None,
        mail_from: "user@example.test".into(),
        rcpt_to: vec!["dest@example.test".into()],
        received_at: OffsetDateTime::now_utc(),
        remote_ip: "203.0.113.8".parse().unwrap(),
        helo: "client.example.test".into(),
        attempts: 0,
        next_attempt_at: None,
        state: SpoolState::Incoming,
        direction: Direction::Inbound,
        tls_version: None,
        tls_cipher: None,
        rcpt_status: Vec::new(),
        prepend_headers: Vec::new(),
        dsn_sent: false,
        tls: Default::default(),
        pipeline: "pending".into(),
    }
}

const MESSAGE: &[u8] =
    b"From: user@example.test\r\nTo: dest@example.test\r\nSubject: hi\r\n\r\nhello\r\n";

#[tokio::test]
async fn evaluation_logs_carry_the_message_id_span_and_scan_time_is_recorded() {
    let _ = metrics_body();
    let buf = MemWriter(Arc::new(Mutex::new(Vec::new())));
    let log = LogConfig {
        format: "json".into(),
        level: "info".into(),
    };
    let _default = tracing::subscriber::set_default(subscriber(&log, None, buf.clone()));
    let mut cfg = Config::default();
    cfg.scanner.clamd.address.clear();
    cfg.scanner.worker_binary = None;
    let auth = AuthChecker::offline("currawong.example.test").unwrap();
    let mut pipeline = Pipeline::new(Arc::new(cfg), auth);
    let env = envelope("01ARZ3NDEKTSV4RRFFQ69G5FAV");
    pipeline.evaluate(&env, MESSAGE, None).await;
    let text = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
    let evaluated = text
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("json line"))
        .find(|value| value["fields"]["message"] == "message evaluated")
        .unwrap_or_else(|| panic!("no evaluation line in:\n{text}"));
    assert_eq!(
        evaluated["span"]["message_id"], "01ARZ3NDEKTSV4RRFFQ69G5FAV",
        "{evaluated}"
    );
    let body = metrics_body();
    assert!(
        body.contains("currawong_scan_duration_seconds_count"),
        "{body}"
    );
}

#[tokio::test]
async fn spool_depth_gauge_counts_waiting_messages() {
    let dir = tempfile::tempdir().unwrap();
    let spool = Spool::open(dir.path().join("spool")).await.unwrap();
    for id in ["01ARZ3NDEKTSV4RRFFQ69G5FA1", "01ARZ3NDEKTSV4RRFFQ69G5FA2"] {
        spool
            .accept(envelope(id), Cursor::new(MESSAGE.to_vec()))
            .await
            .unwrap();
    }
    let _ = metrics_body();
    assert_eq!(record_spool_depth(&spool).await.unwrap(), 2);
    let body = metrics_body();
    assert!(
        body.lines().any(|line| line == "currawong_spool_depth 2"),
        "{body}"
    );
}

#[tokio::test]
async fn concurrent_spool_probes_do_not_race() {
    let dir = tempfile::tempdir().unwrap();
    let check = Arc::new(SpoolWritable {
        dir: dir.path().to_path_buf(),
    });
    let mut set = tokio::task::JoinSet::new();
    for _ in 0..64 {
        let check = Arc::clone(&check);
        set.spawn(async move { check.check().await });
    }
    while let Some(result) = set.join_next().await {
        result.unwrap().unwrap();
    }
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}

#[tokio::test]
async fn a_timed_out_spool_probe_leaves_no_file() {
    let dir = tempfile::tempdir().unwrap();
    let check = SpoolWritable {
        dir: dir.path().to_path_buf(),
    };
    for _ in 0..32 {
        let _ = tokio::time::timeout(std::time::Duration::ZERO, check.check()).await;
    }
    // Let the blocking jobs finish.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}
