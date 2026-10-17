//! Every entry in `testdata/corpus/expected.toml` goes through SMTP and the
//! daemon's scan pipeline, and must get the verdict the file records.
use currawong_testkit::{eicar, eicar_message, send_eml, spawn_fake_clamd, spawn_gateway};
use std::path::PathBuf;

fn corpus_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/corpus")
}

#[tokio::test]
async fn corpus_verdicts_match_expected_toml() {
    let dir = corpus_dir();
    let expected: toml::Table = std::fs::read_to_string(dir.join("expected.toml"))
        .unwrap()
        .parse()
        .unwrap();
    assert!(expected.len() >= 6, "{expected:?}");
    let clamd = spawn_fake_clamd().await;
    for (name, entry) in &expected {
        let file = entry["file"].as_str().unwrap();
        let verdict = entry["verdict"].as_str().unwrap();
        let eml = if name == "eicar" {
            eicar_message()
        } else {
            std::fs::read(dir.join(file)).unwrap_or_else(|err| panic!("{file}: {err}"))
        };
        let gateway = spawn_gateway(|cfg| {
            cfg.scanner.clamd.address = format!("tcp:{clamd}");
        })
        .await;
        let result = send_eml(
            gateway.addr,
            "sender@outside.test",
            &["b@example.test"],
            &eml,
        )
        .await;
        assert_eq!(result.code, 250, "{name}: {result:?}");
        gateway.run_pipeline().await.unwrap();
        assert_eq!(gateway.outcomes().await, [verdict], "{name}");
        let reasons = gateway.quarantine_reasons().await;
        match entry.get("reason").and_then(|reason| reason.as_str()) {
            Some(reason) => assert!(
                reasons.len() == 1 && reasons[0].contains(reason),
                "{name}: wanted reason {reason}, got {reasons:?}"
            ),
            None => assert!(reasons.is_empty(), "{name}: {reasons:?}"),
        }
    }
}

#[tokio::test]
async fn dropping_the_gateway_stops_the_server() {
    let gateway = spawn_gateway(|_| {}).await;
    let addr = gateway.addr;
    drop(gateway);
    let mut refused = false;
    for _ in 0..50 {
        if tokio::net::TcpStream::connect(addr).await.is_err() {
            refused = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(refused, "server still accepting on {addr}");
}

#[test]
fn eicar_is_built_at_run_time_and_not_stored() {
    let sample = eicar();
    assert_eq!(sample.len(), 68);
    assert!(sample.starts_with(b"X5O!P%@AP"));
    let source = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/src/lib.rs")).unwrap();
    assert!(!source.windows(sample.len()).any(|w| w == &sample[..]));
    for entry in std::fs::read_dir(corpus_dir()).unwrap() {
        let bytes = std::fs::read(entry.unwrap().path()).unwrap();
        assert!(!bytes.windows(sample.len()).any(|w| w == &sample[..]));
    }
}
