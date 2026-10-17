//! YARA engine: starter rules, broken files, hot reload and worker matching.
use currawong_core::config::ExtractLimits;
use currawong_core::YaraMatch;
use currawong_parser::parse::parse_bytes_with;
use currawong_parser::yara::YaraScan;
use currawong_scan::engines::yara::{compile_dir, result_for};
use currawong_scan::pool::{worker_binary_from_exe, ScanOutcome, WorkerPool};
use currawong_scan::{eicar, EngineResult, ScanItem, Scanner, YaraEngine};
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const MARKER_RULE: &str =
    "rule Marker : malware { strings: $a = \"currawong-yara-marker\" condition: $a }";
const SECOND_RULE: &str =
    "rule Second : suspicious { strings: $a = \"currawong-second-marker\" condition: $a }";

fn starter_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../rules/yara")
}

fn fires(engine: &YaraEngine, bytes: &[u8]) -> bool {
    let compiled = engine.current();
    let mut scan = YaraScan::new(&compiled.rules);
    scan.scan("test", bytes);
    !scan.matches.is_empty()
}

fn lnk() -> Vec<u8> {
    let mut bytes = vec![0u8; 76];
    bytes[0] = 0x4c;
    bytes[4] = 0x01;
    bytes[5] = 0x14;
    bytes[6] = 0x02;
    bytes
}

#[tokio::test]
async fn yara_starter_rules_fire_on_their_fixtures() {
    compile_dir(&starter_dir()).expect("starter rules compile");
    let engine = YaraEngine::new(starter_dir()).unwrap();
    let scan = |name: &'static str, bytes: Vec<u8>| {
        let engine = &engine;
        async move {
            engine
                .scan(&ScanItem {
                    name,
                    bytes: &bytes,
                })
                .await
        }
    };

    let hit = scan("eicar.com", eicar().to_vec()).await;
    assert!(
        matches!(&hit, EngineResult::Malware { signature } if signature.contains("Currawong_EICAR_Test_File")),
        "{hit:?}"
    );
    let smuggling = b"<html><script>var d = atob('QUJD'); var b = new Blob([d]); navigator.msSaveOrOpenBlob(b, 'a.iso');</script></html>";
    let hit = scan("a.html", smuggling.to_vec()).await;
    assert!(matches!(hit, EngineResult::Suspicious { .. }), "{hit:?}");
    let powershell = b"cmd /c powershell -nop -enc SGVsbG8gZnJvbSBDdXJyYXdvbmcgdGVzdHMgb25seQ==";
    let hit = scan("run.bat", powershell.to_vec()).await;
    assert!(matches!(hit, EngineResult::Suspicious { .. }), "{hit:?}");
    let hit = scan("invite.lnk", lnk()).await;
    assert!(matches!(hit, EngineResult::Suspicious { .. }), "{hit:?}");

    // Reported for policy, not quarantined by the engine.
    let compiled = engine.current();
    let mut bec = YaraScan::new(&compiled.rules);
    bec.scan(
        "body",
        b"Please note our change of bank details. BSB 000-000, account 0000 0000.",
    );
    assert_eq!(bec.matches.len(), 1, "{:?}", bec.matches);
    assert_eq!(bec.matches[0].rule, "Currawong_Bank_Detail_Change");
    assert_eq!(bec.matches[0].tags, vec!["bec".to_string()]);
    assert_eq!(result_for(&bec.matches), EngineResult::Clean);

    let clean = scan("note.txt", b"hello from the gateway".to_vec()).await;
    assert_eq!(clean, EngineResult::Clean);
}

#[derive(Clone, Default)]
struct Logs(Arc<Mutex<Vec<u8>>>);

impl Write for Logs {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Logs {
    type Writer = Logs;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

#[test]
fn yara_broken_rule_file_is_logged_and_old_rules_stay_active() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("good.yar"), MARKER_RULE).unwrap();
    let engine = YaraEngine::new(dir.path()).unwrap();
    assert!(fires(&engine, b"xx currawong-yara-marker xx"));

    std::fs::write(dir.path().join("broken.yar"), "rule Broken { condition: }").unwrap();
    let logs = Logs::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(logs.clone())
        .with_ansi(false)
        .finish();
    let err = tracing::subscriber::with_default(subscriber, || engine.reload()).unwrap_err();
    assert!(err.contains("broken.yar"), "{err}");
    let logged = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    assert!(logged.contains("ERROR"), "{logged}");
    assert!(logged.contains("previous rules stay active"), "{logged}");
    assert!(logged.contains("broken.yar"), "{logged}");

    assert_eq!(engine.current().generation, 0);
    assert!(fires(&engine, b"xx currawong-yara-marker xx"));

    std::fs::write(dir.path().join("broken.yar"), SECOND_RULE).unwrap();
    assert_eq!(engine.reload().unwrap(), 1);
    assert!(fires(&engine, b"currawong-second-marker"));
    assert!(fires(&engine, b"currawong-yara-marker"));
}

#[test]
fn yara_rule_change_is_picked_up_without_restart() {
    let dir = tempfile::tempdir().unwrap();
    let engine = Arc::new(YaraEngine::new(dir.path()).unwrap());
    let _watch = engine.watch().unwrap();
    assert!(!fires(&engine, b"currawong-yara-marker"));
    let path = dir.path().join("hot.yar");
    std::fs::write(&path, MARKER_RULE).unwrap();
    let start = Instant::now();
    while !fires(&engine, b"currawong-yara-marker") {
        assert!(
            start.elapsed() < Duration::from_secs(20),
            "rule change not picked up"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(engine.current().generation >= 1);
}

fn limits() -> ExtractLimits {
    ExtractLimits {
        max_depth: 3,
        max_uncompressed_bytes: 1024 * 1024,
        max_files: 16,
        max_ratio: 100,
    }
}

fn base64(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (b[0] as u32) << 16 | (b[1] as u32) << 8 | b[2] as u32;
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(TABLE[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// EICAR as a base64 attachment and a shortcut inside a zip, so neither can
/// match the raw message: only part and archive-member matching finds them.
fn message() -> Vec<u8> {
    let mut cursor = std::io::Cursor::new(Vec::new());
    {
        let mut zip = zip::ZipWriter::new(&mut cursor);
        zip.start_file("invite.lnk", zip::write::SimpleFileOptions::default())
            .unwrap();
        zip.write_all(&lnk()).unwrap();
        zip.finish().unwrap();
    }
    let archive = cursor.into_inner();
    format!(
        "From: a@example.test\r\nTo: b@example.test\r\nSubject: parts\r\nMIME-Version: 1.0\r\n\
Content-Type: multipart/mixed; boundary=\"b1\"\r\n\r\n\
--b1\r\nContent-Type: text/plain\r\n\r\nSee attached.\r\n\
--b1\r\nContent-Type: application/octet-stream; name=\"eicar.com\"\r\n\
Content-Disposition: attachment; filename=\"eicar.com\"\r\nContent-Transfer-Encoding: base64\r\n\r\n{}\r\n\
--b1\r\nContent-Type: application/zip; name=\"invite.zip\"\r\n\
Content-Disposition: attachment; filename=\"invite.zip\"\r\nContent-Transfer-Encoding: base64\r\n\r\n{}\r\n\
--b1--\r\n",
        base64(eicar()),
        base64(&archive)
    )
    .into_bytes()
}

fn assert_parts_matched(matches: &[YaraMatch]) {
    assert!(
        matches
            .iter()
            .any(|hit| hit.rule == "Currawong_EICAR_Test_File" && hit.part == "eicar.com"),
        "{matches:?}"
    );
    assert!(
        matches
            .iter()
            .any(|hit| hit.rule == "Currawong_Windows_Shortcut" && hit.part == "invite.lnk"),
        "{matches:?}"
    );
    assert!(
        !matches.iter().any(|hit| hit.part == "message"),
        "{matches:?}"
    );
    assert!(matches!(result_for(matches), EngineResult::Malware { .. }));
}

#[tokio::test]
async fn yara_matches_every_part_and_archive_member_in_the_worker() {
    let engine = YaraEngine::new(starter_dir()).unwrap();
    let compiled = engine.current();
    let raw = message();

    let parsed = parse_bytes_with("in-process", &raw, &limits(), Some(&compiled.rules));
    assert_eq!(parsed.error, None);
    assert_parts_matched(&parsed.yara);

    let Some(bin) = worker_binary_from_exe().or_else(|| {
        let candidate = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/debug/currawong-parser-worker");
        candidate.is_file().then_some(candidate)
    }) else {
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("msg.eml");
    std::fs::write(&path, &raw).unwrap();
    let mut pool = WorkerPool::new(bin, 10, 500);
    let outcome = pool
        .scan_file_with_rules("worker", &path, &limits(), Some(compiled.path()))
        .await;
    let ScanOutcome::Parsed(response) = outcome else {
        panic!("{outcome:?}");
    };
    assert_parts_matched(&response.yara);

    let plain = pool.scan_file("no-rules", &path, &limits()).await;
    let ScanOutcome::Parsed(response) = plain else {
        panic!("{plain:?}");
    };
    assert!(response.yara.is_empty());
}
