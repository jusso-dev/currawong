//! YARA engine: starter rules, broken files, hot reload and worker matching.
use currawong_core::config::ExtractLimits;
use currawong_core::YaraMatch;
use currawong_parser::parse::parse_bytes_with;
use currawong_parser::yara::{clean_name, YaraBudget, YaraScan};
use currawong_scan::engines::yara::{compile_dir, result_for};
use currawong_scan::pool::{ScanOutcome, WorkerPool};
use currawong_scan::{eicar, EngineResult, YaraEngine};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const MARKER_RULE: &str =
    "rule Marker : malware { strings: $a = \"currawong-yara-marker\" condition: $a }";
const SECOND_RULE: &str =
    "rule Second : suspicious { strings: $a = \"currawong-second-marker\" condition: $a }";

fn starter_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../rules/yara")
}

fn matches(engine: &YaraEngine, bytes: &[u8]) -> Vec<YaraMatch> {
    let compiled = engine.current();
    let mut scan = YaraScan::new(&compiled.rules);
    scan.scan("test", bytes);
    assert_eq!(scan.error, None);
    scan.matches
}

fn compile_err(dir: &Path) -> String {
    match compile_dir(dir) {
        Ok(_) => panic!("rules in {} compiled", dir.display()),
        Err(err) => err,
    }
}

fn fires(engine: &YaraEngine, bytes: &[u8]) -> bool {
    !matches(engine, bytes).is_empty()
}

fn lnk() -> Vec<u8> {
    let mut bytes = vec![0u8; 76];
    bytes[0] = 0x4c;
    bytes[4] = 0x01;
    bytes[5] = 0x14;
    bytes[6] = 0x02;
    bytes
}

/// The worker binary in this workspace's target directory. `cargo test
/// --workspace` builds it; on its own run `cargo build -p
/// currawong-parser-worker` first. A missing or stale binary fails the test.
fn worker_binary() -> PathBuf {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let target = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join("target"));
    let bin = target.join("debug/currawong-parser-worker");
    let built = std::fs::metadata(&bin).and_then(|m| m.modified());
    let newest_source = std::fs::read_dir(root.join("crates/parser-worker/src"))
        .unwrap()
        .filter_map(|entry| entry.ok()?.metadata().ok()?.modified().ok())
        .max()
        .unwrap();
    assert!(
        matches!(&built, Ok(built) if *built >= newest_source),
        "parser worker missing or stale at {}: run `cargo build -p currawong-parser-worker`",
        bin.display()
    );
    bin
}

#[test]
fn yara_starter_rules_fire_on_their_fixtures() {
    let (_, summary) = compile_dir(&starter_dir()).expect("starter rules compile");
    assert_eq!(summary.rules, 5, "{summary}");
    let engine = YaraEngine::new(starter_dir()).unwrap();
    let result = |bytes: &[u8]| result_for(&matches(&engine, bytes));

    let hit = result(eicar());
    assert!(
        matches!(&hit, EngineResult::Malware { signature } if signature.contains("Currawong_EICAR_Test_File")),
        "{hit:?}"
    );
    let smuggling = b"<html><script>var d = atob('QUJD'); var b = new Blob([d]); navigator.msSaveOrOpenBlob(b, 'a.iso');</script></html>";
    assert!(matches!(result(smuggling), EngineResult::Suspicious { .. }));
    let powershell = b"cmd /c powershell -nop -enc SGVsbG8gZnJvbSBDdXJyYXdvbmcgdGVzdHMgb25seQ==";
    assert!(matches!(
        result(powershell),
        EngineResult::Suspicious { .. }
    ));
    assert!(matches!(result(&lnk()), EngineResult::Suspicious { .. }));

    // Reported for policy, not quarantined by the engine.
    let bec = matches(
        &engine,
        b"Please note our change of bank details. BSB 000-000, account 0000 0000.",
    );
    assert_eq!(bec.len(), 1, "{bec:?}");
    assert_eq!(bec[0].rule, "Currawong_Bank_Detail_Change");
    assert_eq!(bec[0].tags, vec!["bec".to_string()]);
    assert_eq!(result_for(&bec), EngineResult::Clean);

    assert_eq!(result(b"hello from the gateway"), EngineResult::Clean);
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

/// One global subscriber for the test binary. Scoped subscribers miss events
/// whose callsite interest another thread cached first. Returns the log
/// lines that mention `dir`.
fn capture<T>(dir: &Path, f: impl FnOnce() -> T) -> (T, String) {
    static LOGS: std::sync::OnceLock<Logs> = std::sync::OnceLock::new();
    let logs = LOGS.get_or_init(|| {
        let logs = Logs::default();
        tracing_subscriber::fmt()
            .with_writer(logs.clone())
            .with_ansi(false)
            .init();
        logs
    });
    let out = f();
    let text = String::from_utf8_lossy(&logs.0.lock().unwrap()).into_owned();
    let dir = dir.display().to_string();
    let lines: Vec<&str> = text.lines().filter(|line| line.contains(&dir)).collect();
    (out, lines.join("\n"))
}

#[test]
fn yara_broken_rule_file_is_logged_and_old_rules_stay_active() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("good.yar"), MARKER_RULE).unwrap();
    let engine = YaraEngine::new(dir.path()).unwrap();
    assert!(fires(&engine, b"xx currawong-yara-marker xx"));

    std::fs::write(dir.path().join("broken.yar"), "rule Broken { condition: }").unwrap();
    let (result, logged) = capture(dir.path(), || engine.reload());
    let err = result.unwrap_err();
    assert!(err.contains("broken.yar"), "{err}");
    assert!(logged.contains("ERROR"), "{logged}");
    assert!(logged.contains("previous rules stay active"), "{logged}");
    assert!(logged.contains("broken.yar"), "{logged}");

    assert_eq!(engine.current().generation, 0);
    assert!(fires(&engine, b"xx currawong-yara-marker xx"));

    std::fs::write(dir.path().join("broken.yar"), SECOND_RULE).unwrap();
    let (generation, logged) = capture(dir.path(), || engine.reload().unwrap());
    assert_eq!(generation, 1);
    assert!(logged.contains("2 rules from 2 files"), "{logged}");
    assert!(logged.contains("malware=1"), "{logged}");
    assert!(fires(&engine, b"currawong-second-marker"));
    assert!(fires(&engine, b"currawong-yara-marker"));
}

#[test]
fn yara_broken_rules_at_startup_are_an_error_not_an_empty_set() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("broken.yar"), "rule Broken { condition: }").unwrap();
    let err = YaraEngine::new(dir.path())
        .err()
        .expect("broken rules rejected");
    assert!(err.contains("broken.yar"), "{err}");
    assert!(YaraEngine::new(dir.path().join("missing")).is_err());
}

#[test]
fn yara_emptied_directory_keeps_the_active_rules() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("good.yar");
    std::fs::write(&path, MARKER_RULE).unwrap();
    let engine = YaraEngine::new(dir.path()).unwrap();
    std::fs::remove_file(&path).unwrap();
    let err = engine.reload().unwrap_err();
    assert!(err.contains("keeping 1 active rules"), "{err}");
    assert!(fires(&engine, b"currawong-yara-marker"));
}

#[test]
fn yara_rule_files_in_any_case_and_subdirectories_are_loaded() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("community/apt")).unwrap();
    std::fs::create_dir_all(dir.path().join(".staging")).unwrap();
    std::fs::write(dir.path().join("UPPER.YAR"), MARKER_RULE).unwrap();
    std::fs::write(dir.path().join("community/apt/second.Yara"), SECOND_RULE).unwrap();
    std::fs::write(dir.path().join(".staging/half.yar"), "rule Half {").unwrap();
    std::fs::write(dir.path().join("notes.txt"), "not a rule").unwrap();
    let engine = YaraEngine::new(dir.path()).unwrap();
    assert_eq!(engine.current().summary.files, 2);
    assert!(fires(&engine, b"currawong-yara-marker"));
    let hit = matches(&engine, b"currawong-second-marker");
    assert_eq!(hit[0].namespace, "community/apt/second");
}

#[cfg(unix)]
#[test]
fn yara_unreadable_rule_entry_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("good.yar"), MARKER_RULE).unwrap();
    std::os::unix::fs::symlink(dir.path().join("gone.yar"), dir.path().join("link.yar")).unwrap();
    let err = compile_err(dir.path());
    assert!(err.contains("link.yar"), "{err}");
}

#[test]
fn yara_misspelt_action_tags_reject_the_set() {
    for tag in ["Malware", "malwre", "MALWARE", "Suspicious", "suspicous"] {
        let dir = tempfile::tempdir().unwrap();
        let rule = format!("rule Typo : {tag} {{ strings: $a = \"x1y2\" condition: $a }}");
        std::fs::write(dir.path().join("typo.yar"), rule).unwrap();
        let err = compile_err(dir.path());
        assert!(err.contains(tag), "{tag}: {err}");
    }
    let dir = tempfile::tempdir().unwrap();
    let rule = "rule Fine : bec malware { strings: $a = \"x1y2\" condition: $a }";
    std::fs::write(dir.path().join("fine.yar"), rule).unwrap();
    let (_, summary) = compile_dir(dir.path()).unwrap();
    assert_eq!(summary.tags.get("bec"), Some(&1));
    assert_eq!(summary.tags.get("malware"), Some(&1));
}

#[test]
fn yara_compiler_warnings_are_surfaced() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("warn.yar"),
        "rule NonBoolean { condition: \"text\" }",
    )
    .unwrap();
    let (_, summary) = compile_dir(dir.path()).unwrap();
    assert!(!summary.warnings.is_empty(), "{summary:?}");
    let (_, logged) = capture(dir.path(), || YaraEngine::new(dir.path()).unwrap());
    assert!(logged.contains("yara rule warning"), "{logged}");
}

#[test]
fn yara_budget_dedupe_and_part_names() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("good.yar"), MARKER_RULE).unwrap();
    let engine = YaraEngine::new(dir.path()).unwrap();
    let compiled = engine.current();

    // The same bytes under two names (an inline part listed twice) match once.
    let mut scan = YaraScan::new(&compiled.rules);
    scan.scan("a.txt", b"currawong-yara-marker");
    scan.scan("b.txt", b"currawong-yara-marker");
    assert_eq!(scan.matches.len(), 1, "{:?}", scan.matches);

    let tight = |budget: YaraBudget| {
        let mut scan = YaraScan::with_budget(&compiled.rules, budget);
        scan.scan("one", b"first part");
        scan.scan("two", b"second part");
        scan.error
    };
    let parts = tight(YaraBudget {
        max_parts: 1,
        ..YaraBudget::default()
    });
    assert!(parts.unwrap().contains("more than 1 parts"));
    let bytes = tight(YaraBudget {
        max_bytes: 12,
        ..YaraBudget::default()
    });
    assert!(bytes.unwrap().contains("more than 12 bytes"));
    let time = tight(YaraBudget {
        time: Duration::ZERO,
        ..YaraBudget::default()
    });
    assert!(time.unwrap().contains("yara limit exceeded"));

    let mut scan = YaraScan::new(&compiled.rules);
    let hostile = format!("evil\r\nX-Injected: 1\u{1b}[31m{}.txt", "a".repeat(400));
    scan.scan(&hostile, b"currawong-yara-marker");
    let part = &scan.matches[0].part;
    assert!(!part.chars().any(char::is_control), "{part:?}");
    assert_eq!(part.chars().count(), 128);
    assert_eq!(clean_name("ok.pdf"), "ok.pdf");
}

#[test]
fn yara_concurrent_reloads_store_generations_in_order() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("good.yar"), MARKER_RULE).unwrap();
    let engine = Arc::new(YaraEngine::new(dir.path()).unwrap());
    let threads: Vec<_> = (0..8)
        .map(|_| {
            let engine = Arc::clone(&engine);
            std::thread::spawn(move || engine.reload().unwrap())
        })
        .collect();
    let mut generations: Vec<u64> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    generations.sort();
    assert_eq!(generations, (1..=8).collect::<Vec<_>>());
    assert_eq!(engine.current().generation, 8);
}

#[test]
fn yara_rule_change_is_picked_up_without_restart() {
    let dir = tempfile::tempdir().unwrap();
    let engine = Arc::new(YaraEngine::new(dir.path()).unwrap());
    let _watch = engine.watch().unwrap();
    assert!(!fires(&engine, b"currawong-yara-marker"));
    std::fs::write(dir.path().join("hot.yar"), MARKER_RULE).unwrap();
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
    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, bytes)
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
--b1\r\nContent-Type: text/plain\r\n\r\nSee attached. currawong-second-marker\r\n\
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
        !matches
            .iter()
            .any(|hit| hit.part == "message" && hit.rule != "Second"),
        "{matches:?}"
    );
    assert!(matches!(result_for(matches), EngineResult::Malware { .. }));
}

fn copy_starter_rules(to: &Path) {
    for entry in std::fs::read_dir(starter_dir()).unwrap() {
        let path = entry.unwrap().path();
        std::fs::copy(&path, to.join(path.file_name().unwrap())).unwrap();
    }
}

#[tokio::test]
async fn yara_matches_every_part_and_archive_member_in_the_worker() {
    let rules_dir = tempfile::tempdir().unwrap();
    copy_starter_rules(rules_dir.path());
    let engine = YaraEngine::new(rules_dir.path()).unwrap();
    let compiled = engine.current();
    let raw = message();

    let parsed = parse_bytes_with("in-process", &raw, &limits(), Some(&compiled.rules));
    assert_eq!(parsed.error, None);
    assert_parts_matched(&parsed.yara);

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("msg.eml");
    std::fs::write(&path, &raw).unwrap();
    let pool = WorkerPool::new(worker_binary(), 10, 500).with_rules_load_timeout(60);
    let outcome = pool
        .scan_file_with_rules("worker", &path, &limits(), Some(&compiled))
        .await;
    let ScanOutcome::Parsed(response) = outcome else {
        panic!("{outcome:?}");
    };
    assert_parts_matched(&response.yara);
    assert!(!response.yara.iter().any(|hit| hit.rule == "Second"));

    // A new generation is sent to the same worker before the next job.
    std::fs::write(rules_dir.path().join("second.yar"), SECOND_RULE).unwrap();
    engine.reload().unwrap();
    let next = engine.current();
    let outcome = pool
        .scan_file_with_rules("worker-2", &path, &limits(), Some(&next))
        .await;
    let ScanOutcome::Parsed(response) = outcome else {
        panic!("{outcome:?}");
    };
    assert!(
        response.yara.iter().any(|hit| hit.rule == "Second"),
        "{:?}",
        response.yara
    );

    let plain = pool.scan_file("no-rules", &path, &limits()).await;
    let ScanOutcome::Parsed(response) = plain else {
        panic!("{plain:?}");
    };
    assert!(response.yara.is_empty());
}

/// Nested loops over every byte: cheap to write, slow on the Pulley
/// interpreter that rules run on (so the unit can keep
/// `MemoryDenyWriteExecute`). `uint8` never exceeds 255, so `all` never
/// short-circuits and every iteration runs.
const SLOW_RULE: &str = "rule Slow : malware { condition: \
    for all i in (0..filesize) : ( for all j in (0..1000) : ( uint8(i) != 256 + j ) ) }";

fn slow_rules() -> (tempfile::TempDir, YaraEngine) {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("slow.yar"), SLOW_RULE).unwrap();
    let engine = YaraEngine::new(dir.path()).unwrap();
    (dir, engine)
}

/// yara-x epoch interruption works under Pulley: the per-message budget
/// stops a loop-heavy condition on hostile input instead of running for
/// minutes. The heartbeat ticks once a second, so allow a few.
#[test]
fn yara_loop_heavy_rule_is_stopped_by_the_time_budget() {
    let (_dir, engine) = slow_rules();
    let compiled = engine.current();
    let hostile = vec![b'a'; 4 * 1024 * 1024];
    // The budget clock starts with the scanner; on a loaded machine a
    // one-second budget can run out before the scan starts.
    let mut scan = YaraScan::with_budget(
        &compiled.rules,
        YaraBudget {
            time: Duration::from_secs(3),
            ..YaraBudget::default()
        },
    );
    let start = Instant::now();
    scan.scan("hostile.bin", &hostile);
    let elapsed = start.elapsed();
    let err = scan.error.expect("the slow scan is interrupted");
    assert!(err.contains("hostile.bin"), "{err}");
    assert!(err.to_lowercase().contains("timeout"), "{err}");
    assert!(scan.matches.is_empty(), "{:?}", scan.matches);
    assert!(elapsed < Duration::from_secs(15), "took {elapsed:?}");
}

/// The worker's per-job timeout bounds the same rule end to end: the job
/// fails (the pipeline quarantines on `Failed`) and the worker is replaced.
#[tokio::test]
async fn yara_loop_heavy_rule_times_out_the_worker_job() {
    let (_rules, engine) = slow_rules();
    let compiled = engine.current();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("msg.eml");
    let mut raw = b"From: a@example.test\r\nTo: b@example.test\r\nSubject: slow\r\n\r\n".to_vec();
    raw.extend(std::iter::repeat_n(b'a', 4 * 1024 * 1024));
    std::fs::write(&path, &raw).unwrap();
    let pool = WorkerPool::new(worker_binary(), 2, 500).with_rules_load_timeout(60);
    let start = Instant::now();
    let outcome = pool
        .scan_file_with_rules("slow", &path, &limits(), Some(&compiled))
        .await;
    let elapsed = start.elapsed();
    let ScanOutcome::Failed { reason } = outcome else {
        panic!("{outcome:?}");
    };
    assert!(reason.contains("timed out"), "{reason}");
    assert!(elapsed < Duration::from_secs(30), "took {elapsed:?}");
}

/// Load cost for a large set. Run in release:
/// `cargo test --release -p currawong-scan --test yara -- --ignored --nocapture`
#[test]
#[ignore]
fn yara_large_rule_set_load_time() {
    let dir = tempfile::tempdir().unwrap();
    let mut source = String::new();
    for i in 0..5000 {
        source.push_str(&format!(
            "rule R{i} : suspicious {{ strings: $a = \"currawong-{i:05}-marker\" $b = {{ 4D 5A ?? ?? {:02X} }} condition: $a or ($b at 0 and filesize < 1MB) }}\n",
            i % 256
        ));
    }
    std::fs::write(dir.path().join("large.yar"), source).unwrap();
    let start = Instant::now();
    let engine = YaraEngine::new(dir.path()).unwrap();
    let compile = start.elapsed();
    let compiled = engine.current();
    let start = Instant::now();
    let mut cache = currawong_parser::yara::RulesCache::default();
    let reply = cache.load(&currawong_parser::LoadRules {
        generation: 0,
        yara_rules: compiled.encoded.clone(),
    });
    assert_eq!(reply.error, None);
    let load = start.elapsed();
    let rules = cache.get(0).unwrap();
    let start = Instant::now();
    let mut scan = YaraScan::new(rules);
    scan.scan("big", &vec![b'a'; 10 * 1024 * 1024]);
    let scan_time = start.elapsed();
    println!(
        "5000 rules: compile {compile:?}, serialised {} bytes (base64), worker load {load:?}, 10 MiB scan {scan_time:?}",
        compiled.encoded.len()
    );
}
