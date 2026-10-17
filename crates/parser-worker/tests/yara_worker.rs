//! The worker binary loads YARA rules from a stdin frame, never a path, and
//! refuses a job for a rules generation it has not loaded.
use base64::Engine as _;
use currawong_core::config::ExtractLimits;
use currawong_parser::{LoadRules, ParseRequest, ParseResponse};
use std::io::{Read, Write};
use std::process::{Child, Command, Stdio};

struct Worker(Child);

impl Worker {
    fn spawn() -> Self {
        let child = Command::new(env!("CARGO_BIN_EXE_currawong-parser-worker"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        Self(child)
    }

    fn send(&mut self, frame: &[u8]) -> ParseResponse {
        let stdin = self.0.stdin.as_mut().unwrap();
        stdin
            .write_all(&(frame.len() as u32).to_be_bytes())
            .unwrap();
        stdin.write_all(frame).unwrap();
        stdin.flush().unwrap();
        let stdout = self.0.stdout.as_mut().unwrap();
        let mut len = [0u8; 4];
        stdout.read_exact(&mut len).unwrap();
        let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
        stdout.read_exact(&mut body).unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    fn load(&mut self, generation: u64, yara_rules: String) -> ParseResponse {
        let frame = serde_json::to_vec(&LoadRules {
            generation,
            yara_rules,
        })
        .unwrap();
        self.send(&frame)
    }

    fn parse(&mut self, path: &std::path::Path, yara_generation: Option<u64>) -> ParseResponse {
        let frame = serde_json::to_vec(&ParseRequest {
            id: "job".into(),
            raw_path: path.to_path_buf(),
            limits: ExtractLimits::default(),
            yara_generation,
        })
        .unwrap();
        self.send(&frame)
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        let _ = self.0.kill();
    }
}

fn encoded(source: &str) -> String {
    let mut compiler = yara_x::Compiler::new();
    compiler.add_source(source).unwrap();
    let bytes = compiler.build().serialize().unwrap();
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

#[test]
fn yara_rules_load_over_stdin_and_the_generation_is_checked() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("msg.eml");
    std::fs::write(
        &path,
        b"From: a@example.test\r\nTo: b@example.test\r\nSubject: hi\r\n\r\ncurrawong-worker-marker\r\n",
    )
    .unwrap();
    let mut worker = Worker::spawn();

    let before = worker.parse(&path, Some(7));
    assert!(before.error.unwrap().contains("not loaded"));

    let rule = "rule W : malware { strings: $a = \"currawong-worker-marker\" condition: $a }";
    let loaded = worker.load(7, encoded(rule));
    assert_eq!(loaded.id, LoadRules::REPLY_ID);
    assert_eq!(loaded.error, None);

    let hit = worker.parse(&path, Some(7));
    assert_eq!(hit.error, None);
    assert!(hit.yara.iter().any(|m| m.rule == "W"), "{:?}", hit.yara);

    let stale = worker.parse(&path, Some(6));
    assert!(stale.error.unwrap().contains("generation 7 loaded"));

    let none = worker.parse(&path, None);
    assert_eq!(none.error, None);
    assert!(none.yara.is_empty());

    // Garbage is refused and drops the old rules rather than keeping them.
    let bad = worker.load(8, "bm90IHJ1bGVz".into());
    assert!(bad.error.is_some());
    assert!(worker.parse(&path, Some(7)).error.is_some());
}
