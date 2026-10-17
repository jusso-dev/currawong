//! The worker binary loads YARA rules from a stdin frame, never a path, and
//! refuses a job for a rules generation it has not loaded.
use base64::Engine as _;
use currawong_core::config::ExtractLimits;
use currawong_parser::{LoadRules, ParseRequest, ParseResponse};
use std::io::{Read, Write};
use std::process::{Child, Command, Stdio};

struct Worker {
    child: Child,
    /// The worker's stderr, shown if it dies mid-test.
    stderr: std::path::PathBuf,
}

impl Worker {
    /// Started as the pool starts it: in its own directory (Landlock on
    /// Linux allows only `in/` and `out/`), and ready before the first job.
    fn spawn(dir: &std::path::Path) -> Self {
        let stderr = dir.join("stderr");
        let child = Command::new(env!("CARGO_BIN_EXE_currawong-parser-worker"))
            .env_clear()
            .env("CURRAWONG_WORKER_DIR", dir)
            .env("RUST_BACKTRACE", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(std::fs::File::create(&stderr).unwrap())
            .spawn()
            .unwrap();
        let mut worker = Self { child, stderr };
        let ready = worker.read();
        assert_eq!(ready.id, "ready", "{ready:?}");
        worker
    }

    fn send(&mut self, frame: &[u8]) -> ParseResponse {
        let stdin = self.child.stdin.as_mut().unwrap();
        stdin
            .write_all(&(frame.len() as u32).to_be_bytes())
            .unwrap();
        stdin.write_all(frame).unwrap();
        stdin.flush().unwrap();
        self.read()
    }

    fn read(&mut self) -> ParseResponse {
        let stdout = self.child.stdout.as_mut().unwrap();
        let mut len = [0u8; 4];
        if let Err(err) = stdout.read_exact(&mut len) {
            let status = self.child.wait();
            let stderr = std::fs::read_to_string(&self.stderr).unwrap_or_default();
            panic!("worker gone ({err}), {status:?}:\n{stderr}");
        }
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
            out_dir: None,
            yara_generation,
        })
        .unwrap();
        self.send(&frame)
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        let _ = self.child.kill();
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
    for sub in ["in", "out"] {
        std::fs::create_dir(dir.path().join(sub)).unwrap();
    }
    let path = dir.path().join("in/msg.eml");
    std::fs::write(
        &path,
        b"From: a@example.test\r\nTo: b@example.test\r\nSubject: hi\r\n\r\ncurrawong-worker-marker\r\n",
    )
    .unwrap();
    let mut worker = Worker::spawn(dir.path());

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
