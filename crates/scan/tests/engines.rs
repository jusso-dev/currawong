use currawong_core::config::ExtractLimits;
use currawong_scan::clamav::{supplemental_paths_ready, ClamdAddress, ClamdClient};
use currawong_scan::combine::{combine, EngineOutput};
use currawong_scan::engines::{EngineResult, ScanItem};
use currawong_scan::pool::{worker_binary_from_exe, ScanOutcome, WorkerPool};
use currawong_scan::{eicar, Scanner};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// `cargo test --workspace` builds the worker binary. Running this crate's
/// tests alone needs `cargo build -p currawong-parser-worker` first.
fn worker_bin() -> PathBuf {
    worker_binary_from_exe()
        .or_else(|| {
            let candidate = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../target/debug/currawong-parser-worker");
            candidate.is_file().then_some(candidate)
        })
        .expect("parser worker binary: run cargo build -p currawong-parser-worker")
}

fn limits() -> ExtractLimits {
    ExtractLimits {
        max_depth: 3,
        max_uncompressed_bytes: 1024 * 1024,
        max_files: 64,
        max_ratio: 100,
    }
}

fn message_file(dir: &tempfile::TempDir, name: &str, raw: &[u8]) -> PathBuf {
    let path = dir.path().join(name);
    std::fs::write(&path, raw).unwrap();
    path
}

const PLAIN: &[u8] = b"From: a@example.test\r\nTo: b@example.test\r\nSubject: hi\r\n\r\nhello\r\n";

fn kill_9(pid: u32) {
    let status = std::process::Command::new("kill")
        .args(["-9", &pid.to_string()])
        .status()
        .unwrap();
    assert!(status.success());
}

#[tokio::test]
async fn clamav_fake_detects_eicar_and_clean_mail() {
    let addr = fake_clamd().await;
    let client = ClamdClient::new(ClamdAddress::Tcp(addr), true);
    client.ping().await.unwrap();
    let hit = client
        .scan(&ScanItem {
            name: "eicar.txt",
            bytes: eicar(),
        })
        .await;
    assert!(matches!(hit, EngineResult::Malware { .. }), "{hit:?}");
    let clean = client
        .scan(&ScanItem {
            name: "note.txt",
            bytes: b"hello",
        })
        .await;
    assert!(matches!(clean, EngineResult::Clean), "{clean:?}");
}

#[tokio::test]
async fn required_clamd_down_defers() {
    let client = ClamdClient::new(ClamdAddress::Tcp("127.0.0.1:1".parse().unwrap()), true);
    let result = client
        .scan(&ScanItem {
            name: "a",
            bytes: b"x",
        })
        .await;
    let combined = combine(
        &[EngineOutput {
            name: "clamav".into(),
            result,
            required: true,
        }],
        false,
    );
    assert!(combined.defer);
    assert!(!combined.malware);
}

/// Real clamd answers `INSTREAM size limit exceeded` and closes while the
/// client is still sending. That must fail closed, not look unreachable.
#[tokio::test]
async fn clamd_size_limit_reply_fails_closed() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 64 * 1024];
        let _ = sock.read(&mut buf).await;
        let _ = sock
            .write_all(b"INSTREAM size limit exceeded. ERROR\0")
            .await;
        drop(sock);
    });
    let client = ClamdClient::new(ClamdAddress::Tcp(addr), true);
    let body = vec![b'x'; 32 * 1024 * 1024];
    let result = client
        .scan(&ScanItem {
            name: "big.eml",
            bytes: &body,
        })
        .await;
    assert!(
        matches!(
            &result,
            EngineResult::Failed {
                unreachable: false,
                ..
            }
        ),
        "{result:?}"
    );
    let combined = combine(
        &[EngineOutput {
            name: "clamav".into(),
            result,
            required: true,
        }],
        false,
    );
    assert!(combined.fail_closed && !combined.defer, "{combined:?}");
}

#[tokio::test]
async fn stalled_clamd_times_out() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        // Accept and never read or reply.
        let (sock, _) = listener.accept().await.unwrap();
        tokio::time::sleep(Duration::from_secs(60)).await;
        drop(sock);
    });
    let client =
        ClamdClient::new(ClamdAddress::Tcp(addr), true).with_timeout(Duration::from_millis(500));
    let body = vec![b'x'; 16 * 1024 * 1024];
    let result = tokio::time::timeout(
        Duration::from_secs(10),
        client.scan(&ScanItem {
            name: "big.eml",
            bytes: &body,
        }),
    )
    .await
    .expect("scan hung on a stalled clamd");
    assert!(
        matches!(
            result,
            EngineResult::Failed {
                unreachable: true,
                ..
            }
        ),
        "{result:?}"
    );
}

#[tokio::test]
async fn clamd_reply_is_read_to_the_terminator() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut buf = Vec::new();
        let mut tmp = [0u8; 1024];
        while !buf.ends_with(&[0, 0, 0, 0]) {
            let n = sock.read(&mut tmp).await.unwrap();
            if n == 0 {
                return;
            }
            buf.extend_from_slice(&tmp[..n]);
        }
        sock.write_all(b"stream: Eicar-Test").await.unwrap();
        sock.flush().await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        sock.write_all(b"-Signature FOUND\0").await.unwrap();
    });
    let client = ClamdClient::new(ClamdAddress::Tcp(addr), true);
    let result = client
        .scan(&ScanItem {
            name: "a",
            bytes: b"x",
        })
        .await;
    assert_eq!(
        result,
        EngineResult::Malware {
            signature: "Eicar-Test-Signature".into()
        }
    );
}

/// The raw message holds the sample only inside a deflated zip, so clamd
/// sees it only when the worker's extracted member is sent as well.
#[tokio::test]
async fn extracted_parts_are_sent_to_clamd() {
    let mut cursor = std::io::Cursor::new(Vec::new());
    {
        let mut zip = zip::ZipWriter::new(&mut cursor);
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        zip.start_file("readme.txt", opts).unwrap();
        zip.write_all(eicar()).unwrap();
        zip.finish().unwrap();
    }
    let encoded = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        cursor.into_inner(),
    );
    let raw = format!(
        "From: a@example.test\r\nTo: b@example.test\r\nSubject: zip\r\nMIME-Version: 1.0\r\nContent-Type: application/zip; name=\"docs.zip\"\r\nContent-Disposition: attachment; filename=\"docs.zip\"\r\nContent-Transfer-Encoding: base64\r\n\r\n{encoded}\r\n"
    );
    let dir = tempfile::tempdir().unwrap();
    let path = message_file(&dir, "msg.eml", raw.as_bytes());
    let out = dir.path().join("parts");
    std::fs::create_dir(&out).unwrap();
    let pool = WorkerPool::new(worker_bin(), 30, 10);
    let ScanOutcome::Parsed(parsed) = pool.scan_file_into("1", &path, &limits(), Some(&out)).await
    else {
        panic!("worker failed");
    };
    let client = ClamdClient::new(ClamdAddress::Tcp(fake_clamd().await), true);
    let raw_only = client.scan_message(raw.as_bytes(), &[]).await;
    assert_eq!(raw_only, EngineResult::Clean);
    let with_parts = client.scan_message(raw.as_bytes(), &parsed.parts).await;
    assert!(
        matches!(with_parts, EngineResult::Malware { .. }),
        "{with_parts:?} {:?}",
        parsed.parts
    );
}

#[tokio::test]
async fn pool_crash_fails_closed_and_live_worker_parses() {
    let dir = tempfile::tempdir().unwrap();
    let path = message_file(&dir, "msg.eml", PLAIN);
    let crashed = WorkerPool::new("/usr/bin/false", 2, 10);
    let failed = crashed.scan_file("1", &path, &limits()).await;
    assert!(matches!(failed, ScanOutcome::Failed { .. }), "{failed:?}");

    let pool = WorkerPool::new(worker_bin(), 10, 500);
    let parsed = pool.scan_file("2", &path, &limits()).await;
    assert!(matches!(parsed, ScanOutcome::Parsed(_)), "{parsed:?}");
    pool.kill().await;
    let again = pool.scan_file("3", &path, &limits()).await;
    assert!(matches!(again, ScanOutcome::Parsed(_)), "{again:?}");
}

/// A worker that dies is replaced; one bad message does not fail later mail.
#[tokio::test]
async fn live_worker_crash_then_next_job_succeeds() {
    let dir = tempfile::tempdir().unwrap();
    let path = message_file(&dir, "msg.eml", PLAIN);
    let pool = WorkerPool::new(worker_bin(), 10, 500);
    let first = pool.scan_file("1", &path, &limits()).await;
    assert!(matches!(first, ScanOutcome::Parsed(_)), "{first:?}");
    let pids = pool.worker_pids();
    assert_eq!(pids.len(), 1);
    kill_9(pids[0]);
    tokio::time::sleep(Duration::from_millis(200)).await;
    for id in ["2", "3"] {
        let next = pool.scan_file(id, &path, &limits()).await;
        assert!(matches!(next, ScanOutcome::Parsed(_)), "{id}: {next:?}");
    }
    let replaced = pool.worker_pids();
    assert_eq!(replaced.len(), 1);
    assert_ne!(replaced[0], pids[0]);
}

/// A result too big for a frame fails that job and the worker stays up.
#[tokio::test]
async fn oversized_result_fails_the_job_not_the_worker() {
    let mut raw = String::from(
        "From: a@example.test\r\nTo: b@example.test\r\nSubject: many\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"b\"\r\n\r\n",
    );
    for i in 0..60_000 {
        raw.push_str(&format!("--b\r\nContent-Type: text/plain\r\n\r\n{i}\r\n"));
    }
    raw.push_str("--b--\r\n");
    let dir = tempfile::tempdir().unwrap();
    let big = message_file(&dir, "big.eml", raw.as_bytes());
    let small = message_file(&dir, "small.eml", PLAIN);
    let unbounded = ExtractLimits {
        max_files: u32::MAX,
        ..limits()
    };
    let pool = WorkerPool::new(worker_bin(), 60, 500);
    let first = pool.scan_file("big", &big, &unbounded).await;
    assert!(
        matches!(&first, ScanOutcome::Failed { reason } if reason.contains("frame limit")),
        "{first:?}"
    );
    let pid = pool.worker_pids();
    let next = pool.scan_file("small", &small, &limits()).await;
    assert!(matches!(next, ScanOutcome::Parsed(_)), "{next:?}");
    assert_eq!(pool.worker_pids(), pid);
}

#[tokio::test]
async fn pool_size_is_honoured() {
    let dir = tempfile::tempdir().unwrap();
    let path = message_file(&dir, "msg.eml", PLAIN);
    let pool = WorkerPool::new(worker_bin(), 10, 500).with_size(2);
    let limits = limits();
    let (a, b) = tokio::join!(
        pool.scan_file("1", &path, &limits),
        pool.scan_file("2", &path, &limits)
    );
    assert!(matches!(a, ScanOutcome::Parsed(_)), "{a:?}");
    assert!(matches!(b, ScanOutcome::Parsed(_)), "{b:?}");
    assert_eq!(pool.worker_pids().len(), 2);
}

/// The daemon's environment (credentials included) is not passed on.
#[tokio::test]
async fn worker_does_not_inherit_the_daemon_environment() {
    let dir = tempfile::tempdir().unwrap();
    let dump = dir.path().join("env.txt");
    let script = dir.path().join("worker.sh");
    std::fs::write(
        &script,
        format!("#!/bin/sh\n/usr/bin/env > {}\n", dump.display()),
    )
    .unwrap();
    std::fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    std::env::set_var("CURRAWONG_TEST_SECRET", "do-not-pass");
    let path = message_file(&dir, "msg.eml", PLAIN);
    let pool = WorkerPool::new(&script, 5, 10);
    let outcome = pool.scan_file("1", &path, &limits()).await;
    assert!(matches!(outcome, ScanOutcome::Failed { .. }));
    let env = std::fs::read_to_string(&dump).unwrap();
    assert!(env.contains("CURRAWONG_WORKER_AS_MIB"), "{env}");
    assert!(!env.contains("CURRAWONG_TEST_SECRET"), "{env}");
}

/// Issue #23: a decompression bomb hits the worker's address-space limit.
/// The extraction limits are set far above it, so only the rlimit can stop
/// it. Linux only: macOS does not enforce RLIMIT_AS.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn decompression_bomb_hits_the_memory_limit() {
    use currawong_core::PartFlag;
    let member = {
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
        enc.write_all(&vec![0u8; 1024 * 1024]).unwrap();
        enc.finish().unwrap()
    };
    // 1 GiB of zeros from about 1 MiB of gzip members.
    let bomb: Vec<u8> = std::iter::repeat_n(member, 1024).flatten().collect();
    let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &bomb);
    let raw = format!(
        "From: a@example.test\r\nTo: b@example.test\r\nSubject: bomb\r\nMIME-Version: 1.0\r\nContent-Type: application/gzip; name=\"zeros.gz\"\r\nContent-Disposition: attachment; filename=\"zeros.gz\"\r\nContent-Transfer-Encoding: base64\r\n\r\n{encoded}\r\n"
    );
    let dir = tempfile::tempdir().unwrap();
    let path = message_file(&dir, "bomb.eml", raw.as_bytes());
    let unbounded = ExtractLimits {
        max_depth: 5,
        max_uncompressed_bytes: 64 * 1024 * 1024 * 1024,
        max_files: 1000,
        max_ratio: u32::MAX,
    };
    let pool = WorkerPool::new(worker_bin(), 120, 500).with_limits(256, 120);
    let outcome = pool.scan_file("bomb", &path, &unbounded).await;
    match &outcome {
        ScanOutcome::Failed { .. } => {}
        ScanOutcome::Parsed(parsed) => assert!(
            parsed
                .parts
                .iter()
                .any(|part| part.flags.contains(&PartFlag::LimitExceeded)),
            "{parsed:?}"
        ),
    }
    let small = message_file(&dir, "small.eml", PLAIN);
    let next = pool.scan_file("small", &small, &limits()).await;
    assert!(matches!(next, ScanOutcome::Parsed(_)), "{next:?}");
}

#[test]
fn supplemental_signature_dirs_must_exist() {
    let dir = tempfile::tempdir().unwrap();
    supplemental_paths_ready(&[dir.path().to_path_buf()], &[]).unwrap();
    let missing = dir.path().join("nope");
    assert!(supplemental_paths_ready(&[missing], &[]).is_err());
}

#[tokio::test]
#[ignore]
async fn clamav_live_eicar() {
    let addr = std::env::var("CLAMD_ADDR").expect("CLAMD_ADDR");
    let client = ClamdClient::new(ClamdAddress::parse(&format!("tcp:{addr}")).unwrap(), true);
    let hit = client
        .scan(&ScanItem {
            name: "eicar.com",
            bytes: eicar(),
        })
        .await;
    assert!(matches!(hit, EngineResult::Malware { .. }), "{hit:?}");
}

/// Live clamd: 120 MiB is over `StreamMaxLength` unless it was raised, and
/// the size limit reply must fail closed, not defer.
#[tokio::test]
#[ignore]
async fn clamav_live_size_limit_fails_closed() {
    let addr = std::env::var("CLAMD_ADDR").expect("CLAMD_ADDR");
    let client = ClamdClient::new(ClamdAddress::parse(&format!("tcp:{addr}")).unwrap(), true);
    let body = vec![b'x'; 120 * 1024 * 1024];
    let result = client
        .scan(&ScanItem {
            name: "big",
            bytes: &body,
        })
        .await;
    assert!(
        matches!(
            result,
            EngineResult::Failed {
                unreachable: false,
                ..
            }
        ),
        "{result:?}"
    );
}

async fn fake_clamd() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let sample = Arc::new(eicar().to_vec());
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            let sample = Arc::clone(&sample);
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut tmp = [0u8; 1024];
                loop {
                    let n = sock.read(&mut tmp).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                    if buf.windows(6).any(|w| w == b"zPING\0")
                        && !buf.windows(9).any(|w| w == b"zINSTREAM")
                    {
                        let _ = sock.write_all(b"PONG\0").await;
                        break;
                    }
                    if buf.windows(10).any(|w| w == b"zINSTREAM\0") && buf.ends_with(&[0, 0, 0, 0])
                    {
                        let infected = contains_sample(&buf, &sample);
                        let reply = if infected {
                            b"stream: Eicar-Test-Signature FOUND\0".to_vec()
                        } else {
                            b"stream: OK\0".to_vec()
                        };
                        let _ = sock.write_all(&reply).await;
                        break;
                    }
                }
            });
        }
    });
    addr
}

fn contains_sample(buf: &[u8], sample: &[u8]) -> bool {
    buf.windows(sample.len()).any(|window| window == sample)
}
