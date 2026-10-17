use currawong_core::config::ExtractLimits;
use currawong_scan::clamav::{supplemental_paths_ready, ClamdAddress, ClamdClient};
use currawong_scan::combine::{combine, EngineOutput};
use currawong_scan::engines::{EngineResult, ScanItem};
use currawong_scan::pool::{worker_binary_from_exe, ScanOutcome, WorkerPool};
use currawong_scan::{eicar, FileTypeScanner, Scanner};
use std::io::Write;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

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

#[tokio::test]
async fn filetype_flags_renamed_executable_and_macro_without_clamav() {
    let scanner = FileTypeScanner {
        treat_macros_as_active: true,
        treat_executables_as_active: true,
        limits: ExtractLimits {
            max_depth: 2,
            max_uncompressed_bytes: 1024 * 1024,
            max_files: 16,
            max_ratio: 100,
        },
    };
    let mut pe = vec![0u8; 0x80];
    pe[0] = b'M';
    pe[1] = b'Z';
    pe[0x3c] = 0x40;
    pe[0x40] = b'P';
    pe[0x41] = b'E';
    let exe = scanner
        .scan(&ScanItem {
            name: "invoice.pdf",
            bytes: &pe,
        })
        .await;
    assert!(matches!(exe, EngineResult::Suspicious { .. }), "{exe:?}");

    let mut cursor = std::io::Cursor::new(Vec::new());
    {
        let mut zip = zip::ZipWriter::new(&mut cursor);
        zip.start_file(
            "word/vbaProject.bin",
            zip::write::SimpleFileOptions::default(),
        )
        .unwrap();
        zip.write_all(b"benign-placeholder").unwrap();
        zip.finish().unwrap();
    }
    let docm = cursor.into_inner();
    let macro_doc = scanner
        .scan(&ScanItem {
            name: "note.docm",
            bytes: &docm,
        })
        .await;
    assert!(
        matches!(macro_doc, EngineResult::Suspicious { .. }),
        "{macro_doc:?}"
    );
}

#[tokio::test]
async fn pool_crash_fails_closed_and_live_worker_parses() {
    let limits = ExtractLimits {
        max_depth: 2,
        max_uncompressed_bytes: 1024 * 1024,
        max_files: 8,
        max_ratio: 20,
    };
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("msg.eml");
    std::fs::write(
        &path,
        b"From: a@example.test\r\nTo: b@example.test\r\nSubject: hi\r\n\r\nhello\r\n",
    )
    .unwrap();
    let mut crashed = WorkerPool::new("/usr/bin/false", 2, 10);
    let failed = crashed.scan_file("1", &path, &limits).await;
    assert!(matches!(failed, ScanOutcome::Failed { .. }), "{failed:?}");

    let Some(bin) = worker_binary_from_exe().or_else(|| {
        let candidate = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/debug/currawong-parser-worker");
        candidate.is_file().then_some(candidate)
    }) else {
        return;
    };
    let mut pool = WorkerPool::new(bin, 10, 500);
    let parsed = pool.scan_file("2", &path, &limits).await;
    assert!(matches!(parsed, ScanOutcome::Parsed(_)), "{parsed:?}");
    pool.kill().await;
    let again = pool.scan_file("3", &path, &limits).await;
    assert!(matches!(again, ScanOutcome::Parsed(_)), "{again:?}");
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
