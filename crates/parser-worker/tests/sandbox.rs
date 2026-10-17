//! Issue #23 and review round 2: the real worker binary, sandboxed as the
//! pool starts it, cannot reach the network, other processes or files
//! outside its own directory. Linux only; macOS and Windows workers run
//! unsandboxed (dev builds).
#![cfg(target_os = "linux")]

use std::process::Command;

fn probe() -> serde_json::Map<String, serde_json::Value> {
    let dir = tempfile::tempdir().unwrap();
    for sub in ["in", "out"] {
        std::fs::create_dir(dir.path().join(sub)).unwrap();
    }
    std::fs::write(
        dir.path().join("in/message.eml"),
        b"Subject: x\r\n\r\nx\r\n",
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_currawong-parser-worker"))
        .arg("--probe")
        .env_clear()
        .env("CURRAWONG_WORKER_DIR", dir.path())
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let text = String::from_utf8(output.stdout).unwrap();
    serde_json::from_str::<serde_json::Value>(text.trim())
        .unwrap()
        .as_object()
        .unwrap()
        .clone()
}

#[test]
fn sandbox_denies_what_a_compromised_worker_would_try() {
    let report = probe();
    assert_eq!(report["setup"], "", "sandbox did not install: {report:?}");
    let expect = |name: &str, errno: i32| {
        assert_eq!(
            report.get(name).and_then(|v| v.as_i64()),
            Some(errno as i64),
            "{name}: {report:?}"
        );
    };
    for name in [
        "socket_inet",
        "socket_unix",
        "pidfd_open",
        "pidfd_getfd",
        "ptrace",
        "kill",
        "tgkill",
        "execve",
        "clone_newuser",
        "unshare",
    ] {
        expect(name, libc::EPERM);
    }
    #[cfg(target_arch = "x86_64")]
    expect("x32_getpid", libc::EPERM);
    expect("clone3", libc::ENOSYS);
    // Landlock: nothing outside in/ (read) and out/ (write).
    for name in [
        "open_parent_mem",
        "open_etc_passwd",
        "write_input_dir",
        "write_parent_dir",
    ] {
        expect(name, libc::EACCES);
    }
    expect("read_input", 0);
    expect("write_output", 0);
}

#[test]
fn worker_without_its_directory_refuses_to_start() {
    let output = Command::new(env!("CARGO_BIN_EXE_currawong-parser-worker"))
        .arg("--probe")
        .env_clear()
        .output()
        .unwrap();
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("CURRAWONG_WORKER_DIR"), "{text}");
}
