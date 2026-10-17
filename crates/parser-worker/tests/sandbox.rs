//! Issue #23: inside the worker sandbox a TCP socket fails with EPERM.
//! Linux only; macOS and Windows workers run unsandboxed (dev builds).
#![cfg(target_os = "linux")]

use std::process::Command;

/// Re-runs this test binary with only `sandbox_probe` selected, so the
/// filter is installed in a child process and not in the test harness.
#[test]
fn tcp_socket_is_denied_inside_the_sandbox() {
    let status = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "sandbox_probe",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("CURRAWONG_SANDBOX_PROBE", "1")
        .status()
        .unwrap();
    assert_eq!(
        status.code(),
        Some(0),
        "2: sandbox did not install, 3: socket() was not EPERM"
    );
}

#[test]
fn sandbox_probe() {
    if std::env::var_os("CURRAWONG_SANDBOX_PROBE").is_none() {
        return;
    }
    if let Err(err) = currawong_parser::sandbox::install() {
        eprintln!("{err}");
        // SAFETY: exits the probe process without running the harness.
        unsafe { libc::_exit(2) };
    }
    // SAFETY: plain syscalls with constant arguments.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    let errno = std::io::Error::last_os_error().raw_os_error();
    let code = if fd == -1 && errno == Some(libc::EPERM) {
        0
    } else {
        3
    };
    unsafe { libc::_exit(code) };
}
