//! Container HEALTHCHECK probe. Distroless has no shell or curl, so this
//! std-only binary sends `GET /healthz` and exits 0 only on an HTTP 200.
//! Build: `rustc -O -o healthcheck packaging/docker/healthcheck.rs`.
//! Usage: `healthcheck [host:port]`, default `127.0.0.1:9090`.
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

fn main() {
    let target = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:9090".to_string());
    if let Err(err) = probe(&target) {
        eprintln!("healthcheck {target}: {err}");
        std::process::exit(1);
    }
}

fn probe(target: &str) -> Result<(), String> {
    let addr = target
        .to_socket_addrs()
        .map_err(|err| err.to_string())?
        .next()
        .ok_or("no address")?;
    let timeout = Duration::from_secs(3);
    let mut stream = TcpStream::connect_timeout(&addr, timeout).map_err(|err| err.to_string())?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|err| err.to_string())?;
    stream
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .map_err(|err| err.to_string())?;
    let mut head = [0u8; 12];
    stream
        .read_exact(&mut head)
        .map_err(|err| err.to_string())?;
    if head.starts_with(b"HTTP/1.1 200") || head.starts_with(b"HTTP/1.0 200") {
        Ok(())
    } else {
        Err(format!(
            "unexpected status: {}",
            String::from_utf8_lossy(&head)
        ))
    }
}
