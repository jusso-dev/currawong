//! Isolated parser worker. Reads length-prefixed JSON requests on stdin.
use bytes::Bytes;
use currawong_parser::{parse_request, ParseRequest, ParseResponse};
use futures::StreamExt;
use std::io;
use tokio::io::{AsyncWriteExt, BufWriter};
use tokio_util::codec::{FramedRead, LengthDelimitedCodec};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    if let Err(err) = apply_limits() {
        let _ = write_one(&ParseResponse::failed("startup", err.to_string())).await;
        std::process::exit(1);
    }
    install_sandbox();
    let stdin = tokio::io::stdin();
    let mut reader = FramedRead::new(stdin, LengthDelimitedCodec::new());
    while let Some(frame) = reader.next().await {
        let frame = match frame {
            Ok(frame) => frame,
            Err(err) => {
                let _ = write_one(&ParseResponse::failed("frame", err.to_string())).await;
                break;
            }
        };
        let response = match serde_json::from_slice::<ParseRequest>(&frame) {
            Ok(request) => parse_request(&request),
            Err(err) => ParseResponse::failed("request", err.to_string()),
        };
        if write_one(&response).await.is_err() {
            break;
        }
    }
}

async fn write_one(response: &ParseResponse) -> io::Result<()> {
    let bytes = serde_json::to_vec(response)
        .unwrap_or_else(|_| br#"{"id":"","parts":[],"urls":[],"error":"encode"}"#.to_vec());
    let mut codec_out = bytes::BytesMut::new();
    {
        use tokio_util::codec::Encoder;
        let mut codec = LengthDelimitedCodec::new();
        codec.encode(Bytes::from(bytes), &mut codec_out)?;
    }
    let mut stdout = BufWriter::new(tokio::io::stdout());
    stdout.write_all(&codec_out).await?;
    stdout.flush().await
}

fn apply_limits() -> io::Result<()> {
    let mem_mib: u64 = std::env::var("CURRAWONG_WORKER_AS_MIB")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(512);
    let cpu: u64 = std::env::var("CURRAWONG_WORKER_CPU_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(30);
    let bytes = mem_mib.saturating_mul(1024 * 1024);
    rlimit::setrlimit(rlimit::Resource::AS, bytes, bytes).or_else(|err| {
        if err.kind() == io::ErrorKind::InvalidInput {
            Ok(())
        } else {
            Err(err)
        }
    })?;
    rlimit::setrlimit(rlimit::Resource::CPU, cpu, cpu).or_else(|err| {
        if err.kind() == io::ErrorKind::InvalidInput {
            Ok(())
        } else {
            Err(err)
        }
    })?;
    Ok(())
}

fn install_sandbox() {
    #[cfg(target_os = "linux")]
    linux::apply();
}

#[cfg(target_os = "linux")]
mod linux {
    pub fn apply() {
        use seccompiler::{SeccompAction, SeccompFilter, TargetArch};
        use std::env::consts::ARCH;
        let arch = match ARCH {
            "x86_64" => TargetArch::x86_64,
            "aarch64" => TargetArch::aarch64,
            _ => return,
        };
        let names = ["socket", "connect", "execve", "execveat", "ptrace"];
        let mut rules = std::collections::BTreeMap::new();
        for name in names {
            if let Some(nr) = syscall_nr(name) {
                rules.insert(nr, vec![]);
            }
        }
        let filter = match SeccompFilter::new(
            rules,
            SeccompAction::Allow,
            SeccompAction::Errno(libc::EPERM as u32),
            arch,
        ) {
            Ok(filter) => filter,
            Err(_) => return,
        };
        let bpf = match filter.try_into() {
            Ok(prog) => prog,
            Err(_) => return,
        };
        let _ = seccompiler::apply_filter(&bpf);
    }

    fn syscall_nr(name: &str) -> Option<i64> {
        match name {
            "socket" => Some(libc::SYS_socket as i64),
            "connect" => Some(libc::SYS_connect as i64),
            "execve" => Some(libc::SYS_execve as i64),
            "execveat" => Some(libc::SYS_execveat as i64),
            "ptrace" => Some(libc::SYS_ptrace as i64),
            _ => None,
        }
    }
}
