//! Isolated parser worker. Reads length-prefixed JSON requests on stdin.
//! Inherited descriptors are closed and the limits and sandbox installed
//! before the async runtime starts any thread. If any of that fails the
//! worker reports it in a `startup` frame and exits; otherwise it sends a
//! `ready` frame and then answers one frame per request.
//!
//! `--probe` installs the same sandbox, tries what a compromised worker would
//! try, prints `{"name": errno}` as one JSON line and exits (tests).
use bytes::Bytes;
use currawong_parser::ipc::{codec, MAX_FRAME, READY_ID, STARTUP_ID};
use currawong_parser::sandbox::{self, SandboxConfig, WorkerLimits};
use currawong_parser::yara::RulesCache;
use currawong_parser::{parse_request, LoadRules, ParseRequest, ParseResponse};
use futures::{SinkExt, StreamExt};
use std::io;
use tokio_util::codec::{FramedRead, FramedWrite, LengthDelimitedCodec};

fn main() {
    sandbox::close_inherited_fds();
    let limits = WorkerLimits::from_env();
    let cfg = SandboxConfig::from_env();
    // Shared libraries (Pdfium, with the `pdfium` feature) are bound before
    // the sandbox stops the worker opening files.
    currawong_parser::qr::init();
    let setup = sandbox::apply_limits(&limits)
        .map_err(|err| format!("resource limits: {err}"))
        .and_then(|()| sandbox::install(&cfg).map_err(|err| format!("sandbox: {err}")));
    if std::env::args().any(|arg| arg == "--probe") {
        let mut report = serde_json::Map::new();
        report.insert(
            "setup".into(),
            setup.as_ref().err().cloned().unwrap_or_default().into(),
        );
        if setup.is_ok() {
            for (name, errno) in sandbox::probe(&cfg) {
                report.insert(name.into(), errno.into());
            }
        }
        println!("{}", serde_json::Value::Object(report));
        return;
    }
    // No I/O driver: stdin and stdout run on the blocking pool, and the I/O
    // driver brings tokio's signal driver, whose socketpair seccomp denies.
    let runtime = match tokio::runtime::Builder::new_current_thread().build() {
        Ok(runtime) => runtime,
        Err(_) => std::process::exit(1),
    };
    runtime.block_on(serve(limits, setup));
}

async fn serve(limits: WorkerLimits, setup: Result<Vec<String>, String>) {
    let mut writer = FramedWrite::new(tokio::io::stdout(), codec());
    match setup {
        Err(reason) => {
            let _ = writer
                .send(encode(&ParseResponse::failed(STARTUP_ID, reason)))
                .await;
            std::process::exit(1);
        }
        Ok(warnings) => {
            let mut ready = ParseResponse::failed(READY_ID, "");
            ready.error = None;
            ready.warnings = warnings;
            if writer.send(encode(&ready)).await.is_err() {
                return;
            }
        }
    }
    // Requests are small, but YARA rule frames can be large.
    let request_codec = LengthDelimitedCodec::builder()
        .max_frame_length(LoadRules::MAX_FRAME_BYTES)
        .new_codec();
    let mut reader = FramedRead::new(tokio::io::stdin(), request_codec);
    let mut rules = RulesCache::default();
    while let Some(frame) = reader.next().await {
        let frame = match frame {
            Ok(frame) => frame,
            Err(err) => {
                let _ = writer
                    .send(encode(&ParseResponse::failed("frame", err.to_string())))
                    .await;
                break;
            }
        };
        if let Ok(load) = serde_json::from_slice::<LoadRules>(&frame) {
            if send(&mut writer, &rules.load(&load)).await.is_err() {
                break;
            }
            continue;
        }
        let response = match serde_json::from_slice::<ParseRequest>(&frame) {
            Ok(request) => match sandbox::start_job(&limits) {
                Ok(()) => parse_on_big_stack(request, &mut rules),
                Err(err) => ParseResponse::failed(&request.id, format!("cpu limit: {err}")),
            },
            Err(err) => ParseResponse::failed("request", err.to_string()),
        };
        if send(&mut writer, &response).await.is_err() {
            break;
        }
    }
}

/// Parsers recurse; give them a stack well past the default 8 MiB. It is
/// virtual memory, so it counts against the address-space limit.
const PARSE_STACK: usize = 64 * 1024 * 1024;

fn parse_on_big_stack(request: ParseRequest, rules: &mut RulesCache) -> ParseResponse {
    let id = request.id.clone();
    std::thread::scope(|scope| {
        std::thread::Builder::new()
            .name("parse".into())
            .stack_size(PARSE_STACK)
            .spawn_scoped(scope, || parse_request(&request, rules))
            .map_err(|err| format!("parse thread: {err}"))
            .and_then(|handle| handle.join().map_err(|_| "parser panicked".to_string()))
    })
    .unwrap_or_else(|reason| ParseResponse::failed(id, reason))
}

/// A response too big for one frame becomes a failure for the same job.
async fn send<W>(
    writer: &mut FramedWrite<W, LengthDelimitedCodec>,
    response: &ParseResponse,
) -> io::Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut bytes = encode(response);
    if bytes.len() > MAX_FRAME {
        bytes = encode(&ParseResponse::failed(
            &response.id,
            format!(
                "parse result is {} bytes, over the frame limit",
                bytes.len()
            ),
        ));
    }
    writer.send(bytes).await
}

fn encode(response: &ParseResponse) -> Bytes {
    Bytes::from(
        serde_json::to_vec(response)
            .unwrap_or_else(|_| br#"{"id":"","parts":[],"urls":[],"error":"encode"}"#.to_vec()),
    )
}
