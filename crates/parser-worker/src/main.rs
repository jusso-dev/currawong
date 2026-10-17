//! Isolated parser worker. Reads length-prefixed JSON requests on stdin.
//! It refuses to start if the limits or the sandbox cannot be installed.
use bytes::Bytes;
use currawong_parser::ipc::{codec, MAX_FRAME};
use currawong_parser::sandbox::{self, WorkerLimits};
use currawong_parser::{parse_request, ParseRequest, ParseResponse};
use futures::{SinkExt, StreamExt};
use std::io;
use tokio_util::codec::{FramedRead, FramedWrite};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let mut writer = FramedWrite::new(tokio::io::stdout(), codec());
    let limits = WorkerLimits::from_env();
    if let Err(err) = sandbox::apply_limits(&limits) {
        let reason = format!("resource limits: {err}");
        let _ = writer
            .send(encode(&ParseResponse::failed("startup", reason)))
            .await;
        std::process::exit(1);
    }
    if let Err(err) = sandbox::install() {
        let reason = format!("sandbox: {err}");
        let _ = writer
            .send(encode(&ParseResponse::failed("startup", reason)))
            .await;
        std::process::exit(1);
    }
    let mut reader = FramedRead::new(tokio::io::stdin(), codec());
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
        let response = match serde_json::from_slice::<ParseRequest>(&frame) {
            Ok(request) => match sandbox::start_job(&limits) {
                Ok(()) => parse_request(&request),
                Err(err) => ParseResponse::failed(&request.id, format!("cpu limit: {err}")),
            },
            Err(err) => ParseResponse::failed("request", err.to_string()),
        };
        if send(&mut writer, &response).await.is_err() {
            break;
        }
    }
}

/// A response too big for one frame becomes a failure for the same job.
async fn send<W>(
    writer: &mut FramedWrite<W, tokio_util::codec::LengthDelimitedCodec>,
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
