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
use std::sync::mpsc;
use tokio_util::codec::{FramedRead, FramedWrite, LengthDelimitedCodec};

fn main() {
    sandbox::close_inherited_fds();
    sandbox::one_malloc_arena();
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
    // The parse thread starts before any other, so its stack is in place
    // before anything else takes address space.
    let setup = setup.and_then(|warnings| {
        Parser::spawn()
            .map(|parser| (warnings, parser))
            .map_err(|err| format!("parse thread: {err}"))
    });
    // No I/O driver: stdin and stdout run on the blocking pool, and the I/O
    // driver brings tokio's signal driver, whose socketpair seccomp denies.
    let runtime = match tokio::runtime::Builder::new_current_thread().build() {
        Ok(runtime) => runtime,
        Err(_) => std::process::exit(1),
    };
    runtime.block_on(serve(limits, setup));
}

async fn serve(limits: WorkerLimits, setup: Result<(Vec<String>, Parser), String>) {
    let mut writer = FramedWrite::new(tokio::io::stdout(), codec());
    let parser = match setup {
        Err(reason) => {
            let _ = writer
                .send(encode(&ParseResponse::failed(STARTUP_ID, reason)))
                .await;
            std::process::exit(1);
        }
        Ok((warnings, parser)) => {
            let mut ready = ParseResponse::failed(READY_ID, "");
            ready.error = None;
            ready.warnings = warnings;
            if writer.send(encode(&ready)).await.is_err() {
                return;
            }
            parser
        }
    };
    // Requests are small, but YARA rule frames can be large.
    let request_codec = LengthDelimitedCodec::builder()
        .max_frame_length(LoadRules::MAX_FRAME_BYTES)
        .new_codec();
    let mut reader = FramedRead::new(tokio::io::stdin(), request_codec);
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
        let response = match job(&frame, &limits) {
            Ok(job) => {
                let id = job.id();
                match parser.run(job) {
                    Some(response) => response,
                    None => {
                        // The parse thread is gone. Fail this job and exit,
                        // so the supervisor starts a new worker.
                        let failed = ParseResponse::failed(id, "parse thread exited");
                        let _ = send(&mut writer, &failed).await;
                        std::process::exit(1);
                    }
                }
            }
            Err((id, reason)) => ParseResponse::failed(id, reason),
        };
        if send(&mut writer, &response).await.is_err() {
            break;
        }
    }
}

/// Parsers recurse; give them a stack well past the default 8 MiB. It is
/// virtual memory, so it counts against the address-space limit.
const PARSE_STACK: usize = 64 * 1024 * 1024;

enum Job {
    Load(LoadRules),
    Parse(ParseRequest),
}

impl Job {
    fn id(&self) -> String {
        match self {
            Job::Load(_) => LoadRules::REPLY_ID.to_string(),
            Job::Parse(request) => request.id.clone(),
        }
    }
}

/// A request frame as a job for the parse thread, or the id and reason to
/// fail it with.
fn job(frame: &[u8], limits: &WorkerLimits) -> Result<Job, (String, String)> {
    if let Ok(load) = serde_json::from_slice::<LoadRules>(frame) {
        return Ok(Job::Load(load));
    }
    let request = serde_json::from_slice::<ParseRequest>(frame)
        .map_err(|err| ("request".to_string(), err.to_string()))?;
    if let Err(err) = sandbox::start_job(limits) {
        return Err((request.id, format!("cpu limit: {err}")));
    }
    Ok(Job::Parse(request))
}

/// The one thread that loads rules and parses, for the worker's whole life.
/// A thread per job needed `PARSE_STACK` of free address space every time;
/// once something else held it (glibc keeps the address space of a malloc
/// arena for good) every later job failed while the worker lived on.
struct Parser {
    jobs: mpsc::Sender<Job>,
    done: mpsc::Receiver<ParseResponse>,
}

impl Parser {
    fn spawn() -> io::Result<Self> {
        let (jobs, inbox) = mpsc::channel::<Job>();
        let (outbox, done) = mpsc::channel();
        std::thread::Builder::new()
            .name("parse".into())
            .stack_size(PARSE_STACK)
            .spawn(move || Self::serve(inbox, outbox))?;
        Ok(Self { jobs, done })
    }

    fn serve(inbox: mpsc::Receiver<Job>, outbox: mpsc::Sender<ParseResponse>) {
        let mut rules = RulesCache::default();
        for job in inbox {
            let run = std::panic::AssertUnwindSafe(|| match &job {
                Job::Load(load) => rules.load(load),
                Job::Parse(request) => parse_request(request, &mut rules),
            });
            let response = std::panic::catch_unwind(run)
                .unwrap_or_else(|_| ParseResponse::failed(job.id(), "parser panicked"));
            if outbox.send(response).is_err() {
                return;
            }
        }
    }

    /// None if the parse thread has exited.
    fn run(&self, job: Job) -> Option<ParseResponse> {
        self.jobs.send(job).ok()?;
        self.done.recv().ok()
    }
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
