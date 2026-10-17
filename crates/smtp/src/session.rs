//! SMTP session state machine.
use crate::{
    auth_sasl::{self, SaslOutcome, SaslState},
    checks::{CheckStack, ConnCtx, MailCtx, RcptCtx},
    command::{self, Command},
    data::{push_data_line, LineDecision},
    relay::{AuthContext, Relay},
    tls::{tls_labels, TlsManager},
};
use currawong_core::{
    config::{LimitsConfig, ListenerRole},
    telemetry::{MESSAGES_ACCEPTED_TOTAL, MESSAGES_REJECTED_TOTAL, SMTP_CONNECTIONS_TOTAL},
    Direction,
};
use currawong_spool::{Envelope, Spool, SpoolState};
use futures::StreamExt;
use std::{net::SocketAddr, sync::Arc, time::Duration};
use time::OffsetDateTime;
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    time::timeout,
};
use tokio_util::{
    codec::{FramedRead, LinesCodec, LinesCodecError},
    sync::CancellationToken,
};

pub use crate::stream::BoxIo;

pub struct SessionContext {
    pub cfg: Arc<currawong_core::Config>,
    pub spool: Arc<Spool>,
    pub tls: Option<Arc<TlsManager>>,
    pub checks: Arc<CheckStack>,
    pub relay: Arc<Relay>,
    pub role: ListenerRole,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Connected,
    Greeted,
    Mail,
    Rcpt,
}

struct Transaction {
    mail_from: String,
    rcpts: Vec<String>,
}

pub async fn run_session(
    io: BoxIo,
    peer: SocketAddr,
    ctx: Arc<SessionContext>,
    shutdown: CancellationToken,
    mut tls_info: Option<(String, String)>,
) {
    metrics::counter!(SMTP_CONNECTIONS_TOTAL).increment(1);
    let mut trusted = ctx
        .relay
        .tenant_for_ip(peer.ip())
        .map(|tenant| AuthContext {
            tenant_id: tenant.id.clone(),
            principal: "trusted-ip".into(),
        });
    let limits = ctx.cfg.limits.clone();
    let result = session_loop(
        io,
        peer,
        &ctx,
        shutdown,
        &mut tls_info,
        &mut trusted,
        limits,
    )
    .await;
    if let Err(err) = result {
        tracing::debug!(%err, %peer, "smtp session ended");
    }
}

#[allow(clippy::too_many_arguments)]
async fn session_loop(
    io: BoxIo,
    peer: SocketAddr,
    ctx: &SessionContext,
    shutdown: CancellationToken,
    tls_info: &mut Option<(String, String)>,
    trusted: &mut Option<AuthContext>,
    limits: LimitsConfig,
) -> std::io::Result<()> {
    let (read, mut write) = tokio::io::split(io);
    let mut framed = FramedRead::new(read, LinesCodec::new_with_max_length(limits.max_line_bytes));
    let mut phase = Phase::Connected;
    let mut auth = trusted.clone();
    let mut sasl = SaslState::Idle;
    let mut tls_on = tls_info.is_some();
    let mut helo = String::new();
    let mut tx = empty_tx();

    let early = ctx
        .checks
        .on_connect(&ConnCtx {
            ip: peer.ip(),
            helo: String::new(),
        })
        .await;
    if let Some(line) = check_reply(&early) {
        let _ = write_line(&mut write, &line).await;
        metrics::counter!(MESSAGES_REJECTED_TOTAL).increment(1);
        return Ok(());
    }

    write_line(
        &mut write,
        &format!("220 {} ESMTP Currawong", ctx.cfg.gateway.hostname),
    )
    .await?;

    loop {
        let line = tokio::select! {
            _ = shutdown.cancelled() => {
                let _ = write_line(&mut write, "421 4.3.2 service shutting down").await;
                break;
            }
            next = timeout(Duration::from_secs(limits.smtp_command_timeout_secs), framed.next()) => {
                match next {
                    Ok(Some(Ok(line))) => line,
                    Ok(Some(Err(LinesCodecError::MaxLineLengthExceeded))) => {
                        let _ = write_line(&mut write, "500 5.5.2 line too long").await;
                        metrics::counter!(MESSAGES_REJECTED_TOTAL).increment(1);
                        break;
                    }
                    Ok(Some(Err(_))) | Ok(None) | Err(_) => break,
                }
            }
        };

        if !matches!(sasl, SaslState::Idle) {
            let (next_state, outcome) = auth_sasl::next(sasl, line.trim());
            sasl = next_state;
            if !apply_sasl(&mut write, &mut auth, ctx, outcome).await? {
                continue;
            }
            continue;
        }

        let command = match command::parse_command(&line) {
            Ok(command) => command,
            Err(_) => {
                write_line(&mut write, "500 5.5.2 command not recognised").await?;
                continue;
            }
        };

        match command {
            Command::Quit => {
                write_line(&mut write, "221 2.0.0 goodbye").await?;
                break;
            }
            Command::Noop => write_line(&mut write, "250 2.0.0 OK").await?,
            Command::Rset => {
                phase = if phase == Phase::Connected {
                    Phase::Connected
                } else {
                    Phase::Greeted
                };
                tx = empty_tx();
                sasl = SaslState::Idle;
                write_line(&mut write, "250 2.0.0 reset").await?;
            }
            Command::Ehlo(arg) | Command::Helo(arg) => {
                helo = arg;
                phase = Phase::Greeted;
                tx = empty_tx();
                write_all_bytes(&mut write, ehlo_text(ctx, tls_on).as_bytes()).await?;
            }
            Command::StartTls => {
                if tls_on {
                    write_line(&mut write, "503 5.5.1 TLS already active").await?;
                    continue;
                }
                let Some(manager) = &ctx.tls else {
                    write_line(&mut write, "502 5.5.1 STARTTLS not available").await?;
                    continue;
                };
                write_line(&mut write, "220 2.0.0 Ready to start TLS").await?;
                let read = framed.into_inner();
                let io = read.unsplit(write);
                let acceptor = manager.acceptor();
                let tls_stream = match acceptor.accept(io).await {
                    Ok(stream) => stream,
                    Err(err) => {
                        tracing::debug!(%err, "STARTTLS handshake failed");
                        return Ok(());
                    }
                };
                *tls_info = Some(tls_labels(tls_stream.get_ref().1));
                tls_on = true;
                phase = Phase::Connected;
                tx = empty_tx();
                auth = trusted.clone();
                sasl = SaslState::Idle;
                let (read, next_write) = tokio::io::split(BoxIo::new(tls_stream));
                write = next_write;
                framed =
                    FramedRead::new(read, LinesCodec::new_with_max_length(limits.max_line_bytes));
            }
            Command::Auth { mechanism, initial } => {
                let (next_state, outcome) =
                    auth_sasl::start(&mechanism, initial.as_deref(), tls_on);
                sasl = next_state;
                apply_sasl(&mut write, &mut auth, ctx, outcome).await?;
            }
            Command::AuthLine(_) => {
                write_line(&mut write, "500 5.5.2 unexpected auth line").await?;
            }
            Command::Mail { address, params } => {
                if phase != Phase::Greeted && phase != Phase::Mail {
                    write_line(&mut write, "503 5.5.1 send EHLO first").await?;
                    continue;
                }
                if ctx.role == ListenerRole::Submission && auth.is_none() {
                    write_line(&mut write, "530 5.7.1 authentication required").await?;
                    continue;
                }
                if let Some(size) = params
                    .iter()
                    .find(|(k, _)| k == "SIZE")
                    .and_then(|(_, v)| v.parse::<u64>().ok())
                {
                    if size > limits.max_message_bytes {
                        write_line(&mut write, "552 5.3.4 message size exceeds limit").await?;
                        metrics::counter!(MESSAGES_REJECTED_TOTAL).increment(1);
                        continue;
                    }
                }
                if let Some(context) = &auth {
                    match command::domain_of(&address) {
                        Some(domain) if ctx.relay.owns_domain(&context.tenant_id, domain) => {}
                        _ if address.is_empty() => {}
                        _ => {
                            write_line(
                                &mut write,
                                "550 5.7.1 sender domain is not owned by this tenant",
                            )
                            .await?;
                            metrics::counter!(MESSAGES_REJECTED_TOTAL).increment(1);
                            continue;
                        }
                    }
                }
                let mail_result = ctx
                    .checks
                    .on_mail(&MailCtx {
                        ip: peer.ip(),
                        mail_from: address.clone(),
                    })
                    .await;
                if let Some(line) = check_reply(&mail_result) {
                    write_line(&mut write, &line).await?;
                    continue;
                }
                let _ = params;
                tx = Transaction {
                    mail_from: address,
                    rcpts: Vec::new(),
                };
                phase = Phase::Mail;
                write_line(&mut write, "250 2.1.0 OK").await?;
            }
            Command::Rcpt { address, .. } => {
                if phase != Phase::Mail && phase != Phase::Rcpt {
                    write_line(&mut write, "503 5.5.1 need MAIL first").await?;
                    continue;
                }
                if tx.rcpts.len() >= limits.max_recipients {
                    write_line(&mut write, "452 4.5.3 too many recipients").await?;
                    continue;
                }
                let domain = command::domain_of(&address).unwrap_or("");
                let local = ctx
                    .cfg
                    .domains
                    .accept
                    .iter()
                    .any(|item| item.eq_ignore_ascii_case(domain));
                if !local {
                    let allowed = match &auth {
                        Some(context) => command::domain_of(&tx.mail_from)
                            .map(|from_domain| {
                                ctx.relay.owns_domain(&context.tenant_id, from_domain)
                            })
                            .unwrap_or(false),
                        None => false,
                    };
                    if !allowed {
                        write_line(&mut write, "550 5.7.1 Relaying denied").await?;
                        metrics::counter!(MESSAGES_REJECTED_TOTAL).increment(1);
                        continue;
                    }
                }
                let rcpt_result = ctx
                    .checks
                    .on_rcpt(&RcptCtx {
                        ip: peer.ip(),
                        mail_from: tx.mail_from.clone(),
                        recipient: address.clone(),
                    })
                    .await;
                if let Some(line) = check_reply(&rcpt_result) {
                    write_line(&mut write, &line).await?;
                    continue;
                }
                tx.rcpts.push(address);
                phase = Phase::Rcpt;
                write_line(&mut write, "250 2.1.5 OK").await?;
            }
            Command::Data => {
                if phase != Phase::Rcpt || tx.rcpts.is_empty() {
                    write_line(&mut write, "503 5.5.1 need RCPT first").await?;
                    continue;
                }
                write_line(&mut write, "354 start mail input; end with <CRLF>.<CRLF>").await?;
                match read_body(&mut framed, &limits, &shutdown).await {
                    BodyRead::Message(bytes) => {
                        let external = tx.rcpts.iter().any(|rcpt| {
                            let domain = command::domain_of(rcpt).unwrap_or("");
                            !ctx.cfg
                                .domains
                                .accept
                                .iter()
                                .any(|item| item.eq_ignore_ascii_case(domain))
                        });
                        let id = Envelope::new_id();
                        let env = Envelope {
                            id: id.clone(),
                            tenant_id: auth.as_ref().map(|item| item.tenant_id.clone()),
                            mail_from: tx.mail_from.clone(),
                            rcpt_to: tx.rcpts.clone(),
                            received_at: OffsetDateTime::now_utc(),
                            remote_ip: peer.ip(),
                            helo: helo.clone(),
                            attempts: 0,
                            next_attempt_at: None,
                            state: SpoolState::Incoming,
                            direction: if external {
                                Direction::Outbound
                            } else {
                                Direction::Inbound
                            },
                            tls_version: tls_info.as_ref().map(|(v, _)| v.clone()),
                            tls_cipher: tls_info.as_ref().map(|(_, c)| c.clone()),
                            rcpt_status: Vec::new(),
                            prepend_headers: Vec::new(),
                            dsn_sent: false,
                            pipeline: "pending".into(),
                        };
                        match ctx.spool.accept(env, std::io::Cursor::new(bytes)).await {
                            Ok(stored) => {
                                tracing::info!(message_id = %stored, "message spooled");
                                metrics::counter!(MESSAGES_ACCEPTED_TOTAL).increment(1);
                                write_line(&mut write, &format!("250 2.0.0 OK {stored}")).await?;
                            }
                            Err(err) => {
                                tracing::error!(%err, "spool accept failed");
                                write_line(&mut write, "451 4.3.0 spool unavailable").await?;
                            }
                        }
                        phase = Phase::Greeted;
                        tx = empty_tx();
                    }
                    BodyRead::TooLarge => {
                        metrics::counter!(MESSAGES_REJECTED_TOTAL).increment(1);
                        write_line(&mut write, "552 5.3.4 message size exceeds limit").await?;
                        phase = Phase::Greeted;
                        tx = empty_tx();
                    }
                    BodyRead::TooLong => {
                        metrics::counter!(MESSAGES_REJECTED_TOTAL).increment(1);
                        let _ = write_line(&mut write, "500 5.5.2 line too long").await;
                        break;
                    }
                    BodyRead::Closed => break,
                }
            }
        }
    }
    Ok(())
}

enum BodyRead {
    Message(Vec<u8>),
    TooLarge,
    TooLong,
    Closed,
}

async fn read_body<R>(
    framed: &mut FramedRead<R, LinesCodec>,
    limits: &LimitsConfig,
    shutdown: &CancellationToken,
) -> BodyRead
where
    R: AsyncRead + Unpin,
{
    let mut out = Vec::new();
    let mut too_large = false;
    loop {
        let line = tokio::select! {
            _ = shutdown.cancelled() => return BodyRead::Closed,
            next = timeout(Duration::from_secs(limits.smtp_command_timeout_secs), framed.next()) => {
                match next {
                    Ok(Some(Ok(line))) => line,
                    Ok(Some(Err(LinesCodecError::MaxLineLengthExceeded))) => return BodyRead::TooLong,
                    _ => return BodyRead::Closed,
                }
            }
        };
        if too_large {
            if line.trim_end_matches('\r') == "." {
                return BodyRead::TooLarge;
            }
            continue;
        }
        match push_data_line(
            &line,
            &mut out,
            limits.max_line_bytes,
            limits.max_message_bytes as usize,
        ) {
            LineDecision::Continue => {}
            LineDecision::Done => return BodyRead::Message(out),
            LineDecision::TooLarge => {
                too_large = true;
            }
            LineDecision::TooLong => return BodyRead::TooLong,
        }
    }
}

async fn apply_sasl<W: AsyncWrite + Unpin>(
    write: &mut W,
    auth: &mut Option<AuthContext>,
    ctx: &SessionContext,
    outcome: SaslOutcome,
) -> std::io::Result<bool> {
    match outcome {
        SaslOutcome::Continue(line) => {
            write_line(write, &line).await?;
            Ok(false)
        }
        SaslOutcome::Failure(line) => {
            write_line(write, line).await?;
            Ok(true)
        }
        SaslOutcome::Done { username, password } => {
            match ctx.relay.authenticate(&username, &password) {
                Ok(Some(context)) => {
                    *auth = Some(context);
                    write_line(write, "235 2.7.0 authentication succeeded").await?;
                }
                Ok(None) => {
                    write_line(write, "535 5.7.8 authentication failed").await?;
                }
                Err(err) => {
                    tracing::debug!(%err, "credential store unavailable");
                    write_line(write, "454 4.7.0 authentication temporarily unavailable").await?;
                }
            }
            Ok(true)
        }
    }
}

fn check_reply(result: &crate::checks::CheckResult) -> Option<String> {
    match result {
        crate::checks::CheckResult::Pass | crate::checks::CheckResult::Score(_) => None,
        crate::checks::CheckResult::TempFail(line) | crate::checks::CheckResult::Reject(line) => {
            Some(line.clone())
        }
    }
}

fn ehlo_text(ctx: &SessionContext, tls_on: bool) -> String {
    let mut lines = vec![
        format!("250-{}", ctx.cfg.gateway.hostname),
        format!("250-SIZE {}", ctx.cfg.limits.max_message_bytes),
        "250-8BITMIME".into(),
        "250-PIPELINING".into(),
        "250-ENHANCEDSTATUSCODES".into(),
        "250-SMTPUTF8".into(),
    ];
    if !tls_on && ctx.tls.is_some() {
        lines.push("250-STARTTLS".into());
    }
    if tls_on {
        lines.push("250-AUTH PLAIN LOGIN".into());
    }
    lines.push("250 HELP".into());
    let mut text = lines.join("\r\n");
    text.push_str("\r\n");
    text
}

fn empty_tx() -> Transaction {
    Transaction {
        mail_from: String::new(),
        rcpts: Vec::new(),
    }
}

async fn write_line<W: AsyncWrite + Unpin>(write: &mut W, line: &str) -> std::io::Result<()> {
    let mut bytes = line.as_bytes().to_vec();
    if !line.ends_with("\r\n") {
        bytes.extend_from_slice(b"\r\n");
    }
    write_all_bytes(write, &bytes).await
}

async fn write_all_bytes<W: AsyncWrite + Unpin>(
    write: &mut W,
    bytes: &[u8],
) -> std::io::Result<()> {
    write.write_all(bytes).await?;
    write.flush().await
}
