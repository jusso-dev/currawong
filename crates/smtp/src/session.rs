//! SMTP session state machine.
use crate::{
    auth_sasl::{self, SaslOutcome, SaslState},
    checks::{CheckResult, CheckStack, ConnCtx, MailCtx, RcptCtx},
    command::{self, Command},
    data::{unstuff, LineDecision},
    line::{read_line, Line},
    relay::{AuthContext, Login, Relay},
    tls::{tls_labels, TlsManager},
};
use currawong_core::{
    config::{LimitsConfig, ListenerRole},
    telemetry::{MESSAGES_ACCEPTED_TOTAL, MESSAGES_REJECTED_TOTAL, SMTP_CONNECTIONS_TOTAL},
    Direction,
};
use currawong_spool::{Envelope, Spool, SpoolState};
use std::{
    io,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use time::OffsetDateTime;
use tokio::{
    io::{AsyncWriteExt, BufReader, ReadHalf, WriteHalf},
    time::timeout,
};
use tokio_util::sync::CancellationToken;

pub use crate::stream::BoxIo;

/// Failed AUTH attempts allowed on one connection before it is closed.
const MAX_AUTH_FAILURES: u32 = 3;

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

#[derive(PartialEq, Eq)]
enum Flow {
    Continue,
    Close,
    StartTls,
}

struct Transaction {
    mail_from: String,
    rcpts: Vec<String>,
}

/// The transport: a byte line reader and a writer whose replies time out, so
/// a client that stops reading cannot pin the session.
struct Conn {
    reader: BufReader<ReadHalf<BoxIo>>,
    writer: WriteHalf<BoxIo>,
    io_timeout: Duration,
    max_line: usize,
}

impl Conn {
    fn new(io: BoxIo, limits: &LimitsConfig) -> Self {
        let (read, writer) = tokio::io::split(io);
        Self {
            reader: BufReader::new(read),
            writer,
            io_timeout: Duration::from_secs(limits.smtp_command_timeout_secs),
            max_line: limits.max_line_bytes,
        }
    }

    /// Unread buffered input is discarded, as RFC 3207 requires after STARTTLS.
    fn into_io(self) -> BoxIo {
        self.reader.into_inner().unsplit(self.writer)
    }

    async fn reply(&mut self, line: &str) -> io::Result<()> {
        let mut bytes = line.as_bytes().to_vec();
        if !line.ends_with("\r\n") {
            bytes.extend_from_slice(b"\r\n");
        }
        let writer = &mut self.writer;
        timeout(self.io_timeout, async {
            writer.write_all(&bytes).await?;
            writer.flush().await
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "reply write timed out"))?
    }

    async fn line(&mut self) -> io::Result<Line> {
        timeout(self.io_timeout, read_line(&mut self.reader, self.max_line))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "command timeout"))?
    }
}

struct Session<'a> {
    ctx: &'a SessionContext,
    ip: IpAddr,
    shutdown: CancellationToken,
    limits: LimitsConfig,
    phase: Phase,
    /// Set when the peer is inside a tenant's trusted CIDRs.
    trusted: Option<AuthContext>,
    auth: Option<AuthContext>,
    sasl: SaslState,
    sasl_done: bool,
    auth_failures: u32,
    tls_info: Option<(String, String)>,
    helo: String,
    tx: Transaction,
}

pub async fn run_session(
    io: BoxIo,
    peer: SocketAddr,
    ctx: Arc<SessionContext>,
    shutdown: CancellationToken,
    tls_info: Option<(String, String)>,
) {
    metrics::counter!(SMTP_CONNECTIONS_TOTAL).increment(1);
    let ip = peer.ip().to_canonical();
    let trusted = ctx.relay.tenant_for_ip(ip).map(|tenant| AuthContext {
        tenant_id: tenant.id.clone(),
        principal: "trusted-ip".into(),
        senders: None,
    });
    let mut session = Session {
        ctx: &ctx,
        ip,
        shutdown,
        limits: ctx.cfg.limits.clone(),
        phase: Phase::Connected,
        auth: trusted.clone(),
        trusted,
        sasl: SaslState::Idle,
        sasl_done: false,
        auth_failures: 0,
        tls_info,
        helo: String::new(),
        tx: empty_tx(),
    };
    let mut conn = Conn::new(io, &session.limits);
    let result = async {
        if session.open(&mut conn).await? == Flow::Close {
            return Ok(());
        }
        loop {
            match session.serve(&mut conn).await? {
                Flow::StartTls => conn = session.upgrade(conn.into_io()).await?,
                Flow::Close | Flow::Continue => return Ok::<(), io::Error>(()),
            }
        }
    }
    .await;
    if let Err(err) = result {
        tracing::debug!(%err, %peer, "smtp session ended");
    }
}

impl Session<'_> {
    /// Connection checks, then the banner. Submission clients are users on
    /// dynamic and often listed addresses who must still reach AUTH, so the
    /// connect checks (DNSBL, reputation, per-IP rate) only run on inbound
    /// listeners. Submission is guarded by AUTH and its failure limits.
    async fn open(&mut self, conn: &mut Conn) -> io::Result<Flow> {
        if self.trusted.is_none() && self.ctx.role != ListenerRole::Submission {
            let early = self
                .ctx
                .checks
                .on_connect(&ConnCtx {
                    ip: self.ip,
                    helo: String::new(),
                })
                .await;
            if let Some(line) = check_reply(&early) {
                let _ = conn.reply(&line).await;
                metrics::counter!(MESSAGES_REJECTED_TOTAL).increment(1);
                return Ok(Flow::Close);
            }
        }
        conn.reply(&format!(
            "220 {} ESMTP Currawong",
            self.ctx.cfg.gateway.hostname
        ))
        .await?;
        Ok(Flow::Continue)
    }

    async fn serve(&mut self, conn: &mut Conn) -> io::Result<Flow> {
        loop {
            // On shutdown an idle session closes at once. A transaction in
            // progress may finish; the listener's 30 s drain bounds it.
            let idle = matches!(self.phase, Phase::Connected | Phase::Greeted)
                && self.sasl == SaslState::Idle;
            let next = if idle {
                tokio::select! {
                    _ = self.shutdown.cancelled() => None,
                    line = conn.line() => Some(line),
                }
            } else {
                Some(conn.line().await)
            };
            let Some(next) = next else {
                let _ = conn.reply("421 4.3.2 service shutting down").await;
                return Ok(Flow::Close);
            };
            let line = match next {
                Ok(Line::Crlf(line)) => line,
                Ok(Line::BareLf(_)) => {
                    conn.reply("500 5.5.2 lines must end with CRLF").await?;
                    continue;
                }
                Ok(Line::TooLong) => {
                    metrics::counter!(MESSAGES_REJECTED_TOTAL).increment(1);
                    let _ = conn.reply("500 5.5.2 line too long").await;
                    return Ok(Flow::Close);
                }
                Ok(Line::Eof) => return Ok(Flow::Close),
                Err(err) => return timed_out(conn, err).await,
            };
            if self.sasl != SaslState::Idle {
                let text = String::from_utf8_lossy(&line);
                let (next_state, outcome) =
                    auth_sasl::next(std::mem::take(&mut self.sasl), text.trim());
                self.sasl = next_state;
                if self.apply_sasl(conn, outcome).await? == Flow::Close {
                    return Ok(Flow::Close);
                }
                continue;
            }
            match self.command(conn, &line).await? {
                Flow::Continue => {}
                other => return Ok(other),
            }
        }
    }

    async fn command(&mut self, conn: &mut Conn, line: &[u8]) -> io::Result<Flow> {
        let Ok(command) = command::parse_command(line) else {
            conn.reply("500 5.5.2 syntax error or command not recognised")
                .await?;
            return Ok(Flow::Continue);
        };
        match command {
            Command::Quit => {
                conn.reply("221 2.0.0 goodbye").await?;
                return Ok(Flow::Close);
            }
            Command::Noop => conn.reply("250 2.0.0 OK").await?,
            Command::Rset => {
                if self.phase != Phase::Connected {
                    self.phase = Phase::Greeted;
                }
                self.tx = empty_tx();
                conn.reply("250 2.0.0 reset").await?;
            }
            Command::Ehlo(arg) => self.greeting(conn, arg, true).await?,
            Command::Helo(arg) => self.greeting(conn, arg, false).await?,
            Command::StartTls => {
                if self.tls_info.is_some() {
                    conn.reply("503 5.5.1 TLS already active").await?;
                } else if self.ctx.tls.is_none() {
                    conn.reply("502 5.5.1 STARTTLS not available").await?;
                } else {
                    conn.reply("220 2.0.0 Ready to start TLS").await?;
                    return Ok(Flow::StartTls);
                }
            }
            Command::Auth { mechanism, initial } => {
                return self.auth_start(conn, &mechanism, initial.as_deref()).await;
            }
            Command::AuthLine(_) => conn.reply("500 5.5.2 unexpected auth line").await?,
            Command::Mail { address, params } => return self.mail(conn, address, params).await,
            Command::Rcpt { address, params } => return self.rcpt(conn, address, params).await,
            Command::Data => return self.data(conn).await,
        }
        Ok(Flow::Continue)
    }

    async fn greeting(&mut self, conn: &mut Conn, arg: String, extended: bool) -> io::Result<()> {
        if arg.is_empty() {
            return conn
                .reply("501 5.5.4 a domain or address literal is required")
                .await;
        }
        self.helo = arg;
        self.phase = Phase::Greeted;
        self.tx = empty_tx();
        if extended {
            conn.reply(&ehlo_text(self.ctx, self.tls_info.is_some()))
                .await
        } else {
            conn.reply(&format!("250 {}", self.ctx.cfg.gateway.hostname))
                .await
        }
    }

    async fn upgrade(&mut self, io: BoxIo) -> io::Result<Conn> {
        let manager = self
            .ctx
            .tls
            .as_ref()
            .ok_or_else(|| io::Error::other("STARTTLS without a certificate"))?;
        let handshake = Duration::from_secs(self.limits.tls_handshake_timeout_secs);
        let stream = timeout(handshake, manager.acceptor().accept(io))
            .await
            .map_err(|_| {
                io::Error::new(io::ErrorKind::TimedOut, "STARTTLS handshake timed out")
            })??;
        self.tls_info = Some(tls_labels(stream.get_ref().1));
        // RFC 3207: forget everything learnt before the handshake.
        self.phase = Phase::Connected;
        self.tx = empty_tx();
        self.auth = self.trusted.clone();
        self.sasl = SaslState::Idle;
        self.sasl_done = false;
        self.helo.clear();
        Ok(Conn::new(BoxIo::new(stream), &self.limits))
    }

    async fn auth_start(
        &mut self,
        conn: &mut Conn,
        mechanism: &str,
        initial: Option<&str>,
    ) -> io::Result<Flow> {
        let refusal = match self.phase {
            Phase::Connected => Some("503 5.5.1 send EHLO first"),
            Phase::Mail | Phase::Rcpt => {
                Some("503 5.5.1 AUTH is not permitted during a mail transaction")
            }
            Phase::Greeted if self.sasl_done => Some("503 5.5.1 already authenticated"),
            Phase::Greeted if self.ctx.relay.auth_locked(self.ip) => {
                Some("454 4.7.0 too many failed authentication attempts, try again later")
            }
            Phase::Greeted => None,
        };
        if let Some(line) = refusal {
            conn.reply(line).await?;
            return Ok(Flow::Continue);
        }
        let (next_state, outcome) = auth_sasl::start(mechanism, initial, self.tls_info.is_some());
        self.sasl = next_state;
        self.apply_sasl(conn, outcome).await
    }

    async fn apply_sasl(&mut self, conn: &mut Conn, outcome: SaslOutcome) -> io::Result<Flow> {
        match outcome {
            SaslOutcome::Continue(line) => {
                conn.reply(&line).await?;
                Ok(Flow::Continue)
            }
            SaslOutcome::Failure(line) => {
                conn.reply(line).await?;
                if line.starts_with("535") {
                    return self.auth_failed(conn).await;
                }
                Ok(Flow::Continue)
            }
            SaslOutcome::Done { username, password } => {
                match self.ctx.relay.login(self.ip, username, password).await {
                    Login::Accepted(context) => {
                        self.auth = Some(context);
                        self.sasl_done = true;
                        conn.reply("235 2.7.0 authentication succeeded").await?;
                        Ok(Flow::Continue)
                    }
                    Login::Rejected => {
                        conn.reply("535 5.7.8 authentication failed").await?;
                        // `login` has already counted the source and username.
                        self.connection_failure(conn).await
                    }
                    Login::Locked => {
                        conn.reply(
                            "454 4.7.0 too many failed authentication attempts, try again later",
                        )
                        .await?;
                        self.connection_failure(conn).await
                    }
                    Login::Unavailable(err) => {
                        tracing::warn!(%err, "credential store unavailable");
                        conn.reply("454 4.7.0 authentication temporarily unavailable")
                            .await?;
                        Ok(Flow::Continue)
                    }
                }
            }
        }
    }

    async fn auth_failed(&mut self, conn: &mut Conn) -> io::Result<Flow> {
        self.ctx.relay.record_auth_failure(self.ip);
        self.connection_failure(conn).await
    }

    async fn connection_failure(&mut self, conn: &mut Conn) -> io::Result<Flow> {
        self.auth_failures += 1;
        if self.auth_failures >= MAX_AUTH_FAILURES {
            let _ = conn
                .reply("421 4.7.0 too many failed authentication attempts")
                .await;
            return Ok(Flow::Close);
        }
        Ok(Flow::Continue)
    }

    async fn mail(
        &mut self,
        conn: &mut Conn,
        address: String,
        params: Vec<(String, String)>,
    ) -> io::Result<Flow> {
        match self.phase {
            Phase::Connected => {
                conn.reply("503 5.5.1 send EHLO first").await?;
                return Ok(Flow::Continue);
            }
            Phase::Mail | Phase::Rcpt => {
                conn.reply("503 5.5.1 nested MAIL command").await?;
                return Ok(Flow::Continue);
            }
            Phase::Greeted => {}
        }
        if self.ctx.role == ListenerRole::Submission && self.auth.is_none() {
            conn.reply("530 5.7.0 authentication required").await?;
            return Ok(Flow::Continue);
        }
        if let Some(line) = mail_param_error(&params, self.limits.max_message_bytes) {
            if line.starts_with("552") {
                metrics::counter!(MESSAGES_REJECTED_TOTAL).increment(1);
            }
            conn.reply(line).await?;
            return Ok(Flow::Continue);
        }
        if let Some(context) = &self.auth {
            let owned = command::domain_of(&address)
                .is_some_and(|domain| self.ctx.relay.owns_domain(&context.tenant_id, domain));
            if !owned && !address.is_empty() {
                conn.reply("550 5.7.1 sender domain is not owned by this tenant")
                    .await?;
                metrics::counter!(MESSAGES_REJECTED_TOTAL).increment(1);
                return Ok(Flow::Continue);
            }
            // An SMTP AUTH login sends only as its own address or a listed alias,
            // so one user cannot borrow another user's identity and policies.
            if let Some(senders) = &context.senders {
                if !senders.contains(&address.to_ascii_lowercase()) {
                    conn.reply("553 5.7.1 sender address is not authorised for this login")
                        .await?;
                    metrics::counter!(MESSAGES_REJECTED_TOTAL).increment(1);
                    return Ok(Flow::Continue);
                }
            }
        } else {
            let result = self
                .ctx
                .checks
                .on_mail(&MailCtx {
                    ip: self.ip,
                    mail_from: address.clone(),
                })
                .await;
            if let Some(line) = check_reply(&result) {
                conn.reply(&line).await?;
                return Ok(close_on_421(&line));
            }
        }
        self.tx = Transaction {
            mail_from: address,
            rcpts: Vec::new(),
        };
        self.phase = Phase::Mail;
        conn.reply("250 2.1.0 OK").await?;
        Ok(Flow::Continue)
    }

    async fn rcpt(
        &mut self,
        conn: &mut Conn,
        address: String,
        params: Vec<(String, String)>,
    ) -> io::Result<Flow> {
        if self.phase != Phase::Mail && self.phase != Phase::Rcpt {
            conn.reply("503 5.5.1 need MAIL first").await?;
            return Ok(Flow::Continue);
        }
        if !params.is_empty() {
            conn.reply("555 5.5.4 RCPT parameters are not supported")
                .await?;
            return Ok(Flow::Continue);
        }
        if self.tx.rcpts.len() >= self.limits.max_recipients {
            conn.reply("452 4.5.3 too many recipients").await?;
            return Ok(Flow::Continue);
        }
        // RFC 5321 section 4.5.1: <postmaster> with no domain must be accepted.
        let address = if address.eq_ignore_ascii_case("postmaster") {
            match self.ctx.cfg.domains.accept.first() {
                Some(domain) => format!("postmaster@{domain}"),
                None => {
                    conn.reply("550 5.1.1 no postmaster here").await?;
                    return Ok(Flow::Continue);
                }
            }
        } else {
            address
        };
        let domain = command::domain_of(&address).unwrap_or("");
        let local = self
            .ctx
            .cfg
            .domains
            .accept
            .iter()
            .any(|item| item.eq_ignore_ascii_case(domain));
        if !local {
            let allowed = self.auth.as_ref().is_some_and(|context| {
                command::domain_of(&self.tx.mail_from)
                    .is_some_and(|from| self.ctx.relay.owns_domain(&context.tenant_id, from))
            });
            if !allowed {
                conn.reply("550 5.7.1 Relaying denied").await?;
                metrics::counter!(MESSAGES_REJECTED_TOTAL).increment(1);
                return Ok(Flow::Continue);
            }
        }
        if self.auth.is_none() {
            let result = self
                .ctx
                .checks
                .on_rcpt(&RcptCtx {
                    ip: self.ip,
                    mail_from: self.tx.mail_from.clone(),
                    recipient: address.clone(),
                })
                .await;
            if let Some(line) = check_reply(&result) {
                conn.reply(&line).await?;
                return Ok(close_on_421(&line));
            }
        }
        self.tx.rcpts.push(address);
        self.phase = Phase::Rcpt;
        conn.reply("250 2.1.5 OK").await?;
        Ok(Flow::Continue)
    }

    /// Stream the body to the spool. Nothing is buffered beyond one line.
    async fn data(&mut self, conn: &mut Conn) -> io::Result<Flow> {
        if self.phase != Phase::Rcpt || self.tx.rcpts.is_empty() {
            conn.reply("503 5.5.1 need RCPT first").await?;
            return Ok(Flow::Continue);
        }
        let needed = self
            .limits
            .spool_min_free_bytes
            .max(self.limits.max_message_bytes);
        if free_bytes(self.ctx.spool.root()).is_some_and(|free| free < needed) {
            tracing::warn!("spool is low on space; deferring DATA");
            conn.reply("452 4.3.1 insufficient system storage").await?;
            return Ok(Flow::Continue);
        }
        let id = Envelope::new_id();
        let mut body = match self.ctx.spool.begin(&id).await {
            Ok(body) => body,
            Err(err) => {
                tracing::error!(%err, "spool unavailable");
                conn.reply("451 4.3.0 spool unavailable").await?;
                return Ok(Flow::Continue);
            }
        };
        conn.reply("354 start mail input; end with <CRLF>.<CRLF>")
            .await?;
        let max_bytes = self.limits.max_message_bytes as usize;
        // After the limit is hit the rest is read and thrown away, but only
        // up to another message's worth; then the connection is dropped.
        let drain_limit = max_bytes.max(1024 * 1024);
        let deadline =
            tokio::time::Instant::now() + Duration::from_secs(self.limits.data_timeout_secs);
        let mut size = 0usize;
        let mut drained = 0usize;
        let mut too_large = false;
        let mut spool_failed = false;
        // In the header section each field (with its folded lines) is held
        // until the next one starts, so forged Authentication-Results can be
        // removed before anything is spooled while memory stays at one field.
        let authserv_id = &self.ctx.cfg.auth.authserv_id;
        let mut in_header = true;
        let mut field: Vec<u8> = Vec::new();
        loop {
            let Ok(next) = tokio::time::timeout_at(deadline, conn.line()).await else {
                metrics::counter!(MESSAGES_REJECTED_TOTAL).increment(1);
                let _ = conn
                    .reply("421 4.4.2 DATA took too long, closing connection")
                    .await;
                return Ok(Flow::Close);
            };
            let line = match next {
                Ok(Line::Crlf(line)) => line,
                Ok(Line::BareLf(_)) => return refuse_bare_newline(conn).await,
                Ok(Line::TooLong) => {
                    metrics::counter!(MESSAGES_REJECTED_TOTAL).increment(1);
                    let _ = conn.reply("500 5.5.2 line too long").await;
                    return Ok(Flow::Close);
                }
                Ok(Line::Eof) => return Ok(Flow::Close),
                Err(err) => return timed_out(conn, err).await,
            };
            match unstuff(&line, size, self.limits.max_line_bytes, max_bytes) {
                Ok(None) => break,
                Ok(Some(_)) | Err(LineDecision::TooLarge) if too_large => {
                    drained += line.len() + 2;
                    if drained > drain_limit {
                        metrics::counter!(MESSAGES_REJECTED_TOTAL).increment(1);
                        let _ = conn.reply("552 5.3.4 message size exceeds limit").await;
                        return Ok(Flow::Close);
                    }
                }
                Ok(Some(_)) if spool_failed => {}
                Ok(Some(chunk)) => {
                    size += chunk.len() + 2;
                    let folded = chunk.first().is_some_and(|b| *b == b' ' || *b == b'\t');
                    let written = if in_header && folded {
                        field.extend_from_slice(chunk);
                        field.extend_from_slice(b"\r\n");
                        Ok(())
                    } else if in_header {
                        let held = std::mem::take(&mut field);
                        let flushed = body
                            .write(&currawong_auth::strip_forged(&held, authserv_id))
                            .await;
                        if chunk.is_empty() {
                            in_header = false;
                            match flushed {
                                Ok(()) => body.write(b"\r\n").await,
                                Err(err) => Err(err),
                            }
                        } else {
                            field.extend_from_slice(chunk);
                            field.extend_from_slice(b"\r\n");
                            flushed
                        }
                    } else {
                        match body.write(chunk).await {
                            Ok(()) => body.write(b"\r\n").await,
                            Err(err) => Err(err),
                        }
                    };
                    if let Err(err) = written {
                        tracing::error!(%err, "spool write failed");
                        spool_failed = true;
                    }
                }
                Err(LineDecision::TooLarge) => too_large = true,
                Err(LineDecision::BareNewline) => return refuse_bare_newline(conn).await,
                Err(_) => {
                    metrics::counter!(MESSAGES_REJECTED_TOTAL).increment(1);
                    let _ = conn.reply("500 5.5.2 line too long").await;
                    return Ok(Flow::Close);
                }
            }
        }
        self.phase = Phase::Greeted;
        let tx = std::mem::replace(&mut self.tx, empty_tx());
        if too_large {
            metrics::counter!(MESSAGES_REJECTED_TOTAL).increment(1);
            conn.reply("552 5.3.4 message size exceeds limit").await?;
            return Ok(Flow::Continue);
        }
        // The last field of a message with no blank line is still held.
        if !field.is_empty() {
            if let Err(err) = body
                .write(&currawong_auth::strip_forged(&field, authserv_id))
                .await
            {
                tracing::error!(%err, "spool write failed");
                spool_failed = true;
            }
        }
        if spool_failed {
            conn.reply("451 4.3.0 spool unavailable").await?;
            return Ok(Flow::Continue);
        }
        let env = Envelope {
            id,
            tenant_id: self.auth.as_ref().map(|item| item.tenant_id.clone()),
            authenticated_as: self
                .auth
                .as_ref()
                .filter(|item| item.senders.is_some())
                .map(|item| item.principal.clone()),
            mail_from: tx.mail_from,
            rcpt_to: tx.rcpts,
            received_at: OffsetDateTime::now_utc(),
            remote_ip: self.ip,
            helo: self.helo.clone(),
            attempts: 0,
            next_attempt_at: None,
            state: SpoolState::Incoming,
            // Trusted and authenticated senders are ours, whoever they write to.
            direction: if self.auth.is_some() {
                Direction::Outbound
            } else {
                Direction::Inbound
            },
            tls_version: self.tls_info.as_ref().map(|(v, _)| v.clone()),
            tls_cipher: self.tls_info.as_ref().map(|(_, c)| c.clone()),
            rcpt_status: Vec::new(),
            prepend_headers: Vec::new(),
            dsn_sent: false,
            tls: Default::default(),
            pipeline: "pending".into(),
        };
        match self.ctx.spool.commit(body, env).await {
            Ok(stored) => {
                tracing::info!(message_id = %stored, "message spooled");
                metrics::counter!(MESSAGES_ACCEPTED_TOTAL).increment(1);
                conn.reply(&format!("250 2.0.0 OK {stored}")).await?;
            }
            Err(err) => {
                tracing::error!(%err, "spool accept failed");
                conn.reply("451 4.3.0 spool unavailable").await?;
            }
        }
        Ok(Flow::Continue)
    }
}

/// Bytes free to unprivileged users on the file system holding `path`.
#[cfg(unix)]
fn free_bytes(path: &std::path::Path) -> Option<u64> {
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    // SAFETY: `path` is a valid C string and `stat` is a writable statvfs.
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(path.as_ptr(), &mut stat) } != 0 {
        return None;
    }
    #[allow(clippy::unnecessary_cast)]
    Some((stat.f_bavail as u64).saturating_mul(stat.f_frsize as u64))
}

#[cfg(not(unix))]
fn free_bytes(_path: &std::path::Path) -> Option<u64> {
    None
}

/// A bare CR or LF in DATA ends the session: reading on would let the rest
/// of the stream be taken as commands (SMTP smuggling).
async fn refuse_bare_newline(conn: &mut Conn) -> io::Result<Flow> {
    metrics::counter!(MESSAGES_REJECTED_TOTAL).increment(1);
    let _ = conn
        .reply("554 5.5.2 message refused: bare CR or LF is not permitted")
        .await;
    Ok(Flow::Close)
}

async fn timed_out(conn: &mut Conn, err: io::Error) -> io::Result<Flow> {
    if err.kind() == io::ErrorKind::TimedOut {
        let _ = conn.reply("421 4.4.2 timeout, closing connection").await;
        return Ok(Flow::Close);
    }
    Err(err)
}

/// RFC 1870 SIZE, RFC 6152 BODY, RFC 6531 SMTPUTF8 and RFC 4954 AUTH.
fn mail_param_error(params: &[(String, String)], max_bytes: u64) -> Option<&'static str> {
    for (key, value) in params {
        match key.as_str() {
            "SIZE" => match value.parse::<u64>() {
                Ok(size) if size > max_bytes => {
                    return Some("552 5.3.4 message size exceeds limit")
                }
                Ok(_) => {}
                Err(_) => return Some("501 5.5.4 invalid SIZE value"),
            },
            "BODY" => {
                if !value.eq_ignore_ascii_case("7BIT") && !value.eq_ignore_ascii_case("8BITMIME") {
                    return Some("501 5.5.4 invalid BODY value");
                }
            }
            "SMTPUTF8" if value.is_empty() => {}
            "AUTH" => {}
            _ => return Some("555 5.5.4 unsupported MAIL parameter"),
        }
    }
    None
}

fn check_reply(result: &CheckResult) -> Option<String> {
    match result {
        CheckResult::Pass | CheckResult::Score(_) => None,
        CheckResult::TempFail(line) | CheckResult::Reject(line) => Some(line.clone()),
    }
}

fn close_on_421(line: &str) -> Flow {
    if line.starts_with("421") {
        Flow::Close
    } else {
        Flow::Continue
    }
}

fn ehlo_text(ctx: &SessionContext, tls_on: bool) -> String {
    let mut lines = vec![
        ctx.cfg.gateway.hostname.clone(),
        format!("SIZE {}", ctx.cfg.limits.max_message_bytes),
        "8BITMIME".into(),
        "PIPELINING".into(),
        "ENHANCEDSTATUSCODES".into(),
        "SMTPUTF8".into(),
    ];
    if !tls_on && ctx.tls.is_some() {
        lines.push("STARTTLS".into());
    }
    if tls_on {
        lines.push("AUTH PLAIN LOGIN".into());
    }
    let last = lines.len() - 1;
    lines
        .iter()
        .enumerate()
        .map(|(n, line)| format!("250{}{line}\r\n", if n == last { ' ' } else { '-' }))
        .collect()
}

fn empty_tx() -> Transaction {
    Transaction {
        mail_from: String::new(),
        rcpts: Vec::new(),
    }
}
