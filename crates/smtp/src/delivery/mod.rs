//! Outbound delivery, retries and DSNs.
mod dsn;
pub mod route;

use crate::dns::DnsLookup;
pub use dsn::build_dsn;
pub use route::resolve_route;

use currawong_core::config::Config;
use currawong_spool::{next_retry, Envelope, Spool, SpoolState};
use mail_send::SmtpClientBuilder;
use std::{net::SocketAddr, sync::Arc, time::Duration};
use time::OffsetDateTime;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
    time::Instant,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliveryOutcome {
    Delivered,
    TempFail(String),
    PermFail(String),
}

#[derive(Clone)]
pub struct TokioClock {
    start_instant: Instant,
    start_wall: OffsetDateTime,
}

impl TokioClock {
    pub fn new() -> Self {
        Self {
            start_instant: Instant::now(),
            start_wall: OffsetDateTime::now_utc(),
        }
    }

    pub fn now(&self) -> OffsetDateTime {
        let elapsed = self.start_instant.elapsed();
        self.start_wall + time::Duration::try_from(elapsed).unwrap_or(time::Duration::ZERO)
    }
}

impl Default for TokioClock {
    fn default() -> Self {
        Self::new()
    }
}

pub struct Deliverer<D: DnsLookup> {
    pub spool: Arc<Spool>,
    pub cfg: Arc<Config>,
    pub dns: Arc<D>,
    pub clock: TokioClock,
}

impl<D: DnsLookup> Deliverer<D> {
    pub fn new(spool: Arc<Spool>, cfg: Arc<Config>, dns: Arc<D>) -> Self {
        Self {
            spool,
            cfg,
            dns,
            clock: TokioClock::new(),
        }
    }

    pub async fn deliver(&self, id: &currawong_core::MessageId) -> Result<DeliveryOutcome, String> {
        let mut env = self.spool.load(id).await.map_err(|err| err.to_string())?;
        let body = self
            .spool
            .read_body(id)
            .await
            .map_err(|err| err.to_string())?;
        let max_age = Duration::from_secs(self.cfg.delivery.max_age_days.saturating_mul(86_400));
        let age = self.clock.now() - env.received_at;
        if age > time::Duration::try_from(max_age).unwrap_or(time::Duration::days(5)) {
            return self
                .finish_permanent(&mut env, &body, "message expired after 5 days")
                .await;
        }
        let pending: Vec<String> = if env.rcpt_status.is_empty() {
            env.rcpt_to.clone()
        } else {
            env.rcpt_status
                .iter()
                .filter(|status| status.status == "pending" || status.status == "temp")
                .map(|status| status.address.clone())
                .collect()
        };
        if pending.is_empty() {
            self.spool
                .transition(id, SpoolState::Done)
                .await
                .map_err(|err| err.to_string())?;
            return Ok(DeliveryOutcome::Delivered);
        }
        let mut groups: Vec<(String, Vec<String>)> = Vec::new();
        for rcpt in pending {
            let domain = rcpt
                .rsplit_once('@')
                .map(|(_, d)| d.to_ascii_lowercase())
                .unwrap_or_default();
            if let Some(group) = groups.iter_mut().find(|item| item.0 == domain) {
                group.1.push(rcpt);
            } else {
                groups.push((domain, vec![rcpt]));
            }
        }
        let mut any_temp = false;
        let mut any_perm = false;
        let mut temp_detail = String::new();
        let mut perm_detail = String::new();
        let mut perm_rcpts = Vec::new();
        for (domain, rcpts) in groups {
            let outcome = self.deliver_domain(&env, &body, &domain, &rcpts).await;
            match outcome {
                DeliveryOutcome::Delivered => {
                    for rcpt in rcpts {
                        set_status(&mut env, &rcpt, "delivered", "250");
                    }
                }
                DeliveryOutcome::TempFail(detail) => {
                    any_temp = true;
                    temp_detail = detail.clone();
                    for rcpt in rcpts {
                        set_status(&mut env, &rcpt, "temp", &detail);
                    }
                }
                DeliveryOutcome::PermFail(detail) => {
                    any_perm = true;
                    perm_detail = detail.clone();
                    perm_rcpts.extend(rcpts.iter().cloned());
                    for rcpt in rcpts {
                        set_status(&mut env, &rcpt, "perm", &detail);
                    }
                }
            }
        }
        if any_temp {
            env.attempts = env.attempts.saturating_add(1);
            let wait = next_retry(env.attempts);
            env.next_attempt_at = Some(
                self.clock.now()
                    + time::Duration::try_from(wait).unwrap_or(time::Duration::minutes(5)),
            );
            env.state = if env.state == SpoolState::Incoming {
                SpoolState::Incoming
            } else {
                env.state
            };
            self.spool
                .update(&env)
                .await
                .map_err(|err| err.to_string())?;
            if env.state != SpoolState::Deferred {
                self.spool
                    .transition(&env.id, SpoolState::Deferred)
                    .await
                    .map_err(|err| err.to_string())?;
            }
            return Ok(DeliveryOutcome::TempFail(temp_detail));
        }
        if any_perm {
            return self.finish_permanent(&mut env, &body, &perm_detail).await;
        }
        let _ = perm_rcpts;
        self.spool
            .update(&env)
            .await
            .map_err(|err| err.to_string())?;
        self.spool
            .transition(&env.id, SpoolState::Done)
            .await
            .map_err(|err| err.to_string())?;
        Ok(DeliveryOutcome::Delivered)
    }

    async fn finish_permanent(
        &self,
        env: &mut Envelope,
        body: &[u8],
        detail: &str,
    ) -> Result<DeliveryOutcome, String> {
        if !env.dsn_sent && !is_null_sender(&env.mail_from) {
            let dsn = build_dsn(&self.cfg.gateway.hostname, env, body, detail);
            let dsn_env = Envelope {
                id: Envelope::new_id(),
                tenant_id: env.tenant_id.clone(),
                mail_from: String::new(),
                rcpt_to: vec![env.mail_from.clone()],
                received_at: self.clock.now(),
                remote_ip: "127.0.0.1".parse().unwrap(),
                helo: self.cfg.gateway.hostname.clone(),
                attempts: 0,
                next_attempt_at: None,
                state: SpoolState::Incoming,
                direction: currawong_core::Direction::Inbound,
                tls_version: None,
                tls_cipher: None,
                rcpt_status: Vec::new(),
                prepend_headers: Vec::new(),
                dsn_sent: true,
                pipeline: "pending".into(),
            };
            self.spool
                .accept(dsn_env, std::io::Cursor::new(dsn))
                .await
                .map_err(|err| err.to_string())?;
            env.dsn_sent = true;
        }
        self.spool
            .update(env)
            .await
            .map_err(|err| err.to_string())?;
        if env.state != SpoolState::Done {
            self.spool
                .transition(&env.id, SpoolState::Done)
                .await
                .map_err(|err| err.to_string())?;
        }
        Ok(DeliveryOutcome::PermFail(detail.to_string()))
    }

    async fn deliver_domain(
        &self,
        env: &Envelope,
        body: &[u8],
        domain: &str,
        rcpts: &[String],
    ) -> DeliveryOutcome {
        let routes = match resolve_route(domain, &self.cfg, self.dns.as_ref()).await {
            Ok(routes) if !routes.is_empty() => routes,
            Ok(_) => return DeliveryOutcome::TempFail(format!("no route for {domain}")),
            Err(err) => return DeliveryOutcome::TempFail(err),
        };
        let mut last_temp = format!("no route accepted mail for {domain}");
        for addr in routes {
            match smtp_send(&self.cfg.gateway.hostname, addr, env, body, rcpts).await {
                Ok(outcome @ DeliveryOutcome::Delivered) => return outcome,
                Ok(DeliveryOutcome::PermFail(detail)) => return DeliveryOutcome::PermFail(detail),
                Ok(DeliveryOutcome::TempFail(detail)) => last_temp = detail,
                Err(err) => last_temp = err,
            }
        }
        DeliveryOutcome::TempFail(last_temp)
    }

    pub async fn poll_due(&self) -> Result<(), String> {
        let now = self.clock.now();
        for state in [SpoolState::Incoming, SpoolState::Deferred] {
            let items = self
                .spool
                .list(state)
                .await
                .map_err(|err| err.to_string())?;
            for env in items {
                if env.dsn_sent && is_null_sender(&env.mail_from) && state == SpoolState::Done {
                    continue;
                }
                let due = env.next_attempt_at.map(|at| at <= now).unwrap_or(true);
                if due {
                    let _ = self.deliver(&env.id).await?;
                }
            }
        }
        Ok(())
    }
}

fn set_status(env: &mut Envelope, rcpt: &str, status: &str, detail: &str) {
    if let Some(existing) = env.rcpt_status.iter_mut().find(|item| item.address == rcpt) {
        existing.status = status.into();
        existing.detail = detail.into();
    } else {
        env.rcpt_status.push(currawong_spool::RcptStatus {
            address: rcpt.into(),
            status: status.into(),
            detail: detail.into(),
        });
    }
}

pub fn is_null_sender(mail_from: &str) -> bool {
    let trimmed = mail_from.trim();
    trimmed.is_empty() || trimmed == "<>"
}

fn received_header(env: &Envelope, hostname: &str) -> String {
    let tls = match &env.tls_version {
        Some(version) => format!(
            "\r\n\t(using {version} with cipher {})",
            env.tls_cipher.as_deref().unwrap_or("unknown")
        ),
        None => String::new(),
    };
    let date = env
        .received_at
        .format(&time::format_description::well_known::Rfc2822)
        .unwrap_or_else(|_| "Thu, 01 Jan 1970 00:00:00 +0000".into());
    format!(
        "Received: from {} ([{}]) by {} with ESMTP id {}{tls};\r\n\t{date}\r\n",
        sanitise_token(&env.helo),
        env.remote_ip,
        hostname,
        env.id
    )
}

fn sanitise_token(value: &str) -> String {
    value
        .chars()
        .map(|ch| if ch.is_ascii_graphic() { ch } else { '_' })
        .collect()
}

pub fn outbound_bytes(env: &Envelope, body: &[u8], hostname: &str) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(received_header(env, hostname).as_bytes());
    for header in &env.prepend_headers {
        out.extend_from_slice(header.as_bytes());
        if !header.ends_with("\r\n") {
            out.extend_from_slice(b"\r\n");
        }
    }
    out.extend_from_slice(body);
    out
}

async fn smtp_send(
    hostname: &str,
    addr: SocketAddr,
    env: &Envelope,
    body: &[u8],
    rcpts: &[String],
) -> Result<DeliveryOutcome, String> {
    // mail-send builds a client (TLS provider included). The raw transaction
    // is spoken on our own socket so the original bytes, plus our headers,
    // are preserved.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let _builder = SmtpClientBuilder::new(addr.ip().to_string(), addr.port()).implicit_tls(false);
    let mut stream = TcpStream::connect(addr)
        .await
        .map_err(|err| format!("connect {addr}: {err}"))?;
    stream.set_nodelay(true).map_err(|err| err.to_string())?;
    let (read, mut write) = stream.split();
    let mut read = BufReader::new(read);
    let greeting = read_reply(&mut read).await?;
    if greeting.code >= 400 {
        return Ok(classify(greeting));
    }
    write
        .write_all(format!("EHLO {hostname}\r\n").as_bytes())
        .await
        .map_err(|err| err.to_string())?;
    let ehlo = read_reply(&mut read).await?;
    if ehlo.code >= 400 {
        return Ok(classify(ehlo));
    }
    let from = if is_null_sender(&env.mail_from) {
        "<>".to_string()
    } else {
        format!("<{}>", env.mail_from)
    };
    write
        .write_all(format!("MAIL FROM:{from}\r\n").as_bytes())
        .await
        .map_err(|err| err.to_string())?;
    let mail = read_reply(&mut read).await?;
    if mail.code >= 400 {
        return Ok(classify(mail));
    }
    for rcpt in rcpts {
        write
            .write_all(format!("RCPT TO:<{rcpt}>\r\n").as_bytes())
            .await
            .map_err(|err| err.to_string())?;
        let reply = read_reply(&mut read).await?;
        if reply.code >= 400 {
            return Ok(classify(reply));
        }
    }
    write
        .write_all(b"DATA\r\n")
        .await
        .map_err(|err| err.to_string())?;
    let data = read_reply(&mut read).await?;
    if data.code >= 400 {
        return Ok(classify(data));
    }
    let bytes = outbound_bytes(env, body, hostname);
    write
        .write_all(&dot_stuff(&bytes))
        .await
        .map_err(|err| err.to_string())?;
    write
        .write_all(b"\r\n.\r\n")
        .await
        .map_err(|err| err.to_string())?;
    let end = read_reply(&mut read).await?;
    let _ = write.write_all(b"QUIT\r\n").await;
    Ok(classify(end))
}

struct SmtpReply {
    code: u16,
    text: String,
}

fn classify(reply: SmtpReply) -> DeliveryOutcome {
    if (200..300).contains(&reply.code) {
        DeliveryOutcome::Delivered
    } else if (400..500).contains(&reply.code) {
        DeliveryOutcome::TempFail(format!("{} {}", reply.code, reply.text))
    } else {
        DeliveryOutcome::PermFail(format!("{} {}", reply.code, reply.text))
    }
}

async fn read_reply(
    read: &mut BufReader<tokio::net::tcp::ReadHalf<'_>>,
) -> Result<SmtpReply, String> {
    let mut line = String::new();
    let mut code;
    let mut text = String::new();
    loop {
        line.clear();
        let n = read
            .read_line(&mut line)
            .await
            .map_err(|err| err.to_string())?;
        if n == 0 {
            return Err("smtp connection closed".into());
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.len() < 3 {
            return Err(format!("short smtp reply: {trimmed}"));
        }
        code = trimmed[..3]
            .parse()
            .map_err(|_| format!("bad smtp code: {trimmed}"))?;
        if trimmed.len() > 4 {
            if !text.is_empty() {
                text.push(' ');
            }
            text.push_str(trimmed[4..].trim());
        }
        let cont = trimmed.as_bytes().get(3).copied() == Some(b'-');
        if !cont {
            break;
        }
    }
    Ok(SmtpReply { code, text })
}

fn dot_stuff(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len() + 8);
    let mut at_line = true;
    for &byte in bytes {
        if at_line && byte == b'.' {
            out.push(b'.');
        }
        out.push(byte);
        at_line = byte == b'\n';
    }
    out
}
