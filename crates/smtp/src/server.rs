//! SMTP listeners. Tests bind port 0; nothing in the suite binds port 25.
use crate::{
    limits::ConnectionLimits,
    session::{run_session, SessionContext},
    stream::{BoxIo, SmtpStream},
    tls::{tls_labels, TlsManager},
};
use currawong_core::config::{Config, ListenerConfig, ListenerMode};
use std::{future::Future, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    net::{TcpListener, TcpStream},
    task::JoinSet,
};
use tokio_util::sync::CancellationToken;

/// Pause after a failed `accept()` (for example EMFILE) before trying again.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);
/// How long in-flight sessions get to finish after shutdown.
const DRAIN: Duration = Duration::from_secs(30);

/// Source of inbound connections. `TcpListener` in production.
pub trait Accept: Send + Sync {
    fn accept(&self) -> impl Future<Output = std::io::Result<(TcpStream, SocketAddr)>> + Send;
}

impl Accept for TcpListener {
    fn accept(&self) -> impl Future<Output = std::io::Result<(TcpStream, SocketAddr)>> + Send {
        TcpListener::accept(self)
    }
}

pub struct SmtpServer {
    pub ctx: Arc<SessionContext>,
    pub limits: Arc<ConnectionLimits>,
}

impl SmtpServer {
    pub fn new(ctx: Arc<SessionContext>) -> Self {
        let limits = ConnectionLimits::new(
            ctx.cfg.limits.max_connections,
            ctx.cfg.limits.max_connections_per_ip as u32,
        );
        Self { ctx, limits }
    }

    /// Share one set of connection caps between listeners, so the per-IP and
    /// process-wide limits hold across ports 25, 587 and 465 together.
    pub fn with_limits(ctx: Arc<SessionContext>, limits: Arc<ConnectionLimits>) -> Self {
        Self { ctx, limits }
    }

    pub async fn run(self, listener: impl Accept, shutdown: CancellationToken, mode: ListenerMode) {
        let mut tasks = JoinSet::new();
        loop {
            let accepted = tokio::select! {
                _ = shutdown.cancelled() => break,
                accepted = listener.accept() => accepted,
            };
            let (mut sock, peer) = match accepted {
                Ok(pair) => pair,
                Err(err) => {
                    tracing::warn!(%err, "accept failed; retrying");
                    tokio::select! {
                        _ = shutdown.cancelled() => break,
                        _ = tokio::time::sleep(ACCEPT_BACKOFF) => continue,
                    }
                }
            };
            let peer = SocketAddr::new(peer.ip().to_canonical(), peer.port());
            let Some(guard) = self.limits.try_acquire(peer.ip()) else {
                let _ = tokio::time::timeout(
                    Duration::from_secs(1),
                    tokio::io::AsyncWriteExt::write_all(
                        &mut sock,
                        b"421 4.7.0 too many connections\r\n",
                    ),
                )
                .await;
                continue;
            };
            let ctx = Arc::clone(&self.ctx);
            let shutdown = shutdown.clone();
            let mode = mode.clone();
            tasks.spawn(async move {
                let _guard = guard;
                let handshake = Duration::from_secs(ctx.cfg.limits.tls_handshake_timeout_secs);
                let (io, tls_info) = match accept_io(sock, mode, ctx.tls.as_ref(), handshake).await
                {
                    Ok(pair) => pair,
                    Err(err) => {
                        tracing::debug!(%err, %peer, "connection setup failed");
                        return;
                    }
                };
                run_session(io, peer, ctx, shutdown, tls_info).await;
            });
            // Reap finished sessions so the set does not grow for ever.
            while tasks.try_join_next().is_some() {}
        }
        let _ =
            tokio::time::timeout(DRAIN, async { while tasks.join_next().await.is_some() {} }).await;
    }
}

async fn accept_io(
    sock: TcpStream,
    mode: ListenerMode,
    tls: Option<&Arc<TlsManager>>,
    handshake: Duration,
) -> std::io::Result<(BoxIo, Option<(String, String)>)> {
    match mode {
        ListenerMode::Implicit => {
            let manager =
                tls.ok_or_else(|| std::io::Error::other("implicit TLS requires a certificate"))?;
            let stream = tokio::time::timeout(handshake, manager.acceptor().accept(sock))
                .await
                .map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::TimedOut, "TLS handshake timed out")
                })??;
            let info = tls_labels(stream.get_ref().1);
            Ok((BoxIo::new(stream), Some(info)))
        }
        ListenerMode::Plain | ListenerMode::Starttls => {
            Ok((BoxIo::new(SmtpStream::plain(sock)), None))
        }
    }
}

pub fn listener_mode(cfg: &Config, name: &str) -> Option<ListenerConfig> {
    cfg.listeners.iter().find(|item| item.name == name).cloned()
}
