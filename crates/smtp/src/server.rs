//! SMTP listeners. Tests bind port 0; nothing in the suite binds port 25.
use crate::{
    limits::ConnectionLimits,
    session::{run_session, SessionContext},
    stream::{BoxIo, SmtpStream},
    tls::{tls_labels, TlsManager},
};
use currawong_core::config::{Config, ListenerConfig, ListenerMode};
use std::{sync::Arc, time::Duration};
use tokio::{net::TcpListener, task::JoinSet};
use tokio_util::sync::CancellationToken;

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

    pub async fn run(self, listener: TcpListener, shutdown: CancellationToken, mode: ListenerMode) {
        let mut tasks = JoinSet::new();
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => break,
                accepted = listener.accept() => {
                    let Ok((mut sock, peer)) = accepted else { break };
                    let Some(guard) = self.limits.try_acquire(peer.ip()) else {
                        let _ = tokio::io::AsyncWriteExt::write_all(&mut sock, b"421 4.7.0 too many connections\r\n").await;
                        continue;
                    };
                    let ctx = Arc::clone(&self.ctx);
                    let shutdown = shutdown.clone();
                    let tls = ctx.tls.clone();
                    let mode = mode.clone();
                    tasks.spawn(async move {
                        let _guard = guard;
                        let io = match accept_io(sock, mode, tls.as_ref()).await {
                            Ok((io, tls_info)) => (io, tls_info),
                            Err(err) => {
                                tracing::debug!(%err, "connection setup failed");
                                return;
                            }
                        };
                        run_session(io.0, peer, ctx, shutdown, io.1).await;
                    });
                }
            }
        }
        let _ = tokio::time::timeout(Duration::from_secs(30), async {
            while tasks.join_next().await.is_some() {}
        })
        .await;
    }
}

async fn accept_io(
    sock: tokio::net::TcpStream,
    mode: ListenerMode,
    tls: Option<&Arc<TlsManager>>,
) -> std::io::Result<(BoxIo, Option<(String, String)>)> {
    match mode {
        ListenerMode::Implicit => {
            let manager =
                tls.ok_or_else(|| std::io::Error::other("implicit TLS requires a certificate"))?;
            let stream = manager.acceptor().accept(sock).await?;
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
