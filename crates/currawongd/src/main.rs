//! currawongd: SMTP listeners, the scan pipeline and outbound delivery.
use clap::Parser;
use currawong_auth::AuthChecker;
use currawong_core::residency::{load_or_create_signing_key, sign_report, ResidencyGuard};
use currawong_smtp::{
    checks::CheckStack, delivery::Deliverer, dns::HickoryDns, relay::Relay, server::SmtpServer,
    session::SessionContext, tls::TlsManager,
};
use currawong_spool::Spool;
use currawongd::{check_config, checks_for, classify_pending, Pipeline};
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

#[derive(Parser)]
#[command(name = "currawongd")]
struct Args {
    /// Path to the TOML configuration.
    #[arg(long, default_value = "/etc/currawong/currawong.toml")]
    config: PathBuf,
    /// Load and validate the configuration, then exit.
    #[arg(long)]
    check_config: bool,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let cfg = match check_config(&args.config) {
        Ok(cfg) => cfg,
        Err(err) => {
            eprintln!("currawongd: {err}");
            std::process::exit(1);
        }
    };
    if args.check_config {
        println!("configuration ok");
        return;
    }
    currawongd::install_tracing(&cfg);
    if let Err(err) = run(cfg).await {
        tracing::error!(%err, "currawongd stopped");
        std::process::exit(1);
    }
}

async fn run(cfg: currawong_core::Config) -> Result<(), String> {
    let guard = ResidencyGuard::from_config(&cfg.residency).map_err(|err| err.to_string())?;
    guard
        .enforce_startup(&cfg.residency.content_endpoints)
        .map_err(|err| err.to_string())?;
    if let Some(key_path) = &cfg.residency.signing_key_path {
        let key = load_or_create_signing_key(key_path).map_err(|err| err.to_string())?;
        let report = guard.report("startup", &cfg.residency.content_endpoints);
        let signed = sign_report(report, &key);
        tokio::fs::create_dir_all(&cfg.residency.report_dir)
            .await
            .map_err(|err| err.to_string())?;
        let path = cfg.residency.report_dir.join("residency-report.json");
        let body = serde_json::to_vec_pretty(&signed).map_err(|err| err.to_string())?;
        tokio::fs::write(path, body)
            .await
            .map_err(|err| err.to_string())?;
    }
    let cfg = Arc::new(cfg);
    let spool = Arc::new(
        Spool::open(&cfg.spool.dir)
            .await
            .map_err(|err| err.to_string())?,
    );
    spool.recover().await.map_err(|err| err.to_string())?;
    let tls = match (&cfg.tls.cert, &cfg.tls.key) {
        (Some(cert), Some(key)) => Some(Arc::new(
            TlsManager::load(cert, key).map_err(|err| err.to_string())?,
        )),
        _ => None,
    };
    let dns = HickoryDns::system().map_err(|err| err.to_string())?;
    let checks = Arc::new(
        CheckStack::from_checks(&cfg.checks, Arc::new(dns)).map_err(|err| err.to_string())?,
    );
    let relay = Arc::new(
        Relay::open(&cfg.relay.database, &cfg.relay.tenants).map_err(|err| err.to_string())?,
    );
    let shutdown = CancellationToken::new();
    let mut listeners = Vec::new();
    for listener in &cfg.listeners {
        let bound = TcpListener::bind(&listener.bind)
            .await
            .map_err(|err| format!("{}: {err}", listener.bind))?;
        tracing::info!(name = %listener.name, bind = %listener.bind, "smtp listening");
        listeners.push((bound, listener.mode.clone(), listener.role.clone()));
    }
    currawong_core::telemetry::serve(
        cfg.metrics_addr().map_err(|err| err.to_string())?,
        checks_for(&cfg),
    );
    let auth = AuthChecker::new(&cfg.auth.authserv_id)?;
    let mut pipeline = Pipeline::new(Arc::clone(&cfg), auth);
    pipeline.reload_policies().await?;
    tracing::info!(count = pipeline.policies.policies.len(), "policies loaded");
    let quarantine = currawong_quarantine::QuarantineStore::open(cfg.spool.dir.join("quarantine"))
        .map_err(|err| err.to_string())?;
    // DANE needs DNSSEC-validated answers for MX, address and TLSA lookups.
    let delivery_dns = if cfg.delivery.dane {
        HickoryDns::validating()
    } else {
        HickoryDns::system()
    };
    let deliverer = Arc::new(Deliverer::new(
        Arc::clone(&spool),
        Arc::clone(&cfg),
        Arc::new(delivery_dns.map_err(|err| err.to_string())?),
    ));
    let poll = Duration::from_secs(cfg.delivery.poll_secs.max(1));
    // Classification, delivery and TLS-RPT each run on their own loop, so a
    // slow or failing one cannot hold up the others.
    let pipeline = Arc::new(tokio::sync::Mutex::new((pipeline, quarantine)));
    let spool_loop = Arc::clone(&spool);
    every("pipeline", poll, shutdown.clone(), move || {
        let pipeline = Arc::clone(&pipeline);
        let spool = Arc::clone(&spool_loop);
        async move {
            let mut guard = pipeline.lock().await;
            let (pipeline, quarantine) = &mut *guard;
            match pipeline.reload_policies().await {
                Ok(true) => tracing::info!("policies reloaded"),
                Ok(false) => {}
                Err(err) => {
                    tracing::error!(%err, "policy reload failed, keeping the previous policies")
                }
            }
            classify_pending(&spool, pipeline, quarantine).await
        }
    });
    let delivery = Arc::clone(&deliverer);
    every("delivery", poll, shutdown.clone(), move || {
        let deliverer = Arc::clone(&delivery);
        async move { deliverer.poll_due().await }
    });
    let reports = Arc::clone(&deliverer);
    every(
        "TLS-RPT",
        Duration::from_secs(600),
        shutdown.clone(),
        move || {
            let deliverer = Arc::clone(&reports);
            async move { deliverer.send_tls_reports().await.map(|_| ()) }
        },
    );
    let tls_reload = tls.clone();
    let cert = cfg.tls.cert.clone();
    let key = cfg.tls.key.clone();
    let shutdown_signal = shutdown.clone();
    tokio::spawn(async move {
        wait_for_signals(shutdown_signal, tls_reload, cert, key).await;
    });
    let mut set = tokio::task::JoinSet::new();
    for (listener, mode, role) in listeners {
        let ctx = Arc::new(SessionContext {
            cfg: Arc::clone(&cfg),
            spool: Arc::clone(&spool),
            tls: tls.clone(),
            checks: Arc::clone(&checks),
            relay: Arc::clone(&relay),
            role,
        });
        let shutdown = shutdown.clone();
        set.spawn(async move {
            SmtpServer::new(ctx).run(listener, shutdown, mode).await;
        });
    }
    while set.join_next().await.is_some() {}
    Ok(())
}

/// Run `pass` every `period` until shutdown. Each pass is its own task, so
/// an error or a panic is logged and the next pass still runs.
fn every<F, Fut>(name: &'static str, period: Duration, shutdown: CancellationToken, pass: F)
where
    F: Fn() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Result<(), String>> + Send + 'static,
{
    tokio::spawn(async move {
        while !shutdown.is_cancelled() {
            match tokio::spawn(pass()).await {
                Ok(Ok(())) => {}
                Ok(Err(err)) => tracing::error!(%err, "{name} pass failed"),
                Err(err) => tracing::error!(%err, "{name} pass panicked"),
            }
            tokio::select! {
                _ = shutdown.cancelled() => break,
                _ = tokio::time::sleep(period) => {}
            }
        }
    });
}

async fn wait_for_signals(
    shutdown: CancellationToken,
    tls: Option<Arc<TlsManager>>,
    cert: Option<PathBuf>,
    key: Option<PathBuf>,
) {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut terminate = signal(SignalKind::terminate()).ok();
        let mut hangup = signal(SignalKind::hangup()).ok();
        loop {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    shutdown.cancel();
                    break;
                }
                _ = async {
                    if let Some(sig) = terminate.as_mut() { sig.recv().await; }
                } => {
                    shutdown.cancel();
                    break;
                }
                _ = async {
                    if let Some(sig) = hangup.as_mut() { sig.recv().await; }
                } => {
                    if let (Some(tls), Some(cert), Some(key)) = (&tls, &cert, &key) {
                        if let Err(err) = currawongd::reload_certificates(tls, cert, key) {
                            tracing::error!(%err, "SIGHUP certificate reload failed");
                        } else {
                            tracing::info!("reloaded TLS certificate");
                        }
                    }
                }
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tls;
        let _ = cert;
        let _ = key;
        let _ = tokio::signal::ctrl_c().await;
        shutdown.cancel();
    }
}
