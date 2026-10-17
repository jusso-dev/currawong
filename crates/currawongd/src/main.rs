//! currawongd: SMTP listeners, the scan pipeline and outbound delivery.
use clap::Parser;
use currawong_auth::AuthChecker;
use currawong_core::residency::ResidencyGuard;
use currawong_smtp::{
    checks::CheckStack, delivery::Deliverer, dns::HickoryDns, relay::Relay, server::SmtpServer,
    session::SessionContext, tls::TlsManager,
};
use currawong_spool::Spool;
use currawongd::{
    check_config, checks_for, classify_pending, report_signing_key, residency_reports, spool_depth,
    Pipeline, ReportHealth, REPORT_CHECK,
};
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
    let guard =
        Arc::new(ResidencyGuard::from_config(&cfg.residency).map_err(|err| err.to_string())?);
    guard.enforce_config(&cfg).map_err(|err| err.to_string())?;
    let report_key = report_signing_key(&cfg)?;
    let cfg = Arc::new(cfg);
    let shutdown = CancellationToken::new();
    let report_health = ReportHealth::default();
    if let Some(key) = report_key {
        tokio::spawn(residency_reports(
            Arc::clone(&cfg),
            Arc::clone(&guard),
            key,
            report_health.clone(),
            shutdown.clone(),
            time::OffsetDateTime::now_utc,
            REPORT_CHECK,
        ));
    }
    let spool = Arc::new(
        Spool::open(&cfg.spool.dir)
            .await
            .map_err(|err| err.to_string())?,
    );
    spool.recover().await.map_err(|err| err.to_string())?;
    tokio::spawn(spool_depth(
        Arc::clone(&spool),
        Duration::from_secs(cfg.delivery.poll_secs.max(1)),
        shutdown.clone(),
    ));
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
    let mut listeners = Vec::new();
    for listener in &cfg.listeners {
        let bound = TcpListener::bind(&listener.bind)
            .await
            .map_err(|err| format!("{}: {err}", listener.bind))?;
        tracing::info!(name = %listener.name, bind = %listener.bind, "smtp listening");
        listeners.push((bound, listener.mode.clone(), listener.role.clone()));
    }
    let mut readiness = checks_for(&cfg);
    readiness.push(Arc::new(report_health));
    currawong_core::telemetry::serve(
        cfg.metrics_addr().map_err(|err| err.to_string())?,
        readiness,
    )
    .map_err(|err| format!("metrics.listen {}: {err}", cfg.metrics.listen))?;
    let auth = AuthChecker::new(&cfg.auth.authserv_id)?;
    let mut pipeline = Pipeline::new(Arc::clone(&cfg), auth);
    pipeline.reload_policies().await?;
    tracing::info!(count = pipeline.policies.policies.len(), "policies loaded");
    let quarantine = currawong_quarantine::QuarantineStore::open(cfg.spool.dir.join("quarantine"))
        .map_err(|err| err.to_string())?;
    let deliverer = Deliverer::new(
        Arc::clone(&spool),
        Arc::clone(&cfg),
        Arc::new(HickoryDns::system().map_err(|err| err.to_string())?),
    );
    let spool_loop = Arc::clone(&spool);
    let shutdown_loop = shutdown.clone();
    let poll_secs = cfg.delivery.poll_secs.max(1);
    tokio::spawn(async move {
        let mut pipeline = pipeline;
        loop {
            if shutdown_loop.is_cancelled() {
                break;
            }
            match pipeline.reload_policies().await {
                Ok(true) => tracing::info!("policies reloaded"),
                Ok(false) => {}
                Err(err) => {
                    tracing::error!(%err, "policy reload failed, keeping the previous policies")
                }
            }
            if let Err(err) = classify_pending(&spool_loop, &mut pipeline, &quarantine).await {
                tracing::error!(%err, "pipeline pass failed");
            }
            if let Err(err) = deliver_ready(&deliverer).await {
                tracing::error!(%err, "delivery pass failed");
            }
            tokio::select! {
                _ = shutdown_loop.cancelled() => break,
                _ = tokio::time::sleep(Duration::from_secs(poll_secs)) => {}
            }
        }
    });
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

async fn deliver_ready(deliverer: &Deliverer<HickoryDns>) -> Result<(), String> {
    use currawong_spool::SpoolState;
    use currawongd::ready_to_deliver;
    for state in [SpoolState::Incoming, SpoolState::Deferred] {
        for env in deliverer
            .spool
            .list(state)
            .await
            .map_err(|err| err.to_string())?
        {
            if ready_to_deliver(&env) {
                let _ = deliverer.deliver(&env.id).await;
            }
        }
    }
    Ok(())
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
