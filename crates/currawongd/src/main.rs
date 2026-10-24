//! currawongd: SMTP listeners, the scan pipeline and outbound delivery.
use clap::Parser;
use currawong_admin::routes::portal::PortalState;
use currawong_auth::{AuthChecker, DmarcEventStore};
use currawong_core::residency::ResidencyGuard;
use currawong_dlp::encrypt::PortalStore;
use currawong_smtp::{
    acme::Acme, checks::CheckStack, delivery::Deliverer, dns::HickoryDns, limits::ConnectionLimits,
    relay::Relay, server::SmtpServer, session::SessionContext, tls::TlsManager,
};
use currawong_spool::Spool;
use currawongd::{
    check_config, checks_for, classify_pending, report_signing_key, residency_reports,
    send_dmarc_reports, spool_depth, supervise, BimiWorker, Pipeline, ReportHealth, SpoolMailer,
    BIMI_QUEUE, REPORT_CHECK,
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
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(clap::Subcommand)]
enum Command {
    /// Manage DKIM and ARC signing keys.
    #[command(subcommand)]
    Dkim(currawongd::dkim::DkimCommand),
    /// Threat-intel feeds: sync now, or look up an indicator.
    #[command(subcommand)]
    Intel(currawongd::intel::IntelCommand),
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
        if let Ok(Some(summary)) = currawongd::yara_summary(&cfg) {
            println!("yara: {summary}");
            for warning in &summary.warnings {
                println!("yara warning: {warning}");
            }
        }
        println!("configuration ok");
        return;
    }
    if let Some(Command::Dkim(command)) = args.command {
        let result = match AuthChecker::new(&cfg.auth.authserv_id) {
            Ok(dns) => currawongd::dkim::run(&cfg, command, &dns).await,
            Err(err) => Err(err),
        };
        match result {
            Ok(out) => print!("{out}"),
            Err(err) => {
                eprintln!("currawongd: {err}");
                std::process::exit(1);
            }
        }
        return;
    }
    if let Some(Command::Intel(command)) = args.command {
        currawongd::install_tracing(&cfg);
        match currawongd::intel::run(&cfg, command).await {
            Ok(out) => print!("{out}"),
            Err(err) => {
                eprintln!("currawongd: {err}");
                std::process::exit(1);
            }
        }
        return;
    }
    currawongd::install_tracing(&cfg);
    if let Err(err) = run(cfg).await {
        tracing::error!(%err, "currawongd stopped");
        std::process::exit(1);
    }
}

async fn run(cfg: currawong_core::Config) -> Result<(), String> {
    // Parser workers run as this user; they must not be able to ptrace the
    // daemon or read /proc/<pid>/mem.
    #[cfg(target_os = "linux")]
    // SAFETY: plain prctl with constant arguments.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        return Err("PR_SET_DUMPABLE failed".into());
    }
    let guard =
        Arc::new(ResidencyGuard::from_config(&cfg.residency).map_err(|err| err.to_string())?);
    guard.enforce_config(&cfg).map_err(|err| err.to_string())?;
    let report_key = report_signing_key(&cfg)?;
    currawongd::start_events(&cfg, Arc::clone(&guard))?;
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
    // ACME: answer HTTP-01 from now on, and get a certificate before any TLS
    // listener starts if the cached one is missing or due for renewal.
    let acme = match &cfg.tls.acme {
        Some(acme_cfg) => {
            let acme = Arc::new(Acme::new(acme_cfg.clone()).map_err(|err| err.to_string())?);
            let http = TcpListener::bind(&acme_cfg.http_bind)
                .await
                .map_err(|err| format!("tls.acme.http_bind {}: {err}", acme_cfg.http_bind))?;
            tokio::spawn(Arc::clone(&acme).serve_http01(http, shutdown.clone()));
            acme.ensure().await.map_err(|err| err.to_string())?;
            Some(acme)
        }
        None => None,
    };
    let (cert, key) = match &acme {
        Some(acme) => (Some(acme.cert_path()), Some(acme.key_path())),
        None => (cfg.tls.cert.clone(), cfg.tls.key.clone()),
    };
    let tls = match (&cert, &key) {
        (Some(cert), Some(key)) => Some(Arc::new(
            TlsManager::load(cert, key).map_err(|err| err.to_string())?,
        )),
        _ => None,
    };
    if let (Some(acme), Some(tls)) = (&acme, &tls) {
        tokio::spawn(Arc::clone(acme).renew(Arc::clone(tls), shutdown.clone()));
    }
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
    let intel_syncer = if cfg.intel.enabled {
        let syncer = Arc::new(currawongd::intel::syncer(&cfg)?);
        readiness.push(Arc::new(currawongd::intel::IntelReady {
            syncer: Arc::clone(&syncer),
            required: cfg.intel.required,
        }));
        Some(syncer)
    } else {
        None
    };
    currawong_core::telemetry::serve(
        cfg.metrics_addr().map_err(|err| err.to_string())?,
        readiness,
    )
    .map_err(|err| format!("metrics.listen {}: {err}", cfg.metrics.listen))?;
    if cfg.scanner.enabled && currawongd::worker_binary(&cfg).is_none() {
        return Err("parser worker binary not found: set scanner.worker_binary".into());
    }
    let auth = AuthChecker::new(&cfg.auth.authserv_id)?;
    checks.spawn_housekeeping();
    let mut pipeline = Pipeline::new(Arc::clone(&cfg), auth).with_checks(Arc::clone(&checks));
    if let Some(pool) = &pipeline.pool {
        pool.self_test()
            .await
            .map_err(|err| format!("parser worker self-test failed: {err}"))?;
    }
    // Keys exist once `currawongd dkim generate` has run; until then nothing is signed.
    if (cfg.dkim.sign_outbound || cfg.dkim.seal_arc) && cfg.dkim.database.exists() {
        let keys = currawong_auth::KeyStore::open(&cfg.dkim.database, &cfg.dkim.kek_path)?;
        pipeline = pipeline.with_keys(keys);
    } else if cfg.dkim.sign_outbound || cfg.dkim.seal_arc {
        tracing::warn!(database = %cfg.dkim.database.display(), "no DKIM key store; outbound mail is not signed");
    }
    let portal = &cfg.encrypt.portal;
    if portal.enabled {
        let store = Arc::new(
            PortalStore::open(&portal.dir, &portal.key_path, portal.retention_days)
                .map_err(|err| err.to_string())?,
        );
        pipeline = pipeline.with_portal(Arc::clone(&store));
        let mailer = Arc::new(SpoolMailer {
            spool: Arc::clone(&spool),
            cfg: Arc::clone(&cfg),
        });
        let proxies = portal
            .trusted_proxies
            .iter()
            .map(|cidr| cidr.parse())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|err| format!("encrypt.portal.trusted_proxies: {err}"))?;
        let state = PortalState::new(
            Arc::clone(&store),
            mailer,
            portal.requests_per_minute,
            proxies,
        );
        let listener = TcpListener::bind(&portal.listen)
            .await
            .map_err(|err| format!("encrypt.portal.listen {}: {err}", portal.listen))?;
        tracing::info!(bind = %portal.listen, "encryption portal listening");
        tokio::spawn(currawong_admin::routes::portal::serve(listener, state));
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(3600));
            loop {
                tick.tick().await;
                let store = Arc::clone(&store);
                let now = time_now();
                match tokio::task::spawn_blocking(move || store.purge_expired(now)).await {
                    Ok(Ok(0)) => {}
                    Ok(Ok(removed)) => tracing::info!(removed, "expired portal messages removed"),
                    Ok(Err(err)) => tracing::warn!(%err, "portal purge failed"),
                    Err(err) => tracing::warn!(%err, "portal purge failed"),
                }
            }
        });
    }
    if cfg.url_rewrite.enabled {
        let (rewriter, clicks) = currawongd::url_protection(&cfg)?;
        pipeline = pipeline.with_url_rewriter(rewriter);
        let listener = TcpListener::bind(&cfg.url_rewrite.listen)
            .await
            .map_err(|err| format!("{}: {err}", cfg.url_rewrite.listen))?;
        tracing::info!(bind = %cfg.url_rewrite.listen, "click service listening");
        tokio::spawn(currawong_admin::routes::click::serve(listener, clicks));
    }
    pipeline.reload_policies().await?;
    tracing::info!(count = pipeline.policies.policies.len(), "policies loaded");
    if cfg.auth.dmarc_reports.enabled {
        let store = DmarcEventStore::open(&cfg.auth.dmarc_reports)?;
        pipeline = pipeline.with_dmarc_events(store.clone());
        spawn_dmarc_reports(
            Arc::clone(&cfg),
            Arc::clone(&spool),
            store,
            shutdown.clone(),
        )?;
    }
    let quarantine_dir = cfg.quarantine_dir();
    let blobs =
        currawong_quarantine::open_blob_store(&cfg.quarantine.blob_store, &guard, &quarantine_dir)?;
    let quarantine = currawong_quarantine::QuarantineStore::open(&quarantine_dir)
        .map_err(|err| err.to_string())?
        .with_config(&cfg.quarantine)
        .with_blobs(blobs);
    spawn_quarantine(
        Arc::clone(&cfg),
        Arc::clone(&spool),
        quarantine.clone(),
        shutdown.clone(),
    )
    .await?;
    if cfg.auth.bimi {
        // Its own resolver and queue: lookups never wait in the classify loop.
        let (jobs, queue) = tokio::sync::mpsc::channel(BIMI_QUEUE);
        pipeline = pipeline.with_bimi(jobs);
        let txt = AuthChecker::new(&cfg.auth.authserv_id)?;
        tokio::spawn(BimiWorker::default().run(txt, quarantine.clone(), queue));
    }
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
                Ok(true) => {
                    tracing::info!("policies reloaded");
                    // No admin API yet: the policy files or database changed.
                    // TODO: emit the admin user once the admin API exists.
                    currawong_integrations::export::emit(
                        currawong_integrations::export::Event::new(
                            None,
                            currawong_integrations::export::EventKind::AdminAction {
                                actor: "policy-store".into(),
                                action: "policy.reload".into(),
                                target: format!("{} policies", pipeline.policies.policies.len()),
                            },
                        ),
                    );
                }
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
    // Feed downloads write the store on their own loop; a slow feed never
    // holds up classification, which reads it.
    if let Some(syncer) = intel_syncer {
        every(
            "intel sync",
            Duration::from_secs(60),
            shutdown.clone(),
            move || {
                let syncer = Arc::clone(&syncer);
                async move { currawongd::intel::sync_pass(&syncer).await }
            },
        );
    }
    let tls_reload = tls.clone();
    let shutdown_signal = shutdown.clone();
    tokio::spawn(async move {
        wait_for_signals(shutdown_signal, tls_reload, cert, key).await;
    });
    let mut set = tokio::task::JoinSet::new();
    let limits = ConnectionLimits::new(
        cfg.limits.max_connections,
        cfg.limits.max_connections_per_ip as u32,
    );
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
        let limits = Arc::clone(&limits);
        set.spawn(async move {
            SmtpServer::with_limits(ctx, limits)
                .run(listener, shutdown, mode)
                .await;
        });
    }
    while set.join_next().await.is_some() {}
    // Events not sent by now stay in the overflow and go out on the next start.
    currawong_integrations::export::flush(Duration::from_secs(10)).await;
    Ok(())
}

/// The report pass runs on its own supervised task with its own resolver,
/// so slow or hostile DNS for `rua` checks cannot stall classification or
/// delivery, and a panic restarts it. Shutdown cancels a pass mid-way: the
/// claim ledger makes that safe.
fn spawn_dmarc_reports(
    cfg: Arc<currawong_core::Config>,
    spool: Arc<Spool>,
    store: DmarcEventStore,
    shutdown: CancellationToken,
) -> Result<(), String> {
    let auth = Arc::new(AuthChecker::new(&cfg.auth.authserv_id)?);
    let dns = Arc::new(HickoryDns::system().map_err(|err| err.to_string())?);
    tokio::spawn(supervise(
        "dmarc reports",
        shutdown,
        Duration::from_secs(5),
        move || {
            let (cfg, spool, store, auth, dns) = (
                Arc::clone(&cfg),
                Arc::clone(&spool),
                store.clone(),
                Arc::clone(&auth),
                Arc::clone(&dns),
            );
            async move {
                loop {
                    let now = time::OffsetDateTime::now_utc();
                    if let Err(err) =
                        send_dmarc_reports(&spool, &auth, &store, &cfg, dns.as_ref(), now).await
                    {
                        tracing::error!(%err, "dmarc report pass failed");
                    }
                    tokio::time::sleep(Duration::from_secs(300)).await;
                }
            }
        },
    ));
    Ok(())
}

/// Hourly retention purge and digests on their own supervised task, and the
/// digest-link and release endpoints when `quarantine.listen` is set.
async fn spawn_quarantine(
    cfg: Arc<currawong_core::Config>,
    spool: Arc<Spool>,
    store: currawong_quarantine::QuarantineStore,
    shutdown: CancellationToken,
) -> Result<(), String> {
    use currawong_quarantine::{digest, http, LinkSigner};
    let q = &cfg.quarantine;
    let links =
        if q.digests || q.listen.is_some() {
            Some(LinkSigner::load_or_create(&q.link_key_path).map_err(|err| {
                format!("quarantine link key {}: {err}", q.link_key_path.display())
            })?)
        } else {
            None
        };
    if let (Some(listen), Some(links)) = (&q.listen, &links) {
        let listener = TcpListener::bind(listen)
            .await
            .map_err(|err| format!("{listen}: {err}"))?;
        tracing::info!(bind = %listen, "quarantine endpoints listening");
        if listener
            .local_addr()
            .is_ok_and(|addr| !addr.ip().is_loopback())
        {
            tracing::warn!(bind = %listen, "quarantine endpoints serve plain HTTP off loopback; put a TLS proxy in front and bind to loopback");
        }
        let app = http::router(http::HttpState {
            store: store.clone(),
            spool: Arc::clone(&spool),
            links: links.clone(),
        });
        let stop = shutdown.clone();
        tokio::spawn(async move {
            let serve = axum::serve(listener, app).with_graceful_shutdown(stop.cancelled_owned());
            if let Err(err) = serve.await {
                tracing::error!(%err, "quarantine endpoints stopped");
            }
        });
    }
    let digests = q.digests.then(|| digest::DigestSettings::from_config(&cfg));
    tokio::spawn(supervise(
        "quarantine maintenance",
        shutdown,
        Duration::from_secs(5),
        move || {
            let (store, spool, links, digests) = (
                store.clone(),
                Arc::clone(&spool),
                links.clone(),
                digests.clone(),
            );
            async move {
                loop {
                    let now = time::OffsetDateTime::now_utc();
                    match store.purge(now).await {
                        Ok(0) => {}
                        Ok(count) => tracing::info!(count, "expired quarantine items purged"),
                        Err(err) => tracing::error!(%err, "quarantine purge failed"),
                    }
                    if let (Some(settings), Some(links)) = (&digests, &links) {
                        if let Err(err) =
                            digest::send_digests(&store, &spool, links, settings, now).await
                        {
                            tracing::error!(%err, "quarantine digests failed");
                        }
                    }
                    tokio::time::sleep(Duration::from_secs(3600)).await;
                }
            }
        },
    ));
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

/// Wait for `signal`, or for ever when it could not be registered: a missing
/// handler must not read as a signal (an instant shutdown, or a SIGHUP reload
/// in a busy loop).
#[cfg(unix)]
async fn recv_or_pending(signal: Option<&mut tokio::signal::unix::Signal>) {
    match signal {
        Some(signal) => {
            signal.recv().await;
        }
        None => std::future::pending().await,
    }
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
                _ = recv_or_pending(terminate.as_mut()) => {
                    shutdown.cancel();
                    break;
                }
                _ = recv_or_pending(hangup.as_mut()) => {
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

fn time_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}
