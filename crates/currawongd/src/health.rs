//! Readiness: spool is writable, a configured clamd answers, signature paths exist.
use async_trait::async_trait;
use currawong_core::{config::Config, telemetry::ReadinessCheck};
use currawong_scan::clamav::supplemental_paths_ready;
use currawong_smtp::tls::TlsManager;
use std::{
    path::Path,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

static PROBE: AtomicU64 = AtomicU64::new(0);

pub struct SpoolWritable {
    pub dir: std::path::PathBuf,
}

#[async_trait]
impl ReadinessCheck for SpoolWritable {
    fn name(&self) -> &'static str {
        "spool"
    }

    async fn check(&self) -> Result<(), String> {
        if !self.dir.is_dir() {
            return Err(format!("spool {} is not a directory", self.dir.display()));
        }
        // A unique name per probe, so concurrent /readyz calls do not race.
        let probe = self.dir.join(format!(
            ".ready-{}-{}",
            std::process::id(),
            PROBE.fetch_add(1, Ordering::Relaxed)
        ));
        // Write and remove in one blocking job. If /readyz times out and drops
        // this future, the job still runs to the end and leaves no file behind.
        tokio::task::spawn_blocking(move || {
            std::fs::write(&probe, b"ok")?;
            std::fs::remove_file(&probe)
        })
        .await
        .map_err(|err| err.to_string())?
        .map_err(|err| err.to_string())
    }
}

pub struct ClamdReady {
    pub address: String,
    pub required: bool,
}

#[async_trait]
impl ReadinessCheck for ClamdReady {
    fn name(&self) -> &'static str {
        "clamd"
    }

    async fn check(&self) -> Result<(), String> {
        if self.address.is_empty() {
            return if self.required {
                Err("clamd is required and no address is configured".into())
            } else {
                Ok(())
            };
        }
        let address = currawong_scan::ClamdAddress::parse(&self.address)?;
        currawong_scan::ClamdClient::new(address, true)
            .with_timeout(std::time::Duration::from_secs(2))
            .ping()
            .await
    }
}

/// A real parse job through a fresh worker: the binary starts, its sandbox
/// installs and it answers.
pub struct WorkerReady {
    pub cfg: Config,
}

#[async_trait]
impl ReadinessCheck for WorkerReady {
    fn name(&self) -> &'static str {
        "parser_worker"
    }

    async fn check(&self) -> Result<(), String> {
        if !self.cfg.scanner.enabled {
            return Ok(());
        }
        let pool = crate::pipeline::worker_pool(&self.cfg)
            .ok_or("parser worker binary not found")?
            .with_size(1);
        pool.self_test().await
    }
}

pub struct SignaturesReady {
    pub dirs: Vec<std::path::PathBuf>,
    pub files: Vec<std::path::PathBuf>,
}

#[async_trait]
impl ReadinessCheck for SignaturesReady {
    fn name(&self) -> &'static str {
        "signatures"
    }

    async fn check(&self) -> Result<(), String> {
        supplemental_paths_ready(&self.dirs, &self.files)
    }
}

pub struct RspamdReady {
    pub cfg: Config,
}
#[async_trait]
impl ReadinessCheck for RspamdReady {
    fn name(&self) -> &'static str {
        "rspamd"
    }
    async fn check(&self) -> Result<(), String> {
        let mut config = self.cfg.scanner.rspamd.clone();
        config.timeout_secs = 2;
        let guard = Arc::new(
            currawong_core::ResidencyGuard::from_config(&self.cfg.residency)
                .map_err(|e| e.to_string())?,
        );
        currawong_scan::rspamd::RspamdClient::new(&config, guard)?
            .ping()
            .await
    }
}

pub fn checks_for(cfg: &Config) -> Vec<Arc<dyn ReadinessCheck>> {
    let mut checks: Vec<Arc<dyn ReadinessCheck>> = vec![
        Arc::new(SpoolWritable {
            dir: cfg.spool.dir.clone(),
        }),
        Arc::new(ClamdReady {
            address: cfg.scanner.clamd.address.clone(),
            required: cfg.scanner.enabled && cfg.scanner.clamd.required,
        }),
        Arc::new(WorkerReady { cfg: cfg.clone() }),
        Arc::new(SignaturesReady {
            dirs: cfg.scanner.extra_signature_dirs.clone(),
            files: cfg.scanner.extra_database_paths.clone(),
        }),
    ];
    if cfg.scanner.enabled && cfg.scanner.rspamd.required {
        checks.push(Arc::new(RspamdReady { cfg: cfg.clone() }));
    }
    checks
}

pub fn reload_certificates(tls: &TlsManager, cert: &Path, key: &Path) -> Result<(), String> {
    tls.reload_from(cert, key).map_err(|err| err.to_string())
}
