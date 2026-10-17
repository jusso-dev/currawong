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
        tokio::fs::write(&probe, b"ok")
            .await
            .map_err(|err| err.to_string())?;
        tokio::fs::remove_file(&probe)
            .await
            .map_err(|err| err.to_string())?;
        Ok(())
    }
}

pub struct ClamdReady {
    pub address: String,
}

#[async_trait]
impl ReadinessCheck for ClamdReady {
    fn name(&self) -> &'static str {
        "clamd"
    }

    async fn check(&self) -> Result<(), String> {
        if self.address.is_empty() {
            return Ok(());
        }
        let address = currawong_scan::ClamdAddress::parse(&self.address)?;
        currawong_scan::ClamdClient::new(address, true).ping().await
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

pub fn checks_for(cfg: &Config) -> Vec<Arc<dyn ReadinessCheck>> {
    vec![
        Arc::new(SpoolWritable {
            dir: cfg.spool.dir.clone(),
        }),
        Arc::new(ClamdReady {
            address: cfg.scanner.clamd.address.clone(),
        }),
        Arc::new(SignaturesReady {
            dirs: cfg.scanner.extra_signature_dirs.clone(),
            files: cfg.scanner.extra_database_paths.clone(),
        }),
    ]
}

pub fn reload_certificates(tls: &TlsManager, cert: &Path, key: &Path) -> Result<(), String> {
    tls.reload_from(cert, key).map_err(|err| err.to_string())
}
