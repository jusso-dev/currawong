//! Pending task IDs and terminal verdicts survive daemon and spool retries.
use super::SandboxVerdict;
use crate::ServiceError;
use rusqlite::{params, Connection, OptionalExtension};
use std::{
    path::Path,
    sync::{Arc, Mutex},
};

#[derive(Clone)]
pub(super) struct Cache(Arc<Mutex<Connection>>);
#[derive(Clone)]
pub(super) struct Entry {
    pub task: Option<String>,
    pub submitted: i64,
    pub polled: i64,
    pub verdict: Option<SandboxVerdict>,
    pub failed: Option<String>,
}
impl Cache {
    pub fn open(path: &Path) -> Result<Self, String> {
        if let Some(parent) = path.parent() {
            let mut builder = std::fs::DirBuilder::new();
            builder.recursive(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            builder.create(parent).map_err(|e| e.to_string())?;
        }
        let mut options = std::fs::OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options.open(path).map_err(|e| e.to_string())?;
        let conn = Connection::open(path).map_err(|e| e.to_string())?;
        conn.busy_timeout(std::time::Duration::from_secs(5))
            .map_err(|e| e.to_string())?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS sandbox_tasks (
                service TEXT NOT NULL, sha256 TEXT NOT NULL, task TEXT,
                submitted INTEGER NOT NULL, polled INTEGER NOT NULL,
                verdict TEXT, failed TEXT, PRIMARY KEY(service, sha256));",
        )
        .map_err(|e| e.to_string())?;
        Ok(Self(Arc::new(Mutex::new(conn))))
    }
    async fn run<T: Send + 'static>(
        &self,
        f: impl FnOnce(&mut Connection) -> Result<T, rusqlite::Error> + Send + 'static,
    ) -> Result<T, ServiceError> {
        let conn = self.0.clone();
        tokio::task::spawn_blocking(move || f(&mut conn.lock().unwrap_or_else(|e| e.into_inner())))
            .await
            .map_err(|_| ServiceError::unavailable("sandbox cache worker failed"))?
            .map_err(|_| ServiceError::unavailable("sandbox cache unavailable"))
    }
    pub async fn load(
        &self,
        service: &str,
        sha: &str,
        now: i64,
        ttl: i64,
    ) -> Result<Option<Entry>, ServiceError> {
        let (service, sha) = (service.to_string(), sha.to_string());
        let row = self.run(move |conn| {
            conn.execute("DELETE FROM sandbox_tasks WHERE service=?1 AND (verdict IS NOT NULL OR (failed IS NOT NULL AND task IS NOT NULL) OR failed='timeout') AND polled < ?2", params![service, now.saturating_sub(ttl)])?;
            conn.query_row("SELECT task, submitted, polled, verdict, failed FROM sandbox_tasks WHERE service=?1 AND sha256=?2", params![service, sha], |r| {
                Ok((r.get::<_, Option<String>>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?, r.get::<_, Option<String>>(3)?, r.get::<_, Option<String>>(4)?))
            }).optional()
        }).await?;
        row.map(|(task, submitted, polled, verdict, failed)| {
            Ok(Entry {
                task,
                submitted,
                polled,
                verdict: verdict
                    .map(|s| {
                        serde_json::from_str(&s)
                            .map_err(|_| ServiceError::invalid("invalid cached sandbox verdict"))
                    })
                    .transpose()?,
                failed,
            })
        })
        .transpose()
    }
    /// Reserve before sending. If the process dies after upload, an unknown
    /// task times out instead of submitting the attachment a second time.
    pub async fn reserve(&self, service: &str, sha: &str, now: i64) -> Result<bool, ServiceError> {
        let (service, sha) = (service.to_string(), sha.to_string());
        self.run(move |conn| conn.execute("INSERT OR IGNORE INTO sandbox_tasks(service,sha256,submitted,polled) VALUES (?1,?2,?3,?3)", params![service, sha, now]).map(|n| n == 1)).await
    }
    pub async fn save(&self, service: &str, sha: &str, entry: Entry) -> Result<(), ServiceError> {
        let (service, sha) = (service.to_string(), sha.to_string());
        let verdict = entry
            .verdict
            .map(|v| serde_json::to_string(&v).expect("finite sandbox verdict"));
        self.run(move |conn| conn.execute("UPDATE sandbox_tasks SET task=?3, polled=?4, verdict=?5, failed=?6 WHERE service=?1 AND sha256=?2", params![service, sha, entry.task, entry.polled, verdict, entry.failed]).map(|_| ())).await
    }
    /// Release only when the submission is known not to have been sent.
    pub async fn release(&self, service: &str, sha: &str) -> Result<(), ServiceError> {
        let (service, sha) = (service.to_string(), sha.to_string());
        self.run(move |conn| {
            conn.execute(
                "DELETE FROM sandbox_tasks WHERE service=?1 AND sha256=?2",
                params![service, sha],
            )
            .map(|_| ())
        })
        .await
    }
}
