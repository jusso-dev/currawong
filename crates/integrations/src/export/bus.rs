//! Bounded per-exporter queues with a capped disk overflow.
//!
//! `emit` never waits. Each exporter has its own queue and worker, so a slow
//! SIEM only delays its own events. When a queue is full the event goes to the
//! exporter's overflow directory. When that is full too the event is dropped
//! and counted in `currawong_events_dropped_total`.
//!
//! Overflow files follow the spool pattern (write `.tmp`, then rename) but are
//! not fsynced: mail processing must not wait on telemetry, so a power loss can
//! lose buffered events.
use super::{Event, Exporter};
use std::{
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::sync::mpsc;

#[derive(Debug, Clone)]
pub struct BusOptions {
    pub queue_capacity: usize,
    pub batch_size: usize,
    pub overflow_dir: PathBuf,
    pub overflow_max_files: usize,
    pub retry_initial: Duration,
    pub retry_max: Duration,
}

pub struct EventBus {
    sinks: Vec<Sink>,
}

struct Sink {
    name: &'static str,
    tx: mpsc::Sender<Event>,
    overflow: Arc<Overflow>,
    dropped: Arc<AtomicU64>,
}

impl EventBus {
    /// Start one worker per exporter. Must be called inside a Tokio runtime.
    pub fn start(exporters: Vec<Arc<dyn Exporter>>, opts: &BusOptions) -> std::io::Result<Self> {
        let mut sinks = Vec::new();
        for exporter in exporters {
            let name = exporter.name();
            let overflow = Arc::new(Overflow::open(
                &opts.overflow_dir.join(name),
                opts.overflow_max_files,
            )?);
            let (tx, rx) = mpsc::channel(opts.queue_capacity.max(1));
            let dropped = Arc::new(AtomicU64::new(0));
            tokio::spawn(run(
                exporter,
                rx,
                overflow.clone(),
                dropped.clone(),
                opts.clone(),
            ));
            sinks.push(Sink {
                name,
                tx,
                overflow,
                dropped,
            });
        }
        Ok(Self { sinks })
    }

    pub fn emit(&self, event: Event) {
        for sink in &self.sinks {
            match sink.tx.try_send(event.clone()) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(event)) => {
                    if !sink.overflow.push(&event) {
                        sink.drop_one();
                    }
                }
                Err(mpsc::error::TrySendError::Closed(_)) => sink.drop_one(),
            }
        }
    }

    /// Events dropped so far by the named exporter.
    pub fn dropped(&self, name: &str) -> u64 {
        self.sinks
            .iter()
            .find(|sink| sink.name == name)
            .map(|sink| sink.dropped.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    /// Events waiting on disk for the named exporter.
    pub fn overflowed(&self, name: &str) -> usize {
        self.sinks
            .iter()
            .find(|sink| sink.name == name)
            .map(|sink| sink.overflow.len())
            .unwrap_or(0)
    }
}

impl Sink {
    fn drop_one(&self) {
        self.dropped.fetch_add(1, Ordering::Relaxed);
        metrics::counter!("currawong_events_dropped_total", "sink" => self.name).increment(1);
    }
}

async fn run(
    exporter: Arc<dyn Exporter>,
    mut rx: mpsc::Receiver<Event>,
    overflow: Arc<Overflow>,
    dropped: Arc<AtomicU64>,
    opts: BusOptions,
) {
    let batch_size = opts.batch_size.max(1);
    let mut backoff = opts.retry_initial;
    loop {
        // Older events on disk go first.
        let (files, mut batch): (Vec<PathBuf>, Vec<Event>) =
            overflow.load(batch_size).into_iter().unzip();
        if batch.is_empty() {
            match rx.recv().await {
                Some(event) => batch.push(event),
                None => return,
            }
            while batch.len() < batch_size {
                match rx.try_recv() {
                    Ok(event) => batch.push(event),
                    Err(_) => break,
                }
            }
        }
        match exporter.send(&batch).await {
            Ok(()) => {
                overflow.remove(&files);
                backoff = opts.retry_initial;
            }
            Err(err) => {
                tracing::warn!(sink = exporter.name(), %err, events = batch.len(), "event export failed");
                if files.is_empty() {
                    for event in &batch {
                        if !overflow.push(event) {
                            dropped.fetch_add(1, Ordering::Relaxed);
                            metrics::counter!("currawong_events_dropped_total", "sink" => exporter.name())
                                .increment(1);
                        }
                    }
                }
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(opts.retry_max);
            }
        }
    }
}

/// One JSON file per event, named by its ULID so names sort oldest first.
pub(crate) struct Overflow {
    dir: PathBuf,
    max: usize,
    count: AtomicUsize,
}

impl Overflow {
    pub(crate) fn open(dir: &Path, max: usize) -> std::io::Result<Self> {
        std::fs::create_dir_all(dir)?;
        let mut count = 0;
        for entry in std::fs::read_dir(dir)? {
            let path = entry?.path();
            match path.extension().and_then(|ext| ext.to_str()) {
                Some("json") => count += 1,
                Some("tmp") => {
                    let _ = std::fs::remove_file(&path);
                }
                _ => {}
            }
        }
        Ok(Self {
            dir: dir.to_path_buf(),
            max,
            count: AtomicUsize::new(count),
        })
    }

    pub(crate) fn len(&self) -> usize {
        self.count.load(Ordering::Relaxed)
    }

    /// False when the overflow is full or the write failed.
    pub(crate) fn push(&self, event: &Event) -> bool {
        if self.count.fetch_add(1, Ordering::Relaxed) >= self.max {
            self.count.fetch_sub(1, Ordering::Relaxed);
            return false;
        }
        // Event ids come from our own ULIDs, but never trust them as paths.
        let safe = !event.id.is_empty() && event.id.chars().all(|c| c.is_ascii_alphanumeric());
        let name = if safe {
            event.id.clone()
        } else {
            ulid::Ulid::new().to_string()
        };
        let tmp = self.dir.join(format!("{name}.tmp"));
        let path = self.dir.join(format!("{name}.json"));
        let written = serde_json::to_vec(event)
            .map_err(std::io::Error::other)
            .and_then(|bytes| std::fs::write(&tmp, bytes))
            .and_then(|()| std::fs::rename(&tmp, &path));
        if let Err(err) = written {
            tracing::warn!(%err, dir = %self.dir.display(), "event overflow write failed");
            let _ = std::fs::remove_file(&tmp);
            self.count.fetch_sub(1, Ordering::Relaxed);
            return false;
        }
        true
    }

    /// Up to `n` of the oldest events. Unreadable files are removed.
    pub(crate) fn load(&self, n: usize) -> Vec<(PathBuf, Event)> {
        if self.len() == 0 {
            return Vec::new();
        }
        let Ok(entries) = std::fs::read_dir(&self.dir) else {
            return Vec::new();
        };
        let mut paths: Vec<PathBuf> = entries
            .filter_map(|entry| entry.ok().map(|e| e.path()))
            .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("json"))
            .collect();
        paths.sort();
        let mut out = Vec::new();
        for path in paths.into_iter().take(n) {
            match std::fs::read(&path)
                .ok()
                .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            {
                Some(event) => out.push((path, event)),
                None => {
                    tracing::warn!(path = %path.display(), "removing unreadable overflow event");
                    self.remove(std::slice::from_ref(&path));
                }
            }
        }
        out
    }

    pub(crate) fn remove(&self, paths: &[PathBuf]) {
        for path in paths {
            if std::fs::remove_file(path).is_ok() {
                self.count.fetch_sub(1, Ordering::Relaxed);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::export::{event::tests::samples, ExportError};
    use std::sync::Mutex;
    use tokio::sync::Semaphore;

    /// Holds every send until the test adds permits, then records the batch.
    struct SlowSink {
        gate: Semaphore,
        seen: Mutex<Vec<Event>>,
        fail_first: AtomicUsize,
    }

    impl SlowSink {
        fn new(open: bool, fail_first: usize) -> Arc<Self> {
            Arc::new(Self {
                gate: Semaphore::new(if open { Semaphore::MAX_PERMITS } else { 0 }),
                seen: Mutex::new(Vec::new()),
                fail_first: AtomicUsize::new(fail_first),
            })
        }

        fn seen(&self) -> usize {
            self.seen.lock().unwrap().len()
        }
    }

    #[async_trait::async_trait]
    impl Exporter for SlowSink {
        fn name(&self) -> &'static str {
            "slow"
        }

        async fn send(&self, batch: &[Event]) -> Result<(), ExportError> {
            self.gate.acquire().await.unwrap().forget();
            if self
                .fail_first
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_sub(1))
                .is_ok()
            {
                return Err(ExportError::Transport("SIEM unavailable".into()));
            }
            self.seen.lock().unwrap().extend_from_slice(batch);
            Ok(())
        }
    }

    fn opts(dir: &Path, capacity: usize, max_files: usize) -> BusOptions {
        BusOptions {
            queue_capacity: capacity,
            batch_size: 3,
            overflow_dir: dir.to_path_buf(),
            overflow_max_files: max_files,
            retry_initial: Duration::from_millis(5),
            retry_max: Duration::from_millis(20),
        }
    }

    fn event(n: usize) -> Event {
        let mut event = samples().remove(0);
        event.id = format!("01JA{n:022}");
        event
    }

    async fn wait_for(mut done: impl FnMut() -> bool) {
        for _ in 0..500 {
            if done() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("timed out");
    }

    #[tokio::test]
    async fn export_bus_slow_sink_never_blocks_and_stays_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let sink = SlowSink::new(false, 0);
        let bus = EventBus::start(vec![sink.clone()], &opts(dir.path(), 4, 10)).unwrap();
        let started = std::time::Instant::now();
        for n in 0..2_000 {
            bus.emit(event(n));
        }
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "emit waited on the sink"
        );
        let on_disk = std::fs::read_dir(dir.path().join("slow")).unwrap().count();
        assert_eq!(on_disk, 10);
        assert_eq!(bus.overflowed("slow"), 10);
        let dropped = bus.dropped("slow");
        // Queue (4) plus overflow (10) plus at most one batch in flight (3).
        assert!(dropped >= 2_000 - 17, "dropped {dropped}");

        sink.gate.add_permits(Semaphore::MAX_PERMITS / 2);
        let kept = 2_000 - dropped as usize;
        wait_for(|| sink.seen() == kept).await;
        wait_for(|| bus.overflowed("slow") == 0).await;
        assert_eq!(
            std::fs::read_dir(dir.path().join("slow")).unwrap().count(),
            0
        );
    }

    #[tokio::test]
    async fn export_bus_failed_batches_spill_to_disk_and_retry() {
        let dir = tempfile::tempdir().unwrap();
        let sink = SlowSink::new(true, 2);
        let bus = EventBus::start(vec![sink.clone()], &opts(dir.path(), 16, 100)).unwrap();
        for n in 0..5 {
            bus.emit(event(n));
        }
        wait_for(|| sink.seen() == 5).await;
        assert_eq!(bus.dropped("slow"), 0);
        wait_for(|| bus.overflowed("slow") == 0).await;
        let mut ids: Vec<String> = sink
            .seen
            .lock()
            .unwrap()
            .iter()
            .map(|e| e.id.clone())
            .collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), 5);
    }

    #[test]
    fn export_overflow_survives_a_restart_in_order() {
        let dir = tempfile::tempdir().unwrap();
        let overflow = Overflow::open(dir.path(), 3).unwrap();
        for n in [2, 0, 1, 3] {
            overflow.push(&event(n));
        }
        assert_eq!(overflow.len(), 3);
        std::fs::write(dir.path().join("partial.tmp"), b"{").unwrap();
        drop(overflow);
        let overflow = Overflow::open(dir.path(), 3).unwrap();
        assert_eq!(overflow.len(), 3);
        assert!(!dir.path().join("partial.tmp").exists());
        let loaded: Vec<String> = overflow.load(10).into_iter().map(|(_, e)| e.id).collect();
        assert_eq!(loaded, vec![event(0).id, event(1).id, event(2).id]);
    }
}
