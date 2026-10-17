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
use tokio::sync::{mpsc, watch};

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
    /// Set by `flush`: workers stop sending and write queued events to the overflow.
    closing: watch::Sender<bool>,
}

struct Sink {
    name: &'static str,
    tx: mpsc::Sender<Event>,
    overflow: Arc<Overflow>,
    dropped: Arc<AtomicU64>,
    /// Events in the queue or in a batch being sent.
    pending: Arc<AtomicUsize>,
}

impl EventBus {
    /// Start one worker per exporter. Must be called inside a Tokio runtime.
    pub fn start(exporters: Vec<Arc<dyn Exporter>>, opts: &BusOptions) -> std::io::Result<Self> {
        let mut sinks = Vec::new();
        let (closing, closing_rx) = watch::channel(false);
        for exporter in exporters {
            let name = exporter.name();
            let overflow = Arc::new(Overflow::open(
                &opts.overflow_dir.join(name),
                opts.overflow_max_files,
            )?);
            let (tx, rx) = mpsc::channel(opts.queue_capacity.max(1));
            let dropped = Arc::new(AtomicU64::new(0));
            let pending = Arc::new(AtomicUsize::new(0));
            tokio::spawn(run(
                exporter,
                rx,
                overflow.clone(),
                dropped.clone(),
                pending.clone(),
                closing_rx.clone(),
                opts.clone(),
            ));
            sinks.push(Sink {
                name,
                tx,
                overflow,
                dropped,
                pending,
            });
        }
        Ok(Self { sinks, closing })
    }

    pub fn emit(&self, event: Event) {
        for sink in &self.sinks {
            sink.pending.fetch_add(1, Ordering::Relaxed);
            match sink.tx.try_send(event.clone()) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(event)) => {
                    sink.pending.fetch_sub(1, Ordering::Relaxed);
                    if !sink.overflow.push(&event) {
                        sink.drop_one();
                    }
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    sink.pending.fetch_sub(1, Ordering::Relaxed);
                    sink.drop_one();
                }
            }
        }
    }

    /// For shutdown: keep sending for up to `timeout`, then stop and move what
    /// is still queued to the overflow, which is sent on the next start.
    /// True when nothing was left only in memory.
    pub async fn flush(&self, timeout: Duration) -> bool {
        if self.drained_within(timeout).await {
            return true;
        }
        self.closing.send_replace(true);
        let drained = self.drained_within(Duration::from_secs(2)).await;
        if !drained {
            tracing::warn!(
                events = self.pending(),
                "event flush timed out, events still in flight are lost"
            );
        }
        drained
    }

    fn pending(&self) -> usize {
        self.sinks
            .iter()
            .map(|sink| sink.pending.load(Ordering::Relaxed))
            .sum()
    }

    async fn drained_within(&self, timeout: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + timeout;
        while self.pending() > 0 {
            if tokio::time::Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        true
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
    pending: Arc<AtomicUsize>,
    mut closing: watch::Receiver<bool>,
    opts: BusOptions,
) {
    let batch_size = opts.batch_size.max(1);
    let mut backoff = opts.retry_initial;
    loop {
        let closing_now = is_closing(&closing);
        // Older events on disk go first. They stay there while closing.
        let (files, mut batch): (Vec<PathBuf>, Vec<Event>) = if closing_now {
            (Vec::new(), Vec::new())
        } else {
            overflow.load(batch_size).into_iter().unzip()
        };
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
        let queued = if files.is_empty() { batch.len() } else { 0 };
        if is_closing(&closing) && files.is_empty() {
            spill(&overflow, &batch, &dropped, exporter.name());
            pending.fetch_sub(queued, Ordering::Relaxed);
            continue;
        }
        // Closing abandons a send in flight. The batch is kept on disk, so the
        // SIEM may see it twice, which at-least-once delivery allows.
        let sent = tokio::select! {
            sent = exporter.send(&batch) => sent,
            _ = closing.wait_for(|closing| *closing) => {
                Err(super::ExportError::Transport("shutting down".into()))
            }
        };
        match sent {
            Ok(()) => {
                overflow.remove(&files);
                pending.fetch_sub(queued, Ordering::Relaxed);
                backoff = opts.retry_initial;
            }
            Err(err) => {
                tracing::warn!(sink = exporter.name(), %err, events = batch.len(), "event export failed");
                if files.is_empty() {
                    spill(&overflow, &batch, &dropped, exporter.name());
                }
                pending.fetch_sub(queued, Ordering::Relaxed);
                tokio::select! {
                    _ = tokio::time::sleep(backoff) => {}
                    _ = closing.wait_for(|closing| *closing) => {}
                }
                backoff = (backoff * 2).min(opts.retry_max);
            }
        }
    }
}

/// Closing was requested, or the bus is gone.
fn is_closing(closing: &watch::Receiver<bool>) -> bool {
    *closing.borrow() || closing.has_changed().is_err()
}

fn spill(overflow: &Overflow, batch: &[Event], dropped: &AtomicU64, sink: &'static str) {
    for event in batch {
        if !overflow.push(event) {
            dropped.fetch_add(1, Ordering::Relaxed);
            metrics::counter!("currawong_events_dropped_total", "sink" => sink).increment(1);
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
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_sub(1))
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

    #[tokio::test]
    async fn export_bus_flush_moves_queued_events_to_disk_for_the_next_start() {
        let dir = tempfile::tempdir().unwrap();
        let stuck = SlowSink::new(false, 0);
        let bus = EventBus::start(vec![stuck.clone()], &opts(dir.path(), 16, 100)).unwrap();
        for n in 0..8 {
            bus.emit(event(n));
        }
        // The batch stuck in a send and the events still queued all go to disk.
        assert!(bus.flush(Duration::from_millis(100)).await);
        assert_eq!(bus.overflowed("slow"), 8);
        assert_eq!(stuck.seen(), 0);
        drop(bus);

        let sink = SlowSink::new(true, 0);
        let _restarted = EventBus::start(vec![sink.clone()], &opts(dir.path(), 16, 100)).unwrap();
        wait_for(|| sink.seen() == 8).await;

        // A healthy sink is simply drained.
        let dir = tempfile::tempdir().unwrap();
        let sink = SlowSink::new(true, 0);
        let bus = EventBus::start(vec![sink.clone()], &opts(dir.path(), 16, 100)).unwrap();
        for n in 0..8 {
            bus.emit(event(n));
        }
        assert!(bus.flush(Duration::from_secs(5)).await);
        assert_eq!(sink.seen(), 8);
        assert_eq!(bus.overflowed("slow"), 0);
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
