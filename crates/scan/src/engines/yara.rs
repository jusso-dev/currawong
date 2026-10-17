//! YARA rules from `scanner.yara.rules_dir`, compiled with yara-x.
//!
//! Every `*.yar` and `*.yara` file is compiled into its own namespace. A
//! change to the directory recompiles. A broken file is logged and the
//! previous rules stay active. The pipeline matches message parts inside the
//! parser worker (ADR 0002), so each compiled set is also serialised to a
//! private temporary file the worker loads.
//!
//! Rules tagged `malware` make the message malware, rules tagged `suspicious`
//! make it active content. Other matches only appear on the report.
use crate::engines::{EngineResult, ScanItem, Scanner};
use arc_swap::ArcSwap;
use async_trait::async_trait;
use currawong_core::YaraMatch;
use currawong_parser::yara::YaraScan;
pub use notify::PollWatcher;
use notify::{EventKind, RecursiveMode, Watcher};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tempfile::NamedTempFile;
use yara_x::{Compiler, Rules, SourceCode};

/// One compiled rule set. The serialised file lives as long as this value.
pub struct CompiledRules {
    pub rules: Rules,
    pub generation: u64,
    file: NamedTempFile,
}

impl CompiledRules {
    /// Serialised rules for [`currawong_parser::ParseRequest::yara_rules`].
    pub fn path(&self) -> &Path {
        self.file.path()
    }
}

pub struct YaraEngine {
    dir: PathBuf,
    current: ArcSwap<CompiledRules>,
    generation: AtomicU64,
}

impl YaraEngine {
    /// Compile `dir`. If it does not compile, log it and start with no rules;
    /// the watcher picks up the fix.
    pub fn new(dir: impl Into<PathBuf>) -> Result<Self, String> {
        let dir = dir.into();
        let rules = match compile_dir(&dir) {
            Ok(rules) => rules,
            Err(err) => {
                tracing::error!(dir = %dir.display(), %err, "yara rules rejected, starting with none");
                Compiler::new().build()
            }
        };
        Ok(Self {
            current: ArcSwap::from_pointee(persist(rules, 0)?),
            dir,
            generation: AtomicU64::new(0),
        })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The active rules. Hold the `Arc` until the worker has replied.
    pub fn current(&self) -> Arc<CompiledRules> {
        self.current.load_full()
    }

    /// Recompile. On error the previous rules stay active.
    pub fn reload(&self) -> Result<u64, String> {
        let result = compile_dir(&self.dir).and_then(|rules| {
            let generation = self.generation.fetch_add(1, Ordering::SeqCst) + 1;
            persist(rules, generation)
        });
        match result {
            Ok(compiled) => {
                let generation = compiled.generation;
                self.current.store(Arc::new(compiled));
                tracing::info!(dir = %self.dir.display(), generation, "yara rules reloaded");
                Ok(generation)
            }
            Err(err) => {
                tracing::error!(dir = %self.dir.display(), %err, "yara rules rejected, previous rules stay active");
                Err(err)
            }
        }
    }

    /// Reload whenever a rule file in the directory changes. Keep the
    /// returned watcher alive for as long as reloads are wanted.
    ///
    /// Polls every two seconds rather than using inotify or FSEvents: those
    /// miss changes on bind mounts and network volumes, and FSEvents drops
    /// events under load. One directory listing per interval is cheap.
    pub fn watch(self: &Arc<Self>) -> Result<PollWatcher, String> {
        let engine = Arc::clone(self);
        let handler = move |event: notify::Result<notify::Event>| match event {
            Ok(event) if touches_rules(&event) => {
                let _ = engine.reload();
            }
            Ok(_) => {}
            Err(err) => tracing::warn!(%err, "yara rules watch"),
        };
        let config = notify::Config::default().with_poll_interval(Duration::from_secs(2));
        let mut watcher =
            PollWatcher::new(handler, config).map_err(|err| format!("watch yara rules: {err}"))?;
        watcher
            .watch(&self.dir, RecursiveMode::NonRecursive)
            .map_err(|err| format!("watch {}: {err}", self.dir.display()))?;
        Ok(watcher)
    }
}

fn touches_rules(event: &notify::Event) -> bool {
    !matches!(event.kind, EventKind::Access(_))
        && (event.paths.is_empty() || event.paths.iter().any(|path| is_rule_file(path)))
}

fn is_rule_file(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|ext| ext.to_str()),
        Some("yar" | "yara")
    )
}

/// Compile every rule file in `dir`. Any error rejects the whole set.
pub fn compile_dir(dir: &Path) -> Result<Rules, String> {
    let entries =
        std::fs::read_dir(dir).map_err(|err| format!("yara rules_dir {}: {err}", dir.display()))?;
    let mut files: Vec<PathBuf> = entries
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.is_file() && is_rule_file(path))
        .collect();
    files.sort();
    let mut compiler = Compiler::new();
    for path in &files {
        let source = std::fs::read_to_string(path)
            .map_err(|err| format!("read {}: {err}", path.display()))?;
        let namespace = path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .unwrap_or("default");
        compiler.new_namespace(namespace);
        compiler
            .add_source(SourceCode::from(source.as_str()).with_origin(path.display().to_string()))
            .map_err(|err| format!("{}: {err}", path.display()))?;
    }
    Ok(compiler.build())
}

fn persist(rules: Rules, generation: u64) -> Result<CompiledRules, String> {
    let bytes = rules
        .serialize()
        .map_err(|err| format!("serialise yara rules: {err}"))?;
    let mut file = tempfile::Builder::new()
        .prefix("currawong-yara-")
        .suffix(".yarc")
        .tempfile()
        .map_err(|err| format!("yara rules file: {err}"))?;
    file.write_all(&bytes)
        .and_then(|_| file.flush())
        .map_err(|err| format!("yara rules file: {err}"))?;
    Ok(CompiledRules {
        rules,
        generation,
        file,
    })
}

/// Malware beats suspicious. Untagged matches leave the engine clean.
pub fn result_for(matches: &[YaraMatch]) -> EngineResult {
    let tagged = |tag: &str| -> Vec<String> {
        matches
            .iter()
            .filter(|hit| hit.tags.iter().any(|t| t == tag))
            .map(|hit| format!("{} in {}", hit.rule, hit.part))
            .collect()
    };
    let malware = tagged("malware");
    if !malware.is_empty() {
        return EngineResult::Malware {
            signature: malware.join(", "),
        };
    }
    let suspicious = tagged("suspicious");
    if !suspicious.is_empty() {
        return EngineResult::Suspicious {
            detail: suspicious.join(", "),
        };
    }
    EngineResult::Clean
}

#[async_trait]
impl Scanner for YaraEngine {
    fn name(&self) -> &str {
        "yara"
    }

    async fn scan(&self, item: &ScanItem<'_>) -> EngineResult {
        let compiled = self.current();
        let mut scan = YaraScan::new(&compiled.rules);
        scan.scan(item.name, item.bytes);
        if let Some(reason) = scan.error {
            return EngineResult::Failed {
                reason,
                unreachable: false,
            };
        }
        result_for(&scan.matches)
    }
}
