//! YARA rules from `scanner.yara.rules_dir`, compiled with yara-x.
//!
//! Every `*.yar` and `*.yara` file under the directory (any case, dot entries
//! skipped) is compiled into its own namespace. A change recompiles. A set
//! that does not compile, or an empty set replacing a non-empty one, is
//! logged and rejected; the previous rules stay active.
//!
//! Matching runs only in the parser worker (ADR 0002). Each compiled set is
//! serialised once here and sent to workers over their stdin protocol.
//!
//! Rules tagged `malware` make the message malware, rules tagged `suspicious`
//! make it active content. Other matches only appear on the report. A tag that
//! looks like a misspelt action tag (`Malware`, `malwre`) rejects the set.
use crate::engines::EngineResult;
use arc_swap::ArcSwap;
use base64::Engine as _;
use currawong_core::YaraMatch;
pub use notify::PollWatcher;
use notify::{EventKind, RecursiveMode, Watcher};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use yara_x::{Compiler, Rules, SourceCode};

const ACTION_TAGS: [&str; 2] = ["malware", "suspicious"];
const MAX_DEPTH: usize = 8;

/// One compiled rule set.
pub struct CompiledRules {
    pub rules: Rules,
    pub generation: u64,
    /// Base64 of the serialised rules, for the worker's `LoadRules` frame.
    pub encoded: String,
    pub summary: RuleSummary,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuleSummary {
    pub files: usize,
    pub rules: usize,
    pub tags: BTreeMap<String, usize>,
    pub warnings: Vec<String>,
}

impl std::fmt::Display for RuleSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} rules from {} files", self.rules, self.files)?;
        let tags: Vec<String> = self
            .tags
            .iter()
            .map(|(tag, count)| format!("{tag}={count}"))
            .collect();
        if !tags.is_empty() {
            write!(f, "; tags {}", tags.join(", "))?;
        }
        if !self.warnings.is_empty() {
            write!(f, "; {} warnings", self.warnings.len())?;
        }
        Ok(())
    }
}

pub struct YaraEngine {
    dir: PathBuf,
    current: ArcSwap<CompiledRules>,
    reload: Mutex<()>,
}

impl YaraEngine {
    /// Fails when the directory cannot be read or its rules do not compile,
    /// so the caller can fail closed instead of running without rules.
    pub fn new(dir: impl Into<PathBuf>) -> Result<Self, String> {
        let dir = dir.into();
        let compiled = build(&dir, 0)?;
        log_loaded(&dir, &compiled);
        Ok(Self {
            current: ArcSwap::from_pointee(compiled),
            dir,
            reload: Mutex::new(()),
        })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The active rules. Hold the `Arc` until the worker has replied.
    pub fn current(&self) -> Arc<CompiledRules> {
        self.current.load_full()
    }

    /// Recompile. On error the previous rules stay active. Reloads are
    /// serialised so generations are stored in order.
    pub fn reload(&self) -> Result<u64, String> {
        let _guard = self.reload.lock().unwrap_or_else(|err| err.into_inner());
        let current = self.current.load_full();
        let result = build(&self.dir, current.generation + 1).and_then(|next| {
            if next.summary.rules == 0 && current.summary.rules > 0 {
                Err(format!(
                    "{} has no rules; keeping {} active rules",
                    self.dir.display(),
                    current.summary.rules
                ))
            } else {
                Ok(next)
            }
        });
        match result {
            Ok(next) => {
                let generation = next.generation;
                log_loaded(&self.dir, &next);
                self.current.store(Arc::new(next));
                Ok(generation)
            }
            Err(err) => {
                tracing::error!(dir = %self.dir.display(), %err, "yara rules rejected, previous rules stay active");
                Err(err)
            }
        }
    }

    /// Reload whenever a rule file under the directory changes. Keep the
    /// returned watcher alive for as long as reloads are wanted.
    ///
    /// Polls every two seconds rather than using inotify or FSEvents: those
    /// miss changes on bind mounts and network volumes, and FSEvents drops
    /// events under load. Before reloading it waits for the files to stop
    /// changing, so a copy in progress is not compiled half written.
    pub fn watch(self: &Arc<Self>) -> Result<PollWatcher, String> {
        let engine = Arc::clone(self);
        let handler = move |event: notify::Result<notify::Event>| match event {
            Ok(event) if touches_rules(&event) => {
                wait_until_settled(&engine.dir, Duration::from_millis(500));
                let _ = engine.reload();
            }
            Ok(_) => {}
            Err(err) => tracing::warn!(%err, "yara rules watch"),
        };
        let config = notify::Config::default().with_poll_interval(Duration::from_secs(2));
        let mut watcher =
            PollWatcher::new(handler, config).map_err(|err| format!("watch yara rules: {err}"))?;
        watcher
            .watch(&self.dir, RecursiveMode::Recursive)
            .map_err(|err| format!("watch {}: {err}", self.dir.display()))?;
        Ok(watcher)
    }
}

fn log_loaded(dir: &Path, compiled: &CompiledRules) {
    for warning in &compiled.summary.warnings {
        tracing::warn!(dir = %dir.display(), %warning, "yara rule warning");
    }
    tracing::info!(
        dir = %dir.display(),
        generation = compiled.generation,
        summary = %compiled.summary,
        "yara rules loaded"
    );
}

fn touches_rules(event: &notify::Event) -> bool {
    !matches!(event.kind, EventKind::Access(_))
        && (event.paths.is_empty() || event.paths.iter().any(|path| is_rule_file(path)))
}

fn is_rule_file(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.eq_ignore_ascii_case("yar") || ext.eq_ignore_ascii_case("yara"))
        .unwrap_or(false)
}

/// Rule files under `dir`, sorted. A file or directory that cannot be read
/// is an error, not silently skipped.
pub fn rule_files(dir: &Path) -> Result<Vec<PathBuf>, String> {
    let mut files = Vec::new();
    collect(dir, 0, &mut files)?;
    files.sort();
    Ok(files)
}

fn collect(dir: &Path, depth: usize, files: &mut Vec<PathBuf>) -> Result<(), String> {
    let entries =
        std::fs::read_dir(dir).map_err(|err| format!("yara rules_dir {}: {err}", dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|err| format!("yara rules_dir {}: {err}", dir.display()))?;
        let path = entry.path();
        if entry.file_name().to_string_lossy().starts_with('.') {
            continue;
        }
        let meta = std::fs::metadata(&path).map_err(|err| format!("{}: {err}", path.display()))?;
        if meta.is_dir() && depth < MAX_DEPTH {
            collect(&path, depth + 1, files)?;
        } else if meta.is_file() && is_rule_file(&path) {
            files.push(path);
        }
    }
    Ok(())
}

fn fingerprint(dir: &Path) -> Vec<(PathBuf, u64, Option<SystemTime>)> {
    rule_files(dir)
        .unwrap_or_default()
        .into_iter()
        .map(|path| {
            let meta = std::fs::metadata(&path).ok();
            let len = meta.as_ref().map(|m| m.len()).unwrap_or(0);
            let modified = meta.and_then(|m| m.modified().ok());
            (path, len, modified)
        })
        .collect()
}

fn wait_until_settled(dir: &Path, quiet: Duration) {
    let mut before = fingerprint(dir);
    for _ in 0..20 {
        std::thread::sleep(quiet);
        let after = fingerprint(dir);
        if after == before {
            return;
        }
        before = after;
    }
}

/// Compile and serialise `dir`. Any error rejects the whole set.
pub fn build(dir: &Path, generation: u64) -> Result<CompiledRules, String> {
    let (rules, summary) = compile_dir(dir)?;
    let bytes = rules
        .serialize()
        .map_err(|err| format!("serialise yara rules: {err}"))?;
    Ok(CompiledRules {
        rules,
        generation,
        encoded: base64::engine::general_purpose::STANDARD.encode(bytes),
        summary,
    })
}

/// Compile every rule file under `dir` and check the tags.
pub fn compile_dir(dir: &Path) -> Result<(Rules, RuleSummary), String> {
    let files = rule_files(dir)?;
    let mut compiler = Compiler::new();
    for path in &files {
        let source = std::fs::read_to_string(path)
            .map_err(|err| format!("read {}: {err}", path.display()))?;
        let relative = path.strip_prefix(dir).unwrap_or(path).with_extension("");
        compiler.new_namespace(&relative.to_string_lossy());
        compiler
            .add_source(SourceCode::from(source.as_str()).with_origin(path.display().to_string()))
            .map_err(|err| format!("{}: {err}", path.display()))?;
    }
    let rules = build_rules(compiler)?;
    let mut summary = RuleSummary {
        files: files.len(),
        rules: rules.iter().len(),
        tags: BTreeMap::new(),
        warnings: rules.warnings().iter().map(|w| w.to_string()).collect(),
    };
    for rule in rules.iter() {
        for tag in rule.tags() {
            let tag = tag.identifier();
            if let Some(action) = near_action_tag(tag) {
                return Err(format!(
                    "rule {}: tag `{tag}` looks like `{action}`; only the exact lower-case tag acts",
                    rule.identifier()
                ));
            }
            *summary.tags.entry(tag.to_string()).or_default() += 1;
        }
    }
    Ok((rules, summary))
}

/// `Compiler::build` has no error return: it panics when wasmtime cannot
/// compile the generated module (yara-x `expect("WASM module is not valid")`).
/// Under `MemoryDenyWriteExecute` a native JIT fails that way, and a panic
/// here would stop `--check-config` and the daemon, or kill the reload
/// watcher, instead of failing closed. Catch it and return an error.
///
/// The workspace builds yara-x with `pulley` (the wasmtime interpreter), so
/// nothing is mapped executable and this should not fire in practice.
fn build_rules(compiler: Compiler<'_>) -> Result<Rules, String> {
    catch_build(move || {
        #[cfg(test)]
        tests::maybe_fail_build();
        compiler.build()
    })
}

fn catch_build(build: impl FnOnce() -> Rules) -> Result<Rules, String> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(build)).map_err(|panic| {
        let cause = panic
            .downcast_ref::<&str>()
            .map(|s| s.to_string())
            .or_else(|| panic.downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "unknown panic".into());
        format!(
            "yara rules did not compile to wasm code: {cause} (a yara-x JIT build fails like \
             this under MemoryDenyWriteExecute; currawong builds yara-x with pulley)"
        )
    })
}

/// The action tag `tag` was probably meant to be, if it is not exactly one.
fn near_action_tag(tag: &str) -> Option<&'static str> {
    let lower = tag.to_ascii_lowercase();
    ACTION_TAGS
        .into_iter()
        .find(|action| tag != *action && (lower == *action || distance(&lower, action) <= 2))
}

fn distance(a: &str, b: &str) -> usize {
    let b: Vec<char> = b.chars().collect();
    let mut row: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.chars().enumerate() {
        let mut prev = row[0];
        row[0] = i + 1;
        for (j, cb) in b.iter().enumerate() {
            let next = (prev + usize::from(ca != *cb))
                .min(row[j] + 1)
                .min(row[j + 1] + 1);
            prev = row[j + 1];
            row[j + 1] = next;
        }
    }
    row[b.len()]
}

/// Malware beats suspicious. Matches with other tags leave the engine clean.
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    thread_local! {
        static FAIL_BUILD: Cell<bool> = const { Cell::new(false) };
    }

    /// Panic like yara-x does when wasmtime rejects the module.
    pub(super) fn maybe_fail_build() {
        if FAIL_BUILD.with(Cell::get) {
            panic!("WASM module is not valid: injected for a test");
        }
    }

    struct FailBuild;

    impl FailBuild {
        fn on() -> Self {
            FAIL_BUILD.with(|f| f.set(true));
            Self
        }
    }

    impl Drop for FailBuild {
        fn drop(&mut self) {
            FAIL_BUILD.with(|f| f.set(false));
        }
    }

    const MARKER: &str =
        "rule Marker : malware { strings: $a = \"currawong-yara-marker\" condition: $a }";

    #[test]
    fn a_panicking_build_is_an_error_naming_the_cause() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("good.yar"), MARKER).unwrap();
        let _fail = FailBuild::on();
        let err = compile_dir(dir.path())
            .err()
            .expect("build failure is an error");
        assert!(err.contains("WASM module is not valid"), "{err}");
        assert!(err.contains("MemoryDenyWriteExecute"), "{err}");
        assert!(YaraEngine::new(dir.path()).is_err());
    }

    #[test]
    fn a_panicking_reload_keeps_the_last_good_rules() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("good.yar"), MARKER).unwrap();
        let engine = YaraEngine::new(dir.path()).unwrap();
        std::fs::write(
            dir.path().join("second.yar"),
            "rule Second { condition: true }",
        )
        .unwrap();
        let err = {
            let _fail = FailBuild::on();
            engine.reload().unwrap_err()
        };
        assert!(err.contains("WASM module is not valid"), "{err}");
        let current = engine.current();
        assert_eq!(current.generation, 0);
        assert_eq!(current.summary.rules, 1);
        assert_eq!(engine.reload().unwrap(), 1);
        assert_eq!(engine.current().summary.rules, 2);
    }

    #[test]
    fn a_non_string_panic_is_still_an_error() {
        let err = catch_build(|| std::panic::panic_any(7_u8))
            .err()
            .expect("error");
        assert!(err.contains("unknown panic"), "{err}");
    }
}
