//! YARA matching inside the worker (ADR 0002: modules such as `pe` parse
//! hostile files). The supervisor compiles the rules and sends the serialised
//! set on stdin in a [`LoadRules`] frame. The worker never compiles rule
//! source and never loads rules from a path.
use crate::ipc::{LoadRules, ParseResponse};
use base64::Engine as _;
use currawong_core::YaraMatch;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::time::{Duration, Instant};
use yara_x::Rules;

/// The rules from the last [`LoadRules`] frame.
#[derive(Default)]
pub struct RulesCache {
    loaded: Option<(u64, Rules)>,
}

impl RulesCache {
    /// Deserialising recompiles the rules' wasm, so this is the slow step.
    /// The supervisor runs it once per worker and generation, with its own
    /// timeout, not inside a message job.
    pub fn load(&mut self, load: &LoadRules) -> ParseResponse {
        self.loaded = None;
        let result = base64::engine::general_purpose::STANDARD
            .decode(&load.yara_rules)
            .map_err(|err| format!("yara rules: {err}"))
            .and_then(|bytes| {
                Rules::deserialize(bytes).map_err(|err| format!("yara rules: {err}"))
            });
        match result {
            Ok(rules) => {
                self.loaded = Some((load.generation, rules));
                ParseResponse {
                    id: LoadRules::REPLY_ID.into(),
                    parts: Vec::new(),
                    urls: Vec::new(),
                    error: None,
                    yara: Vec::new(),
                }
            }
            Err(err) => ParseResponse::failed(LoadRules::REPLY_ID, err),
        }
    }

    pub fn get(&self, generation: u64) -> Result<&Rules, String> {
        match &self.loaded {
            Some((loaded, rules)) if *loaded == generation => Ok(rules),
            Some((loaded, _)) => Err(format!(
                "yara rules generation {loaded} loaded, {generation} requested"
            )),
            None => Err("yara rules not loaded".into()),
        }
    }
}

/// Per-message limits. Exceeding one fails the job closed.
#[derive(Debug, Clone, Copy)]
pub struct YaraBudget {
    pub time: Duration,
    pub max_bytes: u64,
    pub max_parts: u32,
}

impl Default for YaraBudget {
    fn default() -> Self {
        Self {
            time: Duration::from_secs(20),
            max_bytes: 512 * 1024 * 1024,
            max_parts: 2048,
        }
    }
}

/// One scanner per message, reused for every part. Identical content is
/// matched once.
pub struct YaraScan<'r> {
    scanner: yara_x::Scanner<'r>,
    budget: YaraBudget,
    started: Instant,
    bytes: u64,
    parts: u32,
    seen: HashSet<[u8; 32]>,
    pub matches: Vec<YaraMatch>,
    pub error: Option<String>,
}

impl<'r> YaraScan<'r> {
    pub fn new(rules: &'r Rules) -> Self {
        Self::with_budget(rules, YaraBudget::default())
    }

    pub fn with_budget(rules: &'r Rules, budget: YaraBudget) -> Self {
        Self {
            scanner: yara_x::Scanner::new(rules),
            budget,
            started: Instant::now(),
            bytes: 0,
            parts: 0,
            seen: HashSet::new(),
            matches: Vec::new(),
            error: None,
        }
    }

    pub fn scan(&mut self, part: &str, bytes: &[u8]) {
        if self.error.is_some() || !self.seen.insert(Sha256::digest(bytes).into()) {
            return;
        }
        self.parts += 1;
        self.bytes += bytes.len() as u64;
        if self.parts > self.budget.max_parts {
            self.error = Some(format!(
                "yara limit exceeded: more than {} parts",
                self.budget.max_parts
            ));
            return;
        }
        if self.bytes > self.budget.max_bytes {
            self.error = Some(format!(
                "yara limit exceeded: more than {} bytes",
                self.budget.max_bytes
            ));
            return;
        }
        let Some(left) = self
            .budget
            .time
            .checked_sub(self.started.elapsed())
            .filter(|left| !left.is_zero())
        else {
            self.error = Some(format!(
                "yara limit exceeded: more than {} s",
                self.budget.time.as_secs()
            ));
            return;
        };
        self.scanner.set_timeout(left);
        let part = clean_name(part);
        match self.scanner.scan(bytes) {
            Ok(results) => {
                for rule in results.matching_rules() {
                    self.matches.push(YaraMatch {
                        rule: rule.identifier().to_string(),
                        namespace: rule.namespace().to_string(),
                        tags: rule
                            .tags()
                            .map(|tag| tag.identifier().to_string())
                            .collect(),
                        part: part.clone(),
                    });
                }
            }
            Err(err) => self.error = Some(format!("yara scan of {part}: {err}")),
        }
    }
}

/// Attachment names come from the sender: drop control characters and cap
/// the length before they reach reports, logs and SIEM events.
pub fn clean_name(name: &str) -> String {
    name.chars().filter(|c| !c.is_control()).take(128).collect()
}
