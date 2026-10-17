//! YARA matching inside the worker (ADR 0002: modules such as `pe` parse
//! hostile files). The supervisor compiles the rules and passes the path of a
//! serialised copy it wrote itself; the worker never compiles rule source.
use currawong_core::YaraMatch;
use std::path::{Path, PathBuf};
use std::time::Duration;
use yara_x::Rules;

/// Rules deserialised once per path. A new path means the supervisor reloaded.
#[derive(Default)]
pub struct RulesCache {
    loaded: Option<(PathBuf, Rules)>,
}

impl RulesCache {
    pub fn get(&mut self, path: &Path) -> Result<&Rules, String> {
        if self.loaded.as_ref().map(|(p, _)| p != path).unwrap_or(true) {
            self.loaded = None;
            let bytes = std::fs::read(path).map_err(|err| format!("yara rules: {err}"))?;
            let rules = Rules::deserialize(bytes).map_err(|err| format!("yara rules: {err}"))?;
            self.loaded = Some((path.to_path_buf(), rules));
        }
        match &self.loaded {
            Some((_, rules)) => Ok(rules),
            None => Err("yara rules not loaded".into()),
        }
    }
}

/// One scanner per message, reused for every part.
pub struct YaraScan<'r> {
    scanner: yara_x::Scanner<'r>,
    pub matches: Vec<YaraMatch>,
    pub error: Option<String>,
}

impl<'r> YaraScan<'r> {
    pub fn new(rules: &'r Rules) -> Self {
        let mut scanner = yara_x::Scanner::new(rules);
        scanner.set_timeout(Duration::from_secs(10));
        Self {
            scanner,
            matches: Vec::new(),
            error: None,
        }
    }

    pub fn scan(&mut self, part: &str, bytes: &[u8]) {
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
                        part: part.to_string(),
                    });
                }
            }
            Err(err) => {
                if self.error.is_none() {
                    self.error = Some(format!("yara scan of {part}: {err}"));
                }
            }
        }
    }
}
