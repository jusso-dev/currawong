//! Weighted spam rules from `rules/spam/*.toml`.
//!
//! ```toml
//! [[rule]]
//! name = "subject_shouting"
//! target = "header:Subject"   # or "body" or "uri"
//! pattern = "^[^a-z]*[A-Z]{6,}[^a-z]*$"
//! score = 1.5
//! ```
use super::SpamError;
use crate::message::MessageView;
use currawong_core::RuleHit;
use regex::Regex;
use serde::Deserialize;
use std::path::Path;

/// The rules shipped with Currawong, used when no rules directory is set.
pub const BUILTIN: &str = include_str!("../../../../rules/spam/default.toml");

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleFile {
    #[serde(default)]
    rule: Vec<RuleSpec>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleSpec {
    name: String,
    target: String,
    pattern: String,
    score: f64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Header(String),
    Body,
    Uri,
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub name: String,
    pub target: Target,
    pub pattern: Regex,
    pub score: f64,
}

#[derive(Debug, Clone, Default)]
pub struct RuleSet {
    rules: Vec<Rule>,
}

impl RuleSet {
    pub fn builtin() -> Result<Self, SpamError> {
        Self::parse(BUILTIN, "built-in")
    }

    /// Every `*.toml` file in `dir`, in file name order.
    pub fn load_dir(dir: &Path) -> Result<Self, SpamError> {
        let read = |err: std::io::Error| SpamError::Rules(format!("{}: {err}", dir.display()));
        let mut paths: Vec<_> = std::fs::read_dir(dir)
            .map_err(read)?
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .filter(|path| path.extension().is_some_and(|ext| ext == "toml"))
            .collect();
        paths.sort();
        let mut set = Self::default();
        for path in paths {
            let text = std::fs::read_to_string(&path).map_err(read)?;
            set.extend(Self::parse(&text, &path.display().to_string())?)?;
        }
        Ok(set)
    }

    pub fn parse(text: &str, origin: &str) -> Result<Self, SpamError> {
        let file: RuleFile =
            toml::from_str(text).map_err(|err| SpamError::Rules(format!("{origin}: {err}")))?;
        let mut set = Self::default();
        for spec in file.rule {
            let rule = compile(spec).map_err(|err| SpamError::Rules(format!("{origin}: {err}")))?;
            set.extend(Self { rules: vec![rule] })?;
        }
        Ok(set)
    }

    fn extend(&mut self, other: Self) -> Result<(), SpamError> {
        for rule in other.rules {
            if self.rules.iter().any(|known| known.name == rule.name) {
                return Err(SpamError::Rules(format!(
                    "rule {} is defined twice",
                    rule.name
                )));
            }
            self.rules.push(rule);
        }
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Rules that match, each counted once.
    pub fn evaluate(&self, view: &MessageView, urls: &[String]) -> Vec<RuleHit> {
        self.rules
            .iter()
            .filter(|rule| match &rule.target {
                Target::Header(name) => view.header(name).any(|value| rule.pattern.is_match(value)),
                Target::Body => rule.pattern.is_match(&view.body),
                Target::Uri => view
                    .urls
                    .iter()
                    .chain(urls)
                    .any(|link| rule.pattern.is_match(link)),
            })
            .map(|rule| RuleHit {
                name: rule.name.clone(),
                score: rule.score,
            })
            .collect()
    }
}

fn compile(spec: RuleSpec) -> Result<Rule, String> {
    if spec.name.is_empty() {
        return Err("a rule has an empty name".into());
    }
    let target = match spec.target.as_str() {
        "body" => Target::Body,
        "uri" => Target::Uri,
        other => match other.strip_prefix("header:") {
            Some(name) if !name.is_empty() => Target::Header(name.to_string()),
            _ => {
                return Err(format!(
                    "rule {} target '{other}' must be header:<Name>, body or uri",
                    spec.name
                ))
            }
        },
    };
    if !spec.score.is_finite() {
        return Err(format!("rule {} score must be a number", spec.name));
    }
    let pattern = Regex::new(&spec.pattern)
        .map_err(|err| format!("rule {} pattern does not compile: {err}", spec.name))?;
    Ok(Rule {
        name: spec.name,
        target,
        pattern,
        score: spec.score,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_rules_compile() {
        assert!(!RuleSet::builtin().unwrap().is_empty());
    }

    #[test]
    fn bad_rules_name_the_problem() {
        let err = RuleSet::parse(
            "[[rule]]\nname = \"x\"\ntarget = \"footer\"\npattern = \"a\"\nscore = 1.0\n",
            "test.toml",
        )
        .unwrap_err();
        assert!(err.to_string().contains("footer"), "{err}");
        let err = RuleSet::parse(
            "[[rule]]\nname = \"x\"\ntarget = \"body\"\npattern = \"(\"\nscore = 1.0\n",
            "test.toml",
        )
        .unwrap_err();
        assert!(err.to_string().contains("does not compile"), "{err}");
        let twice = "[[rule]]\nname = \"x\"\ntarget = \"body\"\npattern = \"a\"\nscore = 1.0\n";
        let err = RuleSet::parse(&format!("{twice}{twice}"), "test.toml").unwrap_err();
        assert!(err.to_string().contains("twice"), "{err}");
    }
}
