//! Any engine that reports malware wins. A required engine that is down defers.
use crate::engines::EngineResult;

#[derive(Debug, Clone)]
pub struct EngineOutput {
    pub name: String,
    pub result: EngineResult,
    pub required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Combined {
    pub malware: bool,
    pub active_content: bool,
    pub defer: bool,
    pub fail_closed: bool,
    pub notes: Vec<String>,
}

pub fn combine(outputs: &[EngineOutput], parser_failed: bool) -> Combined {
    let mut combined = Combined {
        malware: false,
        active_content: false,
        defer: false,
        fail_closed: parser_failed,
        notes: Vec::new(),
    };
    if parser_failed {
        combined.notes.push("parser worker failed closed".into());
    }
    for output in outputs {
        match &output.result {
            EngineResult::Clean => {}
            EngineResult::Malware { signature } => {
                combined.malware = true;
                combined.notes.push(format!("{}: {signature}", output.name));
            }
            EngineResult::Suspicious { detail } => {
                combined.active_content = true;
                combined.notes.push(format!("{}: {detail}", output.name));
            }
            EngineResult::Failed {
                reason,
                unreachable,
            } => {
                if *unreachable && output.required {
                    combined.defer = true;
                    combined
                        .notes
                        .push(format!("{} unreachable: {reason}", output.name));
                } else if *unreachable {
                    combined
                        .notes
                        .push(format!("{} skipped: {reason}", output.name));
                } else {
                    combined.fail_closed = true;
                    combined
                        .notes
                        .push(format!("{} failed: {reason}", output.name));
                }
            }
        }
    }
    combined
}
