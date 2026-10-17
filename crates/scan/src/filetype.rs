//! Active-content detection that does not need ClamAV.
use crate::engines::{EngineResult, ScanItem, Scanner};
use async_trait::async_trait;
use currawong_core::config::ExtractLimits;
use currawong_core::PartFlag;
use currawong_parser::archive::extract;
use currawong_parser::filetype::{detect, flags_for};
use currawong_parser::office::ooxml_macro_bytes;

pub struct FileTypeScanner {
    pub treat_macros_as_active: bool,
    pub treat_executables_as_active: bool,
    pub limits: ExtractLimits,
}

impl Default for FileTypeScanner {
    fn default() -> Self {
        Self {
            treat_macros_as_active: true,
            treat_executables_as_active: true,
            limits: ExtractLimits::default(),
        }
    }
}

#[async_trait]
impl Scanner for FileTypeScanner {
    fn name(&self) -> &str {
        "filetype"
    }

    async fn scan(&self, item: &ScanItem<'_>) -> EngineResult {
        let kind = detect(item.bytes);
        let mut flags = flags_for(item.bytes, Some(item.name), &kind);
        if ooxml_macro_bytes(item.bytes) {
            flags.push(PartFlag::HasMacro);
        }
        let extracted = extract(item.bytes, Some(item.name), &self.limits, &[]);
        for part in &extracted.parts {
            for flag in &part.flags {
                if !flags.contains(flag) {
                    flags.push(*flag);
                }
            }
        }
        if self.treat_executables_as_active && flags.contains(&PartFlag::Executable) {
            return EngineResult::Suspicious {
                detail: format!("executable content presented as {}", item.name),
            };
        }
        if self.treat_macros_as_active && flags.contains(&PartFlag::HasMacro) {
            return EngineResult::Suspicious {
                detail: format!("macro document {}", item.name),
            };
        }
        if flags.contains(&PartFlag::LimitExceeded) {
            return EngineResult::Failed {
                reason: "archive extraction limit exceeded".into(),
                unreachable: false,
            };
        }
        EngineResult::Clean
    }
}
