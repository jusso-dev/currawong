//! Scanner trait. Later on-premises engines implement the same trait.
use async_trait::async_trait;

pub mod yara;

#[derive(Debug, Clone)]
pub struct ScanItem<'a> {
    pub name: &'a str,
    pub bytes: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngineResult {
    Clean,
    Malware { signature: String },
    Suspicious { detail: String },
    Failed { reason: String, unreachable: bool },
}

#[async_trait]
pub trait Scanner: Send + Sync {
    fn name(&self) -> &str;
    async fn scan(&self, item: &ScanItem<'_>) -> EngineResult;
}

/// Name used by issue #24. Same contract as [`Scanner`].
pub trait Engine: Scanner {}
impl<T: Scanner + ?Sized> Engine for T {}
