//! Malware engines and the parser worker pool.
//!
//! Official ClamAV signatures are the baseline, not a complete detector.
//! A message is malware if any engine says so. A required engine that cannot
//! be reached fails closed (defer). File-type and macro checks run even when
//! ClamAV is absent.
pub mod clamav;
pub mod combine;
pub mod engines;
pub mod filetype;
pub mod pool;
pub mod url_rewrite;

pub use clamav::{ClamdAddress, ClamdClient};
pub use combine::{combine, EngineOutput};
pub use engines::{Engine, EngineResult, ScanItem, Scanner};
pub use filetype::FileTypeScanner;
pub use pool::{ScanOutcome, WorkerPool};

pub fn eicar() -> &'static [u8] {
    include_bytes!(concat!(env!("OUT_DIR"), "/eicar.txt"))
}
