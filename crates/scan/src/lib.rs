//! Malware engines and the parser worker pool.
//!
//! Official ClamAV signatures are the baseline, not a complete detector.
//! A message is malware if any engine says so. A required engine that cannot
//! be reached fails closed (defer). File-type and macro checks run in the
//! parser worker (ADR 0002), never in the daemon, and work without ClamAV.
pub mod clamav;
pub mod combine;
pub mod engines;
pub mod pool;
pub mod url_rewrite;

pub use clamav::{ClamdAddress, ClamdClient};
pub use combine::{combine, EngineOutput};
pub use engines::yara::YaraEngine;
pub use engines::{Engine, EngineResult, ScanItem, Scanner};
pub use pool::{ScanOutcome, WorkerPool};

pub fn eicar() -> &'static [u8] {
    include_bytes!(concat!(env!("OUT_DIR"), "/eicar.txt"))
}
