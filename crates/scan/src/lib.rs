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
pub mod urls;

use std::sync::OnceLock;

pub use clamav::{ClamdAddress, ClamdClient};
pub use combine::{combine, EngineOutput};
pub use engines::yara::YaraEngine;
pub use engines::{Engine, EngineResult, ScanItem, Scanner};
pub use pool::{ScanOutcome, WorkerPool};

/// The EICAR test string, decoded at run time from XOR bytes so the
/// contiguous string never appears in the repository or in any build artifact.
pub fn eicar() -> &'static [u8] {
    const ENCODED: [u8; 68] = [
        114, 31, 101, 11, 122, 15, 106, 107, 122, 113, 30, 118, 122, 112, 114, 31, 30, 2, 122, 116,
        3, 29, 105, 105, 3, 29, 87, 14, 111, 99, 105, 107, 120, 7, 121, 126, 107, 100, 110, 107,
        120, 110, 7, 107, 100, 126, 99, 124, 99, 120, 127, 121, 7, 126, 111, 121, 126, 7, 108, 99,
        102, 111, 11, 14, 98, 1, 98, 0,
    ];
    static EICAR: OnceLock<Vec<u8>> = OnceLock::new();
    EICAR
        .get_or_init(|| {
            let key = std::hint::black_box(0x2a);
            ENCODED.iter().map(|byte| byte ^ key).collect()
        })
        .as_slice()
}
