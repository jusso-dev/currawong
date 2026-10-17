//! Fuzz entry points shared by `fuzz/fuzz_targets` (libFuzzer, nightly) and
//! the stable `cargo test` stand-in below. Each target takes arbitrary bytes
//! and must not panic or blow up memory.
use bytes::BytesMut;
use currawong_core::config::ExtractLimits;
use tokio_util::codec::{Decoder, LengthDelimitedCodec};

/// A fuzz entry point: arbitrary bytes in, no panic out.
pub type Target = fn(&[u8]);

/// Every fuzz target by name. Names match `fuzz/fuzz_targets/<name>.rs`.
pub const TARGETS: &[(&str, Target)] = &[
    ("smtp_command", currawong_smtp::fuzz::command),
    ("smtp_data", currawong_smtp::fuzz::data),
    ("smtp_sasl", currawong_smtp::fuzz::sasl),
    ("mime_parse", currawong_parser::fuzz::mime),
    ("archive_extract", archive_extract),
    ("office_detect", office_detect),
    ("pspf_parse", pspf_parse),
    ("dlp_scan", dlp_scan),
    ("url_rewrite", url_rewrite),
    ("auth_strip", auth_strip),
    ("clamd_address", clamd_address),
    ("parser_ipc", parser_ipc),
    ("spool_envelope", spool_envelope),
];

fn cap(data: &[u8], max: usize) -> &[u8] {
    &data[..data.len().min(max)]
}

fn text(data: &[u8]) -> String {
    String::from_utf8_lossy(cap(data, 64 * 1024)).into_owned()
}

fn tight() -> ExtractLimits {
    ExtractLimits {
        max_depth: 3,
        max_uncompressed_bytes: 1024 * 1024,
        max_files: 32,
        max_ratio: 50,
    }
}

/// The first byte picks the attachment name, so name-driven paths (zip, tar,
/// gz, iso, 7z, Office) are reached. Two passwords exercise encrypted zips.
pub fn archive_extract(data: &[u8]) {
    const NAMES: [&str; 8] = [
        "a.zip", "a.tar", "a.tar.gz", "a.gz", "a.iso", "a.7z", "a.docm", "a.bin",
    ];
    let Some((&pick, rest)) = data.split_first() else {
        return;
    };
    let name = NAMES[usize::from(pick) % NAMES.len()];
    let passwords = ["infected".to_string(), "password".to_string()];
    let _ =
        currawong_parser::archive::extract(cap(rest, 256 * 1024), Some(name), &tight(), &passwords);
}

pub fn office_detect(data: &[u8]) {
    use currawong_parser::{filetype, office};
    let data = cap(data, 256 * 1024);
    let kind = filetype::detect(data);
    let _ = filetype::flags_for(data, Some("attachment.docx"), &kind);
    let _ = office::has_macro_ole(data);
    let _ = office::has_ole_object(data);
    let _ = office::ooxml_macro_bytes(data);
    let _ = office::rtf_has_object(data);
    let _ = office::password_candidates(&text(data));
}

pub fn pspf_parse(data: &[u8]) {
    let _ = currawong_dlp::parse_pspf(&text(data));
}

pub fn dlp_scan(data: &[u8]) {
    let _ = currawong_dlp::find_tfns(&text(data));
}

pub fn url_rewrite(data: &[u8]) {
    let input = text(data);
    let _ = currawong_scan::url_rewrite::find_urls(&input);
    let _ = currawong_scan::url_rewrite::rewrite(&input, "https://rewrite.local/");
    let _ = currawong_parser::fuzz::urls_in(data);
}

pub fn auth_strip(data: &[u8]) {
    let _ = currawong_auth::strip_forged(cap(data, 256 * 1024), "currawong.example.test");
}

pub fn clamd_address(data: &[u8]) {
    let input = text(cap(data, 4096));
    let _ = currawong_scan::ClamdAddress::parse(&input);
    let _ = currawong_core::config::parse_clamd_address(&input);
}

/// Length-prefixed frames as the worker reads them, then the JSON request.
pub fn parser_ipc(data: &[u8]) {
    let mut codec = LengthDelimitedCodec::builder()
        .max_frame_length(64 * 1024)
        .new_codec();
    let mut buf = BytesMut::from(cap(data, 256 * 1024));
    for _ in 0..64 {
        match codec.decode(&mut buf) {
            Ok(Some(frame)) => {
                let _ = serde_json::from_slice::<currawong_parser::ParseRequest>(&frame);
                let _ = serde_json::from_slice::<currawong_parser::ParseResponse>(&frame);
            }
            _ => return,
        }
    }
}

pub fn spool_envelope(data: &[u8]) {
    let _ = serde_json::from_slice::<currawong_spool::Envelope>(cap(data, 256 * 1024));
}

#[cfg(test)]
mod tests {
    use super::TARGETS;
    use std::{collections::BTreeSet, path::PathBuf};

    /// Mutated inputs per target per run. Deterministic, so a failure repeats.
    /// `FUZZSTAND_ROUNDS=1000000` gives a longer stable run.
    fn rounds() -> usize {
        std::env::var("FUZZSTAND_ROUNDS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(3000)
    }

    fn root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    fn seeds() -> Vec<Vec<u8>> {
        let mut seeds = vec![
            Vec::new(),
            b"EHLO example.test\r\n".to_vec(),
            b"MAIL FROM:<a@example.test> SIZE=1000\r\n".to_vec(),
            b"RCPT TO:<b@example.test>\r\n".to_vec(),
            b"Subject: hi\r\n\r\n..dot\r\n.\r\n".to_vec(),
            b"LOGIN\r\ndXNlcg==\r\ncGFzcw==\r\n".to_vec(),
            b"PLAIN AHVzZXIAcGFzcw==".to_vec(),
            b"OFFICIAL: Sensitive".to_vec(),
            b"SECURITY CLASSIFICATION: PROTECTED".to_vec(),
            b"TFN 123 456 782".to_vec(),
            b"tcp:127.0.0.1:3310".to_vec(),
            b"unix:/run/clamav/clamd.ctl".to_vec(),
            b"\x00\x00\x00\x20{\"id\":\"a\",\"raw_path\":\"/x\",\"limits\":{}}".to_vec(),
            b"{\"id\":\"01ARZ3NDEKTSV4RRFFQ69G5FAV\",\"rcpt_to\":[]}".to_vec(),
            b"Authentication-Results: currawong.example.test; spf=pass\r\n\r\nbody".to_vec(),
            b"see https://example.test/a?b=c and http://x.test".to_vec(),
            b"{\\rtf1\\object\\objdata 0102}".to_vec(),
            b"PK\x03\x04".to_vec(),
            b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1".to_vec(),
            vec![0, 1, 2, 255, 10, 13],
        ];
        for dir in ["testdata/corpus", "testdata/fixtures", "testdata/auth"] {
            // read_dir order is not stable; sort so the mutation stream repeats.
            let mut paths: Vec<PathBuf> = std::fs::read_dir(root().join(dir))
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .collect();
            paths.sort();
            for path in paths {
                seeds.push(std::fs::read(path).unwrap());
            }
        }
        seeds
    }

    /// xorshift64*: small, deterministic and good enough to pick mutations.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
        }

        fn below(&mut self, n: usize) -> usize {
            (self.next() % n.max(1) as u64) as usize
        }
    }

    fn mutate(rng: &mut Rng, seeds: &[Vec<u8>]) -> Vec<u8> {
        let mut data = seeds[rng.below(seeds.len())].clone();
        for _ in 0..=rng.below(8) {
            match rng.below(6) {
                0 if !data.is_empty() => {
                    let at = rng.below(data.len());
                    data[at] ^= 1 << rng.below(8);
                }
                1 => {
                    let at = rng.below(data.len() + 1);
                    data.insert(at, rng.next() as u8);
                }
                2 if !data.is_empty() => {
                    data.remove(rng.below(data.len()));
                }
                3 => data.truncate(rng.below(data.len() + 1)),
                4 => {
                    let other = &seeds[rng.below(seeds.len())];
                    let at = rng.below(data.len() + 1);
                    let from = rng.below(other.len() + 1);
                    data.splice(at..at, other[from..].iter().copied());
                }
                _ => {
                    let interesting: [&[u8]; 6] = [
                        b"\r\n",
                        b".\r\n",
                        b"\xff\xfe",
                        b"\x00\x00\x00\x00",
                        b"=?",
                        b"\"",
                    ];
                    let at = rng.below(data.len() + 1);
                    let pick = interesting[rng.below(interesting.len())];
                    data.splice(at..at, pick.iter().copied());
                }
            }
        }
        data.truncate(16 * 1024);
        data
    }

    #[test]
    fn every_target_survives_seeds_and_mutations() {
        let seeds = seeds();
        let rounds = rounds();
        for (index, (name, target)) in TARGETS.iter().enumerate() {
            for seed in &seeds {
                target(seed);
            }
            let mut rng = Rng(0x9e37_79b9_7f4a_7c15 ^ (index as u64 + 1));
            for round in 0..rounds {
                let input = mutate(&mut rng, &seeds);
                let outcome = std::panic::catch_unwind(|| target(&input));
                assert!(
                    outcome.is_ok(),
                    "{name} panicked in round {round} on {:?}",
                    String::from_utf8_lossy(&input)
                );
            }
        }
    }

    #[test]
    fn targets_match_the_cargo_fuzz_package() {
        let ours: BTreeSet<String> = TARGETS.iter().map(|(name, _)| name.to_string()).collect();
        let files: BTreeSet<String> = std::fs::read_dir(root().join("fuzz/fuzz_targets"))
            .unwrap()
            .map(|entry| {
                let path = entry.unwrap().path();
                path.file_stem().unwrap().to_string_lossy().into_owned()
            })
            .collect();
        assert_eq!(ours, files);
        let manifest = std::fs::read_to_string(root().join("fuzz/Cargo.toml")).unwrap();
        let ci = std::fs::read_to_string(root().join("docs/ci/fuzz.yml")).unwrap();
        for name in &ours {
            assert!(
                manifest.contains(&format!("name = \"{name}\"")),
                "{name} in fuzz/Cargo.toml"
            );
            assert!(
                ci.contains(&format!("- {name}")),
                "{name} in docs/ci/fuzz.yml"
            );
        }
    }
}
