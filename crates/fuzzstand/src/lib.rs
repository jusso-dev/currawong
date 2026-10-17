//! Runs the same library entry points as `fuzz/fuzz_targets` on fixed seeds.
//! `cargo test -p currawong-fuzzstand` does not need libfuzzer or cargo-fuzz.
//! `cargo +nightly fuzz build` in `fuzz/` is the optional libFuzzer build.

#[cfg(test)]
fn seeds() -> Vec<Vec<u8>> {
    vec![
        Vec::new(),
        b"EHLO example.test\r\n".to_vec(),
        b"MAIL FROM:<a@example.test>\r\n".to_vec(),
        b"\r\n.\r\n".to_vec(),
        b"From: a@example.test\r\nSubject: hi\r\n\r\nhello https://example.test/a\r\n".to_vec(),
        b"OFFICIAL: Sensitive".to_vec(),
        b"123456782".to_vec(),
        vec![0, 1, 2, 255, 10, 13],
        b"PK\x03\x04".to_vec(),
    ]
}

#[test]
fn parser_seeds_do_not_panic() {
    for seed in seeds() {
        currawong_smtp::fuzz::command(&seed);
        currawong_smtp::fuzz::data(&seed);
        currawong_parser::fuzz::mime(&seed);
        currawong_parser::fuzz::archive(&seed);
        let _ = currawong_parser::fuzz::urls_in(&seed);
        currawong_scan::urls::fuzz(&seed);
        currawong_dlp::fuzz_scan(&seed);
    }
}
