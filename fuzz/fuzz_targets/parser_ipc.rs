#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    currawong_fuzzstand::parser_ipc(data);
});
