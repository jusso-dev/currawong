#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    currawong_scan::url_rewrite::fuzz(data);
});
