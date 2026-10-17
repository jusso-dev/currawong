//! Writes the EICAR test string into OUT_DIR. The plaintext is not stored in git.
fn main() {
    let encoded: [u8; 68] = [
        114, 31, 101, 11, 122, 15, 106, 107, 122, 113, 30, 118, 122, 112, 114, 31, 30, 2, 122, 116,
        3, 29, 105, 105, 3, 29, 87, 14, 111, 99, 105, 107, 120, 7, 121, 126, 107, 100, 110, 107,
        120, 110, 7, 107, 100, 126, 99, 124, 99, 120, 127, 121, 7, 126, 111, 121, 126, 7, 108, 99,
        102, 111, 11, 14, 98, 1, 98, 0,
    ];
    let plain: Vec<u8> = encoded.iter().map(|byte| byte ^ 0x2a).collect();
    let out = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("eicar.txt");
    std::fs::write(out, plain).unwrap();
}
