//! Panic-free entry points used by cargo-fuzz and the `cargo test` stand-in.
use crate::{command::parse_command, data::decode_data};

pub fn command(data: &[u8]) {
    let line = String::from_utf8_lossy(data);
    let end = line.find(['\n', '\r']).unwrap_or(line.len()).min(4096);
    let _ = parse_command(&line[..end]);
}

pub fn data(data: &[u8]) {
    let capped = if data.len() > 256 * 1024 {
        &data[..256 * 1024]
    } else {
        data
    };
    let _ = decode_data(capped, 1000, 1024 * 1024);
}
