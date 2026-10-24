//! Click-time link protection: inbound links are rewritten to signed
//! `<base_url>/u/<token>` links, and the click service checks the real link
//! again when it is clicked.
pub mod analysis;
pub mod reputation;
pub mod rewrite;
pub mod token;
mod transfer;

pub use reputation::{CheckedUrl, LocalBlocklist, Reputation, UrlReputation};
pub use rewrite::{Delivery, RewriteError, Rewritten, UrlRewriter};
pub use token::{Claims, TokenError, UrlSigner};

/// Fuzz entry: arbitrary bytes as a message must never panic.
pub fn fuzz(data: &[u8]) {
    let data = &data[..data.len().min(64 * 1024)];
    let signer = UrlSigner::new(vec![0x5a; 32]).expect("fixed key");
    let rewriter = UrlRewriter::new(
        signer,
        "https://rewrite.local",
        &["allowed.test".into()],
        3_600,
        64 * 1024,
    )
    .expect("fixed base");
    let delivery = Delivery {
        message_id: "fuzz",
        recipient: "fuzz@example.test",
        issued_at: 0,
    };
    if let Ok(out) = rewriter.rewrite_message(data, &delivery) {
        assert!(out.links > 0 || out.message == data);
    }
}
