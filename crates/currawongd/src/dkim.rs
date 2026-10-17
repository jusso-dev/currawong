//! `currawongd dkim ...`: generate keys, print the DNS records to publish,
//! and activate a key once DNS serves its record. Stands in for the admin
//! API until that crate exists.
//!
//! Rotation is `generate` with a new selector, publish, then `activate`:
//! activation retires the previous key of the same algorithm, whose record
//! must stay in DNS for seven days.
use clap::Subcommand;
use currawong_auth::{generate, now_secs, AuthChecker, KeyStore, StoredKey};
use currawong_core::config::Config;

#[derive(Debug, Subcommand)]
pub enum DkimCommand {
    /// Create a pending key and print the TXT record to publish. It does
    /// not sign until `activate`.
    Generate {
        #[arg(long)]
        tenant: String,
        #[arg(long)]
        domain: String,
        #[arg(long)]
        selector: String,
        /// `rsa` (RSA-2048) or `ed25519`.
        #[arg(long, default_value = "rsa")]
        algorithm: String,
    },
    /// Check DNS serves the selector's record, then make the key active and
    /// retire the previous active key of the same algorithm.
    Activate {
        #[arg(long)]
        tenant: String,
        #[arg(long)]
        domain: String,
        #[arg(long)]
        selector: String,
    },
    /// Print every record that should be in DNS now, with its state.
    Records {
        #[arg(long)]
        tenant: String,
        #[arg(long)]
        domain: String,
    },
}

/// Runs the command and returns what to print. `dns` is only used by
/// `activate`.
pub async fn run(cfg: &Config, command: DkimCommand, dns: &AuthChecker) -> Result<String, String> {
    let store = KeyStore::open(&cfg.dkim.database, &cfg.dkim.kek_path)?;
    let now = now_secs();
    match command {
        DkimCommand::Generate {
            tenant,
            domain,
            selector,
            algorithm,
        } => {
            let key = generate(&tenant, &domain, &selector, &algorithm)?;
            store.insert(&key)?;
            Ok(format!(
                "{}publish this record, then run: currawongd dkim activate --tenant {} --domain {} --selector {}\n",
                record(&key),
                key.tenant_id,
                key.domain,
                key.selector
            ))
        }
        DkimCommand::Activate {
            tenant,
            domain,
            selector,
        } => {
            let key = store
                .find(&tenant, &domain, &selector)?
                .ok_or_else(|| format!("no key {selector} for {tenant} {domain}"))?;
            if key.state() != "pending" {
                return Err(format!(
                    "{} is {}, not pending",
                    key.dns_name(),
                    key.state()
                ));
            }
            match dns.dkim_record_published(&key).await {
                Ok(true) => {}
                Ok(false) => {
                    return Err(format!(
                        "{} does not serve this key yet; publish it and retry",
                        key.dns_name()
                    ))
                }
                Err(err) => return Err(format!("{} is not published: {err}", key.dns_name())),
            }
            store.activate(&key.id, now)?;
            Ok(format!(
                "{} is active; keep retired selectors published for seven days\n",
                key.dns_name()
            ))
        }
        DkimCommand::Records { tenant, domain } => Ok(store
            .publishable_keys(&tenant, &domain, now)?
            .iter()
            .map(record)
            .collect()),
    }
}

/// Zone-file line with the key's state: `pending` (publish, not signing
/// yet), `active` (signing) or `retired` (keep until seven days after
/// retirement). TXT strings are split at 255 bytes (RFC 1035 3.3.14) so
/// RSA-2048 records load as is.
pub fn record(key: &StoredKey) -> String {
    let chunks: Vec<String> = key
        .public_txt
        .as_bytes()
        .chunks(255)
        .map(|chunk| format!("\"{}\"", String::from_utf8_lossy(chunk)))
        .collect();
    format!(
        "{}. IN TXT {} ; {}\n",
        key.dns_name(),
        chunks.join(" "),
        key.state()
    )
}
