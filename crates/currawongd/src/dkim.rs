//! `currawongd dkim ...`: generate and rotate keys, print the DNS records to
//! publish. Stands in for the admin API until that crate exists.
use clap::Subcommand;
use currawong_auth::{generate, KeyStore, StoredKey};
use currawong_core::config::Config;

#[derive(Debug, Subcommand)]
pub enum DkimCommand {
    /// Create a key for a tenant domain and print its TXT record.
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
    /// Create a new selector and retire the active key of the same
    /// algorithm. The old record must stay in DNS for seven days.
    Rotate {
        #[arg(long)]
        tenant: String,
        #[arg(long)]
        domain: String,
        #[arg(long)]
        selector: String,
        #[arg(long, default_value = "rsa")]
        algorithm: String,
    },
    /// Print every record that should currently be published.
    Records {
        #[arg(long)]
        tenant: String,
        #[arg(long)]
        domain: String,
    },
}

/// Runs the command and returns what to print.
pub fn run(cfg: &Config, command: DkimCommand) -> Result<String, String> {
    let store = KeyStore::open(&cfg.dkim.database, &cfg.dkim.kek_path)?;
    let now = now();
    match command {
        DkimCommand::Generate {
            tenant,
            domain,
            selector,
            algorithm,
        } => {
            let key = generate(&tenant, &domain, &selector, &algorithm)?;
            store.insert(&key)?;
            Ok(record(&key))
        }
        DkimCommand::Rotate {
            tenant,
            domain,
            selector,
            algorithm,
        } => {
            let key = generate(&tenant, &domain, &selector, &algorithm)?;
            store.rotate(&key, now)?;
            Ok(format!(
                "{}; keep the previous selector published for seven days\n",
                record(&key).trim_end()
            ))
        }
        DkimCommand::Records { tenant, domain } => Ok(store
            .publishable_keys(&tenant, &domain, now)?
            .iter()
            .map(record)
            .collect()),
    }
}

/// Zone-file line. TXT strings are split at 255 bytes (RFC 1035 3.3.14) so
/// RSA-2048 records load as is.
pub fn record(key: &StoredKey) -> String {
    let chunks: Vec<String> = key
        .public_txt
        .as_bytes()
        .chunks(255)
        .map(|chunk| format!("\"{}\"", String::from_utf8_lossy(chunk)))
        .collect();
    let state = if key.active { "active" } else { "retired" };
    format!(
        "{}. IN TXT {} ; {state}\n",
        key.dns_name(),
        chunks.join(" ")
    )
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}
