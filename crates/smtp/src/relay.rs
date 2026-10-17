//! Trusted networks and SMTP AUTH credentials for outbound relay.
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use currawong_core::config::TenantConfig;
use ipnet::IpNet;
use rusqlite::{params, Connection};
use std::{
    net::IpAddr,
    path::{Path, PathBuf},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthContext {
    pub tenant_id: String,
    pub principal: String,
}

#[derive(Debug, Clone)]
pub struct Tenant {
    pub id: String,
    pub domains: Vec<String>,
    pub cidrs: Vec<IpNet>,
}

pub struct Relay {
    tenants: Vec<Tenant>,
    database: PathBuf,
}

impl Relay {
    pub fn open(database: &Path, tenants: &[TenantConfig]) -> Result<Self, String> {
        let relay = Self {
            tenants: tenants
                .iter()
                .map(|tenant| {
                    let cidrs = tenant
                        .trusted_cidrs
                        .iter()
                        .map(|cidr| {
                            cidr.parse::<IpNet>()
                                .map_err(|err| format!("{cidr}: {err}"))
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    Ok(Tenant {
                        id: tenant.id.clone(),
                        domains: tenant
                            .domains
                            .iter()
                            .map(|domain| domain.to_ascii_lowercase())
                            .collect(),
                        cidrs,
                    })
                })
                .collect::<Result<Vec<_>, String>>()?,
            database: database.to_path_buf(),
        };
        relay.with_conn(|_| Ok(()))?;
        Ok(relay)
    }

    pub fn empty() -> Self {
        Self {
            tenants: Vec::new(),
            database: PathBuf::from("/dev/null"),
        }
    }

    pub fn tenant_for_ip(&self, ip: IpAddr) -> Option<&Tenant> {
        self.tenants
            .iter()
            .filter(|tenant| tenant.cidrs.iter().any(|net| net.contains(&ip)))
            .max_by_key(|tenant| {
                tenant
                    .cidrs
                    .iter()
                    .filter(|net| net.contains(&ip))
                    .map(|net| net.prefix_len())
                    .max()
                    .unwrap_or(0)
            })
    }

    pub fn owns_domain(&self, tenant_id: &str, domain: &str) -> bool {
        let domain = domain.to_ascii_lowercase();
        self.tenants.iter().any(|tenant| {
            tenant.id == tenant_id
                && tenant
                    .domains
                    .iter()
                    .any(|owned| owned.eq_ignore_ascii_case(&domain))
        })
    }

    pub fn upsert_credential(
        &self,
        tenant_id: &str,
        username: &str,
        password: &str,
    ) -> Result<(), String> {
        let salt = SaltString::generate(&mut OsRng);
        let hash = Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .map_err(|err| err.to_string())?
            .to_string();
        let id = format!("{tenant_id}:{username}");
        self.with_conn(|conn| {
            conn.execute(
                "INSERT INTO relay_credentials (id, tenant_id, username, argon2_hash)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(id) DO UPDATE SET argon2_hash = excluded.argon2_hash",
                params![id, tenant_id, username, hash],
            )
            .map_err(|err| err.to_string())?;
            Ok(())
        })
    }

    pub fn authenticate(
        &self,
        username: &str,
        password: &str,
    ) -> Result<Option<AuthContext>, String> {
        if self.database == Path::new("/dev/null") {
            return Ok(None);
        }
        let row: Option<(String, String)> = self.with_conn(|conn| {
            let mut stmt = conn
                .prepare("SELECT tenant_id, argon2_hash FROM relay_credentials WHERE username = ?1")
                .map_err(|err| err.to_string())?;
            let mut rows = stmt
                .query(params![username])
                .map_err(|err| err.to_string())?;
            if let Some(row) = rows.next().map_err(|err| err.to_string())? {
                Ok(Some((
                    row.get(0).map_err(|err| err.to_string())?,
                    row.get(1).map_err(|err| err.to_string())?,
                )))
            } else {
                Ok(None)
            }
        })?;
        let Some((tenant_id, hash)) = row else {
            return Ok(None);
        };
        let parsed = PasswordHash::new(&hash).map_err(|err| err.to_string())?;
        if Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_err()
        {
            return Ok(None);
        }
        Ok(Some(AuthContext {
            tenant_id,
            principal: username.to_string(),
        }))
    }

    fn with_conn<T>(&self, f: impl FnOnce(&Connection) -> Result<T, String>) -> Result<T, String> {
        if self.database == Path::new("/dev/null") {
            return Err("relay database is not configured".into());
        }
        if let Some(parent) = self.database.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|err| err.to_string())?;
            }
        }
        let conn = Connection::open(&self.database).map_err(|err| err.to_string())?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS relay_credentials (
                id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                username TEXT NOT NULL UNIQUE,
                argon2_hash TEXT NOT NULL
            );",
        )
        .map_err(|err| err.to_string())?;
        f(&conn)
    }
}
