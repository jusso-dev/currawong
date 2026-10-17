//! SQLite policy store. The admin API edits policies through these calls;
//! the pack can be imported from and exported to TOML.
//!
//! Every edit names an owner namespace: `None` for the platform, `Some(tenant)`
//! for a tenant. A tenant can only read and write its own policies and groups,
//! cannot write global scope and cannot override the floor.
//!
//! Calls are synchronous. Async callers run them on a blocking thread.
use crate::model::{valid_tenant, Policy, PolicyError, PolicySet, Scope};
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;

/// Applied in order. `PRAGMA user_version` records how many have run.
const MIGRATIONS: &[&str] = &[include_str!("../migrations/0001_policies.sql")];

/// Columns of `policies` in the current layout, to refuse databases written by
/// an earlier development build of migration 0001.
const POLICY_COLUMNS: &[&str] = &[
    "tenant_id TEXT",
    "id TEXT",
    "scope_kind TEXT",
    "scope_value TEXT",
    "priority INTEGER",
    "enabled INTEGER",
    "dry_run INTEGER",
    "mandatory INTEGER",
    "override_floor TEXT",
    "conditions TEXT",
    "actions TEXT",
];

pub struct PolicyStore {
    conn: Connection,
}

fn db(err: impl std::fmt::Display) -> PolicyError {
    PolicyError::Store(err.to_string())
}

fn ns(owner: Option<&str>) -> &str {
    owner.unwrap_or("")
}

type Row = (
    String,
    String,
    String,
    Option<String>,
    i64,
    bool,
    bool,
    bool,
    String,
    String,
    String,
);

impl PolicyStore {
    pub fn open(path: &Path) -> Result<Self, PolicyError> {
        Self::migrate(Connection::open(path).map_err(db)?)
    }

    pub fn open_in_memory() -> Result<Self, PolicyError> {
        Self::migrate(Connection::open_in_memory().map_err(db)?)
    }

    fn migrate(conn: Connection) -> Result<Self, PolicyError> {
        let done: usize = conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .map_err(db)?;
        for (index, sql) in MIGRATIONS.iter().enumerate().skip(done) {
            conn.execute_batch(sql).map_err(db)?;
            conn.pragma_update(None, "user_version", index + 1)
                .map_err(db)?;
        }
        let mut stmt = conn
            .prepare("SELECT name || ' ' || type FROM pragma_table_info('policies') ORDER BY cid")
            .map_err(db)?;
        let columns = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(db)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(db)?;
        let meta: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM sqlite_master WHERE name = 'policy_meta'",
                [],
                |row| row.get(0),
            )
            .map_err(db)?;
        if columns != POLICY_COLUMNS || !meta {
            return Err(PolicyError::Store(
                "policy database has an old layout from a development build; \
                 move it aside and restart to seed a new one"
                    .into(),
            ));
        }
        drop(stmt);
        Ok(Self { conn })
    }

    /// Goes up on every write. Cheap to poll.
    pub fn revision(&self) -> Result<i64, PolicyError> {
        let value: Option<String> = self
            .conn
            .query_row(
                "SELECT value FROM policy_meta WHERE key = 'revision'",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(db)?;
        Ok(value.and_then(|v| v.parse().ok()).unwrap_or(0))
    }

    pub fn seeded(&self) -> Result<bool, PolicyError> {
        self.conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM policy_meta WHERE key = 'seeded'",
                [],
                |row| row.get(0),
            )
            .map_err(db)
    }

    /// Every namespace, for the engine, read in one transaction.
    pub fn load(&self) -> Result<PolicySet, PolicyError> {
        let tx = self.conn.unchecked_transaction().map_err(db)?;
        let set = snapshot(&tx)?;
        tx.finish().map_err(db)?;
        set.validate()?;
        Ok(set)
    }

    pub fn list(&self, owner: Option<&str>) -> Result<Vec<Policy>, PolicyError> {
        policies(&self.conn, Some(owner))
    }

    pub fn get(&self, owner: Option<&str>, id: &str) -> Result<Option<Policy>, PolicyError> {
        Ok(self.list(owner)?.into_iter().find(|p| p.id == id))
    }

    /// Insert or replace one policy in the owner's namespace.
    pub fn upsert(&mut self, owner: Option<&str>, policy: &Policy) -> Result<(), PolicyError> {
        let policy = owned(owner, policy)?;
        self.write(|tx| upsert(tx, &policy))
    }

    pub fn delete(&mut self, owner: Option<&str>, id: &str) -> Result<bool, PolicyError> {
        let owner = namespace(owner)?;
        self.write(|tx| {
            let changed = tx
                .execute(
                    "DELETE FROM policies WHERE tenant_id = ?1 AND id = ?2",
                    [owner, id],
                )
                .map_err(db)?;
            Ok(changed > 0)
        })
    }

    /// Replace one of the owner's groups. An empty list removes it.
    pub fn set_group(
        &mut self,
        owner: Option<&str>,
        name: &str,
        members: &[String],
    ) -> Result<(), PolicyError> {
        let owner = namespace(owner)?;
        self.write(|tx| set_group(tx, owner, name, members))
    }

    /// Replace the owner's policies with the pack's, and set the groups the
    /// pack names. Other namespaces and unnamed groups are left alone.
    pub fn import(&mut self, owner: Option<&str>, set: &PolicySet) -> Result<(), PolicyError> {
        if !set.tenant_groups.is_empty() {
            return Err(PolicyError::Invalid(
                "tenant_groups can only be seeded, import into each tenant instead".into(),
            ));
        }
        let policies = set
            .policies
            .iter()
            .map(|p| owned(owner, p))
            .collect::<Result<Vec<_>, _>>()?;
        let owner = namespace(owner)?;
        self.write(|tx| {
            tx.execute("DELETE FROM policies WHERE tenant_id = ?1", [owner])
                .map_err(db)?;
            for policy in &policies {
                upsert(tx, policy)?;
            }
            for (name, members) in &set.groups {
                set_group(tx, owner, name, members)?;
            }
            Ok(())
        })
    }

    pub fn import_toml(&mut self, owner: Option<&str>, text: &str) -> Result<(), PolicyError> {
        self.import(owner, &PolicySet::from_toml(text)?)
    }

    /// The owner's namespace as a pack, from one consistent read.
    pub fn export_toml(&self, owner: Option<&str>) -> Result<String, PolicyError> {
        let mut all = self.load()?;
        let groups = match owner {
            None => std::mem::take(&mut all.groups),
            Some(tenant) => all.tenant_groups.remove(tenant).unwrap_or_default(),
        };
        PolicySet {
            groups,
            tenant_groups: Default::default(),
            policies: all
                .policies
                .into_iter()
                .filter(|p| p.tenant_id.as_deref() == owner)
                .collect(),
        }
        .to_toml()
    }

    /// Import a full operator pack, every namespace, once. Later calls do nothing.
    pub fn seed(&mut self, set: &PolicySet) -> Result<bool, PolicyError> {
        set.validate()?;
        if self.seeded()? {
            return Ok(false);
        }
        self.write(|tx| {
            for policy in &set.policies {
                upsert(tx, policy)?;
            }
            for (name, members) in &set.groups {
                set_group(tx, "", name, members)?;
            }
            for (tenant, groups) in &set.tenant_groups {
                for (name, members) in groups {
                    set_group(tx, tenant, name, members)?;
                }
            }
            tx.execute(
                "INSERT OR REPLACE INTO policy_meta (key, value) VALUES ('seeded', '1')",
                [],
            )
            .map_err(db)?;
            Ok(true)
        })
    }

    /// Run a write in one transaction and bump the revision with it.
    fn write<T>(
        &mut self,
        f: impl FnOnce(&Connection) -> Result<T, PolicyError>,
    ) -> Result<T, PolicyError> {
        let tx = self.conn.transaction().map_err(db)?;
        let out = f(&tx)?;
        tx.execute(
            "INSERT INTO policy_meta (key, value) VALUES ('revision', '1') \
             ON CONFLICT (key) DO UPDATE SET value = CAST(value AS INTEGER) + 1",
            [],
        )
        .map_err(db)?;
        tx.commit().map_err(db)?;
        Ok(out)
    }
}

fn snapshot(conn: &Connection) -> Result<PolicySet, PolicyError> {
    let mut set = PolicySet {
        policies: policies(conn, None)?,
        ..PolicySet::default()
    };
    let mut stmt = conn
        .prepare("SELECT tenant_id, name, address FROM policy_groups ORDER BY 1, 2, 3")
        .map_err(db)?;
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .map_err(db)?;
    for row in rows {
        let (tenant, name, address) = row.map_err(db)?;
        let groups = if tenant.is_empty() {
            &mut set.groups
        } else {
            set.tenant_groups.entry(tenant).or_default()
        };
        groups.entry(name).or_default().push(address);
    }
    Ok(set)
}

/// Policies in one namespace, or all of them when `only` is `None`.
fn policies(conn: &Connection, only: Option<Option<&str>>) -> Result<Vec<Policy>, PolicyError> {
    let mut stmt = conn
        .prepare(
            "SELECT tenant_id, id, scope_kind, scope_value, priority, enabled, dry_run, \
             mandatory, override_floor, conditions, actions FROM policies \
             WHERE ?1 IS NULL OR tenant_id = ?1 ORDER BY tenant_id, id",
        )
        .map_err(db)?;
    let rows = stmt
        .query_map([only.map(ns)], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
                row.get(7)?,
                row.get(8)?,
                row.get(9)?,
                row.get(10)?,
            ))
        })
        .map_err(db)?;
    let mut out = Vec::new();
    for row in rows {
        let (tenant, id, kind, value, priority, enabled, dry_run, mandatory, floor, c, a): Row =
            row.map_err(db)?;
        out.push(Policy {
            id,
            tenant_id: (!tenant.is_empty()).then_some(tenant),
            scope: Scope::from_parts(&kind, value)?,
            priority,
            enabled,
            dry_run,
            mandatory,
            override_floor: serde_json::from_str(&floor).map_err(db)?,
            conditions: serde_json::from_str(&c).map_err(db)?,
            actions: serde_json::from_str(&a).map_err(db)?,
        });
    }
    Ok(out)
}

/// The namespace key. An empty or padded tenant id would alias the platform.
fn namespace(owner: Option<&str>) -> Result<&str, PolicyError> {
    match owner {
        Some(tenant) if !valid_tenant(tenant) => Err(PolicyError::Invalid(format!(
            "tenant id {tenant:?} is not allowed"
        ))),
        _ => Ok(ns(owner)),
    }
}

/// The policy as it will be stored under `owner`. A tenant cannot write into
/// another namespace; validation then refuses global scope and floor overrides.
fn owned(owner: Option<&str>, policy: &Policy) -> Result<Policy, PolicyError> {
    namespace(owner)?;
    if policy.tenant_id.is_some() && policy.tenant_id.as_deref() != owner {
        return Err(PolicyError::Invalid(format!(
            "{}: belongs to another namespace",
            policy.id
        )));
    }
    let mut policy = policy.clone();
    policy.tenant_id = owner.map(str::to_string);
    policy.validate()?;
    Ok(policy)
}

fn upsert(conn: &Connection, policy: &Policy) -> Result<(), PolicyError> {
    conn.execute(
        "INSERT OR REPLACE INTO policies (tenant_id, id, scope_kind, scope_value, priority, \
         enabled, dry_run, mandatory, override_floor, conditions, actions) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            ns(policy.tenant_id.as_deref()),
            policy.id,
            policy.scope.kind(),
            policy.scope.value(),
            policy.priority,
            policy.enabled,
            policy.dry_run,
            policy.mandatory,
            serde_json::to_string(&policy.override_floor).map_err(db)?,
            serde_json::to_string(&policy.conditions).map_err(db)?,
            serde_json::to_string(&policy.actions).map_err(db)?,
        ],
    )
    .map_err(db)?;
    Ok(())
}

fn set_group(
    conn: &Connection,
    tenant: &str,
    name: &str,
    members: &[String],
) -> Result<(), PolicyError> {
    conn.execute(
        "DELETE FROM policy_groups WHERE tenant_id = ?1 AND name = ?2",
        [tenant, name],
    )
    .map_err(db)?;
    for address in members {
        conn.execute(
            "INSERT OR IGNORE INTO policy_groups (tenant_id, name, address) VALUES (?1, ?2, ?3)",
            [tenant, name, address],
        )
        .map_err(db)?;
    }
    Ok(())
}
