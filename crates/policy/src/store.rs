//! SQLite policy store. The admin API edits policies through these calls;
//! the pack can be imported from and exported to TOML.
//!
//! Every edit names an owner namespace: `None` for the platform, `Some(tenant)`
//! for a tenant. A tenant can only read and write its own policies and groups,
//! cannot write global scope and cannot override the floor.
use crate::model::{Policy, PolicyError, PolicySet, Scope};
use rusqlite::{params, Connection};
use std::path::Path;

/// Applied in order. `PRAGMA user_version` records how many have run.
const MIGRATIONS: &[&str] = &[include_str!("../migrations/0001_policies.sql")];

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
    bool,
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
        Ok(Self { conn })
    }

    /// Every namespace, for the engine.
    pub fn load(&self) -> Result<PolicySet, PolicyError> {
        let mut set = PolicySet {
            policies: self.policies(None)?,
            ..PolicySet::default()
        };
        let mut stmt = self
            .conn
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
        set.validate()?;
        Ok(set)
    }

    /// Policies in one namespace, or all of them when `only` is `None`.
    fn policies(&self, only: Option<Option<&str>>) -> Result<Vec<Policy>, PolicyError> {
        let mut stmt = self
            .conn
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
                override_floor: floor,
                conditions: serde_json::from_str(&c).map_err(db)?,
                actions: serde_json::from_str(&a).map_err(db)?,
            });
        }
        Ok(out)
    }

    pub fn list(&self, owner: Option<&str>) -> Result<Vec<Policy>, PolicyError> {
        self.policies(Some(owner))
    }

    pub fn get(&self, owner: Option<&str>, id: &str) -> Result<Option<Policy>, PolicyError> {
        Ok(self.list(owner)?.into_iter().find(|p| p.id == id))
    }

    /// Insert or replace one policy in the owner's namespace.
    pub fn upsert(&self, owner: Option<&str>, policy: &Policy) -> Result<(), PolicyError> {
        let policy = owned(owner, policy)?;
        upsert(&self.conn, &policy)
    }

    pub fn delete(&self, owner: Option<&str>, id: &str) -> Result<bool, PolicyError> {
        let changed = self
            .conn
            .execute(
                "DELETE FROM policies WHERE tenant_id = ?1 AND id = ?2",
                [ns(owner), id],
            )
            .map_err(db)?;
        Ok(changed > 0)
    }

    /// Replace one of the owner's groups. An empty list removes it.
    pub fn set_group(
        &mut self,
        owner: Option<&str>,
        name: &str,
        members: &[String],
    ) -> Result<(), PolicyError> {
        let tx = self.conn.transaction().map_err(db)?;
        set_group(&tx, ns(owner), name, members)?;
        tx.commit().map_err(db)
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
        let tx = self.conn.transaction().map_err(db)?;
        tx.execute("DELETE FROM policies WHERE tenant_id = ?1", [ns(owner)])
            .map_err(db)?;
        for policy in &policies {
            upsert(&tx, policy)?;
        }
        for (name, members) in &set.groups {
            set_group(&tx, ns(owner), name, members)?;
        }
        tx.commit().map_err(db)
    }

    pub fn import_toml(&mut self, owner: Option<&str>, text: &str) -> Result<(), PolicyError> {
        self.import(owner, &PolicySet::from_toml(text)?)
    }

    /// The owner's namespace as a pack.
    pub fn export_toml(&self, owner: Option<&str>) -> Result<String, PolicyError> {
        let all = self.load()?;
        let groups = match owner {
            None => all.groups,
            Some(tenant) => all.tenant_groups.get(tenant).cloned().unwrap_or_default(),
        };
        PolicySet {
            groups,
            tenant_groups: Default::default(),
            policies: self.list(owner)?,
        }
        .to_toml()
    }

    /// Import a full operator pack, every namespace, once. Later calls do nothing.
    pub fn seed(&mut self, set: &PolicySet) -> Result<bool, PolicyError> {
        set.validate()?;
        let tx = self.conn.transaction().map_err(db)?;
        let seeded: bool = tx
            .query_row(
                "SELECT COUNT(*) > 0 FROM policy_meta WHERE key = 'seeded'",
                [],
                |row| row.get(0),
            )
            .map_err(db)?;
        if seeded {
            return Ok(false);
        }
        for policy in &set.policies {
            upsert(&tx, policy)?;
        }
        for (name, members) in &set.groups {
            set_group(&tx, "", name, members)?;
        }
        for (tenant, groups) in &set.tenant_groups {
            for (name, members) in groups {
                set_group(&tx, tenant, name, members)?;
            }
        }
        tx.execute(
            "INSERT INTO policy_meta (key, value) VALUES ('seeded', '1')",
            [],
        )
        .map_err(db)?;
        tx.commit().map_err(db)?;
        Ok(true)
    }
}

/// The policy as it will be stored under `owner`. A tenant cannot write into
/// another namespace; validation then refuses global scope and floor overrides.
fn owned(owner: Option<&str>, policy: &Policy) -> Result<Policy, PolicyError> {
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
            policy.override_floor,
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
