//! SQLite policy store. The admin API edits policies through these calls;
//! the pack can be imported from and exported to TOML.
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

    pub fn is_empty(&self) -> Result<bool, PolicyError> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM policies", [], |row| row.get(0))
            .map_err(db)?;
        Ok(count == 0)
    }

    pub fn load(&self) -> Result<PolicySet, PolicyError> {
        let mut set = PolicySet::default();
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, tenant_id, scope_kind, scope_value, priority, enabled, dry_run, \
                 conditions, actions FROM policies ORDER BY id",
            )
            .map_err(db)?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, bool>(5)?,
                    row.get::<_, bool>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                ))
            })
            .map_err(db)?;
        for row in rows {
            let (id, tenant_id, kind, value, priority, enabled, dry_run, conditions, actions) =
                row.map_err(db)?;
            set.policies.push(Policy {
                scope: Scope::from_parts(&kind, value)?,
                conditions: serde_json::from_str(&conditions).map_err(db)?,
                actions: serde_json::from_str(&actions).map_err(db)?,
                id,
                tenant_id,
                priority,
                enabled,
                dry_run,
            });
        }
        let mut stmt = self
            .conn
            .prepare("SELECT name, address FROM policy_groups ORDER BY name, address")
            .map_err(db)?;
        let rows = stmt
            .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get(1)?)))
            .map_err(db)?;
        for row in rows {
            let (name, address) = row.map_err(db)?;
            set.groups.entry(name).or_default().push(address);
        }
        set.validate()?;
        Ok(set)
    }

    pub fn get(&self, id: &str) -> Result<Option<Policy>, PolicyError> {
        Ok(self.load()?.policies.into_iter().find(|p| p.id == id))
    }

    /// Insert or replace one policy.
    pub fn upsert(&self, policy: &Policy) -> Result<(), PolicyError> {
        policy.validate()?;
        upsert(&self.conn, policy)
    }

    pub fn delete(&self, id: &str) -> Result<bool, PolicyError> {
        let changed = self
            .conn
            .execute("DELETE FROM policies WHERE id = ?1", [id])
            .map_err(db)?;
        Ok(changed > 0)
    }

    /// Replace a group's members. An empty list removes the group.
    pub fn set_group(&mut self, name: &str, members: &[String]) -> Result<(), PolicyError> {
        let tx = self.conn.transaction().map_err(db)?;
        set_group(&tx, name, members)?;
        tx.commit().map_err(db)
    }

    /// Replace everything with the given pack, atomically.
    pub fn import(&mut self, set: &PolicySet) -> Result<(), PolicyError> {
        set.validate()?;
        let tx = self.conn.transaction().map_err(db)?;
        tx.execute_batch("DELETE FROM policies; DELETE FROM policy_groups;")
            .map_err(db)?;
        for policy in &set.policies {
            upsert(&tx, policy)?;
        }
        for (name, members) in &set.groups {
            set_group(&tx, name, members)?;
        }
        tx.commit().map_err(db)
    }

    pub fn import_toml(&mut self, text: &str) -> Result<(), PolicyError> {
        self.import(&PolicySet::from_toml(text)?)
    }

    pub fn export_toml(&self) -> Result<String, PolicyError> {
        self.load()?.to_toml()
    }
}

fn upsert(conn: &Connection, policy: &Policy) -> Result<(), PolicyError> {
    conn.execute(
        "INSERT OR REPLACE INTO policies (id, tenant_id, scope_kind, scope_value, priority, \
         enabled, dry_run, conditions, actions) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            policy.id,
            policy.tenant_id,
            policy.scope.kind(),
            policy.scope.value(),
            policy.priority,
            policy.enabled,
            policy.dry_run,
            serde_json::to_string(&policy.conditions).map_err(db)?,
            serde_json::to_string(&policy.actions).map_err(db)?,
        ],
    )
    .map_err(db)?;
    Ok(())
}

fn set_group(conn: &Connection, name: &str, members: &[String]) -> Result<(), PolicyError> {
    conn.execute("DELETE FROM policy_groups WHERE name = ?1", [name])
        .map_err(db)?;
    for address in members {
        conn.execute(
            "INSERT OR IGNORE INTO policy_groups (name, address) VALUES (?1, ?2)",
            [name, address],
        )
        .map_err(db)?;
    }
    Ok(())
}
