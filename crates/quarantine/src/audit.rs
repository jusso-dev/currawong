//! Audit trail for quarantine actions. The admin crate (#39) brings its own
//! sink; until then the store writes to an append-only table beside the index.
use rusqlite::{params, Connection};
use serde::Serialize;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AuditEvent {
    /// Unix seconds.
    pub at: i64,
    /// Who acted: an address for end users, an account name for admins,
    /// `system` for the purge.
    pub actor: String,
    pub role: String,
    pub tenant_id: Option<String>,
    pub item_id: String,
    /// `release_started` then `release`, `delete_started` then `delete`,
    /// `purge`, or `denied:<action>`.
    pub action: String,
    pub reason: Option<String>,
    /// Release: the id of the re-injected spool message.
    pub detail: Option<String>,
}

pub trait AuditSink: Send + Sync {
    fn record(&self, event: &AuditEvent) -> Result<(), String>;
}

/// `quarantine_audit` in the quarantine database. Triggers refuse updates
/// and deletes.
#[derive(Clone)]
pub struct SqliteAudit {
    conn: Arc<Mutex<Connection>>,
}

impl SqliteAudit {
    pub(crate) fn new(conn: Arc<Mutex<Connection>>) -> Self {
        Self { conn }
    }

    /// Every event, oldest first.
    pub fn events(&self) -> Result<Vec<AuditEvent>, String> {
        let conn = self.conn.lock().map_err(|err| err.to_string())?;
        let mut stmt = conn
            .prepare(
                "SELECT at, actor, role, tenant_id, item_id, action, reason, detail
                 FROM quarantine_audit ORDER BY seq",
            )
            .map_err(|err| err.to_string())?;
        let rows = stmt
            .query_map([], |row| {
                Ok(AuditEvent {
                    at: row.get(0)?,
                    actor: row.get(1)?,
                    role: row.get(2)?,
                    tenant_id: row.get(3)?,
                    item_id: row.get(4)?,
                    action: row.get(5)?,
                    reason: row.get(6)?,
                    detail: row.get(7)?,
                })
            })
            .map_err(|err| err.to_string())?;
        rows.collect::<Result<_, _>>()
            .map_err(|err| err.to_string())
    }
}

impl AuditSink for SqliteAudit {
    fn record(&self, event: &AuditEvent) -> Result<(), String> {
        let conn = self.conn.lock().map_err(|err| err.to_string())?;
        conn.execute(
            "INSERT INTO quarantine_audit (at, actor, role, tenant_id, item_id, action, reason, detail)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                event.at,
                event.actor,
                event.role,
                event.tenant_id,
                event.item_id,
                event.action,
                event.reason,
                event.detail
            ],
        )
        .map(|_| ())
        .map_err(|err| err.to_string())
    }
}
