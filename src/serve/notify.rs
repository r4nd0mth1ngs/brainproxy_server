//! `serve`'s side of run notifications: sent in the background once a run's end is recorded, each
//! delivery written to the audit log. What is sent and how is in [`crate::notify`].

use std::sync::Arc;

use serde_json::Value;

pub use crate::notify::*;

use super::Server;
use super::db::AuditEntry;

/// Sends a run's notifications in the background, once its end is recorded.
pub fn spawn(server: Arc<Server>, target: String, run: String) {
    tokio::spawn(async move {
        let Some(t) = server.db().target(&target).ok().flatten() else { return };
        let t = t.config;
        if t.notify.is_empty() && t.defectdojo.is_none() {
            return;
        }
        let Some(row) = server.db().run(&target, &run).ok().flatten() else { return };
        let Some(event) = Event::of(&row.state, row.outcome.as_deref()) else { return };
        let dir = server.run_dir(&target, &run);
        let compare = std::fs::read(dir.join("compare.json"))
            .ok()
            .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
            .unwrap_or(Value::Null);
        let note = Arc::new(Note::new(&row, event, &compare));
        for d in deliver(&t, note.clone(), &dir, &server.cfg.secrets_dir).await {
            let (result, detail) = match &d.result {
                Ok(status) => ("ok", format!("{}: HTTP {status}", d.what)),
                Err(e) => ("failed", format!("{}: {e}", d.what)),
            };
            server.audit(AuditEntry {
                actor: "server".into(),
                actor_kind: "server".into(),
                action: d.action.into(),
                target: Some(note.target.clone()),
                run: Some(note.run.clone()),
                result: result.into(),
                detail: Some(detail),
                ..AuditEntry::default()
            });
        }
    });
}
