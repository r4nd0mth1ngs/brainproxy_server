//! `control.db`: targets, tokens, runs, idempotency keys and the audit log (research §4.3, §5.1, §5.7).
//!
//! The server's own SQLite file. It never touches a project file; the CLI does that.

use std::path::Path;

use rusqlite::{Connection, OptionalExtension, Row, params};
use serde_json::{Value, json};

use super::target::TargetConfig;

/// The most targets one server scans. Deliberately not a setting: the service is not a DAST platform.
pub const MAX_TARGETS: usize = 10;

/// `PRAGMA user_version` of `control.db`.
const SCHEMA_VERSION: i64 = 1;

/// What queueing a trigger did.
pub enum Enqueued {
    /// A new queued run, and the queued run it superseded.
    New { superseded: Option<String> },
    /// The same caller's queued run of the same commit and preset answers instead.
    Existing(Box<RunRow>),
}

/// What a token may do on its target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Perm {
    /// Trigger, read and cancel.
    Trigger,
    /// Read only (dashboards, people).
    Read,
}

impl Perm {
    pub fn name(self) -> &'static str {
        match self {
            Perm::Trigger => "trigger",
            Perm::Read => "read",
        }
    }

    pub fn parse(s: &str) -> Option<Perm> {
        match s {
            "trigger" => Some(Perm::Trigger),
            "read" => Some(Perm::Read),
            _ => None,
        }
    }

    /// A token with `self` may do what needs `need`.
    pub fn allows(self, need: Perm) -> bool {
        self == Perm::Trigger || need == Perm::Read
    }
}

#[derive(Debug, Clone)]
pub struct Target {
    pub config: TargetConfig,
    /// The project file exists (a target registered for an upload has none until then).
    pub project_ready: bool,
    pub created: i64,
    /// One-shot settings for the next run, set by an admin.
    pub next_baseline: bool,
    pub next_accept_coverage_drop: bool,
}

#[derive(Debug, Clone)]
pub struct Token {
    pub id: String,
    pub target: String,
    pub name: String,
    pub perm: Perm,
    pub created: i64,
    pub expires: Option<i64>,
    pub last_used: Option<i64>,
    pub revoked: Option<i64>,
}

impl Token {
    pub fn json(&self) -> Value {
        json!({
            "id": self.id, "target": self.target, "name": self.name, "perm": self.perm.name(),
            "created": crate::time::format_millis(self.created),
            "expires": self.expires.map(crate::time::format_millis),
            "last_used": self.last_used.map(crate::time::format_millis),
            "revoked": self.revoked.map(crate::time::format_millis),
        })
    }
}

/// A run's state. `queued` and `running` are live; the rest are final.
pub mod state {
    pub const QUEUED: &str = "queued";
    pub const RUNNING: &str = "running";
    /// The scan completed: the outcome is `passed` or `gate_failed`.
    pub const COMPLETED: &str = "completed";
    pub const INCOMPLETE: &str = "incomplete";
    /// The CLI refused or failed.
    pub const FAILED: &str = "failed";
    pub const CANCELLED: &str = "cancelled";
    // `superseded`: a newer trigger took its place in the queue before it started (set in SQL).

    pub fn is_live(s: &str) -> bool {
        s == QUEUED || s == RUNNING
    }
}

#[derive(Debug, Clone)]
pub struct RunRow {
    pub id: String,
    pub seq: i64,
    pub target: String,
    pub commit: Option<String>,
    pub git_ref: Option<String>,
    pub pipeline_url: Option<String>,
    pub preset: String,
    pub state: String,
    pub outcome: Option<String>,
    pub exit_code: Option<i32>,
    pub job: Option<u64>,
    pub created: i64,
    pub started: Option<i64>,
    pub finished: Option<i64>,
    pub actor: String,
    /// Who may be answered with this run on a repeated trigger: the token id, or `admin`.
    pub owner: String,
    pub cancel_requested: bool,
    pub baseline: bool,
    pub accept_coverage_drop: bool,
    /// The run's `run.json`, as last written.
    pub run_json: Option<Value>,
    /// Why a run ended before the pipeline wrote `run.json` (superseded, cancelled while queued, ...).
    pub note: Option<String>,
}

const RUN_COLUMNS: &str = "id, seq, target, commit_sha, git_ref, pipeline_url, preset, state, outcome, exit_code, \
     job, created, started, finished, actor, cancel_requested, baseline, accept_coverage_drop, run_json, note, owner";

fn run_row(r: &Row) -> rusqlite::Result<RunRow> {
    let run_json: Option<String> = r.get(18)?;
    Ok(RunRow {
        id: r.get(0)?,
        seq: r.get(1)?,
        target: r.get(2)?,
        commit: r.get(3)?,
        git_ref: r.get(4)?,
        pipeline_url: r.get(5)?,
        preset: r.get(6)?,
        state: r.get(7)?,
        outcome: r.get(8)?,
        exit_code: r.get(9)?,
        job: r.get::<_, Option<i64>>(10)?.map(|j| j as u64),
        created: r.get(11)?,
        started: r.get(12)?,
        finished: r.get(13)?,
        actor: r.get(14)?,
        cancel_requested: r.get(15)?,
        baseline: r.get(16)?,
        accept_coverage_drop: r.get(17)?,
        run_json: run_json.and_then(|t| serde_json::from_str(&t).ok()),
        note: r.get(19)?,
        owner: r.get(20)?,
    })
}

pub struct Db {
    conn: Connection,
}

pub type Result<T> = rusqlite::Result<T>;

impl Db {
    pub fn open(path: &Path) -> std::result::Result<Db, String> {
        Db::open_inner(path).map_err(|e| e.to_string())?.ok_or_else(|| {
            format!(
                "{} was made by an older development build of the server (schema {SCHEMA_VERSION} is needed); \
                 move it away and register the targets again",
                path.display()
            )
        })
    }

    fn open_inner(path: &Path) -> Result<Option<Db>> {
        let conn = Connection::open(path)?;
        let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        let fresh: i64 = conn.query_row("SELECT COUNT(*) FROM sqlite_master WHERE name = 'runs'", [], |r| r.get(0))?;
        if fresh > 0 && version != SCHEMA_VERSION {
            return Ok(None);
        }
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.execute_batch(&format!(
            "CREATE TABLE IF NOT EXISTS targets (
                id TEXT PRIMARY KEY,
                config TEXT NOT NULL,
                project_ready INTEGER NOT NULL DEFAULT 0,
                created INTEGER NOT NULL,
                next_baseline INTEGER NOT NULL DEFAULT 0,
                next_accept_coverage_drop INTEGER NOT NULL DEFAULT 0
            );
            -- The cap again, below the handler: a second check that no code path can skip.
            CREATE TRIGGER IF NOT EXISTS targets_cap BEFORE INSERT ON targets
            WHEN (SELECT COUNT(*) FROM targets) >= {MAX_TARGETS}
            BEGIN SELECT RAISE(ABORT, 'at most {MAX_TARGETS} targets'); END;

            CREATE TABLE IF NOT EXISTS tokens (
                id TEXT PRIMARY KEY,
                target TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
                name TEXT NOT NULL,
                hash BLOB NOT NULL UNIQUE,
                perm TEXT NOT NULL,
                created INTEGER NOT NULL,
                expires INTEGER,
                last_used INTEGER,
                revoked INTEGER
            );

            CREATE TABLE IF NOT EXISTS runs (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                id TEXT NOT NULL UNIQUE,
                target TEXT NOT NULL,
                commit_sha TEXT,
                git_ref TEXT,
                pipeline_url TEXT,
                preset TEXT NOT NULL,
                state TEXT NOT NULL,
                outcome TEXT,
                exit_code INTEGER,
                job INTEGER,
                created INTEGER NOT NULL,
                started INTEGER,
                finished INTEGER,
                actor TEXT NOT NULL,
                owner TEXT NOT NULL,
                cancel_requested INTEGER NOT NULL DEFAULT 0,
                baseline INTEGER NOT NULL DEFAULT 0,
                accept_coverage_drop INTEGER NOT NULL DEFAULT 0,
                run_json TEXT,
                note TEXT
            );
            -- One running and one queued run per target.
            CREATE UNIQUE INDEX IF NOT EXISTS runs_one_running ON runs(target) WHERE state = 'running';
            CREATE UNIQUE INDEX IF NOT EXISTS runs_one_queued ON runs(target) WHERE state = 'queued';
            CREATE INDEX IF NOT EXISTS runs_target ON runs(target, seq);

            CREATE TABLE IF NOT EXISTS idempotency (
                token TEXT NOT NULL,
                key TEXT NOT NULL,
                run TEXT NOT NULL,
                created INTEGER NOT NULL,
                PRIMARY KEY (token, key)
            );

            CREATE TABLE IF NOT EXISTS audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                time INTEGER NOT NULL,
                actor TEXT NOT NULL,
                actor_kind TEXT NOT NULL,
                ip TEXT,
                action TEXT NOT NULL,
                target TEXT,
                run TEXT,
                result TEXT NOT NULL,
                detail TEXT
            );"
        ))?;
        conn.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        Ok(Some(Db { conn }))
    }

    // -- targets ---------------------------------------------------------------------------------

    pub fn target_count(&self) -> Result<usize> {
        self.conn.query_row("SELECT COUNT(*) FROM targets", [], |r| r.get::<_, i64>(0)).map(|n| n as usize)
    }

    pub fn insert_target(&self, config: &TargetConfig, project_ready: bool, now: i64) -> Result<()> {
        let text = serde_json::to_string(config).unwrap_or_default();
        self.conn.execute(
            "INSERT INTO targets (id, config, project_ready, created) VALUES (?1, ?2, ?3, ?4)",
            params![config.id, text, project_ready, now],
        )?;
        Ok(())
    }

    pub fn update_config(&self, config: &TargetConfig) -> Result<()> {
        let text = serde_json::to_string(config).unwrap_or_default();
        self.conn.execute("UPDATE targets SET config = ?2 WHERE id = ?1", params![config.id, text])?;
        Ok(())
    }

    pub fn set_project_ready(&self, id: &str) -> Result<()> {
        self.conn.execute("UPDATE targets SET project_ready = 1 WHERE id = ?1", [id])?;
        Ok(())
    }

    pub fn set_next_run(&self, id: &str, baseline: bool, accept_coverage_drop: bool) -> Result<()> {
        self.conn.execute(
            "UPDATE targets SET next_baseline = ?2, next_accept_coverage_drop = ?3 WHERE id = ?1",
            params![id, baseline, accept_coverage_drop],
        )?;
        Ok(())
    }

    /// Removes a target with its tokens (cascade), runs and idempotency keys, so a target
    /// registered again under the same id starts with no history.
    pub fn delete_target(&mut self, id: &str) -> Result<()> {
        let tx = self.conn.transaction()?;
        tx.execute("DELETE FROM idempotency WHERE run IN (SELECT id FROM runs WHERE target = ?1)", [id])?;
        tx.execute("DELETE FROM runs WHERE target = ?1", [id])?;
        tx.execute("DELETE FROM targets WHERE id = ?1", [id])?;
        tx.commit()
    }

    pub fn target(&self, id: &str) -> Result<Option<Target>> {
        self.conn
            .query_row(
                "SELECT config, project_ready, created, next_baseline, next_accept_coverage_drop FROM targets WHERE id = ?1",
                [id],
                target_row,
            )
            .optional()
            .map(Option::flatten)
    }

    pub fn targets(&self) -> Result<Vec<Target>> {
        let mut st = self.conn.prepare(
            "SELECT config, project_ready, created, next_baseline, next_accept_coverage_drop FROM targets ORDER BY id",
        )?;
        let rows = st.query_map([], target_row)?;
        rows.filter_map(|r| r.transpose()).collect()
    }

    // -- tokens ----------------------------------------------------------------------------------

    pub fn insert_token(&self, t: &Token, hash: &[u8]) -> Result<()> {
        self.conn.execute(
            "INSERT INTO tokens (id, target, name, hash, perm, created, expires) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![t.id, t.target, t.name, hash, t.perm.name(), t.created, t.expires],
        )?;
        Ok(())
    }

    /// The token with this hash, and marks it used.
    pub fn token_by_hash(&self, hash: &[u8], now: i64) -> Result<Option<Token>> {
        let t = self
            .conn
            .query_row(
                "SELECT id, target, name, perm, created, expires, last_used, revoked FROM tokens WHERE hash = ?1",
                [hash],
                token_row,
            )
            .optional()?
            .flatten();
        if let Some(t) = &t {
            self.conn.execute("UPDATE tokens SET last_used = ?2 WHERE id = ?1", params![t.id, now])?;
        }
        Ok(t)
    }

    pub fn tokens(&self, target: &str) -> Result<Vec<Token>> {
        let mut st = self.conn.prepare(
            "SELECT id, target, name, perm, created, expires, last_used, revoked FROM tokens WHERE target = ?1 ORDER BY created",
        )?;
        let rows = st.query_map([target], token_row)?;
        rows.filter_map(|r| r.transpose()).collect()
    }

    /// Revokes a token of this target; false when there is no such token.
    pub fn revoke_token(&self, target: &str, id: &str, now: i64) -> Result<bool> {
        let n = self.conn.execute(
            "UPDATE tokens SET revoked = COALESCE(revoked, ?3) WHERE target = ?1 AND id = ?2",
            params![target, id, now],
        )?;
        Ok(n > 0)
    }

    // -- runs ------------------------------------------------------------------------------------

    pub fn run(&self, target: &str, id: &str) -> Result<Option<RunRow>> {
        self.conn
            .query_row(&format!("SELECT {RUN_COLUMNS} FROM runs WHERE target = ?1 AND id = ?2"), [target, id], run_row)
            .optional()
    }

    pub fn runs(&self, target: &str, limit: u32) -> Result<Vec<RunRow>> {
        let mut st = self
            .conn
            .prepare(&format!("SELECT {RUN_COLUMNS} FROM runs WHERE target = ?1 ORDER BY seq DESC LIMIT ?2"))?;
        let rows = st.query_map(params![target, limit], run_row)?;
        rows.collect()
    }

    pub fn runs_in_state(&self, state: &str) -> Result<Vec<RunRow>> {
        let mut st = self.conn.prepare(&format!("SELECT {RUN_COLUMNS} FROM runs WHERE state = ?1 ORDER BY seq"))?;
        let rows = st.query_map([state], run_row)?;
        rows.collect()
    }

    /// The newest run of the target in `state`.
    pub fn last_run_in_state(&self, target: &str, state: &str) -> Result<Option<RunRow>> {
        self.conn
            .query_row(
                &format!("SELECT {RUN_COLUMNS} FROM runs WHERE target = ?1 AND state = ?2 ORDER BY seq DESC LIMIT 1"),
                [target, state],
                run_row,
            )
            .optional()
    }

    /// 1 for the next queued run to start, and so on.
    pub fn queue_position(&self, seq: i64) -> Result<i64> {
        self.conn.query_row("SELECT COUNT(*) + 1 FROM runs WHERE state = 'queued' AND seq < ?1", [seq], |r| r.get(0))
    }

    pub fn state_counts(&self, target: &str) -> Result<Vec<(String, i64)>> {
        let mut st = self.conn.prepare("SELECT state, COUNT(*) FROM runs WHERE target = ?1 GROUP BY state")?;
        let rows = st.query_map([target], |r| Ok((r.get(0)?, r.get(1)?)))?;
        rows.collect()
    }

    /// The run an `Idempotency-Key` of this token created after `since`.
    pub fn idempotent_run(&self, token: &str, key: &str, since: i64) -> Result<Option<String>> {
        self.conn
            .query_row(
                "SELECT run FROM idempotency WHERE token = ?1 AND key = ?2 AND created >= ?3",
                params![token, key, since],
                |r| r.get(0),
            )
            .optional()
    }

    /// Queues a run, in one transaction. The target's queued run answers instead when it is the same
    /// caller's trigger of the same commit and preset (it hasn't scanned anything yet, so it tests
    /// what is deployed now); otherwise it becomes superseded and passes its one-shot settings on.
    pub fn enqueue(&mut self, run: &RunRow, idempotency: Option<(&str, &str)>) -> Result<Enqueued> {
        let tx = self.conn.transaction()?;
        let queued = tx
            .query_row(
                &format!("SELECT {RUN_COLUMNS} FROM runs WHERE target = ?1 AND state = 'queued'"),
                [&run.target],
                run_row,
            )
            .optional()?;
        let remember = |tx: &rusqlite::Transaction, id: &str| -> Result<()> {
            if let Some((token, key)) = idempotency {
                tx.execute(
                    "INSERT OR REPLACE INTO idempotency (token, key, run, created) VALUES (?1, ?2, ?3, ?4)",
                    params![token, key, id, run.created],
                )?;
            }
            Ok(())
        };
        if let Some(q) = &queued
            && run.commit.is_some()
            && q.commit == run.commit
            && q.owner == run.owner
            && q.preset == run.preset
            && !q.baseline
            && !run.baseline
        {
            remember(&tx, &q.id)?;
            tx.commit()?;
            return Ok(Enqueued::Existing(Box::new(q.clone())));
        }
        let (mut baseline, mut accept) = (run.baseline, run.accept_coverage_drop);
        if let Some(q) = &queued {
            tx.execute(
                "UPDATE runs SET state = 'superseded', outcome = 'incomplete', exit_code = 2, finished = ?2,
                 note = ?3 WHERE id = ?1",
                params![q.id, run.created, format!("superseded by run {} before it started", run.id)],
            )?;
            baseline |= q.baseline;
            accept |= q.accept_coverage_drop;
        }
        tx.execute(
            "INSERT INTO runs (id, target, commit_sha, git_ref, pipeline_url, preset, state, created, actor,
             baseline, accept_coverage_drop, owner) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'queued', ?7, ?8, ?9, ?10, ?11)",
            params![
                run.id,
                run.target,
                run.commit,
                run.git_ref,
                run.pipeline_url,
                run.preset,
                run.created,
                run.actor,
                baseline,
                accept,
                run.owner
            ],
        )?;
        remember(&tx, &run.id)?;
        // The one-shot settings are used up by the run that took them.
        if baseline || accept {
            tx.execute(
                "UPDATE targets SET next_baseline = 0, next_accept_coverage_drop = 0 WHERE id = ?1",
                [&run.target],
            )?;
        }
        tx.commit()?;
        Ok(Enqueued::New { superseded: queued.map(|q| q.id) })
    }

    /// queued → running. False when the run isn't queued any more (cancelled or superseded meanwhile).
    pub fn mark_running(&self, id: &str, now: i64) -> Result<bool> {
        let n = self.conn.execute(
            "UPDATE runs SET state = 'running', started = ?2 WHERE id = ?1 AND state = 'queued'",
            params![id, now],
        )?;
        Ok(n > 0)
    }

    pub fn set_progress(&self, id: &str, job: Option<u64>, run_json: &Value) -> Result<()> {
        self.conn.execute(
            "UPDATE runs SET job = COALESCE(?2, job), run_json = ?3 WHERE id = ?1",
            params![id, job.map(|j| j as i64), run_json.to_string()],
        )?;
        Ok(())
    }

    pub fn finish_run(&self, id: &str, end: &RunEnd, now: i64) -> Result<()> {
        self.conn.execute(
            "UPDATE runs SET state = ?2, outcome = ?3, exit_code = ?4, run_json = COALESCE(?5, run_json),
             note = COALESCE(?6, note), finished = ?7 WHERE id = ?1",
            params![id, end.state, end.outcome, end.exit_code, end.run_json.map(Value::to_string), end.note, now],
        )?;
        Ok(())
    }

    /// A queued run becomes cancelled; a running one is marked so its worker ends it as cancelled.
    /// Returns the run's state before. Each step is conditional on the state, so a run that starts
    /// meanwhile is still marked.
    pub fn request_cancel(&self, target: &str, id: &str, now: i64) -> Result<Option<String>> {
        let n = self.conn.execute(
            "UPDATE runs SET state = 'cancelled', outcome = 'incomplete', exit_code = 2, finished = ?3,
             note = 'cancelled before it started' WHERE target = ?1 AND id = ?2 AND state = 'queued'",
            params![target, id, now],
        )?;
        if n > 0 {
            return Ok(Some(state::QUEUED.into()));
        }
        let n = self.conn.execute(
            "UPDATE runs SET cancel_requested = 1 WHERE target = ?1 AND id = ?2 AND state = 'running'",
            [target, id],
        )?;
        if n > 0 {
            return Ok(Some(state::RUNNING.into()));
        }
        self.conn
            .query_row("SELECT state FROM runs WHERE target = ?1 AND id = ?2", [target, id], |r| r.get(0))
            .optional()
    }

    pub fn live_runs_of(&self, target: &str) -> Result<usize> {
        self.conn
            .query_row(
                "SELECT COUNT(*) FROM runs WHERE target = ?1 AND state IN ('queued', 'running')",
                [target],
                |r| r.get::<_, i64>(0),
            )
            .map(|n| n as usize)
    }

    // -- audit -----------------------------------------------------------------------------------

    pub fn audit(&self, e: &AuditEntry) -> Result<()> {
        self.conn.execute(
            "INSERT INTO audit (time, actor, actor_kind, ip, action, target, run, result, detail)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![e.time, e.actor, e.actor_kind, e.ip, e.action, e.target, e.run, e.result, e.detail],
        )?;
        Ok(())
    }

    pub fn audit_log(&self, limit: u32) -> Result<Vec<Value>> {
        let mut st = self.conn.prepare(
            "SELECT time, actor, actor_kind, ip, action, target, run, result, detail FROM audit ORDER BY id DESC LIMIT ?1",
        )?;
        let rows = st.query_map([limit], |r| {
            Ok(json!({
                "time": crate::time::format_millis(r.get(0)?), "actor": r.get::<_, String>(1)?,
                "actor_kind": r.get::<_, String>(2)?, "ip": r.get::<_, Option<String>>(3)?,
                "action": r.get::<_, String>(4)?, "target": r.get::<_, Option<String>>(5)?,
                "run": r.get::<_, Option<String>>(6)?, "result": r.get::<_, String>(7)?,
                "detail": r.get::<_, Option<String>>(8)?,
            }))
        })?;
        rows.collect()
    }

    /// Drops audit lines and idempotency keys older than their retention.
    pub fn prune(&self, audit_before: i64, keys_before: i64) -> Result<()> {
        self.conn.execute("DELETE FROM audit WHERE time < ?1", [audit_before])?;
        self.conn.execute("DELETE FROM idempotency WHERE created < ?1", [keys_before])?;
        Ok(())
    }
}

/// How a run ended.
pub struct RunEnd<'a> {
    pub state: &'a str,
    pub outcome: &'a str,
    pub exit_code: i32,
    pub run_json: Option<&'a Value>,
    pub note: Option<&'a str>,
}

#[derive(Debug, Clone, Default)]
pub struct AuditEntry {
    pub time: i64,
    pub actor: String,
    pub actor_kind: String,
    pub ip: Option<String>,
    pub action: String,
    pub target: Option<String>,
    pub run: Option<String>,
    pub result: String,
    pub detail: Option<String>,
}

fn target_row(r: &Row) -> rusqlite::Result<Option<Target>> {
    let text: String = r.get(0)?;
    // A row this version can't read is skipped rather than failing every request.
    let Ok(config) = serde_json::from_str::<TargetConfig>(&text) else { return Ok(None) };
    Ok(Some(Target {
        config,
        project_ready: r.get(1)?,
        created: r.get(2)?,
        next_baseline: r.get(3)?,
        next_accept_coverage_drop: r.get(4)?,
    }))
}

fn token_row(r: &Row) -> rusqlite::Result<Option<Token>> {
    let perm: String = r.get(3)?;
    let Some(perm) = Perm::parse(&perm) else { return Ok(None) };
    Ok(Some(Token {
        id: r.get(0)?,
        target: r.get(1)?,
        name: r.get(2)?,
        perm,
        created: r.get(4)?,
        expires: r.get(5)?,
        last_used: r.get(6)?,
        revoked: r.get(7)?,
    }))
}
