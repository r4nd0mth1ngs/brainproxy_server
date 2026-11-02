//! `brainproxy-server serve`: the HTTP API, a queue, and workers that run the `ci` pipeline per
//! target (PLAN.md phase 2; research §3, §4).
//!
//! One process: `control.db` (SQLite) holds targets, tokens, runs and the audit log; each target has
//! its own project file and run folders under the work directory:
//!
//! ```text
//! <work>/control.db
//! <work>/system-scope.json             union of all targets' scopes (BRAINPROXY_SYSTEM_SCOPE)
//! <work>/targets/<id>/project.bpdb
//! <work>/targets/<id>/runs/<run>/      run.json, compare.json, report.{json,html,sarif}
//! <work>/targets/<id>/snapshots/<run>.bpdb
//! ```

pub mod api;
pub mod auth;
pub mod db;
pub mod oidc;
pub mod store;
pub mod target;
pub mod ui;

use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::fs::{File, TryLockError};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::sync::{Notify, watch};

use crate::brainproxy::{self, Cli, code};
use crate::ci::{self, Ci, Options};
use crate::record::{Outcome, Run};
use crate::time;
use api::ApiError;
use db::{AuditEntry, Db, RunRow, state};
use target::{ProjectSource, ScopeEntry, TargetConfig};

#[derive(Debug, Clone)]
pub struct Config {
    pub work: PathBuf,
    pub brainproxy: PathBuf,
    pub listen: SocketAddr,
    pub admin_listen: SocketAddr,
    pub admin_token_file: PathBuf,
    pub max_parallel: usize,
    /// Target secrets as files: `<dir>/<target>/<CLI variable>`.
    pub secrets_dir: PathBuf,
    /// Where the system scope is written; the CLI is pointed at it with `BRAINPROXY_SYSTEM_SCOPE`.
    pub system_scope: PathBuf,
    pub keep_snapshots: usize,
    pub max_project_mb: u64,
    pub audit_days: u64,
    pub allow_network_fs: bool,
    pub allow_loopback_targets: bool,
    /// Take the client address from the last `X-Forwarded-For` entry (behind a reverse proxy).
    pub trust_forwarded: bool,
    /// OIDC issuers whose CI tokens targets may bind.
    pub oidc_issuers: Vec<oidc::Issuer>,
    /// The `aud` OIDC tokens must carry: the server's public URL.
    pub oidc_audience: Option<String>,
    /// Object storage the work directory is copied to and restored from (`object-store` feature).
    pub store: Option<String>,
}

/// What `PATCH /v1/targets/{t}` may change.
#[derive(Debug, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetPatch {
    pub oidc: Option<Vec<oidc::Binding>>,
    pub policy: Option<crate::policy::Policy>,
    pub ownership: Option<bool>,
}

/// GETs a small text file over HTTP(S): no redirects, 10 s, 4 KB. Certificates aren't checked:
/// dev instances often have self-signed ones, nothing secret is sent, and the ownership check
/// guards against typos, not attackers.
/// It connects only to `addrs`, never through a proxy.
fn fetch_small(url: &str, addrs: Vec<SocketAddr>) -> Result<String, String> {
    let tls = ureq::tls::TlsConfig::builder().disable_verification(true).build();
    let config = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(10)))
        .max_redirects(0)
        .http_status_as_error(false)
        .proxy(None)
        .tls_config(tls)
        .build();
    let agent = ureq::Agent::with_parts(config, ureq::unversioned::transport::DefaultConnector::new(), Pinned(addrs));
    let mut resp = agent.get(url).call().map_err(|e| format!("{url}: {e}"))?;
    if resp.status() != 200 {
        return Err(format!("{url}: HTTP {}", resp.status()));
    }
    resp.body_mut().with_config().limit(4096).read_to_string().map_err(|e| format!("{url}: {e}"))
}

/// A resolver that answers every name with the addresses it was given.
#[derive(Debug)]
struct Pinned(Vec<SocketAddr>);

impl ureq::unversioned::resolver::Resolver for Pinned {
    fn resolve(
        &self,
        _uri: &axum::http::Uri,
        _config: &ureq::config::Config,
        _timeout: ureq::unversioned::transport::NextTimeout,
    ) -> Result<ureq::unversioned::resolver::ResolvedSocketAddrs, ureq::Error> {
        let mut out = self.empty();
        for a in self.0.iter().take(16) {
            out.push(*a);
        }
        if out.is_empty() { Err(ureq::Error::HostNotFound) } else { Ok(out) }
    }
}

/// How long an `Idempotency-Key` answers a repeated trigger with its run.
pub const DEDUP_MS: i64 = 24 * 3600 * 1000;

/// The live run of one worker: its target, and the sender that cancels it.
struct Live {
    target: String,
    cancel: watch::Sender<Option<&'static str>>,
}

pub struct Server {
    pub cfg: Config,
    db: Mutex<Db>,
    admin_hash: [u8; 32],
    pub limits: auth::Limits,
    pub oidc: oidc::Verifier,
    /// Bumped whenever a run changes; long polls wait on it.
    changed: watch::Sender<u64>,
    wake: Notify,
    live: Mutex<HashMap<String, Live>>,
    /// Targets an upload or a removal is working on: nothing starts on them meanwhile.
    busy: Mutex<HashSet<String>>,
    /// Registrations, uploads and removals, one at a time.
    admin_ops: tokio::sync::Mutex<()>,
    /// Where the work directory is copied to, and the task copying it.
    store: Option<store::Store>,
    sync: OnceLock<store::Sync>,
    _lock: File,
}

/// Runs the server until SIGINT or SIGTERM. Scans keep running across a restart: the next start
/// waits for them again.
pub async fn run(cfg: Config) -> Result<(), String> {
    if cfg.listen == cfg.admin_listen {
        return Err("--listen and --admin-listen must differ: admin endpoints never share the public listener".into());
    }
    std::fs::create_dir_all(cfg.work.join("targets")).map_err(|e| format!("{}: {e}", cfg.work.display()))?;
    let work = cfg.work.canonicalize().map_err(|e| format!("{}: {e}", cfg.work.display()))?;
    let cfg = Config { work, ..cfg };
    if !cfg.allow_network_fs
        && let Some(fs) = network_fs(&cfg.work)
    {
        return Err(format!(
            "{} is on a network filesystem ({fs}); project files need local disk (SQLite WAL and file locks). \
             Use a local volume, or --allow-network-fs at your own risk",
            cfg.work.display()
        ));
    }
    if cfg.oidc_audience.is_none() && cfg.oidc_issuers.iter().any(|i| i.kind != oidc::Kind::Azure) {
        return Err(
            "--oidc-issuer needs --oidc-audience: the server's public URL, which tokens must be minted for".into()
        );
    }
    let lock = lock_work(&cfg.work)?;
    let store = match &cfg.store {
        Some(url) => Some(store::Store::open(url)?),
        None => None,
    };
    let mut first_sync = false;
    if let Some(s) = &store {
        s.acquire(store::LEASE_WAIT).await?;
        match store::restore(s, &cfg.work).await? {
            Some(n) => eprintln!("brainproxy-server: restored control.db and {n} target(s) from {}", s.url),
            None => first_sync = !s.has("control.db").await?,
        }
    }
    let admin_hash = auth::load_admin_token(&cfg.admin_token_file)?;
    let version = brainproxy::check_version(&cfg.brainproxy, Some(&base_env(&cfg))).await?;
    let db = Db::open(&cfg.work.join("control.db")).map_err(|e| format!("control.db: {e}"))?;
    if !cfg.admin_listen.ip().is_loopback() {
        eprintln!(
            "brainproxy-server: warning: admin listener {} is not on loopback; never expose it through the reverse proxy",
            cfg.admin_listen
        );
    }
    if Path::new("/etc/brainproxy/scope.json").exists() {
        eprintln!(
            "brainproxy-server: note: /etc/brainproxy/scope.json exists and takes precedence over {}; \
             it must allow every registered target",
            cfg.system_scope.display()
        );
    }

    let (changed, _) = watch::channel(0);
    let verifier = oidc::Verifier::new(cfg.oidc_issuers.clone(), cfg.oidc_audience.clone());
    let server = Arc::new(Server {
        cfg,
        oidc: verifier,
        db: Mutex::new(db),
        admin_hash,
        limits: auth::Limits::default(),
        changed,
        wake: Notify::new(),
        live: Mutex::new(HashMap::new()),
        busy: Mutex::new(HashSet::new()),
        admin_ops: tokio::sync::Mutex::new(()),
        store,
        sync: OnceLock::new(),
        _lock: lock,
    });
    if server.store.is_some() {
        let _ = server.sync.set(store::start(server.clone()));
        if first_sync {
            server.sync_everything();
        }
    }
    server.prune();
    server.write_system_scope().map_err(|e| format!("system scope: {e}"))?;

    // Runs that were running when the server stopped: wait for their scans again.
    let running = server.db().runs_in_state(state::RUNNING).map_err(|e| e.to_string())?;
    for run in running {
        eprintln!("brainproxy-server: resuming run {} of {}", run.id, run.target);
        server.clone().spawn_worker(run, true);
    }
    tokio::spawn(server.clone().scheduler());
    tokio::spawn({
        let s = server.clone();
        async move {
            loop {
                tokio::time::sleep(Duration::from_secs(24 * 3600)).await;
                s.prune();
            }
        }
    });

    let public = tokio::net::TcpListener::bind(server.cfg.listen)
        .await
        .map_err(|e| format!("listen {}: {e}", server.cfg.listen))?;
    let admin = tokio::net::TcpListener::bind(server.cfg.admin_listen)
        .await
        .map_err(|e| format!("admin listen {}: {e}", server.cfg.admin_listen))?;
    eprintln!(
        "brainproxy-server {} (brainproxy {version}): API on {}, admin on {}, work {}",
        env!("CARGO_PKG_VERSION"),
        public.local_addr().unwrap_or(server.cfg.listen),
        admin.local_addr().unwrap_or(server.cfg.admin_listen),
        server.cfg.work.display()
    );
    let (stop_tx, stop_rx) = watch::channel(false);
    let serve = |listener, router: axum::Router| {
        let mut stop = stop_rx.clone();
        async move {
            axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>())
                .with_graceful_shutdown(async move {
                    let _ = stop.wait_for(|s| *s).await;
                })
                .await
        }
    };
    let public_task = tokio::spawn(serve(public, api::public_router(server.clone())));
    let admin_task = tokio::spawn(serve(admin, api::admin_router(server.clone())));
    let sig = wait_for_stop().await;
    eprintln!("brainproxy-server: {sig}: stopping; running scans continue and are picked up on the next start");
    let _ = stop_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(5), async {
        let _ = public_task.await;
        let _ = admin_task.await;
    })
    .await;
    if let Some(sync) = server.sync.get() {
        sync.flush(Duration::from_secs(20)).await;
    }
    if let Some(s) = &server.store {
        s.release().await;
    }
    Ok(())
}

impl Server {
    pub fn db(&self) -> MutexGuard<'_, Db> {
        self.db.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn is_admin(&self, token: &str) -> bool {
        auth::ct_eq(&auth::sha256(token.as_bytes()), &self.admin_hash)
    }

    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.changed.subscribe()
    }

    fn bump(&self) {
        self.changed.send_modify(|n| *n += 1);
    }

    /// Wakes the scheduler and long polls after a run was queued, cancelled or superseded.
    pub fn runs_changed(&self) {
        self.bump();
        self.wake.notify_one();
    }

    pub fn target_dir(&self, id: &str) -> PathBuf {
        self.cfg.work.join("targets").join(id)
    }

    pub fn run_dir(&self, target: &str, run: &str) -> PathBuf {
        self.target_dir(target).join("runs").join(run)
    }

    /// Writes an audit line to `control.db` and as JSON to stdout.
    pub fn audit(&self, mut e: AuditEntry) {
        e.time = time::now_millis();
        // Nothing a caller sends makes an audit line long.
        for f in [&mut e.actor, &mut e.action, &mut e.result] {
            clip(f);
        }
        for f in [&mut e.target, &mut e.run, &mut e.detail].into_iter().flatten() {
            clip(f);
        }
        println!(
            "{}",
            json!({
                "audit": e.action, "time": time::format_millis(e.time), "actor": e.actor,
                "actor_kind": e.actor_kind, "ip": e.ip, "target": e.target, "run": e.run,
                "result": e.result, "detail": e.detail,
            })
        );
        if let Err(err) = self.db().audit(&e) {
            eprintln!("brainproxy-server: can't write the audit log: {err}");
        }
        // Admin operations change control.db; failed sign-ins only add audit lines.
        if e.action != "authenticate" {
            self.sync(store::Item::Control);
        }
    }

    fn prune(&self) {
        let now = time::now_millis();
        let audit_before = now - self.cfg.audit_days as i64 * 24 * 3600 * 1000;
        if let Err(e) = self.db().prune(audit_before, now - DEDUP_MS) {
            eprintln!("brainproxy-server: pruning control.db: {e}");
        }
    }

    pub fn is_busy(&self, target: &str) -> bool {
        self.busy.lock().unwrap_or_else(|e| e.into_inner()).contains(target)
    }

    // -- the CLI's environment -------------------------------------------------------------------

    /// The environment of a CLI process for this target: a small allowlist plus the target's own
    /// secrets, so one target's scan never sees another's passwords (research §5.5).
    fn target_env(&self, t: &TargetConfig) -> Result<Vec<(OsString, OsString)>, String> {
        let mut env = base_env(&self.cfg);
        for (cli_var, source) in &t.secret_env {
            let file = self.cfg.secrets_dir.join(&t.id).join(cli_var);
            let value = match std::fs::read_to_string(&file) {
                Ok(v) => OsString::from(v.trim_end_matches(['\r', '\n'])),
                Err(_) => std::env::var_os(source).ok_or_else(|| {
                    // Where secrets come from stays in the server log, not in what read tokens see.
                    eprintln!(
                        "brainproxy-server: secret {cli_var} of target {} isn't set: no file {} and no variable {source}",
                        t.id,
                        file.display()
                    );
                    format!("secret {cli_var} of target {} isn't set on the server (see its log)", t.id)
                })?,
            };
            env.push((cli_var.into(), value));
        }
        Ok(env)
    }

    fn cli(&self, project: PathBuf, env: Vec<(OsString, OsString)>) -> Cli {
        Cli { bin: self.cfg.brainproxy.clone(), project, env: Some(Arc::new(env)) }
    }

    // -- the system scope ------------------------------------------------------------------------

    fn write_system_scope(&self) -> std::io::Result<()> {
        let targets = self.db().targets().map_err(std::io::Error::other)?;
        let configs: Vec<&TargetConfig> = targets.iter().map(|t| &t.config).collect();
        write_atomic(&self.cfg.system_scope, target::system_scope(&configs).to_string().as_bytes())
    }

    // -- the queue -------------------------------------------------------------------------------

    async fn scheduler(self: Arc<Self>) {
        loop {
            self.schedule();
            tokio::select! {
                _ = self.wake.notified() => {}
                _ = tokio::time::sleep(Duration::from_secs(30)) => {}
            }
        }
    }

    /// Starts queued runs, oldest first, while there are free workers and their target is idle.
    fn schedule(self: &Arc<Self>) {
        let queued = match self.db().runs_in_state(state::QUEUED) {
            Ok(q) => q,
            Err(e) => {
                eprintln!("brainproxy-server: reading the queue: {e}");
                return;
            }
        };
        for run in queued {
            let (busy_targets, n): (HashSet<String>, usize) = {
                let live = self.live.lock().unwrap_or_else(|e| e.into_inner());
                (live.values().map(|l| l.target.clone()).collect(), live.len())
            };
            if n >= self.cfg.max_parallel {
                return;
            }
            if busy_targets.contains(&run.target) || self.is_busy(&run.target) {
                continue;
            }
            match self.db().mark_running(&run.id, time::now_millis()) {
                Ok(true) => {}
                Ok(false) => continue,
                Err(e) => {
                    eprintln!("brainproxy-server: starting run {}: {e}", run.id);
                    continue;
                }
            }
            self.clone().spawn_worker(run, false);
        }
    }

    fn spawn_worker(self: Arc<Self>, run: RunRow, resume: bool) {
        let (tx, rx) = watch::channel(None);
        if run.cancel_requested {
            let _ = tx.send(Some("a cancel request"));
        }
        self.live
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(run.id.clone(), Live { target: run.target.clone(), cancel: tx.clone() });
        // A cancel between `mark_running` and the insert above found no live entry: read it again.
        if self.db().run(&run.target, &run.id).ok().flatten().is_some_and(|r| r.cancel_requested) {
            let _ = tx.send(Some("a cancel request"));
        }
        self.bump();
        tokio::spawn(async move {
            let (id, target) = (run.id.clone(), run.target.clone());
            let inner = tokio::spawn(self.clone().execute(run, resume, rx));
            let end = match inner.await {
                Ok(end) => end,
                Err(e) => End::failed(code::ERROR, format!("internal error: {e}")),
            };
            let cancelled = self.db().run(&target, &id).ok().flatten().is_some_and(|r| r.cancel_requested);
            // A cancelled run never passes, even when its scan completed before the cancel reached it
            // (the same rule as `ci`).
            let end = if cancelled {
                let mut run = end.run;
                let note = match end.state {
                    state::COMPLETED => {
                        // Also in run.json, which the next run's history reads: not a pass to count from.
                        if let Some(r) = run.as_mut() {
                            r["outcome"] = json!("incomplete");
                            r["exit_code"] = json!(code::USAGE);
                            if let Some(reasons) = r["reasons"].as_array_mut() {
                                reasons.push(json!("cancelled after the scan completed"));
                            }
                            let path = self.run_dir(&target, &id).join(crate::record::RUN_FILE);
                            if let Err(e) = write_atomic(&path, &serde_json::to_vec_pretty(r).unwrap_or_default()) {
                                eprintln!("brainproxy-server: rewriting {}: {e}", path.display());
                            }
                        }
                        Some("cancelled after the scan completed; not counted as a pass".to_string())
                    }
                    _ => end.note,
                };
                End { state: state::CANCELLED, outcome: "incomplete", exit: code::USAGE, note, run }
            } else {
                end
            };
            let end = db::RunEnd {
                state: end.state,
                outcome: end.outcome,
                exit_code: end.exit,
                run_json: end.run.as_ref(),
                note: end.note.as_deref(),
            };
            if let Err(e) = self.db().finish_run(&id, &end, time::now_millis()) {
                eprintln!("brainproxy-server: recording the end of run {id}: {e}");
            }
            self.live.lock().unwrap_or_else(|e| e.into_inner()).remove(&id);
            self.runs_changed();
            self.sync(store::Item::Run { target: target.clone(), run: id.clone() });
            let snapshot = self.target_dir(&target).join("snapshots").join(format!("{id}.bpdb"));
            self.sync(store::Item::Project { target, snapshot: Some(snapshot) });
        });
    }

    /// Cancels a run: a queued one at once, a running one by stopping its scan.
    pub fn cancel(&self, target: &str, run: &str) -> Result<Option<String>, ApiError> {
        let before = self.db().request_cancel(target, run, time::now_millis()).map_err(ApiError::db)?;
        if before.as_deref() == Some(state::RUNNING)
            && let Some(live) = self.live.lock().unwrap_or_else(|e| e.into_inner()).get(run)
        {
            let _ = live.cancel.send(Some("a cancel request"));
        }
        self.runs_changed();
        Ok(before)
    }

    /// One run, from its queued row to the end. Returns how it ended.
    async fn execute(self: Arc<Self>, run: RunRow, resume: bool, cancel: watch::Receiver<Option<&'static str>>) -> End {
        let Some(target) = self.db().target(&run.target).ok().flatten() else {
            return End::failed(code::NOT_FOUND, format!("target {} isn't registered any more", run.target));
        };
        let t = &target.config;
        let env = match self.target_env(t) {
            Ok(env) => env,
            Err(e) => return End::failed(code::ERROR, e),
        };
        let project = self.target_dir(&t.id).join("project.bpdb");
        let cli = self.cli(project.clone(), env.clone());
        // DNS can change after registration: the base host must still resolve to allowed addresses.
        let addrs = match self.check_host(&cli, t).await {
            Ok(a) => a,
            Err((c, e)) => return End::failed(c, e),
        };
        if t.ownership
            && let Err(e) = self.check_ownership(t, addrs).await
        {
            return End::failed(code::OUT_OF_SCOPE, format!("ownership check: {e}"));
        }

        let baseline = run.baseline;
        let args = ci::Args {
            brainproxy: self.cfg.brainproxy.clone(),
            project,
            url: t.base_url.clone(),
            preset: run.preset.clone(),
            fail_on: if baseline { None } else { t.gate.fail_on.clone() },
            new_only: !baseline && t.gate.new_only,
            out: self.target_dir(&t.id).join("runs"),
            max_minutes: Some(t.max_minutes),
            rate: t.rate,
            auth: t.profile().map(String::from),
            accept_coverage_drop: run.accept_coverage_drop,
            baseline,
            policy: if baseline { Default::default() } else { t.policy.clone() },
        };
        let on_write = {
            let s = self.clone();
            let id = run.id.clone();
            Arc::new(move |r: &Run| {
                let value = serde_json::to_value(r).unwrap_or_default();
                if let Err(e) = s.db().set_progress(&id, r.job.as_ref().map(|j| j.id), &value) {
                    eprintln!("brainproxy-server: recording run {id}: {e}");
                }
                s.bump();
            })
        };
        let opts = Options {
            folder: Some(self.run_dir(&t.id, &run.id)),
            env: Some(Arc::new(env)),
            on_write: Some(on_write),
            label: Some(format!("brainproxy-server: {} {}", t.id, run.id)),
        };
        let started = if resume { Ci::resume(args, opts).await } else { Ci::start(args, opts).await };
        let ci = match started {
            Ok(ci) => ci,
            Err((c, e)) => {
                if resume {
                    // The server stopped before the scan's job was recorded: stop any scan it left.
                    stop_orphan_scans(&cli).await;
                    return End::incomplete(format!("the server restarted before the scan started ({e})"));
                }
                return if c == code::USAGE { End::incomplete(e) } else { End::failed(c, e) };
            }
        };
        let done = ci.finish(cancel).await;
        if done.run.scan_complete() {
            self.snapshot(&cli, &t.id, &run.id).await;
        }
        let (state, outcome) = match done.run.outcome {
            Outcome::Passed => (state::COMPLETED, "passed"),
            Outcome::Failed => (state::COMPLETED, "gate_failed"),
            Outcome::Incomplete => (state::INCOMPLETE, "incomplete"),
            Outcome::Error | Outcome::Running => (state::FAILED, "error"),
        };
        End { state, outcome, exit: done.exit, run: serde_json::to_value(&done.run).ok(), note: None }
    }

    /// `engagement check` of the base URL's host and every other host name in the scope: allowed,
    /// and not resolving to this machine or a link-local address (a registered name pointed at the
    /// server itself would reach its admin port).
    /// Checks every scope host's resolved addresses; returns the base URL host's, as the CLI
    /// resolves it (host overrides included).
    async fn check_host(&self, cli: &Cli, t: &TargetConfig) -> Result<Vec<std::net::IpAddr>, (i32, String)> {
        let (host, port) = target::url_host_port(&t.base_url).map_err(|e| (code::USAGE, e))?;
        let base = if host.contains(':') { format!("[{host}]:{port}") } else { format!("{host}:{port}") };
        let mut names = vec![(base, true)];
        for s in &t.scope {
            if let Ok(ScopeEntry::Host { name, port }) = ScopeEntry::parse(s, true) {
                names.push((format!("{name}:{}", port.unwrap_or(443)), false));
            }
        }
        let mut base_addrs = Vec::new();
        for (name, must_be_allowed) in names {
            let out = cli
                .run(["engagement", "check", &name])
                .await
                .map_err(|e| (code::ERROR, format!("can't run {}: {e}", cli.bin.display())))?;
            if !out.ok() {
                let c = if out.code == code::OK { code::ERROR } else { out.code };
                return Err((c, format!("engagement check: {}", out.message())));
            }
            let result = &out.data()["results"][0];
            if must_be_allowed && result["allowed"] != true {
                let why = result["reason"].as_str().unwrap_or("not allowed");
                return Err((code::OUT_OF_SCOPE, format!("{name}: {why}")));
            }
            for a in result["addresses"].as_array().into_iter().flatten().filter_map(Value::as_str) {
                let Ok(ip) = a.parse::<std::net::IpAddr>() else { continue };
                if let Err(e) = target::check_ip(ip, self.cfg.allow_loopback_targets) {
                    return Err((code::OUT_OF_SCOPE, format!("{name} resolves to {ip}: {e}")));
                }
                if must_be_allowed {
                    base_addrs.push(ip);
                }
            }
        }
        Ok(base_addrs)
    }

    /// `project save` into `snapshots/<run>.bpdb`, keeping the newest `keep_snapshots`.
    async fn snapshot(&self, cli: &Cli, target: &str, run: &str) {
        if self.cfg.keep_snapshots == 0 {
            return;
        }
        let dir = self.target_dir(target).join("snapshots");
        if let Err(e) = save(cli, &dir.join(format!("{run}.bpdb"))).await {
            eprintln!("brainproxy-server: snapshot of {target} after {run}: {e}");
        }
        let mut snaps: Vec<PathBuf> = std::fs::read_dir(&dir)
            .map(|d| {
                d.filter_map(|e| e.ok().map(|e| e.path()))
                    .filter(|p| p.extension().is_some_and(|x| x == "bpdb"))
                    .collect()
            })
            .unwrap_or_default();
        snaps.sort();
        let extra = snaps.len().saturating_sub(self.cfg.keep_snapshots);
        for old in &snaps[..extra] {
            let _ = std::fs::remove_file(old);
        }
    }

    /// A consistent copy of a target's project at `path` (`project save`).
    async fn save_project(&self, target: &str, path: &Path) -> Result<(), String> {
        save(&self.cli(self.target_dir(target).join("project.bpdb"), base_env(&self.cfg)), path).await
    }

    /// Queues everything for the store: on the first start with an empty store.
    fn sync_everything(&self) {
        let targets = self.db().targets().unwrap_or_default();
        for t in targets {
            let id = t.config.id;
            let runs = std::fs::read_dir(self.target_dir(&id).join("runs")).into_iter().flatten().flatten();
            for run in runs.filter(|r| r.path().is_dir()) {
                self.sync(store::Item::Run { target: id.clone(), run: run.file_name().to_string_lossy().into() });
            }
            self.sync(store::Item::Project { target: id, snapshot: None });
        }
        self.sync(store::Item::Control);
    }

    // -- admin operations ------------------------------------------------------------------------

    /// Registers a target: checks, creates its project (or waits for an upload), saves it, and
    /// widens the system scope by its hosts.
    pub async fn register(&self, mut t: TargetConfig) -> Result<Value, ApiError> {
        let _op = self.admin_ops.lock().await;
        t.validate(self.cfg.allow_loopback_targets).map_err(ApiError::invalid)?;
        self.check_settings(&mut t, None)?;
        {
            let db = self.db();
            if db.target(&t.id).map_err(ApiError::db)?.is_some() {
                return Err(ApiError::conflict(format!("target {} already exists", t.id)));
            }
            if db.target_count().map_err(ApiError::db)? >= db::MAX_TARGETS {
                return Err(ApiError::limit());
            }
        }
        let dir = self.target_dir(&t.id);
        if dir.exists() {
            return Err(ApiError::conflict(format!("{} exists; move it away first", dir.display())));
        }
        let tmp =
            self.cfg.work.join("targets").join(format!(".new-{}-{}", t.id, auth::base32(&auth::random_bytes::<5>())));
        std::fs::create_dir_all(&tmp).map_err(ApiError::io)?;
        let result = self.prepare_target(&t, &tmp).await;
        if let Err(e) = result {
            let _ = std::fs::remove_dir_all(&tmp);
            return Err(e);
        }
        let _ = std::fs::remove_file(tmp.join("check.bpdb"));
        let _ = std::fs::remove_file(tmp.join("system-scope.json"));
        std::fs::rename(&tmp, &dir).map_err(ApiError::io)?;
        let ready = t.project == ProjectSource::Generate;
        if let Err(e) = self.db().insert_target(&t, ready, time::now_millis()) {
            let _ = std::fs::remove_dir_all(&dir);
            return Err(if e.to_string().contains("at most") { ApiError::limit() } else { ApiError::db(e) });
        }
        self.write_system_scope().map_err(ApiError::io)?;
        if ready {
            self.sync(store::Item::Project { target: t.id.clone(), snapshot: None });
        }
        Ok(json!({
            "id": t.id, "created": true, "project_ready": ready,
            "next": if ready {
                format!("issue a token: POST /v1/targets/{}/tokens", t.id)
            } else {
                format!("upload the project: PUT /v1/targets/{}/project", t.id)
            },
            "target": t.public_json(),
        }))
    }

    /// Checks what `validate` can't (the OIDC issuers this server trusts) and sets the server's own
    /// fields: the ownership token, kept from `before` while ownership stays on.
    fn check_settings(&self, t: &mut TargetConfig, before: Option<&TargetConfig>) -> Result<(), ApiError> {
        oidc::check_bindings(&t.oidc, &self.cfg.oidc_issuers).map_err(ApiError::invalid)?;
        t.ownership_token = match (t.ownership, before.and_then(|b| b.ownership_token.clone())) {
            (false, _) => None,
            (true, Some(kept)) => Some(kept),
            (true, None) => Some(format!("bpo_{}", auth::base32(&auth::random_bytes::<16>()))),
        };
        Ok(())
    }

    /// Changes a target's OIDC bindings, alert policy or ownership check. Scope, URL and project
    /// settings don't change: those need a new registration.
    pub async fn update_target(&self, id: &str, patch: TargetPatch) -> Result<Value, ApiError> {
        let _op = self.admin_ops.lock().await;
        let before = self.db().target(id).map_err(ApiError::db)?.ok_or_else(|| ApiError::not_found("target"))?.config;
        let mut t = before.clone();
        if let Some(b) = patch.oidc {
            t.oidc = b;
        }
        if let Some(p) = patch.policy {
            t.policy = p;
        }
        if let Some(o) = patch.ownership {
            t.ownership = o;
        }
        crate::policy::check(&t.policy).map_err(ApiError::invalid)?;
        self.check_settings(&mut t, Some(&before))?;
        self.db().update_config(&t).map_err(ApiError::db)?;
        Ok(t.public_json())
    }

    /// Fetches `/.well-known/brainproxy-<id>.txt` from the target's origin and looks for its token.
    /// It connects only to `addrs`, the addresses `check_host` just vetted, so a name resolving
    /// elsewhere a moment later can't send the request anywhere else.
    async fn check_ownership(&self, t: &TargetConfig, addrs: Vec<std::net::IpAddr>) -> Result<(), String> {
        let Some(token) = t.ownership_token.clone() else { return Err("ownership is on but has no token".into()) };
        let (host, port) = target::url_host_port(&t.base_url)?;
        let scheme = if t.base_url.starts_with("https://") { "https" } else { "http" };
        let host = if host.contains(':') { format!("[{host}]") } else { host };
        let url = format!("{scheme}://{host}:{port}/.well-known/brainproxy-{}.txt", t.id);
        let shown = url.clone();
        if addrs.is_empty() {
            return Err(format!("{} resolved to no addresses", t.base_url));
        }
        let pinned: Vec<SocketAddr> = addrs.into_iter().map(|ip| SocketAddr::new(ip, port)).collect();
        let body =
            tokio::task::spawn_blocking(move || fetch_small(&url, pinned)).await.map_err(|e| e.to_string())??;
        if body.lines().any(|l| l.trim() == token) {
            Ok(())
        } else {
            Err(format!("{shown} doesn't hold this target's ownership token"))
        }
    }

    /// Creates the project (or a scratch one for an upload target) in `dir` and checks the base URL
    /// against the scope that will be in force: the engagement plus the system scope with this target.
    async fn prepare_target(&self, t: &TargetConfig, dir: &Path) -> Result<(), ApiError> {
        let mut targets: Vec<TargetConfig> =
            self.db().targets().map_err(ApiError::db)?.into_iter().map(|x| x.config).collect();
        targets.push(t.clone());
        let candidate = dir.join("system-scope.json");
        write_atomic(&candidate, target::system_scope(&targets.iter().collect::<Vec<_>>()).to_string().as_bytes())
            .map_err(ApiError::io)?;
        let mut env = base_env(&self.cfg);
        env.retain(|(k, _)| k != "BRAINPROXY_SYSTEM_SCOPE");
        env.push(("BRAINPROXY_SYSTEM_SCOPE".into(), candidate.into_os_string()));
        let name = if t.project == ProjectSource::Generate { "project.bpdb" } else { "check.bpdb" };
        let cli = self.cli(dir.join(name), env);
        let mut argv = vec!["engagement".to_string(), "start".into()];
        for s in &t.scope {
            argv.push(format!("--target={s}"));
        }
        argv.push(format!("--name={}", t.id));
        cli_ok(&cli, &argv).await?;
        if t.project == ProjectSource::Generate
            && let Some(a) = &t.auth
        {
            cli_ok(&cli, &a.argv()).await?;
        }
        self.check_host(&cli, t).await.map(drop).map_err(|(c, e)| {
            ApiError::invalid(format!("base_url {}: {e}", t.base_url)).with_kind(if c == code::OUT_OF_SCOPE {
                "out_of_scope"
            } else {
                "invalid"
            })
        })
    }

    /// Takes an uploaded project (already written to `file`) for a target, after the checks of
    /// research §5.3. The file's folder is removed either way.
    pub async fn accept_upload(&self, id: &str, file: &Path) -> Result<Value, ApiError> {
        let _op = self.admin_ops.lock().await;
        // Released however this ends, also when the client goes away and the handler is dropped.
        let _busy = Busy { server: self, id };
        self.accept_upload_locked(id, file).await
    }

    async fn accept_upload_locked(&self, id: &str, file: &Path) -> Result<Value, ApiError> {
        let target = self.db().target(id).map_err(ApiError::db)?.ok_or_else(|| ApiError::not_found("target"))?;
        let t = &target.config;
        self.claim(id)?;
        let mut magic = [0u8; 16];
        use std::io::Read;
        let is_sqlite =
            File::open(file).and_then(|mut f| f.read_exact(&mut magic)).is_ok() && &magic == b"SQLite format 3\0";
        if !is_sqlite {
            return Err(ApiError::invalid("the upload is not a brainproxy project (SQLite) file"));
        }
        let cli = self.cli(file.to_path_buf(), base_env(&self.cfg));
        let eng = cli_ok(&cli, ["engagement", "show"]).await?;
        let e = &eng.data()["engagement"];
        if e.is_null() {
            return Err(ApiError::invalid("the project has no engagement scope"));
        }
        let allowed: Vec<String> = t.scope.clone();
        for inc in e["include"].as_array().into_iter().flatten() {
            let s = inc.as_str().unwrap_or_default();
            let norm = ScopeEntry::parse(s, self.cfg.allow_loopback_targets).map(|x| x.to_string());
            if !norm.as_ref().is_ok_and(|n| allowed.contains(n)) {
                return Err(ApiError::invalid(format!(
                    "the project's scope includes {s}, which isn't in the target's registered scope ({})",
                    allowed.join(", ")
                ))
                .with_kind("out_of_scope"));
            }
        }
        if eng.data()["engagement_proxies"].as_array().is_some_and(|p| !p.is_empty()) {
            return Err(ApiError::invalid("the project allows upstream proxies; the server doesn't accept those"));
        }
        // Connection settings the CLI applies on top of the scope: an upstream proxy (allowed on
        // loopback by the CLI) or a host override to an address the scope doesn't list would send
        // the scan somewhere the registration never named.
        let conn = cli_ok(&cli, ["connection", "show"]).await?;
        let c = conn.data();
        // An allowlist: host overrides (checked below) and nothing else, including keys a later CLI
        // may add. Client certificates are file paths read on the server, which could name another
        // target's secret files.
        for (key, value) in c.as_object().into_iter().flatten() {
            let empty = value.as_array().is_some_and(Vec::is_empty);
            if !matches!(key.as_str(), "hosts" | "warnings" | "note") && !empty && !value.is_null() {
                return Err(ApiError::invalid(format!(
                    "the project has connection settings the server doesn't accept (`connection {key}`); \
                     only host overrides to addresses in the scope"
                )));
            }
        }
        let entries: Vec<ScopeEntry> =
            t.scope.iter().filter_map(|s| ScopeEntry::parse(s, self.cfg.allow_loopback_targets).ok()).collect();
        for h in c["hosts"].as_array().into_iter().flatten() {
            let ip_text = h["ip"].as_str().unwrap_or_default();
            let listed = ip_text.parse::<std::net::IpAddr>().ok().filter(|ip| {
                target::check_ip(*ip, self.cfg.allow_loopback_targets).is_ok()
                    && entries.iter().any(|e| e.covers_addr(*ip))
            });
            if listed.is_none() {
                return Err(ApiError::invalid(format!(
                    "the project maps {} to {ip_text}, an address the target's scope doesn't list",
                    h["host"].as_str().unwrap_or("?")
                ))
                .with_kind("out_of_scope"));
            }
        }
        let profiles = cli_ok(&cli, ["auth", "list"]).await?;
        let mut names = Vec::new();
        for p in profiles.data()["profiles"].as_array().into_iter().flatten() {
            let name = p["name"].as_str().unwrap_or_default().to_string();
            let shown = cli_ok(&cli, ["auth", "show", &name]).await?;
            if !shown.data()["profile"]["password"]["literal"].is_null() {
                return Err(ApiError::invalid(format!(
                    "auth profile {name} stores its password in the project; use --password-env and the target's secret_env"
                )));
            }
            names.push(name);
        }
        if let Some(p) = t.profile()
            && !names.iter().any(|n| n == p)
        {
            return Err(ApiError::invalid(format!("the project has no auth profile {p}")));
        }
        // A clean, consistent copy (no WAL side files); `project save` reads every page.
        let clean = file.with_file_name("clean.bpdb");
        cli_ok(&cli, [OsString::from("project"), "save".into(), "--output".into(), clean.clone().into_os_string()])
            .await?;

        let dir = self.target_dir(id);
        let project = dir.join("project.bpdb");
        if project.exists() {
            let old = dir.join("replaced").join(time::now().replace([':', '.'], ""));
            std::fs::create_dir_all(&old).map_err(ApiError::io)?;
            for suffix in ["", "-wal", "-shm"] {
                let from = dir.join(format!("project.bpdb{suffix}"));
                if from.exists() {
                    std::fs::rename(&from, old.join(format!("project.bpdb{suffix}"))).map_err(ApiError::io)?;
                }
            }
        }
        std::fs::rename(&clean, &project).map_err(ApiError::io)?;
        self.db().set_project_ready(id).map_err(ApiError::db)?;
        self.sync(store::Item::Project { target: id.to_string(), snapshot: None });
        Ok(json!({"target": id, "project_ready": true, "scope": e["include"], "profiles": names}))
    }

    /// Marks a target busy for an upload or removal (until the caller's [`Busy`] drops); 409 while
    /// it has a queued or running run.
    fn claim(&self, id: &str) -> Result<(), ApiError> {
        let mut busy = self.busy.lock().unwrap_or_else(|e| e.into_inner());
        if self.db().live_runs_of(id).map_err(ApiError::db)? > 0 {
            return Err(ApiError::conflict(format!("target {id} has a queued or running run; cancel it or wait")));
        }
        busy.insert(id.to_string());
        Ok(())
    }

    /// Removes a target: its tokens stop working, and its folder moves to `<work>/removed/`.
    pub async fn remove_target(&self, id: &str) -> Result<Value, ApiError> {
        let _op = self.admin_ops.lock().await;
        if self.db().target(id).map_err(ApiError::db)?.is_none() {
            return Err(ApiError::not_found("target"));
        }
        let _busy = Busy { server: self, id };
        self.claim(id)?;
        (|| {
            let removed = self.cfg.work.join("removed");
            std::fs::create_dir_all(&removed).map_err(ApiError::io)?;
            let to = removed.join(format!("{id}-{}", time::now().replace([':', '.'], "")));
            if self.target_dir(id).exists() {
                std::fs::rename(self.target_dir(id), &to).map_err(ApiError::io)?;
            }
            self.db().delete_target(id).map_err(ApiError::db)?;
            self.write_system_scope().map_err(ApiError::io)?;
            self.sync(store::Item::Removed { target: id.to_string() });
            Ok(json!({"id": id, "removed": true, "moved_to": to}))
        })()
    }
}

/// `project save --output path`.
async fn save(cli: &Cli, path: &Path) -> Result<(), String> {
    match cli.run([OsString::from("project"), "save".into(), "--output".into(), path.as_os_str().to_owned()]).await {
        Ok(out) if out.ok() => Ok(()),
        Ok(out) => Err(out.message()),
        Err(e) => Err(e.to_string()),
    }
}

fn clip(s: &mut String) {
    if s.len() > 300 {
        let mut end = 300;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        s.truncate(end);
        s.push('…');
    }
}

/// Clears a target's busy mark (set by `claim`) when dropped, and wakes the scheduler.
struct Busy<'a> {
    server: &'a Server,
    id: &'a str,
}

impl Drop for Busy<'_> {
    fn drop(&mut self) {
        self.server.busy.lock().unwrap_or_else(|e| e.into_inner()).remove(self.id);
        self.server.wake.notify_one();
    }
}

/// How a run ended, for its row.
struct End {
    state: &'static str,
    outcome: &'static str,
    exit: i32,
    run: Option<Value>,
    note: Option<String>,
}

impl End {
    fn failed(exit: i32, note: String) -> End {
        let exit = if exit == code::OK { code::ERROR } else { exit };
        End { state: state::FAILED, outcome: "error", exit, run: None, note: Some(note) }
    }

    fn incomplete(note: String) -> End {
        End { state: state::INCOMPLETE, outcome: "incomplete", exit: code::USAGE, run: None, note: Some(note) }
    }
}

/// The allowlisted environment every CLI process gets (research §5.5).
fn base_env(cfg: &Config) -> Vec<(OsString, OsString)> {
    let mut env: Vec<(OsString, OsString)> = Vec::new();
    env.push(("PATH".into(), std::env::var_os("PATH").unwrap_or_else(|| "/usr/local/bin:/usr/bin:/bin".into())));
    env.push(("HOME".into(), cfg.work.join("home").into_os_string()));
    let home = std::env::var_os("BRAINPROXY_HOME").unwrap_or_else(|| cfg.work.join(".brainproxy").into_os_string());
    env.push(("BRAINPROXY_HOME".into(), home));
    if let Some(tz) = std::env::var_os("TZ") {
        env.push(("TZ".into(), tz));
    }
    env.push(("BRAINPROXY_SYSTEM_SCOPE".into(), cfg.system_scope.clone().into_os_string()));
    env
}

/// Runs a CLI command that must succeed.
async fn cli_ok<I, S>(cli: &Cli, args: I) -> Result<brainproxy::Output, ApiError>
where
    I: IntoIterator<Item = S>,
    S: Into<OsString>,
{
    let args: Vec<OsString> = args.into_iter().map(Into::into).collect();
    let what = args.iter().take(2).map(|a| a.to_string_lossy()).collect::<Vec<_>>().join(" ");
    let out = cli.run(args).await.map_err(|e| ApiError::internal(format!("can't run {}: {e}", cli.bin.display())))?;
    if !out.ok() {
        let kind = if out.code == code::OUT_OF_SCOPE { "out_of_scope" } else { "invalid" };
        return Err(ApiError::invalid(format!("{what}: {}", out.message())).with_kind(kind));
    }
    Ok(out)
}

/// Stops active scans left running in a project (the server owns its projects alone).
async fn stop_orphan_scans(cli: &Cli) {
    let Ok(list) = cli.run(["job", "list", "--limit", "1000"]).await else { return };
    for j in list.data()["jobs"].as_array().into_iter().flatten() {
        if j["kind"] == "active-scan" && matches!(j["state"].as_str(), Some("running" | "queued")) {
            let id = j["id"].as_u64().unwrap_or(0).to_string();
            let _ = cli.run(["job", "stop", &id]).await;
        }
    }
}

fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)
}

/// One server per work directory.
fn lock_work(work: &Path) -> Result<File, String> {
    let path = work.join(".brainproxy-server.lock");
    let file = File::options()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(TryLockError::WouldBlock) => Err(format!("another brainproxy-server is using {}", work.display())),
        Err(TryLockError::Error(e)) => Err(format!("can't lock {}: {e}", path.display())),
    }
}

/// The kind of network filesystem `path` is on, if it is on one.
#[cfg(target_os = "linux")]
fn network_fs(path: &Path) -> Option<&'static str> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: `c` is a valid C string and `st` a writable statfs.
    if unsafe { libc::statfs(c.as_ptr(), &mut st) } != 0 {
        return None;
    }
    match st.f_type as u64 {
        0x6969 => Some("NFS"),
        0x517b => Some("SMB"),
        0xff53_4d42 => Some("CIFS"),
        0xfe53_4d42 => Some("SMB2"),
        0x6573_5546 => Some("FUSE"),
        0x0102_1997 => Some("9p"),
        0x00c3_6400 => Some("Ceph"),
        0x5346_414f => Some("AFS"),
        0x0bd0_0bd0 => Some("Lustre"),
        _ => None,
    }
}

#[cfg(target_os = "macos")]
fn network_fs(path: &Path) -> Option<&'static str> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: `c` is a valid C string and `st` a writable statfs.
    if unsafe { libc::statfs(c.as_ptr(), &mut st) } != 0 {
        return None;
    }
    let name: Vec<u8> = st.f_fstypename.iter().take_while(|c| **c != 0).map(|c| *c as u8).collect();
    match name.as_slice() {
        b"nfs" => Some("NFS"),
        b"smbfs" => Some("SMB"),
        b"afpfs" => Some("AFP"),
        b"webdav" => Some("WebDAV"),
        b"macfuse" | b"osxfuse" => Some("FUSE"),
        _ => None,
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn network_fs(_path: &Path) -> Option<&'static str> {
    None
}

#[cfg(unix)]
async fn wait_for_stop() -> &'static str {
    use tokio::signal::unix::{SignalKind, signal};
    let (Ok(mut int), Ok(mut term)) = (signal(SignalKind::interrupt()), signal(SignalKind::terminate())) else {
        return std::future::pending().await;
    };
    tokio::select! {
        _ = int.recv() => "SIGINT",
        _ = term.recv() => "SIGTERM",
    }
}

#[cfg(not(unix))]
async fn wait_for_stop() -> &'static str {
    let _ = tokio::signal::ctrl_c().await;
    "Ctrl-C"
}
