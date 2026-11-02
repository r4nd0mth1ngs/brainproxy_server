//! One scan of one target, compared with the previous runs, gated, and written to a run folder: the
//! `ci` command, and each run of `serve` (see [`Ci::start`] and [`Ci::resume`]). The steps are in
//! PLAN.md (phase 1); the outcome rules are research §7.3.

use std::ffi::OsString;
use std::fs::{File, TryLockError};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde_json::Value;
use tokio::sync::watch;

use crate::brainproxy::{self, Cli, Output, code};
use crate::policy::{self, Policy};
use crate::record::{self, Coverage, CoverageBaseline, Gate, Job, JobRef, Outcome, Run, Summary};
use crate::time;

pub const LOCK_FILE: &str = ".brainproxy-server.lock";

/// Seconds per `job wait` call; a progress line is printed after each.
const WAIT_STEP_SECS: u64 = 60;
/// How long to wait for a stopped scan to wind down after a cancel. Short: CI runners send SIGKILL
/// a few seconds after the first signal (GitHub: about 10 s).
const STOP_GRACE_SECS: u64 = 5;
/// `job wait` failures in a row before the job is given up on (and stopped).
const WAIT_RETRIES: u32 = 3;
/// `--limit` for compare.json and the reports, so that nothing is cut off.
const NO_LIMIT: &str = "1000000";

#[derive(Debug, Clone)]
pub struct Args {
    pub brainproxy: PathBuf,
    pub project: PathBuf,
    pub url: String,
    pub preset: String,
    pub fail_on: Option<String>,
    pub new_only: bool,
    pub out: PathBuf,
    pub max_minutes: Option<u64>,
    /// `scan active --rate`: requests per second.
    pub rate: Option<u32>,
    pub auth: Option<String>,
    pub accept_coverage_drop: bool,
    pub baseline: bool,
    /// Alert policy for the gate; empty: the CLI's `--fail-on` alone decides.
    pub policy: Policy,
}

pub type OnWrite = Arc<dyn Fn(&Run) + Send + Sync>;

/// How a run differs when `serve` runs it rather than the `ci` command.
#[derive(Clone, Default)]
pub struct Options {
    /// The run folder. `None`: `<out>/<job start time>-<job>/`, named once the job has started.
    pub folder: Option<PathBuf>,
    /// The whole environment of the CLI processes; `None` inherits this process's.
    pub env: Option<Arc<Vec<(OsString, OsString)>>>,
    /// Called with `run.json` each time it is written.
    pub on_write: Option<OnWrite>,
    /// Starts each progress line on stderr (default `brainproxy-server`).
    pub label: Option<String>,
}

/// A finished run: its `run.json` and exit code.
pub struct Finished {
    pub run: Run,
    pub exit: i32,
}

/// Runs `ci` and returns the exit code. Progress and the summary go to stderr, `run.json` to stdout.
pub async fn run(args: Args) -> i32 {
    let cancel = cancel_signal();
    match Ci::start(args, Options::default()).await {
        Ok(ci) => {
            let done = ci.finish(cancel).await;
            println!("{}", serde_json::to_string_pretty(&done.run).unwrap_or_default());
            done.exit
        }
        Err((code, message)) => {
            eprintln!("brainproxy-server: {message}");
            code
        }
    }
}

/// Everything known before the scan starts.
pub struct Ci {
    args: Args,
    opts: Options,
    cli: Cli,
    _lock: File,
    run: Run,
    history: Vec<record::Past>,
    /// The signal that cancelled the run, once one has.
    cancelled: Option<&'static str>,
    /// Set by [`Ci::resume`]: the job is already running.
    resumed: bool,
}

pub type Refusal = (i32, String);

impl Ci {
    /// Checks the CLI, the project and the run folder, and takes the lock. Nothing is written yet.
    pub async fn start(args: Args, opts: Options) -> Result<Ci, Refusal> {
        Ci::prepare(args, opts, true).await
    }

    /// [`Ci::start`]; `refuse_busy`: refuse a project with a live scan.
    async fn prepare(mut args: Args, opts: Options, refuse_busy: bool) -> Result<Ci, Refusal> {
        let version =
            brainproxy::check_version(&args.brainproxy, opts.env.as_deref()).await.map_err(|e| (code::ERROR, e))?;

        // `--project` creates a missing file, so check first: never scan into a new, empty project.
        if !args.project.is_file() {
            return Err((
                code::NOT_FOUND,
                format!(
                    "project {} doesn't exist; create it with `brainproxy --project FILE engagement start --target HOST`",
                    args.project.display()
                ),
            ));
        }
        args.project = args.project.canonicalize().map_err(|e| (code::ERROR, format!("project: {e}")))?;
        let cli = Cli { bin: args.brainproxy.clone(), project: args.project.clone(), env: opts.env.clone() };

        let eng = call(&cli, ["engagement", "show"]).await?;
        if !eng.ok() {
            return Err((eng.code, format!("engagement show: {}", eng.message())));
        }
        if eng.data()["engagement"].is_null() {
            return Err((
                code::OUT_OF_SCOPE,
                format!("project {} has no engagement scope; set it with `engagement start`", args.project.display()),
            ));
        }

        std::fs::create_dir_all(&args.out)
            .map_err(|e| (code::ERROR, format!("can't create {}: {e}", args.out.display())))?;
        let lock = lock(&args.out)?;

        // One scan per project at a time: a second one would overlap the first's time window.
        let jobs = call(&cli, ["job", "list", "--limit", NO_LIMIT]).await?;
        if !jobs.ok() {
            return Err((jobs.code, format!("job list: {}", jobs.message())));
        }
        let busy = |state: &Value| matches!(state.as_str(), Some("running" | "stopping" | "queued"));
        for j in jobs.data()["jobs"].as_array().into_iter().flatten().filter(|_| refuse_busy) {
            if j["kind"] != "active-scan" || !busy(&j["state"]) {
                continue;
            }
            // `job list` can still say running for a scan whose process died; `job status` checks.
            let id = j["id"].as_u64().unwrap_or(0);
            let status = call(&cli, ["job".into(), "status".into(), id.to_string()]).await?;
            if status.ok() && busy(&status.data()["state"]) {
                return Err((
                    code::USAGE,
                    format!(
                        "job {id} is still {} in this project; wait for it or `job stop {id}`",
                        status.data()["state"].as_str().unwrap_or("?")
                    ),
                ));
            }
        }

        let history = record::history(&args.out).map_err(|e| (code::ERROR, format!("reading the run history: {e}")))?;
        let run = Run {
            schema: record::SCHEMA,
            server_version: env!("CARGO_PKG_VERSION").to_string(),
            brainproxy_version: version,
            project: args.project.clone(),
            url: args.url.clone(),
            preset: args.preset.clone(),
            fail_on: args.fail_on.clone(),
            new_only: args.new_only,
            auth: args.auth.clone(),
            max_minutes: args.max_minutes,
            rate: args.rate,
            policy: if args.baseline { None } else { policy::fingerprint(&args.policy) },
            started_at: time::now(),
            finished_at: None,
            job: None,
            since_scan: None,
            coverage: None,
            coverage_baseline: None,
            summary: None,
            gate: None,
            outcome: Outcome::Running,
            reasons: vec![],
            exit_code: None,
            files: vec![],
            baseline: args.baseline,
            folder: None,
        };
        Ok(Ci { args, opts, cli, _lock: lock, run, history, cancelled: None, resumed: false })
    }

    /// Picks up a run whose `run.json` (in `opts.folder`) says its job started, after `serve` was
    /// restarted: [`Ci::finish`] then waits for that job instead of starting a scan. `Err` when the
    /// run can't be resumed; the caller then ends it as incomplete.
    pub async fn resume(args: Args, opts: Options) -> Result<Ci, Refusal> {
        let folder = opts.folder.clone().ok_or((code::ERROR, "no run folder to resume".to_string()))?;
        let text = std::fs::read_to_string(folder.join(record::RUN_FILE))
            .map_err(|e| (code::USAGE, format!("can't read {}: {e}", folder.join(record::RUN_FILE).display())))?;
        let run: Run = serde_json::from_str(&text).map_err(|e| (code::ERROR, format!("run.json: {e}")))?;
        if run.job.is_none() || run.outcome != Outcome::Running {
            return Err((code::USAGE, "the run's scan hadn't started".into()));
        }
        let mut ci = Ci::prepare(args, opts, false).await?;
        // The same job, not one with the same id in a project file replaced meanwhile.
        let job = run.job.clone().unwrap_or_default();
        let status = call(&ci.cli, ["job".into(), "status".into(), job.id.to_string()]).await?;
        if !status.ok() || status.data()["time"].as_str() != Some(job.time.as_str()) {
            return Err((code::USAGE, format!("job {} isn't the run's job any more", job.id)));
        }
        ci.run = Run { reasons: run.reasons.clone(), ..run };
        ci.run.reasons.push("the server restarted during the scan; it waited for the scan again".into());
        ci.resumed = true;
        Ok(ci)
    }

    /// Runs the scan and everything after it. Every path from here writes `run.json`.
    pub async fn finish(mut self, mut cancel: watch::Receiver<Option<&'static str>>) -> Finished {
        let folder = match self.scan(&mut cancel).await {
            Ok(folder) => folder,
            Err((outcome, code, reason)) => {
                self.run.reasons.push(reason);
                let folder = self.folder(None);
                return self.done(folder, outcome, code);
            }
        };
        let (outcome, code) = self.judge(&folder).await;
        self.done(folder, outcome, code)
    }

    /// Login check, scan, wait. Returns the run folder once the job has finished.
    async fn scan(&mut self, cancel: &mut watch::Receiver<Option<&'static str>>) -> Result<PathBuf, Stop> {
        let id = match &self.run.job {
            Some(job) if self.resumed => job.id,
            _ => self.start_scan(cancel).await?,
        };
        let folder = self.folder(Some(id));
        let status = self.wait(id, &folder, cancel).await;
        self.run.job = Some(job_from(id, status.data()));
        let result = &status.data()["result"];
        if let Some(n) = result["errors"].as_u64().filter(|n| *n > 0) {
            self.run.reasons.push(format!("{n} rule unit(s) of the scan failed; their checks may not have run"));
        }
        if result.is_object() {
            self.run.coverage = Some(Coverage {
                targets: result["targets"].as_u64().unwrap_or(0),
                endpoints: result["crawl"]["endpoints"].as_u64().unwrap_or(0),
                requests: result["requests"].as_u64().unwrap_or(0),
            });
        }
        Ok(folder)
    }

    /// Login check and `scan active --background`. Returns the job id once `run.json` records it.
    async fn start_scan(&mut self, cancel: &mut watch::Receiver<Option<&'static str>>) -> Result<u64, Stop> {
        self.pick_since_scan().await?;
        self.pick_coverage_baseline();
        if let Some(name) = self.args.auth.clone() {
            self.check_login(&name).await?;
        }
        if let Some(sig) = *cancel.borrow() {
            return Err((Outcome::Incomplete, code::USAGE, format!("cancelled by {sig} before the scan started")));
        }

        let mut argv: Vec<String> =
            ["scan", "active", &self.args.url, "--crawl", "--preset", &self.args.preset].map(String::from).to_vec();
        if let Some(m) = self.args.max_minutes {
            argv.extend(["--max-minutes".into(), m.to_string()]);
        }
        if let Some(r) = self.args.rate {
            argv.extend(["--rate".into(), r.to_string()]);
        }
        if let Some(a) = &self.args.auth {
            argv.extend(["--auth".into(), a.clone()]);
        }
        argv.push("--background".into());
        let started = call(&self.cli, &argv).await.map_err(stop_error)?;
        let Some(id) = started.data()["job"].as_u64().filter(|_| started.ok()) else {
            return Err((Outcome::Error, nonzero(started.code), format!("scan active: {}", started.message())));
        };

        let status = call(&self.cli, ["job".into(), "status".into(), id.to_string()]).await.map_err(stop_error)?;
        self.run.job = Some(job_from(id, status.data()));
        let folder = self.folder(Some(id));
        let _ = self.write(&folder);
        self.log(format!("job {id} started, run folder {}", folder.display()));
        Ok(id)
    }

    fn log(&self, line: String) {
        eprintln!("{}: {line}", self.opts.label.as_deref().unwrap_or("brainproxy-server"));
    }

    /// `job wait` in steps until the job is finished, stopping it on a cancel or when waiting keeps
    /// failing, so that a scan is never left running. Returns the last status.
    async fn wait(&mut self, id: u64, folder: &Path, cancel: &mut watch::Receiver<Option<&'static str>>) -> Output {
        let wait_argv = ["job".into(), "wait".into(), id.to_string(), "--timeout".into(), WAIT_STEP_SECS.to_string()];
        let mut failures = 0;
        loop {
            let out = tokio::select! {
                out = call(&self.cli, &wait_argv) => out,
                _ = cancel.changed() => return self.cancel(id, folder, cancel).await,
            };
            let failed = match out {
                Ok(out) if out.ok() => {
                    if is_finished(out.data()["state"].as_str().unwrap_or("")) {
                        return out;
                    }
                    failures = 0;
                    self.log(format!(
                        "job {id} {}: {}",
                        out.data()["state"].as_str().unwrap_or("?"),
                        compact(&out.data()["progress"])
                    ));
                    continue;
                }
                Ok(out) => out.message(),
                Err((_, e)) => e,
            };
            if cancel.borrow().is_some() {
                return self.cancel(id, folder, cancel).await;
            }
            failures += 1;
            self.log(format!("job wait {id} failed ({failures}/{WAIT_RETRIES}): {failed}"));
            if failures >= WAIT_RETRIES {
                self.run.reasons.push(format!("job wait {id} kept failing ({failed}); the job was asked to stop"));
                let _ = call(&self.cli, ["job".into(), "stop".into(), id.to_string()]).await;
                return self.status(id).await;
            }
            tokio::select! {
                _ = tokio::time::sleep(std::time::Duration::from_secs(2)) => {}
                _ = cancel.changed() => return self.cancel(id, folder, cancel).await,
            }
        }
    }

    /// Stops the job after a signal and writes `run.json` as incomplete straight away, in case the
    /// runner kills this process before the compare and the reports are done. A second signal cuts
    /// the wait for the job short.
    async fn cancel(&mut self, id: u64, folder: &Path, cancel: &mut watch::Receiver<Option<&'static str>>) -> Output {
        let sig = cancel.borrow_and_update().unwrap_or("a signal");
        self.cancelled = Some(sig);
        self.log(format!("{sig}: stopping job {id}"));
        self.run.reasons.push(format!("cancelled by {sig}; job {id} was asked to stop"));
        let _ = call(&self.cli, ["job".into(), "stop".into(), id.to_string()]).await;
        self.run.outcome = Outcome::Incomplete;
        self.run.exit_code = Some(code::USAGE);
        let _ = self.write(folder);
        let grace = ["job".into(), "wait".into(), id.to_string(), "--timeout".into(), STOP_GRACE_SECS.to_string()];
        tokio::select! {
            _ = call(&self.cli, &grace) => {}
            _ = cancel.changed() => {}
        }
        self.status(id).await
    }

    async fn status(&self, id: u64) -> Output {
        match call(&self.cli, ["job".into(), "status".into(), id.to_string()]).await {
            Ok(out) => out,
            Err(e) => io_output(e),
        }
    }

    /// Applies the outcome rules, then compares, gates and writes the reports.
    async fn judge(&mut self, folder: &Path) -> (Outcome, i32) {
        let job = self.run.job.clone().unwrap_or_default();
        // A cancelled run never passes, even if its job completed before the stop reached it.
        let mut complete = self.cancelled.is_none();
        if job.state != "completed" {
            complete = false;
            let why = if self.cancelled.is_some() { String::new() } else { self.job_error(job.id).await };
            self.run.reasons.push(format!(
                "job {} {}{why}",
                job.id,
                if job.state.is_empty() { "unknown" } else { &job.state }
            ));
        }
        if job.timed_out {
            complete = false;
            self.run.reasons.push(format!("the scan ran out of --max-minutes {}", self.args.max_minutes.unwrap_or(0)));
        }
        if job.crawl_timed_out {
            complete = false;
            self.run.reasons.push("the crawl was cut short".into());
        }
        if complete
            && let (Some(now), Some(base)) = (&self.run.coverage, &self.run.coverage_baseline)
            && let Some(drop) = record::coverage_drop(now, &base.coverage)
        {
            let reason = format!("coverage dropped below half of job {}: {drop}", base.job);
            if self.args.accept_coverage_drop {
                self.run.reasons.push(format!("{reason} (accepted with --accept-coverage-drop)"));
            } else {
                complete = false;
                self.run.reasons.push(format!(
                    "{reason}; a broken login or an unreachable app would look like everything was fixed. \
                     If the app really shrank, run again with --accept-coverage-drop"
                ));
            }
        }

        let mut outcome = if complete { Outcome::Passed } else { Outcome::Incomplete };
        let mut exit = if complete { code::OK } else { code::USAGE };

        // Compare. A run that didn't complete is still compared, without the gate, so its drift is kept.
        let mut argv = vec!["findings".to_string(), "compare".into(), "--scan".into(), job.id.to_string()];
        if let Some(p) = &self.run.since_scan {
            argv.extend(["--since-scan".into(), p.job.to_string()]);
        }
        argv.extend(["--limit".into(), NO_LIMIT.into()]);
        // With an alert policy the gate is worked out here from the compare output, so the CLI
        // doesn't gate.
        let local_gate = complete && !self.args.baseline && !self.args.policy.is_empty();
        if complete
            && !local_gate
            && let Some(risk) = &self.args.fail_on
        {
            argv.extend(["--fail-on".into(), risk.clone()]);
            if self.args.new_only {
                argv.push("--new-only".into());
            }
        }
        match call(&self.cli, &argv).await {
            Ok(cmp) => {
                let saved = cmp.stdout.trim().is_empty() || self.save(folder, "compare.json", cmp.stdout.as_bytes());
                if !saved && outcome == Outcome::Passed {
                    (outcome, exit) = (Outcome::Error, code::ERROR);
                }
                let d = cmp.data();
                if cmp.json["ok"] == true {
                    let s = &d["summary"];
                    self.run.summary = Some(Summary {
                        new: s["new"].as_u64().unwrap_or(0),
                        unchanged: s["unchanged"].as_u64().unwrap_or(0),
                        fixed: s["fixed"].as_u64().unwrap_or(0),
                    });
                    if local_gate {
                        if s["truncated"] == true {
                            self.run
                                .reasons
                                .push("compare: the finding lists were cut off; the policy gate is incomplete".into());
                        }
                        let gate = policy::gate(d, self.args.fail_on.as_deref(), self.args.new_only, &self.args.policy);
                        if let Some(p) = &gate.policy {
                            if p.ignored + p.warned > 0 {
                                self.run
                                    .reasons
                                    .push(format!("policy: {} finding(s) ignored, {} warned", p.ignored, p.warned));
                            }
                            for w in &p.warnings {
                                self.run.reasons.push(format!("policy warning: {w}"));
                            }
                        }
                        self.run.gate = Some(gate);
                    } else if d["gate"].is_object() {
                        self.run.gate = Some(Gate {
                            fail_on: d["gate"]["fail_on"].as_str().unwrap_or_default().to_string(),
                            new_only: d["gate"]["new_only"].as_bool().unwrap_or(false),
                            passed: d["gate"]["passed"].as_bool().unwrap_or(false),
                            count: d["gate"]["count"].as_u64().unwrap_or(0),
                            policy: None,
                        });
                    }
                    for w in d["warnings"].as_array().into_iter().flatten().filter_map(Value::as_str) {
                        self.run.reasons.push(format!("compare: {w}"));
                    }
                }
                // Exit 0 only counts with a complete envelope and, when gating, a gate that passed.
                let gated = complete && (self.args.fail_on.is_some() || local_gate);
                let gate_passed = self.run.gate.as_ref().is_some_and(|g| g.passed);
                // The policy gate turns the CLI's pass into a gate failure here.
                let code = if local_gate && cmp.code == code::OK && cmp.json["ok"] == true && !gate_passed {
                    code::GATE_FAILED
                } else {
                    cmp.code
                };
                match code {
                    code::OK if cmp.json["ok"] == true && (!gated || gate_passed) => {}
                    code::GATE_FAILED if complete && cmp.json["ok"] == true => {
                        outcome = Outcome::Failed;
                        exit = code::GATE_FAILED;
                        let count = self.run.gate.as_ref().map_or(0, |g| g.count);
                        let threshold = match (&self.args.fail_on, local_gate) {
                            (Some(r), false) => format!("at or above {r}"),
                            (Some(r), true) => format!("at or above {r} or failed by the alert policy"),
                            (None, _) => "failed by the alert policy".into(),
                        };
                        self.run.reasons.push(format!(
                            "the gate failed: {count} {}finding(s) {threshold}",
                            if self.args.new_only { "new " } else { "" },
                        ));
                    }
                    c => {
                        let message = if c == code::OK {
                            "exited 0 without a complete result or a passed gate".to_string()
                        } else {
                            cmp.message()
                        };
                        self.run.reasons.push(format!("findings compare: {message}"));
                        if outcome != Outcome::Incomplete {
                            outcome = Outcome::Error;
                            exit = nonzero(c);
                        }
                    }
                }
            }
            Err((_, e)) => {
                self.run.reasons.push(format!("findings compare: {e}"));
                if outcome != Outcome::Incomplete {
                    (outcome, exit) = (Outcome::Error, code::ERROR);
                }
            }
        }

        // Reports: only what this job found. Written for every finished job, also an incomplete one.
        for (kind, file) in [("json", "report.json"), ("html", "report.html"), ("sarif", "report.sarif")] {
            let path = folder.join(file);
            let argv = [
                "report".into(),
                kind.into(),
                "--scan".into(),
                job.id.to_string(),
                "--limit".into(),
                NO_LIMIT.into(),
                "--force".into(),
                "--output".into(),
                path.to_string_lossy().into_owned(),
            ];
            let (ok, c, message) = match call(&self.cli, &argv).await {
                Ok(r) => (r.ok(), r.code, r.message()),
                Err((c, e)) => (false, c, e),
            };
            if ok {
                self.run.files.push(file.into());
            } else {
                self.run.reasons.push(format!("report {kind}: {message}"));
                if outcome == Outcome::Passed {
                    (outcome, exit) = (Outcome::Error, nonzero(c));
                }
            }
        }
        (outcome, exit)
    }

    /// The newest passed run whose job is still the same job in this project.
    async fn pick_since_scan(&mut self) -> Result<(), Stop> {
        let candidates: Vec<record::Past> = record::since_scan_candidates(&self.history, &self.run).cloned().collect();
        for past in candidates {
            let Some(job) = &past.run.job else { continue };
            let status =
                call(&self.cli, ["job".into(), "status".into(), job.id.to_string()]).await.map_err(stop_error)?;
            let d = status.data();
            if status.ok() && d["time"].as_str() == Some(job.time.as_str()) && d["state"] == "completed" {
                self.run.since_scan = Some(JobRef { job: job.id, time: job.time.clone() });
                return Ok(());
            }
            let name = past.dir.file_name().unwrap_or_default().to_string_lossy();
            self.run.reasons.push(format!("run {name}: job {} isn't in this project any more; skipped", job.id));
        }
        Ok(())
    }

    fn pick_coverage_baseline(&mut self) {
        let base = record::coverage_candidates(&self.history, &self.args.url, &self.args.preset).next();
        self.run.coverage_baseline =
            base.and_then(|p| Some(CoverageBaseline { job: p.run.job.as_ref()?.id, coverage: p.run.coverage? }));
    }

    /// Logs in (when the profile has a login) and checks the session. A broken login is incomplete.
    async fn check_login(&mut self, name: &str) -> Result<(), Stop> {
        let offline = call(&self.cli, ["auth", "status", name, "--offline"]).await.map_err(stop_error)?;
        if !offline.ok() {
            return Err((Outcome::Error, nonzero(offline.code), format!("auth status {name}: {}", offline.message())));
        }
        if offline.data()["has_login"] == true {
            let login = call(&self.cli, ["auth", "login", name]).await.map_err(stop_error)?;
            if !login.ok() {
                return Err((Outcome::Incomplete, code::USAGE, format!("login {name} failed: {}", login.message())));
            }
        }
        let status = call(&self.cli, ["auth", "status", name]).await.map_err(stop_error)?;
        if !status.ok() {
            return Err((Outcome::Incomplete, code::USAGE, format!("auth status {name}: {}", status.message())));
        }
        let d = status.data();
        let logged_in = if d["check"].is_object() {
            d["check"]["logged_in"] == true
        } else if d["has_login"] == true {
            d["session"]["logged_in"] == true
        } else {
            self.run.reasons.push(format!("auth {name} has no login and no check URL; its session wasn't checked"));
            true
        };
        if !logged_in {
            return Err((
                Outcome::Incomplete,
                code::USAGE,
                format!(
                    "auth {name}: the session isn't logged in after logging in; a scan would miss what needs a login"
                ),
            ));
        }
        Ok(())
    }

    /// The job's `error`, for a reason line.
    async fn job_error(&self, id: u64) -> String {
        match call(&self.cli, ["job".into(), "status".into(), id.to_string()]).await {
            Ok(s) => s.data()["error"].as_str().map(|e| format!(": {e}")).unwrap_or_default(),
            Err(_) => String::new(),
        }
    }

    /// `DIR/<time>-<job>/` (or the fixed folder), created. A second run without a job in the same
    /// second gets a suffix.
    fn folder(&self, job: Option<u64>) -> PathBuf {
        if let Some(path) = &self.opts.folder {
            if let Err(e) = std::fs::create_dir_all(path) {
                self.log(format!("can't create {}: {e}", path.display()));
            }
            return path.clone();
        }
        let start = match self.run.job.as_ref() {
            Some(j) if !j.time.is_empty() => j.time.as_str(),
            _ => self.run.started_at.as_str(),
        };
        let base = record::folder_name(start, job);
        let mut path = self.args.out.join(&base);
        let mut n = 1;
        while job.is_none() && path.exists() {
            n += 1;
            path = self.args.out.join(format!("{base}.{n}"));
        }
        if let Err(e) = std::fs::create_dir_all(&path) {
            self.log(format!("can't create {}: {e}", path.display()));
        }
        path
    }

    fn done(mut self, folder: PathBuf, outcome: Outcome, exit: i32) -> Finished {
        self.run.outcome = outcome;
        self.run.exit_code = Some(exit);
        self.run.finished_at = Some(time::now());
        self.run.folder = Some(folder.clone());
        let mut exit = exit;
        if !self.write(&folder) && exit == code::OK {
            // A pass that can't be recorded would drop out of the history; don't call it one.
            self.run.outcome = Outcome::Error;
            self.run.exit_code = Some(code::ERROR);
            exit = code::ERROR;
        }
        self.log(summary_line(&self.run, &folder));
        for r in &self.run.reasons {
            eprintln!("  - {r}");
        }
        Finished { run: self.run, exit }
    }

    /// Writes `run.json` (through a temporary file, so a reader never sees half of it).
    fn write(&mut self, folder: &Path) -> bool {
        let text = serde_json::to_vec_pretty(&self.run).unwrap_or_default();
        let tmp = folder.join(".run.json.tmp");
        match std::fs::write(&tmp, &text).and_then(|_| std::fs::rename(&tmp, folder.join(record::RUN_FILE))) {
            Ok(()) => {
                if let Some(f) = &self.opts.on_write {
                    f(&self.run);
                }
                true
            }
            Err(e) => {
                self.log(format!("can't write {}: {e}", folder.join(record::RUN_FILE).display()));
                false
            }
        }
    }

    fn save(&mut self, folder: &Path, name: &str, bytes: &[u8]) -> bool {
        match std::fs::write(folder.join(name), bytes) {
            Ok(()) => {
                self.run.files.push(name.into());
                true
            }
            Err(e) => {
                self.run.reasons.push(format!("can't write {name}: {e}"));
                false
            }
        }
    }
}

/// Why a run stopped before it got to the compare step.
type Stop = (Outcome, i32, String);

fn stop_error((code, message): Refusal) -> Stop {
    (Outcome::Error, code, message)
}

async fn call<I, S>(cli: &Cli, args: I) -> Result<Output, Refusal>
where
    I: IntoIterator<Item = S>,
    S: Into<OsString>,
{
    cli.run(args).await.map_err(|e| (code::ERROR, format!("can't run {}: {e}", cli.bin.display())))
}

fn io_output(e: Refusal) -> Output {
    Output { code: e.0, json: Value::Null, stdout: String::new(), stderr: e.1 }
}

/// A failed CLI call never turns into a pass, even if it exited 0 with `ok: false`.
fn nonzero(c: i32) -> i32 {
    if c == code::OK { code::ERROR } else { c }
}

fn is_finished(state: &str) -> bool {
    matches!(state, "completed" | "failed" | "stopped")
}

fn job_from(id: u64, d: &Value) -> Job {
    Job {
        id,
        time: d["time"].as_str().unwrap_or_default().to_string(),
        finished_time: d["finished_time"].as_str().map(String::from),
        state: d["state"].as_str().unwrap_or_default().to_string(),
        timed_out: d["result"]["timed_out"] == true,
        crawl_timed_out: d["result"]["crawl"]["timed_out"] == true,
    }
}

fn compact(v: &Value) -> String {
    match v.as_object() {
        Some(m) => m.iter().map(|(k, v)| format!("{k} {v}")).collect::<Vec<_>>().join(", "),
        None => v.to_string(),
    }
}

fn summary_line(run: &Run, folder: &Path) -> String {
    let outcome = match run.outcome {
        Outcome::Passed => "passed",
        Outcome::Failed => "gate failed",
        Outcome::Incomplete => "incomplete",
        Outcome::Error => "error",
        Outcome::Running => "running",
    };
    let mut line = outcome.to_string();
    if let Some(j) = &run.job {
        line.push_str(&format!(" (job {}", j.id));
        if let Some(p) = &run.since_scan {
            line.push_str(&format!(", new since job {}", p.job));
        }
        line.push(')');
    }
    if let Some(s) = &run.summary {
        line.push_str(&format!(": {} new, {} unchanged, {} fixed", s.new, s.unchanged, s.fixed));
    }
    format!("{line} → {}", folder.display())
}

/// Takes the run folder's lock, so two runs never share a history.
fn lock(out: &Path) -> Result<File, Refusal> {
    let path = out.join(LOCK_FILE);
    let file = File::options()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&path)
        .map_err(|e| (code::ERROR, format!("can't open {}: {e}", path.display())))?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(TryLockError::WouldBlock) => {
            Err((code::USAGE, format!("another run is using {}; one run per folder at a time", out.display())))
        }
        Err(TryLockError::Error(e)) => Err((code::ERROR, format!("can't lock {}: {e}", path.display()))),
    }
}

/// Becomes `Some(signal name)` on SIGINT or SIGTERM (Ctrl-C elsewhere), and changes again on every
/// further signal. A CI cancel sends these; the scan job is then stopped and the run ends as incomplete.
fn cancel_signal() -> watch::Receiver<Option<&'static str>> {
    let (tx, rx) = watch::channel(None);
    tokio::spawn(async move {
        loop {
            let name = wait_signal().await;
            if tx.send(Some(name)).is_err() {
                return;
            }
        }
    });
    rx
}

#[cfg(unix)]
async fn wait_signal() -> &'static str {
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
async fn wait_signal() -> &'static str {
    match tokio::signal::ctrl_c().await {
        Ok(()) => "Ctrl-C",
        Err(_) => std::future::pending().await,
    }
}
