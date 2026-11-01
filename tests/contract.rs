//! Contract tests: `brainproxy-server ci` against the real brainproxy CLI and a small local web app.
//!
//! The CLI comes from `BRAINPROXY_BIN`, or `brainproxy` on PATH. Without one the tests are skipped,
//! unless `BRAINPROXY_CONTRACT=1` is set (CI sets it), when a missing CLI fails them.

use std::path::PathBuf;
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use serde_json::Value;

mod common;
use common::{App, cli};

// ---------------------------------------------------------------------------------------------
// The CLI

/// A project and run folder in a temporary directory, with its own brainproxy home.
struct Env {
    bin: PathBuf,
    dir: tempfile::TempDir,
}

impl Env {
    fn new() -> Option<Env> {
        Some(Env { bin: cli()?, dir: tempfile::tempdir().unwrap() })
    }

    fn project(&self) -> PathBuf {
        self.dir.path().join("app.bpdb")
    }

    fn out(&self) -> PathBuf {
        self.dir.path().join("runs")
    }

    fn brainproxy(&self, args: &[&str]) -> Value {
        let out = Command::new(&self.bin)
            .arg("--project")
            .arg(self.project())
            .args(["--format", "json"])
            .args(args)
            .env("BRAINPROXY_HOME", self.dir.path().join("home"))
            .output()
            .unwrap();
        serde_json::from_slice(&out.stdout).unwrap_or(Value::Null)
    }

    fn engage(&self, app: &App) {
        let r = self.brainproxy(&["engagement", "start", "--target", &app.host(), "--name", "contract"]);
        assert_eq!(r["ok"], true, "{r}");
    }

    fn ci_command(&self, url: &str, extra: &[&str]) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_brainproxy-server"));
        cmd.arg("ci")
            .arg("--project")
            .arg(self.project())
            .arg("--out")
            .arg(self.out())
            .args(["--url", url, "--preset", "quick"])
            .args(extra)
            .env("BRAINPROXY_BIN", &self.bin)
            .env("BRAINPROXY_HOME", self.dir.path().join("home"));
        cmd
    }

    /// Runs `ci` and returns its exit code and the `run.json` it printed.
    fn ci(&self, url: &str, extra: &[&str]) -> (i32, Value) {
        let out = self.ci_command(url, extra).output().unwrap();
        result(out)
    }

    fn runs(&self) -> Vec<PathBuf> {
        let mut v: Vec<PathBuf> = std::fs::read_dir(self.out())
            .map(|d| d.map(|e| e.unwrap().path()).filter(|p| p.is_dir()).collect())
            .unwrap_or_default();
        v.sort();
        v
    }
}

fn result(out: Output) -> (i32, Value) {
    let stderr = String::from_utf8_lossy(&out.stderr);
    eprintln!("{stderr}");
    let run = serde_json::from_slice(&out.stdout).unwrap_or(Value::Null);
    (out.status.code().unwrap_or(-1), run)
}

fn job(run: &Value) -> u64 {
    run["job"]["id"].as_u64().unwrap_or_else(|| panic!("no job in {run}"))
}

fn compare(run_dir: &std::path::Path) -> Value {
    serde_json::from_str(&std::fs::read_to_string(run_dir.join("compare.json")).unwrap()).unwrap()
}

fn alert_refs(group: &Value) -> Vec<String> {
    group.as_array().unwrap().iter().map(|f| f["alert_ref"].as_str().unwrap().to_string()).collect()
}

// ---------------------------------------------------------------------------------------------
// The CLI contract the server relies on

#[test]
fn cli_has_the_flags_ci_relies_on() {
    let Some(env) = Env::new() else { return };
    let caps = env.brainproxy(&["capabilities"]);
    assert_eq!(caps["ok"], true);
    let flags = |cmd: &[&str]| -> Vec<String> {
        let mut args = vec!["capabilities"];
        args.extend(cmd);
        let c = env.brainproxy(&args);
        c["data"]["args"].as_array().unwrap().iter().filter_map(|a| a["flag"].as_str().map(String::from)).collect()
    };
    let has = |cmd: &[&str], want: &[&str]| {
        let got = flags(cmd);
        for w in want {
            assert!(got.iter().any(|g| g == w), "{cmd:?} has no {w}: {got:?}");
        }
    };
    has(&["scan", "active"], &["--crawl", "--preset", "--background", "--max-minutes", "--auth"]);
    has(&["findings", "compare"], &["--scan", "--since-scan", "--fail-on", "--new-only", "--limit"]);
    has(&["report"], &["--scan", "--output", "--force", "--limit"]);
    has(&["job", "wait"], &["--timeout"]);
    has(&["auth", "status"], &["--offline"]);
    let codes = &caps["data"]["exit_codes"];
    for c in ["0", "1", "2", "3", "4", "5", "6"] {
        assert!(codes[c].is_string(), "exit code {c} isn't described: {codes}");
    }
}

// ---------------------------------------------------------------------------------------------
// ci

#[test]
fn refuses_a_missing_project_or_engagement() {
    let Some(env) = Env::new() else { return };
    let (code, _) = env.ci("http://127.0.0.1:9/", &[]);
    assert_eq!(code, 4);
    assert!(!env.project().exists(), "ci created the project");

    env.brainproxy(&["project", "info"]);
    let (code, _) = env.ci("http://127.0.0.1:9/", &[]);
    assert_eq!(code, 6);
    assert!(env.runs().is_empty());
}

#[test]
fn out_of_scope_url_is_the_clis_exit_6() {
    let Some(env) = Env::new() else { return };
    let app = App::start(1);
    env.engage(&app);
    let (code, run) = env.ci("http://127.0.0.2:9/", &[]);
    assert_eq!(code, 6, "{run}");
    assert_eq!(run["outcome"], "error");
    assert!(run["job"].is_null());
}

#[test]
fn drift_gate_and_new_until_a_run_passes() {
    let Some(env) = Env::new() else { return };
    let app = App::start(2);
    env.engage(&app);
    let url = app.url();
    let gate = ["--fail-on", "high", "--new-only"];

    // 1: the baseline run, no gate: passed; the XSS is new.
    let (code, r1) = env.ci(&url, &["--baseline"]);
    assert_eq!(code, 0, "{r1}");
    assert_eq!(r1["outcome"], "passed");
    assert!(r1["since_scan"].is_null());
    assert!(r1["summary"]["new"].as_u64().unwrap() > 0);
    let dir1 = &env.runs()[0];
    assert!(dir1.file_name().unwrap().to_string_lossy().ends_with(&format!("-{}", job(&r1))));
    for f in ["run.json", "compare.json", "report.json", "report.html", "report.sarif"] {
        assert!(dir1.join(f).is_file(), "{f} missing");
    }
    let c1 = compare(dir1);
    assert!(alert_refs(&c1["data"]["new"]).iter().any(|a| a.starts_with("40012")), "no XSS in {}", c1["data"]["new"]);

    // 2: a SQL error appears: new since run 1, the gate fails; the XSS is unchanged.
    app.state.drift.store(true, Ordering::SeqCst);
    let (code, r2) = env.ci(&url, &gate);
    assert_eq!(code, 5, "{r2}");
    assert_eq!(r2["outcome"], "failed");
    assert_eq!(r2["since_scan"]["job"], r1["job"]["id"]);
    let dir2 = env.runs().last().unwrap().clone();
    let c2 = compare(&dir2);
    assert_eq!(c2["data"]["baseline"]["since_scan"]["job"], r1["job"]["id"]);
    assert!(alert_refs(&c2["data"]["new"]).iter().any(|a| a.starts_with("40018")), "no SQLi in {}", c2["data"]["new"]);
    assert!(alert_refs(&c2["data"]["unchanged"]).iter().any(|a| a.starts_with("40012")));
    let report: Value = serde_json::from_str(&std::fs::read_to_string(dir2.join("report.json")).unwrap()).unwrap();
    assert!(report.is_object());

    // 3: the same again: run 2 didn't pass, so it isn't the since-scan job and the SQL error is still new.
    let (code, r3) = env.ci(&url, &gate);
    assert_eq!(code, 5, "{r3}");
    assert_eq!(r3["since_scan"]["job"], r1["job"]["id"]);

    // 4: the SQL error is gone: passes, and it shows as fixed.
    app.state.drift.store(false, Ordering::SeqCst);
    let (code, r4) = env.ci(&url, &gate);
    assert_eq!(code, 0, "{r4}");
    let c4 = compare(env.runs().last().unwrap());
    assert!(alert_refs(&c4["data"]["fixed"]).iter().any(|a| a.starts_with("40018")), "SQLi not fixed: {}", c4["data"]);
    assert_eq!(c4["data"]["gate"]["count"], 0);
    eprintln!("run 4 new: {}", c4["data"]["new"]);

    // 5: back to back: nothing new since run 4.
    let (code, r5) = env.ci(&url, &gate);
    assert_eq!(code, 0, "{r5}");
    assert_eq!(r5["since_scan"]["job"], r4["job"]["id"]);
    assert_eq!(r5["summary"]["new"], 0);
}

#[test]
fn coverage_drop_is_incomplete_unless_accepted() {
    let Some(env) = Env::new() else { return };
    let app = App::start(30);
    env.engage(&app);
    let url = app.url();
    let (code, r1) = env.ci(&url, &[]);
    assert_eq!(code, 0, "{r1}");

    app.state.pages.store(0, Ordering::SeqCst);
    let (code, r2) = env.ci(&url, &["--fail-on", "high"]);
    assert_eq!(code, 2, "{r2}");
    assert_eq!(r2["outcome"], "incomplete");
    assert_eq!(r2["coverage_baseline"]["job"], r1["job"]["id"]);
    assert!(r2["reasons"].to_string().contains("coverage dropped"), "{r2}");
    assert!(r2["gate"].is_null(), "an incomplete run was gated");

    // The baseline is still run 1, so the next run is incomplete too, until the drop is accepted.
    let (code, _) = env.ci(&url, &[]);
    assert_eq!(code, 2);
    let (code, r4) = env.ci(&url, &["--accept-coverage-drop"]);
    assert_eq!(code, 0, "{r4}");
    let (code, _) = env.ci(&url, &[]);
    assert_eq!(code, 0, "the accepted run is the new baseline");
}

#[test]
fn a_killed_scan_is_incomplete() {
    let Some(env) = Env::new() else { return };
    let app = App::start(20);
    app.state.delay_ms.store(150, Ordering::SeqCst);
    env.engage(&app);
    let child = env
        .ci_command(&app.url(), &["--fail-on", "high"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let pid = wait_for_running_job(&env);
    kill(pid, "-KILL");
    let (code, run) = result(child.wait_with_output().unwrap());
    assert_eq!(code, 2, "{run}");
    assert_eq!(run["outcome"], "incomplete");
    assert_eq!(run["job"]["state"], "failed");
    assert!(run["gate"].is_null());
}

#[test]
fn a_cancelled_run_stops_its_scan() {
    let Some(env) = Env::new() else { return };
    let app = App::start(20);
    app.state.delay_ms.store(150, Ordering::SeqCst);
    env.engage(&app);
    let child: Child = env.ci_command(&app.url(), &[]).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    wait_for_running_job(&env);
    kill(child.id(), "-TERM");
    let (code, run) = result(child.wait_with_output().unwrap());
    assert_eq!(code, 2, "{run}");
    assert_eq!(run["outcome"], "incomplete");
    assert!(run["reasons"].to_string().contains("SIGTERM"), "{run}");
    let jobs = env.brainproxy(&["job", "list"]);
    let state = jobs["data"]["jobs"][0]["state"].as_str().unwrap().to_string();
    assert!(state == "stopped" || state == "completed", "job left {state}");

    // A later run doesn't use the cancelled one as its since-scan job.
    app.state.delay_ms.store(0, Ordering::SeqCst);
    let (code, r2) = env.ci(&app.url(), &[]);
    assert_eq!(code, 0, "{r2}");
    assert!(r2["since_scan"].is_null());
}

#[test]
fn a_broken_login_is_incomplete_and_nothing_is_scanned() {
    let Some(env) = Env::new() else { return };
    let app = App::start(1);
    env.engage(&app);
    let base = app.url();
    let r = env.brainproxy(&[
        "auth",
        "add",
        "user",
        "--login-url",
        &format!("{base}login"),
        "--login-method",
        "POST",
        "--login-body",
        "username={{username}}&password={{password}}",
        "--login-header",
        "Content-Type: application/x-www-form-urlencoded",
        "--username",
        "ci",
        "--password-env",
        "APP_PW",
        "--check-url",
        &format!("{base}me"),
        "--logged-in",
        "logged in as ci",
    ]);
    assert_eq!(r["ok"], true, "{r}");

    let mut cmd = env.ci_command(&base, &["--auth", "user"]);
    let (code, run) = result(cmd.env("APP_PW", "wrong").output().unwrap());
    assert_eq!(code, 2, "{run}");
    assert_eq!(run["outcome"], "incomplete");
    assert!(run["job"].is_null(), "scanned with a broken login");

    let mut cmd = env.ci_command(&base, &["--auth", "user"]);
    let (code, run) = result(cmd.env("APP_PW", "right").output().unwrap());
    assert_eq!(code, 0, "{run}");
    assert_eq!(run["auth"], "user");

    let (code, _) = env.ci(&base, &["--auth", "nobody"]);
    assert_eq!(code, 4);
}

#[test]
fn one_run_per_folder() {
    let Some(env) = Env::new() else { return };
    let app = App::start(20);
    app.state.delay_ms.store(150, Ordering::SeqCst);
    env.engage(&app);
    let first = env.ci_command(&app.url(), &[]).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    wait_for_running_job(&env);
    let (code, _) = env.ci(&app.url(), &[]);
    assert_eq!(code, 2, "a second run in the same folder wasn't refused");
    kill(first.id(), "-TERM");
    first.wait_with_output().unwrap();
}

/// Waits until the project has a running scan job and returns its pid.
fn wait_for_running_job(env: &Env) -> u32 {
    let start = Instant::now();
    loop {
        let jobs = env.brainproxy(&["job", "list"]);
        if let Some(j) = jobs["data"]["jobs"].as_array().into_iter().flatten().find(|j| j["state"] == "running") {
            std::thread::sleep(Duration::from_secs(2));
            return j["pid"].as_u64().unwrap() as u32;
        }
        assert!(start.elapsed() < Duration::from_secs(60), "no scan job started");
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn kill(pid: u32, signal: &str) {
    let ok = Command::new("kill").arg(signal).arg(pid.to_string()).status().unwrap().success();
    assert!(ok, "kill {signal} {pid}");
}

#[test]
fn a_live_scan_in_the_project_is_refused_and_a_dead_one_is_not() {
    let Some(env) = Env::new() else { return };
    let app = App::start(20);
    app.state.delay_ms.store(150, Ordering::SeqCst);
    env.engage(&app);
    let r = env.brainproxy(&["scan", "active", &app.url(), "--crawl", "--preset", "quick", "--background"]);
    assert_eq!(r["ok"], true, "{r}");
    let pid = wait_for_running_job(&env);
    let (code, _) = env.ci(&app.url(), &[]);
    assert_eq!(code, 2, "ran beside a live scan");

    kill(pid, "-KILL");
    std::thread::sleep(Duration::from_millis(300));
    app.state.delay_ms.store(0, Ordering::SeqCst);
    let (code, run) = env.ci(&app.url(), &[]);
    assert_eq!(code, 0, "refused because of a dead scan: {run}");
}

/// A CLI wrapper whose `findings compare` exits 0 without an envelope must not make a pass.
#[test]
fn a_compare_that_exits_0_without_a_result_is_not_a_pass() {
    let Some(env) = Env::new() else { return };
    let app = App::start(1);
    env.engage(&app);
    let wrapper = env.dir.path().join("brainproxy-wrapper");
    std::fs::write(
        &wrapper,
        format!(
            "#!/bin/sh\nfor a in \"$@\"; do [ \"$a\" = compare ] && {{ echo 'not json'; exit 0; }}; done\nexec '{}' \"$@\"\n",
            env.bin.display()
        ),
    )
    .unwrap();
    Command::new("chmod").arg("+x").arg(&wrapper).status().unwrap();
    let mut cmd = env.ci_command(&app.url(), &["--fail-on", "high"]);
    let (code, run) = result(cmd.env("BRAINPROXY_BIN", &wrapper).output().unwrap());
    assert_eq!(code, 1, "{run}");
    assert_eq!(run["outcome"], "error");
}

/// Ctrl-C reaches the whole process group; the scan must still be stopped, not left running.
#[test]
fn ctrl_c_to_the_process_group_stops_the_scan() {
    let Some(env) = Env::new() else { return };
    let app = App::start(20);
    app.state.delay_ms.store(150, Ordering::SeqCst);
    env.engage(&app);
    let mut cmd = env.ci_command(&app.url(), &[]);
    std::os::unix::process::CommandExt::process_group(&mut cmd, 0);
    let child = cmd.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    wait_for_running_job(&env);
    let group = format!("-{}", child.id());
    let ok = Command::new("kill").args(["-INT", "--", &group]).status().unwrap().success();
    assert!(ok);
    let (code, run) = result(child.wait_with_output().unwrap());
    assert_eq!(code, 2, "{run}");
    assert!(run["reasons"].to_string().contains("SIGINT"), "{run}");
    let jobs = env.brainproxy(&["job", "list"]);
    let state = jobs["data"]["jobs"][0]["state"].as_str().unwrap().to_string();
    assert!(state == "stopped" || state == "stopping", "job left {state}");
    assert!(!run["folder"].is_null());
}
