//! Stateless `ci --target` against the real brainproxy CLI (0.5.2: `findings mark --from`) and the
//! small local web app: a fresh project per run, the known findings carried between runs in the
//! state folder each run writes, and the refusals of a state that can't be trusted.
//!
//! The CLI comes from `BRAINPROXY_BIN`, or `brainproxy` on PATH (see `common::cli`).

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::Ordering;
use std::sync::mpsc;

use serde_json::{Value, json};

mod common;
use common::{App, cli};

struct Env {
    bin: PathBuf,
    dir: tempfile::TempDir,
}

impl Env {
    fn new() -> Option<Env> {
        let env = Env { bin: cli()?, dir: tempfile::tempdir().unwrap() };
        std::fs::create_dir_all(env.tmp()).unwrap();
        env.targets(&["app"]);
        Some(env)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    /// TMPDIR of the `ci` process: its temp folders must be gone after every run.
    fn tmp(&self) -> PathBuf {
        self.path("tmp")
    }

    fn targets(&self, ids: &[&str]) {
        std::fs::write(self.path("targets.json"), json!({ "targets": ids }).to_string()).unwrap();
    }

    fn target(&self, t: Value) {
        std::fs::write(self.path("target.json"), t.to_string()).unwrap();
    }

    /// Runs `ci` with `state` as `--state` and returns its exit code, `run.json` and run folder.
    fn ci(&self, state: &Path, extra: &[&str]) -> (i32, Value, PathBuf) {
        self.ci_env(state, extra, &[])
    }

    fn ci_env(&self, state: &Path, extra: &[&str], env: &[(&str, &str)]) -> (i32, Value, PathBuf) {
        let out = self.command(state, extra, env).output().unwrap();
        self.finish(out)
    }

    fn command(&self, state: &Path, extra: &[&str], env: &[(&str, &str)]) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_brainproxy-server"));
        cmd.arg("ci")
            .arg("--target")
            .arg(self.path("target.json"))
            .arg("--targets")
            .arg(self.path("targets.json"))
            .arg("--state")
            .arg(state)
            .arg("--out")
            .arg(self.path("runs"))
            .arg("--secrets-dir")
            .arg(self.path("secrets"))
            .arg("--allow-loopback-targets")
            .args(extra)
            .env("BRAINPROXY_BIN", &self.bin)
            .env("BRAINPROXY_HOME", self.path("home"))
            .env("TMPDIR", self.tmp())
            .env_remove("BRAINPROXY_SYSTEM_SCOPE")
            .envs(env.iter().copied());
        cmd
    }

    fn finish(&self, out: std::process::Output) -> (i32, Value, PathBuf) {
        eprintln!("{}", String::from_utf8_lossy(&out.stderr));
        let run: Value = serde_json::from_slice(&out.stdout).unwrap_or(Value::Null);
        let folder = run["folder"].as_str().map(PathBuf::from).unwrap_or_default();
        let left: Vec<_> = std::fs::read_dir(self.tmp()).unwrap().collect();
        assert!(left.is_empty(), "temp folders left behind: {left:?}");
        (out.status.code().unwrap_or(-1), run, folder)
    }
}

fn target(app: &App) -> Value {
    json!({
        "id": "app",
        "base_url": app.url(),
        "scope": [app.host()],
        "preset": "quick",
        "max_minutes": 10,
        "gate": {"fail_on": "high", "new_only": true},
    })
}

fn read(path: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))).unwrap()
}

fn refs(list: &Value) -> Vec<String> {
    list.as_array().unwrap().iter().map(|f| f["alert_ref"].as_str().unwrap().to_string()).collect()
}

fn has(list: &Value, prefix: &str) -> bool {
    refs(list).iter().any(|r| r.starts_with(prefix))
}

/// The known set's instances of alerts starting with `prefix`, with their states.
fn known(state: &Path, prefix: &str) -> Vec<String> {
    let k = read(&state.join("known.json"));
    k["alerts"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|a| a["alert_ref"].as_str().unwrap().starts_with(prefix))
        .flat_map(|a| a["instances"].as_array().unwrap().iter().map(|i| i["state"].as_str().unwrap().to_string()))
        .collect()
}

#[test]
fn the_known_set_moves_only_on_a_pass() {
    let Some(env) = Env::new() else { return };
    let app = App::start(2);
    env.target(target(&app));
    let none = env.path("no-state");

    // 1: a baseline run with no state: passes, and the XSS becomes known.
    let (code, r1, d1) = env.ci(&none, &["--baseline", "--commit", "9f2c1e7", "--ref", "refs/heads/main"]);
    assert_eq!(code, 0, "{r1}");
    assert_eq!(r1["mode"], "stateless");
    assert_eq!(r1["target"], "app");
    assert_eq!(r1["commit"], "9f2c1e7");
    assert!(r1["state"]["read_generation"].is_null());
    assert_eq!(r1["state"]["written"], 1);
    assert_eq!(r1["state"]["known_replaced"], true);
    assert!(r1["data_versions"]["rules"].is_object(), "{r1}");
    let s1 = d1.join("state");
    assert_eq!(read(&s1.join("state.json"))["generation"], 1);
    assert!(!known(&s1, "40012").is_empty(), "no XSS known after run 1");
    // The state is the run's, not --state's: nothing was written there.
    assert!(!none.exists());

    // 2: a SQL error appears: new, the gate fails; the XSS is unchanged. Known stays as it was.
    app.state.drift.store(true, Ordering::SeqCst);
    let (code, r2, d2) = env.ci(&s1, &[]);
    assert_eq!(code, 5, "{r2}");
    assert_eq!(r2["state"]["read_generation"], 1);
    assert_eq!(r2["state"]["known_used"], true);
    assert_eq!(r2["state"]["known_replaced"], false);
    let c2 = read(&d2.join("compare.json"));
    assert!(has(&c2["data"]["new"], "40018"), "no SQLi in {}", c2["data"]["new"]);
    assert!(has(&c2["data"]["unchanged"], "40012"));
    let s2 = d2.join("state");
    assert_eq!(read(&s2.join("state.json"))["generation"], 2);
    assert_eq!(std::fs::read(s2.join("known.json")).unwrap(), std::fs::read(s1.join("known.json")).unwrap());

    // 3: the same again from run 2's state: run 2 didn't pass, so the SQL error is still new.
    let (code, r3, d3) = env.ci(&s2, &[]);
    assert_eq!(code, 5, "{r3}");
    assert!(has(&read(&d3.join("compare.json"))["data"]["new"], "40018"));

    // 4: the team lists the SQL error as accepted: marked before the compare, the run passes,
    // and the known set now holds it, without the mark (the list is the marks' only source).
    let c3 = read(&d3.join("compare.json"));
    let sqli: Vec<Value> = c3["data"]["new"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["alert_ref"].as_str().unwrap().starts_with("40018"))
        .map(|f| json!({"alert_ref": f["alert_ref"], "url": f["url"], "method": f["method"], "param": f["param"], "note": "test"}))
        .collect();
    let list = env.path("suppressions.json");
    std::fs::write(&list, Value::Array(sqli).to_string()).unwrap();
    let (code, r4, d4) = env.ci(&d3.join("state"), &["--suppressions", list.to_str().unwrap()]);
    assert_eq!(code, 0, "{r4}");
    assert!(r4["marks"]["suppressions"].as_u64().unwrap() > 0, "{r4}");
    assert_eq!(r4["state"]["known_replaced"], true);
    let s4 = d4.join("state");
    let marks = known(&s4, "40018");
    assert!(!marks.is_empty() && marks.iter().all(|m| m == "open"), "{marks:?}");
    // The reports agree with the gate: the SQL error is a false positive there too.
    let report = read(&d4.join("report.json"));
    assert!(!has_open(&report, "40018"), "{report}");

    // 5: off the list, the finding opens again: the reports show it. It is known now, so a
    // --new-only gate counts it as unchanged.
    let (code, r5, d5) = env.ci(&s4, &[]);
    assert_eq!(code, 0, "{r5}");
    assert!(has_open(&read(&d5.join("report.json")), "40018"));
    assert!(has(&read(&d5.join("compare.json"))["data"]["unchanged"], "40018"));

    // 6: the SQL error is gone: fixed, and it leaves the known set; the XSS stays.
    app.state.drift.store(false, Ordering::SeqCst);
    let (code, r6, d6) = env.ci(&d5.join("state"), &[]);
    assert_eq!(code, 0, "{r6}");
    let c6 = read(&d6.join("compare.json"));
    // A false positive that went away is fixed too, so it leaves the known set.
    assert!(has(&c6["data"]["fixed"], "40018"), "{}", c6["data"]);
    assert!(known(&d6.join("state"), "40018").is_empty());
    assert!(!known(&d6.join("state"), "40012").is_empty());
    assert_eq!(read(&d6.join("state").join("state.json"))["generation"], 6);
}

fn has_open(report: &Value, prefix: &str) -> bool {
    report["data"]["alerts"]
        .as_array()
        .or(report["alerts"].as_array())
        .into_iter()
        .flatten()
        .filter(|a| a["alert_ref"].as_str().unwrap_or_default().starts_with(prefix))
        .flat_map(|a| a["instances"].as_array().into_iter().flatten())
        .any(|i| i["state"] == "open")
}

#[test]
fn a_known_set_from_other_settings_is_not_used() {
    let Some(env) = Env::new() else { return };
    let app = App::start(2);
    env.target(target(&app));
    let (code, r0, d0) = env.ci(&env.path("none"), &["--baseline"]);
    assert_eq!(code, 0, "{r0}");
    // A gated pass after the baseline run: its gate is what later runs are held to.
    let (code, r1, d1) = env.ci(&d0.join("state"), &[]);
    assert_eq!(code, 0, "{r1}");
    let s1 = d1.join("state");
    assert_eq!(read(&s1.join("state.json"))["known"]["baseline"], false);

    // Another URL to scan: everything is new again, and run.json says why.
    let mut t = target(&app);
    t["base_url"] = json!(format!("{}search?q=x", app.url()));
    env.target(t);
    let (code, r2, d2) = env.ci(&s1, &[]);
    assert_eq!(code, 5, "{r2}");
    assert_eq!(r2["state"]["known_used"], false);
    assert!(r2["state"]["reason"].as_str().unwrap().contains("scanning"), "{r2}");
    assert!(has(&read(&d2.join("compare.json"))["data"]["new"], "40012"));

    // A --baseline run starts over too.
    let (code, rb, _) = env.ci(&s1, &["--baseline"]);
    assert_eq!(code, 0, "{rb}");
    assert_eq!(rb["state"]["known_used"], false);
    assert!(rb["state"]["reason"].as_str().unwrap().contains("starts over"), "{rb}");

    // A laxer gate than the run that found them.
    let mut t = target(&app);
    t["gate"] = json!({"fail_on": "low", "new_only": true});
    env.target(t);
    let (_, r3, _) = env.ci(&s1, &[]);
    assert_eq!(r3["state"]["known_used"], false, "{r3}");
    assert!(r3["state"]["reason"].as_str().unwrap().contains("laxer"));
}

#[test]
fn a_state_that_cant_be_trusted_is_refused() {
    let Some(env) = Env::new() else { return };
    let app = App::start(0);
    env.target(target(&app));
    let key = ("STATE_KEY", "0123456789abcdef0123456789abcdef");
    let (code, r1, d1) = env.ci_env(&env.path("none"), &["--baseline", "--state-key-env", "STATE_KEY"], &[key]);
    assert_eq!(code, 0, "{r1}");
    let good = d1.join("state");
    assert!(good.join("state.sig").is_file());
    let runs_before = std::fs::read_dir(env.path("runs")).unwrap().count();

    let copy = |name: &str| {
        let d = env.path(name);
        std::fs::create_dir_all(&d).unwrap();
        for f in ["state.json", "known.json", "state.sig"] {
            std::fs::copy(good.join(f), d.join(f)).unwrap();
        }
        d
    };
    let signed = ["--state-key-env", "STATE_KEY"];
    // Signed, but no key given; the wrong key; a changed known.json; another target's state.
    let (code, ..) = env.ci(&copy("nokey"), &[]);
    assert_eq!(code, 1);
    let (code, ..) = env.ci_env(&copy("wrongkey"), &signed, &[("STATE_KEY", "another key, also 32 characters!!")]);
    assert_eq!(code, 1);
    let d = copy("sha");
    std::fs::write(d.join("known.json"), b"{\"alerts\": []}").unwrap();
    let (code, ..) = env.ci_env(&d, &signed, &[key]);
    assert_eq!(code, 1);
    let mut other = target(&app);
    other["id"] = json!("other");
    env.targets(&["app", "other"]);
    env.target(other);
    let (code, ..) = env.ci_env(&copy("target"), &signed, &[key]);
    assert_eq!(code, 1);
    env.target(target(&app));
    // A folder with something in it but no state.json; a corrupt state.json.
    let d = env.path("junk");
    std::fs::create_dir_all(&d).unwrap();
    std::fs::write(d.join("notes.txt"), b"x").unwrap();
    let (code, ..) = env.ci(&d, &[]);
    assert_eq!(code, 1);
    let d = copy("corrupt");
    std::fs::write(d.join("state.json"), b"{").unwrap();
    let (code, ..) = env.ci(&d, &[]);
    assert_eq!(code, 1);
    // None of them ran a scan or wrote a run folder.
    assert_eq!(std::fs::read_dir(env.path("runs")).unwrap().count(), runs_before);

    // The wrapper's pointer: another generation, or an empty state when it names one, is refused.
    assert_eq!(env.ci_env(&good, &["--state-key-env", "STATE_KEY", "--expect-generation", "5"], &[key]).0, 1);
    let empty = env.path("empty");
    std::fs::create_dir_all(&empty).unwrap();
    assert_eq!(env.ci(&empty, &["--expect-generation", "1"]).0, 1);
    // The state key can't double as a target secret.
    let mut t = target(&app);
    t["secret_env"] = json!({"APP_PW": "STATE_KEY"});
    env.target(t);
    assert_eq!(env.ci_env(&good, &signed, &[key]).0, 2);
    env.target(target(&app));
    assert_eq!(std::fs::read_dir(env.path("runs")).unwrap().count(), runs_before);

    // The registry: the target must be listed, and at most 10 are.
    env.targets(&["shop"]);
    assert_eq!(env.ci(&good, &signed).0, 2);
    let eleven: Vec<String> = (0..10).map(|i| format!("t{i}")).chain(["app".to_string()]).collect();
    env.targets(&eleven.iter().map(String::as_str).collect::<Vec<_>>());
    assert_eq!(env.ci(&good, &signed).0, 2);
}

#[test]
fn keep_project_coverage_drop_and_notify() {
    let Some(env) = Env::new() else { return };
    let app = App::start(30);
    // A generic webhook on this machine, signed with HOOK_KEY.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let hook = format!("http://127.0.0.1:{}/hook", listener.local_addr().unwrap().port());
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for mut conn in listener.incoming().flatten() {
            let mut reader = BufReader::new(conn.try_clone().unwrap());
            let mut length = 0;
            let mut headers = Vec::new();
            loop {
                let mut h = String::new();
                reader.read_line(&mut h).unwrap();
                let h = h.trim_end().to_string();
                if h.is_empty() {
                    break;
                }
                if let Some(v) = h.to_ascii_lowercase().strip_prefix("content-length:") {
                    length = v.trim().parse().unwrap();
                }
                headers.push(h);
            }
            let mut body = vec![0; length];
            reader.read_exact(&mut body).unwrap();
            let _ = conn.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n");
            let _ = tx.send((headers, String::from_utf8_lossy(&body).into_owned()));
        }
    });
    let secrets = env.path("secrets").join("app");
    std::fs::create_dir_all(&secrets).unwrap();
    std::fs::write(secrets.join("HOOK_URL"), &hook).unwrap();
    std::fs::write(secrets.join("HOOK_KEY"), "whsec_test").unwrap();
    let mut t = target(&app);
    t["notify"] =
        json!([{"kind": "generic", "url_secret": "HOOK_URL", "secret": "HOOK_KEY", "on": ["passed", "incomplete"]}]);
    env.target(t);

    let kept = env.path("kept.bpdb");
    let (code, r1, d1) = env.ci(&env.path("none"), &["--keep-project", kept.to_str().unwrap(), "--notify"]);
    assert_eq!(code, 5, "{r1}");
    assert!(kept.is_file(), "--keep-project wrote nothing");
    // The gate failed: not an event this hook wants.
    assert!(rx.try_recv().is_err());
    assert_eq!(r1["notifications"], json!([]));

    // Coverage against the state's, as against the history in project mode.
    let (code, r2, d2) = env.ci(&d1.join("state"), &["--baseline", "--notify"]);
    assert_eq!(code, 0, "{r2}");
    let (headers, body) = rx.recv_timeout(std::time::Duration::from_secs(10)).unwrap();
    let body: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(body["event"], "passed");
    assert_eq!(body["target"], "app");
    assert!(body["links"].is_null());
    assert!(headers.iter().any(|h| h.to_ascii_lowercase().starts_with("x-brainproxy-signature:")));
    assert_eq!(r2["notifications"][0]["ok"], true, "{r2}");

    app.state.pages.store(0, Ordering::SeqCst);
    let (code, r3, d3) = env.ci(&d2.join("state"), &["--notify"]);
    assert_eq!(code, 2, "{r3}");
    assert!(r3["reasons"].to_string().contains("coverage dropped"), "{r3}");
    assert!(rx.recv_timeout(std::time::Duration::from_secs(10)).unwrap().1.contains("incomplete"));
    // An incomplete run keeps the coverage it was compared with.
    assert_eq!(read(&d3.join("state/state.json"))["coverage"], read(&d2.join("state/state.json"))["coverage"]);
    assert_eq!(read(&d3.join("state/state.json"))["generation"], 3);
}

#[test]
fn a_cancelled_run_cleans_up_and_carries_the_state_forward() {
    let Some(env) = Env::new() else { return };
    let app = App::start(20);
    env.target(target(&app));
    let (code, r1, d1) = env.ci(&env.path("none"), &["--baseline"]);
    assert_eq!(code, 0, "{r1}");

    app.state.delay_ms.store(150, Ordering::SeqCst);
    let child = env.command(&d1.join("state"), &[], &[]).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    // Once the scan has started (its run folder is there), stop the run as a task stop would.
    let start = std::time::Instant::now();
    while std::fs::read_dir(env.path("runs")).unwrap().count() < 2 {
        assert!(start.elapsed().as_secs() < 60, "the scan never started");
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    std::thread::sleep(std::time::Duration::from_secs(1));
    assert!(Command::new("kill").args(["-TERM", &child.id().to_string()]).status().unwrap().success());
    let (code, r2, d2) = env.finish(child.wait_with_output().unwrap());
    assert_eq!(code, 2, "{r2}");
    assert_eq!(r2["outcome"], "incomplete");
    assert!(r2["reasons"].to_string().contains("SIGTERM"), "{r2}");
    // The known set is carried forward unchanged; the generation still moves on.
    assert_eq!(r2["state"]["known_replaced"], false);
    assert_eq!(
        std::fs::read(d2.join("state/known.json")).unwrap(),
        std::fs::read(d1.join("state/known.json")).unwrap()
    );
    assert_eq!(read(&d2.join("state/state.json"))["generation"], 2);
}

#[test]
fn a_template_is_vetted_as_an_upload_is() {
    let Some(env) = Env::new() else { return };
    let app = App::start(0);
    let make = |name: &str, scope: &str| {
        let p = env.path(name);
        let out = Command::new(&env.bin)
            .arg("--project")
            .arg(&p)
            .args(["--format", "json", "engagement", "start", "--target", scope])
            .env("BRAINPROXY_HOME", env.path("home"))
            .output()
            .unwrap();
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stdout));
        p
    };
    let good = make("good.bpdb", &app.host());
    let wide = make("wide.bpdb", "127.0.0.1");
    let mut t = target(&app);
    t["project"] = json!("upload");
    env.target(t);
    let none = env.path("none");

    // An uploaded-project target needs --template; a generated one refuses it.
    assert_eq!(env.ci(&none, &[]).0, 2);
    let (code, r, _) = env.ci(&none, &["--baseline", "--template", good.to_str().unwrap()]);
    assert_eq!(code, 0, "{r}");
    // The template itself is only read.
    assert!(good.is_file());
    // A scope wider than the target's: out of scope, nothing scanned.
    assert_eq!(env.ci(&none, &["--template", wide.to_str().unwrap()]).0, 6);
    env.target(target(&app));
    assert_eq!(env.ci(&none, &["--template", good.to_str().unwrap()]).0, 2);
}
