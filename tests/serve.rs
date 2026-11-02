//! `brainproxy-server serve` and `remote`: the real binary, the real brainproxy CLI, and the local
//! test web app. Skipped without a CLI, like the contract tests (see `common::cli`).

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

mod common;
use common::{App, cli};

const SERVER: &str = env!("CARGO_BIN_EXE_brainproxy-server");

struct Server {
    child: Option<Child>,
    dir: PathBuf,
    cli: PathBuf,
    public: u16,
    admin: u16,
    admin_token: String,
    extra: Vec<String>,
    /// `--allow-loopback-targets` (the test app is on 127.0.0.1).
    loopback: bool,
    env: Vec<(String, String)>,
    agent: ureq::Agent,
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

impl Server {
    /// A server in `dir` (its work folder, admin token and secrets live there).
    fn start(dir: &Path, cli: &Path, extra: &[&str]) -> Server {
        Server::start_with(dir, cli, extra, true, &[])
    }

    fn start_with(dir: &Path, cli: &Path, extra: &[&str], loopback: bool, env: &[(&str, &str)]) -> Server {
        std::fs::create_dir_all(dir.join("secrets")).unwrap();
        let admin_token = "a".repeat(20) + &"0123456789abcdef".repeat(2);
        std::fs::write(dir.join("admin_token"), &admin_token).unwrap();
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .timeout_global(Some(Duration::from_secs(120)))
            .build()
            .into();
        let mut s = Server {
            child: None,
            dir: dir.to_path_buf(),
            cli: cli.to_path_buf(),
            public: free_port(),
            admin: free_port(),
            admin_token,
            extra: extra.iter().map(|s| s.to_string()).collect(),
            loopback,
            env: env.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            agent,
        };
        s.spawn();
        s
    }

    fn spawn(&mut self) {
        let log = std::fs::File::options().create(true).append(true).open(self.dir.join("server.log")).unwrap();
        let mut cmd = Command::new(SERVER);
        cmd.arg("serve")
            .arg("--work")
            .arg(self.dir.join("work"))
            .arg("--admin-token-file")
            .arg(self.dir.join("admin_token"))
            .arg("--secrets-dir")
            .arg(self.dir.join("secrets"))
            .args(["--listen", &format!("127.0.0.1:{}", self.public)])
            .args(["--admin-listen", &format!("127.0.0.1:{}", self.admin)])
            .arg("--brainproxy")
            .arg(&self.cli)
            .args(&self.extra)
            .envs(self.env.iter().map(|(k, v)| (k, v)))
            .env_remove("BRAINPROXY_HOME")
            .stdout(Stdio::null())
            .stderr(log);
        if self.loopback {
            cmd.arg("--allow-loopback-targets");
        }
        let child = cmd.spawn().unwrap();
        self.child = Some(child);
        let start = Instant::now();
        while self.get_public("/v1/healthz", None).0 != 200 {
            assert!(start.elapsed() < Duration::from_secs(20), "server didn't start: {}", self.log());
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.dir.join("server.log")).unwrap_or_default()
    }

    fn kill(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }

    /// SIGTERM, as a container stop sends, and waits for the exit.
    #[cfg(feature = "object-store")]
    fn stop(&mut self) {
        if let Some(mut c) = self.child.take() {
            Command::new("kill").args(["-TERM", &c.id().to_string()]).status().unwrap();
            let start = Instant::now();
            while c.try_wait().unwrap().is_none() {
                assert!(start.elapsed() < Duration::from_secs(30), "server didn't stop: {}", self.log());
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }

    fn request(&self, method: &str, port: u16, path: &str, token: Option<&str>, body: Option<&Value>) -> (u16, Value) {
        let url = format!("http://127.0.0.1:{port}{path}");
        let auth = token.map(|t| format!("Bearer {t}"));
        let resp = match method {
            "GET" => {
                let mut r = self.agent.get(&url);
                if let Some(a) = &auth {
                    r = r.header("Authorization", a);
                }
                r.call()
            }
            "DELETE" => {
                let mut r = self.agent.delete(&url);
                if let Some(a) = &auth {
                    r = r.header("Authorization", a);
                }
                r.call()
            }
            m => {
                let mut r = match m {
                    "PUT" => self.agent.put(&url),
                    "PATCH" => self.agent.patch(&url),
                    _ => self.agent.post(&url),
                };
                if let Some(a) = &auth {
                    r = r.header("Authorization", a);
                }
                r.send_json(body.cloned().unwrap_or(json!({})))
            }
        };
        // No answer at all (not listening yet) is status 0.
        let Ok(mut resp) = resp else { return (0, Value::Null) };
        let status = resp.status().as_u16();
        let text = resp.body_mut().read_to_string().unwrap_or_default();
        (status, serde_json::from_str(&text).unwrap_or(Value::String(text)))
    }

    fn get_public(&self, path: &str, token: Option<&str>) -> (u16, Value) {
        self.request("GET", self.public, path, token, None)
    }

    fn post_public(&self, path: &str, token: &str, body: Value) -> (u16, Value) {
        self.request("POST", self.public, path, Some(token), Some(&body))
    }

    fn admin(&self, method: &str, path: &str, body: Option<Value>) -> (u16, Value) {
        self.request(method, self.admin, path, Some(&self.admin_token), body.as_ref())
    }

    /// Registers the app as target `id` (quick preset, the given gate).
    fn register(&self, id: &str, app: &App, extra: Value) -> Value {
        let mut body = json!({
            "id": id, "base_url": app.url(), "scope": [app.host()], "preset": "quick", "max_minutes": 10,
        });
        for (k, v) in extra.as_object().unwrap() {
            body[k] = v.clone();
        }
        let (status, v) = self.admin("POST", "/v1/targets", Some(body));
        assert_eq!(status, 201, "{v}\n{}", self.log());
        v
    }

    fn token(&self, id: &str, perm: &str) -> String {
        let (status, v) =
            self.admin("POST", &format!("/v1/targets/{id}/tokens"), Some(json!({"name": "ci", "perm": perm})));
        assert_eq!(status, 201, "{v}");
        v["data"]["token"].as_str().unwrap().to_string()
    }

    fn trigger(&self, id: &str, token: &str, body: Value) -> (u16, Value) {
        self.post_public(&format!("/v1/targets/{id}/runs"), token, body)
    }

    /// Long-polls a run until it ends.
    fn wait_run(&self, id: &str, run: &str, token: &str) -> Value {
        let start = Instant::now();
        loop {
            let (status, v) = self.get_public(&format!("/v1/targets/{id}/runs/{run}?wait=10"), Some(token));
            assert_eq!(status, 200, "{v}");
            let st = v["data"]["state"].as_str().unwrap().to_string();
            if st != "queued" && st != "running" {
                return v["data"].clone();
            }
            assert!(start.elapsed() < Duration::from_secs(300), "run {run} didn't end: {v}\n{}", self.log());
        }
    }

    /// Waits until the run is running with a job.
    fn wait_job(&self, id: &str, run: &str, token: &str) -> Value {
        let start = Instant::now();
        loop {
            let (_, v) = self.get_public(&format!("/v1/targets/{id}/runs/{run}?wait=5"), Some(token));
            if v["data"]["job"].is_u64() && v["data"]["state"] == "running" {
                return v["data"].clone();
            }
            assert!(start.elapsed() < Duration::from_secs(60), "no job for {run}: {v}\n{}", self.log());
        }
    }

    fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.public)
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.kill();
    }
}

fn setup(extra: &[&str]) -> Option<(tempfile::TempDir, Server)> {
    let cli = cli()?;
    let dir = tempfile::tempdir().unwrap();
    let server = Server::start(dir.path(), &cli, extra);
    Some((dir, server))
}

fn run_id(v: &Value) -> String {
    v["data"]["run"].as_str().unwrap_or_else(|| panic!("no run in {v}")).to_string()
}

/// `brainproxy-server remote ARGS` with the token in BRAINPROXY_TOKEN: (exit code, stdout JSON).
fn remote(server: &Server, token: &str, args: &[&str]) -> (i32, Value) {
    let out = Command::new(SERVER)
        .arg("remote")
        .args(args)
        .args(["--server", &server.url()])
        .env("BRAINPROXY_TOKEN", token)
        .output()
        .unwrap();
    eprintln!("{}", String::from_utf8_lossy(&out.stderr));
    (out.status.code().unwrap_or(-1), serde_json::from_slice(&out.stdout).unwrap_or(Value::Null))
}

// ---------------------------------------------------------------------------------------------

#[test]
fn tokens_are_bound_to_their_target_and_admin_is_only_on_its_listener() {
    let Some((_dir, s)) = setup(&[]) else { return };
    let app = App::start(1);
    s.register("alpha", &app, json!({}));
    s.register("beta", &app, json!({}));
    let alpha = s.token("alpha", "trigger");
    let reader = s.token("alpha", "read");

    // No token, a made-up one, another target's.
    assert_eq!(s.get_public("/v1/targets/alpha/runs", None).0, 401);
    let fake = format!("bpt_alpha_{}", "a".repeat(52));
    assert_eq!(s.get_public("/v1/targets/alpha/runs", Some(&fake)).0, 401);
    let (status, v) = s.get_public("/v1/targets/beta/runs", Some(&alpha));
    assert_eq!(status, 403, "{v}");
    assert_eq!(s.trigger("beta", &alpha, json!({})).0, 403);
    // A token for a target that doesn't exist gets the same answer as for one that does.
    assert_eq!(s.get_public("/v1/targets/nope/runs", Some(&alpha)).0, 403);

    // Its own target, and only that one in the list; no secret sources.
    assert_eq!(s.get_public("/v1/targets/alpha/runs", Some(&alpha)).0, 200);
    let (_, list) = s.get_public("/v1/targets", Some(&alpha));
    let ids: Vec<&str> =
        list["data"]["targets"].as_array().unwrap().iter().map(|t| t["id"].as_str().unwrap()).collect();
    assert_eq!(ids, ["alpha"]);

    // Read-only tokens can't trigger or cancel.
    let (status, v) = s.trigger("alpha", &reader, json!({}));
    assert_eq!(status, 403, "{v}");
    assert_eq!(s.get_public("/v1/targets/alpha", Some(&reader)).0, 200);

    // The admin token means nothing on the public listener; admin endpoints aren't there at all.
    assert_eq!(s.get_public("/v1/targets", Some(&s.admin_token)).0, 401);
    let body = json!({"id": "gamma", "base_url": app.url(), "scope": [app.host()]});
    let (status, _) = s.request("POST", s.public, "/v1/targets", Some(&s.admin_token), Some(&body));
    assert!(status == 404 || status == 405, "{status}");
    let (status, _) =
        s.request("POST", s.public, "/v1/targets/alpha/tokens", Some(&s.admin_token), Some(&json!({"name": "x"})));
    assert!(status == 404 || status == 405, "{status}");
    assert_eq!(s.get_public("/v1/summary", Some(&s.admin_token)).0, 404);
    let (_, all) = s.admin("GET", "/v1/targets", None);
    assert_eq!(all["data"]["targets"].as_array().unwrap().len(), 2, "gamma was registered: {all}");

    // A target token on the admin listener is refused.
    let (status, _) = s.request("GET", s.admin, "/v1/targets", Some(&alpha), None);
    assert_eq!(status, 401);
    let (status, _) = s.request("POST", s.admin, "/v1/targets", Some(&alpha), Some(&body));
    assert_eq!(status, 401);

    // Revoked tokens stop working.
    let (_, tokens) = s.admin("GET", "/v1/targets/alpha/tokens", None);
    let id = tokens["data"]["tokens"][0]["id"].as_str().unwrap().to_string();
    assert_eq!(s.admin("DELETE", &format!("/v1/targets/alpha/tokens/{id}"), None).0, 200);
    assert_eq!(s.get_public("/v1/targets/alpha/runs", Some(&alpha)).0, 401);

    // Failed authentications are audited.
    let (_, audit) = s.admin("GET", "/v1/audit?limit=100", None);
    let refused = audit["data"]["audit"].as_array().unwrap().iter().filter(|e| e["result"] == "refused").count();
    assert!(refused >= 4, "{audit}");
}

#[test]
fn the_results_page_needs_no_token_and_locks_itself_down() {
    let Some((_dir, s)) = setup(&[]) else { return };
    for port in [s.public, s.admin] {
        for (path, ty) in [("/ui", "text/html"), ("/ui/app.js", "text/javascript"), ("/ui/app.css", "text/css")] {
            let resp = s.agent.get(&format!("http://127.0.0.1:{port}{path}")).call().unwrap();
            assert_eq!(resp.status().as_u16(), 200, "{path}");
            let h = resp.headers();
            assert!(h["content-type"].to_str().unwrap().starts_with(ty), "{path}: {h:?}");
            let csp = h["content-security-policy"].to_str().unwrap();
            assert!(
                csp.starts_with("default-src 'none'; script-src 'self';") && csp.contains("frame-ancestors 'none'")
            );
            assert_eq!(h["x-content-type-options"], "nosniff");
            assert_eq!(h["referrer-policy"], "no-referrer");
            assert_eq!(h["cache-control"], "no-store");
        }
    }
    // The page holds no data: the API behind it still wants a token.
    assert_eq!(s.get_public("/v1/targets", None).0, 401);
    assert_eq!(s.get_public("/ui/other.js", None).0, 404);
}

#[test]
fn at_most_ten_targets() {
    let Some((dir, s)) = setup(&[]) else { return };
    let app = App::start(0);
    for i in 0..10 {
        s.register(&format!("t{i}"), &app, json!({}));
    }
    let body = json!({"id": "t10", "base_url": app.url(), "scope": [app.host()]});
    let (status, v) = s.admin("POST", "/v1/targets", Some(body));
    assert_eq!(status, 409, "{v}");
    assert_eq!(v["error"]["kind"], "target_limit");
    assert!(!dir.path().join("work/targets/t10").exists());

    // The SQLite trigger holds even if the handler's check were skipped.
    let db = rusqlite::Connection::open(dir.path().join("work/control.db")).unwrap();
    let err = db
        .execute("INSERT INTO targets (id, config, project_ready, created) VALUES ('x', '{}', 0, 0)", [])
        .unwrap_err();
    assert!(err.to_string().contains("at most 10 targets"), "{err}");

    // Removing one makes room; its tokens die with it.
    let tok = s.token("t3", "trigger");
    assert_eq!(s.admin("DELETE", "/v1/targets/t3", None).0, 200);
    assert_eq!(s.get_public("/v1/targets/t3/runs", Some(&tok)).0, 401);
    s.register("t10", &app, json!({}));
    // A target registered again under a removed id starts without the old one's runs.
    app.state.delay_ms.store(1500, Ordering::SeqCst);
    let (_, _) = s.trigger("t4", &s.token("t4", "trigger"), json!({"commit": "old"}));
    assert_eq!(s.admin("DELETE", "/v1/targets/t4", None).0, 409, "removed with a live run");
    let (_, runs) = s.admin("GET", "/v1/targets/t4/runs", None);
    let r = runs["data"]["runs"][0]["run"].as_str().unwrap().to_string();
    s.admin("POST", &format!("/v1/targets/t4/runs/{r}/cancel"), None);
    let start = Instant::now();
    while s.admin("DELETE", "/v1/targets/t4", None).0 != 200 {
        assert!(start.elapsed() < Duration::from_secs(60), "t4 never became removable");
        std::thread::sleep(Duration::from_millis(200));
    }
    app.state.delay_ms.store(0, Ordering::SeqCst);
    s.register("t4", &app, json!({}));
    let (_, runs) = s.admin("GET", "/v1/targets/t4/runs", None);
    assert_eq!(runs["data"]["runs"], json!([]), "{runs}");
    let scope: Value =
        serde_json::from_str(&std::fs::read_to_string(dir.path().join("work/system-scope.json")).unwrap()).unwrap();
    assert_eq!(scope["include"], json!([app.host()]));
}

#[test]
fn registration_refuses_what_could_point_the_scanner_elsewhere() {
    let Some((dir, s)) = setup(&[]) else { return };
    let app = App::start(0);
    let refused = |body: Value| {
        let (status, v) = s.admin("POST", "/v1/targets", Some(body.clone()));
        assert!(status == 400, "accepted {body}: {status} {v}");
        v["error"]["message"].as_str().unwrap_or_default().to_string()
    };
    let base = |scope: Value, url: &str| json!({"id": "x", "base_url": url, "scope": scope});
    refused(base(json!(["*.corp.test"]), "http://a.corp.test/"));
    refused(base(json!(["169.254.169.254"]), "http://169.254.169.254/"));
    refused(base(json!(["10.0.0.0/8"]), "http://10.0.0.1/"));
    refused(base(json!([app.host()]), "http://127.0.0.1:1/"));
    refused(base(json!([app.host()]), "http://user:pw@127.0.0.1/"));
    // A host that doesn't resolve fails `engagement check`.
    let m = refused(base(json!(["no-such-host.invalid"]), "http://no-such-host.invalid/"));
    assert!(m.contains("no-such-host.invalid"), "{m}");
    // No scan flags, no unknown fields, no secret variables the CLI or the system reads.
    let mut b = base(json!([app.host()]), &app.url());
    b["crawl_any_port"] = json!(true);
    refused(b);
    let mut b = base(json!([app.host()]), &app.url());
    b["secret_env"] = json!({"LD_PRELOAD": "X"});
    refused(b);
    let mut b = base(json!([app.host()]), &app.url());
    b["secret_env"] = json!({"APP_PW": "BRAINPROXY_SYSTEM_SCOPE"});
    refused(b);
    assert_eq!(std::fs::read_dir(dir.path().join("work/targets")).unwrap().count(), 0);

    // Without --allow-loopback-targets this machine can't be a target at all.
    drop(s);
    let dir2 = tempfile::tempdir().unwrap();
    let strict = Server::start_with(dir2.path(), &cli().unwrap(), &[], false, &[]);
    let (status, v) = strict.admin("POST", "/v1/targets", Some(base(json!([app.host()]), &app.url())));
    assert_eq!(status, 400, "{v}");
    assert!(v["error"]["message"].as_str().unwrap().contains("loopback"), "{v}");
}

/// Writes a project with `brainproxy` (own home), for uploads.
fn make_project(cli: &Path, dir: &Path, name: &str, args: &[&[&str]]) -> PathBuf {
    let project = dir.join(name);
    for a in args {
        let out = Command::new(cli)
            .arg("--project")
            .arg(&project)
            .args(["--format", "json"])
            .args(*a)
            .env("BRAINPROXY_HOME", dir.join("home"))
            .output()
            .unwrap();
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stdout));
    }
    project
}

fn upload(s: &Server, id: &str, bytes: Vec<u8>) -> (u16, Value) {
    let resp = s
        .agent
        .put(&format!("http://127.0.0.1:{}/v1/targets/{id}/project", s.admin))
        .header("Authorization", &format!("Bearer {}", s.admin_token))
        .send(&bytes[..]);
    // A server that refuses early (413) may close before the body is sent: no status then.
    let Ok(mut resp) = resp else { return (0, Value::Null) };
    let status = resp.status().as_u16();
    (status, serde_json::from_str(&resp.body_mut().read_to_string().unwrap()).unwrap_or(Value::Null))
}

#[test]
fn uploaded_projects_are_checked() {
    let Some((dir, s)) = setup(&["--max-project-mb", "1"]) else { return };
    let cli = cli().unwrap();
    let app = App::start(1);
    let other = App::start(0);
    s.register("up", &app, json!({"project": "upload", "auth_profile": "user"}));
    let tok = s.token("up", "trigger");
    let (status, v) = s.trigger("up", &tok, json!({}));
    assert_eq!(status, 409, "no project yet: {v}");

    let p = dir.path();
    let (status, v) = upload(&s, "up", b"not a database".to_vec());
    assert_eq!(status, 400, "{v}");
    let (status, _) = upload(&s, "up", vec![0u8; 1024 * 1024 + 1]);
    assert!(status == 413 || status == 0, "{status}");
    let leftovers = std::fs::read_dir(dir.path().join("work/targets/up")).unwrap().flatten();
    assert!(leftovers.into_iter().all(|e| !e.file_name().to_string_lossy().starts_with(".upload")));

    let wide = make_project(
        &cli,
        p,
        "wide.bpdb",
        &[&["engagement", "start", "--target", &app.host(), "--target", &other.host()]],
    );
    let (status, v) = upload(&s, "up", std::fs::read(&wide).unwrap());
    assert_eq!(status, 400, "{v}");
    assert_eq!(v["error"]["kind"], "out_of_scope", "{v}");

    let login = format!("{}login", app.url());
    let literal = make_project(
        &cli,
        p,
        "literal.bpdb",
        &[
            &["engagement", "start", "--target", &app.host()],
            &["auth", "add", "user", "--login-url", &login, "--username", "ci", "--password", "right"],
        ],
    );
    let (status, v) = upload(&s, "up", std::fs::read(&literal).unwrap());
    assert_eq!(status, 400, "{v}");
    assert!(v["error"]["message"].as_str().unwrap().contains("password"), "{v}");

    // Connection settings that send traffic past the scope: an upstream proxy, a host override.
    let proxied = make_project(
        &cli,
        p,
        "proxied.bpdb",
        &[
            &["engagement", "start", "--target", &app.host()],
            &["connection", "upstream", "add", "--host", "*", "--proxy", "http://127.0.0.1:9"],
        ],
    );
    let (status, v) = upload(&s, "up", std::fs::read(&proxied).unwrap());
    assert_eq!(status, 400, "{v}");
    let pinned = make_project(
        &cli,
        p,
        "pinned.bpdb",
        &[
            &["engagement", "start", "--target", &app.host()],
            &["connection", "hosts", "add", "evil.test", "203.0.113.7"],
        ],
    );
    let (status, v) = upload(&s, "up", std::fs::read(&pinned).unwrap());
    assert_eq!(status, 400, "{v}");
    assert_eq!(v["error"]["kind"], "out_of_scope", "{v}");

    let missing = make_project(&cli, p, "noauth.bpdb", &[&["engagement", "start", "--target", &app.host()]]);
    let (status, v) = upload(&s, "up", std::fs::read(&missing).unwrap());
    assert_eq!(status, 400, "profile user is missing: {v}");

    let good = make_project(
        &cli,
        p,
        "good.bpdb",
        &[
            &["engagement", "start", "--target", &app.host()],
            &["auth", "add", "user", "--login-url", &login, "--username", "ci", "--password-env", "APP_PW"],
        ],
    );
    let (status, v) = upload(&s, "up", std::fs::read(&good).unwrap());
    assert_eq!(status, 200, "{v}");
    assert!(dir.path().join("work/targets/up/project.bpdb").is_file());
    let (_, t) = s.get_public("/v1/targets/up", Some(&tok));
    assert_eq!(t["data"]["project_ready"], true);

    // While a run is live, an upload is refused.
    app.state.delay_ms.store(2000, Ordering::SeqCst);
    std::fs::create_dir_all(p.join("secrets/up")).unwrap();
    let (status, v) = s.trigger("up", &tok, json!({}));
    assert_eq!(status, 202, "{v}");
    let run = run_id(&v);
    let (status, v) = upload(&s, "up", std::fs::read(&good).unwrap());
    assert_eq!(status, 409, "{v}");
    s.post_public(&format!("/v1/targets/up/runs/{run}/cancel"), &tok, json!({}));
    assert_eq!(s.wait_run("up", &run, &tok)["state"], "cancelled");
}

#[test]
fn queue_supersede_idempotency_and_cancel() {
    let Some((_dir, s)) = setup(&[]) else { return };
    let app = App::start(3);
    app.state.delay_ms.store(1500, Ordering::SeqCst);
    s.register("slow", &app, json!({}));
    let tok = s.token("slow", "trigger");

    let (status, first) = s.trigger("slow", &tok, json!({"commit": "c1"}));
    assert_eq!(status, 202, "{first}");
    let r1 = run_id(&first);
    s.wait_job("slow", &r1, &tok);

    // The second waits; a third replaces it, and the second ends as superseded (exit 2).
    let (_, second) = s.trigger("slow", &tok, json!({"commit": "c2"}));
    let r2 = run_id(&second);
    assert_eq!(second["data"]["state"], "queued");
    assert_eq!(second["data"]["position"], 1);
    let (_, third) = s.trigger("slow", &tok, json!({"commit": "c3", "ref": "refs/heads/main"}));
    let r3 = run_id(&third);
    assert_eq!(third["data"]["superseded"], r2);
    let (_, v) = s.get_public(&format!("/v1/targets/slow/runs/{r2}"), Some(&tok));
    assert_eq!(v["data"]["state"], "superseded");
    assert_eq!(v["data"]["exit_code"], 2);
    let (code, _) = remote(&s, &tok, &["wait", "--target", "slow", "--run", &r2]);
    assert_eq!(code, 2);

    // The same commit again is the same run; so is the same Idempotency-Key.
    let (status, again) = s.trigger("slow", &tok, json!({"commit": "c3"}));
    assert_eq!(status, 200, "{again}\n{}", s.log());
    assert_eq!(run_id(&again), r3);
    assert_eq!(again["data"]["deduplicated"], true);
    let keyed = |key: &str| {
        let mut resp = s
            .agent
            .post(&format!("{}/v1/targets/slow/runs", s.url()))
            .header("Authorization", &format!("Bearer {tok}"))
            .header("Idempotency-Key", key)
            .send_json(json!({}))
            .unwrap();
        let v: Value = serde_json::from_str(&resp.body_mut().read_to_string().unwrap()).unwrap();
        (resp.status().as_u16(), v)
    };
    let (status, k1) = keyed("key-1");
    assert_eq!(status, 202, "{k1}");
    let (status, k2) = keyed("key-1");
    assert_eq!(status, 200);
    assert_eq!(run_id(&k1), run_id(&k2));

    // Racing triggers of one commit: exactly one run. (A fresh token: each one may trigger 10 times
    // an hour.)
    let tok = s.token("slow", "trigger");
    let ids: Vec<String> = std::thread::scope(|sc| {
        let handles: Vec<_> = (0..6)
            .map(|_| {
                sc.spawn(|| {
                    let (status, v) = s.trigger("slow", &tok, json!({"commit": "c4"}));
                    assert!(status == 200 || status == 202, "{status} {v}");
                    run_id(&v)
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    assert!(ids.iter().all(|i| *i == ids[0]), "{ids:?}");
    let r4 = ids[0].clone();

    // Callers can't send a URL, scan flags or a deeper preset.
    assert_eq!(s.trigger("slow", &tok, json!({"url": "http://elsewhere.test/"})).0, 400);
    assert_eq!(s.trigger("slow", &tok, json!({"preset": "thorough"})).0, 400);
    assert_eq!(s.trigger("slow", &tok, json!({"commit": "$(id)"})).0, 400);

    // Cancel the queued run (at once) and the running one (its scan is stopped): both exit 2.
    let (status, v) = s.post_public(&format!("/v1/targets/slow/runs/{r4}/cancel"), &tok, json!({}));
    assert_eq!(status, 200, "{v}");
    assert_eq!(v["data"]["state"], "cancelled");
    let (status, v) = s.post_public(&format!("/v1/targets/slow/runs/{r1}/cancel"), &tok, json!({}));
    assert_eq!(status, 200, "{v}");
    let end = s.wait_run("slow", &r1, &tok);
    assert_eq!(end["state"], "cancelled", "{end}");
    assert_eq!(end["exit_code"], 2);
    let (_, list) = s.get_public("/v1/targets/slow/runs?limit=50", Some(&tok));
    assert!(list["data"]["runs"].as_array().unwrap().iter().all(|r| r["state"] != "running"), "{list}");
}

#[test]
fn remote_run_exit_codes_drift_and_reports() {
    let Some((dir, s)) = setup(&[]) else { return };
    let app = App::start(8);
    s.register("shop", &app, json!({"gate": {"fail_on": "high", "new_only": true}}));
    let tok = s.token("shop", "trigger");
    let out = dir.path().join("out");
    std::fs::create_dir_all(&out).unwrap();

    // 1: the first run is a baseline (set by the admin): no gate, passes.
    assert_eq!(s.admin("POST", "/v1/targets/shop/next-run", Some(json!({"baseline": true}))).0, 200);
    let (code, r1) = remote(&s, &tok, &["run", "--target", "shop", "--commit", "c1"]);
    assert_eq!(code, 0, "{r1}");
    assert_eq!(r1["baseline"], true);
    assert!(r1["drift"]["new"].as_u64().unwrap() > 0, "{r1}");

    // 2: a SQL error appears: new since run 1, the gate fails (5); reports and drift download.
    app.state.drift.store(true, Ordering::SeqCst);
    let sarif = out.join("r2.sarif");
    let drift = out.join("r2-drift.json");
    let (code, r2) = remote(
        &s,
        &tok,
        &[
            "run",
            "--target",
            "shop",
            "--commit",
            "c2",
            "--sarif",
            sarif.to_str().unwrap(),
            "--drift",
            drift.to_str().unwrap(),
        ],
    );
    assert_eq!(code, 5, "{r2}");
    assert_eq!(r2["outcome"], "gate_failed");
    assert_eq!(r2["baseline"], false);
    assert_eq!(r2["drift"]["since_job"], r1["job"]);
    let sarif: Value = serde_json::from_str(&std::fs::read_to_string(&sarif).unwrap()).unwrap();
    assert!(sarif["runs"].is_array());
    let drift: Value = serde_json::from_str(&std::fs::read_to_string(&drift).unwrap()).unwrap();
    assert!(
        drift["compare"]["new"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["alert_ref"].as_str().unwrap().starts_with("40018"))
    );

    // Another pipeline's token sending the same commit gets a scan of its own, not run 2's verdict;
    // nor does the baseline run's commit answer a gated trigger.
    let other = s.token("shop", "trigger");
    let (status, v) = s.trigger("shop", &other, json!({"commit": "c2"}));
    assert_eq!(status, 202, "deduplicated across tokens: {v}");
    s.wait_run("shop", &run_id(&v), &other);
    let (status, v) = s.trigger("shop", &tok, json!({"commit": "c1"}));
    assert_eq!(status, 202, "deduplicated to the baseline run: {v}");
    s.wait_run("shop", &run_id(&v), &tok);

    // 3: fixed again: passes; `latest` is this run.
    app.state.drift.store(false, Ordering::SeqCst);
    let (code, r3) = remote(&s, &tok, &["run", "--target", "shop", "--commit", "c3"]);
    assert_eq!(code, 0, "{r3}");
    let (_, latest) = s.get_public("/v1/targets/shop/latest", Some(&tok));
    assert_eq!(latest["data"]["run"], r3["run"]);
    // Even the same token sending a finished run's commit gets a new scan: the commit is a label,
    // and that run tested what was deployed then.
    let (status, v) = s.trigger("shop", &tok, json!({"commit": "c3"}));
    assert_eq!(status, 202, "a finished run was reused for its commit: {v}");
    s.wait_run("shop", &run_id(&v), &tok);

    // 4: the app lost most of its pages: coverage dropped, incomplete (2), never a pass.
    app.state.pages.store(0, Ordering::SeqCst);
    let (code, r4) = remote(&s, &tok, &["run", "--target", "shop", "--commit", "c4"]);
    assert_eq!(code, 2, "{r4}");
    assert_eq!(r4["state"], "incomplete");

    // Downloads come with headers that keep a report from running in the API's origin.
    let r3_id = r3["run"].as_str().unwrap();
    let resp = s
        .agent
        .get(&format!("{}/v1/targets/shop/runs/{r3_id}/report.html", s.url()))
        .header("Authorization", &format!("Bearer {tok}"))
        .call()
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(resp.headers().get("content-security-policy").unwrap(), "sandbox");
    assert!(resp.headers().get("content-disposition").unwrap().to_str().unwrap().starts_with("attachment"));
    assert_eq!(s.get_public(&format!("/v1/targets/shop/runs/{r3_id}/project.bpdb"), Some(&tok)).0, 404);
    assert_eq!(s.get_public(&format!("/v1/targets/shop/runs/{r3_id}/..%2Fproject.bpdb"), Some(&tok)).0, 404);
    assert!(dir.path().join("work/targets/shop/snapshots").read_dir().unwrap().count() >= 1);

    // Another target's id: the token is refused (403), exit 1.
    let (code, _) = remote(&s, &tok, &["run", "--target", "other"]);
    assert_eq!(code, 1);
}

#[test]
fn a_restart_mid_scan_waits_for_the_scan_again() {
    let Some((_dir, mut s)) = setup(&[]) else { return };
    let app = App::start(3);
    app.state.delay_ms.store(400, Ordering::SeqCst);
    s.register("long", &app, json!({}));
    let tok = s.token("long", "trigger");
    let (_, v) = s.trigger("long", &tok, json!({"commit": "c1"}));
    let run = run_id(&v);
    let before = s.wait_job("long", &run, &tok);
    s.kill();
    app.state.delay_ms.store(0, Ordering::SeqCst);
    s.spawn();
    let end = s.wait_run("long", &run, &tok);
    assert_eq!(end["job"], before["job"], "{end}");
    assert_eq!(end["state"], "completed", "{end}\n{}", s.log());
    assert!(end["reasons"].to_string().contains("restarted"), "{end}");
}

#[test]
fn secrets_reach_only_their_targets_scans() {
    let Some(real) = cli() else { return };
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path();
    // A CLI wrapper that records the environment of every call.
    std::fs::create_dir_all(p.join("envs")).unwrap();
    let shim = p.join("brainproxy-shim");
    std::fs::write(
        &shim,
        format!("#!/bin/sh\nenv > \"{}/$$\"\nexec \"{}\" \"$@\"\n", p.join("envs").display(), real.display()),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    std::fs::create_dir_all(p.join("secrets/one")).unwrap();
    std::fs::write(p.join("secrets/one/APP_PW"), "right\n").unwrap();
    // A server-side variable for target two, and one no target may see.
    let s = Server::start_with(
        p,
        &shim,
        &[],
        true,
        &[("TWO_PW_SOURCE", "two-secret"), ("SERVER_ONLY_SECRET", "nobody-sees-this")],
    );

    let app = App::start(1);
    let login = format!("{}login", app.url());
    s.register(
        "one",
        &app,
        json!({
            "auth": {"name": "user", "login_url": login, "login_body": "username={{username}}&password={{password}}",
                     "login_header": ["Content-Type: application/x-www-form-urlencoded"],
                     "username": "ci", "password_env": "APP_PW", "check_url": format!("{}me", app.url()),
                     "logged_in": "logged in as ci"},
            "secret_env": {"APP_PW": "ONE_PW_UNUSED"},
        }),
    );
    s.register("two", &app, json!({"secret_env": {"TWO_PW": "TWO_PW_SOURCE"}}));
    let t1 = s.token("one", "trigger");
    let t2 = s.token("two", "trigger");
    let (_, v) = s.trigger("one", &t1, json!({}));
    let end = s.wait_run("one", &run_id(&v), &t1);
    assert_eq!(end["state"], "completed", "the login with the file secret failed: {end}");
    let (_, v) = s.trigger("two", &t2, json!({}));
    s.wait_run("two", &run_id(&v), &t2);

    let allowed = [
        "PATH",
        "HOME",
        "BRAINPROXY_HOME",
        "TZ",
        "BRAINPROXY_SYSTEM_SCOPE",
        "APP_PW",
        "TWO_PW",
        "PWD",
        "SHLVL",
        "_",
        "OLDPWD",
    ];
    let (mut with_one, mut with_two) = (0, 0);
    for f in std::fs::read_dir(p.join("envs")).unwrap() {
        let text = std::fs::read_to_string(f.unwrap().path()).unwrap();
        assert!(!text.contains("nobody-sees-this"), "{text}");
        for line in text.lines() {
            let key = line.split('=').next().unwrap();
            assert!(allowed.contains(&key), "unexpected variable {key} in a CLI call");
        }
        let one = text.contains("APP_PW=right");
        let two = text.contains("TWO_PW=two-secret");
        assert!(!(one && two), "a CLI call saw both targets' secrets");
        with_one += usize::from(one);
        with_two += usize::from(two);
    }
    assert!(with_one > 0 && with_two > 0, "{with_one} {with_two}\n{}", s.log());
}

#[test]
fn rate_limits() {
    let Some((_dir, s)) = setup(&[]) else { return };
    let app = App::start(0);
    s.register("rl", &app, json!({}));
    let tok = s.token("rl", "trigger");
    // 30 failed authentications from one address, then 429 for more; a valid token (or the admin,
    // on its own listener) is never locked out by someone failing from the same address.
    for _ in 0..30 {
        assert_eq!(s.get_public("/v1/targets/rl", Some("bpt_rl_nope")).0, 401);
    }
    assert_eq!(s.get_public("/v1/targets/rl", Some("bpt_rl_nope")).0, 429);
    assert_eq!(s.get_public("/v1/targets/rl", Some(&tok)).0, 200);
    assert_eq!(s.admin("GET", "/v1/summary", None).0, 200);
    // Caller-chosen text in a refused token doesn't make audit lines long.
    let long = format!("bpt_{}_{}", "x".repeat(5000), "a".repeat(52));
    s.get_public("/v1/targets/rl", Some(&long));
    let (_, audit) = s.admin("GET", "/v1/audit?limit=1000", None);
    assert!(audit.to_string().len() < 100_000, "{} bytes", audit.to_string().len());
}

#[test]
fn trigger_rate_limit() {
    let Some((_dir, s)) = setup(&[]) else { return };
    let app = App::start(0);
    app.state.delay_ms.store(3000, Ordering::SeqCst);
    s.register("rl", &app, json!({}));
    let tok = s.token("rl", "trigger");
    for i in 0..10 {
        let (status, v) = s.trigger("rl", &tok, json!({"commit": format!("c{i}")}));
        assert!(status == 202 || status == 200, "{v}");
    }
    let (status, v) = s.trigger("rl", &tok, json!({"commit": "c10"}));
    assert_eq!(status, 429, "{v}");
}

// -- phase 3: OIDC, alert policies, ownership ---------------------------------------------------

/// An ES256 key, its JWKS, and a signer.
struct Issuer {
    pair: ring::signature::EcdsaKeyPair,
}

impl Issuer {
    fn new() -> Issuer {
        use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair};
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        Issuer { pair: EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng).unwrap() }
    }

    fn jwks(&self) -> String {
        use base64::Engine;
        use ring::signature::KeyPair;
        let b = |x: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(x);
        let point = self.pair.public_key().as_ref();
        json!({"keys": [{"kty": "EC", "crv": "P-256", "kid": "k1", "use": "sig", "alg": "ES256",
                         "x": b(&point[1..33]), "y": b(&point[33..65])}]})
        .to_string()
    }

    fn sign(&self, claims: Value) -> String {
        use base64::Engine;
        let b = |x: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(x);
        let h = b(json!({"alg": "ES256", "kid": "k1", "typ": "JWT"}).to_string().as_bytes());
        let p = b(claims.to_string().as_bytes());
        let sig = self.pair.sign(&ring::rand::SystemRandom::new(), format!("{h}.{p}").as_bytes()).unwrap();
        format!("{h}.{p}.{}", b(sig.as_ref()))
    }
}

fn unix_now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
}

#[test]
fn oidc_tokens_trigger_and_read_only_the_targets_that_bind_them() {
    let Some(cli) = cli() else { return };
    let dir = tempfile::tempdir().unwrap();
    let idp = App::start(0);
    let key = Issuer::new();
    idp.state.files.lock().unwrap().insert("/oauth/discovery/keys".into(), key.jwks());
    let iss = format!("http://{}", idp.host());
    let s = Server::start(
        dir.path(),
        &cli,
        &["--oidc-issuer", &format!("gitlab={iss}"), "--oidc-audience", "https://scan.corp.test"],
    );
    let app = App::start(1);

    // Bindings must name the immutable project id, and an issuer the server trusts.
    for bad in [
        json!([{"issuer": iss, "claims": {"ref": "main"}}]),
        json!([{"issuer": iss, "claims": {"project_id": "5"}}]),
        json!([{"issuer": "https://gitlab.elsewhere.test", "claims": {"project_id": "5"}}]),
    ] {
        let body = json!({"id": "bad", "base_url": app.url(), "scope": [app.host()], "oidc": bad});
        let (status, v) = s.admin("POST", "/v1/targets", Some(body));
        assert_eq!(status, 400, "{v}");
    }
    s.register("shop", &app, json!({"oidc": [{"issuer": iss, "claims": {"project_id": "5", "ref": "main"}}]}));
    s.register("other", &app, json!({}));

    let claims = |project: &str, aud: &str, exp: i64| {
        json!({"iss": iss, "aud": aud, "exp": unix_now() + exp, "iat": unix_now(),
               "sub": "project_path:acme/shop:ref_type:branch:ref:main", "project_path": "acme/shop",
               "project_id": project, "ref": "main", "pipeline_id": "77"})
    };
    let jwt = key.sign(claims("5", "https://scan.corp.test", 300));
    assert_eq!(s.get_public("/v1/targets/shop/runs", Some(&jwt)).0, 200);
    assert_eq!(s.get_public("/v1/targets/other/runs", Some(&jwt)).0, 401, "a target that doesn't bind it");
    assert_eq!(s.get_public("/v1/targets", Some(&jwt)).0, 401, "no target in the path");
    let other_project = key.sign(claims("6", "https://scan.corp.test", 300));
    assert_eq!(s.get_public("/v1/targets/shop/runs", Some(&other_project)).0, 401);
    let other_aud = key.sign(claims("5", "https://elsewhere.test", 300));
    assert_eq!(s.get_public("/v1/targets/shop/runs", Some(&other_aud)).0, 401);
    let expired = key.sign(claims("5", "https://scan.corp.test", -600));
    assert_eq!(s.get_public("/v1/targets/shop/runs", Some(&expired)).0, 401);
    let forged = Issuer::new().sign(claims("5", "https://scan.corp.test", 300));
    assert_eq!(s.get_public("/v1/targets/shop/runs", Some(&forged)).0, 401, "another key");
    // OIDC tokens mean nothing on the admin listener.
    assert_eq!(s.request("GET", s.admin, "/v1/targets", Some(&jwt), None).0, 401);

    // A pipeline holding the token (GitLab's id_tokens, named with --token-env) runs a scan.
    let (code, r) = remote(&s, &jwt, &["run", "--target", "shop", "--commit", "c1"]);
    assert_eq!(code, 0, "{r}\n{}", s.log());
    let (_, audit) = s.admin("GET", "/v1/audit?limit=100", None);
    let trigger = audit["data"]["audit"].as_array().unwrap().iter().find(|e| e["action"] == "trigger").unwrap();
    assert_eq!(trigger["actor_kind"], "oidc", "{trigger}");
    assert!(trigger["actor"].as_str().unwrap().contains("project_id=5"), "{trigger}");

    // Unbinding takes effect at once.
    let (status, v) = s.admin("PATCH", "/v1/targets/shop", Some(json!({"oidc": []})));
    assert_eq!(status, 200, "{v}");
    assert_eq!(s.get_public("/v1/targets/shop/runs", Some(&jwt)).0, 401);
    // Scope can't change this way.
    let (status, _) = s.admin("PATCH", "/v1/targets/shop", Some(json!({"scope": ["elsewhere.test"]})));
    assert_eq!(status, 400);
}

#[test]
fn alert_policies_and_the_ownership_check() {
    let Some((_dir, s)) = setup(&[]) else { return };
    let app = App::start(2);
    app.state.drift.store(true, Ordering::SeqCst);
    s.register("shop", &app, json!({"gate": {"fail_on": "high"}}));
    let tok = s.token("shop", "trigger");

    // Without a policy the high findings fail the gate.
    let (code, r1) = remote(&s, &tok, &["run", "--target", "shop", "--commit", "c1"]);
    assert_eq!(code, 5, "{r1}");
    let run = r1["run"].as_str().unwrap();
    let (_, cmp) = s.get_public(&format!("/v1/targets/shop/runs/{run}/compare.json"), Some(&tok));
    let findings: Vec<Value> =
        ["new", "unchanged"].iter().flat_map(|k| cmp["data"][k].as_array().cloned().unwrap_or_default()).collect();
    let id = |f: &Value| f["alert_ref"].as_str().unwrap().split('-').next().unwrap().to_string();
    let high: Vec<String> = findings.iter().filter(|f| f["risk"] == "high").map(id).collect();
    let low = findings.iter().find(|f| f["risk"] != "high").map(id).expect("a finding below high");
    assert!(!high.is_empty(), "{cmp}");

    // Ignoring the high rules lets it pass; the reasons say what the policy did.
    let ignore: serde_json::Map<String, Value> = high.iter().map(|r| (r.clone(), json!("ignore"))).collect();
    let (status, v) = s.admin("PATCH", "/v1/targets/shop", Some(json!({"policy": ignore})));
    assert_eq!(status, 200, "{v}");
    let (code, r2) = remote(&s, &tok, &["run", "--target", "shop", "--commit", "c2"]);
    assert_eq!(code, 0, "{r2}");
    assert!(r2["reasons"].as_array().unwrap().iter().any(|r| r.as_str().unwrap().starts_with("policy:")), "{r2}");

    // A fail rule fails the gate below the risk threshold.
    let mut policy = ignore.clone();
    policy.insert(low.clone(), json!("fail"));
    assert_eq!(s.admin("PATCH", "/v1/targets/shop", Some(json!({"policy": policy}))).0, 200);
    let (code, r3) = remote(&s, &tok, &["run", "--target", "shop", "--commit", "c3"]);
    assert_eq!(code, 5, "{r3}");
    let bad = s.admin("PATCH", "/v1/targets/shop", Some(json!({"policy": {"x10020": "ignore"}})));
    assert_eq!(bad.0, 400, "{}", bad.1);

    // Ownership: the target must serve the token before a scan starts.
    let (status, v) = s.admin("PATCH", "/v1/targets/shop", Some(json!({"ownership": true, "policy": {}})));
    assert_eq!(status, 200, "{v}");
    let owner_token = v["data"]["ownership_token"].as_str().unwrap().to_string();
    assert!(owner_token.starts_with("bpo_"));
    let (code, r4) = remote(&s, &tok, &["run", "--target", "shop", "--commit", "c4"]);
    assert_eq!(code, 6, "{r4}");
    assert!(r4["reasons"].to_string().contains("ownership check"), "{r4}");
    app.state.files.lock().unwrap().insert("/.well-known/brainproxy-shop.txt".into(), format!("{owner_token}\n"));
    let (code, r5) = remote(&s, &tok, &["run", "--target", "shop", "--commit", "c5"]);
    assert_eq!(code, 5, "the scan ran and gated again: {r5}");
    // The token stays the same while ownership stays on.
    let (_, v) = s.admin("PATCH", "/v1/targets/shop", Some(json!({"ownership": true})));
    assert_eq!(v["data"]["ownership_token"], owner_token.as_str());
}

#[cfg(feature = "object-store")]
#[test]
fn a_fresh_work_directory_is_restored_from_the_store() {
    let Some(cli) = cli() else { return };
    let dir = tempfile::tempdir().unwrap();
    let bucket = dir.path().join("bucket");
    let store = format!("file://{}/brainproxy", bucket.display());
    let app = App::start(4);

    // The first server: a baseline run, then a container stop.
    let mut one = Server::start(&dir.path().join("one"), &cli, &["--store", &store]);
    one.register("shop", &app, json!({"gate": {"fail_on": "high", "new_only": true}}));
    let tok = one.token("shop", "trigger");
    assert_eq!(one.admin("POST", "/v1/targets/shop/next-run", Some(json!({"baseline": true}))).0, 200);
    let (code, r1) = remote(&one, &tok, &["run", "--target", "shop", "--commit", "c1"]);
    assert_eq!(code, 0, "{r1}");
    one.stop();
    let run1 = r1["run"].as_str().unwrap();
    let objects = bucket.join("brainproxy");
    for f in ["control.db", "targets/shop/project.bpdb", &format!("targets/shop/runs/{run1}/run.json")] {
        assert!(objects.join(f).is_file(), "{f} isn't in the store: {}", one.log());
    }

    // A new server on an empty disk: the target, its token and its history come back, so the next
    // run compares with run 1.
    let two = Server::start(&dir.path().join("two"), &cli, &["--store", &store]);
    assert!(two.log().contains("restored control.db and 1 target"), "{}", two.log());
    let (status, runs) = two.get_public("/v1/targets/shop/runs", Some(&tok));
    assert_eq!(status, 200, "{runs}");
    assert!(runs.to_string().contains(run1), "{runs}");
    let (code, r2) = remote(&two, &tok, &["run", "--target", "shop", "--commit", "c2"]);
    assert_eq!(code, 0, "{r2}\n{}", two.log());
    assert_eq!(r2["drift"]["since_job"], r1["job"], "{r2}");
    assert!(r2["drift"]["unchanged"].as_u64().unwrap() > 0, "{r2}");

    // Removing the target removes its objects.
    assert_eq!(two.admin("DELETE", "/v1/targets/shop", None).0, 200);
    let start = Instant::now();
    while objects.join("targets/shop/project.bpdb").exists() {
        assert!(start.elapsed() < Duration::from_secs(30), "objects stayed: {}", two.log());
        std::thread::sleep(Duration::from_millis(200));
    }
}
