//! `brainproxy-server remote run|wait`: what a pipeline runs to trigger a scan on a server, wait for
//! it, and exit with the CLI's codes (research §4.6). No brainproxy CLI is involved.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use crate::brainproxy::code;

/// The server was unreachable, or kept failing.
const UNREACHABLE: i32 = 3;
/// How long to keep retrying a server that doesn't answer before giving up with exit 3.
const RETRY_FOR: Duration = Duration::from_secs(120);
/// `?wait=` per status request.
const WAIT_SECS: u64 = 60;

#[derive(Debug, Clone)]
pub struct Args {
    pub server: String,
    pub target: String,
    pub token_env: String,
    /// `wait` only: the run to wait for.
    pub run: Option<String>,
    pub commit: Option<String>,
    pub git_ref: Option<String>,
    pub pipeline_url: Option<String>,
    pub preset: Option<String>,
    pub idempotency_key: Option<String>,
    pub timeout: Duration,
    pub detach: bool,
    pub sarif: Option<PathBuf>,
    pub html: Option<PathBuf>,
    pub json: Option<PathBuf>,
    pub drift: Option<PathBuf>,
}

struct Client {
    agent: ureq::Agent,
    base: String,
    token: String,
}

/// An HTTP answer: status and envelope.
struct Answer {
    status: u16,
    body: Value,
}

impl Answer {
    fn message(&self) -> String {
        self.body["error"]["message"].as_str().map_or_else(|| format!("HTTP {}", self.status), String::from)
    }
}

impl Client {
    fn new(args: &Args) -> Result<Client, (i32, String)> {
        let token = std::env::var(&args.token_env)
            .ok()
            .map(|t| t.trim().to_string())
            .filter(|t| !t.is_empty())
            .ok_or((code::USAGE, format!("no token: set the environment variable {}", args.token_env)))?;
        let base = args.server.trim_end_matches('/').to_string();
        if !(base.starts_with("https://") || base.starts_with("http://")) {
            return Err((code::USAGE, "--server must be an http(s) URL".into()));
        }
        if base.starts_with("http://") && !is_local(&base) {
            eprintln!("brainproxy-server: warning: {base} is plain HTTP; the token crosses the network unencrypted");
        }
        let tls = ureq::tls::TlsConfig::builder().root_certs(ureq::tls::RootCerts::PlatformVerifier).build();
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .timeout_global(Some(Duration::from_secs(WAIT_SECS + 30)))
            .tls_config(tls)
            .user_agent(concat!("brainproxy-server-remote/", env!("CARGO_PKG_VERSION")))
            .build()
            .into();
        Ok(Client { agent, base, token })
    }

    fn target_path(&self, target: &str, rest: &str) -> String {
        format!("{}/v1/targets/{target}{rest}", self.base)
    }

    /// One request; `Err` only for a transport failure (no HTTP answer).
    fn send(&self, method: &str, url: &str, body: Option<&Value>, key: Option<&str>) -> Result<Answer, String> {
        let auth = format!("Bearer {}", self.token);
        let resp = match method {
            "POST" => {
                let mut req = self.agent.post(url).header("Authorization", &auth);
                if let Some(k) = key {
                    req = req.header("Idempotency-Key", k);
                }
                req.send_json(body.cloned().unwrap_or(json!({})))
            }
            _ => self.agent.get(url).header("Authorization", &auth).call(),
        };
        let mut resp = resp.map_err(|e| e.to_string())?;
        let status = resp.status().as_u16();
        let text = resp.body_mut().read_to_string().unwrap_or_default();
        Ok(Answer { status, body: serde_json::from_str(&text).unwrap_or(Value::Null) })
    }

    /// [`Client::send`], retrying transport failures, 5xx and 429 for [`RETRY_FOR`].
    fn send_retrying(
        &self,
        method: &str,
        url: &str,
        body: Option<&Value>,
        key: Option<&str>,
    ) -> Result<Answer, (i32, String)> {
        let start = Instant::now();
        let mut pause = Duration::from_secs(2);
        loop {
            let (retry, last) = match self.send(method, url, body, key) {
                // A trigger refused for its rate limit won't be let through within the retry window.
                Ok(a) if (a.status == 429 && method == "GET") || a.status >= 500 => (true, a.message()),
                Ok(a) => return Ok(a),
                Err(e) => (true, e),
            };
            if !retry || start.elapsed() + pause > RETRY_FOR {
                return Err((UNREACHABLE, format!("{} {url}: {last}", method)));
            }
            eprintln!("brainproxy-server: {last}; retrying in {}s", pause.as_secs());
            std::thread::sleep(pause);
            pause = (pause * 2).min(Duration::from_secs(30));
        }
    }

    fn download(&self, url: &str, to: &PathBuf) -> Result<(), String> {
        let mut resp = self
            .agent
            .get(url)
            .header("Authorization", &format!("Bearer {}", self.token))
            .call()
            .map_err(|e| e.to_string())?;
        if resp.status().as_u16() != 200 {
            let text = resp.body_mut().read_to_string().unwrap_or_default();
            let v: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
            return Err(v["error"]["message"].as_str().map_or_else(|| format!("HTTP {}", resp.status()), String::from));
        }
        let bytes = resp.body_mut().with_config().limit(1 << 30).read_to_vec().map_err(|e| e.to_string())?;
        std::fs::write(to, bytes).map_err(|e| format!("{}: {e}", to.display()))
    }
}

fn is_local(url: &str) -> bool {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    rest.starts_with("localhost") || rest.starts_with("127.") || rest.starts_with("[::1]")
}

/// The exit code for an HTTP refusal.
fn refusal_code(a: &Answer) -> i32 {
    match a.status {
        404 => code::NOT_FOUND,
        400 => code::USAGE,
        _ => code::ERROR,
    }
}

/// `remote run`: triggers a run, then waits like `remote wait`.
pub fn run(args: Args) -> i32 {
    let client = match Client::new(&args) {
        Ok(c) => c,
        Err((c, m)) => return fail(c, &m),
    };
    let mut body = serde_json::Map::new();
    for (k, v) in [
        ("commit", &args.commit),
        ("ref", &args.git_ref),
        ("pipeline_url", &args.pipeline_url),
        ("preset", &args.preset),
    ] {
        if let Some(v) = v {
            body.insert(k.into(), json!(v));
        }
    }
    // Without a commit, a key per invocation still makes a retried POST start one run, not two.
    // A fresh key per invocation: a retried POST starts one run, not two, and no other caller can
    // guess it to be answered with this run.
    let key = Some(
        args.idempotency_key
            .clone()
            .unwrap_or_else(|| crate::serve::auth::base32(&crate::serve::auth::random_bytes::<16>())),
    );
    let url = client.target_path(&args.target, "/runs");
    let answer = match client.send_retrying("POST", &url, Some(&Value::Object(body)), key.as_deref()) {
        Ok(a) => a,
        Err((c, m)) => return fail(c, &m),
    };
    if answer.status != 200 && answer.status != 202 {
        return fail(refusal_code(&answer), &format!("trigger refused: {}", answer.message()));
    }
    let data = &answer.body["data"];
    let Some(run) = data["run"].as_str().map(String::from) else {
        return fail(code::ERROR, "the server's answer has no run id");
    };
    if data["deduplicated"] == true {
        eprintln!(
            "brainproxy-server: run {run} ({}) is already queued for this {}",
            data["state"].as_str().unwrap_or("?"),
            if data["deduplicated_by"] == "commit" { "commit" } else { "idempotency key" }
        );
    } else {
        eprintln!("brainproxy-server: queued run {run} of {}", args.target);
    }
    if let Some(old) = data["superseded"].as_str() {
        eprintln!("brainproxy-server: it replaced queued run {old}, which ends as superseded");
    }
    if args.detach {
        println!("{}", serde_json::to_string_pretty(data).unwrap_or_default());
        return code::OK;
    }
    wait_for(&client, &args, &run)
}

/// `remote wait`: waits for a run and exits with its exit code.
pub fn wait(args: Args) -> i32 {
    let client = match Client::new(&args) {
        Ok(c) => c,
        Err((c, m)) => return fail(c, &m),
    };
    let Some(run) = args.run.clone() else { return fail(code::USAGE, "--run is required") };
    wait_for(&client, &args, &run)
}

fn wait_for(client: &Client, args: &Args, run: &str) -> i32 {
    let url = client.target_path(&args.target, &format!("/runs/{run}"));
    let start = Instant::now();
    let mut last_line = String::new();
    let data = loop {
        let left = args.timeout.saturating_sub(start.elapsed());
        if left.is_zero() {
            return fail(
                code::USAGE,
                &format!(
                    "--timeout reached; run {run} goes on. Pick it up with `remote wait --target {} --run {run}`",
                    args.target
                ),
            );
        }
        let wait = left.as_secs().clamp(1, WAIT_SECS);
        let answer = match client.send_retrying("GET", &format!("{url}?wait={wait}"), None, None) {
            Ok(a) => a,
            Err((c, m)) => return fail(c, &m),
        };
        if answer.status != 200 {
            return fail(refusal_code(&answer), &format!("run {run}: {}", answer.message()));
        }
        let data = answer.body["data"].clone();
        let st = data["state"].as_str().unwrap_or("?");
        if st != "queued" && st != "running" {
            break data;
        }
        let line = match (st, data["position"].as_i64(), data["job"].as_u64()) {
            ("queued", Some(p), _) => format!("run {run} queued (position {p})"),
            (_, _, Some(j)) => format!("run {run} running (job {j})"),
            _ => format!("run {run} {st}"),
        };
        if line != last_line {
            eprintln!("brainproxy-server: {line}");
            last_line = line;
        }
    };

    let exit = data["exit_code"].as_i64().map_or(code::ERROR, |c| c as i32);
    eprintln!("brainproxy-server: {}", summary_line(&data));
    for r in data["reasons"].as_array().into_iter().flatten().filter_map(Value::as_str) {
        eprintln!("  - {r}");
    }
    let wanted = [("report.sarif", &args.sarif), ("report.html", &args.html), ("report.json", &args.json)];
    for (file, to) in wanted {
        if let Some(to) = to {
            match client.download(&format!("{url}/{file}"), to) {
                Ok(()) => eprintln!("brainproxy-server: wrote {}", to.display()),
                Err(e) => eprintln!("brainproxy-server: warning: no {file}: {e}"),
            }
        }
    }
    if let Some(to) = &args.drift {
        match client.send_retrying("GET", &format!("{url}/drift"), None, None) {
            Ok(a) if a.status == 200 => {
                let text = serde_json::to_string_pretty(&a.body["data"]).unwrap_or_default();
                match std::fs::write(to, text) {
                    Ok(()) => eprintln!("brainproxy-server: wrote {}", to.display()),
                    Err(e) => eprintln!("brainproxy-server: warning: {}: {e}", to.display()),
                }
            }
            Ok(a) => eprintln!("brainproxy-server: warning: no drift: {}", a.message()),
            Err((_, m)) => eprintln!("brainproxy-server: warning: no drift: {m}"),
        }
    }
    println!("{}", serde_json::to_string_pretty(&data).unwrap_or_default());
    exit
}

fn summary_line(d: &Value) -> String {
    let state = d["state"].as_str().unwrap_or("?");
    let mut line = match (state, d["outcome"].as_str()) {
        ("completed", Some("passed")) => "passed".to_string(),
        ("completed", Some("gate_failed")) => "gate failed".to_string(),
        (s, _) => s.to_string(),
    };
    line.push_str(&format!(" (run {}", d["run"].as_str().unwrap_or("?")));
    if let Some(j) = d["job"].as_u64() {
        line.push_str(&format!(", job {j}"));
    }
    if let Some(p) = d["drift"]["since_job"].as_u64() {
        line.push_str(&format!(", new since job {p}"));
    }
    line.push(')');
    if d["drift"].is_object() {
        let n = |k: &str| d["drift"][k].as_u64().unwrap_or(0);
        line.push_str(&format!(": {} new, {} unchanged, {} fixed", n("new"), n("unchanged"), n("fixed")));
    }
    line
}

fn fail(code: i32, message: &str) -> i32 {
    eprintln!("brainproxy-server: {message}");
    code
}

/// `90s`, `45m`, `2h`, or a number of minutes.
pub fn parse_duration(s: &str) -> Result<Duration, String> {
    let s = s.trim();
    let (num, unit) = s.find(|c: char| !c.is_ascii_digit()).map_or((s, "m"), |i| s.split_at(i));
    let n: u64 = num.parse().map_err(|_| format!("bad duration {s:?}: use e.g. 90s, 45m or 2h"))?;
    let secs = match unit {
        "s" => n,
        "m" => n * 60,
        "h" => n * 3600,
        _ => return Err(format!("bad duration {s:?}: use e.g. 90s, 45m or 2h")),
    };
    Ok(Duration::from_secs(secs))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations() {
        assert_eq!(parse_duration("90s").unwrap(), Duration::from_secs(90));
        assert_eq!(parse_duration("45m").unwrap(), Duration::from_secs(2700));
        assert_eq!(parse_duration("2h").unwrap(), Duration::from_secs(7200));
        assert_eq!(parse_duration("30").unwrap(), Duration::from_secs(1800));
        assert!(parse_duration("1d").is_err());
        assert!(parse_duration("m").is_err());
    }

    #[test]
    fn summary_lines() {
        let d = json!({"state": "completed", "outcome": "gate_failed", "run": "r-1", "job": 7,
                       "drift": {"new": 2, "unchanged": 14, "fixed": 1, "since_job": 5}});
        assert_eq!(summary_line(&d), "gate failed (run r-1, job 7, new since job 5): 2 new, 14 unchanged, 1 fixed");
        assert_eq!(summary_line(&json!({"state": "superseded", "run": "r-2"})), "superseded (run r-2)");
    }
}
