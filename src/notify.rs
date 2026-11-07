//! Run notifications (PLAN.md phase 4): signed webhooks, Slack and Teams messages, and a DefectDojo
//! reimport of each completed run's SARIF report.
//!
//! `serve` sends them after a run's end is recorded, in tasks of their own (`serve::notify`), and
//! stateless `ci --notify` after its run: a slow or failing receiver never delays or changes a run. Failures go to stderr and the audit log, without URLs or secrets.
//! Webhook URLs are secrets themselves (a Slack or Teams URL is its own credential), so a target's
//! configuration names the secret that holds one, never the URL.

use std::io::Read;
use std::sync::Arc;
use std::time::Duration;

use ring::hmac;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::serve::db::{RunRow, state};
use crate::serve::{auth, oidc};
use crate::target::TargetConfig;
use crate::target::valid_secret_var;
use crate::time;

/// The most hooks a target may have.
pub const MAX_HOOKS: usize = 5;
/// New findings listed in a generic webhook; chat messages list fewer.
const MAX_LISTED: usize = 20;
const CHAT_LISTED: usize = 10;
/// Waits between the three attempts of a delivery (after a network error, 5xx or 429).
const BACKOFF_SECS: [u64; 2] = [1, 5];
/// A report bigger than this isn't sent to DefectDojo (its own default limit is 100 MB).
const MAX_REPORT_BYTES: u64 = 100 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookKind {
    /// JSON signed with HMAC-SHA256 (see the README for how receivers check it).
    Generic,
    /// A Slack incoming webhook.
    Slack,
    /// A Microsoft Teams Workflows webhook ("Post to a channel when a webhook request is received").
    Teams,
}

/// How a run ended, as hooks filter on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Event {
    Passed,
    GateFailed,
    Incomplete,
    Error,
    Cancelled,
}

impl Event {
    /// The event of a run's end; none for a run that hasn't ended or was superseded in the queue.
    pub fn of(state: &str, outcome: Option<&str>) -> Option<Event> {
        match (state, outcome) {
            (state::COMPLETED, Some("passed")) => Some(Event::Passed),
            (state::COMPLETED, _) => Some(Event::GateFailed),
            (state::INCOMPLETE, _) => Some(Event::Incomplete),
            (state::FAILED, _) => Some(Event::Error),
            (state::CANCELLED, _) => Some(Event::Cancelled),
            _ => None,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Event::Passed => "passed",
            Event::GateFailed => "gate_failed",
            Event::Incomplete => "incomplete",
            Event::Error => "error",
            Event::Cancelled => "cancelled",
        }
    }

    fn headline(self) -> &'static str {
        match self {
            Event::Passed => "Passed",
            Event::GateFailed => "Gate failed",
            Event::Incomplete => "Incomplete",
            Event::Error => "Error",
            Event::Cancelled => "Cancelled",
        }
    }
}

/// One webhook of a target.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hook {
    pub kind: HookKind,
    /// The secret holding the URL: `<secrets dir>/<target>/<NAME>`, else the server's variable NAME.
    pub url_secret: String,
    /// Generic hooks only: the secret holding the HMAC key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
    /// The ends to send; by default every one but `passed`.
    #[serde(default = "default_on")]
    pub on: Vec<Event>,
}

fn default_on() -> Vec<Event> {
    vec![Event::GateFailed, Event::Incomplete, Event::Error, Event::Cancelled]
}

/// A DefectDojo reimport (`/api/v2/reimport-scan/`) after each completed run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DefectDojo {
    /// The DefectDojo base URL, e.g. `https://dojo.example.test`.
    pub url: String,
    /// The secret holding the API v2 key.
    pub token_secret: String,
    pub product_name: String,
    pub engagement_name: String,
    /// Default: `brainproxy <target>`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub test_title: Option<String>,
    /// The report sent is `report.sarif`, so `SARIF` is the only type.
    #[serde(default = "default_scan_type")]
    pub scan_type: String,
    #[serde(default = "yes")]
    pub close_old_findings: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minimum_severity: Option<String>,
}

fn default_scan_type() -> String {
    "SARIF".into()
}

fn yes() -> bool {
    true
}

const SEVERITIES: [&str; 5] = ["Info", "Low", "Medium", "High", "Critical"];

/// Checks a target's hooks and DefectDojo settings (the secrets themselves are read at send time).
pub fn check(hooks: &[Hook], dojo: Option<&DefectDojo>) -> Result<(), String> {
    if hooks.len() > MAX_HOOKS {
        return Err(format!("at most {MAX_HOOKS} notify hooks"));
    }
    let bad_name = |what: &str, name: &str| {
        format!("{what} {name}: names must be A-Z, 0-9 and _, and not one the CLI or the system uses")
    };
    for (i, h) in hooks.iter().enumerate() {
        let n = i + 1;
        if !valid_secret_var(&h.url_secret) {
            return Err(bad_name(&format!("notify hook {n}: url_secret"), &h.url_secret));
        }
        match (h.kind, &h.secret) {
            (HookKind::Generic, None) => {
                return Err(format!("notify hook {n}: a generic hook needs secret, the HMAC key's secret"));
            }
            (HookKind::Generic, Some(s)) if !valid_secret_var(s) => {
                return Err(bad_name(&format!("notify hook {n}: secret"), s));
            }
            (HookKind::Slack | HookKind::Teams, Some(_)) => {
                return Err(format!(
                    "notify hook {n}: secret is for generic hooks; Slack and Teams URLs are the credential"
                ));
            }
            _ => {}
        }
        if h.on.is_empty() {
            return Err(format!(
                "notify hook {n}: on must name at least one of passed, gate_failed, incomplete, error, cancelled"
            ));
        }
    }
    let Some(d) = dojo else { return Ok(()) };
    let base = d.url.trim_end_matches('/');
    let authority = base.split_once("://").map_or("", |(_, r)| r.split('/').next().unwrap_or(""));
    if !oidc::secure_url(base)
        || base.len() > 500
        || authority.is_empty()
        || authority.contains('@')
        || base.contains(['?', '#'])
        || base.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return Err("defectdojo.url must be an https:// URL (http only to this machine), without a query".into());
    }
    if !valid_secret_var(&d.token_secret) {
        return Err(bad_name("defectdojo.token_secret", &d.token_secret));
    }
    let texts = [("product_name", Some(&d.product_name)), ("engagement_name", Some(&d.engagement_name))];
    for (name, value) in texts.into_iter().chain([("test_title", d.test_title.as_ref())]) {
        if let Some(v) = value
            && (v.trim().is_empty() || v.len() > 200 || v.chars().any(char::is_control))
        {
            return Err(format!("defectdojo.{name} must be 1-200 characters"));
        }
    }
    if d.scan_type != "SARIF" {
        return Err("defectdojo.scan_type must be SARIF: the server sends the run's report.sarif".into());
    }
    if let Some(s) = &d.minimum_severity
        && !SEVERITIES.contains(&s.as_str())
    {
        return Err(format!("defectdojo.minimum_severity must be one of {}", SEVERITIES.join(", ")));
    }
    Ok(())
}

// -- sending ----------------------------------------------------------------------------------------

/// How one delivery went.
#[derive(Debug, Clone)]
pub struct Delivery {
    /// `notify` (a webhook) or `defectdojo`.
    pub action: &'static str,
    /// `hook 2 (slack)` or `reimport`.
    pub what: String,
    /// The HTTP status, or why it failed (no URLs or secrets in it).
    pub result: Result<u16, String>,
}

/// Sends `note` to the target's hooks that want its event, and the run's SARIF report (in `dir`)
/// to DefectDojo for a completed run. Secrets come from `<secrets_dir>/<target>/<NAME>`, else the
/// variable NAME. A failure's answer excerpt goes to stderr.
pub async fn deliver(
    t: &TargetConfig,
    note: Arc<Note>,
    dir: &std::path::Path,
    secrets_dir: &std::path::Path,
) -> Vec<Delivery> {
    let event = note.event;
    let mut tasks = Vec::new();
    for (i, hook) in t.notify.iter().enumerate().filter(|(_, h)| h.on.contains(&event)) {
        let (note, hook, secrets_dir) = (note.clone(), hook.clone(), secrets_dir.to_path_buf());
        tasks.push(tokio::spawn(async move {
            let what = format!("hook {} ({})", i + 1, kind_name(hook.kind));
            let result = match secrets_of(&secrets_dir, &note.target, &hook) {
                Ok((url, key)) => {
                    let body = match hook.kind {
                        HookKind::Generic => note.generic(),
                        HookKind::Slack => note.slack(),
                        HookKind::Teams => note.teams(),
                    };
                    blocking(move || send_hook(&url, key.as_deref(), &body.to_string())).await
                }
                Err(e) => Err(Failure::short(e)),
            };
            outcome(&note, "notify", what, result)
        }));
    }
    let mut out = Vec::new();
    for task in tasks {
        if let Ok(d) = task.await {
            out.push(d);
        }
    }
    if let Some(dojo) = t.defectdojo.clone()
        && event_completed(event)
    {
        let result = match secret(secrets_dir, &t.id, &dojo.token_secret) {
            Ok(token) => {
                let report = dir.join("report.sarif");
                let test_title = dojo.test_title.clone().unwrap_or_else(|| format!("brainproxy {}", t.id));
                blocking(move || reimport(&dojo, &token, &test_title, &report)).await
            }
            Err(e) => Err(Failure::short(e)),
        };
        out.push(outcome(&note, "defectdojo", "reimport".into(), result));
    }
    out
}

/// A delivery's result, its answer excerpt (on failure) printed to stderr.
fn outcome(note: &Note, action: &'static str, what: String, result: Result<u16, Failure>) -> Delivery {
    let result = result.map_err(|f| {
        let more = if f.body.is_empty() { String::new() } else { format!(": {}", f.body) };
        eprintln!("brainproxy-server: {action} {what} for run {} of {}: {}{more}", note.run, note.target, f.short);
        f.short
    });
    Delivery { action, what, result }
}

fn event_completed(e: Event) -> bool {
    matches!(e, Event::Passed | Event::GateFailed)
}

fn kind_name(k: HookKind) -> &'static str {
    match k {
        HookKind::Generic => "generic",
        HookKind::Slack => "slack",
        HookKind::Teams => "teams",
    }
}

/// Why a delivery failed: `short` for the audit log, `body` (an excerpt of the answer) for stderr.
#[derive(Debug)]
struct Failure {
    short: String,
    body: String,
}

impl Failure {
    fn short(s: String) -> Failure {
        Failure { short: s, body: String::new() }
    }
}

async fn blocking(f: impl FnOnce() -> Result<u16, Failure> + Send + 'static) -> Result<u16, Failure> {
    tokio::task::spawn_blocking(f).await.unwrap_or_else(|e| Err(Failure::short(format!("internal error: {e}"))))
}

/// A secret NAME of a target, as `project::secrets` reads them: the file
/// `<secrets dir>/<target>/<NAME>`, else this process's environment variable NAME.
fn secret(secrets_dir: &std::path::Path, target: &str, name: &str) -> Result<String, String> {
    let file = secrets_dir.join(target).join(name);
    let value = match std::fs::read_to_string(&file) {
        Ok(v) => v.trim_end_matches(['\r', '\n']).to_string(),
        Err(_) => std::env::var(name).unwrap_or_default(),
    };
    if value.is_empty() {
        eprintln!(
            "brainproxy-server: secret {name} of target {target} isn't set: no file {} and no variable {name}",
            file.display()
        );
        return Err(format!("secret {name} isn't set (see the server log)"));
    }
    Ok(value)
}

fn secrets_of(secrets_dir: &std::path::Path, target: &str, hook: &Hook) -> Result<(String, Option<String>), String> {
    let url = secret(secrets_dir, target, &hook.url_secret)?;
    if !oidc::secure_url(&url) {
        return Err(format!("the URL in {} must be https:// (http only to this machine)", hook.url_secret));
    }
    let key = hook.secret.as_deref().map(|s| secret(secrets_dir, target, s)).transpose()?;
    Ok((url, key))
}

/// No redirects (a 3xx is a failure), no status errors, the given time limit. Proxies come from
/// the environment, as for the OIDC key fetches.
fn agent(timeout: Duration) -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(timeout))
        .max_redirects(0)
        .http_status_as_error(false)
        .user_agent(concat!("brainproxy-server/", env!("CARGO_PKG_VERSION")))
        .build()
        .into()
}

/// Up to three attempts, after network errors, 5xx and 429. Returns the 2xx status.
fn with_retries(
    retry_timeouts: bool,
    mut send: impl FnMut() -> Result<ureq::http::Response<ureq::Body>, ureq::Error>,
) -> Result<u16, Failure> {
    let mut last = Failure::short(String::new());
    for attempt in 0..=BACKOFF_SECS.len() {
        if attempt > 0 {
            std::thread::sleep(Duration::from_secs(BACKOFF_SECS[attempt - 1]));
        }
        match send() {
            Ok(mut resp) => {
                let status = resp.status().as_u16();
                if (200..300).contains(&status) {
                    return Ok(status);
                }
                let mut buf = Vec::new();
                let _ = resp.body_mut().as_reader().take(1024).read_to_end(&mut buf);
                let body: String =
                    String::from_utf8_lossy(&buf).chars().filter(|c| !c.is_control()).take(300).collect();
                last = Failure { short: format!("HTTP {status}"), body };
                if status < 500 && status != 429 {
                    return Err(last);
                }
            }
            // A timed-out upload may still be processed: sending it again would import it twice.
            Err(e @ ureq::Error::Timeout(_)) if !retry_timeouts => return Err(Failure::short(describe(&e))),
            Err(e) => last = Failure::short(describe(&e)),
        }
    }
    last.short = format!("{} after {} attempts", last.short, BACKOFF_SECS.len() + 1);
    Err(last)
}

/// A ureq error without the URL it may carry.
fn describe(e: &ureq::Error) -> String {
    match e {
        ureq::Error::Timeout(_) => "timed out".into(),
        ureq::Error::HostNotFound => "host not found".into(),
        ureq::Error::ConnectionFailed => "connection failed".into(),
        ureq::Error::Io(e) => format!("network error ({})", e.kind()),
        ureq::Error::Tls(m) => format!("TLS: {m}"),
        ureq::Error::Rustls(e) => format!("TLS: {e}"),
        _ => "request failed".into(),
    }
}

fn send_hook(url: &str, key: Option<&str>, body: &str) -> Result<u16, Failure> {
    let agent = agent(Duration::from_secs(10));
    let delivery = format!("d-{}", auth::base32(&auth::random_bytes::<10>()));
    with_retries(true, || {
        let mut req =
            agent.post(url).header("Content-Type", "application/json").header("X-Brainproxy-Delivery", &delivery);
        if let Some(key) = key {
            // Signed again on each attempt, with a fresh time.
            let ts = time::now_millis() / 1000;
            req = req
                .header("X-Brainproxy-Timestamp", ts.to_string())
                .header("X-Brainproxy-Signature", format!("sha256={}", sign(key.as_bytes(), ts, body.as_bytes())));
        }
        req.send(body.as_bytes())
    })
}

/// Hex HMAC-SHA256 of `<timestamp>.<body>`.
pub fn sign(key: &[u8], timestamp: i64, body: &[u8]) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA256, key);
    let mut ctx = hmac::Context::with_key(&key);
    ctx.update(timestamp.to_string().as_bytes());
    ctx.update(b".");
    ctx.update(body);
    ctx.sign().as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

fn reimport(dojo: &DefectDojo, token: &str, test_title: &str, report: &std::path::Path) -> Result<u16, Failure> {
    let size = std::fs::metadata(report).map_err(|_| Failure::short("the run has no report.sarif".into()))?.len();
    if size > MAX_REPORT_BYTES {
        return Err(Failure::short(format!("report.sarif is {} MB, over the 100 MB limit", size / (1024 * 1024))));
    }
    let file = std::fs::read(report).map_err(|e| Failure::short(format!("reading report.sarif: {e}")))?;
    let close = if dojo.close_old_findings { "true" } else { "false" };
    let mut fields = vec![
        ("scan_type", dojo.scan_type.as_str()),
        ("product_name", dojo.product_name.as_str()),
        ("engagement_name", dojo.engagement_name.as_str()),
        ("test_title", test_title),
        ("auto_create_context", "true"),
        ("close_old_findings", close),
        ("active", "true"),
        ("verified", "false"),
    ];
    if let Some(s) = &dojo.minimum_severity {
        fields.push(("minimum_severity", s));
    }
    let (boundary, body) = multipart(&fields, "report.sarif", "application/json", &file);
    let url = format!("{}/api/v2/reimport-scan/", dojo.url.trim_end_matches('/'));
    if !oidc::secure_url(&url) {
        return Err(Failure::short("defectdojo.url must be https://".into()));
    }
    let agent = agent(Duration::from_secs(300));
    with_retries(false, || {
        agent
            .post(&url)
            .header("Authorization", &format!("Token {token}"))
            .header("Content-Type", &format!("multipart/form-data; boundary={boundary}"))
            .header("Accept", "application/json")
            .send(&body[..])
    })
}

/// A `multipart/form-data` body: text fields, then the file as `file`. Returns (boundary, body).
pub fn multipart(fields: &[(&str, &str)], filename: &str, content_type: &str, file: &[u8]) -> (String, Vec<u8>) {
    let contains = |hay: &[u8], needle: &[u8]| hay.windows(needle.len()).any(|w| w == needle);
    let boundary = loop {
        let b = format!("brainproxy-{}", auth::base32(&auth::random_bytes::<20>()));
        let clash = contains(file, b.as_bytes()) || fields.iter().any(|(_, v)| contains(v.as_bytes(), b.as_bytes()));
        if !clash {
            break b;
        }
    };
    let mut body = Vec::with_capacity(file.len() + 1024);
    for (name, value) in fields {
        body.extend_from_slice(
            format!("--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n").as_bytes(),
        );
    }
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\n\
             Content-Type: {content_type}\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(file);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    (boundary, body)
}

// -- messages ---------------------------------------------------------------------------------------

/// What a notification says about a run.
#[derive(Debug, Clone)]
pub struct Note {
    pub event: Event,
    pub target: String,
    pub run: String,
    pub state: String,
    pub outcome: Option<String>,
    pub exit_code: Option<i32>,
    pub commit: Option<String>,
    pub git_ref: Option<String>,
    pub pipeline_url: Option<String>,
    pub preset: String,
    pub baseline: bool,
    pub finished: Option<String>,
    /// `run.json`'s gate and drift summary (null without them).
    pub gate: Value,
    pub drift: Value,
    /// New findings, highest risk first: (name, risk), at most [`MAX_LISTED`].
    pub new_findings: Vec<(String, String)>,
    pub new_total: u64,
    /// The first reasons the run isn't a pass (or warnings).
    pub reasons: Vec<String>,
    /// Report file names (`report.sarif`, ...).
    pub reports: Vec<String>,
    /// The run's path on `serve`'s API, for links; `None` for a stateless run, which has no server.
    pub links: Option<String>,
}

impl Note {
    /// From the run's row and its `compare.json` (the CLI's output, or null).
    pub fn new(row: &RunRow, event: Event, compare: &Value) -> Note {
        let r = row.run_json.clone().unwrap_or(Value::Null);
        let mut note = Note::from_run(&row.target, &row.id, &r, event, compare);
        note.reasons = row.note.iter().cloned().chain(note.reasons).take(5).collect();
        note.state = row.state.clone();
        note.outcome = row.outcome.clone();
        note.exit_code = row.exit_code;
        note.commit = row.commit.clone();
        note.git_ref = row.git_ref.clone();
        note.pipeline_url = row.pipeline_url.clone();
        note.preset = row.preset.clone();
        note.baseline = row.baseline;
        note.finished = row.finished.map(time::format_millis);
        note.links = Some(format!("/v1/targets/{}/runs/{}", row.target, row.id));
        note
    }

    /// The event of a run from its `run.json` alone (a stateless run): its outcome.
    pub fn event_of(run: &Value) -> Option<Event> {
        match run["outcome"].as_str()? {
            "passed" => Some(Event::Passed),
            "failed" => Some(Event::GateFailed),
            "incomplete" => Some(Event::Incomplete),
            "error" => Some(Event::Error),
            _ => None,
        }
    }

    /// From a run's `run.json` and its `compare.json` (or null); `run` names it (the run folder).
    pub fn from_run(target: &str, run: &str, r: &Value, event: Event, compare: &Value) -> Note {
        let rank = |risk: &str| ["high", "medium", "low", "info"].iter().position(|x| *x == risk).unwrap_or(4);
        let new = compare["data"]["new"].as_array().cloned().unwrap_or_default();
        let mut found: Vec<(String, String)> = new
            .iter()
            .filter(|f| f["state"] != "false_positive")
            .map(|f| (f["name"].as_str().unwrap_or("?").to_string(), f["risk"].as_str().unwrap_or("?").to_string()))
            .collect();
        found.sort_by_key(|(_, risk)| rank(risk));
        found.truncate(MAX_LISTED);
        let new_total = r["summary"]["new"].as_u64().unwrap_or(new.len() as u64);
        let mut reasons: Vec<String> = Vec::new();
        reasons.extend(r["reasons"].as_array().into_iter().flatten().filter_map(Value::as_str).map(String::from));
        reasons.truncate(5);
        let reports = r["files"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .filter(|f| f.starts_with("report."))
            .map(String::from)
            .collect();
        let text = |k: &str| r[k].as_str().map(String::from);
        Note {
            event,
            target: target.to_string(),
            run: run.to_string(),
            state: "finished".into(),
            outcome: text("outcome"),
            exit_code: r["exit_code"].as_i64().and_then(|c| i32::try_from(c).ok()),
            commit: text("commit"),
            git_ref: text("ref"),
            pipeline_url: None,
            preset: text("preset").unwrap_or_default(),
            baseline: r["baseline"] == true,
            finished: text("finished_at"),
            gate: r["gate"].clone(),
            drift: r["summary"].clone(),
            new_findings: found,
            new_total,
            reasons,
            reports,
            links: None,
        }
    }

    /// The run's API path, or (stateless) its run folder's name.
    fn base(&self) -> String {
        self.links.clone().unwrap_or_else(|| self.run.clone())
    }

    /// The generic webhook's body.
    pub fn generic(&self) -> Value {
        let base = self.base();
        let reports: serde_json::Map<String, Value> = self
            .reports
            .iter()
            .map(|f| (f.trim_start_matches("report.").to_string(), json!(format!("{base}/{f}"))))
            .collect();
        let gate = self.gate.is_object().then(|| {
            json!({"passed": self.gate["passed"], "count": self.gate["count"], "fail_on": self.gate["fail_on"],
                   "new_only": self.gate["new_only"]})
        });
        let mut v = json!({
            "event": self.event.name(),
            "target": self.target,
            "run": self.run,
            "state": self.state,
            "outcome": self.outcome,
            "exit_code": self.exit_code,
            "preset": self.preset,
            "baseline": self.baseline,
            "finished": self.finished,
            "gate": gate,
            "drift": self.drift,
            "new_findings": self.new_findings.iter().map(|(n, r)| json!({"name": n, "risk": r})).collect::<Vec<_>>(),
            "new_total": self.new_total,
            "reasons": self.reasons,
            "links": if self.links.is_some() {
                json!({"run": base, "drift": format!("{base}/drift"), "reports": reports})
            } else {
                Value::Null
            },
        });
        for (k, val) in [("commit", &self.commit), ("ref", &self.git_ref), ("pipeline_url", &self.pipeline_url)] {
            if let Some(val) = val {
                v[k] = json!(val);
            }
        }
        v
    }

    /// One line: `shop: Gate failed (exit 5), 3 new findings`.
    fn summary_line(&self) -> String {
        let mut s = format!("{}: {}", self.target, self.event.headline());
        if let Some(c) = self.exit_code {
            s.push_str(&format!(" (exit {c})"));
        }
        if self.drift.is_object() {
            s.push_str(&format!(", {} new finding{}", self.new_total, if self.new_total == 1 { "" } else { "s" }));
        }
        s
    }

    /// (label, value) pairs shown in chat messages; values are caller-controlled, escape them.
    fn facts(&self) -> Vec<(&'static str, String)> {
        let mut f = vec![("Run", self.run.clone()), ("Preset", self.preset.clone())];
        if let Some(c) = &self.commit {
            f.push(("Commit", c.clone()));
        }
        if let Some(r) = &self.git_ref {
            f.push(("Ref", r.clone()));
        }
        if let Some(p) = &self.pipeline_url {
            f.push(("Pipeline", p.clone()));
        }
        if self.gate.is_object() {
            let g = &self.gate;
            let verdict = if g["passed"] == true { "passed" } else { "failed" };
            let mut text = format!("{verdict}, {} at or above {}", g["count"], g["fail_on"].as_str().unwrap_or("?"));
            if g["new_only"] == true {
                text.push_str(" (new only)");
            }
            f.push(("Gate", text));
        }
        if self.drift.is_object() {
            let d = &self.drift;
            f.push(("Drift", format!("{} new, {} unchanged, {} fixed", d["new"], d["unchanged"], d["fixed"])));
        }
        f
    }

    /// A Slack incoming-webhook message: plain mrkdwn, everything from callers escaped.
    pub fn slack(&self) -> Value {
        let mut blocks = vec![json!({"type": "section", "text": {"type": "mrkdwn",
            "text": format!("*brainproxy* · {}", slack_escape(&self.summary_line()))}})];
        let fields: Vec<Value> = self
            .facts()
            .into_iter()
            .map(|(k, v)| json!({"type": "mrkdwn", "text": format!("*{k}*\n{}", slack_escape(&v))}))
            .collect();
        blocks.push(json!({"type": "section", "fields": fields}));
        if !self.new_findings.is_empty() {
            let lines: Vec<String> = self
                .new_findings
                .iter()
                .take(CHAT_LISTED)
                .map(|(n, r)| format!("• {}: {}", slack_escape(r), slack_escape(n)))
                .collect();
            blocks.push(json!({"type": "section", "text": {"type": "mrkdwn",
                "text": format!("*New findings*\n{}{}", lines.join("\n"), self.more())}}));
        }
        if !self.reasons.is_empty() && !matches!(self.event, Event::Passed) {
            let lines: Vec<String> = self.reasons.iter().map(|r| format!("• {}", slack_escape(r))).collect();
            blocks.push(json!({"type": "section", "text": {"type": "mrkdwn",
                "text": format!("*Reasons*\n{}", lines.join("\n"))}}));
        }
        blocks.push(json!({"type": "context", "elements": [{"type": "mrkdwn", "text": slack_escape(&self.base())}]}));
        json!({"text": format!("brainproxy: {}", slack_escape(&self.summary_line())), "blocks": blocks})
    }

    /// A Teams Workflows message: one Adaptive Card 1.4, everything from callers escaped.
    pub fn teams(&self) -> Value {
        let color = match self.event {
            Event::Passed => "Good",
            Event::GateFailed | Event::Error => "Attention",
            Event::Incomplete | Event::Cancelled => "Warning",
        };
        let mut body = vec![
            json!({"type": "TextBlock", "text": "brainproxy", "weight": "Bolder", "size": "Medium", "wrap": true}),
            json!({"type": "TextBlock", "text": teams_escape(&self.summary_line()), "color": color, "wrap": true}),
            json!({"type": "FactSet", "facts": self.facts().into_iter()
                .map(|(k, v)| json!({"title": k, "value": teams_escape(&v)})).collect::<Vec<_>>()}),
        ];
        if !self.new_findings.is_empty() {
            let lines: Vec<String> = self
                .new_findings
                .iter()
                .take(CHAT_LISTED)
                .map(|(n, r)| format!("- {}: {}", teams_escape(r), teams_escape(n)))
                .collect();
            body.push(json!({"type": "TextBlock", "text": "New findings", "weight": "Bolder", "wrap": true}));
            body.push(
                json!({"type": "TextBlock", "text": format!("{}{}", lines.join("\n"), self.more()), "wrap": true}),
            );
        }
        if !self.reasons.is_empty() && !matches!(self.event, Event::Passed) {
            let lines: Vec<String> = self.reasons.iter().map(|r| format!("- {}", teams_escape(r))).collect();
            body.push(json!({"type": "TextBlock", "text": "Reasons", "weight": "Bolder", "wrap": true}));
            body.push(json!({"type": "TextBlock", "text": lines.join("\n"), "wrap": true}));
        }
        body.push(json!({"type": "TextBlock", "text": teams_escape(&self.base()), "isSubtle": true, "wrap": true}));
        json!({
            "type": "message",
            "attachments": [{
                "contentType": "application/vnd.microsoft.card.adaptive",
                "contentUrl": null,
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "body": body,
                },
            }],
        })
    }

    /// `\n… and N more` when the chat list is shorter than the new findings.
    fn more(&self) -> String {
        let shown = self.new_findings.len().min(CHAT_LISTED) as u64;
        if self.new_total > shown { format!("\n… and {} more", self.new_total - shown) } else { String::new() }
    }
}

/// Slack's three control characters: with `<` and `>` escaped no text becomes a link or a mention.
pub fn slack_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

/// Adaptive Card text is Markdown: brackets and angle brackets would make links or `<at>` mentions.
pub fn teams_escape(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '[' => '(',
            ']' => ')',
            '<' => '‹',
            '>' => '›',
            c if c.is_control() && c != '\n' => ' ',
            c => c,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(state: &str, outcome: Option<&str>) -> RunRow {
        RunRow {
            id: "r-abc".into(),
            seq: 1,
            target: "shop".into(),
            commit: Some("9f2c1e7".into()),
            git_ref: Some("refs/heads/main".into()),
            pipeline_url: Some("https://ci.test/p/1?a=<b>&c".into()),
            preset: "quick".into(),
            state: state.into(),
            outcome: outcome.map(String::from),
            exit_code: Some(5),
            job: Some(3),
            created: 0,
            started: Some(0),
            finished: Some(1_700_000_000_000),
            actor: "ci".into(),
            owner: "t".into(),
            cancel_requested: false,
            baseline: false,
            accept_coverage_drop: false,
            run_json: Some(json!({
                "gate": {"fail_on": "high", "new_only": true, "passed": false, "count": 2},
                "summary": {"new": 25, "unchanged": 1, "fixed": 0},
                "reasons": ["gate: 2 findings"],
                "files": ["run.json", "compare.json", "report.json", "report.sarif"],
            })),
            note: None,
        }
    }

    fn compare() -> Value {
        let mut new: Vec<Value> = (0..24).map(|i| json!({"name": format!("Low {i}"), "risk": "low"})).collect();
        new.push(json!({"name": "SQL Injection <@U123> [x](https://evil.test)", "risk": "high"}));
        json!({"ok": true, "data": {"new": new}})
    }

    #[test]
    fn signing_matches_a_fixed_vector() {
        // printf '%s' '1700000000.{"run":"r-1"}' | openssl dgst -sha256 -hmac whsec_test
        assert_eq!(
            sign(b"whsec_test", 1_700_000_000, br#"{"run":"r-1"}"#),
            "a1c84f68f362e14a590e469de4d155eac5053238c839d4bb0c2e1869bed988c1"
        );
    }

    #[test]
    fn events_and_the_on_filter() {
        assert_eq!(Event::of("completed", Some("passed")), Some(Event::Passed));
        assert_eq!(Event::of("completed", Some("gate_failed")), Some(Event::GateFailed));
        assert_eq!(Event::of("incomplete", Some("incomplete")), Some(Event::Incomplete));
        assert_eq!(Event::of("failed", Some("error")), Some(Event::Error));
        assert_eq!(Event::of("cancelled", Some("incomplete")), Some(Event::Cancelled));
        assert_eq!(Event::of("superseded", None), None);
        assert_eq!(Event::of("running", None), None);
        let hook: Hook = serde_json::from_value(json!({"kind": "slack", "url_secret": "SLACK_URL"})).unwrap();
        assert!(!hook.on.contains(&Event::Passed));
        assert!(hook.on.contains(&Event::GateFailed) && hook.on.contains(&Event::Cancelled));
        let hook: Hook = serde_json::from_value(json!({"kind": "teams", "url_secret": "T", "on": ["passed"]})).unwrap();
        assert_eq!(hook.on, [Event::Passed]);
        assert!(serde_json::from_value::<Hook>(json!({"kind": "teams", "url_secret": "T", "on": ["done"]})).is_err());
        assert!(serde_json::from_value::<Hook>(json!({"kind": "teams", "url_secret": "T", "url": "x"})).is_err());
    }

    #[test]
    fn generic_body() {
        let n = Note::new(&row("completed", Some("gate_failed")), Event::GateFailed, &compare());
        let v = n.generic();
        assert_eq!(v["event"], "gate_failed");
        assert_eq!(v["target"], "shop");
        assert_eq!(v["run"], "r-abc");
        assert_eq!(v["exit_code"], 5);
        assert_eq!(v["commit"], "9f2c1e7");
        assert_eq!(v["ref"], "refs/heads/main");
        assert_eq!(v["gate"], json!({"passed": false, "count": 2, "fail_on": "high", "new_only": true}));
        assert_eq!(v["new_total"], 25);
        let listed = v["new_findings"].as_array().unwrap();
        assert_eq!(listed.len(), 20);
        assert_eq!(listed[0]["risk"], "high", "highest risk first");
        assert_eq!(v["links"]["run"], "/v1/targets/shop/runs/r-abc");
        assert_eq!(v["links"]["reports"]["sarif"], "/v1/targets/shop/runs/r-abc/report.sarif");
        assert!(v["links"]["reports"]["html"].is_null());
        // A run without commit or gate: no commit keys, a null gate.
        let mut bare = row("failed", Some("error"));
        bare.commit = None;
        bare.git_ref = None;
        bare.pipeline_url = None;
        bare.run_json = None;
        bare.note = Some("can't run brainproxy".into());
        let v = Note::new(&bare, Event::Error, &Value::Null).generic();
        assert!(v.get("commit").is_none() && v.get("ref").is_none());
        assert!(v["gate"].is_null());
        assert_eq!(v["reasons"], json!(["can't run brainproxy"]));
    }

    #[test]
    fn slack_and_teams_bodies_escape_what_callers_control() {
        let n = Note::new(&row("completed", Some("gate_failed")), Event::GateFailed, &compare());
        let s = n.slack();
        let text = s.to_string();
        assert!(s["text"].as_str().unwrap().starts_with("brainproxy: shop: Gate failed (exit 5)"));
        assert_eq!(s["blocks"][0]["type"], "section");
        assert!(!text.contains("<@U123>") && text.contains("&lt;@U123&gt;"), "{text}");
        assert!(text.contains("a=&lt;b&gt;&amp;c"), "{text}");
        assert!(text.contains("and 15 more"), "{text}");
        assert!(!text.contains("image"));

        let t = n.teams();
        assert_eq!(t["type"], "message");
        let card = &t["attachments"][0];
        assert_eq!(card["contentType"], "application/vnd.microsoft.card.adaptive");
        assert_eq!(card["content"]["type"], "AdaptiveCard");
        assert_eq!(card["content"]["version"], "1.4");
        let text = t.to_string();
        assert!(!text.contains("[x](") && !text.contains("<@"), "{text}");
        assert!(text.contains("(x)(https://evil.test)"), "{text}");
        let facts = card["content"]["body"][2]["facts"].as_array().unwrap();
        assert!(facts.iter().any(|f| f["title"] == "Commit" && f["value"] == "9f2c1e7"));
    }

    #[test]
    fn escaping() {
        assert_eq!(slack_escape("a <b> & <!channel>"), "a &lt;b&gt; &amp; &lt;!channel&gt;");
        assert_eq!(teams_escape("[a](b) <at>x</at>\u{7}"), "(a)(b) ‹at›x‹/at› ");
    }

    #[test]
    fn multipart_encoding() {
        let (b, body) = multipart(
            &[("scan_type", "SARIF"), ("test_title", "brainproxy shop")],
            "report.sarif",
            "application/json",
            b"{\"runs\":[]}",
        );
        assert!(b.starts_with("brainproxy-") && b.len() > 40);
        let text = String::from_utf8(body).unwrap();
        let want = format!(
            "--{b}\r\nContent-Disposition: form-data; name=\"scan_type\"\r\n\r\nSARIF\r\n\
             --{b}\r\nContent-Disposition: form-data; name=\"test_title\"\r\n\r\nbrainproxy shop\r\n\
             --{b}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"report.sarif\"\r\n\
             Content-Type: application/json\r\n\r\n{{\"runs\":[]}}\r\n--{b}--\r\n"
        );
        assert_eq!(text, want);
    }

    fn dojo() -> DefectDojo {
        serde_json::from_value(json!({"url": "https://dojo.test/", "token_secret": "DOJO_TOKEN",
            "product_name": "Shop", "engagement_name": "CI"}))
        .unwrap()
    }

    #[test]
    fn validation() {
        let hook = |v: Value| serde_json::from_value::<Hook>(v).unwrap();
        let generic = hook(json!({"kind": "generic", "url_secret": "HOOK_URL", "secret": "HOOK_KEY"}));
        assert!(check(std::slice::from_ref(&generic), None).is_ok());
        assert!(check(&vec![generic.clone(); 6], None).unwrap_err().contains("at most 5"));
        let no_key = hook(json!({"kind": "generic", "url_secret": "HOOK_URL"}));
        assert!(check(&[no_key], None).unwrap_err().contains("needs secret"));
        let slack_key = hook(json!({"kind": "slack", "url_secret": "S", "secret": "K"}));
        assert!(check(&[slack_key], None).is_err());
        for bad in ["PATH", "BRAINPROXY_X", "lower", "HTTPS_PROXY"] {
            let h = hook(json!({"kind": "slack", "url_secret": bad}));
            assert!(check(&[h], None).is_err(), "{bad}");
        }
        assert!(check(&[hook(json!({"kind": "slack", "url_secret": "S", "on": []}))], None).is_err());

        let d = dojo();
        assert_eq!(d.scan_type, "SARIF");
        assert!(d.close_old_findings);
        assert!(check(&[], Some(&d)).is_ok());
        for url in
            ["http://dojo.test", "ftp://dojo.test", "https://u:p@dojo.test", "https://dojo.test/?x=1", "https://"]
        {
            let d = DefectDojo { url: url.into(), ..dojo() };
            assert!(check(&[], Some(&d)).is_err(), "{url}");
        }
        assert!(check(&[], Some(&DefectDojo { url: "http://127.0.0.1:8080".into(), ..dojo() })).is_ok());
        assert!(check(&[], Some(&DefectDojo { scan_type: "ZAP Scan".into(), ..dojo() })).is_err());
        assert!(check(&[], Some(&DefectDojo { minimum_severity: Some("high".into()), ..dojo() })).is_err());
        assert!(check(&[], Some(&DefectDojo { minimum_severity: Some("High".into()), ..dojo() })).is_ok());
        assert!(check(&[], Some(&DefectDojo { product_name: " ".into(), ..dojo() })).is_err());
        assert!(check(&[], Some(&DefectDojo { token_secret: "LD_PRELOAD".into(), ..dojo() })).is_err());
    }
}
