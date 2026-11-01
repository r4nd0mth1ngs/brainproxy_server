//! The HTTP API (research §4). Two routers: the public one, for target tokens, and the admin one,
//! for the admin token, which listens on its own (loopback) address. Admin endpoints don't exist on
//! the public listener at all, so registering a target is a property of the network as well as of
//! the token (§5.1).
//!
//! Every response is the CLI's envelope: `{"ok": true, "data": ...}` or
//! `{"ok": false, "error": {"kind", "message"}}`.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{ConnectInfo, DefaultBodyLimit, Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use http_body_util::BodyExt;
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::io::AsyncWriteExt;

use super::auth::{self, Bucket};
use super::db::{self, AuditEntry, Perm, RunRow, Token, state};
use super::target::{self, TargetConfig};
use super::{DEDUP_MS, Server};
use crate::time;

/// Request bodies other than a project upload.
const BODY_LIMIT: usize = 64 * 1024;
/// The longest a status request waits for a change.
const MAX_WAIT_SECS: u64 = 60;

#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    kind: &'static str,
    message: String,
}

impl ApiError {
    fn new(status: StatusCode, kind: &'static str, message: impl Into<String>) -> ApiError {
        ApiError { status, kind, message: message.into() }
    }
    pub fn invalid(m: impl Into<String>) -> ApiError {
        ApiError::new(StatusCode::BAD_REQUEST, "invalid", m)
    }
    pub fn conflict(m: impl Into<String>) -> ApiError {
        ApiError::new(StatusCode::CONFLICT, "conflict", m)
    }
    pub fn not_found(what: &str) -> ApiError {
        ApiError::new(StatusCode::NOT_FOUND, "not_found", format!("no such {what}"))
    }
    pub fn limit() -> ApiError {
        ApiError::new(
            StatusCode::CONFLICT,
            "target_limit",
            format!("a server scans at most {} targets; remove one first", db::MAX_TARGETS),
        )
    }
    pub fn internal(m: impl Into<String>) -> ApiError {
        let m = m.into();
        eprintln!("brainproxy-server: {m}");
        ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal", m)
    }
    pub fn db(e: rusqlite::Error) -> ApiError {
        ApiError::internal(format!("control.db: {e}"))
    }
    pub fn io(e: std::io::Error) -> ApiError {
        ApiError::internal(e.to_string())
    }
    fn unauthorized() -> ApiError {
        ApiError::new(StatusCode::UNAUTHORIZED, "unauthorized", "missing, unknown, expired or revoked token")
    }
    fn forbidden(m: impl Into<String>) -> ApiError {
        ApiError::new(StatusCode::FORBIDDEN, "forbidden", m)
    }
    fn too_many(m: impl Into<String>) -> ApiError {
        ApiError::new(StatusCode::TOO_MANY_REQUESTS, "rate_limited", m)
    }
    fn too_large(m: impl Into<String>) -> ApiError {
        ApiError::new(StatusCode::PAYLOAD_TOO_LARGE, "too_large", m)
    }
    pub fn with_kind(mut self, kind: &'static str) -> ApiError {
        self.kind = kind;
        self
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = json!({"ok": false, "error": {"kind": self.kind, "message": self.message}});
        (self.status, axum::Json(body)).into_response()
    }
}

type ApiResult = Result<Response, ApiError>;

fn ok(status: StatusCode, data: Value) -> ApiResult {
    Ok((status, axum::Json(json!({"ok": true, "data": data}))).into_response())
}

#[derive(Clone)]
pub struct App {
    server: Arc<Server>,
    admin: bool,
}

pub fn public_router(server: Arc<Server>) -> Router {
    common(Router::new()).with_state(App { server, admin: false })
}

pub fn admin_router(server: Arc<Server>) -> Router {
    let max_upload = (server.cfg.max_project_mb as usize).saturating_mul(1024 * 1024);
    common(Router::new())
        .route("/v1/targets", post(register))
        .route("/v1/targets/{t}", axum::routing::delete(remove_target))
        .route("/v1/targets/{t}/tokens", post(issue_token).get(list_tokens))
        .route("/v1/targets/{t}/tokens/{id}", axum::routing::delete(revoke_token))
        .route("/v1/targets/{t}/project", axum::routing::put(upload).layer(DefaultBodyLimit::max(max_upload)))
        .route("/v1/targets/{t}/next-run", post(next_run))
        .route("/v1/summary", get(summary))
        .route("/v1/audit", get(audit_log))
        .with_state(App { server, admin: true })
}

fn common(r: Router<App>) -> Router<App> {
    r.route("/v1/healthz", get(healthz))
        .route("/v1/targets", get(list_targets))
        .route("/v1/targets/{t}", get(show_target))
        .route("/v1/targets/{t}/runs", post(trigger).get(list_runs))
        .route("/v1/targets/{t}/latest", get(latest))
        .route("/v1/targets/{t}/runs/{r}", get(show_run))
        .route("/v1/targets/{t}/runs/{r}/cancel", post(cancel))
        .route("/v1/targets/{t}/runs/{r}/drift", get(drift))
        .route("/v1/targets/{t}/runs/{r}/{file}", get(download))
        .fallback(|| async { ApiError::new(StatusCode::NOT_FOUND, "not_found", "no such endpoint") })
        .method_not_allowed_fallback(|| async {
            ApiError::new(StatusCode::METHOD_NOT_ALLOWED, "not_found", "no such endpoint for this method")
        })
        .layer(DefaultBodyLimit::max(BODY_LIMIT))
}

// -- who is calling ---------------------------------------------------------------------------------

enum Caller {
    Admin,
    Token(Token),
}

impl Caller {
    fn audit(&self, ip: IpAddr, action: &str) -> AuditEntry {
        let (actor, kind) = match self {
            Caller::Admin => ("admin".to_string(), "admin"),
            Caller::Token(t) => (format!("{} ({})", t.name, t.id), "token"),
        };
        AuditEntry {
            actor,
            actor_kind: kind.into(),
            ip: Some(ip.to_string()),
            action: action.into(),
            result: "ok".into(),
            ..AuditEntry::default()
        }
    }

    /// The idempotency-key namespace of this caller.
    fn key_owner(&self) -> String {
        match self {
            Caller::Admin => "admin".into(),
            Caller::Token(t) => t.id.clone(),
        }
    }
}

/// The client's address: the peer, or with `--trust-forwarded` the address the reverse proxy
/// appended last to `X-Forwarded-For`.
fn client_ip(app: &App, peer: SocketAddr, headers: &HeaderMap) -> IpAddr {
    if app.server.cfg.trust_forwarded
        && let Some(ip) = headers
            .get_all("x-forwarded-for")
            .iter()
            .next_back()
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.rsplit(',').next())
            .and_then(|v| v.trim().parse().ok())
    {
        return ip;
    }
    peer.ip()
}

/// Checks the bearer token for `target` (or no target) and `need`. On the admin listener only the
/// admin token counts; on the public one only target tokens.
fn authenticate(
    app: &App,
    ip: IpAddr,
    headers: &HeaderMap,
    target: Option<&str>,
    need: Perm,
) -> Result<Caller, ApiError> {
    let s = &app.server;
    // Failed attempts are counted per address and listener. Valid credentials always get through,
    // so nobody can lock pipelines or the admin out by failing on purpose from a shared address
    // (a reverse proxy on this machine, a CI NAT); tokens are 256-bit, so the limit only bounds
    // noise and audit writes.
    let key = format!("{}:{ip}", if app.admin { "admin" } else { "public" });
    let presented = headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()).and_then(auth::bearer);
    let fail = |why: &str| {
        if !s.limits.take(Bucket::AuthFailure, &key) {
            return ApiError::too_many("too many failed authentications from this address; try again later");
        }
        let named = presented.and_then(auth::token_target).filter(|t| target::valid_id(t));
        s.audit(AuditEntry {
            actor: named.map_or("unknown".into(), |t| format!("a token for {t}")),
            actor_kind: "none".into(),
            ip: Some(ip.to_string()),
            action: "authenticate".into(),
            target: target.filter(|t| target::valid_id(t)).map(String::from),
            result: "refused".into(),
            detail: Some(why.into()),
            ..AuditEntry::default()
        });
        ApiError::unauthorized()
    };
    let Some(token) = presented else { return Err(fail("no bearer token")) };
    if app.admin {
        return if s.is_admin(token) { Ok(Caller::Admin) } else { Err(fail("not the admin token")) };
    }
    let now = time::now_millis();
    let found = s.db().token_by_hash(&auth::sha256(token.as_bytes()), now).map_err(ApiError::db)?;
    let Some(t) = found else { return Err(fail("unknown token")) };
    if t.revoked.is_some() {
        return Err(fail("revoked token"));
    }
    if t.expires.is_some_and(|e| e <= now) {
        return Err(fail("expired token"));
    }
    if let Some(target) = target
        && t.target != target
    {
        let mut e = Caller::Token(t.clone()).audit(ip, "authenticate");
        e.target = Some(target.into());
        e.result = "refused".into();
        e.detail = Some(format!("token for {} used on {target}", t.target));
        s.audit(e);
        return Err(ApiError::forbidden("this token is for another target"));
    }
    if !t.perm.allows(need) {
        return Err(ApiError::forbidden("this token is read-only"));
    }
    // Triggers also take from their own, smaller bucket (in `trigger`).
    if !s.limits.take(Bucket::Read, &t.id) {
        return Err(ApiError::too_many("too many requests for this token; try again later"));
    }
    Ok(Caller::Token(t))
}

/// The target, or 404.
fn load_target(app: &App, id: &str) -> Result<db::Target, ApiError> {
    app.server.db().target(id).map_err(ApiError::db)?.ok_or_else(|| ApiError::not_found("target"))
}

// -- reading --------------------------------------------------------------------------------------

async fn healthz(State(app): State<App>) -> ApiResult {
    let live = app.server.db().runs_in_state(state::RUNNING).map_err(ApiError::db)?.len();
    ok(StatusCode::OK, json!({"status": "ok", "version": env!("CARGO_PKG_VERSION"), "running": live}))
}

fn target_json(app: &App, t: &db::Target) -> Result<Value, ApiError> {
    let counts = app.server.db().state_counts(&t.config.id).map_err(ApiError::db)?;
    let mut v = t.config.public_json();
    if let Some(m) = v.as_object_mut() {
        m.insert("project_ready".into(), json!(t.project_ready));
        m.insert("created".into(), json!(time::format_millis(t.created)));
        m.insert(
            "next_run".into(),
            json!({"baseline": t.next_baseline, "accept_coverage_drop": t.next_accept_coverage_drop}),
        );
        m.insert("runs".into(), counts.into_iter().map(|(k, n)| (k, json!(n))).collect());
    }
    Ok(v)
}

async fn list_targets(
    State(app): State<App>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> ApiResult {
    let ip = client_ip(&app, peer, &headers);
    let caller = authenticate(&app, ip, &headers, None, Perm::Read)?;
    let targets = app.server.db().targets().map_err(ApiError::db)?;
    let mut out = Vec::new();
    for t in targets.iter().filter(|t| match &caller {
        Caller::Admin => true,
        Caller::Token(tok) => tok.target == t.config.id,
    }) {
        out.push(target_json(&app, t)?);
    }
    ok(StatusCode::OK, json!({"targets": out, "max_targets": db::MAX_TARGETS}))
}

async fn show_target(
    State(app): State<App>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(t): Path<String>,
) -> ApiResult {
    let ip = client_ip(&app, peer, &headers);
    authenticate(&app, ip, &headers, Some(&t), Perm::Read)?;
    let target = load_target(&app, &t)?;
    ok(StatusCode::OK, target_json(&app, &target)?)
}

/// A run as the API shows it (research §4.2).
fn run_json(app: &App, row: &RunRow) -> Result<Value, ApiError> {
    let r = row.run_json.clone().unwrap_or(Value::Null);
    let position = if row.state == state::QUEUED {
        Some(app.server.db().queue_position(row.seq).map_err(ApiError::db)?)
    } else {
        None
    };
    let base = format!("/v1/targets/{}/runs/{}", row.target, row.id);
    let mut reasons: Vec<Value> = row.note.iter().map(|n| json!(n)).collect();
    reasons.extend(r["reasons"].as_array().cloned().unwrap_or_default());
    let drift = r["summary"].is_object().then(|| {
        let mut d = r["summary"].clone();
        d["since_job"] = r["since_scan"]["job"].clone();
        d
    });
    let files = r["files"].as_array().cloned().unwrap_or_default();
    let reports: serde_json::Map<String, Value> = files
        .iter()
        .filter_map(Value::as_str)
        .filter(|f| f.starts_with("report."))
        .map(|f| (f.trim_start_matches("report.").to_string(), json!(format!("{base}/{f}"))))
        .collect();
    Ok(json!({
        "run": row.id,
        "target": row.target,
        "commit": row.commit,
        "ref": row.git_ref,
        "pipeline_url": row.pipeline_url,
        "preset": row.preset,
        "baseline": row.baseline,
        "state": row.state,
        "outcome": row.outcome,
        "exit_code": row.exit_code,
        "job": row.job,
        "created": time::format_millis(row.created),
        "started": row.started.map(time::format_millis),
        "finished": row.finished.map(time::format_millis),
        "position": position,
        "cancel_requested": row.cancel_requested,
        "coverage": r["coverage"],
        "coverage_baseline": r["coverage_baseline"],
        "drift": drift,
        "gate": r["gate"],
        "reasons": reasons,
        "links": {"self": base, "drift": format!("{base}/drift"), "reports": reports},
    }))
}

#[derive(Deserialize)]
struct ListQuery {
    limit: Option<u32>,
}

async fn list_runs(
    State(app): State<App>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(t): Path<String>,
    Query(q): Query<ListQuery>,
) -> ApiResult {
    let ip = client_ip(&app, peer, &headers);
    authenticate(&app, ip, &headers, Some(&t), Perm::Read)?;
    load_target(&app, &t)?;
    let rows = app.server.db().runs(&t, q.limit.unwrap_or(20).clamp(1, 200)).map_err(ApiError::db)?;
    let runs = rows.iter().map(|r| run_json(&app, r)).collect::<Result<Vec<_>, _>>()?;
    ok(StatusCode::OK, json!({"runs": runs}))
}

#[derive(Deserialize)]
struct WaitQuery {
    wait: Option<u64>,
}

async fn show_run(
    State(app): State<App>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path((t, r)): Path<(String, String)>,
    Query(q): Query<WaitQuery>,
) -> ApiResult {
    let ip = client_ip(&app, peer, &headers);
    authenticate(&app, ip, &headers, Some(&t), Perm::Read)?;
    let find = || app.server.db().run(&t, &r).map_err(ApiError::db)?.ok_or_else(|| ApiError::not_found("run"));
    let mut row = find()?;
    let wait = q.wait.unwrap_or(0).min(MAX_WAIT_SECS);
    if wait > 0 && state::is_live(&row.state) {
        // Long poll: return as soon as the state (or the job) changes, or after `wait` seconds.
        let (first_state, first_job) = (row.state.clone(), row.job);
        let mut changes = app.server.subscribe();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(wait);
        loop {
            tokio::select! {
                c = changes.changed() => if c.is_err() { break },
                _ = tokio::time::sleep_until(deadline) => break,
            }
            row = find()?;
            if row.state != first_state || row.job != first_job {
                break;
            }
        }
    }
    ok(StatusCode::OK, run_json(&app, &row)?)
}

async fn latest(
    State(app): State<App>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(t): Path<String>,
) -> ApiResult {
    let ip = client_ip(&app, peer, &headers);
    authenticate(&app, ip, &headers, Some(&t), Perm::Read)?;
    load_target(&app, &t)?;
    let row = app.server.db().last_run_in_state(&t, state::COMPLETED).map_err(ApiError::db)?;
    let row = row.ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "not_found", "no completed run yet"))?;
    ok(StatusCode::OK, run_json(&app, &row)?)
}

async fn drift(
    State(app): State<App>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path((t, r)): Path<(String, String)>,
) -> ApiResult {
    let ip = client_ip(&app, peer, &headers);
    authenticate(&app, ip, &headers, Some(&t), Perm::Read)?;
    let row = app.server.db().run(&t, &r).map_err(ApiError::db)?.ok_or_else(|| ApiError::not_found("run"))?;
    let path = app.server.run_dir(&t, &row.id).join("compare.json");
    let text = tokio::fs::read_to_string(&path)
        .await
        .map_err(|_| ApiError::new(StatusCode::NOT_FOUND, "not_found", "this run has no drift (yet)"))?;
    let cmp: Value = serde_json::from_str(&text).map_err(|e| ApiError::internal(format!("compare.json: {e}")))?;
    ok(StatusCode::OK, json!({"run": row.id, "state": row.state, "outcome": row.outcome, "compare": cmp["data"]}))
}

async fn download(
    State(app): State<App>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path((t, r, file)): Path<(String, String, String)>,
) -> ApiResult {
    let ip = client_ip(&app, peer, &headers);
    let caller = authenticate(&app, ip, &headers, Some(&t), Perm::Read)?;
    let content_type = match file.as_str() {
        "report.json" | "compare.json" => "application/json",
        "report.html" => "text/html; charset=utf-8",
        "report.sarif" => "application/sarif+json",
        _ => return Err(ApiError::new(StatusCode::NOT_FOUND, "not_found", "no such file")),
    };
    let row = app.server.db().run(&t, &r).map_err(ApiError::db)?.ok_or_else(|| ApiError::not_found("run"))?;
    let bytes = tokio::fs::read(app.server.run_dir(&t, &row.id).join(&file))
        .await
        .map_err(|_| ApiError::new(StatusCode::NOT_FOUND, "not_found", format!("this run has no {file}")))?;
    let mut e = caller.audit(ip, "download");
    e.target = Some(t.clone());
    e.run = Some(row.id.clone());
    e.detail = Some(file.clone());
    app.server.audit(e);
    let mut resp = Response::new(Body::from(bytes));
    let h = resp.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    // Reports quote what the scanned app sent back: never run it in the API's origin.
    h.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static("sandbox"));
    if let Ok(v) = HeaderValue::from_str(&format!("attachment; filename=\"{t}-{}-{file}\"", row.id)) {
        h.insert(header::CONTENT_DISPOSITION, v);
    }
    Ok(resp)
}

// -- triggering and cancelling --------------------------------------------------------------------

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct TriggerBody {
    commit: Option<String>,
    #[serde(rename = "ref")]
    git_ref: Option<String>,
    pipeline_url: Option<String>,
    /// Only to lower the depth below the target's preset.
    preset: Option<String>,
}

fn parse_body<T: serde::de::DeserializeOwned + Default>(body: &Bytes) -> Result<T, ApiError> {
    if body.iter().all(u8::is_ascii_whitespace) {
        return Ok(T::default());
    }
    serde_json::from_slice(body).map_err(|e| ApiError::invalid(format!("request body: {e}")))
}

fn new_run_id() -> String {
    let compact: String = time::now().chars().take(19).filter(|c| c.is_ascii_digit() || *c == 'T').collect();
    format!("r-{compact}Z-{}", &auth::base32(&auth::random_bytes::<4>())[..6])
}

async fn trigger(
    State(app): State<App>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(t): Path<String>,
    body: Bytes,
) -> ApiResult {
    let ip = client_ip(&app, peer, &headers);
    let caller = authenticate(&app, ip, &headers, Some(&t), Perm::Trigger)?;
    if let Caller::Token(tok) = &caller
        && !app.server.limits.take(Bucket::Trigger, &tok.id)
    {
        return Err(ApiError::too_many("this token triggered 10 runs in the last hour; try again later"));
    }
    let target = load_target(&app, &t)?;
    let b: TriggerBody = parse_body(&body)?;
    for (name, v) in [("commit", &b.commit), ("ref", &b.git_ref)] {
        if let Some(v) = v
            && !target::valid_label(v)
        {
            return Err(ApiError::invalid(format!("{name} must be 1-200 characters of A-Z, a-z, 0-9 and ._/-")));
        }
    }
    if let Some(u) = &b.pipeline_url
        && (u.len() > 500
            || !(u.starts_with("https://") || u.starts_with("http://"))
            || u.chars().any(char::is_control))
    {
        return Err(ApiError::invalid("pipeline_url must be an http(s) URL of at most 500 characters"));
    }
    let preset = match &b.preset {
        None => target.config.preset.clone(),
        Some(p) => {
            let (want, max) = (target::preset_rank(p), target::preset_rank(&target.config.preset));
            match (want, max) {
                (Some(w), Some(m)) if w <= m => p.clone(),
                (Some(_), _) => {
                    return Err(ApiError::invalid(format!(
                        "preset can only lower the depth; this target scans at most {}",
                        target.config.preset
                    )));
                }
                _ => return Err(ApiError::invalid(format!("preset must be one of {}", target::PRESETS.join(", ")))),
            }
        }
    };
    if !target.project_ready {
        return Err(ApiError::conflict("this target has no project yet; an admin uploads it first"));
    }
    let key = match headers.get("idempotency-key") {
        None => None,
        Some(v) => {
            let k = v.to_str().ok().filter(|k| (1..=200).contains(&k.len()));
            Some(k.ok_or_else(|| ApiError::invalid("Idempotency-Key must be 1-200 printable characters"))?.to_string())
        }
    };
    let owner = caller.key_owner();
    let now = time::now_millis();
    let s = &app.server;

    let dedup = |row: RunRow, why: &str| -> ApiResult {
        let mut v = run_json(&app, &row)?;
        v["deduplicated"] = json!(true);
        v["deduplicated_by"] = json!(why);
        ok(StatusCode::OK, v)
    };
    // Each lookup binds its result first: a `MutexGuard` in an `if let` would live through the
    // body, and `dedup` locks the database again.
    let by_key = match &key {
        Some(k) => s.db().idempotent_run(&owner, k, now - DEDUP_MS).map_err(ApiError::db)?,
        None => None,
    };
    if let Some(id) = by_key {
        let row = s.db().run(&t, &id).map_err(ApiError::db)?;
        if let Some(row) = row {
            return dedup(row, "idempotency_key");
        }
    }
    let row = RunRow {
        id: new_run_id(),
        seq: 0,
        target: t.clone(),
        commit: b.commit.clone(),
        git_ref: b.git_ref.clone(),
        pipeline_url: b.pipeline_url.clone(),
        preset: preset.clone(),
        state: state::QUEUED.into(),
        outcome: None,
        exit_code: None,
        job: None,
        created: now,
        started: None,
        finished: None,
        actor: caller.audit(ip, "").actor,
        owner: owner.clone(),
        cancel_requested: false,
        baseline: target.next_baseline,
        accept_coverage_drop: target.next_accept_coverage_drop,
        run_json: None,
        note: None,
    };
    // A commit is only a label the caller chose, so a completed run is never reused for it: only a
    // still-queued run of the same caller, commit and preset answers (see `Db::enqueue`).
    let enqueued = s.db().enqueue(&row, key.as_deref().map(|k| (owner.as_str(), k))).map_err(ApiError::db)?;
    let superseded = match enqueued {
        db::Enqueued::New { superseded } => superseded,
        db::Enqueued::Existing(existing) => return dedup(*existing, "commit"),
    };
    let mut e = caller.audit(ip, "trigger");
    e.target = Some(t.clone());
    e.run = Some(row.id.clone());
    e.detail = Some(format!(
        "commit {}{}",
        row.commit.as_deref().unwrap_or("-"),
        superseded.as_ref().map(|s| format!(", supersedes {s}")).unwrap_or_default()
    ));
    s.audit(e);
    s.runs_changed();
    let stored = s.db().run(&t, &row.id).map_err(ApiError::db)?.ok_or_else(|| ApiError::internal("run vanished"))?;
    let mut v = run_json(&app, &stored)?;
    v["superseded"] = json!(superseded);
    ok(StatusCode::ACCEPTED, v)
}

async fn cancel(
    State(app): State<App>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path((t, r)): Path<(String, String)>,
) -> ApiResult {
    let ip = client_ip(&app, peer, &headers);
    let caller = authenticate(&app, ip, &headers, Some(&t), Perm::Trigger)?;
    let before = app.server.cancel(&t, &r)?.ok_or_else(|| ApiError::not_found("run"))?;
    let mut e = caller.audit(ip, "cancel");
    e.target = Some(t.clone());
    e.run = Some(r.clone());
    e.detail = Some(format!("was {before}"));
    app.server.audit(e);
    let row = app.server.db().run(&t, &r).map_err(ApiError::db)?.ok_or_else(|| ApiError::not_found("run"))?;
    ok(StatusCode::OK, run_json(&app, &row)?)
}

// -- admin ----------------------------------------------------------------------------------------

fn admin_only(app: &App, peer: SocketAddr, headers: &HeaderMap) -> Result<(IpAddr, Caller), ApiError> {
    let ip = client_ip(app, peer, headers);
    if !app.admin {
        return Err(ApiError::not_found("endpoint"));
    }
    Ok((ip, authenticate(app, ip, headers, None, Perm::Trigger)?))
}

async fn register(
    State(app): State<App>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult {
    let (ip, caller) = admin_only(&app, peer, &headers)?;
    let config: TargetConfig =
        serde_json::from_slice(&body).map_err(|e| ApiError::invalid(format!("request body: {e}")))?;
    let id = config.id.clone();
    let result = app.server.register(config).await;
    let mut e = caller.audit(ip, "register");
    e.target = Some(id);
    if let Err(err) = &result {
        e.result = "refused".into();
        e.detail = Some(err.message.clone());
    }
    app.server.audit(e);
    ok(StatusCode::CREATED, result?)
}

async fn remove_target(
    State(app): State<App>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(t): Path<String>,
) -> ApiResult {
    let (ip, caller) = admin_only(&app, peer, &headers)?;
    let result = app.server.remove_target(&t).await;
    let mut e = caller.audit(ip, "remove");
    e.target = Some(t);
    if let Err(err) = &result {
        e.result = "refused".into();
        e.detail = Some(err.message.clone());
    }
    app.server.audit(e);
    ok(StatusCode::OK, result?)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenBody {
    name: String,
    #[serde(default = "default_perm")]
    perm: String,
    expires_days: Option<u64>,
}

fn default_perm() -> String {
    "trigger".into()
}

async fn issue_token(
    State(app): State<App>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(t): Path<String>,
    body: Bytes,
) -> ApiResult {
    let (ip, caller) = admin_only(&app, peer, &headers)?;
    load_target(&app, &t)?;
    let b: TokenBody = serde_json::from_slice(&body).map_err(|e| ApiError::invalid(format!("request body: {e}")))?;
    if !(1..=64).contains(&b.name.len()) || b.name.chars().any(char::is_control) {
        return Err(ApiError::invalid("name must be 1-64 characters"));
    }
    let perm = Perm::parse(&b.perm).ok_or_else(|| ApiError::invalid("perm must be trigger or read"))?;
    let days = b.expires_days.unwrap_or(auth::DEFAULT_TOKEN_DAYS);
    if !(1..=3650).contains(&days) {
        return Err(ApiError::invalid("expires_days must be 1 to 3650"));
    }
    let now = time::now_millis();
    let (secret, hash) = auth::new_token(&t);
    let token = Token {
        id: format!("tok_{}", auth::base32(&auth::random_bytes::<5>())),
        target: t.clone(),
        name: b.name,
        perm,
        created: now,
        expires: Some(now + days as i64 * 24 * 3600 * 1000),
        last_used: None,
        revoked: None,
    };
    app.server.db().insert_token(&token, &hash).map_err(ApiError::db)?;
    let mut e = caller.audit(ip, "token_issue");
    e.target = Some(t);
    e.detail = Some(format!("{} {} ({})", token.id, token.name, perm.name()));
    app.server.audit(e);
    let mut v = token.json();
    v["token"] = json!(secret);
    v["note"] = json!("shown once; store it as a CI secret");
    ok(StatusCode::CREATED, v)
}

async fn list_tokens(
    State(app): State<App>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(t): Path<String>,
) -> ApiResult {
    admin_only(&app, peer, &headers)?;
    load_target(&app, &t)?;
    let tokens = app.server.db().tokens(&t).map_err(ApiError::db)?;
    ok(StatusCode::OK, json!({"tokens": tokens.iter().map(Token::json).collect::<Vec<_>>()}))
}

async fn revoke_token(
    State(app): State<App>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path((t, id)): Path<(String, String)>,
) -> ApiResult {
    let (ip, caller) = admin_only(&app, peer, &headers)?;
    if !app.server.db().revoke_token(&t, &id, time::now_millis()).map_err(ApiError::db)? {
        return Err(ApiError::not_found("token"));
    }
    let mut e = caller.audit(ip, "token_revoke");
    e.target = Some(t);
    e.detail = Some(id.clone());
    app.server.audit(e);
    ok(StatusCode::OK, json!({"id": id, "revoked": true}))
}

async fn upload(
    State(app): State<App>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(t): Path<String>,
    body: Body,
) -> ApiResult {
    let (ip, caller) = admin_only(&app, peer, &headers)?;
    load_target(&app, &t)?;
    let max = app.server.cfg.max_project_mb.saturating_mul(1024 * 1024);
    let too_large = || {
        ApiError::too_large(format!("a project may be {} MB at most (--max-project-mb)", app.server.cfg.max_project_mb))
    };
    if headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .is_some_and(|n| n > max)
    {
        return Err(too_large());
    }
    let dir = app.server.target_dir(&t).join(format!(".upload-{}", auth::base32(&auth::random_bytes::<5>())));
    tokio::fs::create_dir_all(&dir).await.map_err(ApiError::io)?;
    // Removed however this ends, also when the client goes away mid-upload and hyper drops us.
    let _cleanup = RemoveOnDrop(dir.clone());
    let file = dir.join("upload.bpdb");
    let written = async {
        let mut out = tokio::fs::File::create(&file).await.map_err(ApiError::io)?;
        let mut body = body;
        let mut n: u64 = 0;
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(|e| ApiError::invalid(format!("upload: {e}")))?;
            if let Ok(data) = frame.into_data() {
                n += data.len() as u64;
                if n > max {
                    return Err(too_large());
                }
                out.write_all(&data).await.map_err(ApiError::io)?;
            }
        }
        out.flush().await.map_err(ApiError::io)?;
        Ok(n)
    }
    .await;
    let result = match written {
        Ok(_) => app.server.accept_upload(&t, &file).await,
        Err(e) => {
            let _ = tokio::fs::remove_dir_all(&dir).await;
            Err(e)
        }
    };
    let mut e = caller.audit(ip, "project_upload");
    e.target = Some(t);
    if let Err(err) = &result {
        e.result = "refused".into();
        e.detail = Some(err.message.clone());
    }
    app.server.audit(e);
    ok(StatusCode::OK, result?)
}

struct RemoveOnDrop(std::path::PathBuf);

impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct NextRunBody {
    #[serde(default)]
    baseline: bool,
    #[serde(default)]
    accept_coverage_drop: bool,
}

/// One-shot settings for the target's next run: start the history there (`baseline`, no gate), or
/// accept a coverage drop once after the app really shrank.
async fn next_run(
    State(app): State<App>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(t): Path<String>,
    body: Bytes,
) -> ApiResult {
    let (ip, caller) = admin_only(&app, peer, &headers)?;
    load_target(&app, &t)?;
    let b: NextRunBody = parse_body(&body)?;
    app.server.db().set_next_run(&t, b.baseline, b.accept_coverage_drop).map_err(ApiError::db)?;
    let mut e = caller.audit(ip, "next_run");
    e.target = Some(t.clone());
    e.detail = Some(format!("baseline {}, accept_coverage_drop {}", b.baseline, b.accept_coverage_drop));
    app.server.audit(e);
    ok(
        StatusCode::OK,
        json!({"target": t, "next_run": {"baseline": b.baseline, "accept_coverage_drop": b.accept_coverage_drop}}),
    )
}

async fn summary(State(app): State<App>, ConnectInfo(peer): ConnectInfo<SocketAddr>, headers: HeaderMap) -> ApiResult {
    admin_only(&app, peer, &headers)?;
    let targets = app.server.db().targets().map_err(ApiError::db)?;
    let mut out = Vec::new();
    for t in &targets {
        let id = &t.config.id;
        let last = app.server.db().runs(id, 1).map_err(ApiError::db)?;
        let completed = app.server.db().last_run_in_state(id, state::COMPLETED).map_err(ApiError::db)?;
        let brief = |r: &RunRow| {
            json!({"run": r.id, "state": r.state, "outcome": r.outcome, "finished": r.finished.map(time::format_millis),
                   "drift": r.run_json.as_ref().map(|j| j["summary"].clone())})
        };
        out.push(json!({
            "target": id,
            "project_ready": t.project_ready,
            "runs": app.server.db().state_counts(id).map_err(ApiError::db)?.into_iter().map(|(k, n)| (k, json!(n))).collect::<serde_json::Map<_, _>>(),
            "last_run": last.first().map(brief),
            "last_completed": completed.as_ref().map(brief),
        }));
    }
    ok(StatusCode::OK, json!({"targets": out, "max_targets": db::MAX_TARGETS, "version": env!("CARGO_PKG_VERSION")}))
}

async fn audit_log(
    State(app): State<App>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(q): Query<ListQuery>,
) -> ApiResult {
    admin_only(&app, peer, &headers)?;
    let rows = app.server.db().audit_log(q.limit.unwrap_or(100).clamp(1, 1000)).map_err(ApiError::db)?;
    ok(StatusCode::OK, json!({"audit": rows}))
}
