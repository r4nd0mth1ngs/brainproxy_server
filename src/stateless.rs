//! Stateless `ci` (`ci --target FILE --state DIR`, research/CI-STATELESS.md): each run builds a
//! fresh project from the target's settings, scans and gates as project-mode `ci` does, and
//! compares with the findings earlier runs left in `--state` instead of a project's history. It
//! writes the next state to `<run folder>/state/`; moving it between runs is the caller's job.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::Deserialize;
use serde_json::{Value, json};

use crate::brainproxy::{Cli, code};
use crate::ci::{self, Ci, Options};
use crate::project::{self, Refused};
use crate::record::{self, CoverageBaseline, Outcome, Run, StateUse};
use crate::state::{self, CoverageState, Known, State};
use crate::target::{self, MAX_TARGETS, ProjectSource, TargetConfig};

#[derive(Debug, Clone)]
pub struct Args {
    pub brainproxy: PathBuf,
    pub target: PathBuf,
    pub targets: PathBuf,
    pub state: PathBuf,
    pub out: PathBuf,
    pub template: Option<PathBuf>,
    pub suppressions: Option<PathBuf>,
    pub keep_project: Option<PathBuf>,
    pub notify: bool,
    pub baseline: bool,
    pub accept_coverage_drop: bool,
    pub commit: Option<String>,
    pub git_ref: Option<String>,
    pub state_key_env: Option<String>,
    /// The generation the wrapper's pointer names (0: a first run); `None`: any.
    pub expect_generation: Option<u64>,
    pub secrets_dir: PathBuf,
    pub allow_loopback: bool,
}

type Refusal = (i32, String);

/// Runs a stateless `ci` and returns the exit code. Progress goes to stderr, `run.json` to stdout.
pub async fn run(args: Args) -> i32 {
    let cancel = ci::cancel_signal();
    let (work, prepared) = match prepare(&args).await {
        Ok(p) => p,
        Err((c, message)) => {
            eprintln!("brainproxy-server: {message}");
            return c;
        }
    };
    let Prepared { t, cli, loaded, opts, ci_args } = prepared;
    let started = Ci::start(ci_args, opts.clone()).await;
    let ci = match started {
        Ok(ci) => ci,
        Err((c, message)) => {
            eprintln!("brainproxy-server: {message}");
            return c;
        }
    };
    let done = ci.finish(cancel).await;
    let (mut run, mut exit) = (done.run, done.exit);
    let plan = opts.stateless.unwrap_or_default();

    if let Err(e) = next_state(&args, &t, &cli, &loaded, &plan, &mut run).await {
        run.reasons.push(format!("the next state wasn't written: {e}"));
        if exit == code::OK || exit == code::GATE_FAILED {
            run.outcome = Outcome::Error;
            run.exit_code = Some(code::ERROR);
            exit = code::ERROR;
        }
        eprintln!("brainproxy-server: the next state wasn't written: {e}");
    }
    if let Some(keep) = &args.keep_project {
        let argv = ["project".into(), "save".into(), "--output".into(), keep.as_os_str().to_owned()];
        match cli.run::<_, OsString>(argv).await {
            Ok(o) if o.ok() => {}
            Ok(o) => run.reasons.push(format!("--keep-project: {}", o.message())),
            Err(e) => run.reasons.push(format!("--keep-project: {e}")),
        }
    }
    if args.notify {
        notify(&t, &args.secrets_dir, &mut run).await;
    }
    if let Some(folder) = run.folder.clone()
        && let Err(e) = write_run(&folder, &run)
    {
        eprintln!("brainproxy-server: can't write {}: {e}", folder.join(record::RUN_FILE).display());
        // No run.json, no next state: a wrapper must not move on from a run it can't show.
        let _ = std::fs::remove_dir_all(folder.join("state"));
        if exit == code::OK {
            exit = code::ERROR;
            run.exit_code = Some(exit);
            run.outcome = Outcome::Error;
        }
    }
    println!("{}", serde_json::to_string_pretty(&run).unwrap_or_default());
    drop(work);
    exit
}

/// The temp folder of one run (the project, the CLI's HOME, copies of the inputs). Removed when
/// dropped, on every path out of [`run`].
struct Work(PathBuf);

impl Drop for Work {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Prepared {
    t: TargetConfig,
    cli: Cli,
    loaded: state::Loaded,
    opts: Options,
    ci_args: ci::Args,
}

/// Everything before the scan: the inputs checked, the temp project built and vetted, the host
/// and ownership checked, and which known set and coverage apply.
async fn prepare(a: &Args) -> Result<(Work, Prepared), Refusal> {
    let mut t: TargetConfig = read_json(&a.target, "--target")?;
    t.validate(a.allow_loopback).map_err(|e| (code::USAGE, format!("--target {}: {e}", a.target.display())))?;
    crate::notify::check(&t.notify, t.defectdojo.as_ref())
        .map_err(|e| (code::USAGE, format!("--target {}: {e}", a.target.display())))?;
    check_registry(&a.targets, &t.id)?;
    match (t.project, &a.template) {
        (ProjectSource::Upload, None) => {
            return Err((code::USAGE, format!("target {} uses an uploaded project: give it as --template", t.id)));
        }
        (ProjectSource::Generate, Some(_)) => {
            return Err((
                code::USAGE,
                format!("target {} has a generated project; --template is for \"project\": \"upload\"", t.id),
            ));
        }
        _ => {}
    }
    for (flag, f) in [("--template", &a.template), ("--suppressions", &a.suppressions)] {
        if let Some(f) = f
            && !f.is_file()
        {
            return Err((code::NOT_FOUND, format!("{flag} {} doesn't exist", f.display())));
        }
    }
    if let Some(var) = &a.state_key_env {
        check_key_not_shared(&t, var)?;
    }
    let key = state_key(a.state_key_env.as_deref())?;
    let loaded = state::read(&a.state, &t.id, key.as_deref(), a.expect_generation).map_err(|e| (code::ERROR, e))?;

    let work = Work(make_work_dir(&t.id)?);
    let dir = work.0.clone();
    if let Some(fs) = crate::serve::network_fs(&dir) {
        return Err((
            code::ERROR,
            format!("{} is on a network filesystem ({fs}); set TMPDIR to local disk", dir.display()),
        ));
    }
    let mut reasons = Vec::new();
    let env = cli_env(&t, a, &dir, &mut reasons)?;
    let cli = Cli { bin: a.brainproxy.clone(), project: dir.join("project.bpdb"), env: Some(Arc::new(env)) };
    check_cli(&cli).await?;

    match &a.template {
        None => project::create(&cli, &t, t.auth.as_ref()).await.map_err(refused)?,
        Some(template) => {
            std::fs::copy(template, &cli.project)
                .map_err(|e| (code::ERROR, format!("copying --template {}: {e}", template.display())))?;
            project::vet(&cli, &t, a.allow_loopback).await.map_err(refused)?;
        }
    }
    let addrs = project::check_host(&cli, &t, a.allow_loopback).await?;
    if t.ownership {
        project::check_ownership(&t, addrs).await.map_err(|e| (code::OUT_OF_SCOPE, format!("ownership check: {e}")))?;
    }

    let policy = if a.baseline { Default::default() } else { t.policy.clone() };
    let fail_on = if a.baseline { None } else { t.gate.fail_on.clone() };
    let new_only = !a.baseline && t.gate.new_only;
    let fingerprint = if a.baseline { None } else { crate::policy::fingerprint(&policy) };
    let mut record = record::Stateless {
        mode: "stateless".into(),
        target: t.id.clone(),
        commit: a.commit.clone(),
        git_ref: a.git_ref.clone(),
        state: StateUse { read_generation: loaded.state.as_ref().map(|s| s.generation), ..Default::default() },
        marks: json!({}),
        data_versions: data_versions(&cli).await,
        notifications: vec![],
    };
    let mut known = None;
    if let (Some(s), Some(bytes)) = (&loaded.state, &loaded.known)
        && let Some(k) = &s.known
    {
        record.state.known_run = Some(k.run.clone());
        let now =
            (t.base_url.as_str(), t.preset.as_str(), t.profile(), fingerprint.as_deref(), fail_on.as_deref(), new_only);
        let applies = if a.baseline { Err("a --baseline run starts over".to_string()) } else { known_applies(k, now) };
        match applies {
            Ok(()) => {
                let path = dir.join("known.json");
                std::fs::write(&path, bytes).map_err(|e| (code::ERROR, format!("{}: {e}", path.display())))?;
                record.state.known_used = true;
                known = Some(path);
            }
            Err(why) => record.state.reason = Some(why),
        }
    }
    if let Some(why) = &record.state.reason {
        reasons.push(format!("the known findings weren't used ({why}): every finding counts as new"));
    }
    for r in &reasons {
        eprintln!("brainproxy-server: {r}");
    }
    let coverage = loaded
        .state
        .as_ref()
        .and_then(|s| s.coverage.as_ref())
        .filter(|c| c.url == t.base_url && c.preset == t.preset)
        .map(|c| CoverageBaseline {
            job: c.job,
            coverage: record::Coverage { targets: c.targets, endpoints: c.endpoints, requests: c.requests },
        });
    let suppressions = match &a.suppressions {
        Some(f) => {
            let copy = dir.join("suppressions.json");
            std::fs::copy(f, &copy).map_err(|e| (code::ERROR, format!("--suppressions {}: {e}", f.display())))?;
            Some(copy)
        }
        None => None,
    };
    let opts = Options {
        folder: None,
        env: cli.env.clone(),
        on_write: None,
        label: Some(format!("brainproxy-server: {}", t.id)),
        stateless: Some(ci::Stateless {
            known,
            suppressions,
            coverage,
            no_known: dir.join("no-known-findings.json"),
            record,
            notes: reasons,
        }),
    };
    let ci_args = ci::Args {
        brainproxy: a.brainproxy.clone(),
        project: cli.project.clone(),
        url: t.base_url.clone(),
        preset: t.preset.clone(),
        fail_on,
        new_only,
        out: a.out.clone(),
        max_minutes: Some(t.max_minutes),
        rate: t.rate,
        auth: t.profile().map(String::from),
        accept_coverage_drop: a.accept_coverage_drop,
        baseline: a.baseline,
        policy,
    };
    Ok((work, Prepared { t, cli, loaded, opts, ci_args }))
}

fn refused(r: Refused) -> Refusal {
    match r {
        Refused::Invalid(m) => (code::USAGE, m),
        Refused::OutOfScope(m) => (code::OUT_OF_SCOPE, m),
        Refused::Internal(m) => (code::ERROR, m),
    }
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path, flag: &str) -> Result<T, Refusal> {
    let bytes = std::fs::read(path).map_err(|e| {
        let c = if e.kind() == std::io::ErrorKind::NotFound { code::NOT_FOUND } else { code::ERROR };
        (c, format!("{flag} {}: {e}", path.display()))
    })?;
    serde_json::from_slice(&bytes).map_err(|e| (code::USAGE, format!("{flag} {}: {e}", path.display())))
}

/// `--targets`: the deployment's targets, at most [`MAX_TARGETS`], one of them this one.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Registry {
    targets: Vec<String>,
}

fn check_registry(path: &Path, id: &str) -> Result<(), Refusal> {
    let r: Registry = read_json(path, "--targets")?;
    let mut ids = r.targets.clone();
    ids.sort();
    ids.dedup();
    if ids.len() != r.targets.len() || ids.iter().any(|i| !target::valid_id(i)) {
        return Err((code::USAGE, format!("--targets {}: ids must be valid and listed once", path.display())));
    }
    if ids.len() > MAX_TARGETS {
        return Err((
            code::USAGE,
            format!(
                "--targets {} lists {} targets; brainproxy-server scans at most {MAX_TARGETS}",
                path.display(),
                ids.len()
            ),
        ));
    }
    if !ids.iter().any(|i| i == id) {
        return Err((code::USAGE, format!("target {id} isn't listed in --targets {}", path.display())));
    }
    Ok(())
}

/// The state key's variable must not double as a target secret: `secret_env` would hand it to the
/// CLI (and a login form), a hook to a receiver.
fn check_key_not_shared(t: &TargetConfig, var: &str) -> Result<(), Refusal> {
    let mut names: Vec<&str> = t.secret_env.iter().flat_map(|(k, v)| [k.as_str(), v.as_str()]).collect();
    for h in &t.notify {
        names.push(&h.url_secret);
        names.extend(h.secret.as_deref());
    }
    names.extend(t.defectdojo.as_ref().map(|d| d.token_secret.as_str()));
    if names.contains(&var) {
        return Err((code::USAGE, format!("--state-key-env {var} is also one of target {}'s secrets", t.id)));
    }
    Ok(())
}

fn state_key(var: Option<&str>) -> Result<Option<Vec<u8>>, Refusal> {
    let Some(var) = var else { return Ok(None) };
    let value = std::env::var(var).map_err(|_| (code::USAGE, format!("--state-key-env {var} isn't set")))?;
    if value.len() < state::MIN_KEY_LEN {
        return Err((
            code::USAGE,
            format!("--state-key-env {var}: the key needs {} characters or more", state::MIN_KEY_LEN),
        ));
    }
    Ok(Some(value.into_bytes()))
}

/// A private folder under TMPDIR for this run.
fn make_work_dir(id: &str) -> Result<PathBuf, Refusal> {
    let mut rand = [0u8; 8];
    getrandom::fill(&mut rand).map_err(|e| (code::ERROR, format!("random: {e}")))?;
    let suffix: String = rand.iter().map(|b| format!("{b:02x}")).collect();
    let dir = std::env::temp_dir().join(format!("brainproxy-ci-{id}-{suffix}"));
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder.create(&dir).map_err(|e| (code::ERROR, format!("can't create {}: {e}", dir.display())))?;
    Ok(dir)
}

/// The CLI's environment, an allowlist as `serve`'s: PATH, a HOME of its own, the rules and checks
/// bundle (BRAINPROXY_HOME), TZ, the target's secrets, and the system scope (the image's, else
/// this target's scope alone).
fn cli_env(
    t: &TargetConfig,
    a: &Args,
    dir: &Path,
    reasons: &mut Vec<String>,
) -> Result<Vec<(OsString, OsString)>, Refusal> {
    let mut env: Vec<(OsString, OsString)> = Vec::new();
    env.push(("PATH".into(), std::env::var_os("PATH").unwrap_or_else(|| "/usr/local/bin:/usr/bin:/bin".into())));
    let home = dir.join("home");
    std::fs::create_dir_all(&home).map_err(|e| (code::ERROR, format!("{}: {e}", home.display())))?;
    env.push(("HOME".into(), home.clone().into_os_string()));
    match std::env::var_os("BRAINPROXY_HOME") {
        Some(h) => env.push(("BRAINPROXY_HOME".into(), h)),
        None => {
            reasons.push(
                "BRAINPROXY_HOME isn't set: the scan runs with the rules built into the CLI and no downloaded checks"
                    .into(),
            );
            env.push(("BRAINPROXY_HOME".into(), home.join(".brainproxy").into_os_string()));
        }
    }
    if let Some(tz) = std::env::var_os("TZ") {
        env.push(("TZ".into(), tz));
    }
    let scope = match std::env::var_os("BRAINPROXY_SYSTEM_SCOPE") {
        Some(s) => s,
        None => {
            reasons.push(
                "BRAINPROXY_SYSTEM_SCOPE isn't set: the target file alone decides what may be scanned; \
                 set a fixed one in the image or task definition"
                    .into(),
            );
            let path = dir.join("system-scope.json");
            std::fs::write(&path, target::system_scope(&[t]).to_string())
                .map_err(|e| (code::ERROR, format!("{}: {e}", path.display())))?;
            path.into_os_string()
        }
    };
    env.push(("BRAINPROXY_SYSTEM_SCOPE".into(), scope));
    env.extend(project::secrets(t, &a.secrets_dir).map_err(|e| (code::ERROR, e))?);
    Ok(env)
}

/// Stateless runs need `findings mark --from` (and `findings compare --scan --baseline`, which came
/// with it): brainproxy 0.5.2.
async fn check_cli(cli: &Cli) -> Result<(), Refusal> {
    let out = cli
        .run(["capabilities", "findings", "mark"])
        .await
        .map_err(|e| (code::ERROR, format!("can't run {}: {e}", cli.bin.display())))?;
    let has_from = out.data()["args"].as_array().into_iter().flatten().any(|a| a["flag"] == "--from");
    if !has_from {
        return Err((code::ERROR, "stateless ci needs brainproxy 0.5.2 or later (findings mark --from)".into()));
    }
    Ok(())
}

/// Whether the run that wrote `k` would be this run's `--since-scan` run: the same URL, preset and
/// auth profile, and a gate at least as strict, or a `--baseline` run (`record::since_scan_candidates`).
/// `now`: (url, preset, auth, policy fingerprint, fail_on, new_only).
fn known_applies(k: &Known, now: (&str, &str, Option<&str>, Option<&str>, Option<&str>, bool)) -> Result<(), String> {
    let (url, preset, auth, policy, fail_on, new_only) = now;
    if k.url != url {
        return Err(format!("they were found scanning {}, not {url}", k.url));
    }
    if k.preset != preset {
        return Err(format!("they were found with preset {}, not {preset}", k.preset));
    }
    if k.auth.as_deref() != auth {
        return Err(format!(
            "they were found as {}, not {}",
            k.auth.as_deref().unwrap_or("no login"),
            auth.unwrap_or("no login")
        ));
    }
    let strict = record::gate_settings_as_strict(
        (k.policy.as_deref(), k.fail_on.as_deref(), k.new_only),
        (policy, fail_on, new_only),
    );
    if !k.baseline && !strict {
        return Err(
            "the run that found them had a laxer gate or another alert policy; a --baseline run starts over".into()
        );
    }
    Ok(())
}

/// The versions of the rules and checks the CLI scans with.
async fn data_versions(cli: &Cli) -> Value {
    let data = |out: std::io::Result<crate::brainproxy::Output>| match out {
        Ok(o) if o.ok() => o.json["data"].clone(),
        _ => Value::Null,
    };
    let rules = data(cli.run(["scan", "data", "status"]).await);
    let checks = data(cli.run(["checks", "status"]).await);
    let store = |v: &Value| {
        if v.is_object() {
            json!({"commit": v["commit"], "sha256": v["sha256"], "updated_unix": v["updated_unix"], "stored": v["stored"]})
        } else {
            Value::Null
        }
    };
    json!({
        "rules": {
            "commit": rules["manifest"]["commit"],
            "embedded_commit": rules["embedded_commit"],
            "updated_unix": rules["manifest"]["updated_unix"],
        },
        "nuclei": store(&checks["nuclei"]),
        "brainproxy_checks": store(&checks["brainproxy"]),
        "local_checks": checks["local_files"],
    })
}

/// Writes the next state to `<run folder>/state/` and records it in `run.stateless.state`.
async fn next_state(
    a: &Args,
    t: &TargetConfig,
    cli: &Cli,
    loaded: &state::Loaded,
    plan: &ci::Stateless,
    run: &mut Run,
) -> Result<(), String> {
    let folder = run.folder.clone().ok_or("the run has no folder")?;
    let name = folder.file_name().unwrap_or_default().to_string_lossy().into_owned();
    let old = loaded.state.as_ref();
    let mut dropped = 0;
    let replace = run.outcome == Outcome::Passed && run.job.is_some();
    let (known, known_bytes) = if replace {
        let read = |file: &str| -> Result<Value, String> {
            let bytes = std::fs::read(folder.join(file)).map_err(|e| format!("{file}: {e}"))?;
            serde_json::from_slice(&bytes).map_err(|e| format!("{file}: {e}"))
        };
        let compare = read("compare.json")?;
        let data = &compare["data"];
        if data["summary"]["truncated"] == true {
            return Err("compare.json's lists were cut off, so what was fixed isn't known".into());
        }
        // Everything the job found, false positives included: `report.json` leaves them out, and
        // a mark that isn't carried forward would make the finding new again next run.
        let job = run.job.as_ref().map(|j| j.id).unwrap_or_default().to_string();
        let found_path = cli.project.with_file_name("found.json");
        let argv: Vec<OsString> = vec![
            "report".into(),
            "json".into(),
            "--scan".into(),
            job.into(),
            "--state".into(),
            "all".into(),
            "--limit".into(),
            "1000000".into(),
            "--force".into(),
            "--output".into(),
            found_path.clone().into_os_string(),
        ];
        let out = cli.run(argv).await.map_err(|e| format!("report json --state all: {e}"))?;
        if !out.ok() {
            return Err(format!("report json --state all: {}", out.message()));
        }
        let found: Value = serde_json::from_slice(&std::fs::read(&found_path).map_err(|e| format!("found.json: {e}"))?)
            .map_err(|e| format!("found.json: {e}"))?;
        let found = if found["ok"] == true { found["data"].clone() } else { found };
        if found["summary"]["truncated"] == true {
            return Err("the report of the job's findings was cut off".into());
        }
        let used = match &plan.known {
            Some(p) => Some(
                serde_json::from_slice::<Value>(&std::fs::read(p).map_err(|e| format!("known.json: {e}"))?)
                    .map_err(|e| format!("known.json: {e}"))?,
            ),
            None => None,
        };
        let used = used.map(|u| if u["ok"] == true { u["data"].clone() } else { u });
        let fixed = state::keys_of(&data["fixed"]);
        let (next, n) = state::carry_forward(&found, used.as_ref(), &fixed, &t.scope);
        dropped = n;
        let bytes = serde_json::to_vec_pretty(&next).map_err(|e| e.to_string())?;
        // A file the CLI can't read must never become the next state.
        let probe = cli.project.with_file_name("next-known.json");
        std::fs::write(&probe, &bytes).map_err(|e| format!("{}: {e}", probe.display()))?;
        let argv: Vec<OsString> = vec![
            "findings".into(),
            "compare".into(),
            "--baseline".into(),
            probe.clone().into_os_string(),
            "--current".into(),
            found_path.into_os_string(),
        ];
        let check = cli.run(argv).await.map_err(|e| format!("checking the next known set: {e}"))?;
        if !check.ok() {
            return Err(format!("the next known set doesn't load: {}", check.message()));
        }
        let known = Known {
            run: name.clone(),
            finished_at: run.finished_at.clone().unwrap_or_default(),
            url: run.url.clone(),
            preset: run.preset.clone(),
            auth: run.auth.clone(),
            fail_on: run.fail_on.clone(),
            new_only: run.new_only,
            policy: run.policy.clone(),
            baseline: run.baseline,
            file: state::KNOWN_FILE.into(),
            sha256: state::sha256_hex(&bytes),
        };
        (Some(known), Some(bytes))
    } else {
        (old.and_then(|s| s.known.clone()), loaded.known.clone())
    };
    let coverage = match (&run.coverage, &run.job) {
        (Some(c), Some(j)) if run.scan_complete() => Some(CoverageState {
            run: name,
            job: j.id,
            url: run.url.clone(),
            preset: run.preset.clone(),
            targets: c.targets,
            endpoints: c.endpoints,
            requests: c.requests,
        }),
        _ => old.and_then(|s| s.coverage.clone()),
    };
    let next = State {
        schema: state::SCHEMA,
        target: t.id.clone(),
        generation: old.map_or(1, |s| s.generation + 1),
        known,
        coverage,
    };
    let key = state_key(a.state_key_env.as_deref()).map_err(|(_, e)| e)?;
    let dir = folder.join("state");
    if let Err(e) = state::write(&dir, &next, known_bytes.as_deref(), key.as_deref()) {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(format!("{}: {e}", dir.display()));
    }
    if let Some(s) = run.stateless.as_mut() {
        s.state.written = Some(next.generation);
        s.state.known_replaced = replace;
        s.state.dropped_out_of_scope = dropped;
    }
    run.files.push("state/".into());
    Ok(())
}

/// `--notify`: the target's webhooks and DefectDojo reimport, each delivery recorded in `run.json`.
/// A failed one never changes the exit code.
async fn notify(t: &TargetConfig, secrets_dir: &Path, run: &mut Run) {
    let Some(folder) = run.folder.clone() else { return };
    let r = serde_json::to_value(&*run).unwrap_or_default();
    let Some(event) = crate::notify::Note::event_of(&r) else { return };
    let compare = std::fs::read(folder.join("compare.json"))
        .ok()
        .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
        .unwrap_or(Value::Null);
    let name = folder.file_name().unwrap_or_default().to_string_lossy().into_owned();
    let note = Arc::new(crate::notify::Note::from_run(&t.id, &name, &r, event, &compare));
    let sent = crate::notify::deliver(t, note, &folder, secrets_dir).await;
    if let Some(s) = run.stateless.as_mut() {
        s.notifications = sent
            .into_iter()
            .map(|d| match d.result {
                Ok(status) => json!({"action": d.action, "what": d.what, "ok": true, "status": status}),
                Err(e) => json!({"action": d.action, "what": d.what, "ok": false, "error": e}),
            })
            .collect();
    }
}

/// Writes `run.json` again, through a temporary file.
fn write_run(folder: &Path, run: &Run) -> std::io::Result<()> {
    let tmp = folder.join(".run.json.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(run).map_err(std::io::Error::other)?)?;
    std::fs::rename(&tmp, folder.join(record::RUN_FILE))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn known() -> Known {
        Known {
            run: "r".into(),
            finished_at: "t".into(),
            url: "https://a.test/".into(),
            preset: "standard".into(),
            auth: Some("user".into()),
            fail_on: Some("medium".into()),
            new_only: true,
            policy: None,
            baseline: false,
            file: state::KNOWN_FILE.into(),
            sha256: String::new(),
        }
    }

    #[test]
    fn the_known_set_applies_as_a_since_scan_run_would() {
        let k = known();
        let now = ("https://a.test/", "standard", Some("user"), None, Some("high"), true);
        assert!(known_applies(&k, now).is_ok());
        // Another URL, preset, login or policy, or a laxer gate than now: refused.
        assert!(known_applies(&k, ("https://b.test/", "standard", Some("user"), None, Some("high"), true)).is_err());
        assert!(known_applies(&k, ("https://a.test/", "quick", Some("user"), None, Some("high"), true)).is_err());
        assert!(known_applies(&k, ("https://a.test/", "standard", None, None, Some("high"), true)).is_err());
        assert!(
            known_applies(&k, ("https://a.test/", "standard", Some("user"), Some("p"), Some("high"), true)).is_err()
        );
        assert!(known_applies(&k, ("https://a.test/", "standard", Some("user"), None, Some("low"), true)).is_err());
        assert!(known_applies(&k, ("https://a.test/", "standard", Some("user"), None, Some("high"), false)).is_err());
        // A --baseline run accepted what was there: any gate may count from it.
        let b = Known { baseline: true, fail_on: None, ..known() };
        assert!(known_applies(&b, ("https://a.test/", "standard", Some("user"), None, Some("info"), false)).is_ok());
    }

    #[test]
    fn the_registry_holds_at_most_ten_targets() {
        let d = std::env::temp_dir().join(format!("bps-registry-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let f = d.join("targets.json");
        std::fs::write(&f, r#"{"targets": ["a", "shop"]}"#).unwrap();
        assert!(check_registry(&f, "shop").is_ok());
        assert!(check_registry(&f, "other").unwrap_err().1.contains("isn't listed"));
        let eleven: Vec<String> = (0..11).map(|i| format!("t{i}")).collect();
        std::fs::write(&f, json!({ "targets": eleven }).to_string()).unwrap();
        assert!(check_registry(&f, "t0").unwrap_err().1.contains("at most 10"));
        std::fs::write(&f, r#"{"targets": ["a", "a"]}"#).unwrap();
        assert!(check_registry(&f, "a").is_err());
        let _ = std::fs::remove_dir_all(&d);
    }
}
