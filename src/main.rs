//! brainproxy-server: a small scan service around the brainproxy CLI.
//!
//! - `ci`: scan once, compare with the previous runs, gate, write a run folder, and exit with the
//!   CLI's own exit codes.
//! - `serve`: the same pipeline behind an HTTP API, a queue and per-target tokens.
//! - `remote run|wait`: the pipeline side of `serve`: trigger, wait, exit with the run's code.

mod brainproxy;
mod ci;
mod record;
mod remote;
mod serve;
mod time;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(name = "brainproxy-server", version, about)]
struct Opts {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Scan a target once, compare with the previous runs, gate, and write the results to a run folder.
    ///
    /// Exit codes are the brainproxy CLI's: 0 passed, 5 the gate found something, 2 the run is
    /// incomplete (the scan failed, was stopped or cut short, the login broke, or coverage dropped),
    /// 4 the project or auth profile doesn't exist, 6 out of scope or no engagement, 3 network, 1 other.
    Ci(CiOpts),
    /// Run the scan service: an HTTP API for registered targets, a queue, and scan workers.
    ///
    /// Admin endpoints (registering targets, tokens, project uploads) are only on --admin-listen,
    /// which should stay on loopback or a bastion; pipelines use --listen, behind a TLS proxy.
    Serve(ServeOpts),
    /// Trigger a scan on a brainproxy-server, or wait for one, and exit with the run's exit code.
    #[command(subcommand)]
    Remote(RemoteCommand),
}

#[derive(clap::Args)]
struct ServeOpts {
    /// Work directory: control.db, the targets' projects and their runs. Must be on local disk.
    #[arg(long, env = "BRAINPROXY_SERVER_WORK", default_value = "/work")]
    work: PathBuf,
    /// Address of the API for pipelines (put a TLS reverse proxy in front of it).
    #[arg(long, env = "BRAINPROXY_SERVER_LISTEN", default_value = "127.0.0.1:9090")]
    listen: SocketAddr,
    /// Address of the admin API. Keep it on loopback (or a bastion network); never proxy it.
    #[arg(long, env = "BRAINPROXY_SERVER_ADMIN_LISTEN", default_value = "127.0.0.1:9091")]
    admin_listen: SocketAddr,
    /// File holding the admin token (at least 32 characters, e.g. `openssl rand -hex 32`).
    #[arg(long, env = "BRAINPROXY_SERVER_ADMIN_TOKEN_FILE")]
    admin_token_file: PathBuf,
    /// Scans running at the same time, across all targets (one per target at most).
    #[arg(long, default_value_t = 3, value_parser = clap::value_parser!(u64).range(1..=10))]
    max_parallel: u64,
    /// Target secrets as files: DIR/<target>/<VARIABLE> (Docker and Kubernetes secrets).
    #[arg(long, env = "BRAINPROXY_SERVER_SECRETS_DIR", default_value = "/run/secrets")]
    secrets_dir: PathBuf,
    /// Where to write the system scope (all targets' hosts) the CLI enforces; default WORK/system-scope.json.
    #[arg(long)]
    system_scope: Option<PathBuf>,
    /// Project snapshots (`project save`) kept per target, one after each completed run.
    #[arg(long, default_value_t = 5)]
    keep_snapshots: usize,
    /// Largest project upload, in MB.
    #[arg(long, default_value_t = 512)]
    max_project_mb: u64,
    /// Days of audit log kept.
    #[arg(long, default_value_t = 365)]
    audit_days: u64,
    /// Run even if WORK is on a network filesystem (NFS, SMB, FUSE...): SQLite WAL and file locks
    /// may then break, and project files with them.
    #[arg(long)]
    allow_network_fs: bool,
    /// Allow targets on this machine (localhost, 127.0.0.1). Only for trying the server out.
    #[arg(long)]
    allow_loopback_targets: bool,
    /// Take the client address from X-Forwarded-For (only behind a reverse proxy that sets it).
    #[arg(long)]
    trust_forwarded: bool,
    /// The brainproxy CLI to run.
    #[arg(long, env = "BRAINPROXY_BIN", default_value = "brainproxy")]
    brainproxy: PathBuf,
}

#[derive(Subcommand)]
enum RemoteCommand {
    /// Trigger a scan of a target and wait for it. Exit codes: 0 passed, 5 the gate failed,
    /// 2 incomplete, superseded, cancelled or --timeout, 3 server unreachable or network error,
    /// 4 unknown target, 6 out of scope, 1 anything else.
    Run(RemoteRunOpts),
    /// Wait for a run started earlier (e.g. after `run --detach` or a --timeout); same exit codes.
    Wait(RemoteWaitOpts),
}

#[derive(clap::Args)]
struct RemoteCommon {
    /// The server's URL, e.g. https://scan.corp.test
    #[arg(long, env = "BRAINPROXY_SERVER_URL")]
    server: String,
    /// The target's id on the server.
    #[arg(long, env = "BRAINPROXY_SERVER_TARGET")]
    target: String,
    /// Environment variable holding the target token.
    #[arg(long, default_value = "BRAINPROXY_TOKEN")]
    token_env: String,
    /// Give up waiting after this long (90s, 45m, 2h); the run goes on. Exit 2.
    #[arg(long, default_value = "90m", value_parser = remote::parse_duration)]
    timeout: std::time::Duration,
    /// Save the SARIF report here.
    #[arg(long)]
    sarif: Option<PathBuf>,
    /// Save the HTML report here.
    #[arg(long)]
    report: Option<PathBuf>,
    /// Save the JSON report here.
    #[arg(long)]
    json_report: Option<PathBuf>,
    /// Save the drift (new, unchanged and fixed findings) here.
    #[arg(long)]
    drift: Option<PathBuf>,
}

#[derive(clap::Args)]
struct RemoteRunOpts {
    #[command(flatten)]
    common: RemoteCommon,
    /// Commit being tested: a run of the same commit within 24 hours is answered with that run.
    #[arg(long)]
    commit: Option<String>,
    /// Git ref, stored with the run.
    #[arg(long = "ref")]
    git_ref: Option<String>,
    /// Link to the pipeline, stored with the run.
    #[arg(long)]
    pipeline_url: Option<String>,
    /// A lighter scan than the target's own preset (never a deeper one).
    #[arg(long, value_enum)]
    preset: Option<Preset>,
    /// Scan again even if this commit completed within 24 hours.
    #[arg(long)]
    force: bool,
    /// Idempotency-Key for the trigger (default: the commit, or a random key per invocation).
    #[arg(long)]
    idempotency_key: Option<String>,
    /// Print the queued run and exit 0 without waiting.
    #[arg(long)]
    detach: bool,
}

#[derive(clap::Args)]
struct RemoteWaitOpts {
    #[command(flatten)]
    common: RemoteCommon,
    /// The run id `remote run` printed.
    #[arg(long)]
    run: String,
}

#[derive(clap::Args)]
struct CiOpts {
    /// Project file. It must exist and have an engagement scope: `ci` never creates one.
    #[arg(long)]
    project: PathBuf,
    /// URL to crawl and scan; it must be inside the engagement scope.
    #[arg(long)]
    url: String,
    /// Scan depth (`scan active --preset`).
    #[arg(long, value_enum, default_value_t = Preset::Standard)]
    preset: Preset,
    /// Fail (exit 5) on findings at or above this risk.
    #[arg(long, value_enum)]
    fail_on: Option<Risk>,
    /// With --fail-on: only count findings that are new since the previous passed run.
    #[arg(long, requires = "fail_on")]
    new_only: bool,
    /// Folder for the runs: each run writes `DIR/<time>-<job>/`, and the next run reads them back.
    #[arg(long)]
    out: PathBuf,
    /// Stop the scan after this many minutes; a scan stopped this way is incomplete.
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
    max_minutes: Option<u64>,
    /// Requests per second at most (`scan active --rate`).
    #[arg(long, value_parser = clap::value_parser!(u32).range(1..))]
    rate: Option<u32>,
    /// Auth profile in the project to log in with first and to scan with.
    #[arg(long)]
    auth: Option<String>,
    /// Don't treat coverage below half of the previous run as incomplete (once, after the app really shrank).
    #[arg(long)]
    accept_coverage_drop: bool,
    /// Start the history here: no gate, and later gated runs count as new only what is first seen
    /// after this run. For a first run on an app with known issues; recorded in run.json.
    #[arg(long, conflicts_with = "fail_on")]
    baseline: bool,
    /// The brainproxy CLI to run.
    #[arg(long, env = "BRAINPROXY_BIN", default_value = "brainproxy")]
    brainproxy: PathBuf,
}

#[derive(Clone, Copy, ValueEnum)]
enum Preset {
    Quick,
    Standard,
    Thorough,
}

#[derive(Clone, Copy, ValueEnum)]
enum Risk {
    Info,
    Low,
    Medium,
    High,
}

fn name<T: ValueEnum>(v: T) -> String {
    v.to_possible_value().map(|p| p.get_name().to_string()).unwrap_or_default()
}

fn remote_args(c: RemoteCommon) -> remote::Args {
    remote::Args {
        server: c.server,
        target: c.target,
        token_env: c.token_env,
        run: None,
        commit: None,
        git_ref: None,
        pipeline_url: None,
        preset: None,
        force: false,
        idempotency_key: None,
        timeout: c.timeout,
        detach: false,
        sarif: c.sarif,
        html: c.report,
        json: c.json_report,
        drift: c.drift,
    }
}

fn main() -> ExitCode {
    let opts = Opts::parse();
    let code = match opts.command {
        Command::Remote(RemoteCommand::Run(o)) => remote::run(remote::Args {
            commit: o.commit,
            git_ref: o.git_ref,
            pipeline_url: o.pipeline_url,
            preset: o.preset.map(name),
            force: o.force,
            idempotency_key: o.idempotency_key,
            detach: o.detach,
            ..remote_args(o.common)
        }),
        Command::Remote(RemoteCommand::Wait(o)) => {
            remote::wait(remote::Args { run: Some(o.run), ..remote_args(o.common) })
        }
        Command::Serve(o) => serve(o),
        Command::Ci(o) => ci(o),
    };
    ExitCode::from(u8::try_from(code).unwrap_or(1))
}

fn serve(o: ServeOpts) -> i32 {
    let rt = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("brainproxy-server: {e}");
            return 1;
        }
    };
    let cfg = serve::Config {
        system_scope: o.system_scope.unwrap_or_else(|| o.work.join("system-scope.json")),
        work: o.work,
        brainproxy: o.brainproxy,
        listen: o.listen,
        admin_listen: o.admin_listen,
        admin_token_file: o.admin_token_file,
        max_parallel: o.max_parallel as usize,
        secrets_dir: o.secrets_dir,
        keep_snapshots: o.keep_snapshots,
        max_project_mb: o.max_project_mb,
        audit_days: o.audit_days,
        allow_network_fs: o.allow_network_fs,
        allow_loopback_targets: o.allow_loopback_targets,
        trust_forwarded: o.trust_forwarded,
    };
    match rt.block_on(serve::run(cfg)) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("brainproxy-server: {e}");
            1
        }
    }
}

fn ci(o: CiOpts) -> i32 {
    let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("brainproxy-server: {e}");
            return 1;
        }
    };
    rt.block_on(ci::run(ci::Args {
        brainproxy: o.brainproxy,
        project: o.project,
        url: o.url,
        preset: name(o.preset),
        fail_on: o.fail_on.map(name),
        new_only: o.new_only,
        out: o.out,
        max_minutes: o.max_minutes,
        rate: o.rate,
        auth: o.auth,
        accept_coverage_drop: o.accept_coverage_drop,
        baseline: o.baseline,
    }))
}
