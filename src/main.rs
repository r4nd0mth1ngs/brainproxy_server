//! brainproxy-server: a small scan service around the brainproxy CLI.
//!
//! Phase 1 has one command, `ci`: scan, compare with the previous runs, gate, write a run folder,
//! and exit with the CLI's own exit codes.

mod brainproxy;
mod ci;
mod record;
mod time;

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
    /// Auth profile in the project to log in with first and to scan with.
    #[arg(long)]
    auth: Option<String>,
    /// Don't treat coverage below half of the previous run as incomplete (once, after the app really shrank).
    #[arg(long)]
    accept_coverage_drop: bool,
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

fn main() -> ExitCode {
    let opts = Opts::parse();
    let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("brainproxy-server: {e}");
            return ExitCode::from(1);
        }
    };
    let code = match opts.command {
        Command::Ci(o) => rt.block_on(ci::run(ci::Args {
            brainproxy: o.brainproxy,
            project: o.project,
            url: o.url,
            preset: name(o.preset),
            fail_on: o.fail_on.map(name),
            new_only: o.new_only,
            out: o.out,
            max_minutes: o.max_minutes,
            auth: o.auth,
            accept_coverage_drop: o.accept_coverage_drop,
        })),
    };
    ExitCode::from(u8::try_from(code).unwrap_or(1))
}
