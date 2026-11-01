//! Running the brainproxy CLI as a separate program.
//!
//! Every call passes `--format json` and reads the one JSON envelope the CLI prints on stdout:
//! `{ok, command, data}` or `{ok: false, command, error: {kind, message}}`. The exit code is kept as
//! the CLI gives it, because `ci` exits with the CLI's own codes.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use serde_json::Value;
use tokio::process::Command;

/// The oldest CLI with `scan active --preset`, `findings compare --since-scan` and `report --scan`.
pub const MIN_VERSION: (u64, u64, u64) = (0, 4, 6);

/// Exit codes shared with the CLI (`brainproxy capabilities` → `exit_codes`).
pub mod code {
    pub const OK: i32 = 0;
    pub const ERROR: i32 = 1;
    pub const USAGE: i32 = 2;
    pub const NOT_FOUND: i32 = 4;
    pub const GATE_FAILED: i32 = 5;
    pub const OUT_OF_SCOPE: i32 = 6;
}

/// The result of one CLI call.
#[derive(Debug)]
pub struct Output {
    pub code: i32,
    /// The parsed envelope, or `Value::Null` when stdout wasn't JSON.
    pub json: Value,
    pub stdout: String,
    pub stderr: String,
}

impl Output {
    /// `data` of a successful envelope.
    pub fn data(&self) -> &Value {
        &self.json["data"]
    }

    pub fn ok(&self) -> bool {
        self.code == code::OK && self.json["ok"] == Value::Bool(true)
    }

    /// The CLI's error message, or what it printed when there was no envelope.
    pub fn message(&self) -> String {
        if let Some(m) = self.json["error"]["message"].as_str() {
            return m.to_string();
        }
        let text = if self.stderr.trim().is_empty() { &self.stdout } else { &self.stderr };
        let text = text.trim();
        if text.is_empty() { format!("exit code {}", self.code) } else { text.chars().take(500).collect() }
    }
}

/// One project file, used through one CLI binary.
#[derive(Debug, Clone)]
pub struct Cli {
    pub bin: PathBuf,
    pub project: PathBuf,
}

impl Cli {
    /// Runs `brainproxy --project P --format json ARGS...`.
    pub async fn run<I, S>(&self, args: I) -> std::io::Result<Output>
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        let mut cmd = Command::new(&self.bin);
        cmd.arg("--project").arg(&self.project).arg("--format").arg("json");
        cmd.args(args.into_iter().map(Into::into));
        run(cmd).await
    }
}

/// Runs a command that prints a brainproxy JSON envelope.
pub async fn run(mut cmd: Command) -> std::io::Result<Output> {
    cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).kill_on_drop(true);
    // Its own process group, so a Ctrl-C or a CI runner signalling ours reaches `ci` (which then
    // stops the scan job) rather than killing the `job wait` it is running.
    #[cfg(unix)]
    cmd.process_group(0);
    let out = cmd.output().await?;
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    let json = serde_json::from_str(stdout.trim()).unwrap_or(Value::Null);
    // A CLI killed by a signal has no code; count it as an internal error.
    let code = out.status.code().unwrap_or(code::ERROR);
    Ok(Output { code, json, stdout, stderr })
}

/// The CLI's version from `capabilities`, checked against [`MIN_VERSION`].
pub async fn check_version(bin: &Path) -> Result<String, String> {
    let mut cmd = Command::new(bin);
    cmd.args(["--format", "json", "capabilities"]);
    let out = run(cmd).await.map_err(|e| format!("can't run {}: {e}", bin.display()))?;
    let version = out.data()["version"]
        .as_str()
        .ok_or_else(|| format!("{} capabilities didn't print a version ({})", bin.display(), out.message()))?;
    match parse_version(version) {
        Some(v) if v >= MIN_VERSION => Ok(version.to_string()),
        _ => {
            let (a, b, c) = MIN_VERSION;
            Err(format!("brainproxy {version} is too old: {a}.{b}.{c} or later is needed"))
        }
    }
}

/// `"0.4.6"` or `"0.4.6-dev"` → `(0, 4, 6)`.
pub fn parse_version(v: &str) -> Option<(u64, u64, u64)> {
    let core = v.split(['-', '+']).next()?;
    let mut parts = core.split('.').map(|p| p.parse::<u64>().ok());
    Some((parts.next()??, parts.next()??, parts.next()??))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions() {
        assert_eq!(parse_version("0.4.6"), Some((0, 4, 6)));
        assert_eq!(parse_version("1.10.0-dev"), Some((1, 10, 0)));
        assert_eq!(parse_version("0.4"), None);
        assert_eq!(parse_version("x"), None);
        assert!(parse_version("0.4.5").unwrap() < MIN_VERSION);
        assert!(parse_version("0.10.0").unwrap() > MIN_VERSION);
    }
}
