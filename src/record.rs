//! `run.json`: what one `ci` run did, and the run folder history the next run reads.
//!
//! A run folder is `DIR/<start time>-<job>/` (`-none` when no scan was started). The history is
//! only ever read back for two things: the previous run that passed (the `--since-scan` job) and the
//! previous run whose scan completed (the coverage baseline).

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub const SCHEMA: u32 = 1;
pub const RUN_FILE: &str = "run.json";

/// How a run ended. Only `Passed` lets a pipeline go on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// Written when the run starts; a run folder still saying this was killed before it finished.
    Running,
    /// The scan completed and the gate (if any) passed.
    Passed,
    /// The scan completed and the gate found something (exit 5).
    Failed,
    /// The scan didn't run, didn't complete, or can't be trusted (exit 2). Never a pass.
    Incomplete,
    /// The CLI refused or failed (its own exit code).
    Error,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Job {
    pub id: u64,
    /// When the job started, as the CLI gives it (`job status` → `data.time`). It tells a job
    /// apart from one with the same id in a project file that was replaced.
    pub time: String,
    pub finished_time: Option<String>,
    pub state: String,
    /// `data.result.timed_out`: the scan ran out of `--max-minutes`.
    pub timed_out: bool,
    /// `data.result.crawl.timed_out`: the crawl was cut short.
    pub crawl_timed_out: bool,
}

/// How much a scan covered, from `job status` → `data.result`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Coverage {
    /// `result.targets`: distinct requests attacked.
    pub targets: u64,
    /// `result.crawl.endpoints`: endpoints the crawl found.
    pub endpoints: u64,
    /// `result.requests`: requests the scan sent.
    pub requests: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JobRef {
    pub job: u64,
    pub time: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CoverageBaseline {
    pub job: u64,
    pub coverage: Coverage,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Summary {
    pub new: u64,
    pub unchanged: u64,
    pub fixed: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Gate {
    pub fail_on: String,
    pub new_only: bool,
    pub passed: bool,
    pub count: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Run {
    pub schema: u32,
    pub server_version: String,
    pub brainproxy_version: String,
    pub project: PathBuf,
    pub url: String,
    pub preset: String,
    pub fail_on: Option<String>,
    pub new_only: bool,
    pub auth: Option<String>,
    pub max_minutes: Option<u64>,
    #[serde(default)]
    pub rate: Option<u32>,
    pub started_at: String,
    pub finished_at: Option<String>,
    pub job: Option<Job>,
    /// The `--since-scan` job: the previous run that passed.
    pub since_scan: Option<JobRef>,
    pub coverage: Option<Coverage>,
    pub coverage_baseline: Option<CoverageBaseline>,
    pub summary: Option<Summary>,
    pub gate: Option<Gate>,
    pub outcome: Outcome,
    /// Why the run isn't a pass, in order; also warnings that didn't change the outcome.
    pub reasons: Vec<String>,
    pub exit_code: Option<i32>,
    /// Files written next to `run.json`.
    pub files: Vec<String>,
    /// Started with `--baseline`: no gate, and later runs may count new findings from it.
    #[serde(default)]
    pub baseline: bool,
    /// The run folder (set when the run ends).
    #[serde(default)]
    pub folder: Option<PathBuf>,
}

impl Run {
    /// The scan completed in full, whatever the gate said.
    pub fn scan_complete(&self) -> bool {
        matches!(self.outcome, Outcome::Passed | Outcome::Failed)
    }
}

/// A run read back from the history, with its folder.
#[derive(Debug, Clone)]
pub struct Past {
    pub dir: PathBuf,
    pub run: Run,
}

/// Every readable `run.json` under `dir`, oldest first (folder names start with the time).
/// Folders that aren't runs, or whose `run.json` doesn't parse, are skipped.
pub fn history(dir: &Path) -> std::io::Result<Vec<Past>> {
    let mut out = Vec::new();
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(e),
    };
    for entry in entries {
        let path = entry?.path();
        let Ok(text) = std::fs::read_to_string(path.join(RUN_FILE)) else { continue };
        let Ok(run) = serde_json::from_str::<Run>(&text) else { continue };
        if run.schema == SCHEMA {
            out.push(Past { dir: path, run });
        }
    }
    out.sort_by(|a, b| a.dir.file_name().cmp(&b.dir.file_name()));
    Ok(out)
}

/// Candidates for `--since-scan`, newest first: runs that passed, of the same URL, preset and auth
/// profile, with a gate at least as strict as `now`'s. A run whose gate failed isn't one, so what it
/// found stays new until a run passes; nor is a run that didn't complete, nor a narrower or laxer one
/// that passed without finding again what an earlier run failed on. A `--baseline` run is one: it
/// deliberately accepts what is there.
pub fn since_scan_candidates<'a>(history: &'a [Past], now: &'a Run) -> impl Iterator<Item = &'a Past> {
    history.iter().rev().filter(move |p| {
        let r = &p.run;
        r.outcome == Outcome::Passed
            && r.job.is_some()
            && r.url == now.url
            && r.preset == now.preset
            && r.auth == now.auth
            && (r.baseline || gate_as_strict(r, now))
    })
}

/// `past`'s gate was at least as strict as `now`'s: a risk at or below it, and `--new-only` only if
/// `now` has it too. No gate now: anything goes.
fn gate_as_strict(past: &Run, now: &Run) -> bool {
    let Some(want) = now.fail_on.as_deref() else { return true };
    let Some(had) = past.fail_on.as_deref() else { return false };
    risk_rank(had) <= risk_rank(want) && (!past.new_only || now.new_only)
}

fn risk_rank(r: &str) -> u8 {
    match r {
        "info" => 0,
        "low" => 1,
        "medium" => 2,
        _ => 3,
    }
}

/// Candidates for the coverage baseline, newest first: runs of the same URL and preset whose scan
/// completed (passed or gate failed).
pub fn coverage_candidates<'a>(history: &'a [Past], url: &'a str, preset: &'a str) -> impl Iterator<Item = &'a Past> {
    history.iter().rev().filter(move |p| {
        p.run.scan_complete() && p.run.url == url && p.run.preset == preset && p.run.coverage.is_some()
    })
}

/// Below this share of the baseline, coverage counts as dropped.
pub const COVERAGE_MIN_PERCENT: u64 = 50;

/// What dropped below [`COVERAGE_MIN_PERCENT`] of the baseline, if anything.
pub fn coverage_drop(now: &Coverage, before: &Coverage) -> Option<String> {
    let mut dropped = Vec::new();
    for (name, n, b) in
        [("attacked requests", now.targets, before.targets), ("crawled endpoints", now.endpoints, before.endpoints)]
    {
        if n * 100 < b * COVERAGE_MIN_PERCENT {
            dropped.push(format!("{name} {n} (was {b})"));
        }
    }
    (!dropped.is_empty()).then(|| dropped.join(", "))
}

/// The run folder name: `20261101T171404Z-7` from the job's start time and id.
pub fn folder_name(start: &str, job: Option<u64>) -> String {
    let compact: String = start.chars().take(19).filter(|c| c.is_ascii_digit() || *c == 'T').collect();
    let job = job.map_or_else(|| "none".to_string(), |j| j.to_string());
    format!("{compact}Z-{job}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(outcome: Outcome, job: u64, url: &str, preset: &str) -> Run {
        Run {
            schema: SCHEMA,
            server_version: "0".into(),
            brainproxy_version: "0.4.6".into(),
            project: "p.bpdb".into(),
            url: url.into(),
            preset: preset.into(),
            fail_on: None,
            new_only: false,
            auth: None,
            max_minutes: None,
            rate: None,
            started_at: String::new(),
            finished_at: None,
            job: Some(Job { id: job, time: format!("t{job}"), ..Job::default() }),
            since_scan: None,
            coverage: Some(Coverage { targets: job, endpoints: job, requests: job }),
            coverage_baseline: None,
            summary: None,
            gate: None,
            outcome,
            reasons: vec![],
            exit_code: None,
            files: vec![],
            baseline: false,
            folder: None,
        }
    }

    fn write(dir: &Path, name: &str, r: &Run) {
        std::fs::create_dir_all(dir.join(name)).unwrap();
        std::fs::write(dir.join(name).join(RUN_FILE), serde_json::to_string(r).unwrap()).unwrap();
    }

    #[test]
    fn picks_the_last_passed_run_and_the_last_complete_one_for_coverage() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        write(d, "20261101T100000Z-1", &run(Outcome::Passed, 1, "http://a/", "quick"));
        write(d, "20261101T110000Z-2", &run(Outcome::Passed, 2, "http://a/", "standard"));
        write(d, "20261101T120000Z-3", &run(Outcome::Failed, 3, "http://a/", "quick"));
        write(d, "20261101T130000Z-4", &run(Outcome::Incomplete, 4, "http://a/", "quick"));
        write(d, "20261101T140000Z-5", &run(Outcome::Running, 5, "http://a/", "quick"));
        write(d, "20261101T150000Z-none", &run(Outcome::Error, 0, "http://a/", "quick"));
        std::fs::create_dir_all(d.join("not-a-run")).unwrap();
        std::fs::write(d.join("junk.txt"), "x").unwrap();
        let h = history(d).unwrap();
        assert_eq!(h.len(), 6);
        let ids = |now: &Run| -> Vec<u64> {
            since_scan_candidates(&h, now).map(|p| p.run.job.as_ref().unwrap().id).collect()
        };
        assert_eq!(ids(&run(Outcome::Running, 9, "http://a/", "quick")), [1]);
        assert_eq!(ids(&run(Outcome::Running, 9, "http://a/", "standard")), [2]);
        assert!(ids(&run(Outcome::Running, 9, "http://b/", "quick")).is_empty());
        let cov: Vec<u64> =
            coverage_candidates(&h, "http://a/", "quick").map(|p| p.run.job.as_ref().unwrap().id).collect();
        assert_eq!(cov, [3, 1]);
        assert_eq!(coverage_candidates(&h, "http://b/", "quick").count(), 0);
    }

    #[test]
    fn since_scan_needs_a_gate_as_strict() {
        let gated = |risk: Option<&str>, new_only: bool| {
            let mut r = run(Outcome::Passed, 1, "u", "p");
            r.fail_on = risk.map(String::from);
            r.new_only = new_only;
            r
        };
        let ok = |past: &Run, now: &Run| gate_as_strict(past, now);
        assert!(ok(&gated(Some("medium"), false), &gated(Some("high"), true)));
        assert!(ok(&gated(Some("high"), true), &gated(Some("high"), true)));
        assert!(!ok(&gated(Some("high"), true), &gated(Some("high"), false)));
        assert!(!ok(&gated(Some("high"), false), &gated(Some("medium"), false)));
        assert!(!ok(&gated(None, false), &gated(Some("high"), true)));
        assert!(ok(&gated(None, false), &gated(None, false)));
        let mut other_auth = gated(None, false);
        other_auth.auth = Some("user".into());
        let h = vec![Past { dir: "x".into(), run: other_auth }];
        assert_eq!(since_scan_candidates(&h, &gated(None, false)).count(), 0);
        let mut base = gated(None, false);
        base.baseline = true;
        let h = vec![Past { dir: "x".into(), run: base }];
        assert_eq!(since_scan_candidates(&h, &gated(Some("info"), false)).count(), 1);
    }

    #[test]
    fn missing_dir_is_an_empty_history() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(history(&tmp.path().join("nope")).unwrap().is_empty());
    }

    #[test]
    fn coverage_drop_below_half() {
        let before = Coverage { targets: 100, endpoints: 40, requests: 1000 };
        assert_eq!(coverage_drop(&Coverage { targets: 50, endpoints: 20, requests: 1 }, &before), None);
        assert_eq!(
            coverage_drop(&Coverage { targets: 49, endpoints: 20, requests: 1 }, &before).unwrap(),
            "attacked requests 49 (was 100)"
        );
        assert_eq!(
            coverage_drop(&Coverage { targets: 0, endpoints: 0, requests: 0 }, &before).unwrap(),
            "attacked requests 0 (was 100), crawled endpoints 0 (was 40)"
        );
        assert_eq!(coverage_drop(&Coverage::default(), &Coverage::default()), None);
    }

    #[test]
    fn folder_names() {
        assert_eq!(folder_name("2026-11-01T17:14:04.755Z", Some(7)), "20261101T171404Z-7");
        assert_eq!(folder_name("2026-11-01T17:14:04Z", None), "20261101T171404Z-none");
    }
}
