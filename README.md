# brainproxy server

A small self-hosted scan service for [brainproxy](https://github.com/r4nd0mth1ngs/brainproxy).
Pipelines call it after deploying to a dev instance: it scans a registered target, compares the
results with the previous scan, and reports what is new, fixed and unchanged. One server handles
at most 10 targets.

Status: early development. The first command, `ci`, works; the HTTP service (`serve`) is next.

## `brainproxy-server ci`

One scan of one target, from a pipeline or by hand. It needs the
[brainproxy CLI](https://github.com/r4nd0mth1ngs/brainproxy/releases) 0.4.6 or later, on `PATH`, in
`BRAINPROXY_BIN`, or given with `--brainproxy`.

```sh
cargo install --locked --git https://github.com/r4nd0mth1ngs/brainproxy_server brainproxy-server

# Once: a project with a scope (and, for a logged-in scan, an auth profile). ci never creates one.
brainproxy --project app.bpdb engagement start --target shop-dev.example.test

# After each deploy:
brainproxy-server ci --project app.bpdb --url https://shop-dev.example.test/ --preset standard \
    --fail-on high --new-only --out runs [--max-minutes 60] [--auth user]
```

It:

1. refuses a project that doesn't exist (4) or has no engagement scope (6), and a project with a
   scan still running (2);
2. with `--auth NAME`, logs in and checks the session with `auth status`; a broken login ends the run
   as incomplete before anything is scanned;
3. runs `scan active URL --crawl --preset X --background` and waits for the job;
4. applies the outcome rules: a scan that failed, was stopped, ran out of `--max-minutes`, had its
   crawl cut short, or covered less than half of what the previous complete run of the same URL and
   preset covered (attacked requests or crawled endpoints) is **incomplete**, never a pass. After a
   real shrink of the app, run once with `--accept-coverage-drop`;
5. compares with `findings compare --scan J --since-scan P`, where P is the previous run that
   **passed**: "new" means first seen after P finished, so a finding first seen by a failed or
   gate-failed run stays new until a run passes. The gate (`--fail-on`, `--new-only`) only runs on a
   complete scan;
6. writes `run.json`, `compare.json` (the CLI's output as it is), `report.json`, `report.html` and
   `report.sarif` (only what this scan found) to `runs/<start time>-<job>/`;
7. exits with the CLI's codes:

| Code | Meaning |
|------|---------|
| `0` | Passed |
| `5` | The gate found something (the run folder is complete) |
| `2` | Incomplete: the scan failed, was stopped or cut short, the login broke, coverage dropped, the run was cancelled, or another run holds the folder |
| `4` | The project or auth profile doesn't exist |
| `6` | Out of scope, or the project has no engagement |
| `3` | Network error |
| `1` | Anything else |

SIGINT or SIGTERM (a cancelled CI job) stops the scan job and ends the run as incomplete. The run
folder is the history the next run reads: keep it together with the project file, for example in
the CI cache. `run.json` has the job, the since-scan job, coverage and its baseline, the drift
summary, the gate, the outcome and every reason. Progress and a summary go to stderr; `run.json` is
also printed on stdout.

[`contrib/ci/github-actions.yml`](contrib/ci/github-actions.yml) is a complete GitHub Actions
example.

## Development

`scripts/check.sh` runs formatting, clippy and the tests. The contract tests run the real CLI
against a small local web app; they use `BRAINPROXY_BIN` (or `brainproxy` on `PATH`) and are skipped
without one, unless `BRAINPROXY_CONTRACT=1` is set.

## How it relates to brainproxy

The server runs the `brainproxy` command line tool as a separate program and reads its JSON output.
It contains no brainproxy code. brainproxy itself is a separate project under the Apache License 2.0.

## License

This project is source-available under the [PolyForm Shield License 1.0.0](LICENSE.md). You may use,
change and run it, including inside a company, for free. Offering it, or something built from it,
as a product or hosted service that competes with it needs permission: open an issue or contact
the author.
