# brainproxy server

A small self-hosted scan service for [brainproxy](https://github.com/r4nd0mth1ngs/brainproxy).
Pipelines call it after deploying to a dev instance: it scans a registered target, compares the
results with the previous scan, and reports what is new, fixed and unchanged. One server handles
at most 10 targets.

Status: early development. `ci`, `serve` and `remote` work, with OIDC from CI, alert policies, an
optional ownership check and a read-only results page.

## `brainproxy-server ci`

One scan of one target, from a pipeline or by hand. It needs the
[brainproxy CLI](https://github.com/r4nd0mth1ngs/brainproxy/releases) 0.4.6 or later, on `PATH`, in
`BRAINPROXY_BIN`, or given with `--brainproxy`.

```sh
cargo install --locked --git https://github.com/r4nd0mth1ngs/brainproxy_server brainproxy-server

# Once: a project with a scope (and, for a logged-in scan, an auth profile). ci never creates one.
brainproxy --project app.bpdb engagement start --target shop-dev.example.test

# Once, on an app with known issues: accept what is there now as the starting point.
brainproxy-server ci --project app.bpdb --url https://shop-dev.example.test/ --preset standard \
    --baseline --out runs

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
   **passed** with the same URL, preset and auth profile and a gate at least as strict (a risk at or
   below this one; `--new-only` only if this run has it too), or a `--baseline` run. "New" means
   first seen after P finished, so a finding first seen by a failed, gate-failed, narrower or laxer
   run stays new until a run like this one passes. Without such a run every finding this scan made
   is new: start with `--baseline` (no gate) to accept what an app already has. The gate
   (`--fail-on`, `--new-only`) only runs on a complete scan, and an exit 0 from `findings compare`
   only counts with a complete result whose gate passed;
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

SIGINT or SIGTERM (a cancelled CI job) stops the scan job, writes `run.json` as incomplete at once
(runners kill the process a few seconds later), and ends the run as incomplete, even if the job
completed meanwhile. If `job wait` keeps failing, the job is stopped too: a scan is never left
running. Failed rule units (`result.errors`) are listed in the reasons. The run
folder is the history the next run reads: keep it together with the project file, for example in
the CI cache. `run.json` has the job, the since-scan job, coverage and its baseline, the drift
summary, the gate, the outcome, every reason and the run folder (`folder`). Progress and a summary go to stderr; `run.json` is
also printed on stdout.

[`contrib/ci/github-actions.yml`](contrib/ci/github-actions.yml) is a complete GitHub Actions
example.

## `brainproxy-server serve`

The same pipeline behind an HTTP API, for pipelines that shouldn't hold the project file or reach
the dev instance themselves. An admin registers each target once (its URL, exact hosts, scan depth
and gate); a pipeline then only names the target and gets a verdict.

- **Two listeners.** `--listen` (default `127.0.0.1:9090`) is for pipelines, behind a TLS reverse
  proxy. `--admin-listen` (default `127.0.0.1:9091`) is for the admin token and the only place
  where targets are registered, tokens issued and projects uploaded. Keep it on loopback or a
  bastion; admin endpoints don't exist on the public listener.
- **Tokens.** One per target (`bpt_<target>_...`, shown once, stored as SHA-256), with `trigger` or
  `read` permission, 180 days by default. A token only works for its own target. The admin token
  is read from `--admin-token-file`.
- **Callers never send a URL or scan flags.** URL, scope, preset, gate, rate and time limit all come
  from the registration. A trigger can only lower the preset.
- **Scope, four times.** Registration accepts exact hosts, addresses or IPv4 networks of /24 or
  narrower; no wildcards, loopback, link-local or metadata addresses; the base URL must be inside
  the scope and pass `engagement check`, and its host must not resolve to this machine (checked
  again before every run). The project's engagement scope is write-once. The server writes the
  union of all targets' scopes to a system scope file the CLI enforces on top
  (`BRAINPROXY_SYSTEM_SCOPE`). Add an egress firewall to the targets' addresses; in a container
  that also keeps a re-pointed target name away from the server's own bridge address, where the
  admin port listens (it still needs the admin token).
- **Secrets.** A target's `secret_env` maps the variables its auth profile reads to files
  `--secrets-dir/<target>/<VARIABLE>` (Docker and Kubernetes secrets) or the server's environment.
  Every CLI process gets a cleared environment with a small allowlist plus its own target's secrets.
- **Queue.** One running and one queued run per target, at most `--max-parallel` (3) scans. A newer
  trigger replaces the queued run, which ends as `superseded`. A trigger from the same token with the
  same `commit` and preset while that run is still queued returns it; a finished run is never
  reused for a commit (a commit is only a label the caller chose, and the run tested whatever was
  deployed then). The same `Idempotency-Key` from the same token returns its run for 24 hours;
  `remote` sends a fresh random key per invocation. A restart waits for
  running scans again (in a container a restart also ends them: those runs end incomplete).
- **Outcome rules** are those of `ci`: anything cut short, cancelled, superseded, with a broken
  login or collapsed coverage is incomplete (exit 2), never a pass; so is a run cancelled after its
  scan completed. A snapshot of the project is
  kept after each completed run (`--keep-snapshots`, 5).
- **Limits.** At most 10 targets (compiled in). Per token: 10 triggers and 600 requests an hour.
  Failed authentications: 30 per address and listener per 10 minutes, then 429; valid credentials
  are never refused for others' failures. Bodies 64 KB; uploads `--max-project-mb`.
- **Audit log.** Registrations, tokens, uploads, triggers, cancels, downloads and refused
  authentications, in `control.db` and as JSON lines on stdout.
- **Storage.** `--work` (default `/work`) must be local disk: the server refuses NFS, SMB and FUSE.

```sh
openssl rand -hex 32 > admin_token && chmod 600 admin_token
brainproxy-server serve --work /srv/bps --admin-token-file admin_token

ADMIN="Authorization: Bearer $(cat admin_token)"
curl -H "$ADMIN" http://127.0.0.1:9091/v1/targets -d '{
  "id": "shop-dev", "base_url": "https://shop-dev.example.test/", "scope": ["shop-dev.example.test:443"],
  "preset": "standard", "max_minutes": 45, "gate": {"fail_on": "high", "new_only": true},
  "auth": {"name": "ci", "login_url": "https://shop-dev.example.test/login",
           "login_body": "{\"email\":\"{{username}}\",\"password\":\"{{password}}\"}",
           "username": "ci@example.test", "password_env": "APP_PW",
           "check_url": "https://shop-dev.example.test/me", "logged_in": "ci@example.test"},
  "secret_env": {"APP_PW": "SHOP_DEV_APP_PW"}}'
curl -H "$ADMIN" http://127.0.0.1:9091/v1/targets/shop-dev/tokens -d '{"name": "github"}'
# Optional, once: no gate for the first run, later runs count new findings from it.
curl -H "$ADMIN" http://127.0.0.1:9091/v1/targets/shop-dev/next-run -d '{"baseline": true}'
```

Instead of a generated project, a target can take one built in the brainproxy app (recorded login,
macros): register it with `"project": "upload"` and `"auth_profile"`, then
`curl -H "$ADMIN" -T app.bpdb http://127.0.0.1:9091/v1/targets/shop-dev/project`. The upload is
refused unless its scope is inside the registered one, it has no upstream proxies (engagement or
`connection upstream`), its host overrides (`connection hosts`) point only at addresses the scope
lists, and no profile stores a password in the file.

### OIDC, alert policies, ownership

- **OIDC from CI** replaces stored tokens. The server trusts the issuers it is started with
  (`--oidc-issuer github`, `--oidc-issuer gitlab=https://gitlab.example.test`,
  `--oidc-issuer azure=ISSUER,JWKS_URL`) and `--oidc-audience https://scan.example.test`, the
  audience tokens must be minted for. A target binds claims, which must all match exactly:
  `"oidc": [{"issuer": "https://token.actions.githubusercontent.com", "claims": {"repository_id":
  "123456", "ref": "refs/heads/main"}}]`. A GitHub binding must name `repository_id`, a GitLab one
  `project_id` (ids a recreated repository with the same name doesn't inherit), an Azure DevOps one
  `sub` (the service connection; its audience is fixed, so any receiver of that connection's tokens
  accepts them). RS256 and ES256 only; keys are cached for 10 minutes. A bound token may trigger,
  read and cancel on that target, like a trigger token; `remote --oidc github` fetches GitHub's
  token itself, and GitLab's `id_tokens` go in through `--token-env`.
- **Alert policy**: `"policy": {"10020": "ignore", "10038-1": "warn", "40012": "fail"}`, per rule
  id or variant, like ZAP's baseline rules file (`ci --policy FILE` takes that file's
  tab-separated format, or JSON). `ignore` leaves the rule out of the gate, `warn` lists it in the
  reasons without failing, `fail` fails the gate whatever the risk. Reports still list every
  finding. Changing the policy restarts the "new since the last pass" history.
- **Ownership check** (`"ownership": true`, off by default): before each scan the target must
  serve the token the server made (`ownership_token` in the target's configuration) as a line of
  `/.well-known/brainproxy-<id>.txt`, or the run fails with exit 6. It guards against registering
  the wrong host; like GitLab's site validation it is not a security feature.

`PATCH /v1/targets/{t}` (admin) changes `oidc`, `policy` and `ownership`; the scope and URL only
change with a new registration.

### Endpoints

| Method and path | Who | |
|---|---|---|
| `POST /v1/targets`, `DELETE /v1/targets/{t}` | admin | Register or remove a target (at most 10) |
| `PATCH /v1/targets/{t}` | admin | Change `oidc`, `policy`, `ownership` |
| `POST/GET /v1/targets/{t}/tokens`, `DELETE .../tokens/{id}` | admin | Issue, list, revoke tokens |
| `PUT /v1/targets/{t}/project` | admin | Upload a project |
| `POST /v1/targets/{t}/next-run` | admin | `{"baseline": true}` or `{"accept_coverage_drop": true}` for the next run only |
| `GET /v1/summary`, `GET /v1/audit` | admin | Counts and last runs per target; the audit log |
| `GET /v1/targets`, `GET /v1/targets/{t}` | token (own target) or admin | Configuration, without secret sources |
| `POST /v1/targets/{t}/runs` | trigger token or bound OIDC token | `{"commit", "ref", "pipeline_url", "preset"}`, all optional |
| `GET /v1/targets/{t}/runs`, `.../runs/{r}?wait=60` | token | List runs; a run's status, long-polled |
| `POST /v1/targets/{t}/runs/{r}/cancel` | trigger token | Cancel (stops the scan) |
| `GET .../runs/{r}/drift` | token | New, unchanged and fixed findings and the gate (`findings compare`) |
| `GET .../runs/{r}/report.{json,html,sarif}` | token | Reports of what this run found |
| `GET /v1/targets/{t}/latest` | token | The last completed run |
| `GET /v1/healthz` | anyone | Liveness |
| `GET /ui` | anyone (the page asks for a token) | A read-only results page: target, latest run, last 20 runs, drift, report downloads |

Responses use the CLI's envelope: `{"ok": true, "data": ...}` or
`{"ok": false, "error": {"kind", "message"}}`. A run's `state` is `queued`, `running`, `completed`,
`incomplete`, `failed`, `cancelled` or `superseded`; a completed run's `outcome` is `passed` or
`gate_failed`, and `exit_code` is what `remote` exits with.

`/ui` is a small page for people: paste a token and it shows what that token may read. Give
people `read` tokens, not the pipeline's. The page and its script hold no data and are served
with a strict Content-Security-Policy; the token stays in the tab's session storage and is only
sent as an `Authorization` header (downloads too), never in a URL.

[`deploy/compose/`](deploy/compose/) runs it with Caddy for TLS (the reference deployment; the same
on EC2, an Azure VM or your own servers), built from [`docker/server.Dockerfile`](docker/server.Dockerfile).
One replica only.

## `brainproxy-server remote`

What a pipeline runs: trigger a scan, wait, download what it wants, and exit with the run's code.

```sh
BRAINPROXY_TOKEN=bpt_shop-dev_... brainproxy-server remote run --server https://scan.example.test \
    --target shop-dev --commit "$GIT_SHA" --sarif brainproxy.sarif [--report report.html] \
    [--drift drift.json] [--timeout 90m] [--detach]
brainproxy-server remote wait --server ... --target shop-dev --run r-...
```

Exit codes: `0` passed, `5` the gate failed, `2` incomplete, superseded, cancelled or its own
`--timeout` (the run goes on; pick it up with `remote wait`), `3` the server was unreachable (it
retries for two minutes first), `4` unknown target, `6` out of scope, `1` anything else.
[`contrib/remote.sh`](contrib/remote.sh) does the same with curl and jq; `contrib/ci/` has GitHub
Actions, GitLab CI and Azure Pipelines examples.

## Development

`scripts/check.sh` runs formatting, clippy and the tests. The contract tests run the real CLI
against a small local web app (`tests/contract.rs` for `ci`, `tests/serve.rs` for `serve` and
`remote`); they use `BRAINPROXY_BIN` (or `brainproxy` on `PATH`) and are skipped
without one, unless `BRAINPROXY_CONTRACT=1` is set.

## How it relates to brainproxy

The server runs the `brainproxy` command line tool as a separate program and reads its JSON output.
It contains no brainproxy code. brainproxy itself is a separate project under the Apache License 2.0.

## License

This project is source-available under the [PolyForm Shield License 1.0.0](LICENSE.md). You may use,
change and run it, including inside a company, for free. Offering it, or something built from it,
as a product or hosted service that competes with it needs permission: open an issue or contact
the author.
