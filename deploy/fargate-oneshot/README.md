# AWS Fargate one-off task example (stateless `ci`)

An example wrapper that runs `brainproxy-server ci` in stateless mode as a one-off Fargate task per
scan, with its state in S3 and DynamoDB. It is an example, not part of `ci`: `ci` knows nothing
about AWS, and this folder is one way to meet the contract in
[`research/CI-STATELESS.md`](../../research/CI-STATELESS.md) ("Contract for a wrapper"). For the
long-running server instead, see [`deploy/fargate/`](../fargate/README.md).

The files are examples: replace the account id `111122223333`, the region `eu-west-1`, ARNs,
subnets, security groups, buckets, the table and the target id `shop-dev`. Nothing here creates
anything by itself.

- `Dockerfile`: the task's image, the server image plus the AWS CLI, `jq`, the entrypoint and a
  pinned rules bundle.
- `system-scope.json`: the system scope baked into the image (`BRAINPROXY_SYSTEM_SCOPE`): the
  network every scan of this image may reach. Edit it before building.
- `entrypoint.sh`: syncs state, runs `ci`, uploads, moves the generation pointer (POSIX `sh`, only
  `aws` and `jq`).
- `task-definition.json`: one task definition per target
  (`aws ecs register-task-definition --cli-input-json file://task-definition.json`).
- `task-role-policy.json`: the task role: this target's config (and deleting its
  `run-options.json`), state and runs, its items in the table, its own state key.
- `execution-role-policy.json`: the execution role: this target's secrets, injected as environment
  variables. Attach `AmazonECSTaskExecutionRolePolicy` too (ECR pull, CloudWatch Logs).
- `events-rule.json`: one EventBridge rule per target and its ECS target
  (`aws events put-rule --cli-input-json "$(jq .rule events-rule.json)"`, then
  `aws events put-targets --cli-input-json "$(jq .targets events-rule.json)"`).
- `events-role-policy.json`: the role EventBridge uses to start that one task definition.
- `dynamodb-table.json`: the table (`jq .table`, for `aws dynamodb create-table`), its TTL
  (`jq .timeToLive`, for `aws dynamodb update-time-to-live`), point-in-time recovery
  (`jq .pointInTimeRecovery`, for `aws dynamodb update-continuous-backups`) and example items.

## Architecture

```
pipeline ── PutEvents (source ci.pipeline.shop-dev) ──► EventBridge rule brainproxy-ci-shop-dev
                                                         │ fixed input: TARGET_ID=shop-dev and
                                                         │ <aws.events.event.id>, nothing else
                                                         ▼
                                                   ECS RunTask (Fargate)
                                                         │
     entrypoint.sh ──────────────────────────────────────┘
       1. event id seen before?        DynamoDB  event#shop-dev#<id>   (conditional put, TTL 7 days)
       2. target.json, targets.json,   S3        config bucket (read only, but for deleting
          suppressions.json, template,           run-options.json after a baseline)
          run-options.json
       3. take the lease               DynamoDB  lease#shop-dev        (conditional put, expires)
       4. read the pointer, sync its   DynamoDB  pointer#shop-dev  →  S3 state/shop-dev/<gen>-<run>/
          state folder down (empty on a first run)
       5. brainproxy-server ci --target … --targets … --state … --out … --expect-generation <gen>
            [--suppressions …] [--template …] [--state-key-env BRAINPROXY_STATE_KEY]
            [--baseline] [--notify]                  (the last two from run-options.json)
       6. upload the run folder        S3        runs/shop-dev/<run folder>/   (run.json's `folder`)
          upload the next state        S3        state/shop-dev/<gen+1>-<run folder>/
          move the pointer             DynamoDB  pointer#shop-dev (generation = the one read)
          after a passed baseline      S3        delete run-options.json
       7. release the lease, exit with ci's exit code
```

Storage layout, with the defaults of the example:

| Where | What | Who writes it |
|---|---|---|
| `s3://my-brainproxy-ci-config/brainproxy-ci/config/targets.json` | the registry (`--targets`), at most 10 ids | admins |
| `…/config/targets/<id>/target.json` | the target (`--target`), `serve`'s target JSON | admins |
| `…/config/targets/<id>/suppressions.json` | optional, `--suppressions` | admins |
| `…/config/targets/<id>/template.bpdb` | optional, `--template` (a `"project": "upload"` target) | admins |
| `…/config/targets/<id>/run-options.json` | optional, `{"baseline": true, "notify": true}`: the admin-only switches | admins; the task deletes it after a baseline that passed |
| `s3://my-brainproxy-ci-state/brainproxy-ci/state/<id>/<gen>-<run>/` | `state.json`, `known.json`, `state.sig` | the target's task |
| `s3://my-brainproxy-ci-state/brainproxy-ci/runs/<id>/<run>/` | the run folder: `run.json`, `compare.json`, reports, `state/` | the target's task |
| DynamoDB `brainproxy-ci` | `pointer#<id>`, `lease#<id>`, `event#<id>#<event id>` | the target's task |

The task only reads the config bucket (it may delete its own `run-options.json`, nothing else).
Keep it a separate bucket (or at least a prefix with its own bucket policy) that the task roles
can't write: whoever can write `target.json` decides what is scanned.

The state folder is named by generation **and** run folder, not by generation alone: two runs that
read the same generation (which the lease prevents, but a lease can expire) would otherwise upload
to the same folder, and the loser of the compare-and-swap would overwrite the state the winner's
pointer names.

## The wrapper contract, point by point

| Contract | How this example meets it |
|---|---|
| **1. One run per target at a time, in order; compare-and-swap on `generation`.** | The entrypoint takes `lease#<id>` with a conditional put (`attribute_not_exists(pk) OR expires_at < :now`) before it reads the pointer, and releases it on exit (`owner = :me`). The lease lasts the target's `max_minutes` plus `LEASE_MARGIN_SECONDS` (30 min), so a task that dies frees it on its own. The check uses `expires_at` itself, not the TTL deletion, which can lag by hours. The pointer moves only with `generation = <the one read>` (or `attribute_not_exists(pk)` on a first run), so even with an expired lease two runs from one generation can't both write back. The pointer's generation also goes to `ci` as `--expect-generation` (0 on a first run): `ci` refuses a state of any other generation, and an empty state unless it is 0, so an older signed state copied back into the current folder (a replay) is refused, not used. A trigger that finds the lease taken exits 75 without running; it is not queued (see Notes). |
| **2. The target file comes from the wrapper's store; bind each pipeline to its target; drop duplicate deliveries.** | `target.json`, `targets.json`, the suppressions and the template come from the config bucket under `targets/<TARGET_ID>/`, never from the event. The event supplies nothing: the rule's input template holds `TARGET_ID` as a literal and the AWS-generated `<aws.events.event.id>`, and no field of the event's own (see "Commit and ref"). `--baseline` and `--notify` are admin-only switches, so they come from `run-options.json` in the config bucket, not from the task's environment, which container overrides could set. One rule per target, so a pipeline can only start the target of the rule its events match. The task role is scoped to that target's paths and table items, so a wrong `TARGET_ID` would fail on IAM anyway. The event id is recorded as `event#<id>#<event id>` with a conditional put (7-day TTL) before anything else; a redelivery exits 0. If the run never started (lease taken, config missing), the marker is removed so that a retry can run. |
| **3. Write order: run folder, then state, then pointer.** | Exactly that order, each step only if the one before succeeded. A task that dies half-way leaves orphan objects under `runs/` or `state/`, never a pointer to missing ones. The entrypoint also refuses a pointer whose folder has no `state.json`, rather than letting `ci` take it for a first run. |
| **4. System scope and egress fixed in the image or task definition.** | The image bakes `system-scope.json` in at `/etc/brainproxy-ci/system-scope.json` and sets `BRAINPROXY_SYSTEM_SCOPE` to it, and the task definition sets the same path; the entrypoint refuses to start without it. It is never in the config bucket: without it, `ci` would write the target's own scope (and add a reason to `run.json`), and whoever can write `target.json` controls that. Egress is the security group (below). The task definition has no field the event or the config bucket can change besides `TARGET_ID`. |
| **5. Secrets as environment variables or `/run/secrets/<target>/<VAR>`.** | Fargate can't mount secrets as files, so the target's secrets come from Secrets Manager as environment variables (`secrets` in the task definition), named by the target's `secret_env`: `"secret_env": {"APP_PASSWORD": "SHOP_DEV_APP_PASSWORD"}` reads `SHOP_DEV_APP_PASSWORD`. The execution role reads them, and only this target's (`brainproxy-ci/shop-dev/*`), which is one reason for a task definition per target. |
| **6. Stop timeout 120.** | `stopTimeout` is 120. On SIGTERM the entrypoint forwards it to `ci`, waits for `ci` to end the run as incomplete, then still uploads the run folder and the state (the old known set carried forward) and moves the pointer. A SIGTERM before the scan starts ends the task without running. |

## Rules bundle

`ci` updates nothing during a run. `BRAINPROXY_HOME` is a pinned bundle (ZAP patterns and
Retire.js data under `rules/`, Nuclei templates and the signed brainproxy checks feed), and
`run.json` records its versions (`data_versions`). Two ways to provide it, neither updated per run:

- **Baked into the image** (the `Dockerfile` here): `scan data update --ref <commit>` and
  `checks update --ref <commit>` at build time, with full commit ids so GitHub's API isn't needed.
  Rebuild on a schedule (a weekly pipeline, say) and register a new task definition revision.
- **Synced from a read-only S3 prefix**: a scheduled job outside the scan task builds the bundle
  and writes it to, say, `s3://my-brainproxy-ci-config/brainproxy-ci/bundle/`; the entrypoint syncs
  it to `/work` when `BUNDLE_BUCKET` (and `BUNDLE_PREFIX`) are set and points `BRAINPROXY_HOME` at
  it. Add `s3:GetObject` on that prefix and `s3:ListBucket` with an `s3:prefix` condition to the
  task role. The task never writes there.

Either way GitHub stays out of the scan task's egress and out of the system scope.

## State key (`--state-key-env`)

Recommended here: anyone who can write `state/` (an admin, another role, a compromised pipeline)
could otherwise edit `known.json`, for example to make a real finding "unchanged" for a `new_only`
gate, or drop it from the known set. One key per target, at least 32 characters, so that one
target's task can't sign another target's state:

```sh
aws secretsmanager create-secret --name brainproxy/state-key/shop-dev --secret-string "$(openssl rand -hex 32)"
```

`STATE_KEY_SECRET_ID` in the target's task definition names it; the entrypoint reads it with the
task role (not the execution role) just before the run, exports it as `BRAINPROXY_STATE_KEY` for
`ci` alone and passes `--state-key-env BRAINPROXY_STATE_KEY`. Only that target's task role gets
`secretsmanager:GetSecretValue` on `brainproxy/state-key/shop-dev` (`task-role-policy.json`); add a
resource policy on the secret that denies every other principal, and `kms:Decrypt` if it uses a
customer managed key. Once a target has signed state, every run of it needs the key: `ci` refuses a
`state.sig` without it and a non-empty state without a `state.sig`.

The key's variable must start with `BRAINPROXY_`, as `BRAINPROXY_STATE_KEY` does: `ci` refuses a
target whose `secret_env` or hook secrets name the key's variable, so a target file can't have the
key sent to a webhook or handed to the CLI as a "password".

The signature proves who wrote a state, not that it is the newest one: an older signed state
copied back over the current folder would still verify. `--expect-generation` (the pointer's
generation) closes that.

## False positives and the known set

In stateless mode `known.json` carries no false-positive marks. The suppressions file
(`targets/<id>/suppressions.json`, `findings mark --from` list format) is the only source of false
positives: what it lists is marked before the compare and skipped by the gate, and removing an
entry reopens the finding on the next run. `--baseline` ignores the old known set: the run's
findings become the known set, so use it after an admin change to the target's URL, preset, auth or
gate, and not to hide findings (that is what the suppressions file is for, with a reviewable
history if the bucket is versioned).

## Network

- **Security group** of the task: no inbound rules. Out, the target's addresses and ports only,
  and 443 to S3 and DynamoDB through gateway endpoints (their prefix lists), and to interface
  endpoints for ECR, Secrets Manager and CloudWatch Logs. With `"notify": true`, the webhook and
  DefectDojo hosts too. Nothing else: no GitHub, no general internet.
- Private subnets, no public IP.

## Triggers

`events-rule.json` matches `source: ci.pipeline.shop-dev` and `detail-type: brainproxy scan
requested`; a pipeline sends

```sh
aws events put-events --entries '[{"Source":"ci.pipeline.shop-dev","DetailType":"brainproxy scan requested","Detail":"{}"}]'
```

The rule's input template names the target and passes only `<aws.events.event.id>`, which AWS
generates. Restrict which pipeline can send which source with an IAM condition on its role:

```json
{
  "Effect": "Allow",
  "Action": "events:PutEvents",
  "Resource": "arn:aws:events:eu-west-1:111122223333:event-bus/default",
  "Condition": { "StringEquals": { "events:source": "ci.pipeline.shop-dev" } }
}
```

That is the alternative the contract names: with one shared rule for all targets instead, the
`events:source` condition would be the only binding, and the target would have to be derived from
the source in the input template. One rule per target keeps the binding in one place you can read.

For scheduled scans, an EventBridge Scheduler schedule with the same ECS target and a fixed input
works the same way (no event id: pass a fixed one per schedule slot or none).

**Baseline and notifications** are admin-only, so neither the trigger nor container overrides can
turn them on. An admin uploads `targets/<id>/run-options.json`, e.g. `{"baseline": true}`, and the
next run of the target uses it. The entrypoint accepts only the boolean keys `baseline` and
`notify`, and deletes the whole file after a baseline run that passed and whose state was adopted;
re-upload `{"notify": true}` afterwards if notifications should stay on. A baseline that fails or
loses the race leaves the file, so the next run is a baseline again.

### Commit and ref

`ci` can record `--commit` and `--ref` in `run.json`, and the entrypoint passes them when `COMMIT`
and `REF` are set (validated: hex, and `[A-Za-z0-9._/-]`). This example's rule doesn't set them.
EventBridge pastes an input template's `<placeholder>` values into the JSON text without reliably
escaping quotes, so a crafted `detail.commit` such as `x"},{"name":"BASELINE","value":"1` could add
its own entries to the container overrides: any environment variable, including `TARGET_ID` or
`BRAINPROXY_SYSTEM_SCOPE`. Only AWS-generated values (`<aws.events.event.id>`) are safe there.
Record commit and ref only from a wrapper that can pass them safely, for example a queue
consumer that reads the message with a JSON parser, validates the fields and calls `RunTask` with
overrides it builds itself (an SQS FIFO queue in front, as under Notes).

## Exit codes

The task exits with `ci`'s code (0 passed, 5 gate failed, 2 incomplete, 4 not found, 6 out of
scope, 1 error), or the wrapper's own: 64 bad input or configuration (including a missing
`BRAINPROXY_SYSTEM_SCOPE` or a bad `run-options.json`), 70 an AWS call failed or the pointer moved
under the run, 75 the target was busy. A duplicate event exits 0. ECS reports the code in the
task's stopped event, which an EventBridge rule can route to an alarm.

## Notes

- **No queue.** A trigger that arrives while the target runs is dropped (exit 75), not queued.
  For "every commit gets scanned, in order", put an SQS FIFO queue (message group = target) between
  the pipelines and a small consumer that starts one task at a time; the lease and the
  compare-and-swap stay as they are.
- **Lost race.** Exit 70 with "generation moved" means another run wrote back first; this run's
  folder and state are uploaded but not adopted. Its findings show again as new on the next run.
- **Size.** 1 vCPU and 4 GiB run one standard scan. The 40 GiB of ephemeral storage hold the temp
  project (it can reach ~10 GB), the state and the run folder under `/work`; raise it (up to 200)
  for large projects or templates. `/work` and `/tmp` are volumes on the task's ephemeral storage
  because the root filesystem is read-only; Fargate has no `tmpfs`.
- **No ECS Exec** in this task (`enableExecuteCommand` false): nothing in it needs a shell, and it
  allows the read-only root filesystem.
- **Retention.** Add an S3 lifecycle rule on `runs/` and on `state/` (old generations; the pointer
  names the current one) and turn on versioning for the state bucket. `--keep-project` is off: a
  finished project holds session cookies and tokens.
- **CLI version.** Stateless `ci` needs brainproxy 0.6.0 or later in the image (it checks that
  `findings mark --from` exists): build the server image with `--build-arg BRAINPROXY_VERSION` and
  both checksums for that release.
