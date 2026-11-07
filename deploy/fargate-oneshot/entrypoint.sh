#!/bin/sh
# Example wrapper for `brainproxy-server ci` in stateless mode, run as a one-off Fargate task.
# It is an example, not part of `ci`: see README.md in this folder.
#
# One run of one target:
#   1. drop a duplicate delivery (EVENT_ID, conditional put with a TTL)
#   2. fetch target.json, targets.json and the optional suppressions/template/run-options from
#      the config bucket (never from the event)
#   3. take the target's lease (conditional put; expires on its own if this task dies)
#   4. read the generation pointer and sync that state folder down (empty on a first run)
#   5. run `brainproxy-server ci` and keep its exit code (SIGTERM is forwarded, uploads still run)
#   6. upload the run folder, then the next state, then move the pointer (compare-and-swap)
#   7. release the lease and exit with ci's exit code
#
# Needs only `aws` (CLI v2) and `jq` besides the image. Environment:
#   TARGET_ID           required, ^[a-z0-9-]{1,32}$ (from the EventBridge rule's fixed input)
#   CONFIG_BUCKET       required; CONFIG_PREFIX (default brainproxy-ci/config)
#   STATE_BUCKET        required; STATE_PREFIX  (default brainproxy-ci)
#   TABLE               required, the DynamoDB table (dynamodb-table.json)
#   EVENT_ID            optional, the EventBridge event id (AWS-generated), for dedupe
#   COMMIT, REF         optional, recorded in run.json only; only for wrappers that can pass them
#                       safely (README.md, "Commit and ref"); the example's rule doesn't
#   STATE_KEY_SECRET_ID optional, Secrets Manager id of this target's HMAC key for state.sig
#                       (brainproxy/state-key/<target>)
#
# Admin-only switches are not taken from the environment: --baseline and --notify come from an
# optional targets/<id>/run-options.json in the config bucket, {"baseline": true, "notify": true}.
# The entrypoint deletes that file after a baseline run that passed and was adopted.
#
# Fixed by the image or the task definition, never by the trigger:
#   BRAINPROXY_SYSTEM_SCOPE  the system scope file the CLI gets (required here)
#   BUNDLE_BUCKET, BUNDLE_PREFIX  optional, a read-only rules bundle to use as BRAINPROXY_HOME
#                       instead of the one baked into the image
#   LEASE_MARGIN_SECONDS  optional, added to the target's max_minutes (default 1800)
#   WORK_DIR            optional, local scratch (default /work, the task's ephemeral storage)
#
# Exit codes: ci's own (0 passed, 1 error, 2 incomplete, 4 not found, 5 gate failed,
# 6 out of scope), or the wrapper's: 64 bad input, 70 wrapper/AWS error, 75 target busy.
# A duplicate event exits 0 without running.

set -eu
umask 077

EX_USAGE=64
EX_WRAPPER=70
EX_BUSY=75

log() { printf 'ci-entrypoint: %s\n' "$*" >&2; }
die() {
    die_code=$1
    shift
    log "error: $*"
    exit "$die_code"
}

# matches ERE VALUE: VALUE is a single line that matches ERE as a whole.
matches() {
    case $2 in
        *'
'*) return 1 ;;
    esac
    printf '%s' "$2" | grep -Eqx -- "$1"
}

now() { date +%s; }

# --- inputs -----------------------------------------------------------------------------------

TARGET_ID=${TARGET_ID:-}
matches '[a-z0-9-]{1,32}' "$TARGET_ID" || die "$EX_USAGE" "TARGET_ID must match ^[a-z0-9-]{1,32}\$"

# The system scope is part of the image or the task definition, not of anything the trigger or
# the config bucket can change.
SYSTEM_SCOPE=${BRAINPROXY_SYSTEM_SCOPE:-}
[ -n "$SYSTEM_SCOPE" ] || die "$EX_USAGE" "BRAINPROXY_SYSTEM_SCOPE isn't set (image or task definition)"
[ -f "$SYSTEM_SCOPE" ] || die "$EX_USAGE" "BRAINPROXY_SYSTEM_SCOPE names no file: $SYSTEM_SCOPE"

CONFIG_BUCKET=${CONFIG_BUCKET:-}
STATE_BUCKET=${STATE_BUCKET:-}
TABLE=${TABLE:-}
CONFIG_PREFIX=${CONFIG_PREFIX:-brainproxy-ci/config}
STATE_PREFIX=${STATE_PREFIX:-brainproxy-ci}
CONFIG_PREFIX=${CONFIG_PREFIX%/}
STATE_PREFIX=${STATE_PREFIX%/}
for b in "$CONFIG_BUCKET" "$STATE_BUCKET"; do
    matches '[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]' "$b" || die "$EX_USAGE" "CONFIG_BUCKET/STATE_BUCKET missing or not a bucket name"
done
for p in "$CONFIG_PREFIX" "$STATE_PREFIX"; do
    matches '[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*' "$p" || die "$EX_USAGE" "bad prefix '$p'"
done
matches '[A-Za-z0-9._-]{3,255}' "$TABLE" || die "$EX_USAGE" "TABLE missing or not a table name"

EVENT_ID=${EVENT_ID:-}
COMMIT=${COMMIT:-}
REF=${REF:-}
[ -z "$EVENT_ID" ] || matches '[A-Za-z0-9-]{1,128}' "$EVENT_ID" || die "$EX_USAGE" "bad EVENT_ID"
[ -z "$COMMIT" ] || matches '[0-9A-Fa-f]{7,64}' "$COMMIT" || die "$EX_USAGE" "bad COMMIT"
[ -z "$REF" ] || matches '[A-Za-z0-9._/-]{1,200}' "$REF" || die "$EX_USAGE" "bad REF"
LEASE_MARGIN_SECONDS=${LEASE_MARGIN_SECONDS:-1800}
matches '[0-9]{1,6}' "$LEASE_MARGIN_SECONDS" || die "$EX_USAGE" "bad LEASE_MARGIN_SECONDS"

WORK=${WORK_DIR:-/work}
RUN_ROOT="$WORK/oneshot"
CFG_DIR="$RUN_ROOT/config"
STATE_DIR="$RUN_ROOT/state"
OUT_DIR="$RUN_ROOT/out"
ERR="$RUN_ROOT/aws.err"
rm -rf "$RUN_ROOT"
mkdir -p "$CFG_DIR" "$STATE_DIR" "$OUT_DIR"

OWNER=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || od -An -N16 -tx1 /dev/urandom | tr -d ' \n')
[ -n "$OWNER" ] || die "$EX_WRAPPER" "cannot make a lease owner id"
EVENT_KEY=
EVENT_CLAIMED=0
LEASE_KEY="lease#$TARGET_ID"
LEASE_HELD=0
POINTER_KEY="pointer#$TARGET_ID"
CI_STARTED=0
CI_PID=
TERMINATED=0

key_json() { jq -cn --arg pk "$1" '{pk: {S: $pk}}'; }

# ddb OPERATION ARGS...: returns 0, or 3 when the condition failed; any other error exits.
# The output of a successful call is left in DDB_OUT.
DDB_OUT=
ddb() {
    if DDB_OUT=$(aws dynamodb "$@" --table-name "$TABLE" --output json 2>"$ERR"); then
        return 0
    fi
    if grep -q 'ConditionalCheckFailedException' "$ERR"; then
        return 3
    fi
    cat "$ERR" >&2
    die "$EX_WRAPPER" "dynamodb $1 failed"
}

# --- cleanup and signals ----------------------------------------------------------------------

cleanup() {
    status=$?
    trap - EXIT
    if [ "$LEASE_HELD" = 1 ]; then
        aws dynamodb delete-item --table-name "$TABLE" --key "$(key_json "$LEASE_KEY")" \
            --condition-expression '#o = :me' \
            --expression-attribute-names '{"#o":"owner"}' \
            --expression-attribute-values "$(jq -cn --arg me "$OWNER" '{":me": {S: $me}}')" \
            >/dev/null 2>"$ERR" || log "warning: lease not released; it expires on its own"
    fi
    # The scan never started: forget the event so that a redelivery can run.
    if [ "$EVENT_CLAIMED" = 1 ] && [ "$CI_STARTED" = 0 ]; then
        aws dynamodb delete-item --table-name "$TABLE" --key "$(key_json "$EVENT_KEY")" \
            >/dev/null 2>"$ERR" || log "warning: event marker not removed"
    fi
    exit "$status"
}
trap cleanup EXIT

on_term() {
    TERMINATED=1
    log "SIGTERM: stopping the scan, the run folder is still uploaded"
    if [ -n "$CI_PID" ]; then
        kill -TERM "$CI_PID" 2>/dev/null || true
    fi
}
trap on_term TERM INT

# --- 1. duplicate deliveries ------------------------------------------------------------------

if [ -n "$EVENT_ID" ]; then
    EVENT_KEY="event#$TARGET_ID#$EVENT_ID"
    item=$(jq -cn --arg pk "$EVENT_KEY" --arg o "$OWNER" --arg exp "$(($(now) + 7 * 86400))" \
        '{pk: {S: $pk}, owner: {S: $o}, expires_at: {N: $exp}}')
    rc=0
    ddb put-item --item "$item" --condition-expression 'attribute_not_exists(pk)' || rc=$?
    if [ "$rc" -eq 3 ]; then
        log "event $EVENT_ID was already delivered; nothing to do"
        exit 0
    fi
    EVENT_CLAIMED=1
fi

# --- 2. configuration, from the wrapper's own store -------------------------------------------

cfg_key="$CONFIG_PREFIX/targets/$TARGET_ID"
aws s3api list-objects-v2 --bucket "$CONFIG_BUCKET" --prefix "$cfg_key/" \
    --query 'Contents[].Key' --output json >"$RUN_ROOT/config-keys.json" 2>"$ERR" ||
    { cat "$ERR" >&2; die "$EX_WRAPPER" "cannot list s3://$CONFIG_BUCKET/$cfg_key/"; }

has_key() { jq -e --arg k "$1" '(. // []) | index($k) != null' "$RUN_ROOT/config-keys.json" >/dev/null; }

s3get() {
    aws s3 cp --only-show-errors "s3://$CONFIG_BUCKET/$1" "$2" 2>"$ERR" ||
        { cat "$ERR" >&2; die "$EX_WRAPPER" "cannot fetch s3://$CONFIG_BUCKET/$1"; }
}

s3get "$CONFIG_PREFIX/targets.json" "$CFG_DIR/targets.json"
has_key "$cfg_key/target.json" || die "$EX_USAGE" "no s3://$CONFIG_BUCKET/$cfg_key/target.json"
s3get "$cfg_key/target.json" "$CFG_DIR/target.json"
jq -e --arg id "$TARGET_ID" '.id == $id' "$CFG_DIR/target.json" >/dev/null ||
    die "$EX_USAGE" "target.json's id is not $TARGET_ID"

SUPPRESSIONS=
if has_key "$cfg_key/suppressions.json"; then
    SUPPRESSIONS="$CFG_DIR/suppressions.json"
    s3get "$cfg_key/suppressions.json" "$SUPPRESSIONS"
fi
TEMPLATE=
if has_key "$cfg_key/template.bpdb"; then
    TEMPLATE="$CFG_DIR/template.bpdb"
    s3get "$cfg_key/template.bpdb" "$TEMPLATE"
fi

# Admin-only switches: from the config bucket, never from the task's environment or the event.
BASELINE=0
NOTIFY=0
RUN_OPTIONS_KEY="$cfg_key/run-options.json"
if has_key "$RUN_OPTIONS_KEY"; then
    s3get "$RUN_OPTIONS_KEY" "$CFG_DIR/run-options.json"
    jq -e 'type == "object" and (keys - ["baseline", "notify"] == []) and all(.[]; type == "boolean")' \
        "$CFG_DIR/run-options.json" >/dev/null 2>&1 ||
        die "$EX_USAGE" "run-options.json: only boolean \"baseline\" and \"notify\" are allowed"
    BASELINE=$(jq -r 'if .baseline == true then 1 else 0 end' "$CFG_DIR/run-options.json")
    NOTIFY=$(jq -r 'if .notify == true then 1 else 0 end' "$CFG_DIR/run-options.json")
fi

max_minutes=$(jq -r '.max_minutes // 60' "$CFG_DIR/target.json")
matches '[0-9]{1,5}' "$max_minutes" || die "$EX_USAGE" "bad max_minutes in target.json"

# --- 3. one run per target at a time ----------------------------------------------------------

t=$(now)
lease_exp=$((t + max_minutes * 60 + LEASE_MARGIN_SECONDS))
item=$(jq -cn --arg pk "$LEASE_KEY" --arg o "$OWNER" --arg exp "$lease_exp" --arg ev "$EVENT_ID" \
    '{pk: {S: $pk}, owner: {S: $o}, expires_at: {N: $exp}, event: {S: $ev}}')
rc=0
ddb put-item --item "$item" \
    --condition-expression 'attribute_not_exists(pk) OR #e < :now' \
    --expression-attribute-names '{"#e":"expires_at"}' \
    --expression-attribute-values "$(jq -cn --arg now "$t" '{":now": {N: $now}}')" || rc=$?
if [ "$rc" -eq 3 ]; then
    die "$EX_BUSY" "another run of $TARGET_ID holds the lease; not started"
fi
LEASE_HELD=1

# --- 4. the state the previous run left -------------------------------------------------------

ddb get-item --consistent-read --key "$(key_json "$POINTER_KEY")"
READ_GEN=$(printf '%s' "$DDB_OUT" | jq -r '.Item.generation.N // empty')
READ_PREFIX=$(printf '%s' "$DDB_OUT" | jq -r '.Item.state_prefix.S // empty')

if [ -z "$READ_GEN" ]; then
    FIRST_RUN=1
    READ_GEN=0
    log "no pointer for $TARGET_ID: first run, empty state"
else
    FIRST_RUN=0
    matches '[0-9]{1,12}' "$READ_GEN" || die "$EX_WRAPPER" "pointer has a bad generation"
    case $READ_PREFIX in
        "$STATE_PREFIX/state/$TARGET_ID/"*) ;;
        *) die "$EX_WRAPPER" "pointer's state_prefix is outside $STATE_PREFIX/state/$TARGET_ID/" ;;
    esac
    matches '[A-Za-z0-9._/-]+' "$READ_PREFIX" || die "$EX_WRAPPER" "pointer has a bad state_prefix"
    aws s3 sync --only-show-errors "s3://$STATE_BUCKET/${READ_PREFIX%/}/" "$STATE_DIR/" 2>"$ERR" ||
        { cat "$ERR" >&2; die "$EX_WRAPPER" "cannot sync s3://$STATE_BUCKET/$READ_PREFIX"; }
    # A pointer to a missing folder must not turn into a silent first run.
    [ -f "$STATE_DIR/state.json" ] || die "$EX_WRAPPER" "pointer names $READ_PREFIX but it holds no state.json"
    jq -e --arg g "$READ_GEN" '(.generation | tostring) == $g' "$STATE_DIR/state.json" >/dev/null ||
        die "$EX_WRAPPER" "state.json's generation differs from the pointer's ($READ_GEN)"
fi

# --- the pinned rules bundle and the state key ------------------------------------------------

if [ -n "${BUNDLE_BUCKET:-}" ]; then
    BUNDLE_PREFIX=${BUNDLE_PREFIX:-brainproxy-ci/bundle}
    BUNDLE_PREFIX=${BUNDLE_PREFIX%/}
    mkdir -p "$RUN_ROOT/bundle"
    aws s3 sync --only-show-errors "s3://$BUNDLE_BUCKET/$BUNDLE_PREFIX/" "$RUN_ROOT/bundle/" 2>"$ERR" ||
        { cat "$ERR" >&2; die "$EX_WRAPPER" "cannot sync the rules bundle"; }
    BRAINPROXY_HOME="$RUN_ROOT/bundle"
    export BRAINPROXY_HOME
fi

if [ -n "${STATE_KEY_SECRET_ID:-}" ]; then
    BRAINPROXY_STATE_KEY=$(aws secretsmanager get-secret-value --secret-id "$STATE_KEY_SECRET_ID" \
        --query SecretString --output text 2>"$ERR") ||
        { cat "$ERR" >&2; die "$EX_WRAPPER" "cannot read the state key"; }
    export BRAINPROXY_STATE_KEY
fi

# --- 5. the run -------------------------------------------------------------------------------

# --expect-generation: ci refuses a state of another generation (a replayed older signed state)
# and an empty state unless it is 0.
set -- ci --target "$CFG_DIR/target.json" --targets "$CFG_DIR/targets.json" \
    --state "$STATE_DIR" --out "$OUT_DIR" --expect-generation "$READ_GEN"
[ -z "$SUPPRESSIONS" ] || set -- "$@" --suppressions "$SUPPRESSIONS"
[ -z "$TEMPLATE" ] || set -- "$@" --template "$TEMPLATE"
[ -z "${STATE_KEY_SECRET_ID:-}" ] || set -- "$@" --state-key-env BRAINPROXY_STATE_KEY
[ -z "$COMMIT" ] || set -- "$@" --commit "$COMMIT"
[ -z "$REF" ] || set -- "$@" --ref "$REF"
[ "$BASELINE" = 0 ] || set -- "$@" --baseline
[ "$NOTIFY" = 0 ] || set -- "$@" --notify

[ "$TERMINATED" = 0 ] || die "$EX_WRAPPER" "stopped before the scan started"

CI_STARTED=1
CI_STDOUT="$RUN_ROOT/ci-stdout.json"
set +e
# ci prints run.json on stdout; its `folder` is the run folder.
brainproxy-server "$@" >"$CI_STDOUT" &
CI_PID=$!
# A SIGTERM that came between the start and the line above.
[ "$TERMINATED" = 0 ] || kill -TERM "$CI_PID" 2>/dev/null
wait "$CI_PID"
CI_RC=$?
# `wait` returns early when a trapped signal arrives: wait again for ci's own exit code.
while [ "$TERMINATED" = 1 ] && kill -0 "$CI_PID" 2>/dev/null; do
    wait "$CI_PID"
    CI_RC=$?
done
set -e
unset BRAINPROXY_STATE_KEY
log "ci exited with $CI_RC"
cat "$CI_STDOUT"

# --- 6. write order: run folder, then state, then pointer -------------------------------------

count=0
for d in "$OUT_DIR"/*/; do
    [ -d "$d" ] || continue
    count=$((count + 1))
done
if [ "$count" -eq 0 ]; then
    log "ci wrote no run folder; nothing to upload"
    [ "$CI_RC" -ne 0 ] || CI_RC=$EX_WRAPPER
    exit "$CI_RC"
fi
[ "$count" -eq 1 ] || die "$EX_WRAPPER" "expected one run folder in $OUT_DIR, found $count"
RUN_DIR=$(jq -r 'if type == "object" and (.folder | type) == "string" then .folder else empty end' \
    "$CI_STDOUT" 2>/dev/null || true)
[ -n "$RUN_DIR" ] || die "$EX_WRAPPER" "ci's run.json on stdout has no folder"
[ -d "$RUN_DIR" ] || die "$EX_WRAPPER" "ci's folder $RUN_DIR isn't a directory"
# The folder must be directly inside OUT_DIR, whatever the path says (.., symlinks).
real_out=$(cd "$OUT_DIR" && pwd -P)
RUN_DIR=$(cd "$RUN_DIR" && pwd -P)
[ "$(dirname "$RUN_DIR")" = "$real_out" ] || die "$EX_WRAPPER" "ci's folder is not inside $OUT_DIR"
FOLDER=$(basename "$RUN_DIR")
matches '[A-Za-z0-9._-]{1,128}' "$FOLDER" || die "$EX_WRAPPER" "unexpected run folder name"

RUNS_URL="s3://$STATE_BUCKET/$STATE_PREFIX/runs/$TARGET_ID/$FOLDER/"
aws s3 cp --recursive --only-show-errors "$RUN_DIR/" "$RUNS_URL" 2>"$ERR" ||
    { cat "$ERR" >&2; die "$EX_WRAPPER" "run folder upload failed"; }
log "run folder: $RUNS_URL"

if [ ! -f "$RUN_DIR/state/state.json" ]; then
    log "ci wrote no next state; pointer stays at generation $READ_GEN"
    exit "$CI_RC"
fi

NEW_GEN=$(jq -r '.generation' "$RUN_DIR/state/state.json")
matches '[0-9]{1,12}' "$NEW_GEN" || die "$EX_WRAPPER" "next state.json has a bad generation"
# The pointer's generation plus one (a first run reads 0 and writes 1).
[ "$NEW_GEN" -eq $((READ_GEN + 1)) ] ||
    die "$EX_WRAPPER" "next state has generation $NEW_GEN, expected $((READ_GEN + 1))"
jq -e --arg id "$TARGET_ID" '.target == $id' "$RUN_DIR/state/state.json" >/dev/null ||
    die "$EX_WRAPPER" "next state.json names another target"

# A folder per run, not per generation: a run that loses the race below never overwrites the
# state the pointer names.
NEW_PREFIX="$STATE_PREFIX/state/$TARGET_ID/$NEW_GEN-$FOLDER"
aws s3 cp --recursive --only-show-errors "$RUN_DIR/state/" "s3://$STATE_BUCKET/$NEW_PREFIX/" 2>"$ERR" ||
    { cat "$ERR" >&2; die "$EX_WRAPPER" "state upload failed; pointer not moved"; }

t=$(now)
if [ "$FIRST_RUN" = 1 ]; then
    item=$(jq -cn --arg pk "$POINTER_KEY" --arg tg "$TARGET_ID" --arg g "$NEW_GEN" \
        --arg p "$NEW_PREFIX" --arg r "$FOLDER" --arg u "$t" \
        '{pk: {S: $pk}, target: {S: $tg}, generation: {N: $g}, state_prefix: {S: $p},
          run: {S: $r}, updated_at: {N: $u}}')
    rc=0
    ddb put-item --item "$item" --condition-expression 'attribute_not_exists(pk)' || rc=$?
else
    rc=0
    ddb update-item --key "$(key_json "$POINTER_KEY")" \
        --update-expression 'SET #g = :new, #p = :prefix, #r = :run, #u = :now' \
        --condition-expression '#g = :read' \
        --expression-attribute-names '{"#g":"generation","#p":"state_prefix","#r":"run","#u":"updated_at"}' \
        --expression-attribute-values "$(jq -cn --arg new "$NEW_GEN" --arg read "$READ_GEN" \
            --arg prefix "$NEW_PREFIX" --arg run "$FOLDER" --arg now "$t" \
            '{":new": {N: $new}, ":read": {N: $read}, ":prefix": {S: $prefix},
              ":run": {S: $run}, ":now": {N: $now}}')" || rc=$?
fi
if [ "$rc" -eq 3 ]; then
    die "$EX_WRAPPER" "generation moved since this run read $READ_GEN; its state ($NEW_PREFIX) was not adopted"
fi
log "pointer: generation $NEW_GEN, $NEW_PREFIX"

# A baseline is one run, not a standing setting: drop the switch once one passed and was adopted.
# If this fails the next run would be a baseline again, so it is an error.
if [ "$BASELINE" = 1 ] && [ "$CI_RC" -eq 0 ]; then
    aws s3 rm --only-show-errors "s3://$CONFIG_BUCKET/$RUN_OPTIONS_KEY" 2>"$ERR" ||
        { cat "$ERR" >&2; die "$EX_WRAPPER" "baseline adopted, but s3://$CONFIG_BUCKET/$RUN_OPTIONS_KEY wasn't deleted: delete it by hand"; }
    log "baseline adopted; deleted $RUN_OPTIONS_KEY"
fi

# --- 7. done (the EXIT trap releases the lease) -----------------------------------------------

exit "$CI_RC"
