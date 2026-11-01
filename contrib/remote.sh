#!/bin/sh
# What `brainproxy-server remote run` does, with curl and jq: trigger a scan of a target, wait for
# it, print a summary, and exit with the run's exit code.
#
#   BRAINPROXY_TOKEN=... contrib/remote.sh https://scan.corp.test shop-dev "$GIT_SHA" [brainproxy.sarif]
#
# Exit codes: the run's own (0 passed, 5 gate failed, 2 incomplete, superseded or cancelled,
# 6 out of scope...), 2 when this script's own timeout (TIMEOUT_SECS, default 5400) runs out,
# 3 server unreachable, 4 unknown target or run, 1 any other error.
# Unlike `remote run`, it doesn't retry a server that is briefly down.
set -eu

server=${1:?usage: remote.sh SERVER TARGET COMMIT [SARIF_FILE]}
target=${2:?target id missing}
commit=${3:?commit missing}
sarif=${4:-}
: "${BRAINPROXY_TOKEN:?set BRAINPROXY_TOKEN}"
base="${server%/}/v1/targets/$target/runs"
deadline=$(( $(date +%s) + ${TIMEOUT_SECS:-5400} ))
body=$(mktemp)
trap 'rm -f "$body"' EXIT

# api URL [CURL ARGS]: the body goes to $body, the HTTP status (000: no answer) to stdout. The
# token goes to curl on stdin, so it never shows up in the process list.
api() {
  url=$1; shift
  printf 'Authorization: Bearer %s\n' "$BRAINPROXY_TOKEN" |
    curl -sS --max-time 120 -o "$body" -w '%{http_code}' -H @- "$@" "$url" || true
}

fail() {
  case $1 in
    000) echo "remote.sh: $server is unreachable" >&2; exit 3 ;;
    404) echo "remote.sh: $(jq -r '.error.message // "not found"' "$body" 2>/dev/null)" >&2; exit 4 ;;
    *) echo "remote.sh: HTTP $1: $(jq -r '.error.message // empty' "$body" 2>/dev/null)" >&2; exit 1 ;;
  esac
}

payload=$(jq -nc --arg c "$commit" '{commit: $c}')
code=$(api "$base" -H 'Content-Type: application/json' --data "$payload")
case $code in 200|202) ;; *) fail "$code" ;; esac
run=$(jq -r .data.run "$body")
echo "remote.sh: run $run of $target" >&2

while :; do
  [ "$(date +%s)" -lt "$deadline" ] || { echo "remote.sh: timed out; run $run goes on" >&2; exit 2; }
  code=$(api "$base/$run?wait=60")
  [ "$code" = 200 ] || fail "$code"
  state=$(jq -r .data.state "$body")
  case $state in queued|running) ;; *) break ;; esac
done

jq -r '.data | "\(.state) \(.outcome // "") (run \(.run), job \(.job // "-"))"
  + (if .drift then ": \(.drift.new) new, \(.drift.unchanged) unchanged, \(.drift.fixed) fixed" else "" end)
  + ([.reasons[]? | "\n  - \(.)"] | join(""))' "$body" >&2
exit_code=$(jq -r '.data.exit_code // 1' "$body")

if [ -n "$sarif" ]; then
  if [ "$(api "$base/$run/report.sarif")" = 200 ]; then
    cp "$body" "$sarif" && echo "remote.sh: wrote $sarif" >&2
  else
    echo "remote.sh: warning: no report.sarif" >&2
  fi
fi
exit "$exit_code"
