#!/usr/bin/env bash
# The checks CI runs. Use before every commit: scripts/check.sh && git commit ...
# The contract tests need the brainproxy CLI: BRAINPROXY_BIN=/path/to/brainproxy, or brainproxy on PATH.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo fmt --check
cargo clippy --all-targets -q -- -D warnings
cargo test -q
echo "checks passed"
