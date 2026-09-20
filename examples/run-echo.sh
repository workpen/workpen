#!/usr/bin/env bash
# Run a child through the workpen CLI. Unix only.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WS="${1:-$(mktemp -d)}"
cd "$ROOT"
cargo run -q -p workpen-cli -- run --root "$WS" -- /bin/echo ok
