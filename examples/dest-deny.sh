#!/usr/bin/env bash
# Dest-deny .env and a hardlink of it. An ordinary file still runs.
# Unix only. Optional: WORKPEN=/path/to/workpen  [workspace]
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WS="${1:-$(mktemp -d)}"
mkdir -p "$WS"
if [ -n "${WORKPEN:-}" ]; then
  WP=("$WORKPEN")
elif command -v workpen >/dev/null 2>&1; then
  WP=(workpen)
else
  cd "$ROOT"
  WP=(cargo run -q -p workpen-cli --)
fi

printf 'SECRET=1\n' >"$WS/.env"
printf 'hello notes\n' >"$WS/notes.md"
ln "$WS/.env" "$WS/notes.txt"

echo "# .env is dest-deny"
set +e
"${WP[@]}" why --root "$WS" .env
status=$?
set -e
test "$status" -eq 1
echo blocked

echo "# notes.txt is a hardlink of .env"
set +e
"${WP[@]}" why --root "$WS" notes.txt
status=$?
set -e
test "$status" -eq 1
echo blocked

echo "# notes.md is ordinary"
set +e
"${WP[@]}" why --root "$WS" notes.md
why_ok=$?
set -e
test "$why_ok" -eq 0
echo allowed

set +e
out=$("${WP[@]}" run --root "$WS" -- /bin/cat notes.md 2>"$WS/run.err")
run_st=$?
set -e
if [ "$run_st" -eq 0 ]; then
  test "$out" = "hello notes"
  printf '%s\n' "$out"
elif grep -q 'remount unavailable' "$WS/run.err"; then
  echo "run skipped: dest-deny remount unavailable"
else
  cat "$WS/run.err" >&2
  exit 1
fi
