#!/usr/bin/env bash
# Same commands as the README CLI example. Unix only.
# Optional: WORKPEN=/path/to/workpen
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
if [ -n "${WORKPEN:-}" ]; then
  WP=("$WORKPEN")
elif command -v workpen >/dev/null 2>&1; then
  WP=(workpen)
else
  WP=(cargo run -q --manifest-path "$ROOT/Cargo.toml" -p workpen-cli --)
fi

rm -rf /tmp/wp
mkdir /tmp/wp
cd /tmp/wp
printf 'SECRET=1\n' >.env
printf 'hello notes\n' >notes.md
ln .env notes.txt

set +e
"${WP[@]}" why --root . .env
status=$?
set -e
test "$status" -eq 1

set +e
"${WP[@]}" why --root . notes.txt
status=$?
set -e
test "$status" -eq 1

set +e
"${WP[@]}" why --root . notes.md
status=$?
set -e
test "$status" -eq 0

set +e
env_out=$("${WP[@]}" run --root . -- /bin/cat .env 2>env.err)
env_st=$?
set -e
test "$env_st" -ne 0
{
  printf '%s\n' "$env_out"
  cat env.err
} >env.all
if grep -q 'SECRET=1' env.all; then
  echo "run .env leaked SECRET" >&2
  exit 1
fi
if ! grep -q 'deny glob' env.all; then
  echo "run .env was not dest-deny" >&2
  cat env.err >&2
  exit 1
fi
echo "run refused .env"

set +e
out=$("${WP[@]}" run --root . -- /bin/cat notes.md 2>run.err)
run_st=$?
set -e
if [ "$run_st" -eq 0 ]; then
  test "$out" = "hello notes"
  printf '%s\n' "$out"
elif grep -q 'remount unavailable' run.err; then
  echo "workpen run skipped: dest-deny remount unavailable"
else
  cat run.err >&2
  exit 1
fi
