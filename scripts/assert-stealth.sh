#!/usr/bin/env bash
# Fail if stealth-public launch surfaces leak.
set -euo pipefail
ORG_REPO="${1:-workpen/workpen}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

fail() { echo "stealth leak: $*" >&2; exit 1; }

readme="$(tr -d '\r' < "$ROOT/README.md")"
printf '%s\n' "$readme" | grep -qx '# workpen' || fail "README title"
printf '%s\n' "$readme" | grep -qx 'Not ready.' || fail "README must be Not ready."
if printf '%s\n' "$readme" | grep -qiE 'badge|shields.io|containment|dest-deny'; then
  fail "README pitch or badge"
fi

test ! -e "$ROOT/.github/FUNDING.yml" || fail "FUNDING.yml present"

if grep -E 'keywords = \["' "$ROOT"/crates/*/Cargo.toml; then
  fail "crate keywords"
fi
if grep -E 'description = "' "$ROOT"/crates/*/Cargo.toml | grep -v 'Reserved.'; then
  fail "crate description is not Reserved."
fi

if command -v gh >/dev/null 2>&1; then
  desc="$(gh api "repos/${ORG_REPO}" --jq '.description // empty' 2>/dev/null || true)"
  if [ -n "${desc}" ]; then
    fail "GitHub description is set: ${desc}"
  fi
  topics="$(gh api "repos/${ORG_REPO}/topics" -H "Accept: application/vnd.github+json" --jq '.names | length' 2>/dev/null || echo 0)"
  if [ "${topics}" != "0" ]; then
    fail "GitHub topics are set"
  fi
fi

echo "stealth ok: ${ORG_REPO}"
