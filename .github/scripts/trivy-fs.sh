#!/usr/bin/env bash
# Scan the repo with Trivy. A vulnerability DB download failure
# (for example mirror.gcr.io returning 404) must not fail the job when
# a cached DB is already on disk. A failed download deletes
# metadata.json, so the pre-download copy is what --skip-db-update uses.
# A real HIGH/CRITICAL finding still fails the job.
set -euo pipefail

cache="${TRIVY_CACHE_DIR:-${GITHUB_WORKSPACE:-$PWD}/.cache/trivy}"
good="${RUNNER_TEMP:-/tmp}/trivy-db-good"
log="${RUNNER_TEMP:-/tmp}/trivy-scan.log"
mkdir -p "$cache"

if [[ -f "$cache/db/metadata.json" ]]; then
  rm -rf "$good"
  cp -a "$cache" "$good"
fi

set +e
trivy fs \
  --cache-dir "$cache" \
  --scanners vuln \
  --severity HIGH,CRITICAL \
  --ignore-unfixed \
  --exit-code 1 \
  . >"$log" 2>&1
code=$?
set -e
cat "$log"

if [[ "$code" -eq 0 ]]; then
  if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    echo "updated=true" >>"$GITHUB_OUTPUT"
  fi
  exit 0
fi

if grep -q "failed to download vulnerability DB" "$log" \
  && [[ -f "$good/db/metadata.json" ]]; then
  echo "Trivy DB download failed. Scanning with the cached database."
  echo "Cached metadata:"
  cat "$good/db/metadata.json"
  rm -rf "$cache"
  cp -a "$good" "$cache"
  trivy fs \
    --cache-dir "$cache" \
    --skip-db-update \
    --skip-java-db-update \
    --scanners vuln \
    --severity HIGH,CRITICAL \
    --ignore-unfixed \
    --exit-code 1 \
    .
  exit 0
fi

exit "$code"
