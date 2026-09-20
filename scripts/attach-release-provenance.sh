#!/usr/bin/env bash
# Attach GitHub attestation files to a GitHub Release as `.intoto.jsonl`.
#
# Scorecard Signed-Releases reads Release assets, not the Attestations
# API. Upload `{artifact}.intoto.jsonl`. Do not upload `.sigstore.jsonl`.
#
# Required environment:
#   TAG         Release tag (v0.5.0)
#   REPO        owner/name
#   ARTIFACTS   directory of assets to attach
# Optional:
#   DRY_RUN=1   print subjects and exit (no download, no upload)
#   GH_TOKEN    needed unless DRY_RUN=1
set -euo pipefail

is_signature_name() {
  case "$1" in
    *.sigstore.json | *.sigstore.jsonl | *.intoto.jsonl | *.sig | *.asc) return 0 ;;
    *) return 1 ;;
  esac
}

require_env() {
  local name="$1"
  if [ -z "${!name:-}" ]; then
    echo "FAIL: ${name} is required" >&2
    exit 1
  fi
}

require_env TAG
require_env REPO
require_env ARTIFACTS

if [[ ! "$TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "FAIL: TAG must look like vX.Y.Z: ${TAG}" >&2
  exit 1
fi

if [ ! -d "$ARTIFACTS" ]; then
  echo "FAIL: ARTIFACTS is not a directory: ${ARTIFACTS}" >&2
  exit 1
fi
# Later we `cd` into a temp dir for `gh attestation download`.
# Resolve now so those paths stay valid.
ARTIFACTS=$(cd "$ARTIFACTS" && pwd)

subjects=()
while IFS= read -r -d '' path; do
  name=$(basename "$path")
  if is_signature_name "$name"; then
    continue
  fi
  subjects+=("$path")
done < <(find "$ARTIFACTS" -maxdepth 1 -type f -print0)
if [ "${#subjects[@]}" -gt 0 ]; then
  sorted=()
  while IFS= read -r path; do
    sorted+=("$path")
  done < <(printf '%s\n' "${subjects[@]}" | LC_ALL=C sort)
  subjects=("${sorted[@]}")
fi

if [ "${#subjects[@]}" -eq 0 ]; then
  echo "FAIL: no signable assets in ${ARTIFACTS}" >&2
  exit 1
fi

echo "PLAN: attach provenance for ${#subjects[@]} assets for ${TAG} in ${REPO} from ${ARTIFACTS}"
for path in "${subjects[@]}"; do
  echo "SUBJECT: $(basename "$path")"
done

if [ "${DRY_RUN:-}" = "1" ]; then
  echo "OK: dry-run listed ${#subjects[@]} subjects"
  echo "DONE: dry-run"
  exit 0
fi

if ! command -v gh >/dev/null 2>&1; then
  echo "FAIL: gh is not on PATH" >&2
  exit 1
fi
require_env GH_TOKEN

workdir=$(mktemp -d)
trap 'rm -rf "$workdir"' EXIT
mkdir -p "${workdir}/bundles"

echo "DO: download attestation bundles"
for path in "${subjects[@]}"; do
  name=$(basename "$path")
  tmpdir=$(mktemp -d)
  download_ok=0
  pushd "$tmpdir" >/dev/null
  for _attempt in 1 2 3 4 5; do
    if gh attestation download "$path" --repo "$REPO"; then
      download_ok=1
      break
    fi
    sleep 2
  done
  if [ "$download_ok" -eq 0 ]; then
    popd >/dev/null
    rm -rf "$tmpdir"
    echo "FAIL: gh attestation download ${name}" >&2
    exit 1
  fi
  for bundle in *.jsonl; do
    [ -f "$bundle" ] || continue
    cp "$bundle" "${workdir}/bundles/${name}.intoto.jsonl"
    break
  done
  popd >/dev/null
  rm -rf "$tmpdir"
  if [ ! -f "${workdir}/bundles/${name}.intoto.jsonl" ]; then
    echo "FAIL: no jsonl bundle for ${name}" >&2
    exit 1
  fi
done

echo "DO: upload artifacts and provenance"
gh release upload "$TAG" "${subjects[@]}" "${workdir}/bundles/"*.intoto.jsonl \
  --repo "$REPO" --clobber
echo "OK: uploaded ${#subjects[@]} artifacts plus provenance"
echo "DONE: ${TAG}"
