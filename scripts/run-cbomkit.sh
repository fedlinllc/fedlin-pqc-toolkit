#!/usr/bin/env bash
# run-cbomkit.sh — drive an out-of-band CBOMkit source scan and pull the CycloneDX CBOM.
#
# WHY OUT-OF-BAND: CBOMkit (github.com/PQCA/cbomkit) is a compose SERVICE — Quarkus/Java
# backend + Vue frontend + PostgreSQL, ports 8001/8081, scanner = sonar-cryptography
# (Java/Python/Go source). Baking that stack into fedlin-pqc-toolkit would break the
# toolkit's single-container / air-gap properties. Instead we run CBOMkit
# separately and feed its CBOM into the portable pipeline via --merge-cbom, where it
# gets the same policy stage and report as any other source.
#
# PREREQ: a running CBOMkit. From a CBOMkit checkout:  make production            (docker)
#                                                       make production ENGINE=podman
#         Default API base: http://localhost:8081
#
# USAGE:  scripts/run-cbomkit.sh <git-url> [branch] [subfolder] [out.json]
#   env:  CBOMKIT_API   (default http://localhost:8081)
#         POLL_TIMEOUT  (default 600 seconds)
#
# OUTPUT: writes the CycloneDX CBOM to <out.json> (default cbomkit-cbom.json), then:
#   python3 scripts/tier2_pipeline.py --merge-cbom cbomkit-cbom.json \
#     --out out/scan.json --name "<app>" --validate
#
# NOTE: authored against the documented CBOMkit REST API (POST /api/v1/scan;
#   GET /api/v1/cbom/last/{n}). Verify against your CBOMkit version — response
#   envelope field names can differ between releases (handled defensively below).
set -euo pipefail

GIT_URL="${1:?usage: run-cbomkit.sh <git-url> [branch] [subfolder] [out.json]}"
BRANCH="${2:-main}"
SUBFOLDER="${3:-}"
OUT="${4:-cbomkit-cbom.json}"
API="${CBOMKIT_API:-http://localhost:8081}"
POLL_TIMEOUT="${POLL_TIMEOUT:-600}"

command -v jq >/dev/null || { echo "[error] jq required" >&2; exit 3; }

echo "[*] CBOMkit API: $API" >&2
if ! curl -fsS "$API/api" >/dev/null 2>&1; then
  echo "[error] CBOMkit not reachable at $API/api — start it with 'make production' first." >&2
  exit 4
fi

# Baseline: how many CBOMs exist now, so we can detect the new one.
before="$(curl -fsS "$API/api/v1/cbom/last/1" | jq 'if type=="array" then length else 0 end' 2>/dev/null || echo 0)"

echo "[*] triggering scan: $GIT_URL (branch=$BRANCH subfolder='${SUBFOLDER}')" >&2
body="$(jq -nc --arg u "$GIT_URL" --arg b "$BRANCH" --arg s "$SUBFOLDER" \
  '{scanUrl:$u, branch:$b} + (if $s=="" then {} else {subfolder:$s} end)')"
curl -fsS -X POST "$API/api/v1/scan" -H 'Content-Type: application/json' -d "$body" >/dev/null \
  || { echo "[error] scan trigger failed" >&2; exit 5; }

# Poll the recent-CBOM feed until a fresh result lands (or timeout).
echo "[*] waiting for CBOM (timeout ${POLL_TIMEOUT}s) ..." >&2
deadline=$(( $(date +%s) + POLL_TIMEOUT ))
raw=""
while [ "$(date +%s)" -lt "$deadline" ]; do
  sleep 8
  raw="$(curl -fsS "$API/api/v1/cbom/last/1" 2>/dev/null || true)"
  [ -n "$raw" ] || continue
  now="$(printf '%s' "$raw" | jq 'if type=="array" then length else 0 end' 2>/dev/null || echo 0)"
  # a new/updated CBOM is present once the feed is non-empty (and, on a fresh instance, grew)
  if [ "$now" -ge 1 ] && { [ "$before" -eq 0 ] || [ "$now" -gt "$before" ] || \
       printf '%s' "$raw" | jq -e --arg u "$GIT_URL" 'tostring | test($u; "i")' >/dev/null 2>&1; }; then
    break
  fi
done
[ -n "$raw" ] || { echo "[error] no CBOM returned before timeout" >&2; exit 6; }

# Unwrap: the feed may be a list of records; the CycloneDX doc may be under .cbom / .bom
# / .content, or be the object itself. Try each; keep the first that looks like CycloneDX.
printf '%s' "$raw" | jq '
  def unwrap: (.[0] // .);
  def pick(x): (x.cbom // x.bom // x.content // x);
  (if type=="array" then unwrap else . end) | pick(.)
  | if .bomFormat=="CycloneDX" or .specVersion then . else empty end
' > "$OUT" 2>/dev/null || true

if [ ! -s "$OUT" ] || ! jq -e '.specVersion' "$OUT" >/dev/null 2>&1; then
  echo "[error] could not extract a CycloneDX CBOM from the API response." >&2
  echo "        Raw response saved to ${OUT}.raw for inspection; adjust the unwrap filter." >&2
  printf '%s' "$raw" > "${OUT}.raw"
  exit 7
fi

n="$(jq '[.components[]? | select(.type=="cryptographic-asset")] | length' "$OUT")"
echo "[ok] wrote $OUT — $n cryptographic-asset component(s)" >&2
echo "[next] python3 scripts/tier2_pipeline.py --merge-cbom $OUT \\" >&2
echo "         --out out/scan.json --name \"<app>\" --validate" >&2
