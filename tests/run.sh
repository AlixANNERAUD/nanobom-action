#!/usr/bin/env bash
# Runs upload.sh against a mock nanobom and checks exit codes, outputs, annotations and the job
# summary. Needs bash, curl, jq and python3.
set -uo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d)"
port="${MOCK_PORT:-18765}"
python3 "$root/tests/mock_nanobom.py" "$port" "$work/requests.jsonl" &
mock=$!
trap 'kill $mock 2> /dev/null; rm -rf "$work"' EXIT
for _ in $(seq 50); do
  curl --silent --output /dev/null "http://127.0.0.1:$port/" && break
  sleep 0.1
done

printf '{"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}' > "$work/sbom.json"
failures=0

# run PROJECT [VAR=VALUE…]: runs upload.sh with fresh output files; sets $code, $out, $log, $summary.
run() {
  local project="$1"
  shift
  : > "$work/output" && : > "$work/summary"
  log="$(
    env GITHUB_OUTPUT="$work/output" GITHUB_STEP_SUMMARY="$work/summary" \
      NANOBOM_URL="http://127.0.0.1:$port/" NANOBOM_TOKEN="nanobom_secret" \
      NANOBOM_ORGANIZATION="acme" NANOBOM_PROJECT="$project" NANOBOM_SBOM="$work/sbom.json" \
      NANOBOM_SOURCE_COMMIT="abc123" NANOBOM_IMAGE_TAG="" NANOBOM_FAIL_ON="" NANOBOM_WAIT="true" \
      "$@" "$root/upload.sh" 2>&1
  )"
  code=$?
  out="$(cat "$work/output")"
  summary="$(cat "$work/summary")"
}

check() {
  local description="$1"
  shift
  if "$@"; then
    echo "ok   $description"
  else
    echo "FAIL $description"
    echo "     log: $log"
    failures=$((failures + 1))
  fi
}
contains() { [[ "$1" == *"$2"* ]]; }
lacks() { [[ "$1" != *"$2"* ]]; }
last_request() { tail -n 1 "$work/requests.jsonl" | jq --raw-output "$1"; }

run passing
check "a passing upload succeeds" test "$code" -eq 0
check "it sends the token" test "$(last_request .authorization)" = "Bearer nanobom_secret"
check "it sends JSON" test "$(last_request .content_type)" = "application/json"
check "it asks to wait" test "$(last_request .query.wait)" = "true"
check "it sends the commit" test "$(last_request .query.source_commit)" = "abc123"
check "it sends no empty parameter" test "$(last_request '.query | has("image_tag") or has("fail_on")')" = "false"
check "outputs the status" contains "$out" "http-status=201"
check "outputs the evaluation" contains "$out" "evaluation-status=succeeded"
check "outputs the counts" contains "$out" "medium=1"
check "outputs the project URL" contains "$out" "project-url=http://127.0.0.1:$port/organizations/acme/projects/passing"
check "summarizes the findings" contains "$summary" "[GHSA-medium]("
check "summarizes the counts" contains "$summary" "| 0 | 0 | 1 | 0 | 0 | 0 |"

run gated NANOBOM_FAIL_ON=" High "
check "a gated upload fails" test "$code" -ne 0
check "it sends fail_on normalized" test "$(last_request .query.fail_on)" = "high"
check "it does not send wait with fail_on" test "$(last_request '.query | has("wait")')" = "false"
check "it reports the server's error" contains "$log" "::error title=nanobom::2 open findings at or above high"
check "it annotates the critical finding" contains "$log" "::error title=CVE-2021-44228 in pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1::critical, known exploited"
check "it annotates the high finding" contains "$log" "::error title=GHSA-high in pkg:npm/lodash@4.17.20::high"
check "it does not annotate the medium finding" lacks "$log" "GHSA-medium in"
check "outputs known exploited" contains "$out" "known-exploited=1"
check "summarizes the error" contains "$summary" "**2 open findings at or above high**"

run gated NANOBOM_FAIL_ON=exploited
check "exploited annotates the exploited finding" contains "$log" "CVE-2021-44228 in"
check "exploited does not annotate the others" lacks "$log" "GHSA-high in"

run incomplete NANOBOM_FAIL_ON=critical
check "an incomplete evaluation fails" test "$code" -ne 0
check "it says why" contains "$log" "the evaluation did not complete"
check "outputs timed_out" contains "$out" "evaluation-status=timed_out"

run plain NANOBOM_WAIT=false
check "an upload without wait succeeds" test "$code" -eq 0
check "it does not ask to wait" test "$(last_request '.query | has("wait")')" = "false"
check "it warns about components without package URL" contains "$log" "3 components have no package URL"
check "no evaluation output" contains "$out" "evaluation-status="$'\n'

run refused
check "a refused token fails" test "$code" -ne 0
check "it explains the refusal" contains "$log" "the upload token was refused (401)"

run missing
check "an unknown project fails" test "$code" -ne 0
check "it names the project" contains "$log" "acme/missing (404)"

run passing NANOBOM_WAIT=maybe
check "an invalid wait fails before uploading" test "$code" -ne 0

run "My.Project"
check "the project URL is lower-cased" contains "$out" "/projects/my.project"

run passing NANOBOM_SUMMARY=false
check "no summary when disabled" test -z "$summary"

run passing NANOBOM_SBOM="$work/absent.json"
check "a missing SBOM fails" contains "$log" "SBOM not found"

if ((failures > 0)); then
  echo "$failures check(s) failed"
  exit 1
fi
echo "all checks passed"
