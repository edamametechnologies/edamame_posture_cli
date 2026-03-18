#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCENARIO_CONFIG_DEFAULT="$ROOT_DIR/tests/threat_evidence/threat_evidence_scenarios.json"
OUTPUT_ROOT_DEFAULT="$ROOT_DIR/tests/threat_evidence/artifacts/threat_evidence_stability"
RUNNER_SCRIPT_DEFAULT="$ROOT_DIR/tests/threat_evidence/run_threat_evidence_lima.sh"

ITERATIONS=10
MIN_PASS_RATE=95
MAX_UNKNOWN=0
SCENARIOS=""
MODE="enforcement"
SCENARIO_CONFIG="$SCENARIO_CONFIG_DEFAULT"
OUTPUT_ROOT="$OUTPUT_ROOT_DEFAULT"
RUNNER_SCRIPT="$RUNNER_SCRIPT_DEFAULT"
CI_ONLY="true"

usage() {
  cat <<EOF
Usage: $(basename "$0") [options]

Runs repeated threat-evidence scenarios and validates stability thresholds.

Options:
  --iterations <n>            Number of iterations (default: 10)
  --min-pass-rate <percent>   Minimum pass percentage (default: 95)
  --max-unknown <n>           Maximum total unknown exceptions allowed (default: 0)
  --scenarios <csv>           Comma-separated scenario ids (default: all selected by --ci-only)
  --mode <learning|enforcement>
                              Runner mode for assertions (default: enforcement)
  --config <path>             Scenario config JSON path
  --output-dir <path>         Stability artifacts root
  --runner <path>             Runner script (default: tests/run_threat_evidence_lima.sh)
  --ci-only                   Keep only ci_ready scenarios (default)
  --all-scenarios             Disable ci_ready filtering
  --help                      Show this help
EOF
}

log() { echo "[threat-stability] $*"; }
fail() { echo "[threat-stability][error] $*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --iterations)
      ITERATIONS="${2:-}"; shift 2 ;;
    --min-pass-rate)
      MIN_PASS_RATE="${2:-}"; shift 2 ;;
    --max-unknown)
      MAX_UNKNOWN="${2:-}"; shift 2 ;;
    --scenarios)
      SCENARIOS="${2:-}"; shift 2 ;;
    --mode)
      MODE="${2:-}"; shift 2 ;;
    --config)
      SCENARIO_CONFIG="${2:-}"; shift 2 ;;
    --output-dir)
      OUTPUT_ROOT="${2:-}"; shift 2 ;;
    --runner)
      RUNNER_SCRIPT="${2:-}"; shift 2 ;;
    --ci-only)
      CI_ONLY="true"; shift ;;
    --all-scenarios)
      CI_ONLY="false"; shift ;;
    --help|-h)
      usage; exit 0 ;;
    *)
      fail "Unknown argument: $1" ;;
  esac
done

[[ -f "$RUNNER_SCRIPT" ]] || fail "Runner script not found: $RUNNER_SCRIPT"
[[ -f "$SCENARIO_CONFIG" ]] || fail "Config file not found: $SCENARIO_CONFIG"
[[ "$MODE" == "learning" || "$MODE" == "enforcement" ]] || fail "Invalid --mode: $MODE"

command -v jq >/dev/null 2>&1 || fail "Missing required command: jq"

RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_DIR="$OUTPUT_ROOT/$RUN_ID"
mkdir -p "$RUN_DIR"

log "iterations=$ITERATIONS mode=$MODE min_pass_rate=$MIN_PASS_RATE max_unknown=$MAX_UNKNOWN ci_only=$CI_ONLY"
log "stability_run_dir=$RUN_DIR"

total_runs=0
passed_runs=0
failed_runs=0
unknown_total=0

for ((i=1; i<=ITERATIONS; i++)); do
  iter_dir="$RUN_DIR/iter_$i"
  mkdir -p "$iter_dir"

  log "Iteration $i/$ITERATIONS"
  set +e
  if [[ -n "$SCENARIOS" ]]; then
    IFS=',' read -r -a selected <<< "$SCENARIOS"
    iter_fail=0
    for s in "${selected[@]}"; do
      run_args=()
      if [[ "$CI_ONLY" == "true" ]]; then
        run_args+=(--ci-only)
      fi
      "$RUNNER_SCRIPT" \
        --mode "$MODE" \
        --scenario "$s" \
        --config "$SCENARIO_CONFIG" \
        --output-dir "$iter_dir" \
        "${run_args[@]}" >/dev/null 2>&1 || iter_fail=1
    done
    rc=$iter_fail
  else
    run_args=()
    if [[ "$CI_ONLY" == "true" ]]; then
      run_args+=(--ci-only)
    fi
    "$RUNNER_SCRIPT" \
      --mode "$MODE" \
      --scenario all \
      --config "$SCENARIO_CONFIG" \
      --output-dir "$iter_dir" \
      "${run_args[@]}" >/dev/null 2>&1
    rc=$?
  fi
  set -e

  total_runs=$((total_runs + 1))
  if [[ "$rc" -eq 0 ]]; then
    passed_runs=$((passed_runs + 1))
  else
    failed_runs=$((failed_runs + 1))
  fi

  if compgen -G "$iter_dir/*/*/result_summary.json" > /dev/null; then
    current_unknown="$(jq -s '[.[].observed.unknown // 0] | add // 0' "$iter_dir"/*/*/result_summary.json 2>/dev/null || echo 0)"
    unknown_total=$((unknown_total + current_unknown))
  fi
done

pass_rate="$(python3 - <<PY
total = $total_runs
passed = $passed_runs
print(round((passed / total) * 100 if total else 0, 2))
PY
)"

is_pass_rate_ok="$(python3 - <<PY
print("true" if float("$pass_rate") >= float("$MIN_PASS_RATE") else "false")
PY
)"
is_unknown_ok="$(python3 - <<PY
print("true" if int("$unknown_total") <= int("$MAX_UNKNOWN") else "false")
PY
)"

jq -n \
  --arg run_dir "$RUN_DIR" \
  --arg mode "$MODE" \
  --argjson iterations "$ITERATIONS" \
  --argjson total_runs "$total_runs" \
  --argjson passed_runs "$passed_runs" \
  --argjson failed_runs "$failed_runs" \
  --argjson unknown_total "$unknown_total" \
  --argjson min_pass_rate "$MIN_PASS_RATE" \
  --argjson max_unknown "$MAX_UNKNOWN" \
  --argjson pass_rate "$pass_rate" \
  --arg is_pass_rate_ok "$is_pass_rate_ok" \
  --arg is_unknown_ok "$is_unknown_ok" \
  '{
    run_dir: $run_dir,
    mode: $mode,
    iterations: $iterations,
    totals: {
      total_runs: $total_runs,
      passed_runs: $passed_runs,
      failed_runs: $failed_runs,
      pass_rate: $pass_rate,
      unknown_total: $unknown_total
    },
    thresholds: {
      min_pass_rate: $min_pass_rate,
      max_unknown: $max_unknown
    },
    checks: {
      pass_rate_ok: ($is_pass_rate_ok == "true"),
      unknown_ok: ($is_unknown_ok == "true")
    }
  }' > "$RUN_DIR/stability_summary.json"

log "stability_summary=$RUN_DIR/stability_summary.json pass_rate=$pass_rate unknown_total=$unknown_total"
[[ "$is_pass_rate_ok" == "true" && "$is_unknown_ok" == "true" ]] || exit 1
