#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCENARIO_CONFIG_DEFAULT="$ROOT_DIR/tests/threat_evidence/threat_evidence_scenarios.json"
OUTPUT_ROOT_DEFAULT="$ROOT_DIR/tests/threat_evidence/artifacts/threat_evidence_local"

SCENARIO_ID="all"
MODE="enforcement"
SCENARIO_CONFIG="$SCENARIO_CONFIG_DEFAULT"
OUTPUT_ROOT="$OUTPUT_ROOT_DEFAULT"
KEEP_DAEMON="false"
CI_ONLY="false"

cd "$ROOT_DIR"

EDAMAME_POSTURE_CMD_STR="${EDAMAME_POSTURE_CMD:-edamame_posture}"
# The Posture GitHub Action sets EDAMAME_POSTURE_CMD to a full command
# (e.g. "sudo -E edamame_posture"). Parse it so we can invoke it reliably.
read -r -a EDAMAME_POSTURE_CMD_ARR <<<"$EDAMAME_POSTURE_CMD_STR"

posture() {
  "${EDAMAME_POSTURE_CMD_ARR[@]}" "$@"
}

usage() {
  cat <<EOF
Usage: $(basename "$0") [options]

Runs local threat-evidence scenarios in Ubuntu Lima.

Options:
  --scenario <id|all>         Scenario id from config (default: all)
  --mode <learning|enforcement>
                              Assertion mode for expected signals (default: enforcement)
  --config <path>             Path to scenario config JSON
  --output-dir <path>         Directory for evidence artifacts
  --ci-only                   Run only scenarios where ci_ready=true
  --keep-daemon               Do not stop daemon at script exit
  --help                      Show this help

Examples:
  ./tests/run_threat_evidence_lima.sh --scenario contagious_interview_beaconing --mode enforcement
  ./tests/run_threat_evidence_lima.sh --scenario all --mode learning --ci-only
EOF
}

log() { echo "[threat-evidence] $*"; }
warn() { echo "[threat-evidence][warn] $*" >&2; }
fail() { echo "[threat-evidence][error] $*" >&2; exit 1; }

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "Missing required command: $1"
}

count_matches() {
  local pattern="$1"
  local file="$2"
  local out
  out="$(grep -Eic "$pattern" "$file" 2>/dev/null || true)"
  out="$(printf '%s' "$out" | tr -d '\n\r' | sed 's/[^0-9]//g')"
  if [[ -z "$out" ]]; then
    echo 0
  else
    echo "$out"
  fi
}

count_non_empty_lines() {
  local file="$1"
  awk 'NF { c++ } END { print c + 0 }' "$file" 2>/dev/null || echo 0
}

cleanup() {
  if [[ "$KEEP_DAEMON" == "true" ]]; then
    log "Leaving daemon running (--keep-daemon set)"
    return
  fi
  set +e
  posture stop >/dev/null 2>&1 || true
  set -e
}
trap cleanup EXIT

while [[ $# -gt 0 ]]; do
  case "$1" in
    --scenario)
      SCENARIO_ID="${2:-}"; shift 2 ;;
    --mode)
      MODE="${2:-}"; shift 2 ;;
    --config)
      SCENARIO_CONFIG="${2:-}"; shift 2 ;;
    --output-dir)
      OUTPUT_ROOT="${2:-}"; shift 2 ;;
    --ci-only)
      CI_ONLY="true"; shift ;;
    --keep-daemon)
      KEEP_DAEMON="true"; shift ;;
    --help|-h)
      usage; exit 0 ;;
    *)
      fail "Unknown argument: $1" ;;
  esac
done

[[ "$MODE" == "learning" || "$MODE" == "enforcement" ]] || fail "Invalid --mode: $MODE"
[[ -f "$SCENARIO_CONFIG" ]] || fail "Config file not found: $SCENARIO_CONFIG"

require_cmd jq
require_cmd curl
if [[ "${#EDAMAME_POSTURE_CMD_ARR[@]}" -eq 0 ]]; then
  fail "EDAMAME_POSTURE_CMD resolved to empty"
fi

require_cmd "${EDAMAME_POSTURE_CMD_ARR[0]}"
posture_bin="${EDAMAME_POSTURE_CMD_ARR[${#EDAMAME_POSTURE_CMD_ARR[@]}-1]}"
if [[ "$posture_bin" == "edamame_posture" ]]; then
  require_cmd edamame_posture
elif [[ "$posture_bin" == ./* || "$posture_bin" == /* ]]; then
  [[ -x "$posture_bin" ]] || fail "EDAMAME Posture binary not executable: $posture_bin (EDAMAME_POSTURE_CMD=$EDAMAME_POSTURE_CMD_STR)"
fi

RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_DIR="$OUTPUT_ROOT/$RUN_ID"
mkdir -p "$RUN_DIR"

log "Mode=$MODE Scenario=$SCENARIO_ID Config=$SCENARIO_CONFIG CI_ONLY=$CI_ONLY"
log "Evidence directory: $RUN_DIR"

WARMUP_SECONDS="$(jq -r '.baseline.warmup_seconds // 20' "$SCENARIO_CONFIG")"
POST_ATTACK_WAIT_SECONDS="$(jq -r '.baseline.post_attack_wait_seconds // 15' "$SCENARIO_CONFIG")"
DEFAULT_WHITELIST="$(jq -r '.baseline.whitelist_name // "github_ubuntu"' "$SCENARIO_CONFIG")"

start_disconnected_daemon() {
  local whitelist_name="$1"
  log "Starting daemon in disconnected mode"
  posture stop >/dev/null 2>&1 || true
  # Best-effort cleanup for runs that leave a root daemon behind (common in CI/Lima).
  if command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then
    sudo -E pkill -f 'edamame_posture background-process' >/dev/null 2>&1 || true
    sudo -E pkill -f 'edamame_posture background-start-disconnected' >/dev/null 2>&1 || true
    # Package installs can leave a systemd service running; stop it so we can own lifecycle.
    if command -v systemctl >/dev/null 2>&1; then
      sudo systemctl stop edamame_posture.service >/dev/null 2>&1 || true
    fi
  fi
  sleep 2
  posture background-start-disconnected \
    --network-scan \
    --packet-capture \
    --whitelist "$whitelist_name"
  sleep "$WARMUP_SECONDS"
}

generate_baseline_traffic() {
  log "Generating baseline traffic"
  curl -s --max-time 15 https://github.com/robots.txt >/dev/null || true
  curl -s --max-time 15 https://api.github.com/zen >/dev/null || true
  curl -s --max-time 15 https://pypi.org/pypi/requests/json >/dev/null || true
  sleep 5
}

create_and_load_whitelist() {
  local scenario="$1"
  local scenario_dir="$2"
  local include_process
  local wl_file="$scenario_dir/custom_whitelist.json"
  include_process="$(jq -r --arg s "$scenario" '.scenarios[] | select(.id == $s) | .requires_include_process // false' "$SCENARIO_CONFIG")"

  if [[ "$include_process" == "true" ]]; then
    log "Creating process-aware whitelist (--include-process)"
    posture create-custom-whitelists --include-process > "$wl_file"
  else
    posture create-custom-whitelists > "$wl_file"
  fi

  local endpoint_count
  endpoint_count="$(jq '[.whitelists[]? | select(.name == "custom_whitelist") | .endpoints? // [] | length] | add // 0' "$wl_file" 2>/dev/null || echo 0)"
  log "Whitelist endpoint count: $endpoint_count"
  [[ "$endpoint_count" -gt 0 ]] || fail "Baseline whitelist is empty for scenario=$scenario"

  posture set-custom-whitelists-from-file "$wl_file"
}

run_scenario_payload() {
  local scenario="$1"
  local scenario_dir="$2"
  local payload
  payload="$(jq -r --arg s "$scenario" '.scenarios[] | select(.id == $s) | .command' "$SCENARIO_CONFIG")"
  [[ -n "$payload" && "$payload" != "null" ]] || fail "Missing command in config for scenario=$scenario"

  printf '%s\n' "$payload" > "$scenario_dir/payload.sh"
  chmod +x "$scenario_dir/payload.sh"

  log "Running scenario payload: $scenario"
  bash "$scenario_dir/payload.sh" > "$scenario_dir/payload.log" 2>&1 || true
  sleep "$POST_ATTACK_WAIT_SECONDS"
}

collect_and_assert() {
  local scenario="$1"
  local scenario_dir="$2"
  local require_failure
  local min_nonconforming
  local min_anomalous
  local min_recorded_sessions

  require_failure="$(jq -r --arg s "$scenario" --arg mode "$MODE" '.scenarios[] | select(.id == $s) | if $mode == "enforcement" then .enforcement_expected.require_failure // false else .learning_expected.require_failure // false end' "$SCENARIO_CONFIG")"
  min_nonconforming="$(jq -r --arg s "$scenario" --arg mode "$MODE" '.scenarios[] | select(.id == $s) | if $mode == "enforcement" then .enforcement_expected.min_nonconforming // 0 else .learning_expected.min_nonconforming // 0 end' "$SCENARIO_CONFIG")"
  min_anomalous="$(jq -r --arg s "$scenario" --arg mode "$MODE" '.scenarios[] | select(.id == $s) | if $mode == "enforcement" then .enforcement_expected.min_anomalous // 0 else .learning_expected.min_anomalous // 0 end' "$SCENARIO_CONFIG")"
  min_recorded_sessions="$(jq -r --arg s "$scenario" --arg mode "$MODE" '.scenarios[] | select(.id == $s) | if $mode == "enforcement" then .enforcement_expected.min_recorded_sessions // 1 else .learning_expected.min_recorded_sessions // 1 end' "$SCENARIO_CONFIG")"

  local sessions_file="$scenario_dir/sessions.log"
  local exceptions_file="$scenario_dir/exceptions.log"
  local summary_file="$scenario_dir/result_summary.json"
  local sessions_exit=0

  set +e
  if [[ "$MODE" == "enforcement" ]]; then
    posture get-sessions --fail-on-whitelist --fail-on-anomalous > "$sessions_file" 2>&1
  else
    posture get-sessions > "$sessions_file" 2>&1
  fi
  sessions_exit=$?
  set -e

  posture get-exceptions > "$exceptions_file" 2>&1 || true

  local nonconforming_count anomalous_count unknown_count recorded_sessions
  nonconforming_count="$(count_matches 'whitelisted:[[:space:]]*nonconforming' "$exceptions_file")"
  anomalous_count="$(count_matches 'anomalous' "$exceptions_file")"
  unknown_count="$(count_matches 'whitelisted:[[:space:]]*unknown' "$exceptions_file")"
  recorded_sessions="$(count_non_empty_lines "$sessions_file")"

  # Some environments return a nonzero exit + a sentinel line in sessions output,
  # but do not emit per-session exception details via `get-exceptions`.
  if grep -qi 'non[- ]conforming sessions detected' "$sessions_file" 2>/dev/null; then
    if [[ "${nonconforming_count:-0}" -lt 1 ]]; then
      nonconforming_count=1
    fi
  fi

  local pass="true"
  local reason=()

  if [[ "$require_failure" == "true" && "$sessions_exit" -eq 0 ]]; then
    pass="false"
    reason+=("expected_nonzero_exit")
  fi
  if [[ "$nonconforming_count" -lt "$min_nonconforming" ]]; then
    pass="false"
    reason+=("nonconforming_lt_${min_nonconforming}")
  fi
  if [[ "$anomalous_count" -lt "$min_anomalous" ]]; then
    pass="false"
    reason+=("anomalous_lt_${min_anomalous}")
  fi
  if [[ "$recorded_sessions" -lt "$min_recorded_sessions" ]]; then
    pass="false"
    reason+=("sessions_lt_${min_recorded_sessions}")
  fi

  jq -n \
    --arg scenario "$scenario" \
    --arg mode "$MODE" \
    --arg pass "$pass" \
    --arg reason "$(IFS=,; echo "${reason[*]:-ok}")" \
    --argjson sessions_exit "$sessions_exit" \
    --argjson nonconforming "$nonconforming_count" \
    --argjson anomalous "$anomalous_count" \
    --argjson unknown "$unknown_count" \
    --argjson recorded_sessions "$recorded_sessions" \
    --argjson min_nonconforming "$min_nonconforming" \
    --argjson min_anomalous "$min_anomalous" \
    --argjson min_recorded_sessions "$min_recorded_sessions" \
    '{
      scenario: $scenario,
      mode: $mode,
      pass: ($pass == "true"),
      reason: $reason,
      observed: {
        sessions_exit: $sessions_exit,
        nonconforming: $nonconforming,
        anomalous: $anomalous,
        unknown: $unknown,
        recorded_sessions: $recorded_sessions
      },
      expected: {
        min_nonconforming: $min_nonconforming,
        min_anomalous: $min_anomalous,
        min_recorded_sessions: $min_recorded_sessions
      }
    }' > "$summary_file"

  if [[ "$pass" == "true" ]]; then
    log "Scenario passed: $scenario"
    return 0
  fi

  warn "Scenario failed: $scenario (reason=$(IFS=,; echo "${reason[*]}"))"
  return 1
}

declare -a scenarios=()
if [[ "$SCENARIO_ID" == "all" ]]; then
  if [[ "$CI_ONLY" == "true" ]]; then
    while IFS= read -r line; do scenarios+=("$line"); done < <(jq -r '.scenarios[] | select(.ci_ready == true) | .id' "$SCENARIO_CONFIG")
  else
    while IFS= read -r line; do scenarios+=("$line"); done < <(jq -r '.scenarios[].id' "$SCENARIO_CONFIG")
  fi
else
  if ! jq -e --arg s "$SCENARIO_ID" '.scenarios[] | select(.id == $s)' "$SCENARIO_CONFIG" >/dev/null; then
    fail "Unknown scenario id: $SCENARIO_ID"
  fi
  if [[ "$CI_ONLY" == "true" ]] && ! jq -e --arg s "$SCENARIO_ID" '.scenarios[] | select(.id == $s and .ci_ready == true)' "$SCENARIO_CONFIG" >/dev/null; then
    fail "Scenario id is not ci_ready: $SCENARIO_ID"
  fi
  scenarios+=("$SCENARIO_ID")
fi

[[ "${#scenarios[@]}" -gt 0 ]] || fail "No scenarios selected"

pass_count=0
fail_count=0

for scenario in "${scenarios[@]}"; do
  scenario_dir="$RUN_DIR/$scenario"
  mkdir -p "$scenario_dir"
  log "===== Scenario: $scenario ====="

  start_disconnected_daemon "$DEFAULT_WHITELIST"
  generate_baseline_traffic
  create_and_load_whitelist "$scenario" "$scenario_dir"
  run_scenario_payload "$scenario" "$scenario_dir"

  if collect_and_assert "$scenario" "$scenario_dir"; then
    pass_count=$((pass_count + 1))
  else
    fail_count=$((fail_count + 1))
  fi
done

jq -n \
  --arg mode "$MODE" \
  --arg run_dir "$RUN_DIR" \
  --argjson pass_count "$pass_count" \
  --argjson fail_count "$fail_count" \
  --argjson total "$((pass_count + fail_count))" \
  '{
    mode: $mode,
    run_dir: $run_dir,
    total: $total,
    pass_count: $pass_count,
    fail_count: $fail_count
  }' > "$RUN_DIR/summary.json"

log "Completed. pass=$pass_count fail=$fail_count artifacts=$RUN_DIR"
[[ "$fail_count" -eq 0 ]] || exit 1
