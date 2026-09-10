#!/usr/bin/env bash
# Run divergence-verdict detection scenarios against a running edamame_posture
# daemon and record outcomes in the same JSON shape as run_cve_detection.sh.
#
# Why this is a separate runner
# -----------------------------
# run_cve_detection.sh asserts model-independent *vulnerability findings* via
# `get_vulnerability_findings`. A divergence verdict is a different plane and a
# different RPC (`get_divergence_verdict`), and it requires planting a
# behavioral model first. Rather than bolt a second assertion mode onto that
# script, divergence scenarios live here. The result artifacts are deliberately
# identical in shape so `check_gate.py` needs no new parser: pass `--append` and
# this runner merges its rows into the CVE suite's results.ndjson and rewrites
# results.json from the union.
#
# Per scenario the runner needs three things: a behavioral model JSON, a trigger
# script, and an expected evidence shape. Asserting only the verdict would let
# unrelated evidence satisfy the gate, so every scenario also names a substring
# that the evidence description MUST contain -- the same attribution problem
# `scenario_markers_json()` solves in the CVE runner.
#
# Usage:
#   run_divergence_detection.sh \
#     --triggers-dir <dir> \
#     --output-dir <dir> \
#     [--models-dir <dir>]               # default: <repo>/tests/security/models
#     [--trigger-duration <seconds>]     # default: 240
#     [--post-wait <seconds>]            # default: 20
#     [--cooldown <seconds>]             # default: 8
#     [--poll-attempts <count>]          # default: 12
#     [--poll-interval <seconds>]        # default: 15
#     [--engine-interval <seconds>]      # default: 30
#     [--agent-type <string>]            # default: openclaw
#     [--scenarios <comma,separated>]    # default: the full divergence set
#     [--append]                         # merge into an existing results.ndjson
#
# Environment:
#   EDAMAME_CLI        path to edamame_cli binary (mandatory)
#   PYTHON             path to python3 (default: python3)
#
# Outputs (under --output-dir):
#   results.json       full result object: platform, scenarios[], totals
#   results.ndjson     one JSON per scenario, for streaming consumers
#   divergence_ticks.log  stdout/stderr from forced divergence ticks
#   verdicts/<scenario>.json  the final verdict payload, for triage

set -Euo pipefail

log() { printf '[divergence] %s\n' "$*" >&2; }
die() { log "ERROR: $*"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

TRIGGERS_DIR=""
OUTPUT_DIR=""
MODELS_DIR="$SCRIPT_DIR/models"
# The divergence engine reads CURRENT (active) sessions and flodbadd needs the
# stand-in alive to attribute parent_process_path, so the trigger must outlive
# the whole poll window. 240s trigger vs 12x15s polling leaves margin.
TRIGGER_DURATION=240
POST_WAIT=20
COOLDOWN=8
POLL_ATTEMPTS=12
POLL_INTERVAL=15
ENGINE_INTERVAL=30
AGENT_TYPE="openclaw"
APPEND=0
SCENARIOS_CSV="daemon_lineage_egress"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --triggers-dir)      TRIGGERS_DIR="$2"; shift 2;;
    --output-dir)        OUTPUT_DIR="$2"; shift 2;;
    --models-dir)        MODELS_DIR="$2"; shift 2;;
    --trigger-duration)  TRIGGER_DURATION="$2"; shift 2;;
    --post-wait)         POST_WAIT="$2"; shift 2;;
    --cooldown)          COOLDOWN="$2"; shift 2;;
    --poll-attempts)     POLL_ATTEMPTS="$2"; shift 2;;
    --poll-interval)     POLL_INTERVAL="$2"; shift 2;;
    --engine-interval)   ENGINE_INTERVAL="$2"; shift 2;;
    --agent-type)        AGENT_TYPE="$2"; shift 2;;
    --scenarios)         SCENARIOS_CSV="$2"; shift 2;;
    --append)            APPEND=1; shift;;
    -h|--help) sed -n '2,46p' "$0"; exit 0;;
    *) die "unknown flag: $1";;
  esac
done

[[ -n "$TRIGGERS_DIR" ]] || die "--triggers-dir required"
[[ -n "$OUTPUT_DIR"   ]] || die "--output-dir required"
[[ -d "$TRIGGERS_DIR" ]] || die "triggers dir not found: $TRIGGERS_DIR"
[[ -d "$MODELS_DIR"   ]] || die "models dir not found: $MODELS_DIR"
[[ -n "${EDAMAME_CLI:-}" && -x "${EDAMAME_CLI:-}" ]] || die "EDAMAME_CLI must point to an executable edamame_cli"

PYTHON="${PYTHON:-python3}"
mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR_ABS=$(cd "$OUTPUT_DIR" && pwd)
NDJSON="$OUTPUT_DIR_ABS/results.ndjson"
TICK_LOG="$OUTPUT_DIR_ABS/divergence_ticks.log"
RESULT_JSON="$OUTPUT_DIR_ABS/results.json"
mkdir -p "$OUTPUT_DIR_ABS/verdicts"
if (( APPEND == 0 )); then
  : >"$NDJSON"
fi
: >"$TICK_LOG"

IFS=',' read -r -a SCENARIOS <<<"$SCENARIOS_CSV"

# ---------------------------------------------------------------------------
# Scenario registry. Each divergence scenario needs a model, a trigger, and an
# evidence marker. Add new scenarios to all four functions plus SCENARIOS_CSV.
# ---------------------------------------------------------------------------

model_file_for() {
  case "$1" in
    daemon_lineage_egress) echo "$MODELS_DIR/daemon_lineage_egress.json" ;;
    *) echo "" ;;
  esac
}

trigger_script_for() {
  echo "$TRIGGERS_DIR/trigger_$1.py"
}

# The evidence category the scenario must produce.
expected_check_for() {
  case "$1" in
    daemon_lineage_egress) echo "correlation:not_expected" ;;
    *) echo "" ;;
  esac
}

# Prefix the evidence description must start with, and a substring it must
# contain. Together these bind the verdict to THIS scenario's stimulus: a bare
# `deterministic_verdict == DIVERGENCE` assertion would be satisfied by any
# unrelated observation the engine happened to record in the same window.
# `<PFX>` expands to _common.file_prefix_for(agent_type).
evidence_prefix_for() {
  case "$1" in
    daemon_lineage_egress) echo "Parent path '" ;;
    *) echo "" ;;
  esac
}

evidence_marker_for() {
  case "$1" in
    daemon_lineage_egress) echo "<PFX>_xz_sshd_standin" ;;
    *) echo "" ;;
  esac
}

# Scenarios with no sensor or no install path on a platform. Mirrors
# PLATFORM_EXCLUDED_SCENARIOS in check_gate.py, which accepts the recorded
# `unsupported_platform` skip for exactly these pairs and nothing else.
scenario_excluded_on_this_platform() {
  local scenario="$1"
  case "$(uname -s 2>/dev/null || true)" in
    MINGW*|MSYS*|CYGWIN*)
      case "$scenario" in
        # daemon_lineage_egress needs a %WINDIR%\System32 write plus ETW
        # parent-path attribution; neither is implemented. Linux/macOS only.
        daemon_lineage_egress) return 0 ;;
      esac
      ;;
  esac
  return 1
}

file_prefix_for() { echo "demo_$1"; }

# ---------------------------------------------------------------------------
# RPC plumbing
# ---------------------------------------------------------------------------

call_rpc() {
  "$EDAMAME_CLI" rpc "$@" 2>>"$TICK_LOG"
}

force_divergence_tick() {
  call_rpc debug_run_divergence_tick >>"$TICK_LOG" 2>&1 || true
}

# Clear model AND verdict history. Without the history clear a DIVERGENCE from a
# previous scenario stays the latest verdict and the next scenario reads as an
# instant pass.
divergence_reset() {
  call_rpc clear_behavioral_model >>"$TICK_LOG" 2>&1 || true
  call_rpc clear_divergence_history >>"$TICK_LOG" 2>&1 || true
  call_rpc reset_divergence_suppressions >>"$TICK_LOG" 2>&1 || true
  call_rpc clear_divergence_state >>"$TICK_LOG" 2>&1 || true
}

run_cleanup() {
  "$PYTHON" "$TRIGGERS_DIR/cleanup.py" --agent-type "$AGENT_TYPE" >>"$TICK_LOG" 2>&1 || true
}

# Rewrite the model fixture for this run: window timestamps to now / now+20m and
# the agent prefix to match --agent-type. Prints the prepared file path.
prepare_model() {
  local scenario="$1"
  local src="$2"
  local dest="$OUTPUT_DIR_ABS/model.$scenario.json"
  MODEL_SRC="$src" MODEL_DEST="$dest" MODEL_PFX="$(file_prefix_for "$AGENT_TYPE")" \
    "$PYTHON" - <<'PY' 2>>"$TICK_LOG"
import datetime, json, os

src = os.environ["MODEL_SRC"]
dest = os.environ["MODEL_DEST"]
pfx = os.environ["MODEL_PFX"]

raw = open(src, "r", encoding="utf-8").read().replace("demo_openclaw", pfx)
model = json.loads(raw)
model.pop("_comment", None)

now = datetime.datetime.now(datetime.timezone.utc)
stamp = lambda t: t.isoformat().replace("+00:00", "Z")
model["window_start"] = stamp(now)
model["window_end"] = stamp(now + datetime.timedelta(minutes=20))
model["ingested_at"] = stamp(now)

with open(dest, "w", encoding="utf-8") as fh:
    json.dump(model, fh)
PY
  echo "$dest"
}

upsert_model() {
  local model_file="$1"
  MODEL_FILE="$model_file" TRIGGERS_DIR_ENV="$TRIGGERS_DIR" \
    "$PYTHON" - <<'PY' 2>>"$TICK_LOG"
import json, os, sys
sys.path.insert(0, os.environ["TRIGGERS_DIR_ENV"])
from _edamame_cli import cli_rpc

window = open(os.environ["MODEL_FILE"], "r", encoding="utf-8").read()
try:
    res = cli_rpc("upsert_behavioral_model", json.dumps({"window_json": window}))
except Exception as exc:
    print(f"0|upsert raised: {exc}")
    raise SystemExit(0)
# A rejected window (missing required array, empty agent_type) returns an
# error payload rather than raising, and would otherwise look like a model
# that simply never produced a verdict.
if isinstance(res, dict) and res.get("error"):
    print(f"0|upsert rejected: {res['error']}")
else:
    print("1|ok")
PY
}

start_engine() {
  call_rpc start_divergence_engine "[true, $ENGINE_INTERVAL]" >>"$TICK_LOG" 2>&1 || true
}

# Evaluate the current verdict against a scenario's expected evidence shape.
# Prints: matched|deterministic_verdict|final_verdict|evidence_total|categories
evaluate_verdict() {
  local scenario="$1"
  local prefix="$2"
  local marker="$3"
  local category="$4"
  EV_PREFIX="$prefix" EV_MARKER="$marker" EV_CATEGORY="$category" \
  EV_OUT="$OUTPUT_DIR_ABS/verdicts/$scenario.json" TRIGGERS_DIR_ENV="$TRIGGERS_DIR" \
    "$PYTHON" - <<'PY' 2>>"$TICK_LOG"
import json, os, sys
sys.path.insert(0, os.environ["TRIGGERS_DIR_ENV"])
from _edamame_cli import cli_rpc

prefix = os.environ["EV_PREFIX"]
marker = os.environ["EV_MARKER"]
category = os.environ["EV_CATEGORY"]

try:
    summary = cli_rpc("get_divergence_verdict")
except Exception as exc:
    print(f"0|ERROR|ERROR|0|{exc}")
    raise SystemExit(0)
if isinstance(summary, str):
    summary = json.loads(summary)
summary = summary or {}

with open(os.environ["EV_OUT"], "w", encoding="utf-8") as fh:
    json.dump(summary, fh, indent=2)

# VerdictKind derives Serialize with no rename, so the wire value is
# "Divergence" while Display renders "DIVERGENCE". Compare case-insensitively.
final = str(summary.get("verdict") or "").strip().upper()
det = str(summary.get("deterministic_verdict") or "").strip().upper()
evidence = [e for e in (summary.get("evidence") or []) if isinstance(e, dict)]

def attributed(e):
    desc = str(e.get("description") or "")
    if not desc.startswith(prefix) or marker not in desc:
        return False
    if category and str(e.get("category") or "") != category:
        return False
    return not e.get("dismissed")

hits = [e for e in evidence if attributed(e)]
# Mirror production alerting: only HIGH/CRITICAL non-dismissed evidence counts,
# which is also what check_gate.py requires of a passing scenario.
alertable = [e for e in hits if str(e.get("severity") or "").upper() in ("HIGH", "CRITICAL")]

matched = 1 if (det == "DIVERGENCE" and alertable) else 0
cats = ",".join(sorted({str(e.get("category") or "") for e in evidence})) or "none"
print(f"{matched}|{det or 'NONE'}|{final or 'NONE'}|{len(evidence)}|{cats}|{len(alertable)}")
PY
}

record_scenario_result() {
  local scenario="$1" check="$2" status="$3" total="$4" alertable="$5"
  local elapsed="$6" extra="$7" severities="${8:-none}"
  SR_SCENARIO="$scenario" SR_CHECK="$check" SR_STATUS="$status" SR_TOTAL="$total" \
  SR_ALERTABLE="$alertable" SR_ELAPSED="$elapsed" SR_EXTRA="$extra" \
  SR_SEVERITIES="$severities" SR_AGENT="$AGENT_TYPE" SR_DURATION="$TRIGGER_DURATION" \
    "$PYTHON" - <<'PY' | tee -a "$NDJSON" >/dev/null
import json, os, time
env = os.environ
rec = {
    "scenario": env["SR_SCENARIO"],
    "expected_check": env["SR_CHECK"],
    "status": env["SR_STATUS"],
    "finding_total": int(env["SR_TOTAL"]),
    "finding_current": int(env["SR_TOTAL"]),
    "finding_history": 0,
    "finding_alertable": int(env["SR_ALERTABLE"]),
    "severities": env["SR_SEVERITIES"],
    "elapsed_s": float(env["SR_ELAPSED"]),
    "agent_type": env["SR_AGENT"],
    "trigger_duration_s": int(env["SR_DURATION"]),
    "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "extra": env["SR_EXTRA"],
    "plane": "divergence",
}
print(json.dumps(rec))
PY
}

# ---------------------------------------------------------------------------
# Scenario driver
# ---------------------------------------------------------------------------

run_one_scenario() {
  local scenario="$1"
  local check model_file trigger_script prefix marker
  check="$(expected_check_for "$scenario")"
  if [[ -z "$check" ]]; then
    log "SKIP $scenario (no expected check mapping)"
    record_scenario_result "$scenario" "unknown" "skip" 0 0 0 "no_expected_check"
    return 0
  fi
  model_file="$(model_file_for "$scenario")"
  if [[ -z "$model_file" || ! -f "$model_file" ]]; then
    log "SKIP $scenario (model not found: ${model_file:-<unmapped>})"
    record_scenario_result "$scenario" "$check" "skip" 0 0 0 "model_missing"
    return 0
  fi
  trigger_script="$(trigger_script_for "$scenario")"
  if [[ ! -f "$trigger_script" ]]; then
    log "SKIP $scenario (trigger not found: $trigger_script)"
    record_scenario_result "$scenario" "$check" "skip" 0 0 0 "trigger_missing"
    return 0
  fi
  if scenario_excluded_on_this_platform "$scenario"; then
    log "SKIP $scenario (no install path / parent attribution on $(uname -s); platform-excluded)"
    record_scenario_result "$scenario" "$check" "skip" 0 0 0 "unsupported_platform"
    return 0
  fi

  local pfx
  pfx="$(file_prefix_for "$AGENT_TYPE")"
  prefix="$(evidence_prefix_for "$scenario")"
  marker="$(evidence_marker_for "$scenario")"
  marker="${marker//<PFX>/$pfx}"

  log "=== scenario: $scenario (check=$check, duration=${TRIGGER_DURATION}s, polls=${POLL_ATTEMPTS}) ==="
  log "  evidence must start with \"$prefix\" and contain \"$marker\""

  local started_at
  started_at=$(date +%s)

  run_cleanup
  divergence_reset

  local prepared
  prepared="$(prepare_model "$scenario" "$model_file")"
  if [[ ! -s "$prepared" ]]; then
    log "  FAIL: could not prepare model from $model_file"
    record_scenario_result "$scenario" "$check" "fail" 0 0 0 "model_prepare_failed"
    return 0
  fi

  local upsert_status
  upsert_status="$(upsert_model "$prepared")"
  if [[ "${upsert_status%%|*}" != "1" ]]; then
    log "  FAIL: model upsert rejected: ${upsert_status#*|}"
    record_scenario_result "$scenario" "$check" "fail" 0 0 0 "model_upsert_rejected"
    return 0
  fi
  log "  model planted: $prepared"
  start_engine

  local trigger_log="$OUTPUT_DIR_ABS/${scenario}.trigger.log"
  : >"$trigger_log"
  "$PYTHON" "$trigger_script" \
    --agent-type "$AGENT_TYPE" \
    --duration "$TRIGGER_DURATION" \
    >>"$trigger_log" 2>&1 &
  local trigger_pid=$!
  log "  trigger launched (pid=$trigger_pid): $trigger_script"

  sleep "$POST_WAIT"

  # A trigger that has already exited did not just finish early -- for this
  # scenario the most likely cause is a failed privileged install, which MUST
  # read as a loud failure rather than a skip or a silent degrade to /tmp.
  if ! kill -0 "$trigger_pid" 2>/dev/null; then
    local rc=0
    wait "$trigger_pid" || rc=$?
    local elapsed=$(( $(date +%s) - started_at ))
    if (( rc == 3 )); then
      log "  FAIL: trigger could not install into the system daemon location (rc=$rc)"
      log "  ---- trigger log ----"; sed -n '1,40p' "$trigger_log" >&2 || true
      record_scenario_result "$scenario" "$check" "fail" 0 0 "$elapsed" "system_install_failed"
    else
      log "  FAIL: trigger exited early (rc=$rc)"
      log "  ---- trigger log ----"; sed -n '1,40p' "$trigger_log" >&2 || true
      record_scenario_result "$scenario" "$check" "fail" 0 0 "$elapsed" "trigger_exited_early_rc${rc}"
    fi
    divergence_reset
    run_cleanup
    return 0
  fi

  local attempt=0 matched=0 det="NONE" final="NONE" total=0 cats="none" alertable=0
  while (( attempt < POLL_ATTEMPTS )); do
    attempt=$((attempt + 1))
    force_divergence_tick
    local status
    status="$(evaluate_verdict "$scenario" "$prefix" "$marker" "$check")"
    IFS='|' read -r matched det final total cats alertable <<<"$status"
    log "  attempt $attempt/$POLL_ATTEMPTS: deterministic=$det final=$final evidence=$total attributed_alertable=$alertable categories=$cats"
    if [[ "$matched" == "1" ]]; then
      break
    fi
    if ! kill -0 "$trigger_pid" 2>/dev/null; then
      log "  trigger exited before a verdict was reached"
      break
    fi
    sleep "$POLL_INTERVAL"
  done

  if kill -0 "$trigger_pid" 2>/dev/null; then
    kill -TERM "$trigger_pid" 2>/dev/null || true
    wait "$trigger_pid" 2>/dev/null || true
  fi

  local elapsed=$(( $(date +%s) - started_at ))
  local status_word extra severities
  if [[ "$matched" == "1" ]]; then
    status_word="pass"; extra=""; severities="HIGH:$alertable"
  else
    status_word="fail"; severities="none"
    if [[ "$det" == "DIVERGENCE" ]]; then
      # The engine fired but on something else: the verdict is not attributable
      # to this scenario's stimulus. Distinct from "never diverged".
      extra="divergence_without_attributed_evidence"
    elif [[ "$det" == "NONE" || "$det" == "ERROR" ]]; then
      extra="no_verdict_produced"
    else
      extra="deterministic_verdict_${det}"
    fi
  fi

  record_scenario_result "$scenario" "$check" "$status_word" "$total" "$alertable" \
    "$elapsed" "$extra" "$severities"
  log "  RESULT: $status_word  deterministic=$det attributed_alertable=$alertable evidence=$total elapsed=${elapsed}s"

  divergence_reset
  run_cleanup
  sleep "$COOLDOWN"
}

log "starting divergence detection suite: scenarios=${SCENARIOS_CSV} agent_type=$AGENT_TYPE"
log "triggers dir: $TRIGGERS_DIR"
log "models dir:   $MODELS_DIR"
log "output dir:   $OUTPUT_DIR_ABS (append=$APPEND)"
log "cli: $EDAMAME_CLI"

for scen in "${SCENARIOS[@]}"; do
  [[ -z "$scen" ]] && continue
  run_one_scenario "$scen"
done

# Leave the daemon without a planted model so a later job on the same runner
# does not inherit this suite's behavioral window.
divergence_reset

CORE_VERSION_RAW="$(call_rpc get_core_version 2>/dev/null || true)"
CORE_VERSION="$(echo "$CORE_VERSION_RAW" | tr -d '"' | awk '{print $NF}')"

NDJSON_PATH="$NDJSON" RESULT_JSON_PATH="$RESULT_JSON" CORE_VERSION="$CORE_VERSION" \
AGENT_TYPE="$AGENT_TYPE" TRIGGER_DURATION="$TRIGGER_DURATION" POST_WAIT="$POST_WAIT" \
POLL_ATTEMPTS="$POLL_ATTEMPTS" POLL_INTERVAL="$POLL_INTERVAL" \
  "$PYTHON" - <<'PY'
import json, os, platform, time

ndjson_path = os.environ["NDJSON_PATH"]
scenarios = []
if os.path.isfile(ndjson_path):
    with open(ndjson_path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                scenarios.append(json.loads(line))
            except Exception:
                pass

passed = sum(1 for s in scenarios if s.get("status") == "pass")
failed = sum(1 for s in scenarios if s.get("status") == "fail")
skipped = sum(1 for s in scenarios if s.get("status") == "skip")

summary = {
    "platform_system": platform.system(),
    "platform_release": platform.release(),
    "platform_machine": platform.machine(),
    "core_version": os.environ.get("CORE_VERSION") or "unknown",
    "agent_type": os.environ["AGENT_TYPE"],
    "scenarios": scenarios,
    "totals": {
        "passed": passed,
        "failed": failed,
        "skipped": skipped,
        "total": len(scenarios),
    },
    "trigger_duration_s": int(os.environ["TRIGGER_DURATION"]),
    "post_wait_s": int(os.environ["POST_WAIT"]),
    "poll_attempts": int(os.environ["POLL_ATTEMPTS"]),
    "poll_interval_s": int(os.environ["POLL_INTERVAL"]),
    "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
}
with open(os.environ["RESULT_JSON_PATH"], "w", encoding="utf-8") as fh:
    json.dump(summary, fh, indent=2)
print(json.dumps(summary["totals"]))
PY

log "divergence detection suite complete: $RESULT_JSON"
