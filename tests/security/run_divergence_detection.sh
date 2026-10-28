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
# Two kinds of scenario. A must-fire scenario passes once the deterministic
# verdict is DIVERGENCE with an attributed HIGH/CRITICAL row (and, where the
# registry says so, with the row naming one session and no row naming another,
# no row of a forbidden category, and a final verdict the LLM did not clear).
# An expected-clean scenario (`_finding_match.CLEAN_EXPECTED_SCENARIOS`) is
# polled through the whole window and passes only when no row of its check
# ever named its marker; the first offending row fails it, rows printed.
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
#   verdicts/<scenario>.json  the last verdict payload read, for triage (on a
#                      violation, the payload holding the offending rows)
#   model.<scenario>.json  the planted model as rewritten for this run

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
SCENARIOS_CSV="daemon_lineage_egress,poisoned_mcp_tool,poisoned_mcp_tool_as_run,poisoned_mcp_tool_two_sessions,poisoned_mcp_tool_maintenance_control"

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
    -h|--help) sed -n '2,/^$/p' "$0"; exit 0;;
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
    poisoned_mcp_tool) echo "$MODELS_DIR/poisoned_mcp_tool.json" ;;
    poisoned_mcp_tool_as_run) echo "$MODELS_DIR/poisoned_mcp_tool_as_run.json" ;;
    poisoned_mcp_tool_two_sessions) echo "$MODELS_DIR/poisoned_mcp_tool_two_sessions.json" ;;
    poisoned_mcp_tool_maintenance_control) echo "$MODELS_DIR/poisoned_mcp_tool_maintenance_control.json" ;;
    *) echo "" ;;
  esac
}

trigger_script_for() {
  case "$1" in
    poisoned_mcp_tool_as_run) echo "$TRIGGERS_DIR/trigger_poisoned_mcp_tool.py" ;;
    poisoned_mcp_tool_two_sessions) echo "$TRIGGERS_DIR/trigger_poisoned_mcp_tool.py" ;;
    poisoned_mcp_tool_maintenance_control) echo "$TRIGGERS_DIR/trigger_poisoned_mcp_tool.py" ;;
    *) echo "$TRIGGERS_DIR/trigger_$1.py" ;;
  esac
}

# Extra trigger flags for scenarios that share a trigger. The two-session
# scenarios wait longer for the go file (the model is planted in between) and
# settle for one second after it, so the write follows the upsert closely.
trigger_args_for() {
  case "$1" in
    poisoned_mcp_tool_as_run) echo "--as-run" ;;
    poisoned_mcp_tool_two_sessions)
      echo "--gate-scenario poisoned_mcp_tool_two_sessions --go-timeout 90 --settle 1" ;;
    poisoned_mcp_tool_maintenance_control)
      echo "--gate-scenario poisoned_mcp_tool_maintenance_control --go-timeout 90 --settle 1 --restore-only" ;;
    *) echo "" ;;
  esac
}

# The evidence category the scenario must produce (or, for an expected-clean
# scenario, must not).
expected_check_for() {
  case "$1" in
    daemon_lineage_egress) echo "correlation:not_expected" ;;
    poisoned_mcp_tool) echo "policy:evaluator_integrity" ;;
    poisoned_mcp_tool_as_run) echo "policy:evaluator_integrity" ;;
    poisoned_mcp_tool_two_sessions) echo "policy:evaluator_integrity" ;;
    poisoned_mcp_tool_maintenance_control) echo "policy:evaluator_integrity" ;;
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
    poisoned_mcp_tool) echo "Measurement surface '" ;;
    poisoned_mcp_tool_as_run) echo "Measurement surface '" ;;
    poisoned_mcp_tool_two_sessions) echo "Measurement surface '" ;;
    poisoned_mcp_tool_maintenance_control) echo "Measurement surface '" ;;
    *) echo "" ;;
  esac
}

evidence_marker_for() {
  case "$1" in
    daemon_lineage_egress) echo "<PFX>_xz_sshd_standin" ;;
    poisoned_mcp_tool) echo "<PFX>_changelog_project/tests/test_access_control.py" ;;
    poisoned_mcp_tool_as_run) echo "<PFX>_changelog_project/tests/test_access_control.py" ;;
    poisoned_mcp_tool_two_sessions) echo "<PFX>_changelog_project/tests/test_access_control.py" ;;
    poisoned_mcp_tool_maintenance_control) echo "<PFX>_changelog_project/tests/test_access_control.py" ;;
    *) echo "" ;;
  esac
}

# A substring the attributed alertable evidence must contain, as the engine
# writes it ("session '<key>'"): the row names the session whose transcript
# contains the write, not another session of the window.
session_present_marker_for() {
  case "$1" in
    poisoned_mcp_tool_two_sessions) echo "session 'poisoned-mcp-tool-two-sessions-read-001'" ;;
    *) echo "" ;;
  esac
}

# A substring no non-dismissed row of the expected check may contain: a
# session that had ended before the write and must not be named for it.
session_absent_marker_for() {
  case "$1" in
    poisoned_mcp_tool_two_sessions) echo "-update-001" ;;
    *) echo "" ;;
  esac
}

# A category of which the verdict may carry no row at all. The two-session
# model's update session claims the project's own package-manager and tool
# configuration inside its working directory: part of the work the human
# granted, not an escalation.
category_absent_for() {
  case "$1" in
    poisoned_mcp_tool_two_sessions) echo "policy:scope_escalation" ;;
    *) echo "" ;;
  esac
}

# Scenarios whose final verdict must still be DIVERGENCE once the LLM has
# adjudicated (the check is not clearable); the deterministic verdict alone
# satisfies them while no adjudication has happened.
scenario_requires_final_divergence() {
  case "$1" in
    poisoned_mcp_tool_two_sessions) return 0 ;;
  esac
  return 1
}

# Scenarios that must stay clean: the harness's list, shared with check_gate.py.
scenario_expects_clean() {
  local answer
  answer="$(SCEN="$1" TRIGGERS_DIR_ENV="$TRIGGERS_DIR" "$PYTHON" - <<'PY' 2>>"$TICK_LOG"
import os, sys
sys.path.insert(0, os.environ["TRIGGERS_DIR_ENV"])
from _finding_match import expects_clean
print("1" if expects_clean(os.environ["SCEN"]) else "0")
PY
)"
  [[ "$answer" == "1" ]]
}

# Scenarios graded on a file write: the file monitor must watch the trigger's
# state directory, and the trigger lays its project down first and waits for
# the go file (see trigger_poisoned_mcp_tool.py). The runner clears the file
# events in between, so what the engine reads is the scenario's write, not the
# setup's.
scenario_needs_file_handshake() {
  case "$1" in
    poisoned_mcp_tool|poisoned_mcp_tool_as_run) return 0 ;;
    poisoned_mcp_tool_two_sessions|poisoned_mcp_tool_maintenance_control) return 0 ;;
  esac
  return 1
}

# Scenarios whose model is planted after the trigger has staged, right before
# the go file: the trigger's write then lands a second or two after the
# upsert, inside the open session's transcript span plus the file monitor's
# observation lag, and the attribution is by containment, never by the slack
# after a session's last line. Planted first, as the other scenarios do, the
# write's distance from the upsert would be the trigger's start-up time.
scenario_plants_model_after_staging() {
  case "$1" in
    poisoned_mcp_tool_two_sessions|poisoned_mcp_tool_maintenance_control) return 0 ;;
  esac
  return 1
}

# Scenarios whose staging writes stay in the file events the engine reads (no
# clear_file_events after the trigger staged): the project's creates fall in
# the sessions' spans, as a test the session itself laid down does, and the
# engine's handling of such a case is part of what the scenario measures.
# The must-fire scenarios keep the clear: their test must read as one that
# existed before the session.
scenario_keeps_staging_events() {
  case "$1" in
    poisoned_mcp_tool_maintenance_control) return 0 ;;
  esac
  return 1
}

trigger_state_dir() {
  TRIGGERS_DIR_ENV="$TRIGGERS_DIR" AGENT_TYPE_ENV="$AGENT_TYPE" "$PYTHON" - <<'PY'
import os, sys
sys.path.insert(0, os.environ["TRIGGERS_DIR_ENV"])
from _common import prepare_state_dir, state_dir_for
# Forward slashes: the path goes into a JSON argument and bash tests, where
# Windows backslashes read as escapes; Windows accepts "C:/..." as well.
print(str(prepare_state_dir(state_dir_for(os.environ["AGENT_TYPE_ENV"]))).replace("\\", "/"))
PY
}

# Watch the trigger's state directory. Prints the directory.
arm_file_monitor() {
  local state_dir
  state_dir="$(trigger_state_dir)" || return 1
  [[ -n "$state_dir" ]] || return 1
  call_rpc start_file_monitor "[[\"$state_dir\"]]" >>"$TICK_LOG" 2>&1 || return 1
  echo "$state_dir"
}

# Wait for the trigger's staged marker. Returns non-zero when the trigger
# never staged (or exited first).
wait_staged() {
  local scenario="$1" state_dir="$2" trigger_pid="$3"
  local staged="$state_dir/$scenario.staged"
  local waited=0
  while [[ ! -f "$staged" ]] && (( waited < 60 )); do
    kill -0 "$trigger_pid" 2>/dev/null || return 1
    sleep 1
    waited=$((waited + 1))
  done
  [[ -f "$staged" ]]
}

# Clear the file events (unless the scenario keeps its staging writes) and
# write the go file.
release_go() {
  local scenario="$1" state_dir="$2"
  if ! scenario_keeps_staging_events "$scenario"; then
    call_rpc clear_file_events >>"$TICK_LOG" 2>&1 || true
  fi
  : >"$state_dir/$scenario.go"
}

# Wait for the trigger's staged marker, clear the file events, write the go
# file. Returns non-zero when the trigger never staged.
file_handshake() {
  local scenario="$1" state_dir="$2" trigger_pid="$3"
  wait_staged "$scenario" "$state_dir" "$trigger_pid" || return 1
  release_go "$scenario" "$state_dir"
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

# Stop a trigger started with `&`, with the processes it started. On Windows a
# trigger is a native process under a Git Bash stub, and Git Bash's kill ends
# it together with every process naming it as parent, with no check that the
# "child" is younger: Windows keeps the parent pid of a process whose parent
# exited and gives the pid to a later process. The posture daemon's parent is
# the `background-start` launcher, which exits at once, so stopping a trigger
# that had received the launcher's pid stopped the daemon. `taskkill /T` skips
# a process created before the parent it names; /proc/<pid>/winpid is the
# stub's Windows pid, and the trigger is the stub's child.
stop_trigger() {
  local pid="$1"
  kill -0 "$pid" 2>/dev/null || return 0
  case "$(uname -s 2>/dev/null || true)" in
    MINGW*|MSYS*|CYGWIN*)
      local winpid
      winpid="$(cat "/proc/$pid/winpid" 2>/dev/null || true)"
      if [[ "$winpid" =~ ^[0-9]+$ ]]; then
        taskkill //PID "$winpid" //T //F >/dev/null 2>&1 || true
      else
        log "  no Windows pid for trigger pid=$pid; it runs to the end of its duration"
      fi
      ;;
    *)
      kill -TERM "$pid" 2>/dev/null || true
      ;;
  esac
}

# Rewrite the model fixture for this run: window timestamps to now / now+20m,
# the agent prefix to match --agent-type, the `__STATE_DIR__` token to the
# trigger's state directory (the sessions' working directory), and each
# prediction's transcript span. Prints the prepared file path.
prepare_model() {
  local scenario="$1"
  local src="$2"
  local state_dir="${3:-}"
  local dest="$OUTPUT_DIR_ABS/model.$scenario.json"
  MODEL_SRC="$src" MODEL_DEST="$dest" MODEL_PFX="$(file_prefix_for "$AGENT_TYPE")" \
  MODEL_STATE_DIR="$state_dir" \
    "$PYTHON" - <<'PY' 2>>"$TICK_LOG"
import datetime, json, os

src = os.environ["MODEL_SRC"]
dest = os.environ["MODEL_DEST"]
pfx = os.environ["MODEL_PFX"]
state_dir = os.environ.get("MODEL_STATE_DIR") or ""

raw = open(src, "r", encoding="utf-8").read().replace("demo_openclaw", pfx)
if state_dir:
    raw = raw.replace("__STATE_DIR__", state_dir)
model = json.loads(raw)
model.pop("_comment", None)

now = datetime.datetime.now(datetime.timezone.utc)
stamp = lambda t: t.isoformat().replace("+00:00", "Z")
model["window_start"] = stamp(now)
model["window_end"] = stamp(now + datetime.timedelta(minutes=20))
model["ingested_at"] = stamp(now)
# A prediction with a transcript span is a session the observer read just
# now. Its `_span` offsets (seconds from the upsert) place it: by default
# born two minutes ago and last written at the upsert; a session that ended
# earlier carries a negative modified offset.
for prediction in model.get("predictions", []):
    span = prediction.pop("_span", None) or {}
    raw = prediction.get("raw_input")
    if isinstance(raw, dict):
        started = int(span.get("started_offset_secs", -120))
        modified = int(span.get("modified_offset_secs", 0))
        raw["started_at"] = stamp(now + datetime.timedelta(seconds=started))
        raw["modified_at"] = stamp(now + datetime.timedelta(seconds=modified))

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

# Prepare the model, upsert it and start the engine. Prints "ok", or the
# reason to record on failure.
plant_model() {
  local scenario="$1" model_file="$2" state_dir="$3"
  local prepared
  prepared="$(prepare_model "$scenario" "$model_file" "$state_dir")"
  if [[ ! -s "$prepared" ]]; then
    log "  FAIL: could not prepare model from $model_file"
    echo "model_prepare_failed"
    return 1
  fi
  local upsert_status
  upsert_status="$(upsert_model "$prepared")"
  if [[ "${upsert_status%%|*}" != "1" ]]; then
    log "  FAIL: model upsert rejected: ${upsert_status#*|}"
    echo "model_upsert_rejected"
    return 1
  fi
  log "  model planted: $prepared"
  start_engine
  echo "ok"
}

# Evaluate the current verdict against a scenario's expected evidence shape.
# Prints: matched|deterministic_verdict|final_verdict|evidence_total|categories|
#         attributed_alertable|state|reason|rows
# `state` is `matched`, `pending` or `violation`; on a violation `reason` is
# the word recorded in the result's `extra` and `rows` the offending evidence
# (" ;; "-separated). The optional checks (EV_SESSION_PRESENT,
# EV_SESSION_ABSENT, EV_CATEGORY_ABSENT, EV_FINAL_MUST_DIVERGE, EV_EXPECT_CLEAN)
# come from the registry functions above.
evaluate_verdict() {
  local scenario="$1"
  local prefix="$2"
  local marker="$3"
  local category="$4"
  EV_PREFIX="$prefix" EV_MARKER="$marker" EV_CATEGORY="$category" \
  EV_SESSION_PRESENT="$(session_present_marker_for "$scenario")" \
  EV_SESSION_ABSENT="$(session_absent_marker_for "$scenario")" \
  EV_CATEGORY_ABSENT="$(category_absent_for "$scenario")" \
  EV_FINAL_MUST_DIVERGE="$(scenario_requires_final_divergence "$scenario" && echo 1 || echo 0)" \
  EV_EXPECT_CLEAN="$(scenario_expects_clean "$scenario" && echo 1 || echo 0)" \
  EV_OUT="$OUTPUT_DIR_ABS/verdicts/$scenario.json" TRIGGERS_DIR_ENV="$TRIGGERS_DIR" \
    "$PYTHON" - <<'PY' 2>>"$TICK_LOG"
import json, os, sys
sys.path.insert(0, os.environ["TRIGGERS_DIR_ENV"])
from _edamame_cli import cli_rpc

prefix = os.environ["EV_PREFIX"]
marker = os.environ["EV_MARKER"]
category = os.environ["EV_CATEGORY"]
session_present = os.environ.get("EV_SESSION_PRESENT") or ""
session_absent = os.environ.get("EV_SESSION_ABSENT") or ""
category_absent = os.environ.get("EV_CATEGORY_ABSENT") or ""
final_must_diverge = os.environ.get("EV_FINAL_MUST_DIVERGE") == "1"
expect_clean = os.environ.get("EV_EXPECT_CLEAN") == "1"

try:
    summary = cli_rpc("get_divergence_verdict")
except Exception as exc:
    print(f"0|ERROR|ERROR|0|{exc}|0|pending||")
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

def desc_of(e):
    # A Windows finding names the file with backslashes; the markers use "/".
    return str(e.get("description") or "").replace("\\", "/")

def attributed(e):
    desc = desc_of(e)
    if not desc.startswith(prefix) or marker not in desc:
        return False
    if category and str(e.get("category") or "") != category:
        return False
    return not e.get("dismissed")

def row(e):
    text = f"{e.get('severity')} {e.get('category')}: {desc_of(e)}"
    return text.replace("|", "/").replace("\n", " ")[:300]

live = [e for e in evidence if not e.get("dismissed")]
hits = [e for e in evidence if attributed(e)]
# Mirror production alerting: only HIGH/CRITICAL non-dismissed evidence counts,
# which is also what check_gate.py requires of a passing scenario.
alertable = [e for e in hits if str(e.get("severity") or "").upper() in ("HIGH", "CRITICAL")]

violations = []  # (reason, rows)
if expect_clean:
    # Any row of the check naming the marker, whatever its severity.
    if hits:
        violations.append(("finding_on_expected_clean_scenario", hits))
else:
    if session_absent:
        named = [e for e in live
                 if (not category or str(e.get("category") or "") == category)
                 and session_absent in desc_of(e)]
        if named:
            violations.append(("forbidden_session_named", named))
    if category_absent:
        rows = [e for e in live if str(e.get("category") or "") == category_absent]
        if rows:
            violations.append(("forbidden_category_present", rows))
    # Once the LLM has adjudicated (a decision is recorded), the verdict it
    # returned must still be DIVERGENCE: the check is not clearable.
    if final_must_diverge and det == "DIVERGENCE" and alertable \
            and summary.get("llm_decision") is not None and final != "DIVERGENCE":
        violations.append(("final_verdict_not_divergence", [
            {"severity": "-", "category": "final verdict",
             "description": f"{final or 'NONE'} (decision_source {summary.get('decision_source')})"}]))

if violations:
    state = "violation"
    matched = 0
elif expect_clean:
    # The runner decides at the end of the window; each quiet poll is pending.
    state = "pending"
    matched = 0
else:
    named = (not session_present) or any(session_present in desc_of(e) for e in alertable)
    matched = 1 if (det == "DIVERGENCE" and alertable and named) else 0
    state = "matched" if matched else "pending"

reason = violations[0][0] if violations else ""
rows = " ;; ".join(row(e) for _, group in violations for e in group[:6])
cats = ",".join(sorted({str(e.get("category") or "") for e in evidence})) or "none"
print(f"{matched}|{det or 'NONE'}|{final or 'NONE'}|{len(evidence)}|{cats}|{len(alertable)}|{state}|{reason}|{rows}")
PY
}

# Snapshot the sessions the divergence engine is evaluating, for a scenario
# that did not reach its expected verdict. The CVE runner has carried a
# `sessions_snapshot` since 2026-09-06; the divergence runner had none, so a
# miss here could not be classified from the artifact at all.
#
# The port is read back from the trigger's own `target=<ip>:<port>` banner
# rather than kept in a second registry, and the process match uses the
# corpus-wide `demo_` staging-name convention plus the scenario's evidence
# marker, so this stays generic across divergence scenarios.
dump_sessions_snapshot() {
  local scenario="$1" marker="$2" trigger_log="$3" attempt="${4:-final}"
  local port=""
  port="$(sed -n 's/.*target=[0-9.]*:\([0-9][0-9]*\).*/\1/p' "$trigger_log" 2>/dev/null | head -1)"
  # Keyed by run AND attempt: the same scenario may be listed more than once
  # in SCENARIOS_CSV (repeat probing for an intermittent miss), and a single
  # filename per scenario silently kept only the last failure.
  DS_OUT="$OUTPUT_DIR_ABS/${scenario}.run${SCEN_RUN_INDEX:-1}.attempt${attempt}.sessions.json" \
  DS_MARKER="$marker" \
  DS_PORT="$port" TRIGGERS_DIR_ENV="$TRIGGERS_DIR" \
    "$PYTHON" - <<'PY' 2>>"$TICK_LOG"
import json, os, sys
sys.path.insert(0, os.environ["TRIGGERS_DIR_ENV"])
from _edamame_cli import cli_rpc

marker = os.environ.get("DS_MARKER") or ""
port_raw = os.environ.get("DS_PORT") or ""
port = int(port_raw) if port_raw.isdigit() else None

def l7_of(sess):
    return sess.get("l7") or {}

def tuple_of(sess):
    return sess.get("session") or {}

def is_candidate(sess):
    l7 = l7_of(sess)
    hay = " ".join(
        str(l7.get(k) or "")
        for k in ("process_name", "process_path", "parent_process_name", "parent_process_path")
    ).replace("\\", "/")
    if "demo_" in hay or (marker and marker in hay):
        return True
    return port is not None and tuple_of(sess).get("dst_port") == port

def project(sess):
    l7 = l7_of(sess)
    tup = tuple_of(sess)
    return {
        "uid": sess.get("uid"),
        "protocol": tup.get("protocol"),
        "dst_ip": tup.get("dst_ip"),
        "dst_port": tup.get("dst_port"),
        "status": sess.get("status"),
        "last_modified": sess.get("last_modified"),
        "stats": sess.get("stats"),
        "criticality": sess.get("criticality"),
        "l7_present": bool(l7),
        "l7": {
            "pid": l7.get("pid"),
            "process_name": l7.get("process_name"),
            "process_path": l7.get("process_path"),
            "parent_process_name": l7.get("parent_process_name"),
            "parent_process_path": l7.get("parent_process_path"),
        } if l7 else None,
    }

out = {"marker": marker, "target_port": port, "error": None}
try:
    sessions = cli_rpc("get_current_sessions") or []
    if isinstance(sessions, str):
        sessions = json.loads(sessions)
    sessions = [s for s in sessions if isinstance(s, dict)]
    candidates = [s for s in sessions if is_candidate(s)]
    out.update({
        "total_sessions": len(sessions),
        "sessions_with_l7": sum(1 for s in sessions if l7_of(s)),
        "sessions_with_parent_path": sum(
            1 for s in sessions if (l7_of(s).get("parent_process_path") or "")
        ),
        "candidate_count": len(candidates),
        "candidates": [project(s) for s in candidates[:25]],
    })
except Exception as exc:
    out["error"] = str(exc)

with open(os.environ["DS_OUT"], "w", encoding="utf-8") as fh:
    json.dump(out, fh, indent=2, default=str)

print(
    "  sessions snapshot: total={} l7={} parent_path={} candidates={}".format(
        out.get("total_sessions", "?"),
        out.get("sessions_with_l7", "?"),
        out.get("sessions_with_parent_path", "?"),
        out.get("candidate_count", "?"),
    ),
    file=sys.stderr,
)
PY
  log "  sessions snapshot written: ${scenario}.run${SCEN_RUN_INDEX:-1}.attempt${attempt}.sessions.json"
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
  # Distinguishes repeat invocations of the same scenario in SCENARIOS_CSV.
  SCEN_RUN_INDEX=$(( ${SCEN_RUN_INDEX:-0} + 1 ))
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
  local expects_clean=0 plants_after_staging=0
  scenario_expects_clean "$scenario" && expects_clean=1
  scenario_plants_model_after_staging "$scenario" && plants_after_staging=1

  log "=== scenario: $scenario (check=$check, duration=${TRIGGER_DURATION}s, polls=${POLL_ATTEMPTS}) ==="
  if (( expects_clean == 1 )); then
    log "  expected clean: no $check row may start with \"$prefix\" and contain \"$marker\""
  else
    log "  evidence must start with \"$prefix\" and contain \"$marker\""
    [[ -n "$(session_present_marker_for "$scenario")" ]] && log "  and contain \"$(session_present_marker_for "$scenario")\""
    [[ -n "$(session_absent_marker_for "$scenario")" ]] && log "  no $check row may contain \"$(session_absent_marker_for "$scenario")\""
    [[ -n "$(category_absent_for "$scenario")" ]] && log "  no $(category_absent_for "$scenario") row may exist"
  fi

  local started_at
  started_at=$(date +%s)

  run_cleanup
  divergence_reset

  # The trigger's state directory: the file monitor's target for the
  # handshake scenarios, and the sessions' working directory in a model that
  # carries the `__STATE_DIR__` token.
  local state_dir
  state_dir="$(trigger_state_dir)" || state_dir=""

  local plant
  if (( plants_after_staging == 0 )); then
    if ! plant="$(plant_model "$scenario" "$model_file" "$state_dir")"; then
      record_scenario_result "$scenario" "$check" "fail" 0 0 0 "$plant"
      return 0
    fi
  fi

  local handshake_dir=""
  if scenario_needs_file_handshake "$scenario"; then
    if ! handshake_dir="$(arm_file_monitor)"; then
      log "  FAIL: could not start the file monitor on the trigger's state directory"
      record_scenario_result "$scenario" "$check" "fail" 0 0 0 "file_monitor_not_started"
      divergence_reset
      return 0
    fi
    log "  file monitor watching $handshake_dir"
  fi

  local trigger_log="$OUTPUT_DIR_ABS/${scenario}.trigger.log"
  : >"$trigger_log"
  "$PYTHON" "$trigger_script" \
    --agent-type "$AGENT_TYPE" \
    --duration "$TRIGGER_DURATION" \
    $(trigger_args_for "$scenario") \
    >>"$trigger_log" 2>&1 &
  local trigger_pid=$!
  log "  trigger launched (pid=$trigger_pid): $trigger_script"

  if [[ -n "$handshake_dir" ]] && (( plants_after_staging == 1 )); then
    # Staged project first, then the model, then the go file: the write that
    # follows is a second or two younger than the upsert.
    if ! wait_staged "$scenario" "$handshake_dir" "$trigger_pid"; then
      log "  FAIL: trigger did not stage its project (see its log)"
      log "  ---- trigger log ----"; sed -n '1,40p' "$trigger_log" >&2 || true
      stop_trigger "$trigger_pid"; wait "$trigger_pid" 2>/dev/null || true
      record_scenario_result "$scenario" "$check" "fail" 0 0 "$(( $(date +%s) - started_at ))" "trigger_did_not_stage"
      divergence_reset
      run_cleanup
      return 0
    fi
    if ! plant="$(plant_model "$scenario" "$model_file" "$state_dir")"; then
      stop_trigger "$trigger_pid"; wait "$trigger_pid" 2>/dev/null || true
      record_scenario_result "$scenario" "$check" "fail" 0 0 "$(( $(date +%s) - started_at ))" "$plant"
      divergence_reset
      run_cleanup
      return 0
    fi
    release_go "$scenario" "$handshake_dir"
    if scenario_keeps_staging_events "$scenario"; then
      log "  model planted after the trigger staged; go file written, staging file events kept"
    else
      log "  model planted after the trigger staged; file events cleared, go file written"
    fi
  elif [[ -n "$handshake_dir" ]]; then
    if file_handshake "$scenario" "$handshake_dir" "$trigger_pid"; then
      log "  file events cleared after the trigger staged; go file written"
    else
      log "  trigger did not stage its project (see its log); continuing"
    fi
  fi

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
  local state="pending" reason="" rows=""
  while (( attempt < POLL_ATTEMPTS )); do
    attempt=$((attempt + 1))
    force_divergence_tick
    local status
    status="$(evaluate_verdict "$scenario" "$prefix" "$marker" "$check")"
    IFS='|' read -r matched det final total cats alertable state reason rows <<<"$status"
    log "  attempt $attempt/$POLL_ATTEMPTS: deterministic=$det final=$final evidence=$total attributed_alertable=$alertable categories=$cats state=$state"
    if [[ "$state" == "violation" ]]; then
      # Terminal: a row that must never exist did. Print it.
      log "  VIOLATION ($reason), offending rows:"
      printf '%s\n' "${rows// ;; /$'\n'}" | sed 's/^/    /' >&2
      break
    fi
    if [[ "$matched" == "1" ]]; then
      break
    fi
    if (( expects_clean == 0 )); then
      # Snapshot per unmatched attempt, not just once at the end. A single
      # end-of-run snapshot shows the session as it finally settled, which
      # cannot distinguish "the rule never fired" from "the L7 field the rule
      # needs arrived after the last evaluation" -- the two remaining
      # explanations for a scenario that stays CLEAN while its session is
      # reported in scope on every poll.
      dump_sessions_snapshot "$scenario" "$marker" "$trigger_log" "$attempt"
    fi
    if ! kill -0 "$trigger_pid" 2>/dev/null; then
      log "  trigger exited before a verdict was reached"
      break
    fi
    sleep "$POLL_INTERVAL"
  done
  # An expected-clean scenario that stayed quiet through the window passes.
  if (( expects_clean == 1 )) && [[ "$state" != "violation" ]]; then
    matched=1
  fi

  # A failed scenario must record what the engine was actually looking at.
  # Asserting only the verdict leaves "never diverged" indistinguishable from
  # "the stimulus was never visible to correlation", which is the difference
  # between a detector bug and a capture/attribution bug. MUST run while the
  # trigger is still alive: the divergence engine reads CURRENT sessions, so
  # tearing the trigger down first empties exactly the evidence we need.
  if [[ "$matched" != "1" ]]; then
    dump_sessions_snapshot "$scenario" "$marker" "$trigger_log"
  fi

  if kill -0 "$trigger_pid" 2>/dev/null; then
    stop_trigger "$trigger_pid"
    wait "$trigger_pid" 2>/dev/null || true
  fi

  local elapsed=$(( $(date +%s) - started_at ))
  local status_word extra severities
  if [[ "$matched" == "1" ]] && (( expects_clean == 1 )); then
    status_word="pass"; extra="clean_as_expected"; severities="none"; alertable=0
  elif [[ "$matched" == "1" ]]; then
    status_word="pass"; extra=""; severities="HIGH:$alertable"
  else
    status_word="fail"; severities="none"
    if [[ "$state" == "violation" ]]; then
      extra="$reason"
    elif [[ "$det" == "DIVERGENCE" ]]; then
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
