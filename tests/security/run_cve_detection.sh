#!/usr/bin/env bash
# Run a suite of CVE detection scenarios against a running edamame_posture
# daemon and record detection outcomes as JSON.
#
# The trigger scripts live in agent_security/tests/e2e/triggers/ and are
# downloaded at runtime from the agent_security repo (public). This script
# orchestrates: cleanup, trigger launch, detector tick, detection verification
# using edamame_cli RPCs, and JSON result recording.
#
# Usage:
#   run_cve_detection.sh \
#     --triggers-dir <dir> \
#     --output-dir <dir> \
#     [--trigger-duration <seconds>]     # default: 90
#     [--post-wait <seconds>]            # default: 25
#     [--cooldown <seconds>]             # default: 5
#     [--poll-attempts <count>]          # default: 6
#     [--poll-interval <seconds>]        # default: 15
#     [--agent-type <string>]            # default: edamame_posture
#     [--scenarios <comma,separated>]    # default: all nine CVE scenarios
#
# Environment:
#   EDAMAME_CLI        path to edamame_cli binary (mandatory)
#   PYTHON             path to python3 (default: python3)
#
# Outputs (under --output-dir):
#   results.json       full result object: platform, scenarios[], totals
#   results.ndjson     one JSON per scenario, for streaming consumers
#   detector_ticks.log stdout/stderr from forced detector ticks

set -Euo pipefail

log() { printf '[cve] %s\n' "$*" >&2; }
die() { log "ERROR: $*"; exit 1; }

TRIGGERS_DIR=""
OUTPUT_DIR=""
TRIGGER_DURATION=180
POST_WAIT=5
COOLDOWN=8
POLL_ATTEMPTS=24
POLL_INTERVAL=6
READINESS_WAIT=60
AGENT_TYPE="openclaw"
SCENARIOS_CSV="blacklist_comm,cve_token_exfil,cve_sandbox_escape,memory_poisoning,credential_sprawl,tool_poisoning_effects,supply_chain_exfil,npm_rat_beacon,file_events"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --triggers-dir)      TRIGGERS_DIR="$2"; shift 2;;
    --output-dir)        OUTPUT_DIR="$2"; shift 2;;
    --trigger-duration)  TRIGGER_DURATION="$2"; shift 2;;
    --post-wait)         POST_WAIT="$2"; shift 2;;
    --cooldown)          COOLDOWN="$2"; shift 2;;
    --poll-attempts)     POLL_ATTEMPTS="$2"; shift 2;;
    --poll-interval)     POLL_INTERVAL="$2"; shift 2;;
    --readiness-wait)    READINESS_WAIT="$2"; shift 2;;
    --agent-type)        AGENT_TYPE="$2"; shift 2;;
    --scenarios)         SCENARIOS_CSV="$2"; shift 2;;
    -h|--help) sed -n '2,30p' "$0"; exit 0;;
    *) die "unknown flag: $1";;
  esac
done

[[ -n "$TRIGGERS_DIR" ]] || die "--triggers-dir required"
[[ -n "$OUTPUT_DIR"   ]] || die "--output-dir required"
[[ -d "$TRIGGERS_DIR" ]] || die "triggers dir not found: $TRIGGERS_DIR"
[[ -n "${EDAMAME_CLI:-}" && -x "${EDAMAME_CLI:-}" ]] || die "EDAMAME_CLI must point to an executable edamame_cli"

PYTHON="${PYTHON:-python3}"
mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR_ABS=$(cd "$OUTPUT_DIR" && pwd)
case "$(uname -s 2>/dev/null || true)" in
  MINGW*|MSYS*|CYGWIN*)
    if command -v cygpath >/dev/null 2>&1; then
      OUTPUT_DIR_ABS="$(cygpath -m "$OUTPUT_DIR_ABS")"
    fi
    ;;
esac
NDJSON="$OUTPUT_DIR_ABS/results.ndjson"
TICK_LOG="$OUTPUT_DIR_ABS/detector_ticks.log"
RESULT_JSON="$OUTPUT_DIR_ABS/results.json"
: >"$NDJSON"
: >"$TICK_LOG"

IFS=',' read -r -a SCENARIOS <<<"$SCENARIOS_CSV"

expected_check_for() {
  case "$1" in
    blacklist_comm)         echo "blacklisted_sessions" ;;
    cve_token_exfil)        echo "token_exfiltration" ;;
    cve_sandbox_escape)     echo "sandbox_exploitation" ;;
    memory_poisoning)       echo "token_exfiltration" ;;
    credential_sprawl)      echo "token_exfiltration" ;;
    tool_poisoning_effects) echo "token_exfiltration" ;;
    supply_chain_exfil)     echo "credential_harvest" ;;
    npm_rat_beacon)         echo "token_exfiltration" ;;
    file_events)            echo "file_system_tampering" ;;
    *) echo "" ;;
  esac
}

scenario_markers_json() {
  case "$1" in
    cve_token_exfil)        echo '["_exfil_token", "_exfil"]' ;;
    memory_poisoning)       echo '["_memory_poison", "memory_poisoned.md"]' ;;
    credential_sprawl)      echo '["_sprawl_key", "_sprawl", "demo_openclaw_sprawl"]' ;;
    tool_poisoning_effects) echo '["_tool_poison", "demo_openclaw_tool_poison"]' ;;
    file_events)            echo '["_fim_test", "_fim_suspicious"]' ;;
    *) echo '[]' ;;
  esac
}

scenario_ports_json() {
  case "$1" in
    cve_token_exfil)        echo '[63169]' ;;
    credential_sprawl)      echo '[63171]' ;;
    tool_poisoning_effects) echo '[63172]' ;;
    *) echo '[]' ;;
  esac
}

call_rpc() {
  "$EDAMAME_CLI" rpc "$@" 2>>"$TICK_LOG"
}

force_vuln_tick() {
  log "  forcing vulnerability detector tick"
  call_rpc debug_run_vulnerability_detector_tick >>"$TICK_LOG" 2>&1 || true
}

clear_vuln_history() {
  call_rpc clear_vulnerability_history >>"$TICK_LOG" 2>&1 || true
}

# Poll until L7 attribution and anomaly detection have enough evidence for the
# detector to fire. Returns early as soon as signal is visible or the trigger
# has already produced a finding. Mirrors agent_security's wait_for_detection_readiness.
wait_for_readiness() {
  local scenario="$1"
  local check="$2"
  local max_wait="$3"
  local interval=6
  local waited=0
  [[ "$max_wait" -le 0 ]] && return 0

  while (( waited < max_wait )); do
    local triple
    triple="$(TRIGGERS_DIR_ENV="$TRIGGERS_DIR" count_finding_for_scenario "$scenario" "$check" 2>/dev/null)"
    local total=${triple%%|*}
    if [[ "$total" =~ ^[0-9]+$ ]] && (( total > 0 )); then
      log "  readiness: finding already present after ${waited}s (total=$total)"
      return 0
    fi

    local status
    case "$check" in
      token_exfiltration)
        status="$(TRIGGERS_DIR_ENV="$TRIGGERS_DIR" token_exfil_readiness_status)"
        ;;
      credential_harvest)
        status="$(TRIGGERS_DIR_ENV="$TRIGGERS_DIR" credential_harvest_readiness_status)"
        ;;
      sandbox_exploitation)
        status="$(TRIGGERS_DIR_ENV="$TRIGGERS_DIR" sandbox_readiness_status)"
        ;;
      file_system_tampering)
        status="$(TRIGGERS_DIR_ENV="$TRIGGERS_DIR" fim_readiness_status)"
        ;;
      *)
        return 0
        ;;
    esac
    local ready="${status%%|*}"
    local detail="${status#*|}"
    if [[ "$ready" == "1" ]]; then
      log "  readiness reached for $scenario ($check): $detail"
      return 0
    fi
    log "  waiting for readiness ($check): $detail (${waited}/${max_wait}s)"
    local remaining=$((max_wait - waited))
    local sleep_for=$interval
    (( remaining < interval )) && sleep_for=$remaining
    (( sleep_for <= 0 )) && break
    sleep "$sleep_for"
    waited=$((waited + sleep_for))
  done
  log "  readiness timeout for $scenario ($check) after ${max_wait}s; proceeding"
  return 1
}

token_exfil_readiness_status() {
  "$PYTHON" - <<'PY' 2>>"$TICK_LOG"
import os, sys
sys.path.insert(0, os.environ["TRIGGERS_DIR_ENV"])
from _edamame_cli import cli_rpc
try:
    sessions = cli_rpc('get_anomalous_sessions') or []
except Exception:
    sessions = []
active = [s for s in sessions if isinstance(s, dict) and (s.get('status') or {}).get('active')]
with_of = [s for s in active if len(((s.get('l7') or {}).get('open_files') or [])) > 0]
ready = 1 if (len(active) > 0 and len(with_of) > 0) else 0
print(f"{ready}|active_anomalous={len(active)} with_open_files={len(with_of)}")
PY
}

credential_harvest_readiness_status() {
  "$PYTHON" - <<'PY' 2>>"$TICK_LOG"
import os, sys
sys.path.insert(0, os.environ["TRIGGERS_DIR_ENV"])
from _edamame_cli import cli_rpc

LABEL_MARKERS = {
    'ssh': ['/.ssh/', '_supply_chain_key', '_sc_ssh'],
    'aws': ['/.aws/', '_sc_credentials'],
    'gcp': ['/gcloud/', '_sc_adc.json'],
    'git': ['git-credentials', '/.git-credentials'],
    'kube': ['/.kube/', '_sc_config'],
    'docker': ['/.docker/', '_sc_config.json'],
    'vault': ['vault-token'],
    'env': ['/.env_', '_supply_chain'],
    'crypto': ['/.bitcoin/', '/.ethereum/', '/solana/'],
}

def classify(paths):
    labels = set()
    for raw in paths or []:
        p = str(raw).lower()
        for label, needles in LABEL_MARKERS.items():
            if any(needle in p for needle in needles):
                labels.add(label)
    return labels

try:
    sessions = cli_rpc('get_current_sessions') or []
except Exception:
    sessions = []
active = [s for s in sessions if isinstance(s, dict) and (s.get('status') or {}).get('active')]
candidates = 0
max_labels = 0
for s in active:
    l7 = s.get('l7') or {}
    of = l7.get('open_files') or []
    labels = classify(of)
    if len(labels) >= 3:
        candidates += 1
    if len(labels) > max_labels:
        max_labels = len(labels)
ready = 1 if candidates > 0 else 0
print(f"{ready}|active={len(active)} candidates={candidates} max_labels={max_labels}")
PY
}

sandbox_readiness_status() {
  "$PYTHON" - <<'PY' 2>>"$TICK_LOG"
import os, sys
sys.path.insert(0, os.environ["TRIGGERS_DIR_ENV"])
from _edamame_cli import cli_rpc
try:
    sessions = cli_rpc('get_current_sessions') or []
except Exception:
    sessions = []
active = 0
candidates = 0
for s in sessions:
    if not isinstance(s, dict):
        continue
    if not (s.get('status') or {}).get('active'):
        continue
    active += 1
    l7 = s.get('l7') or {}
    paths = [str(l7.get('parent_process_path') or ''), str(l7.get('parent_script_path') or ''), str(l7.get('process_path') or '')]
    spawned = bool(l7.get('spawned_from_tmp'))
    if spawned or any('/tmp/' in p for p in paths if p):
        candidates += 1
ready = 1 if candidates > 0 else 0
print(f"{ready}|active={active} suspicious={candidates}")
PY
}

fim_readiness_status() {
  "$PYTHON" - <<'PY' 2>>"$TICK_LOG"
import os, sys
sys.path.insert(0, os.environ["TRIGGERS_DIR_ENV"])
from _edamame_cli import cli_rpc
try:
    events = cli_rpc('get_file_events', '{"sensitive_only": false}') or []
except Exception:
    events = []
sensitive = sum(1 for e in events if isinstance(e, dict) and e.get('is_sensitive'))
ready = 1 if sensitive > 0 else 0
print(f"{ready}|total={len(events) if isinstance(events, list) else 0} sensitive={sensitive}")
PY
}

fim_watch_paths_json() {
  "$PYTHON" - <<'PY'
import json
import os
import tempfile
from pathlib import Path

home = Path.home()
candidates = [
    home / ".ssh",
    home / ".aws",
    home / ".gnupg",
    home / ".kube",
    home / ".docker",
]
for c in candidates:
    try:
        c.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass

paths = [str(c) for c in candidates if c.exists()]
paths.append(str(home))

tmp = Path(tempfile.gettempdir())
try:
    tmp.mkdir(parents=True, exist_ok=True)
except Exception:
    pass
if tmp.exists():
    paths.append(str(tmp))

if os.name == "nt":
    for env_var in ("TEMP", "TMP"):
        val = os.environ.get(env_var)
        if val:
            p = Path(val)
            if p.exists() and str(p) not in paths:
                paths.append(str(p))

seen = []
for p in paths:
    if p not in seen:
        seen.append(p)
print(json.dumps(seen))
PY
}

prepare_scenario_state() {
  local scenario="$1"
  local check="$2"
  if [[ "$check" == "file_system_tampering" ]]; then
    local watch_json
    watch_json="$(fim_watch_paths_json)"
    log "  FIM watch paths: $watch_json"
    call_rpc clear_file_events >>"$TICK_LOG" 2>&1 || true
    call_rpc start_file_monitor "[$watch_json]" >>"$TICK_LOG" 2>&1 || true
    log "  FIM started for $scenario (args=[$watch_json])"
  fi
}

run_cleanup() {
  local cleanup_path="$TRIGGERS_DIR/cleanup.py"
  [[ -f "$cleanup_path" ]] || return 0
  log "  running trigger cleanup"
  "$PYTHON" "$cleanup_path" --agent-type "$AGENT_TYPE" >>"$TICK_LOG" 2>&1 || true
}

count_finding_for_scenario() {
  local scenario="$1"
  local check="$2"
  MARKERS_JSON="$(scenario_markers_json "$scenario")" \
  PORTS_JSON="$(scenario_ports_json "$scenario")" \
  CHECK="$check" \
  TRIGGERS_DIR_ENV="$TRIGGERS_DIR" \
  "$PYTHON" - <<'PY'
import json, os, sys
sys.path.insert(0, os.environ["TRIGGERS_DIR_ENV"])
from _edamame_cli import cli_rpc

check = os.environ["CHECK"]
markers = [m.lower() for m in json.loads(os.environ.get("MARKERS_JSON", "[]"))]
ports = {int(p) for p in json.loads(os.environ.get("PORTS_JSON", "[]"))}


def matches(finding: dict) -> bool:
    if not isinstance(finding, dict) or finding.get("check") != check:
        return False
    if not markers and not ports:
        return True
    parts = []
    parts.extend(str(p) for p in (finding.get("open_files") or []))
    desc = finding.get("description")
    if desc:
        parts.append(str(desc))
    joined = "\n".join(parts).lower()
    if markers and any(m in joined for m in markers):
        return True
    port = finding.get("destination_port")
    try:
        port_int = int(port) if port is not None else None
    except Exception:
        port_int = None
    return port_int in ports


def _findings(report):
    if isinstance(report, dict):
        return report.get("findings") or []
    return []


current = 0
history = 0

try:
    report = cli_rpc("get_vulnerability_findings")
    current = sum(1 for f in _findings(report) if matches(f))
except Exception as exc:
    print(f"__ERR__ current: {exc}", file=sys.stderr)

try:
    hist = cli_rpc("get_vulnerability_history", '{"limit": 50}')
    if isinstance(hist, list):
        for entry in hist:
            history += sum(1 for f in (entry.get("findings") or []) if matches(f))
except Exception as exc:
    print(f"__ERR__ history: {exc}", file=sys.stderr)

print(f"{current + history}|{current}|{history}")
PY
}

count_blacklisted_sessions() {
  "$PYTHON" - <<'PY' 2>>"$TICK_LOG"
import os, sys
sys.path.insert(0, os.environ["TRIGGERS_DIR_ENV"])
from _edamame_cli import cli_rpc

target_ips = {"5.188.11.1", "45.95.232.1", "2.57.122.1"}
try:
    sessions = cli_rpc("get_blacklisted_sessions")
except Exception:
    print(0)
    raise SystemExit(0)
if not isinstance(sessions, list):
    print(0)
    raise SystemExit(0)
count = 0
for s in sessions:
    if not isinstance(s, dict):
        continue
    sess = s.get("session") or {}
    status = s.get("status") or {}
    if sess.get("dst_ip") in target_ips and status.get("active"):
        count += 1
print(count)
PY
}

record_scenario_result() {
  local scenario="$1"
  local check="$2"
  local status="$3"
  local total="$4"
  local current="$5"
  local history="$6"
  local elapsed="$7"
  local extra="$8"
  "$PYTHON" - <<PY | tee -a "$NDJSON" >/dev/null
import json, sys, time
rec = {
    "scenario": "$scenario",
    "expected_check": "$check",
    "status": "$status",
    "finding_total": int("$total"),
    "finding_current": int("$current"),
    "finding_history": int("$history"),
    "elapsed_s": float("$elapsed"),
    "agent_type": "$AGENT_TYPE",
    "trigger_duration_s": int("$TRIGGER_DURATION"),
    "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "extra": "$extra",
}
print(json.dumps(rec))
PY
}

run_one_scenario() {
  local scenario="$1"
  local check
  check="$(expected_check_for "$scenario")"
  if [[ -z "$check" ]]; then
    log "SKIP $scenario (no expected check mapping)"
    record_scenario_result "$scenario" "unknown" "skip" 0 0 0 0 "no_expected_check"
    return 0
  fi
  local trigger_script="$TRIGGERS_DIR/trigger_${scenario}.py"
  if [[ ! -f "$trigger_script" ]]; then
    log "SKIP $scenario (trigger not found: $trigger_script)"
    record_scenario_result "$scenario" "$check" "skip" 0 0 0 0 "trigger_missing"
    return 0
  fi

  log "=== scenario: $scenario (check=$check, duration=${TRIGGER_DURATION}s) ==="
  clear_vuln_history
  run_cleanup
  prepare_scenario_state "$scenario" "$check"

  local start_epoch
  start_epoch=$(date +%s)
  TRIGGERS_DIR_ENV="$TRIGGERS_DIR" "$PYTHON" "$trigger_script" \
    --agent-type "$AGENT_TYPE" \
    --duration "$TRIGGER_DURATION" \
    >"$OUTPUT_DIR_ABS/${scenario}.trigger.log" 2>&1 &
  local trigger_pid=$!
  log "  trigger started pid=$trigger_pid"

  if (( POST_WAIT > 0 )); then
    log "  initial settle ${POST_WAIT}s for capture + L7 attribution"
    sleep "$POST_WAIT"
  fi

  wait_for_readiness "$scenario" "$check" "$READINESS_WAIT" || true
  force_vuln_tick
  sleep 2

  local attempt=0
  local detected=0
  local total=0
  local current=0
  local history=0
  while (( attempt < POLL_ATTEMPTS )); do
    attempt=$((attempt + 1))
    local trigger_state="alive"
    if ! kill -0 "$trigger_pid" 2>/dev/null; then
      trigger_state="ended"
    fi
    log "  verify attempt $attempt/$POLL_ATTEMPTS (trigger=$trigger_state)"
    force_vuln_tick
    sleep 2
    if [[ "$check" == "blacklisted_sessions" ]]; then
      local bl_count
      bl_count="$(TRIGGERS_DIR_ENV="$TRIGGERS_DIR" count_blacklisted_sessions || echo 0)"
      bl_count=$(echo "$bl_count" | tr -dc '0-9')
      [[ -z "$bl_count" ]] && bl_count=0
      current=$bl_count
      total=$bl_count
      history=0
      if (( bl_count > 0 )); then
        detected=1
        log "  DETECTED: $bl_count active blacklisted sessions"
        break
      fi
    else
      local triple
      triple="$(TRIGGERS_DIR_ENV="$TRIGGERS_DIR" count_finding_for_scenario "$scenario" "$check")"
      total=${triple%%|*}
      local rest=${triple#*|}
      current=${rest%%|*}
      history=${rest#*|}
      if (( total > 0 )); then
        detected=1
        log "  DETECTED: total=$total (current=$current, history=$history)"
        break
      fi
    fi
    if [[ "$trigger_state" == "ended" ]] && (( attempt >= 3 )); then
      log "  trigger already ended and no detection after attempt $attempt; stopping poll"
      break
    fi
    sleep "$POLL_INTERVAL"
  done

  if kill -0 "$trigger_pid" 2>/dev/null; then
    log "  stopping trigger pid=$trigger_pid"
    kill -TERM "$trigger_pid" 2>/dev/null || true
    sleep 2
    kill -9 "$trigger_pid" 2>/dev/null || true
  fi
  wait "$trigger_pid" 2>/dev/null || true

  if (( detected == 0 )); then
    log "  no detection within verify loop; final tick + tail poll"
    force_vuln_tick
    sleep 3
    local triple
    if [[ "$check" == "blacklisted_sessions" ]]; then
      local bl_count
      bl_count="$(TRIGGERS_DIR_ENV="$TRIGGERS_DIR" count_blacklisted_sessions || echo 0)"
      bl_count=$(echo "$bl_count" | tr -dc '0-9')
      [[ -z "$bl_count" ]] && bl_count=0
      current=$bl_count
      total=$bl_count
      history=0
      if (( bl_count > 0 )); then
        detected=1
        log "  DETECTED (tail): $bl_count active blacklisted sessions"
      fi
    else
      triple="$(TRIGGERS_DIR_ENV="$TRIGGERS_DIR" count_finding_for_scenario "$scenario" "$check")"
      total=${triple%%|*}
      local rest=${triple#*|}
      current=${rest%%|*}
      history=${rest#*|}
      if (( total > 0 )); then
        detected=1
        log "  DETECTED (tail): total=$total (current=$current, history=$history)"
      fi
    fi
  fi

  local end_epoch
  end_epoch=$(date +%s)
  local elapsed=$((end_epoch - start_epoch))
  local status="fail"
  if (( detected == 1 )); then
    status="pass"
  fi
  record_scenario_result "$scenario" "$check" "$status" "$total" "$current" "$history" "$elapsed" ""
  log "  RESULT: $status  total=$total current=$current history=$history  elapsed=${elapsed}s"

  run_cleanup
  clear_vuln_history
  sleep "$COOLDOWN"
}

log "starting CVE detection suite: scenarios=${SCENARIOS_CSV} agent_type=$AGENT_TYPE"
log "triggers dir: $TRIGGERS_DIR"
log "output dir: $OUTPUT_DIR_ABS"
log "cli: $EDAMAME_CLI"

for scen in "${SCENARIOS[@]}"; do
  [[ -z "$scen" ]] && continue
  run_one_scenario "$scen"
done

CORE_VERSION_RAW="$(call_rpc get_core_version 2>/dev/null || true)"
CORE_VERSION="$(echo "$CORE_VERSION_RAW" | tr -d '"' | awk '{print $NF}')"

"$PYTHON" - <<PY
import json, os, platform, subprocess, time
ndjson_path = "$NDJSON"
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
    "core_version": "${CORE_VERSION}" or "unknown",
    "agent_type": "$AGENT_TYPE",
    "scenarios": scenarios,
    "totals": {
        "passed": passed,
        "failed": failed,
        "skipped": skipped,
        "total": len(scenarios),
    },
    "trigger_duration_s": int("$TRIGGER_DURATION"),
    "post_wait_s": int("$POST_WAIT"),
    "poll_attempts": int("$POLL_ATTEMPTS"),
    "poll_interval_s": int("$POLL_INTERVAL"),
    "readiness_wait_s": int("$READINESS_WAIT"),
    "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
}
with open("$RESULT_JSON", "w", encoding="utf-8") as fh:
    json.dump(summary, fh, indent=2)
print(json.dumps(summary["totals"]))
PY

log "CVE detection suite complete: $RESULT_JSON"
