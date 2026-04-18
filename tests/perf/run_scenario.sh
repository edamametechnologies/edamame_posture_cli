#!/usr/bin/env bash
# Orchestrate a single performance scenario against an installed edamame_posture binary.
#
# Usage:
#   run_scenario.sh --scenario <name> --duration <seconds> --output-dir <dir> [--warmup <seconds>]
#
# Scenarios (selected by --scenario):
#   idle        Disconnected daemon with no active features
#   hub_idle    Hub-connected daemon with no active features
#   capture     Hub-connected daemon with packet capture
#   lanscan     Hub-connected daemon with LAN scanning
#   llm         Hub-connected daemon with packet capture and agentic (edamame provider)
#   all         Hub-connected daemon with every feature enabled
#
# Environment:
#   EDAMAME_POSTURE_BIN     path to the edamame_posture binary (default: `command -v edamame_posture`)
#   EDAMAME_POSTURE_SUDO    set to "0" to skip sudo (default: "1" on Linux/macOS, "0" on Windows)
#   EDAMAME_POSTURE_USER    hub user for hub-connected scenarios
#   EDAMAME_POSTURE_DOMAIN  hub domain for hub-connected scenarios
#   EDAMAME_POSTURE_PIN     hub pin for hub-connected scenarios
#   EDAMAME_LLM_API_KEY     portal LLM API key for llm/all scenarios
#   PYTHON                  path to python3 (default: python3)
#
# If hub credentials are missing, hub_idle/capture/lanscan/llm/all fall back to
# the disconnected start variant and the resulting summary records
# `fallback_disconnected=true`. If EDAMAME_LLM_API_KEY is missing, llm/all
# continue without agentic mode and record `fallback_no_llm=true`.

set -Euo pipefail

log() { printf '[run_scenario] %s\n' "$*" >&2; }
die() { log "ERROR: $*"; exit 1; }

SCENARIO=""
DURATION=300
OUTPUT_DIR=""
WARMUP=3

while [[ $# -gt 0 ]]; do
  case "$1" in
    --scenario)      SCENARIO="$2"; shift 2;;
    --duration)      DURATION="$2"; shift 2;;
    --output-dir)    OUTPUT_DIR="$2"; shift 2;;
    --warmup)        WARMUP="$2"; shift 2;;
    -h|--help)
      sed -n '2,30p' "$0"; exit 0;;
    *) die "unknown flag: $1";;
  esac
done

[[ -n "$SCENARIO" ]] || die "--scenario required"
[[ -n "$OUTPUT_DIR" ]] || die "--output-dir required"

case "$SCENARIO" in
  idle|hub_idle|capture|lanscan|llm|all) ;;
  *) die "unknown scenario: $SCENARIO";;
esac

mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR_ABS=$(cd "$OUTPUT_DIR" && pwd)
case "$(uname -s 2>/dev/null || true)" in
  MINGW*|MSYS*|CYGWIN*)
    if command -v cygpath >/dev/null 2>&1; then
      OUTPUT_DIR_ABS="$(cygpath -m "$OUTPUT_DIR_ABS")"
    fi
    ;;
esac

PYTHON="${PYTHON:-python3}"
BIN="${EDAMAME_POSTURE_BIN:-$(command -v edamame_posture || true)}"
[[ -n "$BIN" && -x "$BIN" ]] || die "edamame_posture binary not found (EDAMAME_POSTURE_BIN or PATH)"

SUDO_PREFIX=""
IS_WINDOWS=0
case "$(uname -s)" in
  Linux|Darwin)
    if [[ "${EDAMAME_POSTURE_SUDO:-1}" == "1" && "$(id -u 2>/dev/null || echo 0)" != "0" ]]; then
      SUDO_PREFIX="sudo -E"
    fi
    ;;
  MINGW*|MSYS*|CYGWIN*)
    IS_WINDOWS=1
    ;;
esac

USER_SET="${EDAMAME_POSTURE_USER:-}"
DOMAIN_SET="${EDAMAME_POSTURE_DOMAIN:-}"
PIN_SET="${EDAMAME_POSTURE_PIN:-}"
HAVE_HUB=0
if [[ -n "$USER_SET" && -n "$DOMAIN_SET" && -n "$PIN_SET" ]]; then
  HAVE_HUB=1
fi

LLM_KEY="${EDAMAME_LLM_API_KEY:-}"
HAVE_LLM=0
if [[ -n "$LLM_KEY" ]]; then
  HAVE_LLM=1
fi

FALLBACK_DISCONNECTED=false
FALLBACK_NO_LLM=false
WANT_HUB=0
ENABLE_CAPTURE=0
ENABLE_LANSCAN=0
ENABLE_AGENTIC=0

case "$SCENARIO" in
  idle)
    WANT_HUB=0
    ;;
  hub_idle)
    WANT_HUB=1
    ;;
  capture)
    WANT_HUB=1
    ENABLE_CAPTURE=1
    ;;
  lanscan)
    WANT_HUB=1
    ENABLE_LANSCAN=1
    ;;
  llm)
    WANT_HUB=1
    ENABLE_CAPTURE=1
    ENABLE_AGENTIC=1
    ;;
  all)
    WANT_HUB=1
    ENABLE_CAPTURE=1
    ENABLE_LANSCAN=1
    ENABLE_AGENTIC=1
    ;;
esac

if [[ $WANT_HUB -eq 1 && $HAVE_HUB -eq 0 ]]; then
  log "hub credentials missing; falling back to disconnected daemon"
  WANT_HUB=0
  FALLBACK_DISCONNECTED=true
fi
if [[ $ENABLE_AGENTIC -eq 1 && $HAVE_LLM -eq 0 ]]; then
  log "EDAMAME_LLM_API_KEY missing; disabling agentic mode for this run"
  ENABLE_AGENTIC=0
  FALLBACK_NO_LLM=true
fi

wait_for_process_gone() {
  local tries=$1
  "$PYTHON" - "$tries" <<'PY'
import os, sys, time
try:
    import psutil
except Exception:
    time.sleep(2)
    sys.exit(0)
tries = int(sys.argv[1])
for _ in range(max(1, tries)):
    alive = False
    for p in psutil.process_iter(attrs=["name"]):
        name = (p.info.get("name") or "").lower()
        if name in ("edamame_posture", "edamame_posture.exe") or name.startswith("edamame_posture"):
            alive = True
            break
    if not alive:
        sys.exit(0)
    time.sleep(1)
sys.exit(0)
PY
}

find_daemon_pid() {
  "$PYTHON" - <<'PY'
import sys, time
try:
    import psutil
except Exception:
    sys.exit(1)
candidates = []
for p in psutil.process_iter(attrs=["pid", "name", "create_time", "ppid"]):
    name = (p.info.get("name") or "").lower()
    if name in ("edamame_posture", "edamame_posture.exe") or name.startswith("edamame_posture"):
        candidates.append(p.info)
if not candidates:
    sys.exit(2)
candidates.sort(key=lambda c: c.get("create_time") or 0)
print(candidates[0]["pid"])
PY
}

stop_daemon() {
  if [[ -n "$SUDO_PREFIX" ]]; then
    $SUDO_PREFIX "$BIN" background-stop >/dev/null 2>&1 || true
  else
    "$BIN" background-stop >/dev/null 2>&1 || true
  fi
  wait_for_process_gone 20
  local pid
  pid=$(find_daemon_pid || true)
  if [[ -n "$pid" ]]; then
    log "daemon still running as pid=$pid after background-stop; forcing termination"
    if [[ $IS_WINDOWS -eq 1 ]]; then
      taskkill //PID "$pid" //F >/dev/null 2>&1 || true
    else
      if [[ -n "$SUDO_PREFIX" ]]; then
        $SUDO_PREFIX kill -9 "$pid" 2>/dev/null || true
      else
        kill -9 "$pid" 2>/dev/null || true
      fi
    fi
    wait_for_process_gone 10
  fi
}

log "cleaning any previous daemon"
stop_daemon

START_ARGS=()
if [[ $WANT_HUB -eq 1 ]]; then
  START_ARGS=(background-start
    -u "$USER_SET"
    -d "$DOMAIN_SET"
    -p "$PIN_SET"
    --device-id "perf-ci")
else
  START_ARGS=(background-start-disconnected)
fi

[[ $ENABLE_CAPTURE -eq 1 ]] && START_ARGS+=(--packet-capture --include-local-traffic)
[[ $ENABLE_LANSCAN -eq 1 ]] && START_ARGS+=(--network-scan)
if [[ $ENABLE_AGENTIC -eq 1 ]]; then
  START_ARGS+=(--agentic-mode auto --agentic-provider edamame --agentic-interval 60)
fi

log "starting daemon with args: ${START_ARGS[*]}"
STDOUT_LOG="$OUTPUT_DIR_ABS/stdout.log"
STDERR_LOG="$OUTPUT_DIR_ABS/stderr.log"
set +e
if [[ -n "$SUDO_PREFIX" ]]; then
  $SUDO_PREFIX "$BIN" "${START_ARGS[@]}" >"$STDOUT_LOG" 2>"$STDERR_LOG"
else
  "$BIN" "${START_ARGS[@]}" >"$STDOUT_LOG" 2>"$STDERR_LOG"
fi
START_RC=$?
set -e
log "daemon start returned rc=$START_RC"

sleep "$WARMUP"

DAEMON_PID=""
for _ in 1 2 3 4 5 6 7 8 9 10; do
  DAEMON_PID=$(find_daemon_pid || true)
  [[ -n "$DAEMON_PID" ]] && break
  sleep 1
done
[[ -n "$DAEMON_PID" ]] || die "edamame_posture not running after start (see $STDERR_LOG)"
log "daemon pid: $DAEMON_PID"

if [[ -n "$SUDO_PREFIX" ]]; then
  $SUDO_PREFIX "$BIN" background-status >"$OUTPUT_DIR_ABS/daemon_status.txt" 2>/dev/null || true
else
  "$BIN" background-status >"$OUTPUT_DIR_ABS/daemon_status.txt" 2>/dev/null || true
fi

SCENARIO_JSON="$OUTPUT_DIR_ABS/scenario.json"
CORE_VERSION=$("$BIN" get-core-version 2>/dev/null | awk -F': ' '/version/ {print $2}' | head -n 1 || true)
cat >"$SCENARIO_JSON" <<JSON
{
  "scenario": "$SCENARIO",
  "duration_s": $DURATION,
  "want_hub": $WANT_HUB,
  "enable_capture": $ENABLE_CAPTURE,
  "enable_lanscan": $ENABLE_LANSCAN,
  "enable_agentic": $ENABLE_AGENTIC,
  "fallback_disconnected": $FALLBACK_DISCONNECTED,
  "fallback_no_llm": $FALLBACK_NO_LLM,
  "daemon_pid": $DAEMON_PID,
  "core_version": "${CORE_VERSION:-unknown}",
  "binary_path": "$BIN",
  "start_args": "${START_ARGS[*]}",
  "start_utc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
JSON

log "starting sampler for ${DURATION}s"
SAMPLER_JSONL="$OUTPUT_DIR_ABS/samples.jsonl"
SAMPLER_SUMMARY="$OUTPUT_DIR_ABS/summary.json"
SAMPLER_RC=0
"$PYTHON" "$(dirname "$0")/sampler.py" \
  --pid "$DAEMON_PID" \
  --interval 1.0 \
  --duration "$DURATION" \
  --warmup 2 \
  --scenario "$SCENARIO" \
  --jsonl-output "$SAMPLER_JSONL" \
  --summary-output "$SAMPLER_SUMMARY" || SAMPLER_RC=$?

if [[ $SAMPLER_RC -ne 0 ]]; then
  log "WARNING: sampler exited with rc=$SAMPLER_RC"
fi

log "stopping daemon"
stop_daemon
log "scenario $SCENARIO complete: $OUTPUT_DIR_ABS"
