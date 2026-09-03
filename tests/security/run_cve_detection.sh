#!/usr/bin/env bash
# Run a suite of CVE detection scenarios against a running edamame_posture
# daemon and record detection outcomes as JSON.
#
# The trigger scripts are vendored in tests/security/triggers/ and staged into
# a scratch directory by the caller. This script orchestrates: cleanup, trigger
# launch, detector tick, detection verification using edamame_cli RPCs, and
# JSON result recording.
#
# Usage:
#   run_cve_detection.sh \
#     --triggers-dir <dir> \
#     --output-dir <dir> \
#     [--trigger-duration <seconds>]     # default: 300
#     [--post-wait <seconds>]            # default: 5
#     [--cooldown <seconds>]             # default: 8
#     [--poll-attempts <count>]          # default: 6
#     [--poll-interval <seconds>]        # default: 30
#     [--readiness-wait <seconds>]       # default: 120
#     [--agent-type <string>]            # default: openclaw
#     [--scenarios <comma,separated>]    # default: all nine CVE scenarios
#
# Detection timing defaults are tuned so iForest has enough observation time on
# the token-exfil scenarios; see the per-flag defaults below.
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
# 120s L7 readiness wait + 5x30s verify loop and a 300s trigger
# duration so iForest has enough observation time on the token-exfil
# CVE scenarios.
TRIGGER_DURATION=300
POST_WAIT=5
COOLDOWN=8
POLL_ATTEMPTS=6
POLL_INTERVAL=30
READINESS_WAIT=120
AGENT_TYPE="openclaw"
SCENARIOS_CSV="blacklist_comm,cve_token_exfil,cve_sandbox_escape,memory_poisoning,credential_sprawl,supply_chain_exfil,npm_rat_beacon,file_events,skill_supply_chain,pgserve_postinstall,temp_modify,nonsensitive_path,agent_config_tamper,agent_cred_harvest,agent_denylist_bypass"

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
    supply_chain_exfil)     echo "credential_harvest" ;;
    npm_rat_beacon)         echo "token_exfiltration" ;;
    file_events)            echo "file_system_tampering" ;;
    skill_supply_chain)     echo "skill_supply_chain" ;;
    pgserve_postinstall)    echo "credential_harvest" ;;
    temp_modify)            echo "file_system_tampering" ;;
    nonsensitive_path)      echo "sensitive_material_egress" ;;
    agent_config_tamper)    echo "file_system_tampering" ;;
    agent_cred_harvest)     echo "credential_harvest" ;;
    agent_denylist_bypass)  echo "agent_denylist_bypass" ;;
    *) echo "" ;;
  esac
}

# Most scenarios use `trigger_<scenario>.py`. A scenario may reuse another
# scenario's trigger when the same stimulus is expected to produce two
# distinct findings: `trigger_blacklist_comm.py` generates sustained egress to
# a blacklisted sinkhole *while holding a credential file open*, which is both
# a blacklisted session and the `skill_supply_chain` shape. The two scenarios
# assert different checks against the same stimulus rather than duplicating
# the trigger.
trigger_script_for() {
  case "$1" in
    skill_supply_chain)     echo "$TRIGGERS_DIR/trigger_blacklist_comm.py" ;;
    *)                      echo "$TRIGGERS_DIR/trigger_$1.py" ;;
  esac
}

scenario_markers_json() {
  case "$1" in
    cve_token_exfil)        echo '["_exfil_token", "_exfil"]' ;;
    memory_poisoning)       echo '["_memory_poison", "memory_poisoned.md"]' ;;
    credential_sprawl)      echo '["_sprawl_key", "_sprawl", "demo_openclaw_sprawl"]' ;;
    file_events)            echo '["_fim_test", "_fim_suspicious"]' ;;
    skill_supply_chain)     echo '["_blacklist_key"]' ;;
    pgserve_postinstall)    echo '["_sc_wallet", "_sc_state.ldb", "_pgserve_key", "_pgserve_credentials", "_pgserve_accessTokens.json", "_pgserve_adc.json"]' ;;
    temp_modify)            echo '["_temp_staged_binary"]' ;;
    nonsensitive_path)      echo '["_workspace_demo", "project_secrets.env"]' ;;
    agent_config_tamper)    echo '["_cfgtamper_hook.mdc", "_cfgtamper_mcp.mdc", "_cfgtamper_memory.mdc", "_cfgtamper"]' ;;
    agent_cred_harvest)     echo '["_ach_key", "_ach_secring.key", "_ach.mdc"]' ;;
    agent_denylist_bypass)  echo '["denylist-bypass-probe.edamame.test"]' ;;
    *) echo '[]' ;;
  esac
}

scenario_ports_json() {
  case "$1" in
    cve_token_exfil)        echo '[63169]' ;;
    credential_sprawl)      echo '[63171]' ;;
    pgserve_postinstall)    echo '[63174]' ;;
    *) echo '[]' ;;
  esac
}

# Per-scenario knob overrides for github-hosted runners that need a
# longer detection window. The default cycle (POLL_ATTEMPTS=6 x 30s =
# 180s) plus 300s trigger covers macos / windows / self-hosted lanes,
# but `cve_sandbox_escape` and `memory_poisoning` reproducibly miss
# detection on the github-hosted ubuntu runners (both x64 and arm64)
# because L7 enrichment + iForest convergence lose the race against
# the verify window under shared-runner CPU pressure. Per
# `edamame_app/.cursor/rules/workspace.mdc` ("Self-Hosted Runners"
# / known transient CI failures), the canonical fix is per-scenario
# `POLL_ATTEMPTS` lift on the test side rather than relaxing the
# deterministic gate.
scenario_poll_attempts_for() {
  case "$1" in
    cve_sandbox_escape)     echo "${SANDBOX_POLL_ATTEMPTS:-12}" ;;
    memory_poisoning)       echo "${MEMORY_POLL_ATTEMPTS:-12}" ;;
    *) echo "$POLL_ATTEMPTS" ;;
  esac
}

scenario_trigger_duration_for() {
  case "$1" in
    cve_sandbox_escape)     echo "${SANDBOX_TRIGGER_DURATION:-600}" ;;
    memory_poisoning)       echo "${MEMORY_TRIGGER_DURATION:-600}" ;;
    *) echo "$TRIGGER_DURATION" ;;
  esac
}

# Per-scenario fresh-attempt count override. The default
# SCENARIO_MAX_ATTEMPTS=2 (one retry on detect-failure) is enough
# for the macos / windows / self-hosted lanes, but
# `memory_poisoning` on the github-hosted ubuntu-arm64 runner
# routinely needs an extra fresh attempt: even with the bumped
# POLL_ATTEMPTS=12 / TRIGGER_DURATION=600s (~960s observation
# window), iForest convergence on a steady-state TCP flow under
# shared-runner CPU pressure can lose the race twice in a row
# before catching up. Three fresh attempts (state reset between
# each) brings the per-scenario worst case to ~27 min, still
# inside the 60-min job timeout.
scenario_max_attempts_for() {
  local default_max="${SCENARIO_MAX_ATTEMPTS:-2}"
  case "$1" in
    memory_poisoning)       echo "${MEMORY_MAX_ATTEMPTS:-3}" ;;
    *) echo "$default_max" ;;
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
# has already produced a finding.
wait_for_readiness() {
  local scenario="$1"
  local check="$2"
  local max_wait="$3"
  local interval=6
  local waited=0
  [[ "$max_wait" -le 0 ]] && return 0

  while (( waited < max_wait )); do
    local counts
    counts="$(TRIGGERS_DIR_ENV="$TRIGGERS_DIR" count_finding_for_scenario "$scenario" "$check" 2>/dev/null)"
    local total=${counts%%|*}
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
      skill_supply_chain|sensitive_material_egress)
        status="$(TRIGGERS_DIR_ENV="$TRIGGERS_DIR" sensitive_egress_readiness_status)"
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
    'gnupg': ['/.gnupg/'],
    'instruction': ['/.cursor/rules/', '/.cursorrules', '/mcp.json'],
    'claude': ['/.claude/'],
    'codex': ['/.codex/'],
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

# Readiness proxy for the two egress checks that key on sensitive material
# without needing an iForest anomaly verdict: `skill_supply_chain` (blacklisted
# destination + open sensitive file) and `sensitive_material_egress` (routine
# destination + open sensitive file). Both only require that L7 attribution has
# tied at least one open file to an active session, which is the slow step on
# non-eBPF platforms (netstat/libproc polling at 30s Linux / 60s macOS /
# 120s Windows).
sensitive_egress_readiness_status() {
  "$PYTHON" - <<'PY' 2>>"$TICK_LOG"
import os, sys
sys.path.insert(0, os.environ["TRIGGERS_DIR_ENV"])
from _edamame_cli import cli_rpc
try:
    sessions = cli_rpc('get_current_sessions') or []
except Exception:
    sessions = []
active = [s for s in sessions if isinstance(s, dict) and (s.get('status') or {}).get('active')]
with_of = [s for s in active if len(((s.get('l7') or {}).get('open_files') or [])) > 0]
ready = 1 if len(with_of) > 0 else 0
print(f"{ready}|active={len(active)} with_open_files={len(with_of)}")
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
    def _is_suspicious(p: str) -> bool:
        if not p:
            return False
        pl = p.lower().replace('\\', '/')
        return '/tmp/' in pl or '/var/tmp/' in pl or '/appdata/local/temp/' in pl or '/temp/' in pl
    if spawned or any(_is_suspicious(p) for p in paths):
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
    snapshot = cli_rpc('get_file_events', '{"sensitive_only": false}') or []
except Exception:
    snapshot = []
# get_file_events returns a FimSnapshotAPI object ({"events": [...],
# "sensitive_events": [...], ...}), not a bare list. Reading the object as a
# list made this probe report total=0 on every platform, so FIM scenarios
# always burned the full readiness budget instead of starting to verify as
# soon as the first sensitive write was visible.
if isinstance(snapshot, dict):
    events = snapshot.get('events') or []
else:
    events = snapshot if isinstance(snapshot, list) else []
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
    # AI-agent config dirs -- watched so agent_config_tamper's SessionStart /
    # MCP / rules writes produce FIM events (labels: claude / instruction).
    home / ".claude",
    home / ".claude" / "projects",
    home / ".cursor",
    home / ".cursor" / "rules",
    home / ".codex",
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

trigger_extra_args() {
  local scenario="$1"
  case "$scenario" in
    npm_rat_beacon)
      # The npm RAT scenario detects through the anomaly-token path:
      # active anomalous session + sensitive open file attribution.
      # A 10s beacon cadence only emits ~30 requests in the 5-minute
      # CI window, which is too sparse on noisy ubuntu-x64 runners: the
      # iForest anomaly window can appear after the live-open-file sample
      # has already missed the stage-2 process. Keep the same threat
      # shape (stage-2 beacon from /tmp with npm/ssh files held open)
      # but shorten the cadence so anomaly scoring and L7 enrichment have
      # overlapping samples inside the fixed release-gate window.
      echo "--interval 2"
      ;;
    *)
      echo ""
      ;;
  esac
}

run_cleanup() {
  local cleanup_path="$TRIGGERS_DIR/cleanup.py"
  [[ -f "$cleanup_path" ]] || return 0
  log "  running trigger cleanup"
  "$PYTHON" "$cleanup_path" --agent-type "$AGENT_TYPE" >>"$TICK_LOG" 2>&1 || true
}

# Emit `total|current|history|alertable|severity_histogram` for a scenario.
#
# `alertable` counts only the matched findings that would raise an alert in
# production (HIGH/CRITICAL, not dismissed -- see
# triggers/_finding_match.py). The gate keys on that field rather than on
# `total`, so a scenario whose finding was demoted to LOW by the CRS severity
# path or the LLM adjudicator fails instead of passing on bare presence.
count_finding_for_scenario() {
  local scenario="$1"
  local check="$2"
  MARKERS_JSON="$(scenario_markers_json "$scenario")" \
  PORTS_JSON="$(scenario_ports_json "$scenario")" \
  CHECK="$check" \
  TRIGGERS_DIR_ENV="$TRIGGERS_DIR" \
  EVIDENCE_DUMP="$OUTPUT_DIR_ABS/findings/$scenario.json" \
  "$PYTHON" - <<'PY'
import json, os, sys
sys.path.insert(0, os.environ["TRIGGERS_DIR_ENV"])
from _edamame_cli import cli_rpc
from _finding_match import (
    findings_of,
    format_histogram,
    is_alertable,
    matches,
    severity_histogram,
)

check = os.environ["CHECK"]
markers = json.loads(os.environ.get("MARKERS_JSON", "[]"))
ports = {int(p) for p in json.loads(os.environ.get("PORTS_JSON", "[]"))}

matched = []

try:
    report = cli_rpc("get_vulnerability_findings")
    current_matched = [f for f in findings_of(report) if matches(f, check, markers, ports)]
except Exception as exc:
    print(f"__ERR__ current: {exc}", file=sys.stderr)
    current_matched = []

history_matched = []
try:
    hist = cli_rpc("get_vulnerability_history", '{"limit": 50}')
    if isinstance(hist, list):
        for entry in hist:
            if not isinstance(entry, dict):
                continue
            entry_findings = entry.get("findings")
            if not isinstance(entry_findings, list):
                continue
            history_matched.extend(
                f for f in entry_findings if matches(f, check, markers, ports)
            )
except Exception as exc:
    print(f"__ERR__ history: {exc}", file=sys.stderr)

matched = current_matched + history_matched
alertable = sum(1 for f in matched if is_alertable(f))

# Persist the whole matched finding objects, not just the counters. Each
# finding carries its `evidence` packet (the CRS inputs) and its severity, so
# this file is what lets a severity regression be diagnosed from the artifact
# instead of by re-deriving the CRS arithmetic by hand.
dump_path = os.environ.get("EVIDENCE_DUMP")
if dump_path:
    try:
        os.makedirs(os.path.dirname(dump_path), exist_ok=True)
        with open(dump_path, "w", encoding="utf-8") as fh:
            json.dump(
                {
                    "check": check,
                    "markers": markers,
                    "ports": sorted(ports),
                    "alertable": alertable,
                    "current": current_matched,
                    "history": history_matched,
                },
                fh,
                indent=2,
                default=str,
            )
    except Exception as exc:
        print(f"__ERR__ evidence dump: {exc}", file=sys.stderr)

print(
    "{}|{}|{}|{}|{}".format(
        len(matched),
        len(current_matched),
        len(history_matched),
        alertable,
        format_histogram(severity_histogram(matched)),
    )
)
PY
}

# Parse the pipe-delimited counter line into the TOTAL/CURRENT/HISTORY/
# ALERTABLE/SEVERITIES globals. Uses `IFS` splitting rather than nested
# `${v%%|*}` / `${v#*|}` expansions so appending a field to the line cannot
# silently leave a trailing field holding a multi-field string.
parse_finding_counts() {
  local line="$1"
  TOTAL=0; CURRENT=0; HISTORY=0; ALERTABLE=0; SEVERITIES="none"
  local _t _c _h _a _s
  IFS='|' read -r _t _c _h _a _s <<<"$line"
  TOTAL="$(printf '%s' "${_t:-0}" | tr -dc '0-9')"
  CURRENT="$(printf '%s' "${_c:-0}" | tr -dc '0-9')"
  HISTORY="$(printf '%s' "${_h:-0}" | tr -dc '0-9')"
  ALERTABLE="$(printf '%s' "${_a:-0}" | tr -dc '0-9')"
  [[ -z "$TOTAL" ]] && TOTAL=0
  [[ -z "$CURRENT" ]] && CURRENT=0
  [[ -z "$HISTORY" ]] && HISTORY=0
  [[ -z "$ALERTABLE" ]] && ALERTABLE=0
  [[ -n "${_s:-}" ]] && SEVERITIES="$_s"
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
  local alertable="${9:-0}"
  local severities="${10:-none}"
  "$PYTHON" - <<PY | tee -a "$NDJSON" >/dev/null
import json, sys, time
rec = {
    "scenario": "$scenario",
    "expected_check": "$check",
    "status": "$status",
    "finding_total": int("$total"),
    "finding_current": int("$current"),
    "finding_history": int("$history"),
    "finding_alertable": int("$alertable"),
    "severities": "$severities",
    "elapsed_s": float("$elapsed"),
    "agent_type": "$AGENT_TYPE",
    "trigger_duration_s": int("$TRIGGER_DURATION"),
    "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "extra": "$extra",
}
print(json.dumps(rec))
PY
}

# Run a single attempt of a scenario. Sets DETECTED, TOTAL, CURRENT, HISTORY,
# ALERTABLE, SEVERITIES, DEMOTED_ONLY, ELAPSED globals and returns 0 on
# success, 1 on failure.
#
# Success requires an ALERTABLE finding (HIGH/CRITICAL, not dismissed), not
# merely a matching finding. DEMOTED_ONLY records the case where the scenario
# did produce its finding but every instance landed below the alerting
# threshold -- the shape a CRS-weight or adjudicator regression takes.
run_one_scenario_attempt() {
  local scenario="$1"
  local check="$2"
  local trigger_script="$3"

  # Per-scenario overrides for slow github-hosted ubuntu runners.
  # Compute the per-scenario values BEFORE declaring the local
  # shadows: bash uses dynamic scoping, so a `local POLL_ATTEMPTS`
  # declared first would be visible to `scenario_poll_attempts_for`
  # as an empty string, making its `*) echo "$POLL_ATTEMPTS"` fall-
  # through return empty. Computing first reads the outer scope.
  local _scen_polls _scen_dur
  _scen_polls="$(scenario_poll_attempts_for "$scenario")"
  _scen_dur="$(scenario_trigger_duration_for "$scenario")"
  local POLL_ATTEMPTS="$_scen_polls"
  local TRIGGER_DURATION="$_scen_dur"

  DETECTED=0
  TOTAL=0
  CURRENT=0
  HISTORY=0
  ALERTABLE=0
  SEVERITIES="none"
  DEMOTED_ONLY=0
  ELAPSED=0

  clear_vuln_history
  run_cleanup
  prepare_scenario_state "$scenario" "$check"

  local start_epoch
  start_epoch=$(date +%s)
  local extra_args_str
  extra_args_str="$(trigger_extra_args "$scenario")"
  if [[ -n "$extra_args_str" ]]; then
    # shellcheck disable=SC2206 # Intentional simple flag splitting.
    local extra_args=( $extra_args_str )
    TRIGGERS_DIR_ENV="$TRIGGERS_DIR" "$PYTHON" "$trigger_script" \
      --agent-type "$AGENT_TYPE" \
      --duration "$TRIGGER_DURATION" \
      "${extra_args[@]}" \
      >>"$OUTPUT_DIR_ABS/${scenario}.trigger.log" 2>&1 &
  else
    TRIGGERS_DIR_ENV="$TRIGGERS_DIR" "$PYTHON" "$trigger_script" \
      --agent-type "$AGENT_TYPE" \
      --duration "$TRIGGER_DURATION" \
      >>"$OUTPUT_DIR_ABS/${scenario}.trigger.log" 2>&1 &
  fi
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
      CURRENT=$bl_count
      TOTAL=$bl_count
      HISTORY=0
      # blacklisted_sessions is a session-list assertion, not a
      # VulnerabilityFinding, so it carries no severity to demote.
      ALERTABLE=$bl_count
      SEVERITIES="n/a"
      if (( bl_count > 0 )); then
        DETECTED=1
        log "  DETECTED: $bl_count active blacklisted sessions"
        break
      fi
    else
      local counts
      counts="$(TRIGGERS_DIR_ENV="$TRIGGERS_DIR" count_finding_for_scenario "$scenario" "$check")"
      parse_finding_counts "$counts"
      if (( ALERTABLE > 0 )); then
        DETECTED=1
        DEMOTED_ONLY=0
        log "  DETECTED: alertable=$ALERTABLE total=$TOTAL (current=$CURRENT, history=$HISTORY, severities=$SEVERITIES)"
        break
      fi
      if (( TOTAL > 0 )); then
        DEMOTED_ONLY=1
        log "  finding present but NOT alertable: total=$TOTAL severities=$SEVERITIES (need HIGH or CRITICAL)"
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

  if (( DETECTED == 0 )); then
    log "  no alertable detection within verify loop; final tick + tail poll"
    force_vuln_tick
    sleep 3
    if [[ "$check" == "blacklisted_sessions" ]]; then
      local bl_count
      bl_count="$(TRIGGERS_DIR_ENV="$TRIGGERS_DIR" count_blacklisted_sessions || echo 0)"
      bl_count=$(echo "$bl_count" | tr -dc '0-9')
      [[ -z "$bl_count" ]] && bl_count=0
      CURRENT=$bl_count
      TOTAL=$bl_count
      HISTORY=0
      ALERTABLE=$bl_count
      SEVERITIES="n/a"
      if (( bl_count > 0 )); then
        DETECTED=1
        log "  DETECTED (tail): $bl_count active blacklisted sessions"
      fi
    else
      local counts
      counts="$(TRIGGERS_DIR_ENV="$TRIGGERS_DIR" count_finding_for_scenario "$scenario" "$check")"
      parse_finding_counts "$counts"
      if (( ALERTABLE > 0 )); then
        DETECTED=1
        DEMOTED_ONLY=0
        log "  DETECTED (tail): alertable=$ALERTABLE total=$TOTAL (current=$CURRENT, history=$HISTORY, severities=$SEVERITIES)"
      elif (( TOTAL > 0 )); then
        DEMOTED_ONLY=1
        log "  finding present but NOT alertable (tail): total=$TOTAL severities=$SEVERITIES"
      fi
    fi
  fi

  local end_epoch
  end_epoch=$(date +%s)
  ELAPSED=$((end_epoch - start_epoch))

  if (( DETECTED == 1 )); then
    return 0
  fi
  return 1
}

# Run a scenario with retry-on-failure. The CVE detector relies on iForest
# anomaly scoring whose warm-up depends on observation throughput. On
# slow GitHub-hosted ARM runners the first scenario after a clean
# detector tick can miss the detection window. A single retry resolves
# this without making the gate probabilistic: a real architectural
# breakage will fail both attempts, while runner-induced timing flakes
# almost never recur on the second attempt.
run_one_scenario() {
  local scenario="$1"
  local check
  check="$(expected_check_for "$scenario")"
  if [[ -z "$check" ]]; then
    log "SKIP $scenario (no expected check mapping)"
    record_scenario_result "$scenario" "unknown" "skip" 0 0 0 0 "no_expected_check" 0 "none"
    return 0
  fi
  local trigger_script
  trigger_script="$(trigger_script_for "$scenario")"
  if [[ ! -f "$trigger_script" ]]; then
    log "SKIP $scenario (trigger not found: $trigger_script)"
    record_scenario_result "$scenario" "$check" "skip" 0 0 0 0 "trigger_missing" 0 "none"
    return 0
  fi

  : >"$OUTPUT_DIR_ABS/${scenario}.trigger.log"
  local scenario_duration scenario_polls scenario_max
  scenario_duration="$(scenario_trigger_duration_for "$scenario")"
  scenario_polls="$(scenario_poll_attempts_for "$scenario")"
  scenario_max="$(scenario_max_attempts_for "$scenario")"
  log "=== scenario: $scenario (check=$check, duration=${scenario_duration}s, polls=${scenario_polls}, max_attempts=${scenario_max}) ==="

  local max_attempts="$scenario_max"
  local scen_attempt=0
  local total_elapsed=0
  local final_status="fail"
  local extra_note=""
  while (( scen_attempt < max_attempts )); do
    scen_attempt=$((scen_attempt + 1))
    if (( scen_attempt > 1 )); then
      log "--- $scenario: retry attempt ${scen_attempt}/${max_attempts} (previous attempt did not detect ${check}) ---"
      extra_note="retry_${scen_attempt}"
    fi
    if run_one_scenario_attempt "$scenario" "$check" "$trigger_script"; then
      final_status="pass"
      total_elapsed=$((total_elapsed + ELAPSED))
      break
    fi
    total_elapsed=$((total_elapsed + ELAPSED))
    if (( scen_attempt < max_attempts )); then
      log "  $scenario: attempt $scen_attempt did not detect; resetting state and retrying after cooldown"
      run_cleanup
      clear_vuln_history
      sleep "$COOLDOWN"
    fi
  done

  # A scenario that produced its finding but never reached HIGH/CRITICAL is
  # tagged distinctly: the trigger and detection path work, the severity path
  # regressed. Without this the failure reads identically to "trigger never
  # fired", which sends triage down the wrong branch.
  if [[ "$final_status" == "fail" ]] && (( DEMOTED_ONLY == 1 )); then
    if [[ -n "$extra_note" ]]; then
      extra_note="${extra_note},demoted_below_alertable"
    else
      extra_note="demoted_below_alertable"
    fi
  fi

  record_scenario_result "$scenario" "$check" "$final_status" "$TOTAL" "$CURRENT" "$HISTORY" "$total_elapsed" "$extra_note" "$ALERTABLE" "$SEVERITIES"
  log "  RESULT: $final_status  alertable=$ALERTABLE total=$TOTAL current=$CURRENT history=$HISTORY severities=$SEVERITIES  elapsed=${total_elapsed}s attempts=$scen_attempt"

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
