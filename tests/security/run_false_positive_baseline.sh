#!/usr/bin/env bash
# Baseline false-positive observation harness for the CVE detection suite.
#
# Observes a running edamame_posture daemon in an "idle" state (no attack
# triggers, no explicit file monitor) for `--duration` seconds and records
# any vulnerability findings that appear. A clean runner MUST produce zero
# findings during this window; any finding emitted while no attack trigger
# is running is treated as a false positive and hard-fails the security
# release gate.
#
# This harness runs BEFORE `run_cve_detection.sh` so a platform that emits
# detections without any stimulus cannot taint the CVE regression suite
# that follows: the gate policy (fail-abort) short-circuits the workflow
# and skips the CVE suite entirely when the baseline is dirty.
#
# Usage:
#   run_false_positive_baseline.sh \
#     --triggers-dir <dir> \
#     --output-dir <dir> \
#     [--duration <seconds>]         # default: 600 (10 minutes)
#     [--tick-interval <seconds>]    # default: 60
#     [--abort-on-first-finding 0|1] # default: 1 (fail fast)
#
# Environment:
#   EDAMAME_CLI   path to edamame_cli binary (mandatory)
#   PYTHON        path to python3 (default: python3)
#
# Outputs (under --output-dir):
#   baseline.json         full observation record with per-sample findings
#   baseline_ticks.log    stdout/stderr from forced detector ticks
#   baseline_samples/     per-sample JSON snapshots (for post-hoc triage)
#
# Exit codes:
#   0  no false positives
#   1  at least one vulnerability finding was observed in the idle window
#   2  infrastructure error (CLI / RPC failure, missing triggers dir, etc.)

set -Euo pipefail

log() { printf '[baseline] %s\n' "$*" >&2; }
die() { log "ERROR: $*"; exit 2; }

TRIGGERS_DIR=""
OUTPUT_DIR=""
DURATION=600
TICK_INTERVAL=60
ABORT_ON_FIRST_FINDING=1

while [[ $# -gt 0 ]]; do
  case "$1" in
    --triggers-dir)             TRIGGERS_DIR="$2"; shift 2;;
    --output-dir)               OUTPUT_DIR="$2"; shift 2;;
    --duration)                 DURATION="$2"; shift 2;;
    --tick-interval)            TICK_INTERVAL="$2"; shift 2;;
    --abort-on-first-finding)   ABORT_ON_FIRST_FINDING="$2"; shift 2;;
    -h|--help) sed -n '2,36p' "$0"; exit 0;;
    *) die "unknown flag: $1";;
  esac
done

[[ -n "$TRIGGERS_DIR" ]] || die "--triggers-dir required"
[[ -n "$OUTPUT_DIR"   ]] || die "--output-dir required"
[[ -d "$TRIGGERS_DIR" ]] || die "triggers dir not found: $TRIGGERS_DIR"
[[ -n "${EDAMAME_CLI:-}" && -x "${EDAMAME_CLI:-}" ]] \
  || die "EDAMAME_CLI must point to an executable edamame_cli"

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
TICK_LOG="$OUTPUT_DIR_ABS/baseline_ticks.log"
RESULT_JSON="$OUTPUT_DIR_ABS/baseline.json"
SAMPLES_DIR="$OUTPUT_DIR_ABS/baseline_samples"
mkdir -p "$SAMPLES_DIR"
: >"$TICK_LOG"

call_rpc() {
  "$EDAMAME_CLI" rpc "$@" 2>>"$TICK_LOG"
}

force_vuln_tick() {
  call_rpc debug_run_vulnerability_detector_tick >>"$TICK_LOG" 2>&1 || true
}

clear_vuln_history() {
  # Per the edamame_core vuln-persistence invariant, clearing history also
  # invalidates the detector input-hash cache so the next tick re-evaluates
  # live telemetry from a known-empty baseline instead of a stale skip.
  call_rpc clear_vulnerability_history >>"$TICK_LOG" 2>&1 || true
}

clear_file_events() {
  call_rpc clear_file_events >>"$TICK_LOG" 2>&1 || true
}

# Sample the detector state as JSON on stdout. Returns findings grouped
# into current (get_vulnerability_findings) vs history (last 50 entries
# of get_vulnerability_history). A clean idle baseline MUST return
# empty arrays for both.
sample_findings() {
  TRIGGERS_DIR_ENV="$TRIGGERS_DIR" "$PYTHON" - <<'PY'
import json, os, sys
sys.path.insert(0, os.environ["TRIGGERS_DIR_ENV"])
from _edamame_cli import cli_rpc


def _findings(report):
    if isinstance(report, dict):
        return report.get("findings") or []
    return []


out = {"current": [], "history": [], "errors": []}

try:
    report = cli_rpc("get_vulnerability_findings")
    out["current"] = _findings(report)
except Exception as exc:
    out["errors"].append(f"get_vulnerability_findings: {exc}")

try:
    hist = cli_rpc("get_vulnerability_history", '{"limit": 50}')
    if isinstance(hist, list):
        for entry in hist:
            out["history"].extend(entry.get("findings") or [])
except Exception as exc:
    out["errors"].append(f"get_vulnerability_history: {exc}")

print(json.dumps(out))
PY
}

count_findings() {
  local sample_file="$1"
  "$PYTHON" - "$sample_file" <<'PY'
import json, sys
with open(sys.argv[1], "r", encoding="utf-8") as fh:
    data = json.load(fh)
current = data.get("current") or []
history = data.get("history") or []
# We treat every finding that has a `check` label as a positive, regardless
# of check type: no stimulus means every finding is a false positive.
cur = sum(1 for f in current if isinstance(f, dict) and f.get("check"))
his = sum(1 for f in history if isinstance(f, dict) and f.get("check"))
print(f"{cur + his} {cur} {his}")
PY
}

write_result_json() {
  local status="$1"
  local total="$2"
  local cur="$3"
  local hist="$4"
  local elapsed="$5"
  local first_finding_sample="$6"
  TOTAL_ENV="$total" \
  CUR_ENV="$cur" \
  HIST_ENV="$hist" \
  STATUS_ENV="$status" \
  ELAPSED_ENV="$elapsed" \
  FIRST_FINDING_SAMPLE_ENV="$first_finding_sample" \
  DURATION_ENV="$DURATION" \
  TICK_INTERVAL_ENV="$TICK_INTERVAL" \
  SAMPLES_DIR_ENV="$SAMPLES_DIR" \
  RESULT_JSON_ENV="$RESULT_JSON" \
  "$PYTHON" - <<'PY'
import json, os, time

samples = []
samples_dir = os.environ["SAMPLES_DIR_ENV"]
if os.path.isdir(samples_dir):
    for name in sorted(os.listdir(samples_dir)):
        path = os.path.join(samples_dir, name)
        try:
            with open(path, "r", encoding="utf-8") as fh:
                samples.append({"name": name, "findings": json.load(fh)})
        except Exception as exc:
            samples.append({"name": name, "error": str(exc)})

record = {
    "status": os.environ["STATUS_ENV"],
    "duration_s": int(os.environ["DURATION_ENV"]),
    "tick_interval_s": int(os.environ["TICK_INTERVAL_ENV"]),
    "elapsed_s": int(os.environ["ELAPSED_ENV"]),
    "finding_total": int(os.environ["TOTAL_ENV"]),
    "finding_current": int(os.environ["CUR_ENV"]),
    "finding_history": int(os.environ["HIST_ENV"]),
    "first_finding_sample": os.environ["FIRST_FINDING_SAMPLE_ENV"] or None,
    "samples": samples,
    "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
}
with open(os.environ["RESULT_JSON_ENV"], "w", encoding="utf-8") as fh:
    json.dump(record, fh, indent=2)
print(json.dumps({k: record[k] for k in (
    "status",
    "duration_s",
    "elapsed_s",
    "finding_total",
    "finding_current",
    "finding_history",
    "first_finding_sample",
)}, indent=2))
PY
}

log "starting false-positive baseline: duration=${DURATION}s tick_interval=${TICK_INTERVAL}s"
log "abort_on_first_finding=${ABORT_ON_FIRST_FINDING}"
log "output dir: $OUTPUT_DIR_ABS"
log "cli: $EDAMAME_CLI"

start_epoch=$(date +%s)

# Start from a known-empty state: no prior findings, no in-flight FIM events
# left over from an earlier test run on the same daemon.
clear_vuln_history
clear_file_events
force_vuln_tick
sleep 2

total=0
current=0
history=0
sample_count=0
first_finding_sample=""

emit_result() {
  local elapsed=$(( $(date +%s) - start_epoch ))
  if (( total > 0 )); then
    log "FAIL: $total baseline finding(s) observed (current=$current history=$history)"
    log "  first dirty sample: $first_finding_sample"
    write_result_json "fail" "$total" "$current" "$history" "$elapsed" "$first_finding_sample" >&2 || true
    return 1
  fi
  log "PASS: no findings after ${elapsed}s idle"
  write_result_json "pass" 0 0 0 "$elapsed" "" >&2 || true
  return 0
}

while :; do
  now=$(date +%s)
  elapsed=$((now - start_epoch))
  if (( elapsed >= DURATION )); then
    break
  fi
  remaining=$((DURATION - elapsed))
  sleep_for=$TICK_INTERVAL
  (( remaining < sleep_for )) && sleep_for=$remaining
  (( sleep_for > 0 )) && sleep "$sleep_for"

  sample_count=$((sample_count + 1))
  log "  tick ${sample_count}: elapsed=$((elapsed + sleep_for))s / ${DURATION}s"
  force_vuln_tick
  sleep 1
  sample_file="$SAMPLES_DIR/sample_$(printf '%04d' "$sample_count").json"
  if ! sample_findings >"$sample_file"; then
    log "  WARN: sample ${sample_count} failed to collect"
    continue
  fi

  read -r sample_total sample_cur sample_hist < <(count_findings "$sample_file")
  sample_total=${sample_total:-0}
  sample_cur=${sample_cur:-0}
  sample_hist=${sample_hist:-0}

  if (( sample_total > 0 )); then
    total=$sample_total
    current=$sample_cur
    history=$sample_hist
    first_finding_sample=$(basename "$sample_file")
    log "  FINDING in sample ${sample_count}: total=$sample_total current=$sample_cur history=$sample_hist"
    if (( ABORT_ON_FIRST_FINDING == 1 )); then
      log "  aborting early: abort-on-first-finding enabled"
      break
    fi
  fi
done

# Final tick + settle so any just-enqueued finding has a chance to surface.
force_vuln_tick
sleep 2
sample_count=$((sample_count + 1))
sample_file="$SAMPLES_DIR/sample_$(printf '%04d' "$sample_count")_final.json"
sample_findings >"$sample_file" || true

if read -r sample_total sample_cur sample_hist < <(count_findings "$sample_file"); then
  sample_total=${sample_total:-0}
  sample_cur=${sample_cur:-0}
  sample_hist=${sample_hist:-0}
  if (( sample_total > total )); then
    total=$sample_total
    current=$sample_cur
    history=$sample_hist
    [[ -z "$first_finding_sample" ]] && first_finding_sample=$(basename "$sample_file")
    log "  final sweep found additional findings: total=$sample_total"
  fi
fi

if emit_result; then
  exit 0
else
  exit 1
fi
