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
#     [--anomaly-warmup-duration <seconds>] # default: 0 (disabled)
#     [--anomaly-warmup-settle <seconds>]   # default: 15
#
# Environment:
#   EDAMAME_CLI   path to edamame_cli binary (mandatory)
#   PYTHON        path to python3 (default: python3)
#
# Outputs (under --output-dir):
#   baseline.json         full observation record with per-sample findings
#   baseline_ticks.log    stdout/stderr from forced detector ticks
#   baseline_ticks.ndjson one parsed record per forced tick (adjudication
#                         status, mode, raw candidate count)
#   baseline_samples/     per-sample JSON snapshots (for post-hoc triage)
#
# Exit codes:
#   0  no false positives, and the last tick published what it measured
#   1  at least one vulnerability finding was observed in the idle window
#   2  infrastructure error (CLI / RPC failure, missing triggers dir, etc.),
#      or the window is unmeasured: under `llm` adjudication a tick whose
#      model call failed withholds its raw candidates, which reads exactly
#      like a clean host. The last tick (retried) must not be withheld.

set -Euo pipefail

log() { printf '[baseline] %s\n' "$*" >&2; }
die() { log "ERROR: $*"; exit 2; }

TRIGGERS_DIR=""
OUTPUT_DIR=""
DURATION=600
TICK_INTERVAL=60
ABORT_ON_FIRST_FINDING=1
ANOMALY_WARMUP_DURATION=0
ANOMALY_WARMUP_SETTLE=15
ANOMALY_WARMUP_URLS="${ANOMALY_WARMUP_URLS:-https://example.com/,https://example.net/,https://example.org/,https://www.apple.com/}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --triggers-dir)             TRIGGERS_DIR="$2"; shift 2;;
    --output-dir)               OUTPUT_DIR="$2"; shift 2;;
    --duration)                 DURATION="$2"; shift 2;;
    --tick-interval)            TICK_INTERVAL="$2"; shift 2;;
    --abort-on-first-finding)   ABORT_ON_FIRST_FINDING="$2"; shift 2;;
    --anomaly-warmup-duration)  ANOMALY_WARMUP_DURATION="$2"; shift 2;;
    --anomaly-warmup-settle)    ANOMALY_WARMUP_SETTLE="$2"; shift 2;;
    -h|--help) sed -n '2,42p' "$0"; exit 0;;
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
TICK_NDJSON="$OUTPUT_DIR_ABS/baseline_ticks.ndjson"
RESULT_JSON="$OUTPUT_DIR_ABS/baseline.json"
SAMPLES_DIR="$OUTPUT_DIR_ABS/baseline_samples"
mkdir -p "$SAMPLES_DIR"
: >"$TICK_LOG"
: >"$TICK_NDJSON"

call_rpc() {
  "$EDAMAME_CLI" rpc "$@" 2>>"$TICK_LOG"
}

# Force a detector tick and append its parsed record to $TICK_NDJSON. A tick
# that waited on an overlapping one answers without its adjudication fields;
# the detector status carries the same values then.
force_vuln_tick() {
  TRIGGERS_DIR_ENV="$TRIGGERS_DIR" "$PYTHON" - >>"$TICK_NDJSON" 2>>"$TICK_LOG" <<'PY'
import json, os, sys, time
sys.path.insert(0, os.environ["TRIGGERS_DIR_ENV"])
from _edamame_cli import cli_rpc

FIELDS = ("adjudication_status", "adjudication_mode", "raw_candidate_count",
          "active_findings", "active_alertable_findings")
rec = {"at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
try:
    # An adjudicated tick waits on the model (up to its 120 s timeout).
    tick = cli_rpc("debug_run_attack_pattern_detector_tick", timeout=300)
    if isinstance(tick, dict):
        rec.update(tick)
    if not all(k in rec for k in FIELDS):
        status = cli_rpc("get_attack_pattern_detector_status")
        if isinstance(status, dict):
            for k in FIELDS:
                rec.setdefault(k, status.get(k))
except Exception as exc:  # noqa: BLE001
    rec["error"] = str(exc)
print(json.dumps(rec), flush=True)
print(f"[tick] {json.dumps(rec)}", file=sys.stderr)
PY
}

# Exit 0 when the last recorded tick published what it measured: anything
# but a withheld status (`error` / `unavailable`, the core's
# `adjudication_status_is_withheld`) with raw candidates under `llm`.
last_tick_measured() {
  "$PYTHON" - "$TICK_NDJSON" <<'PY'
import json, sys
last = None
with open(sys.argv[1], "r", encoding="utf-8") as fh:
    for line in fh:
        line = line.strip()
        if line:
            try:
                last = json.loads(line)
            except ValueError:
                pass
if not isinstance(last, dict) or last.get("error"):
    raise SystemExit(1)
withheld = (
    str(last.get("adjudication_mode") or "") == "llm"
    and str(last.get("adjudication_status") or "") in ("error", "unavailable")
    and int(last.get("raw_candidate_count") or 0) > 0
)
raise SystemExit(1 if withheld else 0)
PY
}

clear_vuln_history() {
  # Per the edamame_core vuln-persistence invariant, clearing history also
  # invalidates the detector input-hash cache so the next tick re-evaluates
  # live telemetry from a known-empty baseline instead of a stale skip.
  call_rpc clear_attack_pattern_history >>"$TICK_LOG" 2>&1
}

clear_file_events() {
  call_rpc clear_file_events >>"$TICK_LOG" 2>&1
}

# Sample the detector state as JSON on stdout. Returns findings grouped
# into current (get_attack_pattern_findings) vs history (last 50 entries
# of get_attack_pattern_history). A clean idle baseline MUST return
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
    report = cli_rpc("get_attack_pattern_findings")
    out["current"] = _findings(report)
except Exception as exc:
    out["errors"].append(f"get_attack_pattern_findings: {exc}")

try:
    hist = cli_rpc("get_attack_pattern_history", '{"limit": 50}')
    if isinstance(hist, list):
        for entry in hist:
            out["history"].extend(entry.get("findings") or [])
except Exception as exc:
    out["errors"].append(f"get_attack_pattern_history: {exc}")

print(json.dumps(out))
sys.exit(1 if out["errors"] else 0)
PY
}

count_findings() {
  local sample_file="$1"
  "$PYTHON" - "$sample_file" <<'PY'
import json, sys
with open(sys.argv[1], "r", encoding="utf-8") as fh:
    data = json.load(fh)
errors = data.get("errors") or []
if errors:
    raise SystemExit("; ".join(str(e) for e in errors))
current = data.get("current") or []
history = data.get("history") or []
# We treat every finding that has a `check` label as a positive, regardless
# of check type: no stimulus means every finding is a false positive.
cur = sum(1 for f in current if isinstance(f, dict) and f.get("check"))
his = sum(1 for f in history if isinstance(f, dict) and f.get("check"))
print(f"{cur + his} {cur} {his}")
PY
}

run_anomaly_warmup() {
  [[ "$ANOMALY_WARMUP_DURATION" =~ ^[0-9]+$ ]] || die "--anomaly-warmup-duration must be an integer"
  [[ "$ANOMALY_WARMUP_SETTLE" =~ ^[0-9]+$ ]] || die "--anomaly-warmup-settle must be an integer"
  if (( ANOMALY_WARMUP_DURATION <= 0 )); then
    return 0
  fi

  log "running pre-baseline anomaly warm-up: duration=${ANOMALY_WARMUP_DURATION}s settle=${ANOMALY_WARMUP_SETTLE}s"
  if ! ANOMALY_WARMUP_DURATION_ENV="$ANOMALY_WARMUP_DURATION" \
    ANOMALY_WARMUP_URLS_ENV="$ANOMALY_WARMUP_URLS" \
    "$PYTHON" - <<'PY' >>"$TICK_LOG" 2>&1
import os
import sys
import time

try:
    import requests
except Exception as exc:
    print(f"[warmup] requests import failed: {exc}", file=sys.stderr)
    raise SystemExit(1)

duration = int(os.environ["ANOMALY_WARMUP_DURATION_ENV"])
urls = [u.strip() for u in os.environ.get("ANOMALY_WARMUP_URLS_ENV", "").split(",") if u.strip()]
if duration <= 0 or not urls:
    raise SystemExit(0)

deadline = time.monotonic() + duration
successes = 0
attempts = 0
session = requests.Session()

while time.monotonic() < deadline:
    url = urls[attempts % len(urls)]
    attempts += 1
    try:
        resp = session.get(url, timeout=10)
        _ = resp.content[:256]
        successes += 1
        print(f"[warmup] GET {url} -> {resp.status_code}", flush=True)
    except Exception as exc:
        print(f"[warmup] GET {url} failed: {exc}", file=sys.stderr, flush=True)
    time.sleep(1.0)

if successes == 0:
    print("[warmup] no warm-up requests succeeded", file=sys.stderr)
    raise SystemExit(1)

print(f"[warmup] completed: attempts={attempts} successes={successes}", flush=True)
PY
  then
    die "anomaly warm-up failed"
  fi

  if (( ANOMALY_WARMUP_SETTLE > 0 )); then
    log "settling after anomaly warm-up for ${ANOMALY_WARMUP_SETTLE}s"
    sleep "$ANOMALY_WARMUP_SETTLE"
  fi
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
  TICK_NDJSON_ENV="$TICK_NDJSON" \
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

ticks = []
try:
    with open(os.environ["TICK_NDJSON_ENV"], "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                try:
                    ticks.append(json.loads(line))
                except ValueError:
                    ticks.append({"error": "unparsable tick record"})
except OSError:
    pass


def _withheld(t):
    return (
        str(t.get("adjudication_mode") or "") == "llm"
        and str(t.get("adjudication_status") or "") in ("error", "unavailable")
        and int(t.get("raw_candidate_count") or 0) > 0
    )


last = ticks[-1] if ticks else {}
adjudication = {
    "ticks": len(ticks),
    "withheld_ticks": sum(1 for t in ticks if isinstance(t, dict) and _withheld(t)),
    "error_ticks": sum(1 for t in ticks if isinstance(t, dict) and t.get("error")),
    "statuses": sorted({str(t.get("adjudication_status")) for t in ticks
                        if isinstance(t, dict) and t.get("adjudication_status")}),
    "mode": last.get("adjudication_mode") if isinstance(last, dict) else None,
    "last_status": last.get("adjudication_status") if isinstance(last, dict) else None,
    "last_raw_candidates": last.get("raw_candidate_count") if isinstance(last, dict) else None,
    "measured": os.environ["STATUS_ENV"] != "unmeasured",
}

record = {
    "status": os.environ["STATUS_ENV"],
    "duration_s": int(os.environ["DURATION_ENV"]),
    "tick_interval_s": int(os.environ["TICK_INTERVAL_ENV"]),
    "elapsed_s": int(os.environ["ELAPSED_ENV"]),
    "finding_total": int(os.environ["TOTAL_ENV"]),
    "finding_current": int(os.environ["CUR_ENV"]),
    "finding_history": int(os.environ["HIST_ENV"]),
    "first_finding_sample": os.environ["FIRST_FINDING_SAMPLE_ENV"] or None,
    "adjudication": adjudication,
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
    "adjudication",
)}, indent=2))
PY
}

log "starting false-positive baseline: duration=${DURATION}s tick_interval=${TICK_INTERVAL}s"
log "abort_on_first_finding=${ABORT_ON_FIRST_FINDING}"
log "anomaly_warmup_duration=${ANOMALY_WARMUP_DURATION}s anomaly_warmup_settle=${ANOMALY_WARMUP_SETTLE}s"
log "output dir: $OUTPUT_DIR_ABS"
log "cli: $EDAMAME_CLI"

# Detection is off until an operator turns it on (core 2.0: the agentic
# protection switch, off by default). Start the detector, and with it the file
# monitoring it reads, so the idle baseline covers what a protected host runs.
# Idempotent against a daemon where it already runs.
log "starting the attack pattern detector (interval ${DETECTOR_INTERVAL:-60}s)"
call_rpc start_attack_pattern_detector "[true, ${DETECTOR_INTERVAL:-60}]" >>"$TICK_LOG" 2>&1 || true

run_anomaly_warmup

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
  if ! last_tick_measured; then
    log "UNMEASURED: no findings, but the last tick withheld its raw candidates"
    log "  (llm adjudication failed; see $TICK_NDJSON). A withheld tick is not a clean host."
    write_result_json "unmeasured" 0 0 0 "$elapsed" "" >&2 || true
    return 2
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
    die "sample ${sample_count} failed to collect cleanly"
  fi

  if ! read -r sample_total sample_cur sample_hist < <(count_findings "$sample_file"); then
    die "sample ${sample_count} reported RPC/read errors"
  fi
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
# A withheld tick re-reads its evidence on the next one (the FIM window does
# not advance and the input-hash skip is off), so a transient Portal failure
# is retried here rather than read as clean or as a gate failure.
for retry in 1 2 3; do
  last_tick_measured && break
  log "  last tick withheld by llm adjudication; retry ${retry}/3 in 30s"
  sleep 30
  force_vuln_tick
  sleep 2
done
sample_count=$((sample_count + 1))
sample_file="$SAMPLES_DIR/sample_$(printf '%04d' "$sample_count")_final.json"
if ! sample_findings >"$sample_file"; then
  die "final sample failed to collect cleanly"
fi

if ! read -r sample_total sample_cur sample_hist < <(count_findings "$sample_file"); then
  die "final sample reported RPC/read errors"
fi
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

emit_result
exit $?
