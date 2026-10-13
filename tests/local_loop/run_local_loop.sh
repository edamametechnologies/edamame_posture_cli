#!/usr/bin/env bash
# run_local_loop.sh -- close the attack-pattern detection loop on this Mac.
#
# Opens an owned-daemon window (the EDAMAME app and helper stopped, root's
# posture state saved and cleared, a posture built from the workspace started
# as root), runs against it a short idle baseline, the CVE attack scenarios
# with their alertable exports and the agent-free FP-lab scenarios, closes the
# window, then shapes the evidence offline: attack exports into staged
# attack-corpus envelopes (edamame_core/tools/attack_corpus_from_gate.py),
# FP-lab alertables into staged FP candidates. summary.json / summary.md end
# with a one-line verdict.
#
# The window ALWAYS closes: an EXIT trap (Ctrl-C, a failed step, a runner that
# died, the terminal closing) stops the owned daemon, restores root's posture
# state, restarts the helper the way it ran (launchd, or by hand from its
# checkout), relaunches the app from the bundle that ran, and resumes the
# paused LaunchAgents. After a SIGKILL or a reboot, `--restore <out-dir>`
# replays that restore from the state recorded in <out-dir>/window/.
#
# Usage:
#   tests/local_loop/run_local_loop.sh [options]
#   tests/local_loop/run_local_loop.sh --dry-run [options]   # every step; nothing changes
#   tests/local_loop/run_local_loop.sh --restore <out-dir>
#   tests/local_loop/run_local_loop.sh --promote-from <out-dir>
#
# Options:
#   --build                 build posture (make macos_release) and edamame_cli
#                           (cargo build --release) from the workspace first
#   --posture-bin PATH      default: <posture>/target/release/edamame_posture
#                           ($CARGO_TARGET_DIR/release/... when it is set)
#   --cli-bin PATH          default: <workspace>/edamame_cli/target/release/edamame_cli
#   --adjudication MODE     advisory (default: no Portal key, the detector's
#                           grades are published as they are), auto or llm
#                           (both load the Portal key from the secrets)
#   --portal                load the Portal key with advisory too
#   --secrets DIR           default: <workspace>/secrets (agentic.env holds the key)
#   --baseline-secs N       idle baseline window (default 120; 0 skips it)
#   --scenarios CSV         CVE scenarios (default: the runner's full set; none skips)
#   --cve-args "ARGS"       extra run_cve_detection.sh flags ("--trigger-duration 120")
#   --export-matched N      alertable exports per CVE scenario (default 3)
#   --fp-lab-scenarios CSV  FP-lab scenarios (default: every direct scenario for
#                           macOS; none skips)
#   --fp-lab-args "ARGS"    extra run_fp_lab.py run flags
#   --out DIR               default: ~/fp-lab/local-loop/<host>-<time>
#   --promote               copy the staged attack envelopes into
#                           edamame_core/tests/attack_corpus (left uncommitted)
#   --helper-mode MODE      auto (default) | launchd | manual | none
#   --helper-dir DIR        a hand-started helper's checkout (default <workspace>/edamame_helper)
#   --helper-bin PATH       its binary, relative to --helper-dir (default: the running
#                           helper's own path, else target/release/edamame_helper.app/
#                           Contents/MacOS/edamame_helper)
#   --app-bundle PATH       bundle to relaunch (default: the bundle of the running app)
#   --keep-hygiene          leave the cargo-hygiene LaunchAgents running
#
# Environment: PYTHON (default python3), CARGO_TARGET_DIR (builds),
# LOCAL_LOOP_PAUSE_AGENTS (LaunchAgent labels the window pauses).
#
# Exit codes: 0 verdict PASS, 1 FAIL, 2 INCOMPLETE or refused, 3 the restore
# reported a problem (read its lines; `--restore <out-dir>` retries it).

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POSTURE_REPO="$(cd "$HERE/../.." && pwd)"
WORKSPACE="$(cd "$POSTURE_REPO/.." && pwd)"
CORE_REPO="$WORKSPACE/edamame_core"
ROOT_SH="$HERE/window_root.sh"
SUMMARY_PY="$HERE/local_loop_summary.py"
TRIGGERS_SRC="$POSTURE_REPO/tests/security/triggers"
SHAPER="$CORE_REPO/tools/attack_corpus_from_gate.py"
CORPUS_DIR="$CORE_REPO/tests/attack_corpus"

APP_NAME="EDAMAME Security"
HELPER_LABEL="com.edamametechnologies.edamame-helper"
HELPER_PLIST="/Library/LaunchDaemons/$HELPER_LABEL.plist"
DEFAULT_HELPER_BIN="target/release/edamame_helper.app/Contents/MacOS/edamame_helper"
# The cargo-hygiene jobs of this Mac: with the debug app down, the hourly one
# runs `edamame_app make clean`, which deleted the app's debug build in the
# middle of a window (2026-10-11).
PAUSE_AGENTS="${LOCAL_LOOP_PAUSE_AGENTS:-tech.edamame.cargo-hygiene tech.edamame.cargo-hygiene-lowwater}"
LOCK_DIR="$HOME/fp-lab/local-loop/.window"
# Through 2.0.4 an edamame_cli one-shot removed the app's Portal key and Hub
# PIN from the shared file secret store (fixed in core 2.0.5).
MIN_CLI_VERSION="2.0.5"
PYTHON="${PYTHON:-python3}"

BUILD=0
POSTURE_BIN=""
CLI_BIN=""
ADJUDICATION="advisory"
PORTAL=0
SECRETS="$WORKSPACE/secrets"
BASELINE_SECS=120
SCENARIOS=""
CVE_ARGS=""
EXPORT_MATCHED=3
FP_LAB_SCENARIOS=""
FP_LAB_ARGS=""
OUT=""
PROMOTE=0
HELPER_MODE_OPT="auto"
HELPER_DIR="$WORKSPACE/edamame_helper"
HELPER_BIN_OPT=""
APP_BUNDLE_OPT=""
KEEP_HYGIENE=0
DRY_RUN=0
MODE="run"
MODE_DIR=""

LOG_FILE=""
say() {
  printf '[loop] %s\n' "$*" >&2
  if [[ -n "$LOG_FILE" ]]; then printf '%s %s\n' "$(date -u +%H:%M:%S)" "$*" >>"$LOG_FILE"; fi
  return 0
}
die() { say "ERROR: $*"; exit 2; }
banner() { printf '\n' >&2; say "=== $* ==="; }
q() { local out="" a; for a in "$@"; do out+=" $(printf '%q' "$a")"; done; printf '%s' "${out# }"; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --build)             BUILD=1; shift;;
    --posture-bin)       POSTURE_BIN="$2"; shift 2;;
    --cli-bin)           CLI_BIN="$2"; shift 2;;
    --adjudication)      ADJUDICATION="$2"; shift 2;;
    --portal)            PORTAL=1; shift;;
    --secrets)           SECRETS="$2"; shift 2;;
    --baseline-secs)     BASELINE_SECS="$2"; shift 2;;
    --scenarios)         SCENARIOS="$2"; shift 2;;
    --cve-args)          CVE_ARGS="$2"; shift 2;;
    --export-matched)    EXPORT_MATCHED="$2"; shift 2;;
    --fp-lab-scenarios)  FP_LAB_SCENARIOS="$2"; shift 2;;
    --fp-lab-args)       FP_LAB_ARGS="$2"; shift 2;;
    --out)               OUT="$2"; shift 2;;
    --promote)           PROMOTE=1; shift;;
    --helper-mode)       HELPER_MODE_OPT="$2"; shift 2;;
    --helper-dir)        HELPER_DIR="$2"; shift 2;;
    --helper-bin)        HELPER_BIN_OPT="$2"; shift 2;;
    --app-bundle)        APP_BUNDLE_OPT="$2"; shift 2;;
    --keep-hygiene)      KEEP_HYGIENE=1; shift;;
    --dry-run)           DRY_RUN=1; shift;;
    --restore)           MODE="restore"; MODE_DIR="$2"; shift 2;;
    --promote-from)      MODE="promote"; MODE_DIR="$2"; shift 2;;
    -h|--help)           sed -n '2,/^$/p' "$0"; exit 0;;
    *)                   die "unknown flag: $1 (see --help)";;
  esac
done

case "$ADJUDICATION" in
  advisory) ;;
  auto|llm) PORTAL=1 ;;
  *) die "--adjudication must be advisory, auto or llm (the FP lab refuses deterministic)" ;;
esac
for n in "$BASELINE_SECS" "$EXPORT_MATCHED"; do
  [[ "$n" =~ ^[0-9]+$ ]] || die "--baseline-secs and --export-matched take a non-negative integer"
done
case "$HELPER_MODE_OPT" in auto|launchd|manual|none) ;; *) die "--helper-mode: auto, launchd, manual or none" ;; esac
[[ "$(uname -s)" == "Darwin" ]] || die "macOS only: Linux and Windows hosts run the window with tests/fp_lab/deploy_owned_posture.sh"
(( EUID != 0 )) || die "run as the console user: the loop asks sudo for the root steps, and the FP lab refuses root"

abs_path() { case "$1" in /*) printf '%s' "$1" ;; *) printf '%s/%s' "$PWD" "$1" ;; esac; }
TARGET_ROOT="${CARGO_TARGET_DIR:-}"
[[ -n "$POSTURE_BIN" ]] || POSTURE_BIN="${TARGET_ROOT:-$POSTURE_REPO/target}/release/edamame_posture"
[[ -n "$CLI_BIN" ]] || CLI_BIN="${TARGET_ROOT:-$WORKSPACE/edamame_cli/target}/release/edamame_cli"
POSTURE_BIN="$(abs_path "$POSTURE_BIN")"
CLI_BIN="$(abs_path "$CLI_BIN")"
USER_HOME="$HOME"
HOST_SHORT="$(hostname -s 2>/dev/null || hostname)"
STAMP="$(date +%Y%m%d-%H%M%S)"
case "$(uname -m)" in arm64|aarch64) ARCH=arm64 ;; x86_64) ARCH=x64 ;; *) ARCH="$(uname -m)" ;; esac
PLATFORM_LABEL="macos-$ARCH"
RUN_LABEL="local-$HOST_SHORT-$STAMP"
[[ -n "$OUT" ]] || OUT="$HOME/fp-lab/local-loop/$HOST_SHORT-$STAMP"
OUT="$(abs_path "$OUT")"

# ── actions ─────────────────────────────────────────────────────────────

act() {  # act <cmd...>: print it, run it unless --dry-run
  say "+ $(q "$@")"
  (( DRY_RUN )) && return 0
  "$@"
}

as_root() {  # as_root <window_root.sh command> [args...]
  say "+ sudo -H bash $(q "$ROOT_SH" "$@")"
  (( DRY_RUN )) && return 0
  sudo -H bash "$ROOT_SH" "$@"
}

record_step() {  # record_step <name> <status> <rc> <seconds> [log]
  (( DRY_RUN )) && return 0
  printf '%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "${5:-}" >>"$OUT/steps.tsv"
}

record() {  # record <key> <value>: one row of window.tsv
  (( DRY_RUN )) && return 0
  [[ -d "$OUT" ]] || return 0
  printf '%s\t%s\n' "$1" "$(printf '%s' "$2" | tr '\t\n' '  ')" >>"$OUT/window.tsv"
}

run_step() {  # run_step <name> <log> <cmd...>: the step's output to the terminal and its log
  local name="$1" log="$2" start rc
  shift 2
  banner "$name"
  say "+ $(q "$@")"
  (( DRY_RUN )) && return 0
  start=$SECONDS
  "$@" 2>&1 | tee "$log"
  rc=${PIPESTATUS[0]}
  record_step "$name" "$( ((rc == 0)) && echo ok || echo exit)" "$rc" "$((SECONDS - start))" "$log"
  say "$name: exit $rc after $((SECONDS - start)) s"
  return "$rc"
}

port_listening() { /usr/sbin/netstat -an -p tcp | grep LISTEN | grep -q "\\.$1 "; }
app_running() { pgrep -x "$APP_NAME" >/dev/null; }
helper_running() { pgrep -x edamame_helper >/dev/null; }
agent_loaded() { launchctl print "gui/$(id -u)/$1" >/dev/null 2>&1; }

version_at_least() {  # version_at_least <x.y.z> <min>
  local a b c x y z
  IFS=. read -r a b c <<<"$1"
  IFS=. read -r x y z <<<"$2"
  a=${a//[^0-9]/}; b=${b//[^0-9]/}; c=${c//[^0-9]/}
  (( ${a:-0} != x )) && { (( ${a:-0} > x )); return; }
  (( ${b:-0} != y )) && { (( ${b:-0} > y )); return; }
  (( ${c:-0} >= z ))
}

# ── what runs on this Mac now ───────────────────────────────────────────

APP_PID=""
APP_BUNDLE=""
HELPER_MODE="none"
HELPER_PID=""
HELPER_BIN=""
HELPER_CMD=""
HYGIENE_PAUSED=""
STARTED_EPOCH=""
PROBLEMS=()
problem() { PROBLEMS+=("$*"); say "$( ((DRY_RUN)) && echo 'WOULD REFUSE' || echo 'REFUSED'): $*"; }

detect_host_state() {
  APP_PID="$(pgrep -x "$APP_NAME" | head -n 1)"
  if [[ -n "$APP_BUNDLE_OPT" ]]; then
    APP_BUNDLE="$(abs_path "$APP_BUNDLE_OPT")"
  elif [[ -n "$APP_PID" ]]; then
    local exe
    exe="$(ps -o comm= -p "$APP_PID")"
    case "$exe" in
      /*.app/Contents/MacOS/*) APP_BUNDLE="${exe%%.app/Contents/MacOS/*}.app" ;;
      *) problem "the app runs (pid $APP_PID, $exe) but its bundle is unknown: pass --app-bundle" ;;
    esac
  fi
  if [[ -n "$APP_PID" ]]; then
    local version
    version="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$APP_BUNDLE/Contents/Info.plist" 2>/dev/null)"
    say "app: running, pid $APP_PID, bundle $APP_BUNDLE (version ${version:-?}); relaunched from that bundle after the window"
    [[ -d "$APP_BUNDLE" ]] || problem "app bundle $APP_BUNDLE does not exist: it could not be relaunched"
  else
    say "app: not running (nothing to relaunch)"
  fi

  HELPER_PID="$(pgrep -x edamame_helper | head -n 1)"
  [[ -n "$HELPER_PID" ]] && HELPER_CMD="$(ps -o command= -p "$HELPER_PID")"
  local helper_loaded=0
  launchctl print "system/$HELPER_LABEL" >/dev/null 2>&1 && helper_loaded=1
  HELPER_MODE="$HELPER_MODE_OPT"
  if [[ "$HELPER_MODE" == auto ]]; then
    if (( helper_loaded )); then
      HELPER_MODE="launchd"
    elif [[ -n "$HELPER_PID" ]]; then
      HELPER_MODE="manual"
    else
      HELPER_MODE="none"
    fi
  fi
  # The window restores what ran, nothing more: a forced mode with no helper
  # behind it has nothing to stop or restart.
  if [[ "$HELPER_MODE" == launchd ]] && (( ! helper_loaded )); then HELPER_MODE="none"; fi
  if [[ "$HELPER_MODE" == manual && -z "$HELPER_PID" ]]; then HELPER_MODE="none"; fi
  case "$HELPER_MODE" in
    launchd)
      say "helper: launchd job $HELPER_LABEL (pid ${HELPER_PID:-none}); disabled and booted out, then enabled and bootstrapped"
      [[ -f "$HELPER_PLIST" ]] || problem "no $HELPER_PLIST: the helper could not be bootstrapped again"
      ;;
    manual)
      HELPER_BIN="$HELPER_BIN_OPT"
      if [[ -z "$HELPER_BIN" && -n "$HELPER_PID" ]]; then
        HELPER_BIN="$(ps -o comm= -p "$HELPER_PID")"
      fi
      [[ -n "$HELPER_BIN" ]] || HELPER_BIN="$DEFAULT_HELPER_BIN"
      say "helper: started by hand (pid ${HELPER_PID:-none}: ${HELPER_CMD:-?}); restarted as root from $HELPER_DIR with $HELPER_BIN"
      case "$HELPER_BIN" in
        /*) [[ -x "$HELPER_BIN" ]] || problem "helper binary $HELPER_BIN is not executable: the helper could not be restarted" ;;
        *) [[ -x "$HELPER_DIR/$HELPER_BIN" ]] || problem "helper binary $HELPER_DIR/$HELPER_BIN is not executable: the helper could not be restarted (--helper-dir / --helper-bin)" ;;
      esac
      ;;
    none) say "helper: not running (nothing to restart)" ;;
  esac

  local label pid
  for label in $PAUSE_AGENTS; do
    (( KEEP_HYGIENE )) && break
    agent_loaded "$label" || continue
    [[ -f "$HOME/Library/LaunchAgents/$label.plist" ]] || { say "LaunchAgent $label: loaded, no plist under ~/Library/LaunchAgents; left alone"; continue; }
    pid="$(launchctl print "gui/$(id -u)/$label" 2>/dev/null | sed -n 's/^[[:space:]]*pid = \([0-9]*\).*/\1/p' | head -n 1)"
    [[ -n "$pid" ]] && problem "LaunchAgent $label is running a job now (pid $pid): retry when it is done"
    say "LaunchAgent $label: paused for the window"
  done

  if pgrep -x edamame_posture >/dev/null; then
    problem "a posture daemon already runs ($(pgrep -lx edamame_posture | tr '\n' ' '))"
  fi
  for port in 40151 40152; do
    if port_listening "$port"; then say "port $port: listening now (freed by the window)"; fi
  done
}

check_prerequisites() {
  [[ -f "$ROOT_SH" ]] || problem "missing $ROOT_SH"
  [[ -d "$TRIGGERS_SRC" ]] || problem "missing $TRIGGERS_SRC"
  [[ -f "$SHAPER" ]] || problem "missing $SHAPER (edamame_core checkout)"
  command -v "$PYTHON" >/dev/null || problem "no $PYTHON"
  "$PYTHON" -c 'import requests' 2>/dev/null || problem "$PYTHON has no requests module (the triggers need it: $PYTHON -m pip install requests)"
  command -v jq >/dev/null || say "warning: no jq; FP-lab alertables are exported but not shaped into candidates"
  if (( BUILD )); then
    say "posture: built from $POSTURE_REPO -> $POSTURE_BIN"
    say "edamame_cli: built from $WORKSPACE/edamame_cli -> $CLI_BIN"
    local branch
    branch="$(git -C "$POSTURE_REPO" rev-parse --abbrev-ref HEAD 2>/dev/null)"
    case "$branch" in
      main|master|dev) ;;
      *)
        # VERGEN_GIT_BRANCH is compiled in: any other branch talks to the
        # DEV backends, where the production Portal key fails.
        if (( PORTAL )); then
          problem "posture is on branch '$branch': a build from it talks to the dev backends and the Portal key would fail (build from main, or drop the Portal)"
        else
          say "warning: posture is on branch '$branch': the build talks to the dev backends"
        fi
        ;;
    esac
  else
    [[ -x "$POSTURE_BIN" ]] || problem "no posture binary at $POSTURE_BIN (--build, or --posture-bin)"
    [[ -x "$CLI_BIN" ]] || problem "no edamame_cli at $CLI_BIN (--build, or --cli-bin)"
  fi
  if (( ! BUILD )) && [[ -x "$CLI_BIN" ]]; then
    local cli_version
    cli_version="$("$CLI_BIN" --version 2>/dev/null | awk '{print $NF}' | head -n 1)"
    if version_at_least "${cli_version:-0}" "$MIN_CLI_VERSION"; then
      say "edamame_cli: $CLI_BIN ($cli_version)"
    else
      problem "edamame_cli $cli_version at $CLI_BIN is older than $MIN_CLI_VERSION: it would erase the app's stored credentials"
    fi
  fi
  if [[ -x "$POSTURE_BIN" ]] && ! codesign -d --entitlements - "$POSTURE_BIN" 2>/dev/null | grep -q endpoint-security; then
    say "note: $POSTURE_BIN carries no Endpoint Security entitlement (a plain cargo build): no ES client, so FIM runs on FSEvents and the macOS task-port route of process_memory_scrape / agent_memory_scrape is absent"
  fi
  if (( PORTAL )); then
    if [[ -f "$SECRETS/agentic.env" ]] && grep -qE '^(export[[:space:]]+)?EDAMAME_LLM_API_KEY=.' "$SECRETS/agentic.env"; then
      say "Portal: key from $SECRETS/agentic.env, read by the root step only (never printed)"
    else
      problem "no EDAMAME_LLM_API_KEY in $SECRETS/agentic.env (needed by --adjudication $ADJUDICATION / --portal)"
    fi
  fi
  if [[ -e "$LOCK_DIR" ]]; then
    problem "a local-loop window is recorded open ($(cat "$LOCK_DIR/out" 2>/dev/null || echo '?')): close it with --restore <out-dir>"
  fi
  if [[ -e "$OUT" ]] && [[ -n "$(ls -A "$OUT" 2>/dev/null)" ]]; then
    problem "output directory $OUT is not empty"
  fi
}

# ── the window ──────────────────────────────────────────────────────────

WINDOW_OPEN=0
RESTORE_DONE=0
RESTORE_PROBLEMS=0
KEEPALIVE_PID=""
CORE_VERSION=""

write_pre_state() {
  (( DRY_RUN )) && return 0
  local var
  {
    printf '# run_local_loop.sh window state, read by: run_local_loop.sh --restore %s\n' "$OUT"
    for var in OUT APP_PID APP_BUNDLE HELPER_MODE HELPER_PID HELPER_DIR HELPER_BIN HELPER_CMD \
               HYGIENE_PAUSED POSTURE_BIN CLI_BIN USER_HOME STARTED_EPOCH; do
      printf '%s=%q\n' "$var" "${!var}"
    done
  } >"$OUT/window/pre-state.env"
}

start_sudo_keepalive() {
  (( DRY_RUN )) && return 0
  # The restore and the memory-scrape trigger's `sudo -n` need the
  # credentials hours after the prompt.
  ( while kill -0 "$MAIN_PID" 2>/dev/null; do sudo -n -v 2>/dev/null; sleep 50; done ) &
  KEEPALIVE_PID=$!
}

wait_for_daemon() {
  local answer=""
  for _ in $(seq 1 180); do
    answer="$("$CLI_BIN" rpc get_core_version 2>/dev/null | sed -n 's/^Result: //p' | tr -d '"')"
    [[ -n "$answer" ]] && { CORE_VERSION="$answer"; return 0; }
    sleep 1
  done
  return 1
}

open_window() {
  banner "opening the owned-daemon window"
  act sudo -v || die "sudo refused"
  start_sudo_keepalive
  as_root check || die "the root check refused the window (above)"
  # From here on the restore runs on any exit.
  if (( ! DRY_RUN )); then
    mkdir -p "$(dirname "$LOCK_DIR")" "$OUT/window"
    mkdir "$LOCK_DIR" 2>/dev/null || die "another local-loop window just opened ($LOCK_DIR)"
    printf '%s\n' "$OUT" >"$LOCK_DIR/out"
  fi
  WINDOW_OPEN=1
  STARTED_EPOCH="$(date +%s)"
  write_pre_state
  record started_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  local label
  for label in $PAUSE_AGENTS; do
    (( KEEP_HYGIENE )) && break
    if agent_loaded "$label" && [[ -f "$HOME/Library/LaunchAgents/$label.plist" ]]; then
      if act launchctl bootout "gui/$(id -u)/$label"; then
        HYGIENE_PAUSED="${HYGIENE_PAUSED:+$HYGIENE_PAUSED }$label"
        write_pre_state
      fi
    fi
  done

  if [[ -n "$APP_PID" ]]; then
    act kill -TERM "$APP_PID" || act sudo kill -TERM "$APP_PID"
    if (( ! DRY_RUN )); then
      for _ in $(seq 1 20); do app_running || break; sleep 1; done
      if app_running; then kill -KILL "$APP_PID" 2>/dev/null || sudo kill -KILL "$APP_PID"; sleep 2; fi
      app_running && die "the app is still running"
    fi
  fi
  case "$HELPER_MODE" in
    launchd) as_root stop-helper launchd "$HELPER_LABEL" || die "the helper did not stop" ;;
    manual) [[ -z "$HELPER_PID" ]] || as_root stop-helper pid "$HELPER_PID" || die "the helper did not stop" ;;
  esac
  say "+ check that ports 40151 and 40152 are free"
  if (( ! DRY_RUN )); then
    for port in 40151 40152; do
      port_listening "$port" && die "port $port is still held after the app and the helper stopped"
    done
  fi
  as_root save-state || die "could not save root's posture state"
  if (( PORTAL )); then
    as_root start-posture "$POSTURE_BIN" "$USER_HOME" "$SECRETS/agentic.env" || die "the owned posture did not start"
  else
    as_root start-posture "$POSTURE_BIN" "$USER_HOME" || die "the owned posture did not start"
  fi
  say "+ wait up to 180 s for the owned daemon on 127.0.0.1:40152 ($(q "$CLI_BIN") rpc get_core_version), then 20 s for protection, capture and the file monitor"
  if (( ! DRY_RUN )); then
    wait_for_daemon || die "the owned daemon did not answer within 180 s"
    say "owned daemon: core $CORE_VERSION, pid(s) $(pgrep -x edamame_posture | tr '\n' ' ')"
    record core_version "$CORE_VERSION"
    record daemon_pids "$(pgrep -x edamame_posture | tr '\n' ' ')"
    sleep 20
  fi
  # A plain cargo build has no Endpoint Security entitlement: the log says
  # whether this daemon got an ES client (FIM writer attribution, task-port
  # events) or runs on FSEvents and polling.
  if (( DRY_RUN )); then
    as_root es-status
  else
    record es_status "$(as_root es-status 2>/dev/null | tr '\n' '|')"
    say "Endpoint Security: $(tail -n 1 "$OUT/window.tsv" | cut -f2-)"
  fi
  # --agentic-mode analyze pins llm when the setting is auto; the loop's mode
  # replaces it on both engines. A managed lock refuses with success false.
  local method reply
  for method in set_attack_pattern_adjudication_mode set_divergence_adjudication_mode; do
    reply="$(act "$CLI_BIN" rpc "$method" "{\"mode\": \"$ADJUDICATION\"}")"
    (( DRY_RUN )) && continue
    record "$method" "$(printf '%s' "$reply" | sed -n 's/^Result: //p')"
    # shellcheck disable=SC1003 # tr deletes the backslashes of a string result
    printf '%s' "$reply" | tr -d '\\' | grep -q '"success": *true' || say "warning: $method did not succeed: $reply"
  done
  if (( ! DRY_RUN )); then
    record detector_status "$("$CLI_BIN" rpc get_attack_pattern_detector_status 2>/dev/null | sed -n 's/^Result: //p')"
  fi
}

restore_host() {
  local problems=0 label pids
  # A trigger an interrupted CVE step left running, and the demo files the
  # triggers wrote (cleanup.py: their pid files and created-file markers).
  if (( DRY_RUN )) || [[ -d "$OUT/triggers" ]]; then
    pids="$(pgrep -f -- "$OUT/triggers/trigger_" 2>/dev/null | tr '\n' ' ')"
    if [[ -n "${pids// /}" ]]; then
      # shellcheck disable=SC2086 # a pid list
      act kill -TERM $pids
      if (( ! DRY_RUN )); then
        sleep 2
        # shellcheck disable=SC2086
        kill -KILL $pids 2>/dev/null
      fi
    fi
    say "+ $(q "$PYTHON" "$OUT/triggers/cleanup.py" --agent-type openclaw)"
    (( DRY_RUN )) || "$PYTHON" "$OUT/triggers/cleanup.py" --agent-type openclaw >/dev/null 2>&1
  fi
  as_root stop-posture "$POSTURE_BIN" "$USER_HOME" || problems=1
  as_root collect-logs "$OUT/daemon-logs" "$(id -un)" "${STARTED_EPOCH:-0}" || true
  as_root restore-state || problems=1
  case "$HELPER_MODE" in
    launchd)
      if (( DRY_RUN )) || ! helper_running || ! launchctl print "system/$HELPER_LABEL" >/dev/null 2>&1; then
        as_root start-helper launchd "$HELPER_LABEL" "$HELPER_PLIST" || problems=1
      fi
      ;;
    manual)
      if (( DRY_RUN )) || ! helper_running; then
        as_root start-helper manual "$HELPER_DIR" "$HELPER_BIN" "$USER_HOME" || problems=1
      fi
      ;;
  esac
  if [[ -n "$APP_BUNDLE" && -n "$APP_PID" ]] && { (( DRY_RUN )) || ! app_running; }; then
    act open "$APP_BUNDLE" || problems=1
    if (( ! DRY_RUN )); then
      for _ in $(seq 1 60); do app_running && port_listening 40152 && break; sleep 2; done
      local pid home
      pid="$(pgrep -x "$APP_NAME" | head -n 1)"
      if [[ -n "$pid" ]]; then
        home="$(ps -E -p "$pid" -o command= 2>/dev/null | tr ' ' '\n' | sed -n 's/^HOME=//p' | head -n 1)"
        say "app: running (pid $pid, HOME ${home:-unknown})"
        [[ -z "$home" || "$home" == "$USER_HOME" ]] || { say "app HOME is $home, not $USER_HOME: quit it and relaunch it from the Dock"; problems=1; }
      else
        say "app: NOT RUNNING"; problems=1
      fi
    fi
  fi
  for label in $HYGIENE_PAUSED; do
    if (( DRY_RUN )) || ! agent_loaded "$label"; then
      act launchctl bootstrap "gui/$(id -u)" "$HOME/Library/LaunchAgents/$label.plist" || problems=1
    fi
  done
  if (( DRY_RUN )); then
    say "+ verify: the app on 40152, the helper on 40151, the app's connection and protection"
  else
    if port_listening 40151; then
      say "port 40151: listening"
    elif [[ "$HELPER_MODE" != none ]]; then
      say "port 40151: NOT LISTENING"; problems=1
    fi
    if port_listening 40152; then
      say "port 40152: listening"
    elif [[ -n "$APP_PID" ]]; then
      say "port 40152: NOT LISTENING"; problems=1
    fi
    # Never only "app: running": an app relaunched with the wrong HOME came
    # back signed out of the Hub and the Portal.
    if [[ -n "$APP_PID" ]] && [[ -x "$CLI_BIN" ]]; then
      local method
      for method in get_core_version get_connection agentic_get_protection_status; do
        # shellcheck disable=SC1003 # tr deletes the backslashes of a string result
        say "app $method: $("$CLI_BIN" rpc "$method" 2>/dev/null | sed -n 's/^Result: //p' | tr -d '\\' \
          | grep -oE 'Core version is [^,]*|"(is_connected|connected_domain|enabled)": ?[^,}]*|^"?[0-9][^"]*"?$' | tr '\n' ' ')"
      done
    fi
    [[ -n "$KEEPALIVE_PID" ]] && kill "$KEEPALIVE_PID" 2>/dev/null
    if [[ "$(cat "$LOCK_DIR/out" 2>/dev/null)" == "$OUT" ]]; then rm -rf "$LOCK_DIR"; fi
    record closed_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    record restore_problems "$problems"
  fi
  RESTORE_PROBLEMS=$problems
  if (( problems )); then
    say "the restore reported a problem (above); retry with: $(q "$0") --restore $(q "$OUT")"
  fi
  return 0
}

close_window() {
  (( WINDOW_OPEN )) || return 0
  (( RESTORE_DONE )) && return 0
  RESTORE_DONE=1
  trap '' INT TERM HUP
  banner "closing the window (Ctrl-C is ignored until the app and the helper are back)"
  restore_host
  trap 'on_signal INT' INT
  trap 'on_signal TERM' TERM
  trap 'on_signal HUP' HUP
}

MAIN_PID=$$
# shellcheck disable=SC2329 # the signal and EXIT traps call these
on_signal() { say "caught SIG$1"; record interrupted "SIG$1"; exit 130; }
SUMMARY_DONE=0
# shellcheck disable=SC2329
finish() {
  local rc=$?
  close_window
  # A run that died after it started still leaves its summary (INCOMPLETE,
  # with what it measured before).
  if [[ "$MODE" == run ]] && (( ! DRY_RUN && ! SUMMARY_DONE )) && [[ -f "$OUT/window.tsv" ]]; then
    SUMMARY_DONE=1
    "$PYTHON" -I "$SUMMARY_PY" "$OUT" >&2 || true
  fi
  if (( RESTORE_PROBLEMS )); then exit 3; fi
  exit "$rc"
}

# ── modes without a window ──────────────────────────────────────────────

promote_envelopes() {  # promote_envelopes <loop out dir>
  local src="$1/staging/attack_corpus" f rel count=0
  if (( DRY_RUN )) && [[ ! -d "$src" ]]; then
    say "+ cp $(q "$src")/<scenario>/<envelope>.json $(q "$CORPUS_DIR")/<scenario>/   (every staged envelope)"
    return 0
  fi
  if [[ ! -d "$src" ]]; then say "no staged envelopes in $src"; return 0; fi
  while IFS= read -r -d '' f; do
    rel="${f#"$src"/}"
    act mkdir -p "$CORPUS_DIR/$(dirname "$rel")"
    act cp "$f" "$CORPUS_DIR/$rel"
    count=$((count + 1))
  done < <(find "$src" -mindepth 2 -maxdepth 2 -name '*.json' -print0)
  say "$( ((DRY_RUN)) && echo 'would promote' || echo 'promoted') $count envelope(s) into $CORPUS_DIR (not committed); replay them: (cd $(q "$CORE_REPO") && tools/fp_loop/offline_gate.sh --quick)"
}

if [[ "$MODE" == "promote" ]]; then
  promote_envelopes "$(abs_path "$MODE_DIR")"
  exit 0
fi

if [[ "$MODE" == "restore" ]]; then
  OUT="$(abs_path "$MODE_DIR")"
  [[ -f "$OUT/window/pre-state.env" ]] || die "no $OUT/window/pre-state.env"
  # shellcheck disable=SC1091 # written by this script with printf %q
  source "$OUT/window/pre-state.env"
  (( DRY_RUN )) || LOG_FILE="$OUT/loop.log"
  trap finish EXIT
  trap 'on_signal INT' INT
  trap 'on_signal TERM' TERM
  trap 'on_signal HUP' HUP
  act sudo -v || die "sudo refused"
  start_sudo_keepalive
  WINDOW_OPEN=1
  close_window
  exit 0
fi

# ── the run ─────────────────────────────────────────────────────────────

banner "local loop $HOST_SHORT-$STAMP$( ((DRY_RUN)) && echo ' (dry run: nothing is stopped, started or written)')"
say "workspace: $WORKSPACE"
say "output: $OUT"
say "adjudication: $ADJUDICATION, Portal: $( ((PORTAL)) && echo yes || echo no)"
check_prerequisites
detect_host_state

if [[ -z "$FP_LAB_SCENARIOS" ]]; then
  # The catalog's own list: every agent-free scenario that runs on macOS.
  FP_LAB_SCENARIOS="$("$PYTHON" -I -c 'import sys; sys.path.insert(0, sys.argv[1]); from scenarios import SCENARIOS; print(",".join(s.id for s in SCENARIOS if s.kind == "direct" and "macos" in s.platforms))' "$POSTURE_REPO/tests/fp_lab" 2>/dev/null)"
  [[ -n "$FP_LAB_SCENARIOS" ]] || problem "could not read the FP-lab direct scenarios from tests/fp_lab/scenarios.py"
fi
if [[ -n "$SCENARIOS" ]]; then
  say "CVE scenarios: $SCENARIOS"
else
  default_count="$(sed -n 's/^SCENARIOS_CSV="\(.*\)"$/\1/p' "$POSTURE_REPO/tests/security/run_cve_detection.sh" | tr ',' '\n' | grep -c .)"
  say "CVE scenarios: the runner's full set ($default_count)"
fi
say "FP-lab scenarios: $FP_LAB_SCENARIOS"

if (( ${#PROBLEMS[@]} )); then
  say "${#PROBLEMS[@]} problem(s) above: $( ((DRY_RUN)) && echo 'a real run would refuse' || echo 'nothing was changed')"
  (( DRY_RUN )) || exit 2
fi

if (( ! DRY_RUN )); then
  mkdir -p "$OUT/window" "$OUT/build" "$OUT/staging"
  LOG_FILE="$OUT/loop.log"
  record host "$HOST_SHORT"
  record platform_label "$PLATFORM_LABEL"
  record run_label "$RUN_LABEL"
  record adjudication "$ADJUDICATION"
  record portal "$( ((PORTAL)) && echo yes || echo no)"
  record posture_bin "$POSTURE_BIN"
  record cli_bin "$CLI_BIN"
  record helper_mode "$HELPER_MODE"
  record app_bundle "$APP_BUNDLE"
fi
trap finish EXIT
trap 'on_signal INT' INT
trap 'on_signal TERM' TERM
trap 'on_signal HUP' HUP

# shellcheck disable=SC2329 # run_step calls it
build_in() {  # build_in <dir> <cmd...>: in a subshell with the compile-time (envc!) variables, never printed
  (
    for f in foundation lambda-signature sentry analytics; do
      # shellcheck disable=SC1090 # the operator's secrets
      if [[ -f "$SECRETS/$f.env" ]]; then set -a; . "$SECRETS/$f.env"; set +a; fi
    done
    cd "$1" || exit 2
    shift
    "$@"
  )
}
if (( BUILD )); then
  run_step build_posture "$OUT/build/posture.log" build_in "$POSTURE_REPO" make macos_release \
    || die "the posture build failed ($OUT/build/posture.log)"
  run_step build_cli "$OUT/build/cli.log" build_in "$WORKSPACE/edamame_cli" cargo build --release \
    || die "the edamame_cli build failed ($OUT/build/cli.log)"
  if (( ! DRY_RUN )); then
    [[ -x "$POSTURE_BIN" && -x "$CLI_BIN" ]] || die "the builds did not produce $POSTURE_BIN and $CLI_BIN"
    cli_version="$("$CLI_BIN" --version 2>/dev/null | awk '{print $NF}' | head -n 1)"
    version_at_least "${cli_version:-0}" "$MIN_CLI_VERSION" || die "edamame_cli $cli_version is older than $MIN_CLI_VERSION"
  fi
fi
(( DRY_RUN )) || record posture_sha256 "$(shasum -a 256 "$POSTURE_BIN" | cut -d' ' -f1)"

open_window

act mkdir -p "$OUT/triggers"
act cp -R "$TRIGGERS_SRC/." "$OUT/triggers/"
act rm -rf "$OUT/triggers/__pycache__"
# The runners and the triggers they spawn need no credential: the operator's
# shell may export the Portal key and a Hub PIN, which reach the daemon only
# through the root step.
RUNNER_ENV=(env -u EDAMAME_LLM_API_KEY -u EDAMAME_PIN
            "EDAMAME_CLI=$CLI_BIN" "EDAMAME_CLI_BIN=$CLI_BIN" "PYTHON=$PYTHON")

if (( BASELINE_SECS > 0 )); then
  # A dev Mac is not an idle runner: ambient findings are recorded and the
  # loop goes on (CI skips the CVE suite on a dirty baseline).
  tick=60; (( BASELINE_SECS < 300 )) && tick=30
  run_step baseline "$OUT/baseline.log" "${RUNNER_ENV[@]}" bash "$POSTURE_REPO/tests/security/run_false_positive_baseline.sh" \
    --triggers-dir "$OUT/triggers" --output-dir "$OUT/baseline" \
    --duration "$BASELINE_SECS" --tick-interval "$tick" --abort-on-first-finding 0
else
  say "baseline: skipped (--baseline-secs 0)"
  record_step baseline skipped 0 0
fi

if [[ "$SCENARIOS" != "none" ]]; then
  cve_cmd=("${RUNNER_ENV[@]}" bash "$POSTURE_REPO/tests/security/run_cve_detection.sh"
           --triggers-dir "$OUT/triggers" --output-dir "$OUT/cve" --export-matched "$EXPORT_MATCHED")
  [[ -n "$SCENARIOS" ]] && cve_cmd+=(--scenarios "$SCENARIOS")
  if [[ -n "$CVE_ARGS" ]]; then read -r -a cve_extra <<<"$CVE_ARGS"; cve_cmd+=("${cve_extra[@]}"); fi
  run_step cve "$OUT/cve.log" "${cve_cmd[@]}"
else
  say "cve: skipped (--scenarios none)"
  record_step cve skipped 0 0
fi

if [[ "$FP_LAB_SCENARIOS" != "none" ]]; then
  # Direct scenarios only (--agents ""): no agent and no provider key. The
  # runner's own windows are shortened: the baseline above already watched
  # this host idle.
  fp_cmd=("${RUNNER_ENV[@]}" "$PYTHON" "$POSTURE_REPO/tests/fp_lab/run_fp_lab.py" run
          --out "$OUT/fp_lab" --scenarios "$FP_LAB_SCENARIOS" --agents ""
          --set-adjudication "$ADJUDICATION" --warmup-secs 60 --drain-secs 120)
  # The daemon that answered when the window opened: the lab refuses any other.
  if [[ -n "$CORE_VERSION" ]]; then
    fp_cmd+=(--expect-core-version "$CORE_VERSION")
  elif (( DRY_RUN )); then
    fp_cmd+=(--expect-core-version "<owned core version>")
  fi
  (( PORTAL )) || fp_cmd+=(--allow-no-llm)
  if [[ -n "$FP_LAB_ARGS" ]]; then read -r -a fp_extra <<<"$FP_LAB_ARGS"; fp_cmd+=("${fp_extra[@]}"); fi
  run_step fp_lab "$OUT/fp_lab.log" "${fp_cmd[@]}"
else
  say "fp_lab: skipped (--fp-lab-scenarios none)"
  record_step fp_lab skipped 0 0
fi

close_window

# Offline from here: the host is back to its own app and helper.
if [[ "$SCENARIOS" != "none" ]]; then
  run_step shape_attack "$OUT/staging/attack_corpus.log" "$PYTHON" -I "$SHAPER" \
    --out "$OUT/staging/attack_corpus" --platform "$PLATFORM_LABEL" --label "$RUN_LABEL" \
    --report "$OUT/staging/attack_corpus.report.json" "$OUT/cve"
fi
if [[ "$FP_LAB_SCENARIOS" != "none" ]]; then
  for kind in attack_pattern:fp_corpus divergence:divergence_corpus; do
    if (( DRY_RUN )) || [[ -d "$OUT/fp_lab/candidates/${kind%%:*}" ]]; then
      act mkdir -p "$OUT/staging/${kind#*:}"
      act cp -R "$OUT/fp_lab/candidates/${kind%%:*}/." "$OUT/staging/${kind#*:}/"
    fi
  done
fi
(( PROMOTE )) && promote_envelopes "$OUT"

banner "summary"
say "+ $(q "$PYTHON" -I "$SUMMARY_PY" "$OUT")"
if (( DRY_RUN )); then
  say "dry run complete: $( ((${#PROBLEMS[@]})) && echo "${#PROBLEMS[@]} problem(s) would refuse the run" || echo 'the run would start')"
  trap - EXIT
  (( ${#PROBLEMS[@]} )) && exit 2
  exit 0
fi
SUMMARY_DONE=1
"$PYTHON" -I "$SUMMARY_PY" "$OUT"
VERDICT_RC=$?
say "summary: $OUT/summary.md"
exit "$VERDICT_RC"
