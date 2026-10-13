#!/usr/bin/env bash
# window_root.sh -- the root half of run_local_loop.sh's owned-daemon window on
# this Mac. run_local_loop.sh is the only caller, always as
# `sudo -H bash window_root.sh <command> ...`: HOME is root's, so `defaults`
# reaches root's own preferences domain, and sudo's env_reset keeps the
# operator's environment (Hub credentials, a Portal key) away from the daemon.
# The steps are tests/fp_lab/deploy_owned_posture_macos.sh's `start` / `stop`
# for a posture built in the workspace instead of a CI pkg, run with sudo
# instead of over SSH, and for a helper launchd may or may not manage.
#
#   check                          refuse when an FP-lab window is open here or a posture daemon runs
#   save-state                     once per window: save root's posture state, then clear it
#   restore-state                  root's posture state back exactly as saved; the lab's kept aside
#   stop-helper launchd <label>    launchctl disable + bootout
#   stop-helper pid <pid>          TERM, KILL after 20 s
#   start-helper launchd <label> <plist>
#   start-helper manual <dir> <bin> <home>   as it was started by hand
#   start-posture <bin> <home> [<portal-env>]
#   stop-posture <bin> <home>
#   es-status                      Endpoint Security lines of the newest posture log
#   collect-logs <dest> <owner> <since-epoch>
#
# Root's posture state: a root posture keeps its records under root's home
# whatever HOME says -- the `edamame_posture` defaults domain,
# /var/root/.edamame (file secret store) and, for records that outgrew the
# defaults (2.0.3+), /var/root/Library/Application Support/edamame_posture.
# It is saved under /var/root/fp-lab/local-loop/original, apart from the
# deploy script's /var/root/fp-lab/original, so the two windows never mix.
# Ports are read with netstat, never lsof (lsof can hang on a wedged network volume).

set -uo pipefail

BASE=/var/root/fp-lab/local-loop
ORIG="$BASE/original"
APPSUP="/var/root/Library/Application Support/edamame_posture"
POSTURE_LOGS=/var/log/edamame

die() { echo "window_root: $*" >&2; exit 2; }
[[ $(id -u) -eq 0 ]] || die "run as root: sudo -H bash $0 ..."
port_listening() { /usr/sbin/netstat -an -p tcp | grep LISTEN | grep -q "\\.$1 "; }
helper_running() { pgrep -x edamame_helper >/dev/null; }
posture_running() { pgrep -x edamame_posture >/dev/null; }

CMD="${1:-}"
[[ -n "$CMD" ]] || { sed -n '2,/^$/p' "$0"; exit 2; }
shift

case "$CMD" in
  check)
    problems=0
    if [[ -f /var/root/fp-lab/original/.saved || -f /var/root/fp-lab/pre-state ]]; then
      echo "an FP-lab window (deploy_owned_posture_macos.sh) is open on this Mac: stop it first"
      problems=1
    fi
    if posture_running; then
      echo "a posture daemon already runs: $(pgrep -lx edamame_posture | tr '\n' ' ')"
      problems=1
    fi
    # A window that never restored (SIGKILL, reboot) left root's original
    # state here; save-state keeps it rather than saving the lab's over it.
    [[ -f "$ORIG/.saved" ]] && echo "note: $ORIG holds root posture state an earlier local window saved and never restored; this window restores it"
    exit "$problems"
    ;;

  save-state)
    mkdir -p "$BASE" && chmod 700 "$BASE"
    if [[ ! -f "$ORIG/.saved" ]]; then
      mkdir -p "$ORIG"
      if defaults export edamame_posture "$ORIG/edamame_posture.plist" 2>/dev/null; then
        echo "saved the edamame_posture domain"
      else
        rm -f "$ORIG/edamame_posture.plist"
        echo "no edamame_posture domain"
      fi
      if [[ -d /var/root/.edamame ]]; then mv /var/root/.edamame "$ORIG/dot-edamame" && echo "saved /var/root/.edamame"; fi
      if [[ -d "$APPSUP" ]]; then mv "$APPSUP" "$ORIG/app-support" && echo "saved $APPSUP"; fi
      touch "$ORIG/.saved"
    else
      echo "root posture state already saved for this window"
    fi
    defaults delete edamame_posture 2>/dev/null || true
    rm -rf /var/root/.edamame "$APPSUP"
    echo "root posture state cleared: the owned build starts empty and disconnected"
    ;;

  restore-state)
    if [[ ! -f "$ORIG/.saved" ]]; then
      echo "no saved root posture state (nothing to restore)"
      exit 0
    fi
    ts=$(date +%Y%m%d%H%M%S)
    lab="$BASE/lab-state-$ts"
    mkdir -p "$lab"
    defaults export edamame_posture "$lab/edamame_posture.plist" 2>/dev/null || true
    if [[ -d /var/root/.edamame ]]; then mv /var/root/.edamame "$lab/dot-edamame"; fi
    if [[ -d "$APPSUP" ]]; then mv "$APPSUP" "$lab/app-support"; fi
    defaults delete edamame_posture 2>/dev/null || true
    if [[ -f "$ORIG/edamame_posture.plist" ]]; then
      defaults import edamame_posture "$ORIG/edamame_posture.plist" && echo "restored the edamame_posture domain"
    fi
    if [[ -d "$ORIG/dot-edamame" ]]; then mv "$ORIG/dot-edamame" /var/root/.edamame && echo "restored /var/root/.edamame"; fi
    if [[ -d "$ORIG/app-support" ]]; then mv "$ORIG/app-support" "$APPSUP" && echo "restored $APPSUP"; fi
    mv "$ORIG" "$BASE/restored-$ts"
    echo "the lab's root posture state is kept in $lab"
    ;;

  stop-helper)
    mode="${1:-}"
    case "$mode" in
      launchd)
        label="${2:?label}"
        launchctl disable "system/$label"
        launchctl bootout "system/$label" 2>/dev/null || true
        ;;
      pid)
        pid="${2:?pid}"
        kill -TERM "$pid" 2>/dev/null || true
        ;;
      *) die "stop-helper launchd <label> | pid <pid>" ;;
    esac
    for _ in $(seq 1 20); do helper_running || break; sleep 1; done
    if helper_running && [[ "$mode" == pid ]]; then kill -KILL "$pid" 2>/dev/null; sleep 2; fi
    if helper_running; then echo "helper still running"; exit 1; fi
    echo "helper stopped"
    ;;

  start-helper)
    mode="${1:-}"
    case "$mode" in
      launchd)
        label="${2:?label}"; plist="${3:?plist}"
        launchctl enable "system/$label"
        launchctl bootstrap system "$plist" 2>/dev/null || launchctl kickstart -k "system/$label" 2>/dev/null || true
        ;;
      manual)
        # The way a developer helper is started by hand (sudo, cwd the
        # helper checkout, HOME kept by macOS sudoers): nohup and no stdio,
        # so it outlives this script and sudo.
        dir="${2:?dir}"; bin="${3:?bin}"; home="${4:?home}"
        cd "$dir" || die "no helper directory $dir"
        [[ -x "$bin" ]] || die "no helper binary $bin in $dir"
        mkdir -p "$BASE"
        HOME="$home" RUST_BACKTRACE=1 EDAMAME_LOG_LEVEL=edamame_foundation=info \
          nohup "$bin" >>"$BASE/helper-restart.log" 2>&1 </dev/null &
        ;;
      *) die "start-helper launchd <label> <plist> | manual <dir> <bin> <home>" ;;
    esac
    for _ in $(seq 1 30); do helper_running && port_listening 40151 && break; sleep 1; done
    if helper_running; then echo "helper: running"; else echo "helper: NOT RUNNING"; fi
    if port_listening 40151; then echo "port 40151: listening"; else echo "port 40151: NOT LISTENING"; exit 1; fi
    ;;

  start-posture)
    bin="${1:?bin}"; home="${2:?home}"; portal_env="${3:-}"
    [[ -x "$bin" ]] || die "no posture binary $bin"
    posture_running && die "a posture daemon already runs"
    args=(background-start-disconnected --packet-capture --agentic-mode analyze)
    if [[ -n "$portal_env" ]]; then
      # The key goes into this process's environment only (the daemon reads
      # EDAMAME_LLM_API_KEY): never argv, never printed.
      line=$(grep -hE '^(export[[:space:]]+)?EDAMAME_LLM_API_KEY=' "$portal_env" | tail -n 1 | tr -d '\r')
      value="${line#*=}"
      value="${value%\"}"; value="${value#\"}"; value="${value%\'}"; value="${value#\'}"
      [[ -n "$value" ]] || die "no EDAMAME_LLM_API_KEY in $portal_env"
      export EDAMAME_LLM_API_KEY="$value"
      args+=(--agentic-provider edamame)
      echo "Portal key: loaded from $portal_env (not shown)"
    fi
    mkdir -p "$BASE"
    cd "$BASE" || die "cannot enter $BASE"
    HOME="$home" "$bin" "${args[@]}" </dev/null
    rc=$?
    echo "background-start-disconnected exited $rc"
    exit "$rc"
    ;;

  stop-posture)
    bin="${1:?bin}"; home="${2:?home}"
    if posture_running && [[ -x "$bin" ]]; then
      HOME="$home" "$bin" background-stop >/dev/null 2>&1 || true
    fi
    for _ in $(seq 1 20); do posture_running || break; sleep 1; done
    if posture_running; then pkill -TERM -x edamame_posture; sleep 5; fi
    if posture_running; then pkill -KILL -x edamame_posture; sleep 2; fi
    if posture_running; then echo "posture still running"; exit 1; fi
    echo "no posture daemon running"
    ;;

  es-status)
    # The newest log only: the directory keeps earlier runs' logs
    # (deploy_owned_posture_macos.sh, 2026-10-06).
    # shellcheck disable=SC2012 # newest by mtime; posture log names are plain
    newest=$(ls -t "$POSTURE_LOGS"/edamame_posture_* 2>/dev/null | head -n 1)
    echo "log: ${newest:-none}"
    if [[ -n "$newest" ]]; then
      grep -hE "ES client|ES disabled|ES subscribe|ES helper|Endpoint Security" "$newest" | tail -n 5
    fi
    exit 0
    ;;

  collect-logs)
    dest="${1:?dest}"; owner="${2:?owner}"; since="${3:?since}"
    mkdir -p "$dest"
    copied=0
    for f in "$POSTURE_LOGS"/edamame_posture_*; do
      [[ -f "$f" ]] || continue
      (( $(stat -f %m "$f") >= since )) || continue
      cp "$f" "$dest/" && copied=$((copied + 1))
    done
    chown -R "$owner" "$dest"
    echo "copied $copied posture log(s) to $dest"
    ;;

  *) die "unknown command $CMD" ;;
esac
