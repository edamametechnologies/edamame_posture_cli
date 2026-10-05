#!/usr/bin/env bash
# deploy_owned_posture_macos.sh -- the macOS (fmba-3) leg of
# deploy_owned_posture.sh: run the FP lab against a posture we own (a signed
# CI pkg of the release candidate) on a dogfood Mac that normally runs the
# released app and helper, then put the Mac back exactly as it was.
#
#   deploy_owned_posture_macos.sh <command> [args]      (called by deploy_owned_posture.sh)
#
# The window, in order (Frank, 2026-10-05: "disable the helper, kill the app
# during your test and re-enable the helper and relaunch the app after, and
# disable your posture"):
#   fetch            download posture-binary-macos-arm64 (signed pkg) of CI run $FP_LAB_RUN_ID
#   push             copy the pkg, a 2.0.5+ edamame_cli and the lab harness to ~/fp-lab
#   keys             copy the approved provider and Portal keys (0600, never printed)
#   agents           install the agent CLIs the lab drives when missing (npm)
#   start            quit the app, disable the helper, install the pkg, start posture
#   status           what the lab preflight will see
#   run [args]       start run_fp_lab.py detached (args go to `run`)
#   wait <run>       follow a detached run until its summary exists
#   collect <run>    copy the run back and shape attack-pattern candidates here
#   stop             stop and remove posture, re-enable the helper, relaunch the
#                    app, delete the keys, verify
#
# Why each step:
# - Ports are checked with netstat, never lsof: lsof hangs on fmba-3 (an
#   uninterruptible lsof survived kill -9 there on 2026-10-05).
# - The app hosts its own core on 40152 (core per frontend) and the helper
#   runs its own capture and file monitoring: both stay off for the window so
#   only the owned build observes the host.
# - Never the brew edamame_cli on this Mac: through 2.0.4 a CLI one-shot
#   removes the app's Portal key and Hub PIN from ~/.edamame/secrets. The lab
#   uses the 2.0.5+ CLI copied to ~/fp-lab/bin (EDAMAME_CLI_BIN).
# - Endpoint Security needs Full Disk Access for the client's responsible
#   process. Posture is started from the root SSH session, whose responsible
#   process (sshd-keygen-wrapper) holds FDA on fmba-3, so ES comes up with no
#   GUI approval; `start` checks the daemon log for an ES client failure.
# - HOME is the console user's so the transcript observer reads that user's
#   ~/.claude and ~/.codex; a root posture keeps its own records under root's
#   home whatever HOME says: the `edamame_posture` defaults domain
#   (/var/root/Library/Preferences/edamame_posture.plist) and the file secret
#   store /var/root/.edamame/secrets. On fmba-3 that domain held a Homebrew
#   posture 1.0.5's Hub record: the first window (2026-10-05) connected to the
#   Hub with it and migrated its credentials, because state isolation looked
#   at a guessed plist name. `start` now exports the domain and moves the
#   store aside (once per window, through `defaults`, which cfprefsd caches),
#   clears both, and `stop` imports them back exactly.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
WORKSPACE="$(cd "$REPO/.." && pwd)"
RUN_ID="${FP_LAB_RUN_ID:?FP_LAB_RUN_ID: the tests.yml run that built posture-binary-macos-arm64}"
GH_REPO="${FP_LAB_GH_REPO:-edamametechnologies/edamame_posture_cli}"
CACHE="${FP_LAB_CACHE:-$HOME/Library/Caches/edamame-agents/fp-lab}"
OWNED_VERSION="${FP_LAB_OWNED_VERSION:-2.0.5}"
HOSTNAME_="${FP_LAB_MAC_HOST:-fmba-3.local}"
USER_="${FP_LAB_MAC_USER:-flyonnet}"
CLI_LOCAL="${FP_LAB_CLI:-$HOME/Library/Caches/edamame-agents/target-cli/release/edamame_cli}"
SECRETS="${FP_LAB_SECRETS:-$WORKSPACE/secrets}"
LABEL="macos-arm64"
APP_NAME="EDAMAME Security"
HELPER_LABEL="com.edamametechnologies.edamame-helper"
HELPER_PLIST="/Library/LaunchDaemons/$HELPER_LABEL.plist"
POSTURE_BUNDLE="/Library/Application Support/EDAMAME/EDAMAME-Posture"
POSTURE_LINK="/usr/local/bin/edamame_posture"
BIN_DIR="$CACHE/bin/$RUN_ID/$LABEL"

die() { echo "deploy_owned_posture_macos: $*" >&2; exit 2; }
say() { echo "== $*" >&2; }
CMD="${1:-}"; [[ -n "$CMD" ]] || { sed -n '2,40p' "$0"; exit 2; }
shift

SSH_OPTS=(-o ConnectTimeout=20 -o ServerAliveInterval=30)
as_user() { ssh "${SSH_OPTS[@]}" "$USER_@$HOSTNAME_" "$@"; }
as_root() { ssh "${SSH_OPTS[@]}" "root@$HOSTNAME_" "$@"; }
# user_bash: run the script on stdin as the console user under bash, after
# USER_LIB (the login shell is zsh; the lab helpers are bash).
user_bash() { { printf '%s\n' "$USER_LIB"; cat; } | as_user 'bash -s'; }

# Shipped in front of each user-side script.
USER_LIB='
set -u
export PATH=/opt/homebrew/bin:/usr/local/bin:$HOME/.local/bin:$HOME/.cargo/bin:/usr/bin:/bin:/usr/sbin:/sbin
export EDAMAME_CLI_BIN=$HOME/fp-lab/bin/edamame_cli EDAMAME_CLI=$HOME/fp-lab/bin/edamame_cli
cli() { "$EDAMAME_CLI_BIN" "$@"; }
wait_rpc() { # wait_rpc <version-prefix> <secs>
  want="$1"; secs="$2"; v=""
  for _ in $(seq 1 "$secs"); do
    v=$(cli rpc get_core_version 2>/dev/null | sed -n "s/^Result: //p" | tr -d "\"")
    case "$v" in "$want"*) echo "$v"; return 0 ;; esac
    sleep 1
  done
  echo "timeout (last answer: ${v:-none})"; return 1
}
show_state() {
  for m in get_core_info agentic_get_protection_status is_capturing get_connection; do
    echo "-- $m"; cli rpc "$m" 2>&1 | sed -n "/^Result:/,\$p" | grep -oE "Core version is [^,]*|\"(enabled|assistant|attack_pattern_detection|divergence_detection|is_connected|connected_domain)\":[^,}]*|Result: (true|false)"
  done
  for m in get_attack_pattern_detector_status get_divergence_engine_status get_transcript_observer_status; do
    echo "-- $m"; cli rpc "$m" 2>&1 | sed -n "s/^Result: //p" | tr -d "\\\\" | grep -oE "\"(running|adjudication_mode|active_findings|active_alertable_findings|last_verdict|contributor_count|agents_observed)\":[^,}]*"
  done
  echo "-- get_file_monitor_status"; cli rpc get_file_monitor_status 2>&1 | grep -oE "\"is_monitoring\": [a-z]+"
}
'

case "$CMD" in
  fetch)
    mkdir -p "$BIN_DIR"
    gh run view "$RUN_ID" --repo "$GH_REPO" --json headBranch,headSha,status,conclusion \
      --jq '"run \(.status)/\(.conclusion) on \(.headBranch)@\(.headSha)"'
    gh run download "$RUN_ID" --repo "$GH_REPO" -n "posture-binary-$LABEL" -D "$BIN_DIR"
    pkgutil --check-signature "$BIN_DIR/edamame-posture.pkg" | sed -n '1,4p'
    shasum -a 256 "$BIN_DIR/edamame-posture.pkg" | tee "$BIN_DIR/SHA256"
    ;;

  push)
    [[ -f "$BIN_DIR/edamame-posture.pkg" ]] || die "no pkg in $BIN_DIR (run fetch first)"
    [[ -x "$CLI_LOCAL" ]] || die "no edamame_cli at $CLI_LOCAL (FP_LAB_CLI): build one against core >= 2.0.5"
    CLI_VER=$("$CLI_LOCAL" --version 2>&1 | head -1)
    case "$CLI_VER" in *2.0.[5-9]*|*2.[1-9].*|*[3-9].[0-9]*) ;; *) die "edamame_cli $CLI_VER is older than 2.0.5: it would erase the app's stored credentials" ;; esac
    as_user 'mkdir -p ~/fp-lab/bin ~/fp-lab/secrets ~/fp-lab/runs ~/fp-lab/state && chmod 700 ~/fp-lab/secrets'
    scp -q "${SSH_OPTS[@]}" "$BIN_DIR/edamame-posture.pkg" "$USER_@$HOSTNAME_:fp-lab/bin/edamame-posture.pkg"
    scp -q "${SSH_OPTS[@]}" "$CLI_LOCAL" "$USER_@$HOSTNAME_:fp-lab/bin/edamame_cli"
    as_user 'chmod 755 ~/fp-lab/bin/edamame_cli; xattr -c ~/fp-lab/bin/edamame_cli ~/fp-lab/bin/edamame-posture.pkg 2>/dev/null; ~/fp-lab/bin/edamame_cli --version'
    STAGE="$CACHE/stage-macos"; rm -rf "$STAGE"; mkdir -p "$STAGE/tests/fp_lab/tools" "$STAGE/tests/e2e" \
      "$STAGE/tests/security/triggers" "$STAGE/supported_agents"
    cp "$HERE"/*.py "$HERE"/*.md "$STAGE/tests/fp_lab/" 2>/dev/null || true
    cp "$REPO/tests/e2e/agent_harness.py" "$REPO/tests/e2e/supported_agents.py" "$STAGE/tests/e2e/"
    cp "$REPO/tests/security/triggers/_edamame_cli.py" "$STAGE/tests/security/triggers/"
    cp "$WORKSPACE/edamame_foundation/supported_agents/index.json" "$STAGE/supported_agents/"
    cp "$WORKSPACE/edamame_core/tools/fp_corpus_from_export.sh" "$STAGE/tests/fp_lab/tools/"
    COPYFILE_DISABLE=1 tar --no-xattrs -C "$STAGE" -cf - . | as_user 'rm -rf ~/fp-lab/harness && mkdir -p ~/fp-lab/harness && tar -C ~/fp-lab/harness -xf -'
    user_bash <<'SCRIPT'
cd ~/fp-lab/harness && python3 tests/fp_lab/run_fp_lab.py validate
SCRIPT
    ;;

  keys)
    # The approved keys (Frank, 2026-10-05): the agents' provider keys for the
    # user side, the Portal key for the root daemon. Values go over stdin into
    # 0600 files and are never echoed; `stop` deletes both files.
    for f in claude.env openai.env cursor.env agentic.env; do [[ -f "$SECRETS/$f" ]] || die "missing $SECRETS/$f"; done
    grep -hE '^(export )?(ANTHROPIC_API_KEY|OPENAI_API_KEY|CURSOR_API_KEY)=' \
      "$SECRETS/claude.env" "$SECRETS/openai.env" "$SECRETS/cursor.env" | sed 's/^export //; s/^/export /' \
      | as_user 'umask 077; mkdir -p ~/fp-lab/secrets; cat > ~/fp-lab/secrets/providers.env; chmod 600 ~/fp-lab/secrets/providers.env; sed -E "s/=.*/=<set>/" ~/fp-lab/secrets/providers.env'
    grep -hE '^(export )?EDAMAME_LLM_API_KEY=' "$SECRETS/agentic.env" | sed 's/^export //; s/^/export /' \
      | as_root 'umask 077; mkdir -p /var/root/fp-lab; cat > /var/root/fp-lab/portal.env; chmod 600 /var/root/fp-lab/portal.env; sed -E "s/=.*/=<set>/" /var/root/fp-lab/portal.env'
    ;;

  agents)
    # The agent CLIs the lab drives (Claude Code, Codex), user-level through
    # npm like the fleet E2E; an installed one is left as it is.
    user_bash <<'SCRIPT'
for pair in "claude:@anthropic-ai/claude-code" "codex:@openai/codex"; do
  bin=${pair%%:*}; pkg=${pair#*:}
  if command -v "$bin" >/dev/null; then echo "$bin: $(command -v $bin)"; else echo "installing $pkg"; npm install -g "$pkg" 2>&1 | tail -n 2; fi
done
for t in claude codex; do echo "$t version: $($t --version 2>&1 | head -1)"; done
SCRIPT
    ;;

  start)
    as_user 'test -f ~/fp-lab/bin/edamame-posture.pkg && test -x ~/fp-lab/bin/edamame_cli' || die "push first"
    # The pkg on the host must be this run's: a broken upload leaves the
    # previous one in place.
    WANT_SHA=$(cut -d' ' -f1 "$BIN_DIR/SHA256" 2>/dev/null) || die "no $BIN_DIR/SHA256 (fetch first)"
    HOST_SHA=$(as_user 'shasum -a 256 ~/fp-lab/bin/edamame-posture.pkg | cut -d" " -f1')
    [[ "$WANT_SHA" == "$HOST_SHA" ]] || die "host pkg $HOST_SHA is not run $RUN_ID's $WANT_SHA (push again)"
    as_root 'test -f /var/root/fp-lab/portal.env' || die "keys first"
    say "recording the released state"
    as_root "bash -s" <<EOF | tee "$CACHE/state/fmba-3-$(date +%Y%m%d-%H%M%S)-pre.txt"
mkdir -p /var/root/fp-lab
{ pgrep -x "$APP_NAME" >/dev/null && echo app=running || echo app=stopped
  launchctl print system/$HELPER_LABEL >/dev/null 2>&1 && echo helper=loaded || echo helper=unloaded
  launchctl print-disabled system | grep -q '"$HELPER_LABEL" => disabled' && echo helper_disabled=yes || echo helper_disabled=no
} > /var/root/fp-lab/pre-state.now
# Once per window: a second start (after a failed one) must not record the
# app it stopped itself as "stopped".
[ -f /var/root/fp-lab/pre-state ] || mv /var/root/fp-lab/pre-state.now /var/root/fp-lab/pre-state
rm -f /var/root/fp-lab/pre-state.now
cat /var/root/fp-lab/pre-state
/usr/sbin/netstat -an -p tcp | grep LISTEN | grep -q '\.40152 ' && echo 'port 40152: listening'
EOF
    # SIGTERM from root, not `osascript ... quit`: Apple Events from an SSH
    # session can raise an Automation consent prompt on the console.
    say "stopping the app"
    as_root "bash -s" <<EOF
pkill -TERM -x "$APP_NAME" 2>/dev/null || true
for _ in \$(seq 1 20); do pgrep -x "$APP_NAME" >/dev/null || break; sleep 1; done
pgrep -x "$APP_NAME" >/dev/null && { pkill -KILL -x "$APP_NAME"; sleep 2; }
pgrep -x "$APP_NAME" >/dev/null && { echo "app still running"; exit 1; }
echo "disabling the helper"
launchctl disable system/$HELPER_LABEL
launchctl bootout system/$HELPER_LABEL 2>/dev/null || true
for _ in \$(seq 1 20); do pgrep -f "EDAMAME-Helper/edamame_helper.app" >/dev/null || break; sleep 1; done
pgrep -f "EDAMAME-Helper/edamame_helper.app" >/dev/null && { echo "helper still running"; exit 1; }
for p in 40151 40152; do
  /usr/sbin/netstat -an -p tcp | grep LISTEN | grep -q "\\.\$p " && { echo "port \$p still held"; exit 1; }
done
echo "app and helper stopped, ports free"
# Root's own posture state (an earlier install's) is saved once per window
# and cleared, so the owned build starts empty, disconnected and touches
# nothing of it.
if [ ! -f /var/root/fp-lab/original/.saved ]; then
  mkdir -p /var/root/fp-lab/original
  defaults export edamame_posture /var/root/fp-lab/original/edamame_posture.plist 2>/dev/null \
    && echo "saved the edamame_posture domain" || echo "no edamame_posture domain"
  [ -d /var/root/.edamame ] && mv /var/root/.edamame /var/root/fp-lab/original/dot-edamame && echo "saved /var/root/.edamame"
  touch /var/root/fp-lab/original/.saved
fi
defaults delete edamame_posture 2>/dev/null || true
rm -rf /var/root/.edamame
echo "installing the owned posture"
installer -pkg /Users/$USER_/fp-lab/bin/edamame-posture.pkg -target / | tail -2
codesign -dvv "$POSTURE_BUNDLE/edamame_posture.app" 2>&1 | grep -E "Authority=Developer ID Application|TeamIdentifier" | head -2
echo "starting the owned posture"
set -a; . /var/root/fp-lab/portal.env; set +a
HOME=/Users/$USER_ "$POSTURE_LINK" background-start-disconnected --packet-capture --agentic-mode analyze --agentic-provider edamame
EOF
    user_bash <<SCRIPT
echo "owned daemon: \$(wait_rpc $OWNED_VERSION 180)"
sleep 20
show_state
SCRIPT
    say "Endpoint Security status (daemon log)"
    as_root 'grep -hE "ES client creation failed|ES disabled|ES subscribe failed|ES helper|Endpoint Security" /var/log/edamame*/* /var/root/Library/Logs/edamame*/* 2>/dev/null | tail -n 5 || true'
    ;;

  status)
    as_root "cat /var/root/fp-lab/pre-state 2>/dev/null; pgrep -x '$APP_NAME' >/dev/null && echo 'app: RUNNING' || echo 'app: stopped'; pgrep -f 'EDAMAME-Helper/edamame_helper.app' >/dev/null && echo 'helper: RUNNING' || echo 'helper: stopped'; pgrep -fl 'edamame_posture' | head -3"
    user_bash <<'SCRIPT'
show_state
SCRIPT
    ;;

  run)
    NAME="fmba-3-$(date +%Y%m%d-%H%M%S)"
    ARGS=""; for a in "$@"; do ARGS="$ARGS $(printf '%q' "$a")"; done
    user_bash <<SCRIPT
set -a; . ~/fp-lab/secrets/providers.env; set +a
cd ~/fp-lab/harness
nohup python3 tests/fp_lab/run_fp_lab.py run --out ~/fp-lab/runs/$NAME \\
  --expect-core-version $OWNED_VERSION --set-adjudication auto $ARGS \\
  > ~/fp-lab/runs/$NAME.log 2>&1 < /dev/null &
sleep 3; echo "started $NAME"; tail -n 5 ~/fp-lab/runs/$NAME.log
SCRIPT
    echo "$NAME"
    ;;

  wait)
    NAME="${1:?run name}"
    while :; do
      if as_user "test -f ~/fp-lab/runs/$NAME/summary.md"; then as_user "cat ~/fp-lab/runs/$NAME/summary.md"; break; fi
      if ! as_user "pgrep -f 'run_fp_lab.py run --out .*/$NAME' >/dev/null"; then
        as_user "test -f ~/fp-lab/runs/$NAME/summary.md" && continue
        as_user "tail -n 40 ~/fp-lab/runs/$NAME.log"; die "runner exited without a summary"
      fi
      as_user "tail -n 2 ~/fp-lab/runs/$NAME.log"
      sleep 60
    done
    ;;

  collect)
    NAME="${1:?run name}"
    DEST="$CACHE/runs/$NAME"; mkdir -p "$DEST"
    as_user "tar -C ~/fp-lab/runs -cf - $NAME $NAME.log" | tar -C "$CACHE/runs" -xf -
    mv "$CACHE/runs/$NAME.log" "$DEST/run.log" 2>/dev/null || true
    python3 "$HERE/run_fp_lab.py" shape "$DEST" \
      --corpus-tool "$WORKSPACE/edamame_core/tools/fp_corpus_from_export.sh" || true
    python3 "$HERE/run_fp_lab.py" summarize "$DEST" >/dev/null || true
    say "artifacts in $DEST"
    ;;

  stop)
    as_root "bash -s" <<EOF
echo "stopping the owned posture"
HOME=/Users/$USER_ "$POSTURE_LINK" background-stop >/dev/null 2>&1 || true
for _ in \$(seq 1 20); do pgrep -f "EDAMAME-Posture/edamame_posture.app" >/dev/null || break; sleep 1; done
pkill -f "EDAMAME-Posture/edamame_posture.app" 2>/dev/null || true
echo "removing the owned posture"
if [ -L "$POSTURE_LINK" ] && readlink "$POSTURE_LINK" | grep -q "EDAMAME-Posture"; then rm -f "$POSTURE_LINK"; fi
rm -rf "$POSTURE_BUNDLE"
for id in \$(pkgutil --pkgs | grep -i "edamame.*posture"); do pkgutil --forget "\$id" >/dev/null && echo "forgot \$id"; done
# Root's posture state back exactly as saved; the lab's own goes.
if [ -f /var/root/fp-lab/original/.saved ]; then
  ts=\$(date +%Y%m%d%H%M%S); mkdir -p /var/root/fp-lab/lab-state-\$ts
  defaults export edamame_posture /var/root/fp-lab/lab-state-\$ts/edamame_posture.plist 2>/dev/null || true
  [ -d /var/root/.edamame ] && mv /var/root/.edamame /var/root/fp-lab/lab-state-\$ts/dot-edamame
  defaults delete edamame_posture 2>/dev/null || true
  if [ -f /var/root/fp-lab/original/edamame_posture.plist ]; then
    defaults import edamame_posture /var/root/fp-lab/original/edamame_posture.plist && echo "restored the edamame_posture domain"
  fi
  [ -d /var/root/fp-lab/original/dot-edamame ] && mv /var/root/fp-lab/original/dot-edamame /var/root/.edamame && echo "restored /var/root/.edamame"
  mv /var/root/fp-lab/original /var/root/fp-lab/restored-\$ts
fi
echo "re-enabling the helper"
launchctl enable system/$HELPER_LABEL
launchctl bootstrap system "$HELPER_PLIST" 2>/dev/null || launchctl kickstart -k system/$HELPER_LABEL 2>/dev/null || true
for _ in \$(seq 1 30); do pgrep -f "EDAMAME-Helper/edamame_helper.app" >/dev/null && break; sleep 1; done
pgrep -f "EDAMAME-Helper/edamame_helper.app" >/dev/null && echo "helper: running" || echo "helper: NOT RUNNING"
echo "relaunching the app in the console session"
uid=\$(id -u $USER_)
launchctl asuser "\$uid" sudo -u $USER_ open -a "$APP_NAME" || echo "open failed (no console session?)"
for _ in \$(seq 1 60); do pgrep -x "$APP_NAME" >/dev/null && break; sleep 1; done
pgrep -x "$APP_NAME" >/dev/null && echo "app: running" || echo "app: NOT RUNNING"
for _ in \$(seq 1 60); do /usr/sbin/netstat -an -p tcp | grep LISTEN | grep -q '\.40152 ' && break; sleep 2; done
/usr/sbin/netstat -an -p tcp | grep LISTEN | grep -q '\.40152 ' && echo 'port 40152: listening' || echo 'port 40152: NOT LISTENING'
echo "deleting the lab keys"
rm -f /var/root/fp-lab/portal.env
mv /var/root/fp-lab/pre-state /var/root/fp-lab/pre-state.done 2>/dev/null || true
EOF
    as_user 'rm -f ~/fp-lab/secrets/*.env; ls ~/fp-lab/secrets'
    ;;

  *) die "unknown command $CMD" ;;
esac
