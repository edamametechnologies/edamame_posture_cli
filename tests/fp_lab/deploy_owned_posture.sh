#!/usr/bin/env bash
# deploy_owned_posture.sh -- run the FP lab on a dogfood host against a posture
# daemon we own (the CI build of main), then put the host back on its released
# service. Runs on the operator machine; everything on the host goes over SSH.
#
#   deploy_owned_posture.sh <host> <command> [args]
#
# Hosts: test-mint (Linux), fmba-3 (macOS: deploy_owned_posture_macos.sh) and
# shiawase (Windows: deploy_owned_posture_windows.sh); the desktop legs add
# `keys` and `agents` commands.
#
# On a desktop host the window stops the released app and disables its helper
# first, and `stop` re-enables the helper, relaunches the app and removes the
# owned posture (Frank, 2026-10-05). Only the owned build observes the host
# during the window.
#
# Commands, in the order a lab window uses them:
#   fetch            download posture-binary-<label> of CI run $FP_LAB_RUN_ID
#   push             copy the owned binary and the lab harness to the host
#   record [tag]     record the released daemon's state (read-only)
#   start            stop the released service, start the owned daemon isolated
#   status           what the lab preflight will see
#   run [args]       start run_fp_lab.py detached on the host (args go to `run`)
#   wait <run>       follow a detached run until its summary exists
#   collect <run>    copy the run back and shape attack-pattern candidates here
#   stop             stop the owned daemon, restart the released service, verify
#
# Credentials: this script handles none. The owned daemon gets the host's own
# Portal configuration through the released service's EnvironmentFile
# (/etc/edamame_posture.env, root-only), which systemd reads on the host. The
# agent provider keys are an operator step on the host (owned_posture.md);
# without them the agent scenarios report SKIP.
#
# Isolation (Linux): the owned daemon is a transient systemd unit whose
# private mount namespace bind-mounts /var/lib/edamame-fplab/state over
# /root/.edamame (persisted config + file-backed secret store) and
# /var/lib/edamame-fplab/log over /var/log/edamame. The released service's
# state, Hub identity and PIN are never read or rewritten by the owned build,
# and the owned daemon never connects to the Hub (no --user/--domain/--pin).

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
WORKSPACE="$(cd "$REPO/.." && pwd)"
RUN_ID="${FP_LAB_RUN_ID:-37293583988}"
GH_REPO="${FP_LAB_GH_REPO:-edamametechnologies/edamame_posture_cli}"
CACHE="${FP_LAB_CACHE:-$HOME/Library/Caches/edamame-agents/fp-lab}"
OWNED_VERSION="${FP_LAB_OWNED_VERSION:-2.0.5}"
RELEASED_VERSION="${FP_LAB_RELEASED_VERSION:-2.0.4}"

die() { echo "deploy_owned_posture: $*" >&2; exit 2; }
say() { echo "== $*" >&2; }

HOST="${1:-}"; CMD="${2:-}"
[[ -n "$HOST" && -n "$CMD" ]] || { sed -n '2,33p' "$0"; exit 2; }
shift 2

case "$HOST" in
  test-mint)
    SSH_KEY="${TEST_MINT_KEY:-$HOME/OneDrive - Edamame Technologies/Keys/secrets/test-mint_key.pem}"
    SSH_TARGET="azureuser@20.19.88.225"
    LABEL="ubuntu-x64"
    SERVICE="edamame_posture.service"
    UNIT="edamame-fplab"
    ;;
  fmba-3)
    exec bash "$HERE/deploy_owned_posture_macos.sh" "$CMD" "$@"
    ;;
  shiawase)
    exec bash "$HERE/deploy_owned_posture_windows.sh" "$CMD" "$@"
    ;;
  *) die "unknown host $HOST" ;;
esac

ssh_host() { ssh -o ConnectTimeout=20 -o ServerAliveInterval=30 -i "$SSH_KEY" "$SSH_TARGET" "$@"; }
BIN_DIR="$CACHE/bin/$RUN_ID/$LABEL"

# Shell functions shipped to the host in front of each remote script.
REMOTE_LIB='
set -u
wait_rpc() { # wait_rpc <version-prefix> <secs>: wait until the daemon answers with that version
  want="$1"; secs="$2"; v=""
  for _ in $(seq 1 "$secs"); do
    v=$(timeout 20 edamame_cli rpc get_core_version 2>/dev/null | sed -n "s/^Result: //p" | tr -d "\"")
    case "$v" in "$want"*) echo "$v"; return 0 ;; esac
    sleep 1
  done
  echo "timeout (last answer: ${v:-none})"; return 1
}
show_state() {
  for m in get_core_info agentic_get_protection_status is_capturing get_connection; do
    echo "-- $m"; timeout 60 edamame_cli rpc "$m" 2>&1 | sed -n "/^Result:/,\$p" | grep -oE "Core version is [^,]*|\"(enabled|assistant|attack_pattern_detection|divergence_detection|is_connected|connected_domain)\":[^,}]*|Result: (true|false)"
  done
  for m in get_attack_pattern_detector_status get_divergence_engine_status; do
    echo "-- $m"; timeout 60 edamame_cli rpc "$m" 2>&1 | sed -n "s/^Result: //p" | tr -d "\\\\" | grep -oE "\"(running|adjudication_mode|active_findings|active_alertable_findings|last_verdict|contributor_count)\":[^,}]*"
  done
  echo "-- get_file_monitor_status"; timeout 60 edamame_cli rpc get_file_monitor_status 2>&1 | grep -oE "\"is_monitoring\": [a-z]+"
}
'

case "$CMD" in
  fetch)
    mkdir -p "$BIN_DIR"
    gh run view "$RUN_ID" --repo "$GH_REPO" --json headSha,status,conclusion \
      --jq '"run \(.status)/\(.conclusion) on \(.headSha)"'
    gh run download "$RUN_ID" --repo "$GH_REPO" -n "posture-binary-$LABEL" -D "$BIN_DIR"
    shasum -a 256 "$BIN_DIR/edamame_posture" | tee "$BIN_DIR/SHA256"
    ;;

  push)
    [[ -f "$BIN_DIR/edamame_posture" ]] || die "no binary in $BIN_DIR (run fetch first)"
    LOCAL_SHA=$(shasum -a 256 "$BIN_DIR/edamame_posture" | cut -d' ' -f1)
    REMOTE_SHA=$(ssh_host 'sha256sum ~/fp-lab/bin/edamame_posture 2>/dev/null | cut -d" " -f1' || true)
    if [[ "$LOCAL_SHA" != "$REMOTE_SHA" ]]; then
      ssh_host 'mkdir -p ~/fp-lab/bin'
      scp -C -i "$SSH_KEY" "$BIN_DIR/edamame_posture" "$SSH_TARGET:fp-lab/bin/edamame_posture.part"
      ssh_host "cd ~/fp-lab/bin && echo '$LOCAL_SHA  edamame_posture.part' | sha256sum -c - && mv edamame_posture.part edamame_posture && chmod 755 edamame_posture"
    fi
    ssh_host '~/fp-lab/bin/edamame_posture --version'
    # Harness bundle: the lab plus the shared modules it imports, in the repo
    # layout; the registry next to it; the corpus shaper under tests/fp_lab/tools.
    STAGE="$CACHE/stage"; rm -rf "$STAGE"; mkdir -p "$STAGE/tests/fp_lab/tools" "$STAGE/tests/e2e" \
      "$STAGE/tests/security/triggers" "$STAGE/supported_agents"
    cp "$HERE"/*.py "$HERE"/*.md "$STAGE/tests/fp_lab/" 2>/dev/null || true
    cp "$REPO/tests/e2e/agent_harness.py" "$REPO/tests/e2e/supported_agents.py" "$STAGE/tests/e2e/"
    cp "$REPO/tests/security/triggers/_edamame_cli.py" "$STAGE/tests/security/triggers/"
    cp "$WORKSPACE/edamame_foundation/supported_agents/index.json" "$STAGE/supported_agents/"
    cp "$WORKSPACE/edamame_core/tools/fp_corpus_from_export.sh" "$STAGE/tests/fp_lab/tools/"
    COPYFILE_DISABLE=1 tar --no-xattrs -C "$STAGE" -cf - . | ssh_host 'rm -rf ~/fp-lab/harness && mkdir -p ~/fp-lab/harness && tar -C ~/fp-lab/harness -xf -'
    ssh_host 'cd ~/fp-lab/harness && python3 tests/fp_lab/run_fp_lab.py validate'
    ;;

  record)
    TAG="${1:-state}"
    OUT="$CACHE/state/$HOST-$(date +%Y%m%d-%H%M%S)-$TAG.txt"; mkdir -p "$(dirname "$OUT")"
    ssh_host 'bash -s' <<EOF | tee "$OUT"
$REMOTE_LIB
date -u
systemctl is-active $SERVICE || true
systemctl show $SERVICE -p MainPID -p ActiveEnterTimestamp -p NRestarts
systemctl is-active $UNIT 2>/dev/null || true
show_state
EOF
    say "recorded to $OUT"
    ;;

  start)
    ssh_host 'bash -s' <<EOF
$REMOTE_LIB
set -e
if systemctl is-active --quiet $UNIT; then echo "owned daemon already running"; exit 0; fi
test -x ~/fp-lab/bin/edamame_posture
sudo install -d -m 0700 /var/lib/edamame-fplab /var/lib/edamame-fplab/state
sudo install -d -m 0755 /var/lib/edamame-fplab/bin /var/lib/edamame-fplab/log
sudo install -m 0755 ~/fp-lab/bin/edamame_posture /var/lib/edamame-fplab/bin/edamame_posture
echo "stopping the released service"
sudo systemctl stop $SERVICE
for _ in \$(seq 1 30); do ss -ltn | grep -q '127.0.0.1:40152 ' || break; sleep 1; done
if ss -ltn | grep -q '127.0.0.1:40152 '; then echo "port 40152 still held"; sudo systemctl start $SERVICE; exit 1; fi
ENVFILE=""
sudo test -f /etc/edamame_posture.env && ENVFILE="-p EnvironmentFile=/etc/edamame_posture.env"
sudo systemd-run --unit=$UNIT --description="EDAMAME FP lab owned posture" \
  -p WorkingDirectory=/var/lib/edamame-fplab \
  -p BindPaths=/var/lib/edamame-fplab/state:/root/.edamame \
  -p BindPaths=/var/lib/edamame-fplab/log:/var/log/edamame \
  -p Environment=HOME=/root \$ENVFILE \
  /var/lib/edamame-fplab/bin/edamame_posture foreground-start -v \
    --agentic-mode analyze --agentic-provider edamame --packet-capture
echo "owned daemon: \$(wait_rpc $OWNED_VERSION 180)"
sleep 20
show_state
EOF
    ;;

  status)
    ssh_host 'bash -s' <<EOF
$REMOTE_LIB
echo "released service: \$(systemctl is-active $SERVICE)  owned unit: \$(systemctl is-active $UNIT 2>/dev/null)"
show_state
EOF
    ;;

  run)
    NAME="$HOST-$(date +%Y%m%d-%H%M%S)"
    ARGS=""; for a in "$@"; do ARGS="$ARGS $(printf '%q' "$a")"; done
    ssh_host 'bash -s' <<EOF
mkdir -p ~/fp-lab/runs
cd ~/fp-lab/harness
setsid -f python3 tests/fp_lab/run_fp_lab.py run --out ~/fp-lab/runs/$NAME \
  --expect-core-version $OWNED_VERSION --set-adjudication auto $ARGS \
  > ~/fp-lab/runs/$NAME.log 2>&1 < /dev/null
sleep 2; echo "started $NAME"; tail -n 5 ~/fp-lab/runs/$NAME.log
EOF
    echo "$NAME"
    ;;

  wait)
    NAME="${1:?run name}"
    while :; do
      if ssh_host "test -f ~/fp-lab/runs/$NAME/summary.md"; then
        ssh_host "cat ~/fp-lab/runs/$NAME/summary.md"; break
      fi
      if ! ssh_host "pgrep -f 'run_fp_lab.py run --out .*/$NAME' >/dev/null"; then
        # The runner may have written its summary between the two checks.
        ssh_host "test -f ~/fp-lab/runs/$NAME/summary.md" && continue
        ssh_host "tail -n 40 ~/fp-lab/runs/$NAME.log"; die "runner exited without a summary"
      fi
      ssh_host "tail -n 3 ~/fp-lab/runs/$NAME.log"
      sleep 60
    done
    ;;

  collect)
    NAME="${1:?run name}"
    DEST="$CACHE/runs/$NAME"; mkdir -p "$DEST"
    ssh_host "tar -C ~/fp-lab/runs -cf - $NAME $NAME.log" | tar -C "$CACHE/runs" -xf -
    mv "$CACHE/runs/$NAME.log" "$DEST/run.log" 2>/dev/null || true
    python3 "$HERE/run_fp_lab.py" shape "$DEST" \
      --corpus-tool "$WORKSPACE/edamame_core/tools/fp_corpus_from_export.sh" || true
    python3 "$HERE/run_fp_lab.py" summarize "$DEST" >/dev/null || true
    say "artifacts in $DEST"
    ;;

  stop)
    ssh_host 'bash -s' <<EOF
$REMOTE_LIB
if systemctl is-active --quiet $UNIT; then
  echo "stopping the owned daemon"
  sudo systemctl stop $UNIT || true
fi
sudo systemctl reset-failed $UNIT 2>/dev/null || true
# The installed copy is redundant with ~/fp-lab/bin (start reinstalls it); the
# owned state and log stay in /var/lib/edamame-fplab for forensics.
sudo rm -f /var/lib/edamame-fplab/bin/edamame_posture
for _ in \$(seq 1 30); do ss -ltn | grep -q '127.0.0.1:40152 ' || break; sleep 1; done
echo "starting the released service"
sudo systemctl start $SERVICE
echo "released daemon: \$(wait_rpc $RELEASED_VERSION 240)"
sleep 30
systemctl is-active $SERVICE
show_state
EOF
    ;;

  *) die "unknown command $CMD" ;;
esac
