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
RUN_ID="${FP_LAB_RUN_ID:?FP_LAB_RUN_ID: the tests.yml run that built posture-binary-ubuntu-x64}"
GH_REPO="${FP_LAB_GH_REPO:-edamametechnologies/edamame_posture_cli}"
CACHE="${FP_LAB_CACHE:-$HOME/Library/Caches/edamame-agents/fp-lab}"
# The released service's version: FP_LAB_RELEASED_VERSION, else the host's
# installed edamame-posture package (read on the host by `stop`).
RELEASED_VERSION="${FP_LAB_RELEASED_VERSION:-}"

die() { echo "deploy_owned_posture: $*" >&2; exit 2; }
say() { echo "== $*" >&2; }

# The owned build's version: FP_LAB_OWNED_VERSION, else the candidate run's
# Cargo.toml at its head commit, cached beside the binary. A literal default
# went stale every release: the first 2.0.6 windows aborted at preflight on
# "core version 2.0.6 is not the owned build 2.0.5" (2026-10-09).
owned_version() {
  if [[ -n "${FP_LAB_OWNED_VERSION:-}" ]]; then echo "$FP_LAB_OWNED_VERSION"; return; fi
  local f="$CACHE/bin/$RUN_ID/VERSION" sha v
  if [[ ! -s "$f" ]]; then
    sha=$(gh run view "$RUN_ID" --repo "$GH_REPO" --json headSha --jq .headSha) || die "cannot read run $RUN_ID"
    v=$(gh api -H "Accept: application/vnd.github.raw" "repos/$GH_REPO/contents/Cargo.toml?ref=$sha" \
      | sed -n 's/^version = "\([^"]*\)".*/\1/p' | head -n 1)
    [[ -n "$v" ]] || die "no version in $GH_REPO Cargo.toml at $sha (set FP_LAB_OWNED_VERSION)"
    mkdir -p "$(dirname "$f")"; echo "$v" > "$f"
  fi
  cat "$f"
}

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
case "$CMD" in start|run) OWNED_VERSION=$(owned_version) ;; esac

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

  keys)
    # The agents' provider keys (approved by Frank, 2026-10-05), 0600, never
    # echoed; `stop` deletes them. The Portal key comes from the released
    # service's EnvironmentFile, which the owned unit reads.
    SECRETS="${FP_LAB_SECRETS:-$WORKSPACE/secrets}"
    for f in claude.env openai.env; do [[ -f "$SECRETS/$f" ]] || die "missing $SECRETS/$f"; done
    grep -hE '^(export )?(ANTHROPIC_API_KEY|OPENAI_API_KEY)=' "$SECRETS/claude.env" "$SECRETS/openai.env" \
      | sed 's/^export //; s/^/export /' \
      | ssh_host 'umask 077; mkdir -p ~/fp-lab/secrets; cat > ~/fp-lab/secrets/providers.env; chmod 600 ~/fp-lab/secrets/providers.env; sed -E "s/=.*/=<set>/" ~/fp-lab/secrets/providers.env'
    ;;

  agents)
    # Claude Code and Codex, user-level, when missing. A Codex binary alone
    # is not an install: since 0.160 its tools run in codex-code-mode-host,
    # beside the binary (test-mint 2026-10-06: a copied binary answered
    # --version, ran no tool, and every Codex case was a SKIP). Without npm,
    # Codex comes from the npm registry's platform tarball, verified against
    # the registry's sha512.
    ssh_host 'bash -s' <<'EOF'
export PATH="$HOME/.local/bin:$HOME/.npm-global/bin:$PATH"
codex_ok() {
  codex --version 2>/dev/null | grep -q codex-cli || return 1
  [ -x "$(dirname "$(readlink -f "$(command -v codex)")")/codex-code-mode-host" ]
}
install_codex_tarball() {
  case "$(uname -m)" in x86_64) arch=x64 ;; aarch64|arm64) arch=arm64 ;; *) echo "no Codex build for $(uname -m)"; return 1 ;; esac
  python3 - "$arch" <<'PY'
import base64, hashlib, json, os, sys, tarfile, urllib.request
arch = sys.argv[1]
reg = "https://registry.npmjs.org/@openai%2Fcodex"
ver = json.load(urllib.request.urlopen(reg))["dist-tags"]["latest"]
meta = json.load(urllib.request.urlopen(f"{reg}/{ver}-linux-{arch}"))
data = urllib.request.urlopen(meta["dist"]["tarball"]).read()
algo, want = meta["dist"]["integrity"].split("-", 1)
if base64.b64encode(hashlib.new(algo, data).digest()).decode() != want:
    sys.exit("codex tarball integrity mismatch")
root = os.path.expanduser(f"~/.local/share/codex/{ver}")
os.makedirs(root, exist_ok=True)
tmp = os.path.join(root, "package.tgz")
open(tmp, "wb").write(data)
with tarfile.open(tmp) as t:
    t.extractall(root, filter="tar")
os.remove(tmp)
vendor = os.path.join(root, "package", "vendor")
triple = next(d for d in os.listdir(vendor) if d.endswith("linux-musl"))
binary = os.path.join(vendor, triple, "bin", "codex")
link = os.path.expanduser("~/.local/bin/codex")
os.makedirs(os.path.dirname(link), exist_ok=True)
if os.path.lexists(link):
    if os.path.islink(link):
        os.remove(link)
    else:
        os.replace(link, link + ".standalone")
os.symlink(binary, link)
print(f"installed codex {ver} from the registry ({triple})")
PY
}
if command -v npm >/dev/null; then
  npm config get prefix | grep -q "$HOME" || npm config set prefix "$HOME/.npm-global"
fi
if claude --version 2>/dev/null | grep -q "Claude Code"; then echo "claude: $(command -v claude)"
elif command -v npm >/dev/null; then echo "installing @anthropic-ai/claude-code"; npm install -g @anthropic-ai/claude-code 2>&1 | tail -n 2
else echo "claude missing and no npm"; fi
if codex_ok; then echo "codex: $(command -v codex)"
elif command -v npm >/dev/null; then echo "installing @openai/codex"; npm install -g @openai/codex 2>&1 | tail -n 2
else install_codex_tarball; fi
for t in claude codex; do echo "$t version: $($t --version 2>&1 | head -1)"; done
codex_ok && echo "codex: code-mode host present" || echo "codex: NOT USABLE (no code-mode host)"
EOF
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
    # The binary on the host must be the one fetched for this run: a push
    # whose upload broke leaves the previous binary in place (2026-10-05: a
    # reset connection left build 1 running under build 3's name).
    [[ -f "$BIN_DIR/SHA256" ]] || die "no $BIN_DIR/SHA256 (run fetch first)"
    WANT_SHA=$(cut -d' ' -f1 "$BIN_DIR/SHA256")
    HOST_SHA=$(ssh_host 'sha256sum ~/fp-lab/bin/edamame_posture | cut -d" " -f1')
    [[ "$WANT_SHA" == "$HOST_SHA" ]] || die "host binary $HOST_SHA is not run $RUN_ID's $WANT_SHA (push again)"
    ssh_host 'bash -s' <<EOF
$REMOTE_LIB
set -e
# An owned daemon still running is this window's only if it runs this
# build: an r3 daemon a window never stopped passed for r5's (2026-10-06).
if systemctl is-active --quiet $UNIT; then
  if [ "\$(sudo sha256sum /var/lib/edamame-fplab/bin/edamame_posture 2>/dev/null | cut -d" " -f1)" = "$WANT_SHA" ]; then
    echo "owned daemon already running (this build)"; exit 0
  fi
  echo "an owned daemon of another build is running: run stop first"; exit 1
fi
test -x ~/fp-lab/bin/edamame_posture
mkdir -p ~/fp-lab/state
# Once per window (a marker that stop removes): record whether the GUI ran,
# and give the owned build an empty state. A start after a failed one must
# not record the GUI it stopped itself as "stopped", and an earlier window's
# findings and model would be absorbed into the baseline, hiding a false
# positive that build raised too. The earlier state stays for forensics.
if [ ! -f ~/fp-lab/state/window ]; then
  if pgrep -u "\$USER" -f /usr/lib/edamame-security/edamame_security >/dev/null; then
    echo running > ~/fp-lab/state/gui
  else echo stopped > ~/fp-lab/state/gui; fi
  if sudo test -d /var/lib/edamame-fplab/state; then
    prev=/var/lib/edamame-fplab/state-\$(date +%Y%m%d%H%M%S)
    sudo mv /var/lib/edamame-fplab/state "\$prev"; echo "earlier owned state moved to \$prev"
  fi
  # The released daemon's resources, the reference beside the candidate's
  # (daemon_perf): same product, same host, before the window.
  rpid=\$(systemctl show $SERVICE -p MainPID --value 2>/dev/null)
  if [ -n "\$rpid" ] && [ "\$rpid" != 0 ] && [ -r /proc/\$rpid/status ]; then
    rss_kb=\$(awk '/^VmRSS:/{print \$2}' /proc/\$rpid/status)
    up=\$(ps -o etimes= -p \$rpid | tr -d ' ')
    cpu_ns=\$(systemctl show $SERVICE -p CPUUsageNSec --value)
    printf '{"what": "released %s", "rss_mb": %s, "uptime_secs": %s, "cpu_seconds": %s}\\n' \
      "$SERVICE" "\$((rss_kb / 1024))" "\${up:-0}" "\$((\${cpu_ns:-0} / 1000000000))" > ~/fp-lab/state/released-perf.json
    cat ~/fp-lab/state/released-perf.json
  fi
  touch ~/fp-lab/state/window
fi
sudo install -d -m 0700 /var/lib/edamame-fplab /var/lib/edamame-fplab/state
sudo install -d -m 0755 /var/lib/edamame-fplab/bin /var/lib/edamame-fplab/log
sudo install -m 0755 ~/fp-lab/bin/edamame_posture /var/lib/edamame-fplab/bin/edamame_posture
# The GUI is a thin client of whichever daemon owns the port: it stays off
# for the window so nothing but the lab drives the owned daemon.
if pkill -u "\$USER" -f /usr/lib/edamame-security/edamame_security; then echo "GUI stopped"; fi
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
    # Only in an open window: after a failed start the released service
    # answers, and the runner's preflight refusing it is the only guard
    # (2026-10-09).
    ssh_host "systemctl is-active --quiet $UNIT" || die "no owned daemon ($UNIT): run start first"
    ssh_host 'bash -s' <<EOF
mkdir -p ~/fp-lab/runs
cd ~/fp-lab/harness
export PATH="\$HOME/.local/bin:\$HOME/.npm-global/bin:\$PATH"
if [ -f ~/fp-lab/secrets/providers.env ]; then set -a; . ~/fp-lab/secrets/providers.env; set +a; fi
setsid -f python3 tests/fp_lab/run_fp_lab.py run --out ~/fp-lab/runs/$NAME \
  --expect-core-version $OWNED_VERSION --set-adjudication auto \
  --perf-reference ~/fp-lab/state/released-perf.json $ARGS \
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
      # [r]: the remote shell's own command line carries the pattern, so a
      # plain one always matched and `wait` never saw the runner exit.
      if ! ssh_host "pgrep -f '[r]un_fp_lab.py run --out .*/$NAME' >/dev/null"; then
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
rm -f ~/fp-lab/secrets/*.env
# The installed copy is redundant with ~/fp-lab/bin (start reinstalls it); the
# owned state and log stay in /var/lib/edamame-fplab for forensics.
sudo rm -f /var/lib/edamame-fplab/bin/edamame_posture
for _ in \$(seq 1 30); do ss -ltn | grep -q '127.0.0.1:40152 ' || break; sleep 1; done
echo "starting the released service"
sudo systemctl start $SERVICE
rel="$RELEASED_VERSION"
[ -n "\$rel" ] || rel=\$(dpkg-query -W -f='\${Version}' edamame-posture 2>/dev/null | cut -d- -f1)
echo "released daemon: \$(wait_rpc "\$rel" 240)"
if [ "\$(cat ~/fp-lab/state/gui 2>/dev/null)" = running ]; then
  # Relaunch in the live desktop session (dogfood-status skill): inherit its
  # DISPLAY / DBUS from the running cinnamon-session.
  CPID=\$(pgrep -f cinnamon-session | head -1)
  if [ -n "\$CPID" ]; then
    eval "\$(tr "\\0" "\\n" < /proc/\$CPID/environ | grep -E "^(DISPLAY|DBUS_SESSION_BUS_ADDRESS|XDG_RUNTIME_DIR)=" | sed "s/^/export /")"
    setsid env DISPLAY="\$DISPLAY" DBUS_SESSION_BUS_ADDRESS="\$DBUS_SESSION_BUS_ADDRESS" XDG_RUNTIME_DIR="\$XDG_RUNTIME_DIR" \
      XAUTHORITY="\$HOME/.Xauthority" /usr/lib/edamame-security/edamame_security >> ~/edamame_security_dogfood.log 2>&1 < /dev/null &
    sleep 6
  fi
  pgrep -f /usr/lib/edamame-security/edamame_security >/dev/null && echo "GUI: running" || echo "GUI: NOT RUNNING"
fi
rm -f ~/fp-lab/state/window
sleep 30
systemctl is-active $SERVICE
show_state
EOF
    ;;

  *) die "unknown command $CMD" ;;
esac
