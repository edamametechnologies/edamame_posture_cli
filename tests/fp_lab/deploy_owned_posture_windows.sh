#!/usr/bin/env bash
# deploy_owned_posture_windows.sh -- the Windows (shiawase) leg of
# deploy_owned_posture.sh: run the FP lab against a posture we own (the
# signed CI exe of the release candidate) on a dogfood PC that normally runs
# the released app and helper, then put the PC back exactly as it was.
#
#   deploy_owned_posture_windows.sh <command> [args]    (called by deploy_owned_posture.sh)
#
# The window, in order (Frank, 2026-10-05: "disable the helper, kill the app
# during your test and re-enable the helper and relaunch the app after, and
# disable your posture"):
#   fetch            download posture-binary-windows-x64 (signed exe) of CI run $FP_LAB_RUN_ID
#   push             copy the exe and the lab harness to C:\Users\<profile>\fp-lab
#   keys             copy the approved provider and Portal keys (owner-only ACL, never printed)
#   agents           install the agent CLIs the lab drives when missing (npm)
#   start            stop the app, disable the helper (recovery off first), start posture
#   status           what the lab preflight will see
#   run [args]       start run_fp_lab.py as a scheduled task (args go to `run`)
#   wait <run>       follow the run until its summary exists
#   collect <run>    copy the run back and shape attack-pattern candidates here
#   stop             stop and remove posture, re-enable the helper and its
#                    recovery, relaunch the app, delete the keys, verify
#
# Why each step:
# - The app hosts its own core on 40152 and the helper (40151) runs its own
#   capture and file monitoring: both stay off so only the owned build
#   observes the PC. The helper restarts itself on failure (recovery action
#   RESTART/0 ms) and 2.0.3+ cannot be stopped through the SCM, so recovery
#   is turned off and the service disabled before the process is killed;
#   `stop` puts back exactly the recorded start mode and recovery action.
# - Windows OpenSSH kills a session's processes when it ends, so posture and
#   the lab runner run as scheduled tasks in the account's existing
#   interactive session (/IT), as that account (the transcript observer's
#   home is the process account's profile, never SYSTEM's).
# - State isolation: core keeps its JSON and DPAPI secrets under %APPDATA%,
#   the app's directory. The owned posture runs with APPDATA (and
#   LOCALAPPDATA) pointed at fp-lab\state, so it never reads or rewrites the
#   app's config, history or Hub credentials, and it has no Hub credentials.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
WORKSPACE="$(cd "$REPO/.." && pwd)"
RUN_ID="${FP_LAB_RUN_ID:?FP_LAB_RUN_ID: the tests.yml run that built posture-binary-windows-x64}"
GH_REPO="${FP_LAB_GH_REPO:-edamametechnologies/edamame_posture_cli}"
CACHE="${FP_LAB_CACHE:-$HOME/Library/Caches/edamame-agents/fp-lab}"
OWNED_VERSION="${FP_LAB_OWNED_VERSION:-2.0.5}"
TARGET="${FP_LAB_WIN_TARGET:-flyonnet@172.30.81.81}"
ACCOUNT="${FP_LAB_WIN_ACCOUNT:-flyonnet}"
SECRETS="${FP_LAB_SECRETS:-$WORKSPACE/secrets}"
LABEL="windows-x64"
APP_AUMID="EDAMAMETechnologies.EDAMAMESecurity_rx2dyyqk4mc6r!edamame"
BIN_DIR="$CACHE/bin/$RUN_ID/$LABEL"

die() { echo "deploy_owned_posture_windows: $*" >&2; exit 2; }
say() { echo "== $*" >&2; }
CMD="${1:-}"; [[ -n "$CMD" ]] || { sed -n '2,37p' "$0"; exit 2; }
shift

SSH_OPTS=(-o ConnectTimeout=20 -o ServerAliveInterval=30 -o LogLevel=ERROR)
ssh_win() { ssh "${SSH_OPTS[@]}" "$TARGET" "$@"; }

# ps_run <preamble>: run the PowerShell script on stdin, after <preamble>
# (local values as PowerShell assignments) and PS_LIB, as a script file
# (no cmd/PowerShell quoting on the way, no command-line length limit).
PS_LIB=$(cat <<'PSLIB'
$ErrorActionPreference = "Continue"; $ProgressPreference = "SilentlyContinue"
$Lab = Join-Path $env:USERPROFILE "fp-lab"
$Cli = (Get-Command edamame_cli -ErrorAction SilentlyContinue).Source
function Wait-Rpc([string]$want, [int]$secs) {
  for ($i = 0; $i -lt $secs; $i++) {
    $v = (& $Cli rpc get_core_version 2>$null | Select-String '^Result:') -replace '^Result: ','' -replace '"',''
    if ("$v".StartsWith($want)) { return "$v" }
    Start-Sleep 1
  }
  return "timeout (last answer: $v)"
}
function Show-State {
  foreach ($m in "get_core_info","agentic_get_protection_status","is_capturing","get_connection","get_attack_pattern_detector_status","get_divergence_engine_status","get_transcript_observer_status") {
    "-- $m"; (& $Cli rpc $m 2>&1 | Out-String) -replace '\\','' | Select-String -AllMatches -Pattern 'Core version is [^,]*|"(enabled|is_connected|running|adjudication_mode|active_findings|active_alertable_findings|last_verdict|contributor_count)":[^,}]*|Result: (true|false)' | ForEach-Object { $_.Matches.Value }
  }
}
function Port-Owner([int]$port) {
  Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction SilentlyContinue | ForEach-Object { "$port pid=$($_.OwningProcess) $((Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name)" }
}
function Run-Task([string]$name, [string]$cmdFile) {
  schtasks /Create /TN $name /TR "`"$cmdFile`"" /SC ONCE /ST 00:00 /RU $Account /RL HIGHEST /IT /F | Out-Null
  schtasks /Run /TN $name | Out-Null
}
PSLIB
)
# ps_script <preamble> <script-file>: copy preamble + PS_LIB + script to the
# host and run it with `powershell -File`. An -EncodedCommand of the longer
# scripts exceeded cmd.exe's 8191-character command line ("La ligne de
# commande est trop longue", 2026-10-05). stdin passes through to the script
# ([Console]::In), which is how `keys` hands over secrets without echoing.
ps_script() {
  local pre="$1" body_file="$2" local_ps remote
  local_ps=$(mktemp "$CACHE/ps-XXXXXX")
  remote="fp-lab-$(basename "$local_ps").ps1"
  # The script removes itself first (already parsed), so the exit code is
  # the script's own.
  { printf '%s\n' 'Remove-Item -LiteralPath $PSCommandPath -Force -ErrorAction SilentlyContinue'
    printf '%s\n' "$pre"; printf '%s\n' "$PS_LIB"; cat "$body_file"; } > "$local_ps"
  scp -q "${SSH_OPTS[@]}" "$local_ps" "$TARGET:$remote" || { rm -f "$local_ps"; return 1; }
  rm -f "$local_ps"
  ssh_win "powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"%USERPROFILE%\\$remote\""
}
# ps_run <preamble>: the script on stdin.
ps_run() {
  local body_file rc
  body_file=$(mktemp "$CACHE/body-XXXXXX"); cat > "$body_file"
  ps_script "$1" "$body_file" < /dev/null; rc=$?
  rm -f "$body_file"; return $rc
}
# ps_run_input <preamble> <script>: the script as an argument; this
# process's stdin reaches the script (secrets).
ps_run_input() {
  local body_file rc
  body_file=$(mktemp "$CACHE/body-XXXXXX"); printf '%s\n' "$2" > "$body_file"
  ps_script "$1" "$body_file"; rc=$?
  rm -f "$body_file"; return $rc
}
PRE="\$Account = '$ACCOUNT'; \$Owned = '$OWNED_VERSION'; \$Aumid = '$APP_AUMID'"
SAVE_SECRET='
$name = $SecretFile; $path = Join-Path $Lab "secrets\$name"
New-Item -ItemType Directory -Force -Path (Split-Path $path) | Out-Null
$data = [Console]::In.ReadToEnd()
[IO.File]::WriteAllText($path, $data)
icacls $path /inheritance:r /grant:r "$($env:USERNAME):F" | Out-Null
(Get-Content $path) -replace "=.*","=<set>"
'


case "$CMD" in
  fetch)
    mkdir -p "$BIN_DIR"
    gh run view "$RUN_ID" --repo "$GH_REPO" --json headBranch,headSha,status,conclusion \
      --jq '"run \(.status)/\(.conclusion) on \(.headBranch)@\(.headSha)"'
    gh run download "$RUN_ID" --repo "$GH_REPO" -n "posture-binary-$LABEL" -D "$BIN_DIR"
    shasum -a 256 "$BIN_DIR/edamame_posture.exe" | tee "$BIN_DIR/SHA256"
    ;;

  push)
    [[ -f "$BIN_DIR/edamame_posture.exe" ]] || die "no exe in $BIN_DIR (run fetch first)"
    ps_run "$PRE" <<'PS'
New-Item -ItemType Directory -Force -Path "$Lab\bin","$Lab\secrets","$Lab\runs","$Lab\state","$Lab\harness" | Out-Null
"lab: $Lab"; "cli: $Cli $(& $Cli --version 2>&1 | Select-Object -First 1)"
PS
    scp -q "${SSH_OPTS[@]}" "$BIN_DIR/edamame_posture.exe" "$TARGET:fp-lab/bin/edamame_posture.exe"
    STAGE="$CACHE/stage-windows"; rm -rf "$STAGE"; mkdir -p "$STAGE/tests/fp_lab/tools" "$STAGE/tests/e2e" \
      "$STAGE/tests/security/triggers" "$STAGE/supported_agents"
    cp "$HERE"/*.py "$HERE"/*.md "$STAGE/tests/fp_lab/" 2>/dev/null || true
    cp "$REPO/tests/e2e/agent_harness.py" "$REPO/tests/e2e/supported_agents.py" "$STAGE/tests/e2e/"
    cp "$REPO/tests/security/triggers/_edamame_cli.py" "$STAGE/tests/security/triggers/"
    cp "$WORKSPACE/edamame_foundation/supported_agents/index.json" "$STAGE/supported_agents/"
    cp "$WORKSPACE/edamame_core/tools/fp_corpus_from_export.sh" "$STAGE/tests/fp_lab/tools/"
    COPYFILE_DISABLE=1 tar --no-xattrs -C "$STAGE" -czf "$CACHE/harness-windows.tgz" .
    scp -q "${SSH_OPTS[@]}" "$CACHE/harness-windows.tgz" "$TARGET:fp-lab/harness.tgz"
    ps_run "$PRE" <<'PS'
Remove-Item -Recurse -Force "$Lab\harness" -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path "$Lab\harness" | Out-Null
tar -xzf "$Lab\harness.tgz" -C "$Lab\harness"; Remove-Item "$Lab\harness.tgz"
$sig = Get-AuthenticodeSignature "$Lab\bin\edamame_posture.exe"
"signature: $($sig.Status) $($sig.SignerCertificate.Subject)"
& "$Lab\bin\edamame_posture.exe" --version
Set-Location "$Lab\harness"; python tests\fp_lab\run_fp_lab.py validate
PS
    ;;

  keys)
    for f in claude.env openai.env cursor.env agentic.env; do [[ -f "$SECRETS/$f" ]] || die "missing $SECRETS/$f"; done
    # KEY=value lines (no `export`), owner-only ACL, never echoed.
    grep -hE '^(export )?(ANTHROPIC_API_KEY|OPENAI_API_KEY|CURSOR_API_KEY)=' \
      "$SECRETS/claude.env" "$SECRETS/openai.env" "$SECRETS/cursor.env" | sed 's/^export //' \
      | ps_run_input "$PRE; \$SecretFile = 'providers.env'" "$SAVE_SECRET"
    grep -hE '^(export )?EDAMAME_LLM_API_KEY=' "$SECRETS/agentic.env" | sed 's/^export //' \
      | ps_run_input "$PRE; \$SecretFile = 'portal.env'" "$SAVE_SECRET"
    ;;

  agents)
    # The agent CLIs the lab drives (Claude Code, Codex), user-level, through
    # npm like the fleet E2E; an installed one is left as it is.
    ps_run "$PRE" <<'PS'
# npm.cmd, not npm (npm.ps1 is blocked by the execution policy and failed
# silently); a CLI counts as installed only when --version answers like the
# real one (shiawase had a July smoke-test stub claude.cmd in the npm bin).
foreach ($pair in @(@("claude","@anthropic-ai/claude-code","Claude Code"), @("codex","@openai/codex","codex-cli"))) {
  $c = Get-Command $pair[0] -ErrorAction SilentlyContinue
  $v = if ($c) { & $pair[0] --version 2>&1 | Select-Object -First 1 } else { "" }
  if ("$v" -match $pair[2]) { "$($pair[0]): $($c.Source)" }
  else { "installing $($pair[1]) (found: $v)"; & npm.cmd install -g $pair[1] 2>&1 | Select-Object -Last 3 }
}
foreach ($t in "claude","codex") { "$t version: $(& $t --version 2>&1 | Select-Object -First 1)" }
PS
    ;;

  start)
    WANT_SHA=$(cut -d' ' -f1 "$BIN_DIR/SHA256" 2>/dev/null | tr 'a-f' 'A-F') || die "no $BIN_DIR/SHA256 (fetch first)"
    HOST_SHA=$(ps_run "$PRE" <<'PS' | tr -d '\r' | tail -n 1
(Get-FileHash "$Lab\bin\edamame_posture.exe" -Algorithm SHA256).Hash
PS
)
    [[ "$WANT_SHA" == "$HOST_SHA" ]] || die "host exe $HOST_SHA is not run $RUN_ID's $WANT_SHA (push again)"
    ps_run "$PRE" <<'PS' | tee "$CACHE/state/shiawase-$(date +%Y%m%d-%H%M%S)-pre.txt"
if (-not (Test-Path "$Lab\bin\edamame_posture.exe")) { "push first"; exit 1 }
if (-not (Test-Path "$Lab\secrets\portal.env")) { "keys first"; exit 1 }
$svc = Get-CimInstance Win32_Service -Filter "Name='edamame_helper'"
$app = Get-Process edamame -ErrorAction SilentlyContinue
$state = [ordered]@{ app = [bool]$app; helper_state = $svc.State; helper_start = $svc.StartMode;
  helper_failure = ((sc.exe qfailure edamame_helper) -join "`n") }
if (-not (Test-Path "$Lab\state\pre-state.json")) { $state | ConvertTo-Json | Set-Content "$Lab\state\pre-state.json" }
Get-Content "$Lab\state\pre-state.json"
"stopping the app"
Stop-Process -Name edamame -Force -ErrorAction SilentlyContinue
"disabling the helper (recovery off first)"
sc.exe failure edamame_helper reset= 0 actions= '""' | Out-Null
Set-Service edamame_helper -StartupType Disabled
Stop-Process -Name edamame_helper -Force -ErrorAction SilentlyContinue
for ($i = 0; $i -lt 30 -and ((Get-Process edamame,edamame_helper -ErrorAction SilentlyContinue) -or (Port-Owner 40151) -or (Port-Owner 40152)); $i++) { Start-Sleep 1 }
if (Get-Process edamame,edamame_helper -ErrorAction SilentlyContinue) { "app or helper still running"; exit 1 }
if ((Port-Owner 40151) -or (Port-Owner 40152)) { "ports still held: $(Port-Owner 40151) $(Port-Owner 40152)"; exit 1 }
"app and helper stopped, ports free"
New-Item -ItemType Directory -Force -Path "$Lab\state\AppData\Roaming","$Lab\state\AppData\Local" | Out-Null
$launcher = @"
@echo off
set APPDATA=$Lab\state\AppData\Roaming
set LOCALAPPDATA=$Lab\state\AppData\Local
for /f "usebackq tokens=1,* delims==" %%a in ("$Lab\secrets\portal.env") do set "%%a=%%b"
"$Lab\bin\edamame_posture.exe" foreground-start -v --packet-capture --agentic-mode analyze --agentic-provider edamame > "$Lab\state\posture.log" 2>&1
"@
Set-Content -Encoding ascii "$Lab\bin\start-posture.cmd" $launcher
"starting the owned posture (scheduled task in $Account's session)"
Run-Task "EdamameFpLabPosture" "$Lab\bin\start-posture.cmd"
"owned daemon: $(Wait-Rpc $Owned 240)"
Start-Sleep 20
Show-State
PS
    ;;

  status)
    ps_run "$PRE" <<'PS'
Get-Content "$Lab\state\pre-state.json" -ErrorAction SilentlyContinue
"app: $([bool](Get-Process edamame -ErrorAction SilentlyContinue))  helper: $((Get-Service edamame_helper).Status)/$((Get-Service edamame_helper).StartType)"
Port-Owner 40151; Port-Owner 40152
Show-State
PS
    ;;

  run)
    NAME="shiawase-$(date +%Y%m%d-%H%M%S)"
    ARGS=""; for a in "$@"; do ARGS="$ARGS $a"; done
    ps_run "$PRE; \$Name = '$NAME'; \$Args2 = '$ARGS'" <<'PS'
$runner = @"
@echo off
for /f "usebackq tokens=1,* delims==" %%a in ("$Lab\secrets\providers.env") do set "%%a=%%b"
set EDAMAME_CLI_BIN=$Cli
set PATH=%PATH%;C:\Program Files\Git\bin;%APPDATA%\npm;%USERPROFILE%\.cargo\bin;%USERPROFILE%\.local\bin
cd /d "$Lab\harness"
python tests\fp_lab\run_fp_lab.py run --out "$Lab\runs\$Name" --expect-core-version $Owned --set-adjudication auto $Args2 > "$Lab\runs\$Name.log" 2>&1
"@
Set-Content -Encoding ascii "$Lab\bin\run-lab.cmd" $runner
Run-Task "EdamameFpLabRun" "$Lab\bin\run-lab.cmd"
Start-Sleep 5; "started $Name"; Get-Content "$Lab\runs\$Name.log" -Tail 5 -ErrorAction SilentlyContinue
PS
    echo "$NAME"
    ;;

  wait)
    NAME="${1:?run name}"
    while :; do
      OUT=$(ps_run "$PRE; \$Name = '$NAME'" <<'PS'
if (Test-Path "$Lab\runs\$Name\summary.md") { "DONE"; Get-Content "$Lab\runs\$Name\summary.md"; exit 0 }
$t = (schtasks /Query /TN EdamameFpLabRun /FO CSV 2>$null | ConvertFrom-Csv).Status
"STATE $t"; Get-Content "$Lab\runs\$Name.log" -Tail 2 -ErrorAction SilentlyContinue
PS
)
      echo "$OUT" | tail -n 3
      case "$OUT" in DONE*) echo "$OUT"; break ;; esac
      if echo "$OUT" | grep -q "^STATE Ready"; then die "runner exited without a summary"; fi
      sleep 60
    done
    ;;

  collect)
    NAME="${1:?run name}"
    DEST="$CACHE/runs/$NAME"; mkdir -p "$DEST"
    ps_run "$PRE; \$Name = '$NAME'" <<'PS'
tar -czf "$Lab\runs\$Name.tgz" -C "$Lab\runs" $Name "$Name.log"
PS
    scp -q "${SSH_OPTS[@]}" "$TARGET:fp-lab/runs/$NAME.tgz" "$CACHE/runs/$NAME.tgz"
    tar -C "$CACHE/runs" -xzf "$CACHE/runs/$NAME.tgz" && rm -f "$CACHE/runs/$NAME.tgz"
    mv "$CACHE/runs/$NAME.log" "$DEST/run.log" 2>/dev/null || true
    python3 "$HERE/run_fp_lab.py" shape "$DEST" \
      --corpus-tool "$WORKSPACE/edamame_core/tools/fp_corpus_from_export.sh" || true
    python3 "$HERE/run_fp_lab.py" summarize "$DEST" >/dev/null || true
    say "artifacts in $DEST"
    ;;

  stop)
    ps_run "$PRE" <<'PS'
"stopping the owned posture"
schtasks /End /TN EdamameFpLabRun 2>$null | Out-Null
schtasks /End /TN EdamameFpLabPosture 2>$null | Out-Null
Get-Process edamame_posture -ErrorAction SilentlyContinue | Where-Object { $_.Path -like "$Lab\*" } | Stop-Process -Force
schtasks /Delete /TN EdamameFpLabRun /F 2>$null | Out-Null
schtasks /Delete /TN EdamameFpLabPosture /F 2>$null | Out-Null
for ($i = 0; $i -lt 30 -and (Port-Owner 40152); $i++) { Start-Sleep 1 }
"removing the owned posture"
Remove-Item -Force "$Lab\bin\edamame_posture.exe","$Lab\bin\start-posture.cmd","$Lab\bin\run-lab.cmd" -ErrorAction SilentlyContinue
$pre = Get-Content "$Lab\state\pre-state.json" -Raw | ConvertFrom-Json
"re-enabling the helper (start mode $($pre.helper_start), recovery restart/0)"
$mode = if ($pre.helper_start -eq "Auto") { "Automatic" } elseif ($pre.helper_start -eq "Manual") { "Manual" } else { "Automatic" }
Set-Service edamame_helper -StartupType $mode
sc.exe failure edamame_helper reset= 0 actions= restart/0 | Out-Null
if ($pre.helper_state -eq "Running") { Start-Service edamame_helper -ErrorAction SilentlyContinue }
for ($i = 0; $i -lt 30 -and -not (Port-Owner 40151); $i++) { Start-Sleep 1 }
"helper: $((Get-Service edamame_helper).Status)/$((Get-Service edamame_helper).StartType)"; (sc.exe qfailure edamame_helper | Select-String "RESTART|FAILURE_ACTIONS") -join " "
if ($pre.app) {
  "relaunching the app in $Account's session"
  Set-Content -Encoding ascii "$Lab\bin\start-app.cmd" "@echo off`r`nstart `"`" explorer.exe shell:AppsFolder\$Aumid"
  Run-Task "EdamameFpLabApp" "$Lab\bin\start-app.cmd"
  for ($i = 0; $i -lt 90 -and -not (Port-Owner 40152); $i++) { Start-Sleep 2 }
  schtasks /Delete /TN EdamameFpLabApp /F 2>$null | Out-Null
  Remove-Item -Force "$Lab\bin\start-app.cmd" -ErrorAction SilentlyContinue
}
"app: $([bool](Get-Process edamame -ErrorAction SilentlyContinue))"; Port-Owner 40151; Port-Owner 40152
"deleting the lab keys"
Remove-Item -Force "$Lab\secrets\*.env" -ErrorAction SilentlyContinue
Rename-Item "$Lab\state\pre-state.json" "pre-state-$(Get-Date -Format yyyyMMddHHmmss).json"
PS
    ;;

  *) die "unknown command $CMD" ;;
esac
