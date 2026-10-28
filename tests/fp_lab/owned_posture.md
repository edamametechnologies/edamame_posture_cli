# The owned posture daemon

The FP lab measures the detection code we are about to ship, so it runs
against a posture daemon built from that code, on a real host, and gives the
host back on its released service afterwards. `deploy_owned_posture.sh`
does this on test-mint (Linux) and dispatches to
`deploy_owned_posture_macos.sh` (fmba-3) and `deploy_owned_posture_windows.sh`
(shiawase); this page is their design. The end-to-end sequence is in the
README ("The release candidate, end to end").

## Which binary

Never build locally for the lab (the operator Mac's swap is the constraint).
Use the binary CI built from the commit under test: `tests.yml` uploads
`posture-binary-<label>` from its build jobs (labels `ubuntu-x64`,
`ubuntu-arm64`, `macos-arm64` (signed pkg), `windows-x64` (signed exe)),
kept 7 days.

```bash
FP_LAB_RUN_ID=<tests.yml run id> tests/fp_lab/deploy_owned_posture.sh test-mint fetch
```

`fetch` prints the run's head SHA; check it is the commit you mean to test
(posture's `Cargo.lock` pins the core / foundation / flodbadd commits).

## Linux (test-mint): what `start` and `stop` do

test-mint runs the released posture as the systemd service
`edamame_posture` (as root, Hub-connected as the dogfood identity, Portal key
from `/etc/edamame_posture.env`), plus the Linux GUI, which is a thin gRPC
client of whichever daemon owns `127.0.0.1:40152`.

`start`:

0. refuses an owned daemon of another build (it must be `stop`ped first);
   once per window (a marker `stop` removes) records whether the GUI ran and
   the released service's RSS and CPU (`~/fp-lab/state/released-perf.json`,
   the resources reference), and moves the previous window's owned state
   aside (`/var/lib/edamame-fplab/state-<time>`), so the candidate starts
   empty;
1. installs the owned binary to `/var/lib/edamame-fplab/bin/`;
2. stops `edamame_posture.service` and waits for port 40152 to free;
3. starts the owned daemon as the transient unit `edamame-fplab`:
   `foreground-start -v --agentic-mode analyze --agentic-provider edamame
   --packet-capture`, no `--user/--domain/--pin` (never connects to the Hub),
   `EnvironmentFile=/etc/edamame_posture.env` (the host's own Portal
   configuration, read by systemd on the host; the script never touches the
   value), and two `BindPaths`:
   - `/var/lib/edamame-fplab/state` over `/root/.edamame`: core keeps a root
     process's persisted JSON and its file-backed secret store there
     (`storage_home`, `secrets_location`), so the owned build starts from an
     empty state and never reads, migrates or blanks the released daemon's
     config, history, Hub PIN or Portal key;
   - `/var/lib/edamame-fplab/log` over `/var/log/edamame`;
4. waits for `get_core_version` to answer with the owned version and prints
   the protection / capture / detector / divergence / FIM state.

`analyze` turns the protection switch on (Assistant at Review, both engines,
capture, file monitor) and pins `llm` adjudication; the runner's
`--set-adjudication auto` (passed by `deploy ... run`) puts both engines back
on the shipped default (advisory while the Portal answers), which is what the
dogfood hosts and the app run.

`stop`: stops `edamame-fplab`, starts `edamame_posture.service`, waits for
the released version on the RPC port and prints the same state block. Check
`active_alertable_findings`, `running` and `is_connected: true` against the
`record pre-lab` output in `~/Library/Caches/edamame-agents/fp-lab/state/`.

Checked on 2026-10-05: during the lab the released daemon's
`/root/.edamame` files kept the mtimes of its own shutdown, and
`findmnt -N <owned pid>` showed both binds.

## Agents on the host

The lab user must be the host's console user: a root daemon's transcript
observer reads the home of the single logged-in non-root user
(`edamame_foundation::console_user`). On test-mint that is `azureuser`.
Installed user-level, nothing system-wide:

- Claude Code: official installer (`~/.local/bin/claude`, native build).
- Codex: `agents` installs it from the npm registry's platform tarball
  (integrity-checked) under `~/.local/share/codex/<ver>` and links
  `~/.local/bin/codex`: since 0.160 a Codex binary without its
  `codex-code-mode-host` runs no tool (2026-10-06).
- uv (`~/.local/bin/uv`): test-mint has no `python3-venv`; the venv
  scenarios fall back to it.
- No Node.js on test-mint: the npm scenarios report SKIP there.

Provider keys: `keys` copies them from the operator's
`~/Programming/secrets` to an owner-only file on the host for the window
(approved by Frank, 2026-10-05; over SSH stdin, never printed), and `stop`
deletes it. `run` loads them into the runner's environment; the runner
removes them from its own environment at start and hands each one only to
the agent that needs it, for the length of its drive. Without them the agent
scenarios report SKIP with the reason; the direct scenarios still run.

## macOS (fmba-3): what the leg needs

- **The window stops the app and the helper, and `stop` brings both back**
  (Frank, 2026-10-05). The standalone app hosts its own core on 40152 (core
  per frontend) and the helper runs its own capture and file monitoring;
  with either running, the host is observed twice and the lab cannot tell
  which build produced a finding. `start` quits the app, `launchctl
  disable` + `bootout` the helper, and checks 40151/40152 are free; `stop`
  removes the owned posture (bundle, link, pkg receipt, root state), `enable`
  + `bootstrap` the helper, and relaunches the app in the console session
  (`launchctl asuser`). Implemented in `deploy_owned_posture_macos.sh`.
- **Binary:** `posture-binary-macos-arm64` is the signed, notarized pkg with
  the Endpoint Security provisioning profile. Installing it places the bundle
  under `/Library/Application Support/EDAMAME/EDAMAME-Posture/` and links
  `/usr/local/bin/edamame_posture`; restore by removing them (or reinstalling
  the previous pkg) after the window.
- **Full Disk Access: no approval click.** macOS creates an Endpoint
  Security client only when the client's responsible process holds FDA, and
  posture takes process lineage, FIM writer attribution and task-port events
  from ES (`flodbadd/src/l7_es.rs`; without it: FSEvents and polling, and
  "ES client creation failed" in the log). On fmba-3 the root SSH session's
  responsible process, `/usr/libexec/sshd-keygen-wrapper`, holds FDA
  (TCC.db, granted 2026-05-29), so a posture started from that session gets
  ES without a GUI approval. `start` greps the daemon log for an ES failure.
- **State isolation:** a root posture keeps its records under root's own
  home whatever `$HOME` says: the `edamame_posture` defaults domain,
  `/var/root/.edamame` (file secrets) and, for records that outgrew the
  defaults (2.0.3+), `/var/root/Library/Application Support/edamame_posture`.
  `start` saves all three once per window (`/var/root/fp-lab/original`) and
  clears them before every start; `stop` imports them back exactly and keeps
  the lab's copy (`lab-state-<time>`) for forensics.
- **edamame_cli:** do NOT use the brew 2.0.4 CLI on fmba-3: through 2.0.4 a
  CLI one-shot removes the app's Portal key and Hub PIN from
  `~/.edamame/secrets` (fixed in core 0480c973, 2.0.5). `push` copies a 2.0.5
  CLI (`FP_LAB_CLI`) to `~/fp-lab/bin/edamame_cli`, which the runner uses.
- **Observer home:** start posture with `sudo` from the console user's shell
  (macOS sudoers keeps `HOME`), so the observer reads that user's
  `~/.claude` / `~/.codex`.
- **Start/stop:** `start` installs the candidate pkg and starts it
  disconnected with `--packet-capture --agentic-mode analyze
  --agentic-provider edamame` and the Portal key from
  `/var/root/fp-lab/portal.env`; it prints the ES status from the newest
  posture log. `stop` removes the bundle, link and pkg receipt, restores
  root's state, re-enables the helper and relaunches the app.

- **Reaching fmba-3:** it moves between networks; resolve the address with
  `edamame_app/.claude/skills/dogfood-status/scripts/fmba_host.sh` and pass
  it as `FP_LAB_MAC_HOST=<addr>` (rule `self-hosted-runners.mdc` "Reaching
  fmba-3"). If it leaves the network mid-window, the run is not a gate leg:
  run `stop` as soon as it answers again.
- **A fresh install can take minutes** (fmba-3, 2026-10-16: 3 min and 35
  min). Both the pkg `installer` and the daemon's Endpoint Security client
  wait on macOS after a new binary is installed; the installer looked hung
  twice. If the receipt is written (`pkgutil --pkg-info
  com.edamametechnologies.edamame-posture`) and `installer` still runs, the
  install is done: killing it lets `start` continue. `start` then waits for
  "ES client subscribed" (up to 45 min) and checks that FIM runs on Endpoint
  Security, restarting the file monitor only if it started before the client
  (posture a341c3a, d3ff67d). A window that ran without it grades file
  events with no writer (FP-MAC-37): not a valid leg.
- **Never `lsof` on fmba-3:** a stale Time Machine SMB mount makes it hang
  uninterruptibly (five stuck after one window). The scripts check ports with
  `netstat` (posture e30ef79).

## macOS on kralizec-3 (when fmba-3 is away)

The operator's workstation can carry the macOS leg, with the operator's
consent: the window quits the `flutter run` debug app and the hand-started
helper.
- Driver: `/Volumes/Kari/flyonnet/Temporaire/edamame-agents/fp_lab_window_kralizec_<version>.sh`
  (`FP_LAB_MAC_HOST=localhost`); its stop runs a copy of
  `deploy_owned_posture_macos.sh` regenerated from the current script with
  one change, the relaunch of the debug bundle
  (`edamame_app/build/macos/Build/Products/Debug/EDAMAME Security.app`)
  instead of `open -a`: `/Applications` holds an old app that must never be
  opened against the 2.0 state. Regenerate that copy before every window.
- Pause both cargo-hygiene LaunchAgents (`launchctl bootout gui/$UID
  ~/Library/LaunchAgents/tech.edamame.cargo-hygiene{,-lowwater}.plist`)
  for the whole window and `bootstrap` them after: with the debug app down
  the hourly job runs `make clean` and deletes the debug build.
- Do not run other lab windows from this Mac at the same time: their SSH
  traffic and keys are observed as ambient activity.
- Ambient findings are expected (the operator's own agent sessions, desktop
  apps). Classify each FAIL by what it names: a divergence incident whose
  session `source_path` is not under `fp-lab/ws/`, or an attack-pattern
  finding on a process the lab does not drive, is ambient; a lab-session or
  lab-process finding is a blocker.

## Windows (shiawase): what the leg needs

- **The app owns the RPC port and needs a logged-in session** (Parallels
  Client RDP, see the dogfood-status skill). `start` records the app and the
  helper (state, start mode, recovery action, resources), stops the app,
  turns the helper's recovery action off, disables and stops it (posture is
  standalone: Npcap and ETW in process), and checks 40151/40152 are free.
  `stop` ends the daemon's whole process tree (the `powershell.exe` children
  of its checks inherit its handle on `posture.log`, and a surviving one
  blocks the next `start`), checks the log is free, restores the start mode
  and recovery action, starts the helper and relaunches the app in the
  user's session. Posture and the runner run as scheduled tasks in that
  session (OpenSSH kills its own session's processes when the connection
  ends).
- **State isolation is NOT automatic here.** On Windows core keeps both its
  persisted JSON and its DPAPI secret store under
  `%APPDATA%\com.edamametech\EDAMAME Security` (`storage_userspace`,
  `storage_secrets::secrets_location`), the same directory as the app. Start
  the owned posture with `APPDATA` pointed at a lab directory: that isolates
  both, as the bind mounts do on Linux. Without it the owned build would
  load and rewrite the app's config, history and Hub credentials. The agents'
  transcript roots resolve from the user profile, not `APPDATA`. `start`
  points `APPDATA` / `LOCALAPPDATA` at `fp-lab\state\AppData`, moved aside
  once per window so the candidate starts empty.
- **Binary:** `posture-binary-windows-x64` is the Authenticode-signed exe;
  verify the signature before running it (Get-AuthenticodeSignature).
- **Remote shell:** cmd over SSH; use PowerShell `-EncodedCommand` for
  anything with quotes (AMSI and quoting notes in the dogfood-status skill).
- **Agents:** `agents` installs Claude Code and Codex user-level through
  `npm.cmd` (npm.ps1 is blocked by the execution policy); Git Bash for the
  POSIX-shaped prompts (the heredoc and rustup scenarios are POSIX-only in
  the catalog).
