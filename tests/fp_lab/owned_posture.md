# The owned posture daemon

The FP lab measures the detection code we are about to ship, so it runs
against a posture daemon built from that code, on a real host, and gives the
host back on its released service afterwards. `deploy_owned_posture.sh`
does this for Linux (test-mint); this page is its design and the plan for the
macOS and Windows legs.

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
- Codex: the `codex-x86_64-unknown-linux-musl` release binary, checked
  against the release digest, at `~/.local/bin/codex`.
- uv (`~/.local/bin/uv`): test-mint has no `python3-venv`; the venv
  scenarios fall back to it.
- No Node.js on test-mint: the npm scenarios report SKIP there.

Provider keys for the agents are an operator step: they must be present in
the lab user's environment on the host when `run_fp_lab.py run` starts
(`ANTHROPIC_API_KEY` for Claude Code, `OPENAI_API_KEY` for Codex). The runner
removes them from its own environment at start and hands each one only to the
agent that needs it, for the length of its drive. Without them the agent
scenarios report SKIP with the reason; the direct scenarios still run.
`deploy_owned_posture.sh` does not provision credentials.

## macOS (fmba-3): what the leg needs

- **The app owns the RPC port.** The standalone app hosts its own core on
  40152 (core per frontend). Quit EDAMAME Security for the window (and
  check `lsof -iTCP:40152` is free); the helper can stay.
- **Binary:** `posture-binary-macos-arm64` is the signed, notarized pkg with
  the Endpoint Security provisioning profile. Installing it places the bundle
  under `/Library/Application Support/EDAMAME/EDAMAME-Posture/` and links
  `/usr/local/bin/edamame_posture`; restore by removing them (or reinstalling
  the previous pkg) after the window. ES and file monitoring need Full Disk
  Access for the bundle: a TCC approval in the GUI (VNC), once.
- **State isolation:** a root posture keeps its records under root's own
  home whatever `$HOME` says (`storage_home`: root's defaults / records
  directory, file secrets in `/var/root/.edamame/secrets` when it has no
  keychain group), never in the console user's app domain. Check whether an
  earlier root posture left state there and move it aside for the window.
- **edamame_cli:** do NOT use the brew 2.0.4 CLI on fmba-3: through 2.0.4 a
  CLI one-shot removes the app's Portal key and Hub PIN from
  `~/.edamame/secrets` (fixed in core 0480c973, 2.0.5). The runner needs an
  `edamame_cli` built against core 2.0.5 (`EDAMAME_CLI_BIN`), from CI or a
  release, before this leg runs.
- **Observer home:** start posture with `sudo` from the console user's shell
  (macOS sudoers keeps `HOME`), so the observer reads that user's
  `~/.claude` / `~/.codex`.
- **Start/stop:** `sudo edamame_posture background-start-disconnected
  --packet-capture --agentic-mode analyze --agentic-provider edamame` with the
  Portal key in the root environment the way the security gate does it;
  `sudo edamame_posture background-stop`; relaunch the app.

## Windows (shiawase): what the leg needs

- **The app owns the RPC port and needs a logged-in session** (Parallels
  Client RDP, see the dogfood-status skill). Close the app for the window;
  posture is standalone (in-process capture via Npcap, ETW), so the helper is
  not needed but must not be killed carelessly (2.0.3 helper recovery
  actions).
- **State isolation is NOT automatic here.** On Windows core keeps both its
  persisted JSON and its DPAPI secret store under
  `%APPDATA%\com.edamametech\EDAMAME Security` (`storage_userspace`,
  `storage_secrets::secrets_location`), the same directory as the app. Start
  the owned posture with `APPDATA` pointed at a lab directory: that isolates
  both, as the bind mounts do on Linux. Without it the owned build would
  load and rewrite the app's config, history and Hub credentials. The agents'
  transcript roots resolve from the user profile, not `APPDATA`.
- **Binary:** `posture-binary-windows-x64` is the Authenticode-signed exe;
  verify the signature before running it (Get-AuthenticodeSignature).
- **Remote shell:** cmd over SSH; use PowerShell `-EncodedCommand` for
  anything with quotes (AMSI and quoting notes in the dogfood-status skill).
- **Agents:** Claude Code native installer for Windows and the codex
  `x86_64-pc-windows-msvc` release binary, user-level; Git Bash for the
  POSIX-shaped prompts (the heredoc and rustup scenarios are POSIX-only in the
  catalog).
