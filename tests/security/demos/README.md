# Operator-driven demos

The triggers in [`../triggers/`](../triggers/) run hands-off: the Attack
Simulator starts and stops them, the CVE gate asserts them, and
[`catalog.json`](../triggers/catalog.json) says what each one does. The
demos here need an operator at the keyboard for one step a script must not
take, so the simulator does not bundle them and the catalog does not list
them. They reuse the triggers' shared helpers (`_common.py`,
`_edamame_cli.py`, `_finding_export.py`) and write their results in the
gate's output shape.

| Demo | What the operator does | What EDAMAME should show |
|---|---|---|
| `observe_claude_desktop_sneakpeek.py` | attaches two staged decoy credentials to a new chat in the real Claude Desktop and sends it | a credential finding attributed to the app's own processes |

## SneakPeek from the real Claude Desktop

`observe_claude_desktop_sneakpeek.py` observes the attack pattern detector
while the real Claude Desktop reads decoy credentials and sends a message.
`trigger_sneakpeek.py` reproduces the same host shape with a stand-in (a copy
of the interpreter under the render engine's name) so the simulator and the
gate can run it unattended; this demo produces it from the real application:
a signed main process reads the files, and a separate network helper sends
them.

### What it does, and does not do

The tool is EDAMAME-side only. It never launches, drives, instruments, patches
or exploits Claude Desktop; the one action inside the app is the operator's,
by hand. In order:

1. **Prerequisites** over `edamame_cli rpc`: a daemon answers, helper
   enabled, capture on, file monitor on, agentic protection on, detector
   running and its ticker not stalled, the adjudication mode and the model
   provider (an `llm` mode with no model publishes nothing).
2. **Process tree** of the app: pid, parent pid and image name, never the
   command line.
3. **Decoys** in the real credential directories, under the demo prefix the
   triggers use (`~/.ssh/demo_claude_desktop_sneakpeek_desktop_id`,
   `~/.aws/demo_claude_desktop_sneakpeek_desktop_credentials`): the sensors
   label a read by its parent directory, so the files must live there. Their
   contents are labelled placeholders. The real `id_*`, `credentials` and
   `config` files are never read or written; a symlink is refused and an
   existing file is never replaced.
4. **Baseline** of the active finding keys, then the **operator step** and a
   **watch** over natural detector cycles: no forced ticks, a poll every 20 s
   for 600 s by default.
5. **Exports** of every new finding, in the gate's output shape, so
   `edamame_core/tools/attack_corpus_from_gate.py` shapes the capture like a
   CI leg's.
6. **Cleanup** of the decoys it recorded (`cleanup`). The simulator's Run
   cleanup does not know this demo's files.

### Platforms

| Platform | Claude Desktop | What the tool matches | Notes |
|---|---|---|---|
| macOS | yes | `Claude`, `Claude Helper`, `Claude Helper (Renderer)`, `Claude Helper (GPU)`, inside an application bundle; case-sensitive, so the Claude Code CLI (`claude`) is not the app | main process and network helper are distinct image names |
| Windows | yes | `claude.exe` | every process of the app has the same image name: the split shows as pid and parent pid |
| Linux | no official build | `claude`, `claude-*` | the stand-in trigger is the option there; the tool still runs for another app (`--app-name`) |

### Running it

```bash
# 1. Is the host ready? Prerequisites and the app's process tree, no decoys.
python3 -I tests/security/demos/observe_claude_desktop_sneakpeek.py check

# 2. The demo: stage, baseline, operator step, watch, export, cleanup.
python3 -I tests/security/demos/observe_claude_desktop_sneakpeek.py run
```

Requirements: python3 (standard library only); `edamame_cli` 2.0.5 or later
(`$EDAMAME_CLI_BIN`, PATH, or a sibling `edamame_cli` checkout's build); the
EDAMAME app or posture daemon with protection on; Claude Desktop installed,
running and signed in.

The operator step, printed by the tool after staging:

1. Start a **new** chat in Claude Desktop.
2. Attach the staged decoys. macOS Open dialog: `Cmd+Shift+G`, paste the
   path. Windows: paste the path in the file-name box. Or show hidden files.
3. Send: *"EDAMAME detector demo: the attached files are decoys staged by our
   own test tool. Reply with one word."*
4. Back in the terminal, press Enter the moment the message is sent. The
   clock for "time to first alert" starts there.

Flags:

| Flag | Default | Use |
|---|---|---|
| `--creds ssh,aws` | `ssh,aws` | Decoy classes. Two classes sent by the reader are the quiet form (`credential_misrouted`); `credential_harvest` needs three |
| `--suffix .txt` | none | When the app's file picker refuses a file without an extension. The directory label still applies |
| `--duration 600`, `--poll 20` | | The watch window and the poll interval, in seconds |
| `--stop-on-alertable` | off | End the watch at the first alertable finding on the app tree |
| `--expected-check` | `credential_misrouted` | The check whose alertable finding on the app tree makes the gate-shaped result a pass |
| `--clear-history` | off | Clear vulnerability history and FIM events before the baseline. Deletes the host's findings: lab and dev hosts only |
| `--no-wait` | off | Start the watch at once; the operator does the chat step from elsewhere |
| `--keep-decoys` | off | Leave the decoys for a second attempt; `cleanup` removes them |
| `--agent-type`, `--state-dir` | `claude_desktop`, its demo state dir | The triggers' conventions for the file prefix and the marker directory |
| `--app-name` | `Claude` | Observe another desktop app read-then-send |
| `--out` | `<state dir>/sneakpeek_desktop/<UTC time>/` | Output directory |

### Reading the result

Each new finding prints as one line:

```
  +   87s APP DECOY [HIGH    ] credential_misrouted       Claude Helper(4812) <- Claude  -> claude.ai:443  basis=[provenance:read_then_send,sustained_egress]
           provenance:read_then_send: an earlier read by this process was linked to the send
```

`APP` means the finding's process, parent or pid is on the app's tree;
`DECOY` means a staged file is in its evidence. The basis tags say who read
and who sent:

| Basis tag | Meaning |
|---|---|
| `parent_credential_reads` | the finding's process sent; its **parent** read the decoys: the two-process shape |
| `breadth_credential_reads`, `remembered_credential_reads` | reads remembered after the files were closed |
| `live_sensitive_scan` | the sending process held the decoys open |
| `provenance:read_then_send` | an earlier read by this process was linked to the send |
| `courier_to_own_provider` | an agent carried the credential to its own model provider |
| `non_routine_destination`, `anomaly`, `blacklist` | the corroboration that raised the grade |

Which check to expect: one or two keys read then sent to a service they are
never used with is `credential_misrouted` HIGH; three or more classes read by
the main process and sent by the helper is `credential_harvest` with
`parent_credential_reads`; decoys held open under a sustained stream is
`token_exfiltration` or `sensitive_material_egress`. A reused HTTPS connection
is still a session with new egress, so the chat does not have to open a new
one. Allow several cycles: the gate's first alerts for the stand-in come one to
three minutes after the trigger starts.

No finding on the app tree after the full watch is a result too: keep the
exports with it.

### Outputs

```
<out>/
    summary.json                          # prerequisites, process tree, decoys, every new finding, timings, status
    results.json                          # gate shape: generated_utc, platform, scenarios[{scenario, status, expected_check}]
    findings/sneakpeek_desktop.export.json    # alertable_exports (app tree, HIGH/CRITICAL) and exports (the rest)
    findings/sneakpeek_desktop.meta.json      # expected check, as the gate records it
```

From an `edamame_core` checkout, the capture becomes an attack-corpus
envelope that must keep alerting on every replay:

```bash
python3 -I tools/attack_corpus_from_gate.py --platform macos-arm64 \
    --label local-<host>-<yyyymmdd> <out>
```

Status `pass` requires an alertable finding of `--expected-check` on the app
tree; the corpus tool only takes passed scenarios unless `--include-failed`.

### Safety and privacy

- Nothing leaves the host because of this tool. It sends no network traffic;
  the app sends the attached decoys to its own service, as it does with any
  attachment. The decoys are labelled placeholders.
- No real credential is touched. Staging never replaces an existing file,
  refuses symlinks, and `cleanup` removes only the `demo_`-prefixed files it
  recorded.
- The report carries no secret: the model provider and model name only, pids
  and image names only, never a command line.
- The exports hold the host's session telemetry (paths, destinations,
  process names). Review them before they leave the machine, as for any
  export.

### Troubleshooting

| Printed | Cause and fix |
|---|---|
| `no daemon answers` | start the EDAMAME app or the posture daemon |
| `helper state is ...` | anything that starts with `Enabled` is fine (`EnabledFullDisk` on a macOS helper with Full Disk Access) |
| `agentic protection is off` | the protection button in the app, or `agentic_set_protection true` |
| `adjudication is llm with no model configured` | connect a model, or pin `advisory` / `deterministic` for the demo |
| `the agentic ticker is stalled` | `running: true` is configuration, not liveness; restart the daemon and read `last_run` again |
| `Claude is not running` | start it and sign in before the operator step |
| the picker refuses the decoy | `--suffix .txt`; the directory label still classifies the read |
| nothing in 10 minutes | check `get_file_monitor_status` and `is_capturing` again, that demo mode is off (it pauses the detector ticks), and that the chat really sent; then keep the exports |
