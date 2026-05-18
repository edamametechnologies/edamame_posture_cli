# EDAMAME Posture: Extracting User Intent

This guide shows how to use `edamame_posture` (the daemon) and `edamame_cli`
(the RPC client) to extract a structured stream of **user behavior** from a
machine, including:

- Which **applications** the user runs (process path, command line, parent
  process, working directory, open files)
- Which **network destinations** each application talks to (IP, port,
  resolved domain, ASN owner, well-known service name, byte/packet volume)
- How the user **uses AI coding agents** (Cursor, Claude Code, Claude
  Desktop, OpenClaw): tool calls, shell commands, intents, expected
  destinations -- merged into a per-agent behavioral model
- File-system writes the user (or an app on their behalf) performs in
  monitored locations

The daemon is the data source. `edamame_cli` is a thin RPC client that
turns the same RPC surface used by the EDAMAME app and the posture CLI
into JSON on stdout, ready to pipe into your own tooling.

> Throughout this guide we assume **disconnected mode** (no EDAMAME Hub
> account, no Portal LLM key required). The signals listed here are local
> and do not depend on any backend.

---

## Table of Contents

1. [What you get](#what-you-get)
2. [Architecture in one paragraph](#architecture-in-one-paragraph)
3. [Install](#install)
4. [Bring up the daemon](#bring-up-the-daemon)
5. [Discover and call RPCs](#discover-and-call-rpcs)
6. [Stream 1: applications and per-app network activity](#stream-1-applications-and-per-app-network-activity)
7. [Stream 2: AI agent usage](#stream-2-ai-agent-usage)
8. [Stream 3: filesystem activity](#stream-3-filesystem-activity)
9. [A complete tick loop](#a-complete-tick-loop)
10. [Privacy, scope, and what is NOT captured](#privacy-scope-and-what-is-not-captured)
11. [Troubleshooting](#troubleshooting)

---

## What you get

| Stream | Posture CLI subcommand | Generic RPC method | Cadence |
|---|---|---|---|
| Active flows with process attribution | `background-get-sessions` | `get_current_sessions`, `get_sessions` | Continuous |
| Anomalous flows (ML-flagged) | `background-get-anomalous-sessions` | `get_anomalous_sessions` | Continuous |
| Blacklisted destinations hit | `background-get-blacklisted-sessions` | `get_blacklisted_sessions` | Continuous |
| Capture / analyzer health | -- | `is_capturing`, `get_packet_stats`, `get_analyzer_stats` | On demand |
| Agent transcript observer status | -- (RPC only) | `get_transcript_observer_status` | On demand |
| Per-agent behavioral slices | -- (RPC only) | `get_behavioral_model_contributors` | Per tick of observer |
| Merged behavioral model | `background-divergence-get-model` | `get_behavioral_model` | Per tick of observer |
| Behavioral model history | `background-divergence-get-history [LIMIT]` | `get_behavioral_model_history` | On demand |
| Pause / resume agent observer | -- (RPC only) | `set_transcript_observer_enabled` | On demand |
| Force one observer tick | -- (RPC only) | `run_transcript_observer_tick_for` | On demand |
| File-system events | `background-get-file-events` | `get_file_events` | Continuous |
| Score / threat / device facts | `background-score`, `get-device-info` | `get_score`, `get_device_info` | On demand |

All RPCs return JSON on stdout when invoked through `edamame_cli rpc
<method> --pretty`. The posture aliases above are equivalent shortcuts
that bake in sensible defaults.

> Rows marked `-- (RPC only)` have no posture subcommand today; they are
> reachable only via `edamame_cli rpc <method>`. The posture
> `background-divergence-*` family covers the merged divergence-engine
> view; the transcript-observer surface (per-agent slices, observer
> status, pause/resume, force-tick) is part of the agentic API and is
> only exposed through the generic RPC client.

---

## Architecture in one paragraph

`edamame_posture` runs a long-lived daemon. The daemon owns a packet
capture pipeline (`flodbadd`) that attributes every TCP/UDP flow to the
local process that produced it (process path, command line, parent and
grandparent lineage, open files). In parallel, a host-side **transcript
observer** discovers each supported AI agent's transcript root on disk
(no plugin install required) and ingests reasoning-plane sessions into a
**behavioral model** -- a structured record of tool calls, shell
commands, and the destinations / process paths the agent said it would
touch. Both streams are exposed over a local JSON-RPC endpoint that the
posture binary, the EDAMAME app, and `edamame_cli` all share.

You read it; you do not have to install plugins, sign in, or reach a
backend.

---

## Install

You need two binaries. Both are released for Linux, macOS, and Windows.

### 1. `edamame_posture` (the daemon)

```bash
curl --proto '=https' --tlsv1.2 -sSf \
  https://raw.githubusercontent.com/edamametechnologies/edamame_posture_cli/main/install.sh \
  | sudo -E sh -s --
```

This drops the binary at `/usr/local/bin/edamame_posture` (or `$HOME` on
Windows). See [`INSTALL.md`](./INSTALL.md) for the full set of installer
flags; for this use case the defaults are fine.

### 2. `edamame_cli` (the RPC client)

#### Linux (Debian/Ubuntu/Alpine)

```bash
curl --proto '=https' --tlsv1.2 -sSf \
  https://raw.githubusercontent.com/edamametechnologies/edamame_cli/main/install.sh \
  | sudo -E sh -s --
```

#### macOS (Homebrew)

```bash
brew tap edamametechnologies/tap
brew install edamame-cli
```

#### Windows (Chocolatey)

```powershell
choco install edamame-cli
```

Manual binary downloads for all platforms are available from the
[`edamame_cli` releases page](https://github.com/edamametechnologies/edamame_cli/releases).

Verify both are on PATH:

```bash
edamame_posture --version
edamame_cli --version
```

---

## Bring up the daemon

`edamame_posture` exposes the same RPC surface in two states:

- **Foreground** (the daemon runs in your shell, stdout/stderr visible) --
  good for development and one-shot extraction.
- **Background** (daemonized, persists across shells) -- good for
  continuous observation.

For local intent extraction we recommend **disconnected background mode**:
no Hub credentials, no domain authentication, capture and the AI
transcript observer enabled.

### Recommended: background, disconnected, capture on, observer on

```bash
sudo edamame_posture background-start-disconnected \
  --packet-capture \
  --include-local-traffic
```

Then start the on-demand subsystems you want to read from:

```bash
# Network capture status
edamame_cli rpc is_capturing --pretty

# AI transcript observer (one tick across all discovered agents)
edamame_cli rpc get_transcript_observer_status --pretty

# Optional: file integrity monitoring on default sensitive paths
edamame_posture background-start-file-monitor
```

> The transcript observer auto-discovers Cursor, Claude Code, Claude
> Desktop, and OpenClaw transcript roots under the user's home directory.
> If the agent has never run on this host there is nothing to observe and
> the API returns an empty contributor list -- this is normal.

### Alternative: foreground for one-shot extraction

```bash
sudo edamame_posture foreground-start \
  --packet-capture \
  --include-local-traffic
```

Run your queries from a second shell, then `Ctrl-C` the foreground
process when done.

### Stop / restart

```bash
edamame_posture background-stop
edamame_posture background-status
```

---

## Discover and call RPCs

`edamame_cli` is a generic RPC client. Three commands are enough.

```bash
# List all available RPC methods
edamame_cli list-methods

# Show the signature and example arguments for a specific method
edamame_cli get-method-info get_current_sessions

# Call a method (zero-arg or with a JSON array of positional arguments)
edamame_cli rpc get_current_sessions --pretty
edamame_cli rpc get_score '[false]' --pretty
edamame_cli rpc get_behavioral_model_history '[100]' --pretty
```

All examples below use this shape. The posture aliases
(`background-get-sessions`, `background-divergence-get-model`, ...) are
equivalent and may be more convenient when you only need one stream.

---

## Stream 1: applications and per-app network activity

This is the **system plane**: every active flow on the host annotated
with the process that opened it.

### Pull active flows

```bash
edamame_cli rpc get_current_sessions --pretty
```

Each entry is a `SessionInfoAPI` -- the fields you'll care about are:

```json
{
  "session": {
    "protocol": "TCP",
    "src_ip": "192.168.1.42",
    "dst_ip": "140.82.121.4",
    "dst_port": 443
  },
  "stats": {
    "first_activity": "2026-05-18T10:11:02Z",
    "last_activity":  "2026-05-18T10:11:47Z",
    "inbound_bytes":  88234,
    "outbound_bytes": 12011,
    "orig_pkts":      42
  },
  "dst_domain":  "github.com",
  "dst_service": "https",
  "dst_asn": { "as_number": 36459, "country": "US", "owner": "GITHUB" },
  "l7": {
    "pid": 31278,
    "username": "alice",
    "process_name": "Cursor",
    "process_path": "/Applications/Cursor.app/Contents/MacOS/Cursor",
    "cmd":  ["/Applications/Cursor.app/Contents/MacOS/Cursor"],
    "cwd":  "/Users/alice/work/repo",
    "open_files": ["/Users/alice/work/repo/.git/HEAD", "..."],
    "parent_process_name": "launchd",
    "parent_process_path": "/sbin/launchd",
    "spawned_from_tmp": false
  },
  "uid": "tcp:192.168.1.42:54321:140.82.121.4:443",
  "last_modified": "2026-05-18T10:11:47Z"
}
```

This single record answers:

- **Which app?** `l7.process_name`, `l7.process_path`, `l7.cmd`
- **Started from where?** `l7.cwd`, `l7.parent_process_*`,
  `l7.grandparent_process_*`, `l7.spawned_from_tmp`
- **Who owns the destination?** `dst_domain`, `dst_asn.owner`,
  `dst_service`
- **How much traffic?** `stats.inbound_bytes`, `stats.outbound_bytes`,
  `stats.orig_pkts`
- **When?** `stats.first_activity`, `stats.last_activity`

### Convenience aliases

```bash
# Same data, posture-CLI shortcut
edamame_posture background-get-sessions

# Zeek conn-style output (for pipelines that already speak Zeek)
edamame_posture background-get-sessions --zeek-format

# Just the curated subsets
edamame_posture background-get-anomalous-sessions
edamame_posture background-get-blacklisted-sessions
```

### A useful jq slice: "apps that sent bytes in this tick"

```bash
edamame_cli rpc get_current_sessions \
  | jq -r '.[]
    | select(.l7 != null)
    | [.l7.process_name,
       .dst_domain // .session.dst_ip,
       .session.dst_port,
       .stats.outbound_bytes]
    | @tsv' \
  | sort -u
```

---

## Stream 2: AI agent usage

This is the **reasoning plane**: what the user asked the agent to do, the
tools the agent called, and the destinations / process paths the agent
itself said it would touch. The transcript observer reads this directly
from each agent's on-disk transcript store -- no plugin install required.

### Discover what's being observed

```bash
edamame_cli rpc get_transcript_observer_status --pretty
```

Returns one entry per supported agent type with whether it was
discovered, when it last ticked, whether the operator paused it, and how
many sessions it ingested.

### Read the per-agent behavioral slices

```bash
edamame_cli rpc get_behavioral_model_contributors --pretty
```

Each contributor is keyed by `agent_type` (e.g. `cursor`,
`claude_code`, `claude_desktop`, `openclaw`) and `agent_instance_id`.
The reasoning-plane payload for each session contains:

| Field | Meaning |
|---|---|
| `session_key`, `title` | Stable identifier and human title |
| `started_at`, `modified_at` | Session window |
| `user_text` | What the user asked |
| `assistant_text` | What the agent replied |
| `tool_names` | MCP / built-in tools the agent invoked |
| `commands` | Shell commands the agent ran via tool calls |
| `derived_expected_traffic` | Hostnames / ports the agent's plan implies |
| `derived_expected_local_open_ports` | Local ports the plan implies |
| `derived_expected_process_paths` | Process paths the plan implies |
| `derived_expected_parent_paths` | Parent-process paths the plan implies |
| `derived_expected_open_files` | Files the plan implies opening |
| `source_path` | Where on disk this session lives |

This is the structured "what was the user trying to accomplish with the
AI" view. The same data is also available pre-merged via
`get_behavioral_model` and historically via `get_behavioral_model_history
'[N]'`.

### Posture CLI equivalents (partial)

The posture binary exposes **only the merged behavioral model and its
history**, plus the divergence-engine status. The per-agent contributor
slices, the transcript-observer status, and the observer's
pause/resume/force-tick controls are RPC-only today.

```bash
# Merged behavioral model (whatever set of agents are live)
edamame_posture background-divergence-get-model

# History (positional LIMIT, default 20 if omitted)
edamame_posture background-divergence-get-history 100

# Divergence engine status (running, last tick, last verdict, ...)
edamame_posture background-divergence-status
```

For everything else in this section, use `edamame_cli rpc` directly.

### Pause, resume, force-tick (RPC only)

```bash
# Pause observation for one agent (no changes, just stops ingest)
edamame_cli rpc set_transcript_observer_enabled '["cursor", false]'

# Resume
edamame_cli rpc set_transcript_observer_enabled '["cursor", true]'

# Force one tick now (useful for tests / on-demand extraction)
edamame_cli rpc run_transcript_observer_tick_for '["cursor"]'
```

`agent_type` accepts `cursor`, `claude_code`, `claude_desktop`, or
`openclaw` (the four supported types in the transcript-observer
registry).

---

## Stream 3: filesystem activity

The file integrity monitor reports create/modify/delete events on the
paths it watches. Useful when "user behavior" needs to include
"the user (or an app) wrote to a sensitive file".

```bash
# Start with the default sensitive watch set (auto-detected per platform)
edamame_posture background-start-file-monitor

# Or with explicit paths -- comma-separated, no spaces around the commas
edamame_posture background-start-file-monitor \
  --paths /Users/alice/.aws,/Users/alice/.ssh,/Users/alice/work

# Status
edamame_posture background-file-monitor-status

# Pull the events
edamame_posture background-get-file-events
edamame_cli rpc get_file_events --pretty
```

> **`--paths` replaces, it does not augment.** Omitting the flag
> activates the platform-default sensitive watch set resolved by the
> foundation-side helper. Passing `--paths` overrides that set entirely
> with exactly the paths you list. If you want both the defaults and a
> custom path, list them all explicitly.

The equivalent generic RPC call (one positional argument that is itself a
JSON array of strings) is:

```bash
edamame_cli rpc start_file_monitor \
  '[["/Users/alice/.aws","/Users/alice/.ssh","/Users/alice/work"]]'

# Empty array = use the platform defaults
edamame_cli rpc start_file_monitor '[[]]'
```

Each event carries the path, kind (create/modify/delete), timestamp, and
when available the writer process identity. Combine with stream 1 above
to correlate "this app wrote this file at this time".

---

## A complete tick loop

This bash snippet snapshots all three streams once per minute into
timestamped JSON files. Drop it in a `cron` job or `systemd` timer.

```bash
#!/usr/bin/env bash
set -euo pipefail

OUT="${HOME}/userintent"
mkdir -p "$OUT"

while true; do
  ts="$(date -u +%Y%m%dT%H%M%SZ)"

  edamame_cli rpc get_current_sessions \
    > "$OUT/${ts}-sessions.json"

  edamame_cli rpc get_anomalous_sessions \
    > "$OUT/${ts}-anomalous.json"

  edamame_cli rpc get_behavioral_model_contributors \
    > "$OUT/${ts}-agents.json"

  edamame_cli rpc get_transcript_observer_status \
    > "$OUT/${ts}-agents-status.json"

  edamame_cli rpc get_file_events \
    > "$OUT/${ts}-fim.json"

  sleep 60
done
```

To turn this into a proper event stream rather than full snapshots, key
each session by its `uid` and each behavioral session by `session_key`,
and emit only deltas between ticks.

For one-shot extraction (e.g. before submitting a CI job), call each
endpoint once and pipe to your collector -- no loop needed.

---

## Privacy, scope, and what is NOT captured

**What is captured.** Process attribution per flow (path, command line,
parent lineage, open files), the network destination tuple including
resolved domain and ASN owner, byte/packet counters, file-system events
on monitored paths, and the full text of AI-agent reasoning sessions
(user prompts and assistant replies) for any discovered agent.

**Where the data lives.** Locally, in the daemon process. Nothing in
this guide ships data off the host. The Hub / Portal flags
(`--user`, `--domain`, `--pin`, `EDAMAME_LLM_API_KEY`) are deliberately
absent from `background-start-disconnected`.

**What is NOT captured today.**

- **Process exec events independent of network.** App launches that
  never produce a flow do not appear in stream 1. They will appear in
  stream 1 the moment they open a socket, but pure-offline tools (a
  local PDF reader, an offline editor) won't.
- **Window focus / keyboard / mouse activity.** Out of scope. EDAMAME
  is a network and AI-agent observer, not a UI activity tracker.
- **Decrypted application-layer payloads.** TLS payloads are not
  decrypted; only the metadata (5-tuple, SNI/DNS-resolved domain, ASN,
  packet counts, byte counts) is recorded.
- **AI-agent transcript content for agents that have not run on this
  machine.** The observer reads existing on-disk transcripts. If the
  user has never opened Cursor on this host, there is no Cursor data.

If your use case requires a process-exec stream or a window-focus
stream, those are additive features (a new `core_manager` module + new
RPC) rather than restrictions of the current design.

**Operator controls.**

- Pause AI-agent observation per agent type with
  `set_transcript_observer_enabled`.
- Stop capture with `edamame_posture background-stop` (kills the
  daemon entirely) or by leaving `--packet-capture` off at start time.
- Stop file monitoring with `edamame_posture background-stop-file-monitor`.

---

## Troubleshooting

**`edamame_cli rpc ...` returns "connection refused".**
The daemon isn't running. Start it with
`sudo edamame_posture background-start-disconnected --packet-capture`.

**`is_capturing` returns `false`.**
The daemon is up but capture wasn't enabled. Either restart with
`--packet-capture`, or call `edamame_cli rpc start_capture`.

**`get_transcript_observer_status` shows zero discovered agents.**
The user has never run a supported AI agent on this machine, or the
agent stores its transcripts somewhere non-standard. Run the agent
once, then `edamame_cli rpc run_transcript_observer_tick_for '["cursor"]'`
(or the relevant agent type) to force a tick.

**Sessions show `l7: null`.**
L7 attribution requires elevated capture rights. On Linux make sure the
daemon was started via `sudo` or has `CAP_NET_RAW`; on macOS run as
root or grant packet-capture entitlements; on Windows ensure Npcap is
installed and the daemon runs as Administrator.

**`edamame_cli list-methods` shows fewer methods than this guide
references.**
The daemon is older than the methods. Update both binaries
(`edamame_posture --version` should match a current
[posture release](https://github.com/edamametechnologies/edamame_posture_cli/releases),
and the same for `edamame_cli`).

**The daemon prints findings I don't want in this stream.**
The vulnerability detector and divergence engine emit findings as a
separate concern; if you only want raw user behavior, ignore them
(don't call `start_vulnerability_detector` / `start_divergence_engine`).
The streams documented here are independent.
