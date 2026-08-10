# Agent fleet monitoring E2E

End-to-end proof that EDAMAME's **host-side transcript observer** monitors the
supported agent fleet on every desktop platform, using **real agents** and **no
EDAMAME plugin**. This is the divergence-detection counterpart to the CVE /
attack-pattern gate in [`tests/security/`](../security) -- together the two
suites make `edamame_posture` self-contained for both detection planes.

> **EDAMAME 1.7.0:** Level-2 agent plugins are retired. Per-repo plugin
> `test_e2e.yml` workflows are no-op stubs. `.github/workflows/agent_monitoring_e2e.yml`
> in this repo is the **sole release-gating agent E2E** (listed in
> `edamame_app/release_all.sh::AGENT_PLUGIN_E2E_WORKFLOWS`).

Synthetic transcript injection, fabricated `sessions.json`, and harness-seeded
observer roots are **forbidden** as the basis of this gate -- they prove the
parser, not detection of a real agent. When an agent cannot be installed or
driven on a platform, that leg hard-SKIPs with a logged reason rather than being
replaced by a synthetic green.

## Files

| File | Purpose |
|---|---|
| `run_fleet_monitoring.py` | The driver. Installs/drives each real agent, verifies observer discovery, the `unsecured_<agent>` toggle, a real divergence verdict, and the host blast radius. |
| `supported_agents.py` | Registry helper. Resolves `supported_agents/index.json`, per-agent install layouts, and repo overrides. |
| `../security/triggers/_edamame_cli.py` | Shared `edamame_cli` RPC wrapper, imported by the driver. Lives with the CVE trigger corpus. |

The driver adds `../security/triggers` to `sys.path`, so the CVE corpus and the
fleet driver share one copy of the RPC helper. A co-located `tests/e2e/triggers/`
is also honored if a checkout keeps them side by side.

## Supported-agent registry

`supported_agents.py::registry_path()` resolves `index.json` in this order,
mirroring `edamame_foundation::supported_agents::local_registry_candidates` so
the harness and the daemon always agree on which fleet is in scope:

1. `EDAMAME_SUPPORTED_AGENTS_INDEX` (explicit file -- what CI exports)
2. `EDAMAME_SUPPORTED_AGENTS_DIR/index.json`
3. a sibling-clone walk upwards for `supported_agents/index.json`,
   `edamame_foundation/supported_agents/index.json`, then the deprecating
   `agent_security/supported_agents/index.json` mirror

`edamame_foundation` owns the canonical registry. CI sparse-checks out just that
directory and exports `EDAMAME_SUPPORTED_AGENTS_INDEX` at it. The trailing mirror
probe exists only for the window in which released daemons still resolve the
registry from its old home.

The registry is the source of truth for the accepted `agent_type` values, repo
locations and per-agent override env vars, repo-local install/uninstall/healthcheck
script paths, and per-agent timeouts. Current fleet: `cursor`, `claude_code`,
`claude_desktop`, `codex`, `hermes`, `openclaw`.

## Legs and severity

| Leg | Scope | Severity | What it asserts |
|---|---|---|---|
| real agent drive | per-agent | HARD (when the provider key is present) | the real product runs headlessly and writes its own transcripts |
| observer detection | per-agent | HARD | `run_transcript_observer_tick_for` -> the agent becomes `discovered` |
| unsecured toggle | per-agent | SOFT | `set_transcript_observer_enabled(false)` raises `unsecured_<agent>`; re-enabling clears it |
| divergence verdict | fleet-wide | HARD on Linux/macOS, best-effort on Windows | a real behavioral model plus a genuine divergent egress through the agent -> `get_divergence_verdict` returns `DIVERGENCE` |
| host blast radius | fleet-wide | HARD | `get_host_blast_radius` returns `host_privilege.assessed=true`, a non-empty `agent_sandboxes`, and list-typed `blast_radius_agents` / `harnesses` |
| real-coverage floor | per-leg | HARD | at least one HARD agent was actually driven and detected -- an all-skips run is rejected |

Per-agent gating:

- `claude_code` / `codex` / `hermes` / `openclaw`: HARD. Each has a headless
  installer on every desktop OS (hermes via `install.sh` on Linux/macOS and
  `install.ps1` on Windows; the rest via npm), so a HARD agent is SKIPPED
  (non-gating) only when its provider key is absent.
- `claude_desktop`: BEST-EFFORT. GUI app with no headless drive CLI -- attempted
  and reported honestly, never faked, never gating.
- `cursor`: SKIP. GUI IDE with no headless agent CLI wired in hosted CI.

HARD failures exit non-zero; SOFT failures warn. The driver loops over every
agent before reporting, so one run surfaces all per-agent failures at once.

### The divergence probe

The probe drives egress through the agent's own persistent shell via bash
builtin `/dev/udp`: six fixed RFC 5737 TEST-NET addresses (`192.0.2.x` /
`198.51.100.x` / `203.0.113.x` -- IANA documentation blocks with no real host, so
the agent does not refuse them as third-party infrastructure) x two high,
non-standard UDP ports (63169/63170) = **12 unique unexplained destinations**,
well above the engine's production default threshold of 4. Each socket is held
open for the whole ~100s window so flodbadd's socket-table poll attributes
`pid=bash -> parent=node/claude`; an earlier open-send-close probe left every
session `proc=None` and was dropped.

A high UDP port to a TEST-NET IP is never deterministically
infrastructure-exempt (`is_local_or_infrastructure` spares only
loopback/RFC1918/link-local plus DNS/NTP/OCSP), so the engine recognizes
divergence. The gate asserts the **deterministic** verdict, so it holds whether
the downstream LLM keeps or suppresses the alert.

`/dev/udp` works on Linux `/bin/bash` and macOS `/bin/bash` 3.2. On Windows Git
Bash (MSYS2), `/dev/udp` support and OS-level L7 attribution of a bash-opened UDP
socket are unverified, so the probe still runs but a miss is a warning.

## Local invocation

Detection-only, against an already-running core:

```bash
EDAMAME_CLI=../edamame_cli/target/release/edamame_cli \
  python3 tests/e2e/run_fleet_monitoring.py \
    --skip-install --skip-divergence --agents openclaw,codex
```

Full run:

```bash
EDAMAME_CLI=../edamame_cli/target/release/edamame_cli \
EDAMAME_SUPPORTED_AGENTS_INDEX=../edamame_foundation/supported_agents/index.json \
  python3 tests/e2e/run_fleet_monitoring.py
```

| Flag / env var | Purpose |
|---|---|
| `--agents` / `EDAMAME_AGENTS` | CSV of agent_types to run (default: all in registry) |
| `--representative-agent` / `FLEET_REPRESENTATIVE` | agent used for the divergence leg |
| `--skip-divergence` / `FLEET_SKIP_DIVERGENCE=1` | skip the divergence leg |
| `--skip-blast-radius` / `FLEET_SKIP_BLAST_RADIUS=1` | skip the blast-radius leg |
| `--skip-install` | detection-only; for local dev against an already-provisioned fleet |
| `EDAMAME_CLI` | path to `edamame_cli` |
| `EDAMAME_SUPPORTED_AGENTS_INDEX` | explicit registry file |
| `<AGENT>_REPO` (e.g. `OPENCLAW_REPO`) | per-agent repo override consumed by `supported_agents.py` |

## CI workflow

`.github/workflows/agent_monitoring_e2e.yml` runs the driver on
`ubuntu-latest`, `macos-latest`, and `windows-latest`. Per-OS shape:

1. Checkout this repo.
2. `Setup EDAMAME Posture` (`edamame_posture_action@v1`) connected, with
   `packet_capture`, `vulnerability_detection`, `agentic_mode: analyze`, and
   `agentic_provider: edamame`. The LLM provider is required, not optional: the
   plugin-free observer builds behavioral models through
   `upsert_behavioral_model_from_raw_sessions`, a daemon-side LLM round-trip.
   Without a provider it fails with "No configured LLM provider available for
   raw-session ingest" and no model reaches the divergence engine.
3. Sparse-checkout `edamame_foundation/supported_agents` and export
   `EDAMAME_SUPPORTED_AGENTS_INDEX`. This runs **after** posture setup, because
   the org IP allow list only lifts once the runner has reported posture.
4. Toolchains: Node 22, Python 3.12, `xz` (hermes' installer unpacks an `.xz`
   tarball), mingw-w64 gcc on Windows.
5. Install the real agent CLIs (`claude`, `codex`, `openclaw` via npm; hermes
   self-installs from the driver) and `edamame_cli`.
6. Run the driver with a 40-minute timeout. On Linux it runs as root with
   `HOME=/root`, because the posture daemon runs as root for packet capture and
   its observer resolves agent roots under `/root`.
7. Dump the attack-pattern findings, stop the daemon, Slack-alert on failure.

The trailing detector steps **publish evidence and never gate**. The driver
deliberately produces adversarial-shaped telemetry (agent CLIs installing and
running from temp dirs, 12 unexplained UDP destinations), so those findings are
the expected result here. Clearing history first does not make it gateable
either: the clear invalidates the detector's input-hash cache, so the next 60s
tick re-derives `sandbox_exploitation` from the probe session, which outlives the
process in the capture pipeline. Whether the gate saw 0 or 1 came down to which
side of a tick it landed on -- Windows tripped while Linux/macOS passed on the
same commit. The real assertion is the driver's own PASS/FAIL.

`workflow_dispatch` inputs restrict the run to a CSV of `agents` or force
`skip_divergence`. Push/PR triggers are path-filtered to the driver, the registry
helper, `tests/security/triggers/**`, and the workflow file.

## Verification RPCs

| RPC method | Arguments | Returns |
|---|---|---|
| `get_transcript_observer_status` | none | observer status (`agents[]` with `discovered`, `last_session_count`, `last_transcripts_roots`) |
| `run_transcript_observer_tick_for` | `{"agent_type": "..."}` | forces a single-agent tick; returns that agent's fresh status row |
| `set_transcript_observer_enabled` | `{"agent_type": "...", "enabled": bool}` | pauses/resumes one agent's observer (pausing raises `unsecured_<agent>`) |
| `get_behavioral_model` | none | current merged behavioral model |
| `get_divergence_verdict` | none | current divergence classification |
| `get_host_blast_radius` | none | host privilege + per-agent sandbox confinement + governance harness surface |
| `get_score` | `{"complete_only": false}` | security score with the `active` threat list (where `unsecured_<agent>` appears) |
| `get_current_sessions` | none | active sessions with L7 attribution |
| `get_anomalous_sessions` | none | sessions classified anomalous by iForest |

## Prerequisites

- macOS, Linux, or Windows (Git Bash). All three are exercised in CI.
- A running EDAMAME core (`edamame_posture` daemon or the EDAMAME Security app)
  with an LLM provider configured.
- `edamame_cli` on `PATH` or via `EDAMAME_CLI`.
- `python3`, `node`, `curl`.
- Provider keys for the agents being driven (`ANTHROPIC_API_KEY`,
  `OPENAI_API_KEY`). A HARD agent whose key is absent is skipped, not failed.

### Platform notes

- **Linux**: packet capture needs `CAP_NET_RAW` or root. Because the daemon runs
  as root, drive the agents as root with `HOME=/root` so the transcripts land
  where the observer looks.
- **Windows**: packet capture needs Npcap and an elevated session. The
  divergence leg is best-effort (see above).
- Agent install paths resolve through `supported_agents.py resolve-paths`, which
  mirrors each agent's own installer for Darwin, Linux (XDG), and Windows
  (`APPDATA`/`LOCALAPPDATA`).

## Troubleshooting

**`edamame_cli` method not found.** Run `edamame_cli list-methods`. A stale CLI
cannot dispatch an RPC that did not exist when it was built -- upgrade before
concluding the daemon lacks the method.

**Agent never becomes `discovered`.** Confirm the agent actually wrote
transcripts under the root the observer advertises
(`get_transcript_observer_status` -> `last_transcripts_roots`), and that the
driver and the daemon agree on `HOME`.

**Divergence verdict stays Clean.** The engine needs a behavioral model to
compare against. Confirm `get_behavioral_model` is non-empty and that the probe's
egress was attributed to the agent's process lineage (`get_current_sessions`).

**Registry not found.** Export `EDAMAME_SUPPORTED_AGENTS_INDEX`. The fallback
walk only finds a sibling `edamame_foundation` / `agent_security` clone.
