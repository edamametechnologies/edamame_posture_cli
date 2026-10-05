# FP lab

Every recent false positive came from active, benign agent work: an agent
choosing a destination for a delegated task, reading the repository's agent
instruction files, staging a throwaway script in temp, building in temp,
reading its own harness store while talking to its provider. No gate
exercises that. The idle baseline (`tests/security/run_false_positive_baseline.sh`)
has no stimulus, the CVE suite (`run_cve_detection.sh`) is attacks, and the
fleet E2E (`tests/e2e/run_fleet_monitoring.py`) drives real agents only to
prove a divergence DOES fire.

The FP lab drives REAL coding agents (Claude Code, Codex) and agent-free
scripts through ordinary work against a posture daemon built from the code
under test, on real hosts, and **fails on any alertable attack-pattern
finding (HIGH / CRITICAL, not dismissed) or any divergence incident (any
severity)**. Each one is exported and shaped into a corpus candidate ready
for review. LOW findings are recorded, never gating.

## Files

| File | Purpose |
|---|---|
| `scenarios.py` | The catalog: id, FP class, platforms, kind (`agent` prompts / `direct` action), fixture, expectation, stimulus marker. |
| `lab_workspace.py` | Workspace fixtures (a small web-app repo, the same with agent instruction files, the same with secret-shaped test fixtures). Built under the lab root, never in OS temp. |
| `direct_actions.py` | Agent-free scenarios: cargo / venv / npm builds in the workspace and in temp, git clone/fetch/push, curl to public APIs, rustup-init temp staging, a git credential helper. |
| `run_fp_lab.py` | The runner: preflight, warm-up baseline, cases, settle ticks, collection and export, drain, summary. Also `list`, `validate`, `shape`. |
| `deploy_owned_posture.sh` | Operator-side: fetch the CI build, push it and the harness to a host, record state, swap the released service for the owned daemon (isolated), run, collect, restore. Linux in v1. |
| `owned_posture.md` | How the owned daemon is deployed and isolated, and what the macOS / Windows legs need. |

Shared code, not copied: agent installation and driving, observer ticks and
the model helpers are `tests/e2e/agent_harness.py` (moved out of the fleet
E2E, which imports it too); the RPC wrapper is
`tests/security/triggers/_edamame_cli.py`; the agent registry reader is
`tests/e2e/supported_agents.py`. Attack-pattern candidates are shaped by
`edamame_core/tools/fp_corpus_from_export.sh`.

## How a run works

1. **Preflight** (`preflight.json`): the daemon answers through
   `edamame_cli`; optional version check (`--expect-core-version`); not
   connected to the Hub (`--allow-hub` to override); the LLM / Portal answers
   (`agentic_test_llm`); both engines' effective adjudication mode
   (`--set-adjudication auto` puts both on the shipped default, advisory with
   the Portal; `deterministic` is refused); capture, file monitor,
   attack-pattern detector, divergence engine and the transcript observer for
   each lab agent running. Any miss: exit 2.
2. **Warm-up** (`--warmup-secs`, default 120): ticks and snapshots with no
   stimulus; whatever appears here is ambient and becomes the baseline
   (`baseline.json`).
3. **Cases**: one per scenario, and per agent for agent scenarios
   (`<id>@claude_code`). The workspace is fresh. Agent requests run in one
   session (request 2 resumes request 1: `--resume <session>` for Claude Code,
   `exec resume --last` for Codex). Then a **settle** window
   (`--settle-secs`, default 120): every `--tick-every` seconds the runner
   forces `run_transcript_observer_tick_for` (each lab agent),
   `debug_run_vulnerability_detector_tick` and `debug_run_divergence_tick`,
   snapshots findings / incidents / verdicts, and handles what is new:
   - every new finding is exported (`export_attack_pattern_finding_details`
     with `{"request_json": "{\"finding_key\": ...}"}`); alertable ones are
     shaped into `candidates/attack_pattern/<FP-ID>/`. The export's debug
     trace tells whether the detector graded it HIGH+ and the adjudicator
     demoted it (`adjudicator_demoted`: alerts whenever the Portal does not
     answer);
   - every new divergence incident is captured with its debug trace, the
     behavioral model and its history and the raw agent activity
     (`get_raw_agent_activity`), and a draft divergence corpus envelope is
     written to `candidates/divergence/DIV-LAB-<scenario>/` (asserting
     `Clean` with the fired categories absent);
   - near misses: new reports whose raw detector findings were HIGH+ but did
     not land as alertable (trace saved), non-clean verdicts without an
     incident, and the detector's LLM-SUPPRESS FP candidates.
4. **Drain** (`--drain-secs`, default 240): late findings are attributed to
   `post-run-drain`.
5. **Summary**: `summary.json` and `summary.md`. Status per case: `FAIL`
   (alertable finding or incident), `PASS` (stimulus delivered, nothing
   alertable), `SKIP` (platform, missing tool / key / env, agent refusal, or
   the stimulus marker never appeared), `ERROR` (runner exception). Exit 1
   on any FAIL (naming each candidate file), 2 on preflight failure, else 0.

Findings are attributed to the case in whose window they appeared; a late
finding of case N can land in case N+1's window. The export (process, paths,
timestamps) says which.

## Running it

On a dogfood host, with the owned daemon (see `owned_posture.md`):

```bash
H=test-mint
D=tests/fp_lab/deploy_owned_posture.sh
FP_LAB_RUN_ID=<tests.yml run id> $D $H fetch
$D $H push
$D $H record pre-lab
$D $H start
NAME=$($D $H run | tail -1)          # extra args go to `run_fp_lab.py run`
$D $H wait "$NAME"
$D $H collect "$NAME"                # -> ~/Library/Caches/edamame-agents/fp-lab/runs/$NAME
$D $H stop
$D $H record post-lab
```

Directly on a host whose daemon is already the build under test:

```bash
python3 tests/fp_lab/run_fp_lab.py list
python3 tests/fp_lab/run_fp_lab.py run --dry-run          # the plan, with SKIP reasons
python3 tests/fp_lab/run_fp_lab.py run --set-adjudication auto \
    --scenarios div-instruction-files-read,direct-git-lab-repo
python3 tests/fp_lab/run_fp_lab.py shape <run_dir>       # where jq and the core tools exist
python3 tests/fp_lab/run_fp_lab.py summarize <run_dir>   # re-render the summary from the case files
```

In CI: `agent_monitoring_e2e.yml` has an `fp_lab` mode (workflow_dispatch
`mode: fp_lab`, `posture_build_run_id: <tests.yml run id>`,
`fp_lab_scenarios`). It reuses the job's agent CLI installs, provider keys,
`edamame_cli` and registry checkout, swaps the action's released daemon for
the `posture-binary-<label>` build of the run you name, runs the lab, and
uploads the run directory as `fp-lab-<label>`. The default `fleet` mode (push,
PR, release gate) is unchanged.

## Safety rules

- The lab user is the host's console user; the runner refuses root unless
  `--allow-root` (CI only, where the root daemon observes `/root`).
- Workspaces live under the lab root (`~/fp-lab/ws`), never in OS temp or a
  scratchpad. Only `temp_behaviour` scenarios use temp, through their own
  `mktemp -d`, and remove it.
- No scenario reads or writes the user's real credentials or config:
  fixtures carry AWS's documentation example key and a fake PEM body; the
  credential-helper scenario points `GIT_CONFIG_GLOBAL` at a lab gitconfig
  and a lab-local store with a placeholder; git identities come from the
  environment, never `git config --global`.
- Provider keys are taken out of the runner's environment at start and given
  only to the agent that needs them while it runs; direct scenarios and the
  RPC CLI never see them; nothing prints or writes them.
- Prompts are plain developer requests. If an agent refuses one, the case is
  SKIP with the refusal quoted. Do not reword a prompt to get past an
  agent's own safety refusal.
- Never point the lab at a daemon connected to the Hub (findings would be
  reported as the dogfood identity's) unless that is the point
  (`--allow-hub`).
- The runner never clears history, suppressions or dismissals: it diffs
  snapshots. A host's daemon state stays what the run left.

## Adding a scenario

Add a `Scenario` to `scenarios.py` (and a function to `direct_actions.ACTIONS`
or a fixture to `lab_workspace.FIXTURES` if needed), then
`python3 tests/fp_lab/run_fp_lab.py validate`. Set `fp_class` to the FP it
reproduces (`FALSEPOSITIVES.md` id) or `new`, `marker` to a file the stimulus
must produce, and `temp_behaviour=True` only when temp is the point.
