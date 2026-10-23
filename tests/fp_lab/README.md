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
| `direct_actions.py` | Agent-free scenarios: cargo / venv / npm builds in the workspace and in temp, git clone/fetch/push, curl to public APIs, rustup-init temp staging, a git credential helper, and the operator's-day set (below). |
| `standins.py` | Stand-in programs for the operator's-day set (a cloud-sync client, a user's report script), standard library only, copied into the case workspace and run as their own processes. |
| `run_fp_lab.py` | The runner: preflight, warm-up baseline, cases, settle ticks, collection and export, drain, summary. Also `list`, `validate`, `shape`. |
| `daemon_perf.py` | Samples the candidate daemon's RSS and CPU every 30 s through the run (`perf.csv`, `perf.json`, the summary's "Daemon resources": peaks, slope, restarts, per-case peaks, flags). |
| `deploy_owned_posture.sh` | Operator-side: fetch the CI build, push it and the harness to a host, record state, swap the released service for the owned daemon (isolated, on empty state), run, collect, restore. Linux here; `deploy_owned_posture_macos.sh` and `_windows.sh` for fmba-3 and shiawase. |
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
   the Portal; `deterministic` is refused on the LLM leg); capture, file monitor,
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
export FP_LAB_RUN_ID=<tests.yml run id>  # every command, on every host
$D $H fetch
$D $H push
$D $H record pre-lab
$D $H start
NAME=$($D $H run | tail -1)          # extra args go to `run_fp_lab.py run`
$D $H wait "$NAME"
$D $H collect "$NAME"                # -> ~/Library/Caches/edamame-agents/fp-lab/runs/$NAME
$D $H stop
$D $H record post-lab
```

The owned build's version comes from the run (`Cargo.toml` at its head
commit; `FP_LAB_OWNED_VERSION` overrides), the released one from the host.
`push` verifies the binary's SHA-256 on the host before it replaces the
previous one, and `run` refuses unless `start` opened the window.

Directly on a host whose daemon is already the build under test:

```bash
python3 tests/fp_lab/run_fp_lab.py list
python3 tests/fp_lab/run_fp_lab.py run --dry-run          # the plan, with SKIP reasons
python3 tests/fp_lab/run_fp_lab.py run --set-adjudication auto \
    --scenarios div-instruction-files-read,direct-git-lab-repo
python3 tests/fp_lab/run_fp_lab.py shape <run_dir>       # where jq and the core tools exist
python3 tests/fp_lab/run_fp_lab.py run --leg deterministic   # the no-model user's leg
python3 tests/fp_lab/run_fp_lab.py run --scenarios tag:operators_day --agents ""   # one tagged group
python3 tests/fp_lab/run_fp_lab.py summarize <run_dir>   # re-render the summary from the case files
```

In CI: `agent_monitoring_e2e.yml` has an `fp_lab` mode (workflow_dispatch
`mode: fp_lab`, `posture_build_run_id: <tests.yml run id>`,
`fp_lab_scenarios`). It reuses the job's agent CLI installs, provider keys,
`edamame_cli` and registry checkout, swaps the action's released daemon for
the `posture-binary-<label>` build of the run you name, runs the lab, and
uploads the run directory as `fp-lab-<label>`. The default `fleet` mode (push,
PR, release gate) is unchanged.

### The deterministic leg

`run --leg deterministic` is the same scenarios with both engines pinned to
`deterministic` and no model required: what a user without a Portal or own
model sees. Its summary is labelled (`leg: deterministic`), its alertable
findings are the deterministic layer's rate on benign work and are never
shaped as corpus candidates (`shape` refuses the run directory): a finding
is evidence only once the Portal adjudicated it. Run it in the CI leg after
the LLM leg (`fp_lab_leg: deterministic`): the workflow cancels a run on the
same branch, so the two legs go one after the other. In a dogfood window it
needs a window of its own: a second leg in the same window inherits the
first leg's findings, which the runner baselines, and hides repeats.

## The operator's day set (`tag:operators_day`)

On 2026-10-23 the operator's developer Mac raised seven alertable findings
on an ordinary day, all benign and none of them a lab shape
(`edamame_core/FALSEPOSITIVES-APPROACH-2026-10.md`, section 2.1). These five
agent-free scenarios reproduce those shapes. Each is benign by construction
and passes (no alertable finding) on a correct detector. A FAIL is the FP
named in the case's `fp_class`, or a new one. The automatic CI leg runs them
with the rest of the catalog. Run the set alone with
`run --scenarios tag:operators_day --agents ""` (add `--leg deterministic`
for the no-model user's view).

| Scenario | Platforms | What it does | Why it is benign | Cleanup | FP |
|---|---|---|---|---|---|
| `direct-headless-browser-own-profile` | Linux, macOS, Windows; SKIP when no Chromium-family browser is found | Runs Playwright's cached `chrome-headless-shell` or Chrome for Testing when present, else an installed Chrome / Chromium / Edge / Brave (`FP_LAB_BROWSER` overrides). It runs headless on `--user-data-dir=<workspace>/browser-test-profile` and opens sites through its loopback DevTools port: github.com, wikipedia.org, python.org in launch 1 (which creates the profile's cookie store), then mozilla.org, pypi.org, rust-lang.org in launch 2 (which reads it back), 15 s each | The profile is the browser's own: it created it, and it holds only what those sites set. `--use-mock-keychain` and `--password-store=basic` (what Playwright passes) keep it off the macOS keychain and the Linux keyring. The user's browser profiles are never opened | Process tree stopped (its process group; `taskkill /T /F` on Windows), profile removed | FP-MAC-12 / FP-MAC-29 |
| `direct-os-relay-keychain-sidecars` | macOS only | `/usr/bin/curl`, an Apple platform binary standing in for `networkserviceproxy`, inherits open descriptors on two files in a test home's `Library/Keychains`: the lock `.fl<hex>` and the safe-save sidecar `login.keychain-db.sb-<hex>-<hex>`. It requests Apple's connectivity page every 10 s for about 80 s (`--rate 6/m`; a curl older than 7.84 holds one slow transfer instead) | The files are placeholders in the workspace (an empty lock file and a copy of a placeholder database) and curl never reads them. The real keychain and `~/Library/Keychains` are never opened | Descriptors closed, test home removed | FP-MAC-19 |
| `direct-sync-client-store-rename` | Linux, macOS, Windows | `standins.py`, run as `sync-client/fplab_sync_client.py sync-client --data-dir <dir>`, creates its data directory in a test home under the workspace, at the platform's application-data layout (`Library/Application Support/FPLab Sync/account-0001`, `.config/fplab-sync/account-0001`, `AppData/Local/FPLab Sync/account-0001`). It writes a placeholder `credentials.json` there with a safe-save rename and holds it open while it fetches the Drive API discovery document from www.googleapis.com every 8 s for about 80 s. It refreshes the file three times (writes `credentials.json.sb-<hex>`, then replaces the store with it) | The client created the directory and the file, and its command line names the directory. The store holds a fixed placeholder, and the client reads nothing it did not write | Test home removed | FP-MAC-40 |
| `direct-installer-sibling-temp-staging` | Linux, macOS, Windows (needs the system `tar`; on Windows `%SystemRoot%\System32\tar.exe`) | Copies the platform's `tar` into `<tmp>/<ID2>/FPLab Installer/` (the extractor a self-extracting installer carries), writes `payload.tar` beside it, and runs the copy to unpack 480 files into `<tmp>/<ID1>/`, a sibling tree the extraction creates: a manifest, 30 locale tables, 40 components with a descriptor and 10 data parts each, and 9 documents | The payload is inert data: no executable bits, no scripts, no binaries, no network | Both trees removed | FP-MAC-31 |
| `direct-script-document-in-temp` | Linux, macOS, Windows | `standins.py`, run as `scripts/make_report.py report --out <tmp>/report-<hex>.pdf`, requests pypi.org's JSON API every 8 s for about 60 s. Meanwhile it writes a 1-page PDF report into the temp directory, then rewrites it with 2 pages | The PDF is text in Helvetica, with no JavaScript, actions, annotations or embedded files. The request has nothing to do with the document | PDF removed | E3 in `FALSEPOSITIVES.md` (`fp_class` `new`) |

Notes:

- **Stand-ins.** The lab cannot install Google Drive, an OS relay daemon or
  the operator's own script on a runner, so three cases use stand-ins.
  `standins.py` runs as its own process from the case workspace, so the
  process the detector sees is a program whose command line names what it
  owns. The relay stand-in is a real OS platform binary.
- **macOS only for the keychain sidecars.** The login keychain's lock and
  safe-save sidecars, and Apple's platform-binary signature, have no
  equivalent on Linux or Windows: the case is not built there.
- **Where the files go.** The sync client's data directory is a test home
  in the workspace, outside the directories the file monitor watches by
  default, so its renames are not file events in the lab: that case
  measures the client holding its own store open during its sync. Writing
  into the user's real application-data directory instead would break the
  rule that the lab keeps to its workspace and temp. The two temp scenarios
  write under `/tmp` on Linux and macOS, where the operator Mac's shapes
  were, and under `%TEMP%` on Windows, at uniquely named paths.
- **TLS.** The Python stand-ins always verify certificates. When the
  interpreter has no CA bundle and no `certifi`, they exit 3 and the case is
  SKIP. They never turn verification off.
- **noexec temp.** A temp root mounted `noexec` makes the installer case
  SKIP (stimulus not delivered).

## Local loop (the operator Mac)

`tests/local_loop/run_local_loop.sh` opens the same owned-daemon window on
the operator Mac itself, for a posture built from the workspace (`--build`)
instead of a CI pkg: it records and stops the app and the helper, saves root's
posture state, and its EXIT trap puts all of it back. In that window it runs a
short idle baseline, the CVE scenarios with their alertable exports, and this
lab's agent-free `direct-*` scenarios (`--agents ""`), then shapes the
evidence: attack exports into staged `edamame_core/tests/attack_corpus`
envelopes (`tools/attack_corpus_from_gate.py`, `--promote` copies them), this
lab's alertables into staged FP candidates. It is the live step between the
offline replay (`edamame_core/tools/fp_loop/`) and CI; `--dry-run` prints
every step and changes nothing. See `tests/local_loop/README.md`.

## The release candidate, end to end

The gate itself (what blocks, why) is `edamame_rules/edamame_app/release.mdc`,
Pre-Release FP Lab Gate. This is the command sequence one session runs, with
`<ver>` the release (`2.0.5`) and `rN` the candidate number.

**1. Lab branches** (before the cascade: the candidate is built from branches
whose git dependencies point at each other; `main` later receives the same
commits). Work in throwaway worktrees, never in the clones' `main`.

- flodbadd: `git push origin <local main sha>:refs/heads/fp-lab-<ver>`.
- edamame_foundation: on `fp-lab-<ver>`, `git reset --hard main`, cherry-pick
  the branch-only commit "fp lab: build against flodbadd fp-lab-<ver>",
  `cargo update -p flodbadd`, commit `Cargo.lock`, `git push
  --force-with-lease=fp-lab-<ver>:<head you started from>`.
- edamame_core: the same, with "fp lab: build against foundation and
  flodbadd fp-lab-<ver>" and `cargo update -p edamame_foundation -p flodbadd`.
- edamame_posture: `git checkout -b fp-lab-<ver>-rN main`, cherry-pick the two
  branch-only commits ("build against core, foundation and flodbadd
  fp-lab-<ver>" and "production backends, as the main build", which passes
  `main` as the backend branch), `cargo update -p edamame_core -p
  edamame_foundation -p flodbadd`, commit the lock, push the branch.
- Every branch-only commit says "(branch only, never main)".

**2. Build:** `gh workflow run tests.yml --ref fp-lab-<ver>-rN -f run_tests=true
-f run_perf=true -f run_security=true`. Its security jobs (CVE scenarios,
idle baseline, lineage gate) and perf jobs are part of the gate.

**3. Lab legs, once the four builds are green:**
- CI: `gh workflow run agent_monitoring_e2e.yml --ref fp-lab-<ver>-rN -f
  mode=fp_lab -f posture_build_run_id=<tests.yml run id>`; read it with `gh
  run download <run> --dir ~/Library/Caches/edamame-agents/fp-lab/runs/ci-<run>`.
- Dogfood, all three hosts in parallel, `export FP_LAB_RUN_ID=<tests.yml run id>`
  first (every command reads it):

  ```bash
  D=tests/fp_lab/deploy_owned_posture.sh      # test-mint | fmba-3 | shiawase
  $D <host> status                            # released service/app/helper up, no owned daemon
  $D <host> fetch && $D <host> push
  $D <host> keys && $D <host> agents          # keys for the window only
  $D <host> start                             # check: active_findings 0, contributor_count 0
  NAME=$($D <host> run | tail -1)
  $D <host> wait "$NAME" && $D <host> collect "$NAME"
  $D <host> stop                              # always; read its output
  ```

- Results: `~/Library/Caches/edamame-agents/fp-lab/runs/<name>/summary.md`
  (verdict per case, "Daemon resources"), the bundles and corpus candidates
  beside it.

**4. Not clean:** fix the root cause (`falsepositive-analyze-fix`), commit the
lab's candidate as a corpus entry, run `fp_replay`, `divergence_replay` and
`divergence_ingest_replay` on core, and go back to 1 with `rN+1`. Restore the
hosts (`stop`) between candidates.

**5. Clean on all three platforms:** push flodbadd and edamame_foundation
`main`; in edamame_core `cargo update -p edamame_foundation -p flodbadd` (core
pins them by git revision); if an `src/api/` signature changed, run
`edamame_app/tear_down_walls.sh` and commit core's and the app's regenerated
bridge together; run `edamame_app/commit_all.sh` (the cascade pushes every
repo); record the run in `edamame_app/NEXTRELEASE.md` (posture commit, legs,
PASS / SKIP with reasons, resources, artifacts); then `release_all.sh`.

## Safety rules

- The lab user is the host's console user; the runner refuses root unless
  `--allow-root` (CI only, where the root daemon observes `/root`).
- Workspaces live under the lab root (`~/fp-lab/ws`), never in OS temp or a
  scratchpad. Only `temp_behaviour` scenarios use temp, through their own
  `mktemp -d` (the operator's-day temp scenarios: uniquely named paths under
  `/tmp` or `%TEMP%`), and remove it.
- No scenario reads or writes the user's real credentials or config:
  fixtures carry AWS's documentation example key and a fake PEM body; the
  credential-helper scenario points `GIT_CONFIG_GLOBAL` at a lab gitconfig
  and a lab-local store with a placeholder; git identities come from the
  environment, never `git config --global`. The operator's-day scenarios
  build their keychain and application-data layouts in test homes under the
  workspace, and the headless browser runs on its own profile with the OS
  keychain and keyring mocked.
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
  snapshots. A host's daemon state stays what the run left, which is why
  every window's `start` gives the candidate an empty owned state (the
  previous window's moves aside) and why `active_findings` must read 0
  after it.
- Live-check every host before a window (`<host> status`), and `stop`
  after `collect` on every host: a window is over when the released
  service, app and helper run again and the keys are gone.
- One session drives the lab (`edamame_rules/edamame_app/release.mdc`,
  Pre-Release FP Lab Gate): a second assistant that finds windows open
  reports and stops.
- The `dogfood-watch` LaunchAgent on the operator Mac reads an open window
  as lab mode (the window markers or a candidate daemon): the candidate's
  samples are recorded apart, nothing is graded or upgraded, and a host
  still in lab mode after 8 h alerts qa-alerts.

## Adding a scenario

Add a `Scenario` to `scenarios.py` (and a function to `direct_actions.ACTIONS`
or a fixture to `lab_workspace.FIXTURES` if needed), then
`python3 tests/fp_lab/run_fp_lab.py validate`. Set `fp_class` to the FP it
reproduces (`FALSEPOSITIVES.md` id) or `new`, `marker` to a file the stimulus
must produce, and `temp_behaviour=True` only when temp is the point. `tags`
groups scenarios into a set that `--scenarios tag:<name>` selects.
