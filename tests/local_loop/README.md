# Local loop

One command on the operator Mac that runs the live detection checks against a
posture built from the workspace, and turns what they produce into replayable
evidence: every attack the CVE suite fires becomes an attack-corpus envelope,
every benign FP-lab action that alerts becomes an FP candidate. A detector or
params change is then validated and tuned offline
(`edamame_core/tools/fp_loop/`) before the cascade sends it to CI and before
any dogfood host sees it.

```
tests/local_loop/
    run_local_loop.sh        the loop: window, steps, shaping, summary
    window_root.sh           its root steps (sudo -H): root state, helper, posture
    local_loop_summary.py    summary.json / summary.md and the verdict line
    test_local_loop_summary.py
```

## Running it

```bash
tests/local_loop/run_local_loop.sh --dry-run --build    # the plan, read-only; nothing stops, starts or is written
tests/local_loop/run_local_loop.sh --build              # build posture + edamame_cli, then the full loop
tests/local_loop/run_local_loop.sh --scenarios cve_token_exfil,dns_tunnel --fp-lab-scenarios none
tests/local_loop/run_local_loop.sh --adjudication llm   # Portal-adjudicated, as the CI gate (G-46)
tests/local_loop/run_local_loop.sh --promote-from ~/fp-lab/local-loop/<run>
tests/local_loop/run_local_loop.sh --restore ~/fp-lab/local-loop/<run>   # after a SIGKILL or a reboot
```

Run it as the console user from a terminal (it asks for sudo once and keeps
the credentials fresh: the restore and the memory-scrape trigger's `sudo -n`
need them an hour later). A terminal holding Full Disk Access gives the root
daemon the same file access a root SSH session gives the FP-lab daemon. `--help` lists every flag.

At CI timing the CVE suite alone is the long part: the macOS leg's scenarios
took 46 minutes in run 34902330391 (their `elapsed_s` sum). `--cve-args
"--trigger-duration 120 --poll-attempts 4"` shortens it; a subset runs with
`--scenarios`.

## What one run does

1. `--build` (optional): `make macos_release` in `edamame_posture` and
   `cargo build --release` in `edamame_cli`, with the compile-time variables
   from `../secrets/{foundation,lambda-signature,sentry,analytics}.env`
   (never printed). A posture branch other than main/master/dev talks to the
   dev backends (VERGEN_GIT_BRANCH): with the Portal the loop refuses.
2. **Window** (`deploy_owned_posture_macos.sh`'s `start`, locally): records
   what runs (the app's pid and bundle, the helper under launchd or started
   by hand, the cargo-hygiene LaunchAgents) in `<out>/window/pre-state.env`,
   pauses those agents, quits the app, stops the helper, checks 40151/40152
   are free, saves and clears root's posture state (the `edamame_posture`
   defaults domain, `/var/root/.edamame`, `/var/root/Library/Application
   Support/edamame_posture`, under `/var/root/fp-lab/local-loop/original`),
   and starts the owned posture as root with `background-start-disconnected
   --packet-capture --agentic-mode analyze` (never the Hub; `HOME` is the
   console user's so the transcript observer reads this user's agents).
3. **Adjudication**: both engines are pinned to `--adjudication`
   (`set_*_adjudication_mode`). `advisory` (default, no Portal key) publishes
   the detector's own grades; `auto` and `llm` load the Portal key from
   `../secrets/agentic.env` in the root step only, into the daemon's
   environment (never argv, never printed).
4. **Idle baseline**: `run_false_positive_baseline.sh --duration
   <--baseline-secs> --abort-on-first-finding 0`. Unlike CI, a dirty baseline
   does not stop the loop: this Mac is a workstation, and its findings are
   listed for triage.
5. **CVE suite**: `run_cve_detection.sh --export-matched <N>` against a staged
   copy of the triggers. Every scenario writes `findings/<scenario>.meta.json`
   and, when it alerted, up to N alertable exports (`alertable_exports` in
   `findings/<scenario>.export.json`).
6. **FP lab, agent-free**: `run_fp_lab.py run --scenarios <every direct
   scenario for macOS> --agents "" --set-adjudication <mode>
   --expect-core-version <the owned daemon's> --warmup-secs 60 --drain-secs
   120` (`--allow-no-llm` without the Portal). Workspaces go under
   `~/fp-lab/ws/fp_lab/`.
7. **Window closes** (also on any failure, Ctrl-C or SIGTERM / SIGHUP, through
   the EXIT trap; Ctrl-C is ignored while it runs): leftover trigger
   processes and their demo files (`cleanup.py`), the owned posture, its logs
   (copied to `<out>/daemon-logs/`), root's posture state back exactly (the
   lab's kept in `/var/root/fp-lab/local-loop/lab-state-<time>`), the helper
   restarted as it ran, the app relaunched from the bundle that ran (its HOME,
   connection and protection printed), the agents resumed.
8. **Shaping, offline**: `edamame_core/tools/attack_corpus_from_gate.py
   --platform macos-<arch> --label local-<host>-<time>` on `<out>/cve` into
   `<out>/staging/attack_corpus/`; the FP lab's candidates (shaped by
   `fp_corpus_from_export.sh` as they were found) copied to
   `<out>/staging/fp_corpus/` and `staging/divergence_corpus/`. `--promote`
   copies the attack envelopes into `edamame_core/tests/attack_corpus/`,
   uncommitted; FP candidates are drafts and are reviewed and committed by
   hand.
9. **Summary**: `summary.json`, `summary.md`, and one line, for example
   `VERDICT FAIL: cve 21/23 passed (failed: process_memory_scrape,
   agent_memory_scrape); baseline clean (120 s); fp-lab 0 alertable, 0
   incident(s); 18 attack envelope(s) staged`.

Exit codes: 0 PASS, 1 FAIL (a CVE scenario failed, the baseline saw a
finding, the FP lab alerted), 2 INCOMPLETE (a step left no result) or a
refused start, 3 the restore reported a problem.

## Output

```
~/fp-lab/local-loop/<host>-<time>/
    summary.md, summary.json, loop.log, window.tsv, steps.tsv
    window/pre-state.env          what --restore puts back
    build/*.log                   with --build
    triggers/                     the staged CVE triggers
    baseline/                     baseline.json, samples, tick logs
    cve/                          results.json, findings/<s>.{json,meta.json,export.json}, trigger logs
    fp_lab/                       the FP lab run (summary.json, cases/, candidates/)
    daemon-logs/                  the owned daemon's /var/log/edamame logs
    staging/attack_corpus/<scenario>/macos-<arch>-local-<host>-<time>.json
    staging/attack_corpus.report.json   written / skipped, with reasons
    staging/fp_corpus/<FP-ID>/    FP-lab alertables as draft fp_corpus envelopes
```

## This Mac, specifically

- The app on the operator Mac is a `flutter run` debug build: quitting it
  ends `flutter run`, and the loop relaunches the same bundle with `open`
  (hot reload is gone until `flutter run` again). The loop only relaunches the
  bundle that was running, never `open -a`: `/Applications` holds an old app
  that must not be opened against the 2.0 state.
- The helper there is a release build started by hand as root from its
  checkout; the loop restarts it the same way (`--helper-dir`, `--helper-bin`
  override the recorded path). A helper under launchd is disabled, booted out,
  then enabled and bootstrapped again.
- The cargo-hygiene LaunchAgents are paused for the window
  (`LOCAL_LOOP_PAUSE_AGENTS`, `--keep-hygiene`): with the debug app down the
  hourly job runs `edamame_app make clean`. A job running at start refuses the
  window.
- A plain `cargo build` has no Endpoint Security entitlement, so the daemon
  runs FIM on FSEvents and has no macOS task-port route; the window records
  the log's ES lines (`window.tsv`, `es_status`). Expect
  `process_memory_scrape` and `agent_memory_scrape` to miss on such a build:
  their macOS source is the ES task-port event. `--posture-bin` takes the
  binary of a signed bundle instead.
- Ambient findings are real observations of this workstation (this session's
  builds, agents, other apps): read them before calling one a detector FP,
  and only Portal-adjudicated findings count as FP evidence.
- The triggers never overwrite a canonical agent config that exists here
  (`EDAMAME_ALLOW_CANONICAL_TAMPER` is never set): those shapes are skipped.

## Validation without a window

```bash
bash -n tests/local_loop/run_local_loop.sh && bash -n tests/local_loop/window_root.sh
shellcheck -x tests/local_loop/run_local_loop.sh tests/local_loop/window_root.sh
tests/local_loop/run_local_loop.sh --dry-run --build
python3 -m unittest discover -s tests/local_loop -p 'test_*.py'
python3 -m unittest discover -s tests/security -p 'test_*.py'      # the CVE runner's exports
python3 -I -B ../edamame_core/tools/test_attack_corpus_from_gate.py
```
