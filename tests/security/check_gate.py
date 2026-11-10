#!/usr/bin/env python3
"""Release-gate check for the CVE detection suite.

Reads per-platform ``results.json`` files produced by
``tests/security/run_cve_detection.sh`` and per-platform ``baseline.json``
files produced by ``tests/security/run_false_positive_baseline.sh`` and
decides whether the security gate should block a release.

The gate is **strict and fail-closed**: absent evidence is a failure, not
a pass. Any scenario that reports ``status=fail`` on any observed
platform, any *required* scenario that is missing or skipped, any
unreadable artifact, and any platform whose 10-minute idle baseline
surfaced one or more vulnerability findings hard-fails the gate and
blocks the release. There is no per-platform tolerance and no
flaky-scenario carve-out. Adversarial / iForest-dependent evasion
scenarios live in ``edamame_core/tests/evasion`` so their probabilistic
detection path does not gate releases here.

Gate policy:

- **HARD FAIL** (exit 1):
  * at least one scenario reports ``status=fail`` on at least one
    platform, OR
  * a required scenario (``--required-scenarios``) is absent from a
    platform's ``results.json``, or present with ``status=skip``, OR
  * a scenario reports ``status=pass`` while recording zero **alertable**
    (HIGH/CRITICAL, non-dismissed) findings -- the shape a CRS-weight or
    LLM-adjudicator regression takes -- or while recording no
    ``finding_alertable`` field at all, OR
  * an adjudicator-demotable scenario (``ADJUDICATOR_DEMOTABLE_SCENARIOS``
    in ``triggers/_finding_match.py``, the harness's own list) reports
    ``status=pass`` with neither an alertable finding nor a finding the
    detector graded HIGH/CRITICAL and the adjudicator DEMOTEd
    (``finding_adjudicator_demoted``, proved from the finding's debug trace
    by the harness), OR
  * an expected-clean scenario (``CLEAN_EXPECTED_SCENARIOS`` in
    ``triggers/_finding_match.py``: benign work the planted model
    authorizes, which must raise nothing) reports ``status=pass`` with an
    alertable finding, OR
  * a platform named in ``--expected-platforms`` produced no results
    directory at all, OR
  * a platform ran a clean baseline but produced no readable
    ``results.json`` (CVE step crashed, timed out, or was never
    reached), OR
  * any ``results.json`` / ``baseline.json`` present on disk cannot be
    parsed, OR
  * at least one platform reports a dirty idle baseline (``baseline.json``
    with ``status=fail`` or ``finding_total > 0``), OR
  * a platform's kernel process-ancestry check (``lineage.json``, written by
    ``run_lineage_gate.py``) is missing, unreadable, or anything but
    ``status=pass`` with every recorded check true -- whatever the baseline
    did: the ancestry check runs before it and does not depend on it, OR
  * only with ``--fail-on-idle-raw-candidates``: a platform's clean idle
    baseline recorded raw candidates (the deterministic layer raised them
    and adjudication quieted them), or did not record the counts.
  The matrix of failures is printed to stdout so the caller can forward
  it to ``$GITHUB_STEP_SUMMARY`` and trigger a rollback.
- **PASS** (exit 0): every expected platform resolved the kernel ancestry
  of the lineage gate's process chain, produced results, every
  required scenario reported ``status=pass`` with at least one alertable
  finding (an adjudicator-demotable scenario: or an alertable grade the
  adjudicator DEMOTEd) on every
  platform, no scenario failed, and every platform's idle baseline was
  clean.

Why a missing platform is not a pass
------------------------------------

The gate reads whichever per-platform directories exist under
``--results-dir``, and the native matrix is built dynamically by the
``setup`` job. Without ``--expected-platforms`` a matrix leg that was
cancelled, timed out before its ``if: always()`` artifact upload, or was
dropped from the matrix entirely simply has no directory -- and the gate
would pass on the platforms that did report. Naming the expected labels
turns that silent shortfall into a hard failure.

Why "skip" is not a pass
------------------------

``run_cve_detection.sh`` emits ``status=skip`` when it cannot even
attempt a scenario -- no expected-check mapping, or the trigger script is
missing from the triggers directory. Treating that as a pass means a
renamed or unshipped trigger silently removes an attack scenario from the
release gate. ``--required-scenarios`` is the allowlist of scenarios that
MUST produce a real verdict; anything on that list reporting ``skip`` is
a hard failure. Scenarios not on the list keep the permissive behaviour
so an experimental trigger can ride along without gating.

Input layout::

    <results-dir>/
      <platform-a>/
        run_stamp.json      # which attempt of the run produced this directory
        lineage.json        # kernel process-ancestry check (required)
        results.json        # CVE suite (required for a full gate)
        baseline.json       # 10-min idle baseline (may be absent)
      <platform-b>/
        results.json
        baseline.json

``results.json`` is the output of ``run_cve_detection.sh`` and always
contains ``scenarios[i].{scenario, status, expected_check, finding_total,
finding_alertable, severities, extra}`` plus ``totals.{passed, failed,
skipped, total}``.

``baseline.json`` is the output of ``run_false_positive_baseline.sh`` and
contains ``status`` (``"pass"`` | ``"fail"``), ``finding_total``,
``finding_current``, ``finding_history`` and ``first_finding_sample``, and
the idle window's raw candidate counts, ``raw_candidates_max`` and
``ticks_with_raw_candidates``.

``lineage.json`` is the output of ``run_lineage_gate.py``: ``status``
(``"pass"`` | ``"fail"``), ``reason`` on a failure, ``checks`` (check name ->
bool), the ``chain`` pids and the last probe answer.

``run_stamp.json`` is written by the ``security`` job of
``.github/workflows/tests.yml`` beside the results it is about to produce:
``run_id``, ``run_attempt``, ``platform``.

Reported, never part of the verdict
-----------------------------------

- **Run attempts.** When one platform leg of a run is run again, the report
  job downloads every platform's artifact, and the other platforms' are an
  earlier attempt's: the passing report then combines attempts. The gate
  prints the attempt of each platform's results (``run_stamp.json``) and a
  NOTE when they differ or when any is above 1.
- **Idle raw candidates.** A baseline is clean when no finding was published
  during the idle window. A tick can still have had raw candidates that
  adjudication quieted. The gate prints the counts per platform (counts
  only) and a NOTE when any clean baseline had some;
  ``--fail-on-idle-raw-candidates`` turns that into a hard failure.

``--summary-json`` writes the verdict, the attempts and the idle raw
candidate counts as JSON, for tools.

Exit codes:

- ``0``: gate satisfied.
- ``1``: at least one hard failure. A Markdown summary is printed to
  stdout.
- ``2``: the results directory is empty or unreadable.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import sys
from collections import defaultdict
from typing import Dict, List, Optional, Tuple

# The harness's list of adjudicator-demotable scenarios: read from the same
# module the harness uses, never from the artifact, so a results.json cannot
# relax another scenario.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "triggers"))
from _finding_match import expects_clean, requires_alert  # noqa: E402

VALID_STATUSES = ("pass", "skip", "fail")

# Scenarios that cannot produce a verdict on a platform because the
# platform has no sensor for the shape (not a flake, not a gap in the
# suite). They are not required there: a ``skip`` with a recorded reason
# or an absent row is accepted; a ``fail`` still fails. Mirrors
# ``scenario_excluded_on_this_platform()`` in run_cve_detection.sh (CVE
# scenarios) and in run_divergence_detection.sh (divergence scenarios);
# an entry added here MUST be added to whichever runner owns the scenario.
PLATFORM_EXCLUDED_SCENARIOS: dict = {
    # process_memory_scrape gained its Windows source (flodbadd's
    # Kernel-Audit-API-Calls ETW session) on 2026-09-07 and is no longer
    # excluded anywhere.
    "windows-x64": {
        # daemon_lineage_egress installs a stand-in daemon into a
        # soft-trusted system location and asserts on l7.parent_process_path.
        # The Windows equivalent needs a %WINDIR%\System32 write plus ETW
        # parent attribution; neither is implemented. Owned by
        # run_divergence_detection.sh.
        "daemon_lineage_egress",
    },
}


def required_on(platform: str, required: List[str]) -> List[str]:
    excluded = PLATFORM_EXCLUDED_SCENARIOS.get(platform, set())
    return [name for name in required if name not in excluded]


def _read_json(path: str) -> Tuple[Optional[dict], Optional[str]]:
    """Load a JSON artifact.

    Returns ``(data, error)``. ``(None, None)`` means the file does not
    exist; ``(None, "...")`` means it exists but could not be parsed --
    which the gate treats as a hard failure rather than a warning,
    because an unparseable artifact carries no evidence that the suite
    actually ran.
    """
    if not os.path.isfile(path):
        return None, None
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception as exc:
        return None, f"{type(exc).__name__}: {exc}"
    if not isinstance(data, dict):
        return None, f"expected a JSON object, got {type(data).__name__}"
    return data, None


def _platform_dirs(results_dir: str) -> List[str]:
    return [
        path
        for path in sorted(glob.glob(os.path.join(results_dir, "*")))
        if os.path.isdir(path)
    ]


def _baseline_is_dirty(data: Optional[dict]) -> bool:
    if not isinstance(data, dict):
        return False
    if str(data.get("status", "")).lower() == "fail":
        return True
    try:
        return int(data.get("finding_total") or 0) > 0
    except (TypeError, ValueError):
        return False


def _baseline_is_unmeasured(data: Optional[dict]) -> bool:
    """No findings, but the last tick withheld its raw candidates (``llm``
    adjudication failed): ``run_false_positive_baseline.sh`` writes
    ``status: unmeasured``. Not a clean host, and the CVE suite was skipped."""
    return isinstance(data, dict) and str(data.get("status", "")).lower() == "unmeasured"


def _lineage_failure(data: dict) -> Optional[str]:
    """Why a readable ``lineage.json`` fails the gate, or ``None`` when it
    passes. Fail-closed: a pass needs ``status=pass`` AND a non-empty
    ``checks`` map whose every value is ``true``, so an artifact that says
    pass without its evidence (hand-edited, truncated, an older script) does
    not read as one."""
    status = str(data.get("status", "")).lower()
    checks = data.get("checks")
    if status != "pass":
        reason = str(data.get("reason") or "").strip() or "no reason recorded"
        return f"status={status or 'missing'}: {reason}"
    if not isinstance(checks, dict) or not checks:
        return "status=pass without its checks (malformed lineage.json)"
    failed = sorted(name for name, ok in checks.items() if ok is not True)
    if failed:
        return f"status=pass but check(s) failed: {', '.join(failed)}"
    return None


def _as_int(value: object) -> Optional[int]:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


# Written by the `security` job beside the results it is about to produce:
# which attempt of the run a platform's results come from.
RUN_STAMP = "run_stamp.json"


def _platform_attempt(path: str) -> Optional[int]:
    """The run attempt that produced a platform's results, or ``None`` when
    its ``run_stamp.json`` is absent, unreadable or carries no positive
    ``run_attempt``. Never a failure: the attempts are reported, not gated."""
    data, _err = _read_json(os.path.join(path, RUN_STAMP))
    value = (data or {}).get("run_attempt")
    attempt = None if isinstance(value, bool) else _as_int(value)
    return attempt if attempt is not None and attempt >= 1 else None


def attempts_summary(by_platform: Dict[str, Optional[int]], report_attempt: Optional[int] = None) -> dict:
    """The ``attempts`` object of the machine-readable summary.

    ``platforms`` maps each platform to the attempt its results come from
    (``None``: no stamp). ``mixed`` says the platforms come from different
    attempts, ``rerun`` that at least one comes from an attempt above 1.
    ``report`` is the attempt this report was produced in, when known."""
    known = {p: a for p, a in by_platform.items() if a is not None}
    distinct = sorted(set(known.values()))
    return {
        "platforms": {p: by_platform[p] for p in sorted(by_platform)},
        "distinct": distinct,
        "mixed": len(distinct) > 1,
        "rerun": any(a > 1 for a in known.values()),
        "unstamped": sorted(p for p, a in by_platform.items() if a is None),
        "report": report_attempt,
    }


def attempts_lines(attempts: dict) -> Tuple[List[str], List[str]]:
    """``(lines, notes)``: the "Run attempts" section, one line per platform,
    and the NOTEs it carries (also returned alone, for the JSON summary)."""
    lines = ["### Run attempts", ""]
    for platform, attempt in attempts["platforms"].items():
        lines.append(f"- {platform}: attempt {attempt}" if attempt is not None
                     else f"- {platform}: attempt not recorded (no `{RUN_STAMP}`)")
    if attempts.get("report") is not None:
        lines.append(f"- this report: attempt {attempts['report']}")
    lines.append("")
    notes: List[str] = []
    if attempts["mixed"]:
        groups = "; ".join(
            f"attempt {a}: {', '.join(p for p, v in attempts['platforms'].items() if v == a)}"
            for a in attempts["distinct"]
        )
        notes.append(
            f"NOTE: the platform results come from different attempts of this run ({groups})."
            " At least one platform leg was run again and this report combines"
            " attempts: it is not the result of a single attempt. The verdict"
            " below is unchanged by this."
        )
    elif attempts["rerun"]:
        notes.append(
            f"NOTE: the platform results come from attempt {attempts['distinct'][0]} of this run,"
            " not from its first attempt: the run was run again and the earlier"
            " attempt's results are not in this report. The verdict below is"
            " unchanged by this."
        )
    if attempts["unstamped"] and len(attempts["unstamped"]) < len(attempts["platforms"]):
        notes.append(
            f"NOTE: no attempt is recorded for {', '.join(attempts['unstamped'])}:"
            " its results cannot be tied to an attempt of this run."
        )
    for note in notes:
        lines += [note, ""]
    return lines, notes


def _baseline_raw_candidates(data: Optional[dict]) -> Optional[dict]:
    """The idle window's raw candidate counts from a ``baseline.json``:
    ``ticks`` (detector ticks recorded), ``ticks_with_raw_candidates`` and
    ``raw_candidates_max``. ``None`` when the baseline does not record them
    (written by an earlier ``run_false_positive_baseline.sh``)."""
    if not isinstance(data, dict):
        return None
    ticks_with = _as_int(data.get("ticks_with_raw_candidates"))
    peak = _as_int(data.get("raw_candidates_max"))
    if ticks_with is None or peak is None:
        return None
    adjudication = data.get("adjudication")
    ticks = _as_int(adjudication.get("ticks")) if isinstance(adjudication, dict) else None
    return {"ticks": ticks, "ticks_with_raw_candidates": ticks_with, "raw_candidates_max": peak}


def _had_raw_candidates(raw: Optional[dict]) -> bool:
    return bool(raw) and (raw["ticks_with_raw_candidates"] > 0 or raw["raw_candidates_max"] > 0)


def idle_raw_candidate_lines(
    raw_by_platform: Dict[str, Optional[dict]],
    baseline_state: Dict[str, str],
    quieted: List[str],
    fail_on: bool,
) -> Tuple[List[str], List[str]]:
    """``(lines, notes)`` for the idle baseline section, from the baselines
    that were read: one line per platform with its raw candidate counts
    (counts only, never their content) and a NOTE when a clean baseline had
    some. One line when none had any; nothing when no baseline recorded the
    counts (an earlier ``run_false_positive_baseline.sh``)."""
    recorded = {p: raw for p, raw in raw_by_platform.items() if raw is not None}
    if not recorded:
        return [], []
    if not any(_had_raw_candidates(raw) for raw in recorded.values()):
        return [
            f"Raw candidates during the idle window: none on the {len(recorded)}"
            f" platform(s) that recorded them ({', '.join(sorted(recorded))}).",
            "",
        ], []
    lines = [
        "Raw candidates during the idle window (raised by the deterministic"
        " layer before adjudication; counts only):",
        "",
    ]
    for platform in sorted(raw_by_platform):
        raw = raw_by_platform[platform]
        state = baseline_state.get(platform, "?")
        if raw is None:
            lines.append(f"- {platform} ({state} baseline): not recorded")
            continue
        ticks = raw["ticks"] if raw["ticks"] is not None else "?"
        if not _had_raw_candidates(raw):
            lines.append(f"- {platform} ({state} baseline): none in {ticks} tick(s)")
        else:
            lines.append(
                f"- {platform} ({state} baseline): {raw['ticks_with_raw_candidates']} of"
                f" {ticks} tick(s) had raw candidates, at most {raw['raw_candidates_max']}"
                " on one tick"
            )
    lines.append("")
    notes: List[str] = []
    if quieted:
        notes.append(
            f"NOTE: {len(quieted)} platform(s) ({', '.join(quieted)}) had raw candidates on an"
            " idle runner and still report a clean baseline: adjudication quieted"
            " them and no finding was published. Their idle baseline is clean"
            " after adjudication, not before it. "
            + (
                "`--fail-on-idle-raw-candidates` is set: this fails the gate."
                if fail_on
                else "This does not change the verdict; `--fail-on-idle-raw-candidates`"
                " (workflow input `fail_on_idle_raw_candidates`) makes it a failure."
            )
        )
    for note in notes:
        lines += [note, ""]
    return lines, notes


def _warm_baseline_lines(warm_dir: str) -> List[str]:
    """Render the ADVISORY warm-host baseline section (step 7.1 / D-4).

    Reads per-platform ``baseline.json`` files produced by the 60-minute idle
    window on the self-hosted ``vm-runner-*`` legs. This section is purely
    informational for the first release: it is printed as its own row in the
    security report but NEVER changes the gate's exit code. A dirty warm baseline
    here is surfaced for triage, not blocked on.
    """
    lines: List[str] = ["### Warm-host baseline (advisory, non-gating)", ""]
    if not warm_dir:
        lines.append(
            "_Not collected in this run (no `--warm-baseline-dir`)._"
        )
        lines.append("")
        return lines
    platform_dirs = _platform_dirs(warm_dir)
    if not platform_dirs:
        lines.append(
            "_No warm-host baseline artifacts were produced by the"
            " `warm-baseline` job (self-hosted `vm-runner-*` legs). Advisory"
            " only -- the strict gate is unaffected._"
        )
        lines.append("")
        return lines
    lines.append(
        "A 60-minute idle window on the self-hosted warm runners (persistent"
        " state, unlike the ephemeral GitHub-hosted matrix). Advisory for the"
        " first release: findings here are surfaced for triage but do NOT block"
        " the release. See the `warm-baseline` job in"
        " `.github/workflows/tests.yml`."
    )
    lines.append("")
    lines.append(
        "| Platform | Status | Duration (s) | Total findings | Current | History | First dirty sample |"
    )
    lines.append("|---|---|---|---|---|---|---|")
    for path in platform_dirs:
        platform = os.path.basename(path)
        data, err = _read_json(os.path.join(path, "baseline.json"))
        if err:
            lines.append(f"| {platform} | `UNREADABLE` | - | - | - | - | `{err}` |")
            continue
        if data is None:
            lines.append(f"| {platform} | `MISSING` | - | - | - | - | - |")
            continue
        status = (
            "DIRTY" if _baseline_is_dirty(data)
            else "UNMEASURED" if _baseline_is_unmeasured(data)
            else "CLEAN"
        )
        total = _as_int(data.get("finding_total")) or 0
        cur = _as_int(data.get("finding_current")) or 0
        hist = _as_int(data.get("finding_history")) or 0
        duration = data.get("duration_s", "?")
        first = str(data.get("first_finding_sample") or "-")
        lines.append(
            f"| {platform} | `{status}` | {duration} | {total} | {cur} | {hist} | `{first}` |"
        )
    lines.append("")
    return lines


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--results-dir",
        required=True,
        help="Directory containing per-platform subdirectories with results.json files",
    )
    ap.add_argument(
        "--required-scenarios",
        default="",
        help=(
            "Comma-separated scenarios that MUST report status=pass with at"
            " least one alertable finding on every platform that ran the"
            " suite. A required scenario that is missing or skipped is a hard"
            " failure. Empty (default) keeps the legacy permissive behaviour."
        ),
    )
    ap.add_argument(
        "--expected-platforms",
        default="",
        help=(
            "Comma-separated platform labels that MUST each have produced a"
            " results directory. A platform that never appears under"
            " --results-dir is a hard failure. Without this, the gate only"
            " inspects the directories that happen to exist, so a matrix leg"
            " that was cancelled, timed out, or was dropped from the matrix"
            " passes silently."
        ),
    )
    ap.add_argument(
        "--warm-baseline-dir",
        default="",
        help=(
            "Optional directory containing per-platform subdirectories with a"
            " warm-host baseline.json (the 60-minute idle window on the"
            " self-hosted vm-runner-* legs, step 7.1). Rendered as an ADVISORY"
            " section in the report; it never changes the gate's exit code."
        ),
    )
    ap.add_argument(
        "--fail-on-idle-raw-candidates",
        action="store_true",
        help=(
            "Fail the gate on a clean idle baseline whose ticks had raw"
            " candidates (raised by the deterministic layer, quieted by"
            " adjudication), or that did not record the counts. Off by default:"
            " the counts are then reported with a NOTE and the verdict is"
            " unchanged."
        ),
    )
    ap.add_argument(
        "--summary-json",
        default="",
        help=(
            "Write the machine-readable summary here: the verdict and exit"
            " code, the run attempt of each platform's results (`attempts`),"
            " the idle raw candidate counts and the NOTEs."
        ),
    )
    args = ap.parse_args()

    required = [s.strip() for s in args.required_scenarios.split(",") if s.strip()]
    expected_platforms = [
        s.strip() for s in args.expected_platforms.split(",") if s.strip()
    ]
    fail_on_raw = bool(args.fail_on_idle_raw_candidates)

    platform_dirs = _platform_dirs(args.results_dir)
    found_platforms = {os.path.basename(p) for p in platform_dirs}
    missing_platforms = [p for p in expected_platforms if p not in found_platforms]
    attempts = attempts_summary(
        {os.path.basename(p): _platform_attempt(p) for p in platform_dirs},
        _as_int(os.environ.get("GITHUB_RUN_ATTEMPT")),
    )

    def finish(rc: int, verdict: str, **extra: object) -> int:
        """Write the machine-readable summary (when asked) and return ``rc``."""
        if args.summary_json:
            summary = {
                "verdict": verdict,
                "exit_code": rc,
                "results_dir": args.results_dir,
                "platforms": sorted(found_platforms),
                "missing_platforms": missing_platforms,
                "attempts": attempts,
            }
            summary.update(extra)
            try:
                with open(args.summary_json, "w", encoding="utf-8") as fh:
                    json.dump(summary, fh, indent=2, sort_keys=True)
                    fh.write("\n")
            except OSError as exc:
                print(f"[gate] WARN: cannot write {args.summary_json}: {exc}", file=sys.stderr)
        return rc

    if not platform_dirs:
        print(
            f"[gate] ERROR: no per-platform subdirectories found under"
            f" {args.results_dir}",
            file=sys.stderr,
        )
        return finish(2, "error", reason="no per-platform subdirectories")

    # scenario -> [(platform, check, findings, alertable, severities, note)]
    scenario_fails: Dict[str, List[Tuple[str, str, int, int, str, str]]] = defaultdict(
        list
    )
    # (platform, artifact, reason)
    artifact_fails: List[Tuple[str, str, str]] = []
    baseline_fails: List[Tuple[str, int, int, int, str]] = []
    # (platform, reason): a lineage.json that was read and failed.
    lineage_fails: List[Tuple[str, str]] = []
    lineage_passed = 0
    # Idle raw candidate counts per platform (None: not recorded), the state
    # of each platform's baseline, the clean baselines that had raw
    # candidates, and (only with --fail-on-idle-raw-candidates) the failures
    # they make: (platform, reason).
    raw_by_platform: Dict[str, Optional[dict]] = {}
    baseline_state: Dict[str, str] = {}
    raw_quieted: List[str] = []
    raw_fails: List[Tuple[str, str]] = []

    for plat in missing_platforms:
        artifact_fails.append(
            (
                plat,
                "results.json + baseline.json",
                "expected platform produced no results directory at all"
                " (matrix leg cancelled, timed out, lost its artifact upload,"
                " or was dropped from the matrix)",
            )
        )

    total_scenarios = 0
    passed_scenarios = 0
    adjudicator_demoted_passes = 0
    clean_passes = 0
    skipped_scenarios = 0
    baseline_total = 0
    baseline_present = 0
    baseline_clean = 0
    platforms_with_results = 0
    any_artifact_found = False

    for path in platform_dirs:
        platform = os.path.basename(path)
        results, results_err = _read_json(os.path.join(path, "results.json"))
        baseline, baseline_err = _read_json(os.path.join(path, "baseline.json"))
        lineage, lineage_err = _read_json(os.path.join(path, "lineage.json"))
        if results is not None or baseline is not None or lineage is not None:
            any_artifact_found = True
        if results_err or baseline_err or lineage_err:
            any_artifact_found = True

        # Kernel process ancestry: independent of the baseline (it runs
        # before it), so required on every platform whatever happened next.
        if lineage_err:
            artifact_fails.append((platform, "lineage.json", f"unreadable ({lineage_err})"))
        elif lineage is None:
            artifact_fails.append(
                (
                    platform,
                    "lineage.json",
                    "missing (the kernel process-ancestry check never ran)",
                )
            )
        else:
            failure = _lineage_failure(lineage)
            if failure:
                lineage_fails.append((platform, failure))
            else:
                lineage_passed += 1

        baseline_total += 1
        if baseline_err:
            baseline_state[platform] = "unreadable"
            artifact_fails.append((platform, "baseline.json", f"unreadable ({baseline_err})"))
        elif baseline is None:
            baseline_state[platform] = "missing"
            artifact_fails.append(
                (platform, "baseline.json", "missing (idle false-positive window never ran)")
            )
        else:
            baseline_present += 1
            raw = _baseline_raw_candidates(baseline)
            raw_by_platform[platform] = raw
            baseline_state[platform] = (
                "unmeasured" if _baseline_is_unmeasured(baseline)
                else "dirty" if _baseline_is_dirty(baseline)
                else "clean"
            )
            if baseline_state[platform] == "clean":
                # Clean after adjudication: what the deterministic layer
                # raised on the idle runner is reported, and fails the gate
                # only when asked to.
                if _had_raw_candidates(raw):
                    raw_quieted.append(platform)
                    if fail_on_raw:
                        raw_fails.append(
                            (
                                platform,
                                f"{raw['ticks_with_raw_candidates']} idle tick(s) had raw candidates"
                                f" (at most {raw['raw_candidates_max']} on one tick) that"
                                " adjudication quieted",
                            )
                        )
                elif raw is None and fail_on_raw:
                    raw_fails.append(
                        (
                            platform,
                            "the baseline did not record its raw candidate counts"
                            " (raw_candidates_max, ticks_with_raw_candidates)",
                        )
                    )
            if _baseline_is_unmeasured(baseline):
                adj = baseline.get("adjudication") or {}
                artifact_fails.append(
                    (
                        platform,
                        "baseline.json",
                        "unmeasured: the last idle tick withheld its raw candidates"
                        f" (llm adjudication {adj.get('last_status') or '?'};"
                        f" {adj.get('withheld_ticks', '?')} of {adj.get('ticks', '?')}"
                        " ticks withheld), so a clean result proves nothing",
                    )
                )
            elif _baseline_is_dirty(baseline):
                baseline_fails.append(
                    (
                        platform,
                        int(baseline.get("finding_total") or 0),
                        int(baseline.get("finding_current") or 0),
                        int(baseline.get("finding_history") or 0),
                        str(baseline.get("first_finding_sample") or ""),
                    )
                )
            else:
                baseline_clean += 1

        # Both skip the CVE suite (the workflow runs it only after a clean
        # baseline step), so a missing results.json is expected for either.
        dirty_baseline = _baseline_is_dirty(baseline) or _baseline_is_unmeasured(baseline)

        if results_err:
            artifact_fails.append((platform, "results.json", f"unreadable ({results_err})"))
            continue
        if results is None:
            # A dirty baseline deliberately skips the CVE suite (the
            # workflow gates the detection step on baseline success), so a
            # missing results.json there is expected and the baseline
            # failure already blocks the release. Every other cause -- CVE
            # step timeout, crash, artifact upload loss -- means we have no
            # detection evidence at all and MUST NOT read as a pass.
            if not dirty_baseline:
                artifact_fails.append(
                    (
                        platform,
                        "results.json",
                        "missing while the idle baseline was clean"
                        " (CVE step crashed, timed out, or never ran)",
                    )
                )
            continue

        platforms_with_results += 1
        seen: Dict[str, dict] = {}
        for scen in results.get("scenarios", []):
            if not isinstance(scen, dict):
                continue
            total_scenarios += 1
            name = str(scen.get("scenario", ""))
            status = str(scen.get("status", ""))
            check = str(scen.get("expected_check", ""))
            findings = _as_int(scen.get("finding_total")) or 0
            alertable = _as_int(scen.get("finding_alertable"))
            severities = str(scen.get("severities", "") or "")
            extra = str(scen.get("extra", "") or "")
            if name:
                seen[name] = scen

            if status == "pass" and expects_clean(name):
                # An expected-clean scenario passes only quiet: its runner
                # recorded `pass` after polling the whole window without a
                # finding of its check, and an alertable finding on it is the
                # regression the scenario exists to catch. The list is the
                # harness's own, never a field of the artifact.
                if (alertable or 0) > 0:
                    scenario_fails[name].append(
                        (
                            platform,
                            check,
                            findings,
                            alertable or 0,
                            severities or "-",
                            "pass_with_finding_on_expected_clean_scenario",
                        )
                    )
                else:
                    passed_scenarios += 1
                    clean_passes += 1
            elif status == "pass" and not requires_alert(name):
                # An adjudicator-demotable scenario passes when its finding
                # alerts, or when the detector graded it alertable and only
                # the adjudicator's DEMOTE lowered it. A grade the detector
                # itself lowered still fails.
                demoted = _as_int(scen.get("finding_adjudicator_demoted")) or 0
                if (alertable or 0) > 0:
                    passed_scenarios += 1
                elif demoted > 0:
                    passed_scenarios += 1
                    adjudicator_demoted_passes += 1
                else:
                    scenario_fails[name].append(
                        (
                            platform,
                            check,
                            findings,
                            alertable or 0,
                            severities or "-",
                            "pass_without_alert_or_adjudicator_demote",
                        )
                    )
            elif status == "pass":
                # A scenario cannot pass without an alertable finding: the
                # gate mirrors production alerting, where only HIGH and
                # CRITICAL non-dismissed findings notify anyone.
                # `run_cve_detection.sh` records `finding_alertable` on every
                # result path, and the gate only ever reads artifacts produced
                # by the same run, so an absent field means a malformed or
                # hand-edited artifact -- absent evidence, which this gate
                # fails closed on rather than accepting as a pass.
                if alertable is None:
                    scenario_fails[name].append(
                        (
                            platform,
                            check,
                            findings,
                            0,
                            severities or "-",
                            "pass without a finding_alertable field"
                            " (malformed results.json)",
                        )
                    )
                elif alertable <= 0:
                    scenario_fails[name].append(
                        (
                            platform,
                            check,
                            findings,
                            0,
                            severities or "-",
                            "pass_without_alertable_finding",
                        )
                    )
                else:
                    passed_scenarios += 1
            elif status == "skip":
                skipped_scenarios += 1
                if name in required_on(platform, required):
                    scenario_fails[name].append(
                        (
                            platform,
                            check,
                            findings,
                            alertable or 0,
                            severities or "-",
                            f"required scenario skipped ({extra or 'no reason recorded'})",
                        )
                    )
            elif status == "fail":
                scenario_fails[name].append(
                    (platform, check, findings, alertable or 0, severities or "-", extra)
                )
            else:
                scenario_fails[name].append(
                    (
                        platform,
                        check,
                        findings,
                        alertable or 0,
                        severities or "-",
                        f"unknown status {status!r} (expected one of {VALID_STATUSES})",
                    )
                )

        for name in required_on(platform, required):
            if name not in seen:
                scenario_fails[name].append(
                    (
                        platform,
                        "-",
                        0,
                        0,
                        "-",
                        "required scenario absent from results.json"
                        " (not in --scenarios, or the run aborted early)",
                    )
                )

    if not any_artifact_found:
        print(
            f"[gate] ERROR: no results.json or baseline.json files found"
            f" under {args.results_dir}",
            file=sys.stderr,
        )
        return finish(2, "error", reason="no results.json, baseline.json or lineage.json")

    attempt_lines, attempt_notes = attempts_lines(attempts)
    raw_lines, raw_notes = idle_raw_candidate_lines(raw_by_platform, baseline_state, raw_quieted, fail_on_raw)

    def summary_extra() -> dict:
        return {
            "idle_raw_candidates": {
                "fail_on_idle_raw_candidates": fail_on_raw,
                "platforms": {
                    p: dict({"baseline": baseline_state.get(p), "recorded": raw is not None}, **(raw or {}))
                    for p, raw in sorted(raw_by_platform.items())
                },
                "quieted": sorted(raw_quieted),
            },
            "failures": {
                "scenarios": len(scenario_fails),
                "baselines": len(baseline_fails),
                "kernel_ancestry": len(lineage_fails),
                "artifacts": len(artifact_fails),
                "idle_raw_candidates": len(raw_fails),
            },
            "notes": attempt_notes + raw_notes,
        }

    print("## Security release gate")
    print()

    # Which attempt each platform's results come from: a re-run leg mixes
    # attempts in this report. Reported, never part of the verdict.
    for line in attempt_lines:
        print(line)

    print("### Idle baseline (no-stimulus window)")
    print()
    if not baseline_fails and baseline_present == baseline_total and baseline_total:
        print(
            f"CLEAN - {baseline_clean}/{baseline_total} platforms observed"
            " zero vulnerability findings during the 10-minute idle window."
        )
        print()
    elif baseline_fails:
        print(
            f"DIRTY - {len(baseline_fails)}/{baseline_total} platform(s)"
            " emitted vulnerability findings with no attack trigger running."
            " The release MUST be blocked."
        )
        print()
        print("| Platform | Total findings | Current | History | First dirty sample |")
        print("|---|---|---|---|---|")
        for plat, total, cur, hist, first in sorted(baseline_fails):
            print(f"| {plat} | {total} | {cur} | {hist} | `{first or '-'}` |")
        print()
    else:
        print(
            f"INCOMPLETE - {baseline_present}/{baseline_total} platform(s)"
            " produced a baseline artifact. Missing baselines are listed"
            " under artifact failures below."
        )
        print()
    # Counts only: what the deterministic layer raised on the idle runner
    # before adjudication. A NOTE when a clean baseline had some.
    for line in raw_lines:
        print(line)

    print("### Kernel process ancestry")
    print()
    if lineage_fails:
        print(
            f"FAIL - {len(lineage_fails)}/{baseline_total} platform(s) did not"
            " resolve the ancestry of the lineage gate's process chain"
            " (`python -> edl_p -> edl_c`). Without kernel ancestry the"
            " detector cannot bind a process to its parent or to an agent"
            " subtree. The release MUST be blocked."
        )
        print()
        print("| Platform | Reason |")
        print("|---|---|")
        for plat, reason in sorted(lineage_fails):
            print(f"| {plat} | {reason.replace('|', '/')} |")
        print()
    elif lineage_passed == baseline_total and baseline_total:
        print(
            f"PASS - {lineage_passed}/{baseline_total} platforms resolved"
            " `edl_c -> edl_p -> python` from the kernel process-event stream,"
            " with no event naming a process as its own parent."
        )
        print()
    else:
        print(
            f"INCOMPLETE - {lineage_passed}/{baseline_total} platform(s)"
            " produced a passing lineage artifact. Missing ones are listed"
            " under artifact failures below."
        )
        print()

    # Advisory warm-host baseline section (step 7.1 / D-4). Printed in BOTH the
    # pass and fail branches (it sits before the decision) and NEVER affects the
    # exit code -- it is informational for the first release.
    for line in _warm_baseline_lines(args.warm_baseline_dir):
        print(line)

    # raw_fails is empty unless --fail-on-idle-raw-candidates is set.
    if not scenario_fails and not baseline_fails and not artifact_fails and not lineage_fails and not raw_fails:
        print(
            f"PASS - kernel ancestry resolved on {lineage_passed} platform(s);"
            f" {total_scenarios} scenario result(s) across"
            f" {platforms_with_results} platform(s):"
            f" {passed_scenarios - adjudicator_demoted_passes - clean_passes} passed with an alertable finding,"
            f" {adjudicator_demoted_passes} with an alertable grade the adjudicator lowered,"
            f" {clean_passes} expected-clean scenario(s) stayed clean,"
            f" {skipped_scenarios} skipped (none required),"
            f" and {baseline_clean}/{baseline_total} platform(s) had a"
            " clean idle baseline."
        )
        if required:
            print()
            print(
                f"Required scenarios verified on every platform:"
                f" `{'`, `'.join(required)}`."
            )
        return finish(0, "pass", **summary_extra())

    raw_part = (
        f" {len(raw_fails)} idle baseline(s) with raw candidates"
        " (--fail-on-idle-raw-candidates),"
        if raw_fails
        else ""
    )
    print(
        f"FAIL - {len(scenario_fails)} CVE scenario(s),"
        f" {len(baseline_fails)} baseline(s),{raw_part}"
        f" {len(lineage_fails)} kernel-ancestry check(s) and"
        f" {len(artifact_fails)} missing/unreadable artifact(s) failed across"
        f" {baseline_total} platform(s). The release"
        " MUST be blocked or rolled back."
    )
    print()

    if raw_fails:
        print(
            f"### Idle raw candidates (release-blocking with"
            f" `--fail-on-idle-raw-candidates`) -- {len(raw_fails)} platform(s)"
        )
        print()
        print("| Platform | Reason |")
        print("|---|---|")
        for platform, reason in sorted(raw_fails):
            print(f"| {platform} | {reason.replace('|', '/')} |")
        print()
        print(
            "The idle baseline published no finding, but the deterministic layer"
            " raised candidates on an idle runner and adjudication quieted them"
            " (or the baseline did not record the counts)."
        )
        print()

    if scenario_fails:
        total_fails = sum(len(f) for f in scenario_fails.values())
        print(
            f"### CVE scenario failures (release-blocking) -- {total_fails}"
            " platform-scenario failure(s)"
        )
        print()
        print(
            "| Platform | Scenario | Expected check | Findings | Alertable |"
            " Severities | Notes |"
        )
        print("|---|---|---|---|---|---|---|")
        for name, fails in sorted(scenario_fails.items()):
            for platform, check, findings, alertable, severities, note in fails:
                notes = note.replace("|", "/") if note else ""
                print(
                    f"| {platform} | {name} | {check} | {findings} |"
                    f" {alertable} | {severities} | {notes} |"
                )
        print()

    if artifact_fails:
        print(
            f"### Missing or unreadable artifacts (release-blocking) --"
            f" {len(artifact_fails)} artifact(s)"
        )
        print()
        print("| Platform | Artifact | Reason |")
        print("|---|---|---|")
        for platform, artifact, reason in sorted(artifact_fails):
            print(f"| {platform} | `{artifact}` | {reason.replace('|', '/')} |")
        print()
        print(
            "An absent artifact is a gate failure, not a pass: it means the"
            " platform produced no detection or false-positive evidence at"
            " all. Check the `security` job log for a step that timed out or"
            " crashed before writing its JSON."
        )
        print()

    print(
        "This gate is enforced by the `security` job in `.github/workflows/tests.yml`. It"
        " requires every scenario on every platform to produce a"
        " deterministic ALERTABLE (HIGH/CRITICAL) detection AND a clean"
        " 10-minute idle baseline before the CVE suite. Scenarios whose"
        " detection path is probabilistic (iForest anomaly scoring on"
        " slow-rate traffic, timing-sensitive attribution races) are tracked"
        " as adversarial evasion scenarios under"
        " `edamame_core/tests/evasion/` instead of in this CVE suite."
    )

    return finish(1, "fail", **summary_extra())


if __name__ == "__main__":
    sys.exit(main())
