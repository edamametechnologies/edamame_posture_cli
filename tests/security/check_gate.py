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
    LLM-adjudicator regression takes, OR
  * a platform ran a clean baseline but produced no readable
    ``results.json`` (CVE step crashed, timed out, or was never
    reached), OR
  * any ``results.json`` / ``baseline.json`` present on disk cannot be
    parsed, OR
  * at least one platform reports a dirty idle baseline (``baseline.json``
    with ``status=fail`` or ``finding_total > 0``).
  The matrix of failures is printed to stdout so the caller can forward
  it to ``$GITHUB_STEP_SUMMARY`` and trigger a rollback.
- **PASS** (exit 0): every required scenario reported ``status=pass``
  with at least one alertable finding on every platform that ran, no
  scenario failed, and every platform's idle baseline was clean.

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
``finding_current``, ``finding_history`` and ``first_finding_sample``.

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

VALID_STATUSES = ("pass", "skip", "fail")


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


def _as_int(value: object) -> Optional[int]:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


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
    args = ap.parse_args()

    required = [s.strip() for s in args.required_scenarios.split(",") if s.strip()]

    platform_dirs = _platform_dirs(args.results_dir)
    if not platform_dirs:
        print(
            f"[gate] ERROR: no per-platform subdirectories found under"
            f" {args.results_dir}",
            file=sys.stderr,
        )
        return 2

    # scenario -> [(platform, check, findings, alertable, severities, note)]
    scenario_fails: Dict[str, List[Tuple[str, str, int, int, str, str]]] = defaultdict(
        list
    )
    # (platform, artifact, reason)
    artifact_fails: List[Tuple[str, str, str]] = []
    baseline_fails: List[Tuple[str, int, int, int, str]] = []

    total_scenarios = 0
    passed_scenarios = 0
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
        if results is not None or baseline is not None:
            any_artifact_found = True
        if results_err or baseline_err:
            any_artifact_found = True

        baseline_total += 1
        if baseline_err:
            artifact_fails.append((platform, "baseline.json", f"unreadable ({baseline_err})"))
        elif baseline is None:
            artifact_fails.append(
                (platform, "baseline.json", "missing (idle false-positive window never ran)")
            )
        else:
            baseline_present += 1
            if _baseline_is_dirty(baseline):
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

        dirty_baseline = _baseline_is_dirty(baseline)

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

            if status == "pass":
                # A scenario cannot pass without an alertable finding: the
                # gate mirrors production alerting, where only HIGH and
                # CRITICAL non-dismissed findings notify anyone. `alertable`
                # is None only for results produced before the harness
                # started recording it.
                if alertable is not None and alertable <= 0:
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
                if name in required:
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

        for name in required:
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
        return 2

    print("## Security release gate")
    print()

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

    if not scenario_fails and not baseline_fails and not artifact_fails:
        print(
            f"PASS - {total_scenarios} scenario result(s) across"
            f" {platforms_with_results} platform(s):"
            f" {passed_scenarios} passed with an alertable finding,"
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
        return 0

    print(
        f"FAIL - {len(scenario_fails)} CVE scenario(s),"
        f" {len(baseline_fails)} baseline(s) and"
        f" {len(artifact_fails)} missing/unreadable artifact(s) failed across"
        f" {baseline_total} platform(s). The release"
        " MUST be blocked or rolled back."
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

    return 1


if __name__ == "__main__":
    sys.exit(main())
