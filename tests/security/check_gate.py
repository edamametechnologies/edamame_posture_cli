#!/usr/bin/env python3
"""Release-gate check for the CVE detection suite.

Reads per-platform ``results.json`` files produced by
``tests/security/run_cve_detection.sh`` and per-platform ``baseline.json``
files produced by ``tests/security/run_false_positive_baseline.sh`` and
decides whether the security gate should block a release.

The gate is **strict**: any scenario that reports ``status=fail`` on any
observed platform, OR any platform whose 10-minute idle baseline surfaced
one or more vulnerability findings, hard-fails the gate and blocks the
release. There is no per-platform tolerance and no flaky-scenario
carve-out. Adversarial / iForest-dependent evasion scenarios live in
``edamame_core/tests/evasion`` so their probabilistic detection path does
not gate releases here.

Gate policy:

- **HARD FAIL** (exit 1):
  * at least one scenario reports ``status=fail`` on at least one
    platform, OR
  * at least one platform reports a dirty idle baseline (``baseline.json``
    with ``status=fail`` or ``finding_total > 0``).
  The matrix of failures is printed to stdout so the caller can forward
  it to ``$GITHUB_STEP_SUMMARY`` and trigger a rollback.
- **PASS** (exit 0): every scenario on every platform reports
  ``status=pass`` or ``status=skip`` AND every platform's idle baseline
  was clean (or absent, if this was a legacy run with no baseline).

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
extra}`` plus ``totals.{passed, failed, skipped, total}``.

``baseline.json`` is the output of ``run_false_positive_baseline.sh`` and
contains ``status`` (``"pass"`` | ``"fail"``), ``finding_total``,
``finding_current``, ``finding_history`` and ``first_finding_sample``.

Exit codes:

- ``0``: gate satisfied (all pass or skip, all baselines clean).
- ``1``: at least one scenario hard-failed or at least one platform
  had a dirty baseline. A Markdown summary of the failures is printed
  to stdout.
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


def _load_results(results_dir: str) -> List[Tuple[str, dict]]:
    platforms: List[Tuple[str, dict]] = []
    for path in sorted(glob.glob(os.path.join(results_dir, "*"))):
        if not os.path.isdir(path):
            continue
        rj = os.path.join(path, "results.json")
        if not os.path.isfile(rj):
            continue
        try:
            with open(rj, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except Exception as exc:
            print(f"[gate] WARN: could not read {rj}: {exc}", file=sys.stderr)
            continue
        platforms.append((os.path.basename(path), data))
    return platforms


def _load_baselines(results_dir: str) -> List[Tuple[str, Optional[dict]]]:
    """Load each platform's ``baseline.json`` if present.

    Returns a list of ``(platform, data_or_None)`` tuples for every
    platform directory, including ones that do not (yet) carry a baseline
    artifact. The caller decides whether missing baselines are fatal; by
    default we treat them as informational because older release bundles
    predate the false-positive harness.
    """
    entries: List[Tuple[str, Optional[dict]]] = []
    for path in sorted(glob.glob(os.path.join(results_dir, "*"))):
        if not os.path.isdir(path):
            continue
        platform = os.path.basename(path)
        bj = os.path.join(path, "baseline.json")
        if not os.path.isfile(bj):
            entries.append((platform, None))
            continue
        try:
            with open(bj, "r", encoding="utf-8") as fh:
                entries.append((platform, json.load(fh)))
        except Exception as exc:
            print(f"[gate] WARN: could not read {bj}: {exc}", file=sys.stderr)
            entries.append((platform, None))
    return entries


def _baseline_is_dirty(data: Optional[dict]) -> bool:
    if not isinstance(data, dict):
        return False
    if str(data.get("status", "")).lower() == "fail":
        return True
    try:
        return int(data.get("finding_total") or 0) > 0
    except (TypeError, ValueError):
        return False


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--results-dir",
        required=True,
        help="Directory containing per-platform subdirectories with results.json files",
    )
    args = ap.parse_args()

    platforms = _load_results(args.results_dir)
    baselines = _load_baselines(args.results_dir)
    if not platforms and not baselines:
        print(
            f"[gate] ERROR: no results.json or baseline.json files found"
            f" under {args.results_dir}",
            file=sys.stderr,
        )
        return 2

    scenario_fails: Dict[str, List[Tuple[str, str, int, str]]] = defaultdict(list)
    total_scenarios = 0
    passed_scenarios = 0
    skipped_scenarios = 0

    for platform, data in platforms:
        for scen in data.get("scenarios", []):
            if not isinstance(scen, dict):
                continue
            total_scenarios += 1
            name = str(scen.get("scenario", ""))
            status = scen.get("status")
            check = str(scen.get("expected_check", ""))
            if status == "pass":
                passed_scenarios += 1
            elif status == "skip":
                skipped_scenarios += 1
            elif status == "fail":
                scenario_fails[name].append(
                    (
                        platform,
                        check,
                        int(scen.get("finding_total", 0) or 0),
                        str(scen.get("extra", "") or ""),
                    )
                )

    baseline_fails: List[Tuple[str, int, int, int, str]] = []
    baseline_total = 0
    baseline_present = 0
    baseline_clean = 0
    for platform, baseline in baselines:
        baseline_total += 1
        if baseline is None:
            continue
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

    print("## Security release gate")
    print()

    print("### Idle baseline (no-stimulus window)")
    print()
    if baseline_present == 0:
        print(
            "_No `baseline.json` found on any platform -- legacy run, skipping"
            " the false-positive check._"
        )
        print()
    elif not baseline_fails:
        print(
            f"CLEAN - {baseline_clean}/{baseline_total} platforms observed"
            " zero vulnerability findings during the 10-minute idle window."
        )
        print()
    else:
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

    if not scenario_fails and not baseline_fails:
        print(
            f"PASS - {total_scenarios} scenario result(s) across"
            f" {len(platforms)} platform(s) reported status=pass"
            f" ({passed_scenarios}) or status=skip ({skipped_scenarios}),"
            f" and {baseline_clean}/{baseline_total} platform(s) had a"
            " clean idle baseline."
        )
        return 0

    print(
        f"FAIL - {len(scenario_fails)} CVE scenario(s) and"
        f" {len(baseline_fails)} baseline(s) failed across"
        f" {max(len(platforms), baseline_total)} platform(s). The release"
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
        print("| Platform | Scenario | Expected check | Findings | Notes |")
        print("|---|---|---|---|---|")
        for name, fails in sorted(scenario_fails.items()):
            for platform, check, findings, extra in fails:
                notes = extra.replace("|", "/") if extra else ""
                print(f"| {platform} | {name} | {check} | {findings} | {notes} |")
        print()

    print(
        "This gate is enforced by the `security` job in `.github/workflows/tests.yml`. It"
        " requires every scenario on every platform to produce a"
        " deterministic detection AND a clean 10-minute idle baseline"
        " before the CVE suite. Scenarios whose detection path is"
        " probabilistic (iForest anomaly scoring on slow-rate traffic,"
        " timing-sensitive attribution races) are tracked as adversarial"
        " evasion scenarios under `edamame_core/tests/evasion/` instead of"
        " in this CVE suite."
    )

    return 1


if __name__ == "__main__":
    sys.exit(main())
