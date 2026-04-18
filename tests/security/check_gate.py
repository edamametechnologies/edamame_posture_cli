#!/usr/bin/env python3
"""Release-gate check for the CVE detection suite.

Reads per-platform ``results.json`` files produced by
``tests/security/run_cve_detection.sh`` and decides whether the security gate
should block a release.

The gate is **strict**: any scenario that reports ``status=fail`` on any
observed platform hard-fails the gate and blocks the release. There is no
per-platform tolerance and no flaky-scenario carve-out. Adversarial /
iForest-dependent evasion scenarios live in ``edamame_core/tests/evasion``
so their probabilistic detection path does not gate releases here.

Gate policy:

- **HARD FAIL** (exit 1): at least one scenario reports ``status=fail`` on
  at least one platform. The matrix of failures is printed to stdout so
  the caller can forward it to ``$GITHUB_STEP_SUMMARY`` and trigger a
  rollback.
- **PASS** (exit 0): every scenario on every platform reports
  ``status=pass`` or ``status=skip``.

Input layout::

    <results-dir>/
      <platform-a>/
        results.json
      <platform-b>/
        results.json

``results.json`` is the output of ``run_cve_detection.sh`` and always
contains ``scenarios[i].{scenario, status, expected_check, finding_total,
extra}`` plus ``totals.{passed, failed, skipped, total}``.

Exit codes:

- ``0``: gate satisfied (all pass or skip).
- ``1``: at least one scenario hard-failed. A Markdown summary of the
  failures is printed to stdout.
- ``2``: the results directory is empty or unreadable.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import sys
from collections import defaultdict
from typing import Dict, List, Tuple


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


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--results-dir",
        required=True,
        help="Directory containing per-platform subdirectories with results.json files",
    )
    args = ap.parse_args()

    platforms = _load_results(args.results_dir)
    if not platforms:
        print(
            f"[gate] ERROR: no results.json files found under {args.results_dir}",
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

    print("## Security release gate")
    print()

    if not scenario_fails:
        print(
            f"PASS - {total_scenarios} scenario result(s) across"
            f" {len(platforms)} platforms reported status=pass"
            f" ({passed_scenarios}) or status=skip ({skipped_scenarios})."
        )
        return 0

    total_fails = sum(len(f) for f in scenario_fails.values())
    print(
        f"FAIL - {len(scenario_fails)} scenario(s) failed across"
        f" {len(platforms)} platforms ({total_fails} platform-scenario"
        " failure(s) total). The release MUST be blocked or rolled back."
    )
    print()
    print("### Failures (release-blocking)")
    print()
    print("| Platform | Scenario | Expected check | Findings | Notes |")
    print("|---|---|---|---|---|")
    for name, fails in sorted(scenario_fails.items()):
        for platform, check, findings, extra in fails:
            notes = extra.replace("|", "/") if extra else ""
            print(f"| {platform} | {name} | {check} | {findings} | {notes} |")
    print()

    print(
        "This gate is enforced by `.github/workflows/security.yml`. It"
        " requires every scenario on every platform to produce a"
        " deterministic detection. Scenarios whose detection path is"
        " probabilistic (iForest anomaly scoring on slow-rate traffic,"
        " timing-sensitive attribution races) are tracked as adversarial"
        " evasion scenarios under `edamame_core/tests/evasion/` instead of"
        " in this CVE suite."
    )

    return 1


if __name__ == "__main__":
    sys.exit(main())
