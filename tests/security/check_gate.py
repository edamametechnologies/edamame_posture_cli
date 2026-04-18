#!/usr/bin/env python3
"""Release-gate check for the CVE detection suite.

Reads per-platform ``results.json`` files produced by
``tests/security/run_cve_detection.sh`` and exits non-zero if any scenario on
any platform reported ``status == "fail"``. A scenario with ``status == "skip"``
is not treated as a failure (the underlying trigger was intentionally not
executed on that platform).

Input layout::

    <results-dir>/
      <platform-a>/
        results.json
      <platform-b>/
        results.json

``results.json`` is the output of ``run_cve_detection.sh`` and always contains
``scenarios[i].{scenario, status, expected_check, finding_total, extra}`` plus
``totals.{passed, failed, skipped, total}``.

Exit codes:

- ``0``: every scenario on every platform passed (or was explicitly skipped).
- ``1``: at least one scenario failed. A Markdown summary of failing
  ``(platform, scenario)`` pairs is printed to stdout so the caller can forward
  it to ``$GITHUB_STEP_SUMMARY``.
- ``2``: the results directory is empty or unreadable.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import sys
from typing import List, Tuple


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

    failing: List[Tuple[str, str, str, int, str]] = []
    total_scenarios = 0
    for platform, data in platforms:
        for scen in data.get("scenarios", []):
            if not isinstance(scen, dict):
                continue
            total_scenarios += 1
            if scen.get("status") != "fail":
                continue
            failing.append(
                (
                    platform,
                    str(scen.get("scenario", "")),
                    str(scen.get("expected_check", "")),
                    int(scen.get("finding_total", 0) or 0),
                    str(scen.get("extra", "") or ""),
                )
            )

    print("## Security release gate")
    print()
    if not failing:
        print(
            f"PASS - {total_scenarios} scenarios across {len(platforms)} platforms"
            " reported status=pass or status=skip."
        )
        return 0

    print(
        f"FAIL - {len(failing)} scenario failure(s) across {len(platforms)} platforms."
        " Every CVE scenario must produce at least one detection to satisfy the"
        " release gate."
    )
    print()
    print("| Platform | Scenario | Expected check | Findings | Notes |")
    print("|---|---|---|---|---|")
    for platform, scenario, check, findings, extra in failing:
        notes = extra.replace("|", "/") if extra else ""
        print(f"| {platform} | {scenario} | {check} | {findings} | {notes} |")
    print()
    print(
        "This gate is enforced by `.github/workflows/security.yml`. Any regression"
        " here justifies blocking the release (or rolling it back) because it"
        " means the vulnerability detector no longer catches a published"
        " attack scenario."
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
