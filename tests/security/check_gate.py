#!/usr/bin/env python3
"""Release-gate check for the CVE detection suite.

Reads per-platform ``results.json`` files produced by
``tests/security/run_cve_detection.sh`` and decides whether the security gate
should block a release.

The gate is **tiered** to avoid being flapped by known single-platform
flakiness in packet capture / L7 attribution (notably Npcap on Windows,
whose ``tool_poisoning_effects`` detection is ~2/5 reliable under slow-rate
HTTP POST traffic on GitHub-hosted runners). A detector regression that
affects the actual detection logic will show up on more than one platform;
a transient capture glitch will not.

Gate policy:

- **HARD FAIL** (exit 1): a scenario reports ``status == "fail"`` on **two or
  more** platforms. This indicates the vulnerability detector (or a shared
  code path) no longer catches a published attack scenario, and the release
  must be blocked or rolled back.
- **WARN** (exit 0): a scenario reports ``status == "fail"`` on exactly one
  platform but passes on every other platform. Treated as platform-specific
  flakiness. Logged in the Markdown summary so it still shows up in the run
  UI / Slack alert, but does not block the release.
- **PASS** (exit 0): every scenario passed (or was explicitly skipped) on
  every platform.

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

- ``0``: gate satisfied (all pass, or only single-platform WARN).
- ``1``: at least one scenario failed on 2+ platforms. A Markdown summary
  of the regression is printed to stdout so the caller can forward it to
  ``$GITHUB_STEP_SUMMARY``.
- ``2``: the results directory is empty or unreadable.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import sys
from collections import defaultdict
from typing import Dict, List, Set, Tuple


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

    # Build per-scenario view across platforms.
    scenario_platforms: Dict[str, Set[str]] = defaultdict(set)
    scenario_fails: Dict[str, List[Tuple[str, str, int, str]]] = defaultdict(list)
    scenario_check: Dict[str, str] = {}
    total_scenarios = 0

    for platform, data in platforms:
        for scen in data.get("scenarios", []):
            if not isinstance(scen, dict):
                continue
            total_scenarios += 1
            name = str(scen.get("scenario", ""))
            status = scen.get("status")
            check = str(scen.get("expected_check", ""))
            if check:
                scenario_check[name] = check
            if status == "skip":
                continue
            scenario_platforms[name].add(platform)
            if status == "fail":
                scenario_fails[name].append(
                    (
                        platform,
                        check,
                        int(scen.get("finding_total", 0) or 0),
                        str(scen.get("extra", "") or ""),
                    )
                )

    # Classify each failing scenario.
    hard_fails: List[Tuple[str, List[Tuple[str, str, int, str]]]] = []
    warns: List[Tuple[str, List[Tuple[str, str, int, str]]]] = []
    for name, fails in scenario_fails.items():
        observed = len(scenario_platforms[name])
        failed_plats = len(fails)
        passed_plats = observed - failed_plats
        # A scenario is a hard fail if it fails on 2+ platforms, OR if it
        # fails on the only platform that observed it (no cross-platform
        # evidence that detection works elsewhere).
        if failed_plats >= 2 or passed_plats == 0:
            hard_fails.append((name, fails))
        else:
            warns.append((name, fails))

    print("## Security release gate")
    print()

    if not hard_fails and not warns:
        print(
            f"PASS - {total_scenarios} scenario result(s) across"
            f" {len(platforms)} platforms reported status=pass or status=skip."
        )
        return 0

    if hard_fails:
        total_fails = sum(len(f) for _, f in hard_fails)
        multi_plat_fails = sum(
            1 for name, f in hard_fails if len(f) >= 2
        )
        sole_plat_fails = sum(
            1 for name, f in hard_fails
            if len(f) < 2 and len(scenario_platforms[name]) <= len(f)
        )
        reasons: List[str] = []
        if multi_plat_fails:
            reasons.append(
                f"{multi_plat_fails} failed on 2+ platforms (real detector"
                " regression)"
            )
        if sole_plat_fails:
            reasons.append(
                f"{sole_plat_fails} failed on the only platform that ran the"
                " scenario (no cross-platform evidence of a working path)"
            )
        reason_text = "; ".join(reasons)
        print(
            f"FAIL - {len(hard_fails)} scenario(s) hard-failed across"
            f" {len(platforms)} platforms ({total_fails} platform-scenario"
            f" failure(s) total): {reason_text}. The release MUST be blocked"
            " or rolled back."
        )
        print()
        print("### Hard failures (release-blocking)")
        print()
        print("| Platform | Scenario | Expected check | Findings | Notes |")
        print("|---|---|---|---|---|")
        for name, fails in hard_fails:
            for platform, check, findings, extra in fails:
                notes = extra.replace("|", "/") if extra else ""
                print(f"| {platform} | {name} | {check} | {findings} | {notes} |")
        print()

    if warns:
        total_warns = sum(len(f) for _, f in warns)
        print(
            f"WARN - {len(warns)} scenario(s) failed on a single platform but"
            f" passed on every other platform ({total_warns} platform-scenario"
            " failure(s) total). Treated as platform-specific flakiness"
            " (typically Npcap / L7 attribution on Windows for slow-rate HTTP"
            " scenarios). Not release-blocking; surfaced here so regressions"
            " that start as single-platform drift are still visible."
        )
        print()
        print("### Single-platform warnings (non-blocking)")
        print()
        print("| Platform | Scenario | Expected check | Findings | Notes |")
        print("|---|---|---|---|---|")
        for name, fails in warns:
            for platform, check, findings, extra in fails:
                notes = extra.replace("|", "/") if extra else ""
                print(f"| {platform} | {name} | {check} | {findings} | {notes} |")
        print()

    print(
        "This gate is enforced by `.github/workflows/security.yml`. A"
        " release-blocking regression requires the same scenario to fail on"
        " at least two platforms so known per-platform flakiness in packet"
        " capture or L7 attribution does not gate shipping a detector that"
        " is otherwise healthy."
    )

    return 1 if hard_fails else 0


if __name__ == "__main__":
    sys.exit(main())
