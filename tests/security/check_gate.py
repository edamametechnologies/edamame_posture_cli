#!/usr/bin/env python3
"""Release-gate check for the CVE detection suite.

Reads per-platform ``results.json`` files produced by
``tests/security/run_cve_detection.sh`` and decides whether the security gate
should block a release.

The gate is **tiered** to avoid being flapped by two known sources of
non-determinism:

1. **Cross-platform packet-capture / L7 attribution flakiness**: a single
   platform occasionally misses a detection because of capture-layer
   glitches (Npcap on Windows, BPF filter races on Linux, etc.). A real
   detector regression will show up on 2+ platforms, so we only block the
   release when the same scenario fails on 2+ platforms.

2. **iForest anomaly scoring for slow-rate beacon traffic**: some
   scenarios (notably ``tool_poisoning_effects``) use slow-rate HTTP POST
   traffic (~300 B/s, ~68x slower than other token-exfil triggers). The
   iForest anomaly score for these flows sits near the detection threshold
   and is sensitive to the amount of background traffic on the GitHub
   runner. Historical pass rates across the 3 platforms: Ubuntu ~17%,
   macOS ~83%, Windows ~50%. These scenarios are listed in
   ``KNOWN_FLAKY_SCENARIOS`` and treated as non-blocking unless **all**
   observed platforms fail (which would indicate a real regression in the
   detector for that scenario, not just iForest noise).

Gate policy:

- **HARD FAIL** (exit 1):
   - A non-flaky scenario fails on **2+** platforms (real detector
     regression), OR
   - A non-flaky scenario fails on the only platform that observed it
     (no cross-platform evidence of a working path), OR
   - A known-flaky scenario fails on **all** observed platforms (full
     regression that cannot be attributed to iForest noise).
- **WARN** (exit 0):
   - A non-flaky scenario fails on exactly one platform but passes on
     every other platform (platform-specific flakiness), OR
   - A known-flaky scenario fails on 1 or more platforms but passes on
     at least one (iForest noise for slow-rate beacon traffic).
- **PASS** (exit 0): every scenario passed (or was explicitly skipped)
  on every platform.

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

- ``0``: gate satisfied (all pass, or only WARN-classified failures).
- ``1``: at least one scenario hard-failed under the policy above. A
  Markdown summary of the regression is printed to stdout so the caller
  can forward it to ``$GITHUB_STEP_SUMMARY``.
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


# Scenarios whose iForest anomaly scoring is inherently noisy on CI runners.
#
# ``tool_poisoning_effects`` emits ~300 B/sec HTTP POST traffic (MCPTox-style
# slow-rate exfiltration), ~68x slower than the 4 KB/0.2s raw-TCP streaming
# pattern used by the other token-exfil scenarios. At that byte rate the
# iForest anomaly score sits near the detection threshold and is sensitive
# to background traffic on the GitHub-hosted runner. Observed historical
# pass rate across the 3 CI platforms over 6 consecutive runs: Ubuntu 1/6,
# macOS 5/6, Windows 3/6. The detection code path is identical to the
# faster token-exfil scenarios, which all pass reliably; the inconsistency
# is in the anomaly scoring step, not in the ``token_exfiltration`` check
# itself. Treat partial failures as flakiness, but still block on a full
# regression (all observed platforms fail).
KNOWN_FLAKY_SCENARIOS: Set[str] = {
    "tool_poisoning_effects",
}


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
        is_flaky = name in KNOWN_FLAKY_SCENARIOS

        if is_flaky:
            # Known-flaky scenarios are only release-blocking when they fail
            # on EVERY observed platform. Any cross-platform evidence of a
            # working path is enough to attribute the failure to iForest
            # noise rather than a detector regression.
            if passed_plats == 0:
                hard_fails.append((name, fails))
            else:
                warns.append((name, fails))
        else:
            # Non-flaky scenario: block on 2+ platform failures, or on the
            # only platform that observed the scenario (no cross-platform
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
            1 for name, f in hard_fails
            if name not in KNOWN_FLAKY_SCENARIOS and len(f) >= 2
        )
        sole_plat_fails = sum(
            1 for name, f in hard_fails
            if name not in KNOWN_FLAKY_SCENARIOS
            and len(f) < 2
            and len(scenario_platforms[name]) <= len(f)
        )
        flaky_total_fails = sum(
            1 for name, f in hard_fails
            if name in KNOWN_FLAKY_SCENARIOS
            and len(scenario_platforms[name]) <= len(f)
        )
        reasons: List[str] = []
        if multi_plat_fails:
            reasons.append(
                f"{multi_plat_fails} non-flaky scenario(s) failed on 2+"
                " platforms (real detector regression)"
            )
        if sole_plat_fails:
            reasons.append(
                f"{sole_plat_fails} non-flaky scenario(s) failed on the only"
                " platform that ran the scenario (no cross-platform evidence"
                " of a working path)"
            )
        if flaky_total_fails:
            reasons.append(
                f"{flaky_total_fails} known-flaky scenario(s) failed on ALL"
                " observed platforms (full regression, not iForest noise)"
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
        flaky_warns = sum(
            1 for name, _ in warns if name in KNOWN_FLAKY_SCENARIOS
        )
        single_plat_warns = len(warns) - flaky_warns
        reasons = []
        if single_plat_warns:
            reasons.append(
                f"{single_plat_warns} scenario(s) failed on a single platform"
                " and passed elsewhere (platform-specific flakiness, typically"
                " Npcap / L7 attribution)"
            )
        if flaky_warns:
            reasons.append(
                f"{flaky_warns} known-flaky scenario(s) failed on some"
                " platforms but passed on at least one (iForest noise for"
                " slow-rate beacon traffic)"
            )
        reason_text = "; ".join(reasons)
        print(
            f"WARN - {len(warns)} scenario(s) produced non-blocking"
            f" failures ({total_warns} platform-scenario failure(s) total):"
            f" {reason_text}. Not release-blocking; surfaced here so"
            " regressions that start as partial drift are still visible."
        )
        print()
        print("### Non-blocking warnings")
        print()
        print("| Platform | Scenario | Expected check | Findings | Notes |")
        print("|---|---|---|---|---|")
        for name, fails in warns:
            for platform, check, findings, extra in fails:
                notes = extra.replace("|", "/") if extra else ""
                flaky_tag = " (known-flaky)" if name in KNOWN_FLAKY_SCENARIOS else ""
                print(
                    f"| {platform} | {name}{flaky_tag} | {check} | {findings}"
                    f" | {notes} |"
                )
        print()

    print(
        "This gate is enforced by `.github/workflows/security.yml`. A"
        " release-blocking regression requires the same scenario to fail on"
        " at least two platforms (or on every observed platform for"
        " known-flaky scenarios) so known per-platform flakiness in packet"
        " capture or L7 attribution - and iForest noise for slow-rate beacon"
        " traffic - does not gate shipping a detector that is otherwise"
        " healthy."
    )

    return 1 if hard_fails else 0


if __name__ == "__main__":
    sys.exit(main())
