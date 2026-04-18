#!/usr/bin/env python3
"""Release-gate check for the performance suite.

Compares the current ``tests/perf`` results against a baseline directory with
the same layout (produced by an earlier run of the same workflow) and exits
non-zero if any (platform, scenario, metric) triple regressed by more than the
configured threshold (default: +50%).

Input layout for both ``--current`` and ``--baseline``::

    <dir>/
      <platform-label>/
        calibration.json
        <scenario>/
          summary.json

We only compare per-scenario ``summary.json`` values. Metrics not present in
either side are silently skipped; platform/scenario combinations that do not
appear on both sides are skipped too (with a warning).

Metrics compared (from ``summary.json``):

- ``cpu_percent_avg``
- ``cpu_percent_max``
- ``rss_mb_avg``
- ``rss_mb_max``

The tool also applies a small absolute floor to the baseline value to avoid
flagging huge relative increases on metrics that are effectively noise (e.g. an
idle-CPU baseline of 0.03% -> 1.2% is nominally +3,900%, but both values are
noise).

Exit codes:

- ``0``: no regression (or baseline was missing / empty; the gate is a
  soft no-op on first runs, but still reports what it did).
- ``1``: at least one regression exceeded the threshold. A Markdown
  summary is printed to stdout so it can be forwarded to
  ``$GITHUB_STEP_SUMMARY``.
- ``2``: the current results directory is empty / unreadable.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import sys
from typing import Dict, List, Optional, Tuple


METRICS: List[Tuple[str, str, float]] = [
    ("cpu_percent_avg", "CPU avg %", 1.0),
    ("cpu_percent_max", "CPU max %", 5.0),
    ("rss_mb_avg", "RSS avg MB", 10.0),
    ("rss_mb_max", "RSS max MB", 10.0),
]
"""List of (summary.json key, human label, absolute floor).

Metrics whose baseline value is strictly below the floor are not compared;
this avoids false positives on very small values (e.g. idle CPU percent).
"""


def _load_summary(path: str) -> Optional[dict]:
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception as exc:
        print(f"[gate] WARN: could not read {path}: {exc}", file=sys.stderr)
        return None


def _discover(root: str) -> Dict[str, Dict[str, dict]]:
    out: Dict[str, Dict[str, dict]] = {}
    for plat_dir in sorted(glob.glob(os.path.join(root, "*"))):
        if not os.path.isdir(plat_dir):
            continue
        plat = os.path.basename(plat_dir)
        out[plat] = {}
        for scen_dir in sorted(glob.glob(os.path.join(plat_dir, "*"))):
            if not os.path.isdir(scen_dir):
                continue
            scen = os.path.basename(scen_dir)
            summary = _load_summary(os.path.join(scen_dir, "summary.json"))
            if summary is None:
                continue
            out[plat][scen] = summary
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--current", required=True, help="Current results directory")
    ap.add_argument(
        "--baseline",
        required=True,
        help="Baseline results directory (may be missing on first run)",
    )
    ap.add_argument(
        "--threshold",
        type=float,
        default=0.50,
        help="Fractional regression threshold. 0.50 => fail if current > 1.50 * baseline",
    )
    args = ap.parse_args()

    cur = _discover(args.current)
    if not cur:
        print(
            f"[gate] ERROR: no platform/scenario data under {args.current}",
            file=sys.stderr,
        )
        return 2

    print("## Performance release gate")
    print()
    print(
        f"Threshold: current must not exceed baseline by more than"
        f" **{args.threshold * 100:+.0f}%** on any tracked metric."
    )
    print()

    if not os.path.isdir(args.baseline):
        print(
            f"_No baseline available at `{args.baseline}` - first run, accepting"
            " current results as the new baseline._"
        )
        return 0

    base = _discover(args.baseline)
    if not base:
        print(
            f"_Baseline directory `{args.baseline}` contained no summaries -"
            " accepting current results as the new baseline._"
        )
        return 0

    regressions: List[Tuple[str, str, str, float, float, float, float]] = []
    comparisons = 0
    for plat, scen_map in sorted(cur.items()):
        for scen, cur_summary in sorted(scen_map.items()):
            base_summary = base.get(plat, {}).get(scen)
            if not base_summary:
                continue
            for key, label, floor in METRICS:
                cv = cur_summary.get(key)
                bv = base_summary.get(key)
                if cv is None or bv is None:
                    continue
                try:
                    cv = float(cv)
                    bv = float(bv)
                except Exception:
                    continue
                if bv < floor:
                    continue
                comparisons += 1
                ratio = (cv - bv) / bv
                if ratio > args.threshold:
                    regressions.append((plat, scen, label, bv, cv, ratio, floor))

    if not regressions:
        print(
            f"PASS - compared {comparisons} metric(s) across"
            f" {sum(len(v) for v in cur.values())} (platform, scenario) tuples."
            " No regression exceeded the threshold."
        )
        return 0

    print(
        f"FAIL - {len(regressions)} metric(s) regressed by more than"
        f" {args.threshold * 100:+.0f}% relative to the baseline run."
    )
    print()
    print("| Platform | Scenario | Metric | Baseline | Current | Change | Absolute floor |")
    print("|---|---|---|---|---|---|---|")
    for plat, scen, label, bv, cv, ratio, floor in regressions:
        print(
            f"| {plat} | {scen} | {label} |"
            f" {bv:,.2f} | {cv:,.2f} | {ratio * 100:+.1f}% | {floor:g} |"
        )
    print()
    print(
        "This gate is enforced by `.github/workflows/perf.yml`. Any regression"
        " here justifies blocking the release (or rolling it back) because it"
        " means `edamame_posture` consumes materially more CPU or memory than"
        " the previous green run."
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
