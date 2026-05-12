#!/usr/bin/env python3
"""Release-gate check for the performance suite.

Compares the current ``tests/perf`` results against a baseline directory with
the same layout (produced by an earlier run of the same workflow) and exits
non-zero if any (platform, scenario, metric) triple regressed by more than its
per-metric threshold.

GitHub-hosted Azure VMs share host CPU/IO with neighbour tenants, so the
variance profile of each metric is fundamentally different:

- ``*_avg`` metrics (``cpu_percent_avg``, ``rss_mb_avg``) integrate over
  the whole scenario window and are generally more stable than peaks, but
  capture-heavy windows can still exceed +/-100% across same-code consecutive
  runs when shared-runner CPU steal, packet-capture startup, and CloudModel
  refresh work land inside the same 5-minute sample.
- ``cpu_percent_max`` is a 1-second peak sample on a 4-core box and
  routinely swings between +50% and +200% across same-code runs because
  background scheduler steal hits unpredictably.
- ``rss_mb_max`` is a peak resident-set sample. It is less noisy than
  CPU peak, but it can still catch one-off child-process / first-touch
  startup spikes when the sampler walks the daemon and descendants. The
  gate therefore treats peak RSS as corroborating evidence: it blocks
  only when average RSS also regressed, or when the peak alone exceeds
  the much wider emergency threshold.

The thresholds below mirror this physics: avg metrics gate at +100%
(genuine regressions worth blocking double the steady-state load), peak
CPU at +200% (can spike on cross-tenant noise without any code change),
and peak RSS at +100% (memory peak should not double on a no-op release
candidate).

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


# (summary.json key, human label, absolute floor, fractional regression
# threshold multiplier). The threshold multiplier is applied on top of
# the global --threshold default (so a multiplier of 2.0 doubles the
# headroom for a metric known to be noisy).
METRICS: List[Tuple[str, str, float, float]] = [
    ("cpu_percent_avg", "CPU avg %", 1.0, 1.0),
    # cpu_percent_max is a 1-second peak sample dominated by neighbour
    # CPU steal on Azure-hosted shared runners; double the headroom.
    ("cpu_percent_max", "CPU max %", 5.0, 2.0),
    ("rss_mb_avg", "RSS avg MB", 10.0, 1.0),
    ("rss_mb_max", "RSS max MB", 10.0, 1.0),
]

# Per-scenario per-metric overrides. When a scenario's tracked metric is
# structurally noisy for that workload shape, we evaluate a different
# summary key instead. The label and threshold multiplier are taken from
# the original METRICS entry; only the underlying summary.json key is
# remapped.
#
# - hub_idle: replaces cpu_percent_max with cpu_percent_p95. hub_idle is
#   an idle daemon whose only CPU activity is sub-second PowerShell
#   threat-metric checks fired by compute_score_task every 300s. The
#   1Hz sampler aliases those bursts as 100-180% spikes; whether a given
#   run catches one, two, or zero of them inside the sampling window is
#   pure phase noise. cpu_percent_p95 cuts off the top 5% of samples,
#   which neutralises the burst-aliasing artifact while still catching
#   any genuine sustained CPU regression. (run_scenario.sh also bumps
#   hub_idle's duration to 360s so the window is no longer a multiple
#   of the 300s score-task period.)
SCENARIO_METRIC_OVERRIDES: Dict[str, Dict[str, str]] = {
    "hub_idle": {"cpu_percent_max": "cpu_percent_p95"},
}
"""List of (summary.json key, human label, absolute floor, threshold multiplier).

Metrics whose baseline value is strictly below the floor are not compared;
this avoids false positives on very small values (e.g. idle CPU percent).

The threshold multiplier scales the global ``--threshold`` for that metric:
  effective_threshold = global_threshold * metric_multiplier * scenario_multiplier
"""

# Peak RSS is useful for catching true memory blowups, but it is too brittle
# as a standalone release blocker. In the sampler used by the perf suite,
# `rss_mb_max` includes short-lived descendants of the daemon. A one-sample
# child-process peak can double `rss_mb_max` while `rss_mb_avg` remains flat.
#
# Gate policy:
#   - if RSS avg also exceeds its effective threshold, RSS max can fail normally
#   - otherwise RSS max only fails if it exceeds this emergency multiplier
#     (default +300%), which catches genuine memory explosions without blocking
#     on isolated one-sample startup/report/update spikes.
RSS_MAX_STANDALONE_MULTIPLIER = 3.0


# Per-scenario threshold multipliers. Some scenarios are intrinsically
# more variable than the steady-state ones because they involve work
# that does not converge inside the 5-minute sampling window:
#
# - ``capture``: packet capture startup on GitHub-hosted runners includes
#   pcap/eBPF initialization, first session analysis, resolver/cache warmup,
#   and CloudModel update/check work. On shared Azure-hosted ubuntu-x64
#   runners, same-code CPU avg can move a little over 2x at low absolute
#   values depending on host steal and network background traffic. A 2x
#   multiplier preserves a release block for a 3x+ capture regression while
#   avoiding repeated false blocks from runner noise.
#
# - ``all``: combines capture, LAN scan, hub reporting, and agentic setup in
#   one 5-minute window. It inherits the startup variance of the component
#   scenarios, so it gets the same moderate multiplier rather than forcing
#   every component to be perfectly phase-aligned with the previous baseline.
#
# - ``llm``: agentic mode with the EDAMAME LLM provider. The local LLM
#   model is downloaded/loaded lazily on first use, then runs inference
#   on captured traffic. Whether and when the model finishes loading
#   inside the 5-minute window depends on host disk speed, network
#   bandwidth and CPU steal. Empirically the same code can produce
#   570 MB / 48% CPU runs (model not yet warm) and 1.4 GB / 240%
#   CPU runs (model warm and inferring) on consecutive ubuntu-x64
#   runners. We still want this scenario in the report for visibility,
#   but a +100% regression gate cannot distinguish "released a slower
#   LLM" from "got a faster runner that warmed the model in time".
#   A 4x multiplier (effective +400%/+800% headroom) tolerates the
#   warm-vs-cold transition while still flagging a 5x+ regression
#   that would indicate a real problem.
#
# - ``lanscan``: discovery scenario that drives ARP/ICMP/mDNS/DNS
#   probes against the runner's RFC1918 subnet plus a 1020-entry
#   gateway candidate sweep. Several inputs whose cost we do not
#   control land in the 5-minute window:
#     * Upstream DNS / mDNS responsiveness (varies with neighbour
#       traffic on the shared Azure subnet).
#     * On-demand decode of `Lazy<String>` CloudModel embedded
#       fallbacks (OUI, vendor_vulns_db, port_vulns_db, ...) when
#       device classification first touches each DB; subsequent
#       reads are pointer loads but the first-touch decode shows
#       up in the avg if it lands inside the sampling window.
#     * Windows subprocess invocation cost (PowerShell-backed
#       lookups + Defender real-time scanning of the spawned
#       processes) which is unusually expensive on shared
#       windows-2022 runners.
#   Empirically this can swing the same code's `cpu_percent_avg`
#   from ~2.5% to ~5.5% on consecutive windows-x64 runs without any
#   real change. A 2x multiplier (effective +200%/+400% headroom)
#   absorbs this without masking a real 3x+ steady-state
#   regression.
SCENARIO_MULTIPLIERS: Dict[str, float] = {
    "all": 2.0,
    "capture": 2.0,
    "llm": 4.0,
    "lanscan": 2.0,
}

# Short rationale string per scenario, used to label the per-scenario
# multiplier in the gate's Markdown output. Keeping this separate from
# ``SCENARIO_MULTIPLIERS`` so that the table renders correctly even if
# someone adds a multiplier without updating the rationale (the table
# falls back to a generic note).
SCENARIO_MULTIPLIER_NOTES: Dict[str, str] = {
    "all": "combined capture/LAN/agentic startup variance on shared runners",
    "capture": "packet-capture startup and first-window CloudModel/network variance",
    "llm": "intrinsic variance from LLM model load/inference timing",
    "lanscan": "intrinsic variance from DNS/mDNS/Defender + on-demand CloudModel fallback decode",
}


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
        default=1.00,
        help="Fractional regression threshold. 1.00 => fail if current > 2.00 * baseline",
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
        f"Base threshold: current must not exceed baseline by more than"
        f" **{args.threshold * 100:+.0f}%** on any tracked metric."
    )
    print()
    print("| Metric | Effective threshold |")
    print("|---|---|")
    for _, label, _, mult in METRICS:
        eff = args.threshold * mult
        note = "" if mult == 1.0 else f" (x{mult:g} multiplier for runner-noise tolerance)"
        print(f"| {label} | +{eff * 100:.0f}%{note} |")
    print()
    if SCENARIO_MULTIPLIERS:
        print("| Scenario | Threshold multiplier |")
        print("|---|---|")
        for scen, mult in sorted(SCENARIO_MULTIPLIERS.items()):
            note = SCENARIO_MULTIPLIER_NOTES.get(scen, "intrinsic variance")
            print(f"| `{scen}` | x{mult:g} ({note}) |")
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

    regressions: List[Tuple[str, str, str, float, float, float, float, float]] = []
    comparisons = 0
    for plat, scen_map in sorted(cur.items()):
        for scen, cur_summary in sorted(scen_map.items()):
            base_summary = base.get(plat, {}).get(scen)
            if not base_summary:
                continue

            rss_avg_ratio: Optional[float] = None
            rss_avg_threshold: Optional[float] = None
            try:
                rss_avg_current = float(cur_summary.get("rss_mb_avg"))
                rss_avg_baseline = float(base_summary.get("rss_mb_avg"))
                if rss_avg_baseline >= 10.0:
                    scen_mult_for_rss = SCENARIO_MULTIPLIERS.get(scen, 1.0)
                    rss_avg_ratio = (rss_avg_current - rss_avg_baseline) / rss_avg_baseline
                    rss_avg_threshold = args.threshold * scen_mult_for_rss
            except Exception:
                rss_avg_ratio = None
                rss_avg_threshold = None

            for key, label, floor, mult in METRICS:
                # Per-scenario metric remap: e.g. hub_idle gates on
                # cpu_percent_p95 instead of cpu_percent_max because its CPU
                # profile is "steady-state idle plus periodic sub-second
                # bursts" that the 1Hz sampler aliases unpredictably.
                effective_key = SCENARIO_METRIC_OVERRIDES.get(scen, {}).get(key, key)
                effective_label = label
                if effective_key != key:
                    # Annotate the label so the gate's output makes the
                    # remap obvious to anyone reading the report.
                    effective_label = f"{label} (via {effective_key})"
                cv = cur_summary.get(effective_key)
                bv = base_summary.get(effective_key)
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
                scen_mult = SCENARIO_MULTIPLIERS.get(scen, 1.0)
                effective_threshold = args.threshold * mult * scen_mult
                # Use the local effective_label going forward so the report
                # reflects the remapped metric.
                label = effective_label
                if key == "rss_mb_max" and ratio > effective_threshold:
                    avg_also_regressed = (
                        rss_avg_ratio is not None
                        and rss_avg_threshold is not None
                        and rss_avg_ratio > rss_avg_threshold
                    )
                    emergency_threshold = (
                        args.threshold
                        * RSS_MAX_STANDALONE_MULTIPLIER
                        * scen_mult
                    )
                    if not avg_also_regressed and ratio <= emergency_threshold:
                        continue
                if ratio > effective_threshold:
                    regressions.append(
                        (plat, scen, label, bv, cv, ratio, floor, effective_threshold)
                    )

    if not regressions:
        print(
            f"PASS - compared {comparisons} metric(s) across"
            f" {sum(len(v) for v in cur.values())} (platform, scenario) tuples."
            " No regression exceeded the threshold."
        )
        return 0

    print(
        f"FAIL - {len(regressions)} metric(s) regressed beyond the"
        " per-metric threshold relative to the baseline run."
    )
    print()
    print("| Platform | Scenario | Metric | Baseline | Current | Change | Threshold | Absolute floor |")
    print("|---|---|---|---|---|---|---|---|")
    for plat, scen, label, bv, cv, ratio, floor, eff in regressions:
        print(
            f"| {plat} | {scen} | {label} |"
            f" {bv:,.2f} | {cv:,.2f} | {ratio * 100:+.1f}% |"
            f" +{eff * 100:.0f}% | {floor:g} |"
        )
    print()
    print(
        "This gate is enforced by the `perf` job in `.github/workflows/tests.yml`. Any regression"
        " here justifies blocking the release (or rolling it back) because it"
        " means `edamame_posture` consumes materially more CPU or memory than"
        " the previous green run."
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
