#!/usr/bin/env python3
"""Aggregate per-scenario summaries into a Markdown performance report.

The input directory layout is:

    results/
      <platform>/
        calibration.json
        <scenario>/
          summary.json
          scenario.json

Where `<platform>` is a short label like `ubuntu-24.04-x64` and `<scenario>`
is one of idle, hub_idle, capture, lanscan, llm, all.

The script renders a single Markdown document and writes it to the output path.
It reports three CPU views to sidestep runner-to-runner CPU heterogeneity:

1. Raw CPU %: unnormalized psutil output (100% == one full core).
2. Load-normalized CPU: raw CPU divided by logical core count, expressed as
   percent of the machine. This isolates "how busy did this machine get".
3. Work-normalized CPU: raw CPU divided by the platform's composite work score
   (from calibration.json) relative to the chosen baseline platform, so that
   a slower CPU reporting 10% counts more than a faster CPU reporting 10%.
"""

from __future__ import annotations

import argparse
import datetime
import glob
import json
import os
import pathlib
import sys
from typing import Dict, List, Optional, Tuple


SCENARIO_ORDER = ["idle", "hub_idle", "capture", "lanscan", "llm", "all"]
SCENARIO_LABELS = {
    "idle": "Disconnected idle",
    "hub_idle": "Hub-connected idle",
    "capture": "Packet capture",
    "lanscan": "LAN scan",
    "llm": "LLM processing (capture + agentic)",
    "all": "All features",
}


def _load_json(path: str) -> Optional[dict]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return None


def _fmt_int(v) -> str:
    try:
        return f"{int(round(float(v))):,}"
    except Exception:
        return "-"


def _fmt_float(v, digits: int = 2) -> str:
    try:
        if v is None:
            return "-"
        return f"{float(v):.{digits}f}"
    except Exception:
        return "-"


def _load_platform(
    platform_dir: str,
) -> Tuple[str, Optional[dict], Dict[str, Tuple[Optional[dict], Optional[dict]]]]:
    label = os.path.basename(os.path.normpath(platform_dir))
    calibration = _load_json(os.path.join(platform_dir, "calibration.json"))
    scenarios: Dict[str, Tuple[Optional[dict], Optional[dict]]] = {}
    for scen in SCENARIO_ORDER:
        scen_dir = os.path.join(platform_dir, scen)
        if not os.path.isdir(scen_dir):
            continue
        summary = _load_json(os.path.join(scen_dir, "summary.json"))
        meta = _load_json(os.path.join(scen_dir, "scenario.json"))
        scenarios[scen] = (summary, meta)
    return label, calibration, scenarios


def _pick_baseline(platforms: List[str], calibrations: Dict[str, Optional[dict]]) -> str:
    prefs = [
        "ubuntu-24.04",
        "ubuntu-22.04",
        "ubuntu-latest",
        "ubuntu",
        "linux",
    ]
    for p in prefs:
        for plat in platforms:
            if p in plat and calibrations.get(plat):
                return plat
    for plat in platforms:
        if calibrations.get(plat):
            return plat
    return platforms[0] if platforms else ""


def _platform_banner(label: str, calibration: Optional[dict]) -> str:
    if calibration is None:
        return f"### {label}\n\n_No calibration data available._\n"
    parts: List[str] = [f"### {label}", ""]
    parts.append(f"- CPU model: `{calibration.get('cpu_model', 'unknown')}`")
    parts.append(
        f"- Logical cores: {_fmt_int(calibration.get('ncpu_logical'))},"
        f" physical cores: {_fmt_int(calibration.get('ncpu_physical'))}"
    )
    parts.append(
        f"- Total RAM: {_fmt_int(calibration.get('total_ram_mb'))} MB"
        f" ({_fmt_int(calibration.get('total_ram_bytes'))} bytes)"
    )
    parts.append(
        f"- OS: {calibration.get('platform_system')} {calibration.get('platform_release')}"
        f" ({calibration.get('platform_machine')})"
    )
    parts.append(
        f"- SHA-256: {_fmt_int(calibration.get('sha256_hps'))} hashes/sec of 16 MB"
    )
    parts.append(
        f"- BLAKE3: {_fmt_int(calibration.get('blake3_hps'))} hashes/sec of 16 MB"
    )
    if not calibration.get("blake3_available", True):
        parts.append(f"  _{calibration.get('blake3_note', 'blake3 fallback in use')}_")
    parts.append(
        f"- Composite work score (geometric mean): {_fmt_int(calibration.get('composite_score'))} hashes/sec"
    )
    parts.append("")
    return "\n".join(parts)


def _scenario_row(
    scenario: str,
    summary: Optional[dict],
    meta: Optional[dict],
    ncpu_logical: float,
    normalization_factor: float,
) -> List[str]:
    label = SCENARIO_LABELS.get(scenario, scenario)
    cells = [label]
    if summary is None:
        cells += ["-"] * 10
        return cells
    cpu_avg = summary.get("cpu_percent_avg", 0.0) or 0.0
    cpu_max = summary.get("cpu_percent_max", 0.0) or 0.0
    rss_avg = summary.get("rss_mb_avg", 0.0) or 0.0
    rss_max = summary.get("rss_mb_max", 0.0) or 0.0
    vms_avg = summary.get("vms_mb_avg", 0.0) or 0.0
    threads_avg = summary.get("threads_avg", 0.0) or 0.0
    fds_avg = summary.get("fds_avg", 0.0) or 0.0

    ncpu_logical = max(1.0, float(ncpu_logical or 1))
    load_norm_avg = cpu_avg / ncpu_logical
    load_norm_max = cpu_max / ncpu_logical
    work_norm_avg = cpu_avg * max(0.0, float(normalization_factor))

    fallback_notes: List[str] = []
    if meta:
        if meta.get("fallback_disconnected"):
            fallback_notes.append("disconnected")
        if meta.get("fallback_no_llm"):
            fallback_notes.append("no-llm")
    suffix = f" <sub>({'; '.join(fallback_notes)})</sub>" if fallback_notes else ""

    cells = [
        label + suffix,
        f"{_fmt_float(cpu_avg)}",
        f"{_fmt_float(cpu_max)}",
        f"{_fmt_float(load_norm_avg)}",
        f"{_fmt_float(load_norm_max)}",
        f"{_fmt_float(work_norm_avg)}",
        f"{_fmt_float(rss_avg, 1)}",
        f"{_fmt_float(rss_max, 1)}",
        f"{_fmt_float(vms_avg, 0)}",
        f"{_fmt_float(threads_avg, 0)}",
        f"{_fmt_float(fds_avg, 0)}",
    ]
    return cells


def _scenario_table(
    platform_label: str,
    calibration: Optional[dict],
    scenarios: Dict[str, Tuple[Optional[dict], Optional[dict]]],
    normalization_factor: float,
) -> str:
    if not scenarios:
        return f"_No scenario data recorded for {platform_label}._\n"
    ncpu_logical = float((calibration or {}).get("ncpu_logical") or 1)
    header = (
        "| Scenario | CPU avg % | CPU max % | "
        "Load avg % | Load max % | Work-norm avg | "
        "RSS avg MB | RSS max MB | VMS avg MB | Threads avg | FDs avg |"
    )
    sep = "|" + "|".join(["---"] * 11) + "|"
    rows: List[str] = [header, sep]
    for scen in SCENARIO_ORDER:
        if scen not in scenarios:
            continue
        summary, meta = scenarios[scen]
        cells = _scenario_row(scen, summary, meta, ncpu_logical, normalization_factor)
        rows.append("| " + " | ".join(cells) + " |")
    return "\n".join(rows) + "\n"


def _metadata_block(platforms: List[str], calibrations: Dict[str, Optional[dict]]) -> str:
    parts: List[str] = []
    for plat in platforms:
        cal = calibrations.get(plat)
        if not cal:
            continue
        parts.append(
            f"- `{plat}`: composite={_fmt_int(cal.get('composite_score'))}"
            f" SHA-256={_fmt_int(cal.get('sha256_hps'))}"
            f" BLAKE3={_fmt_int(cal.get('blake3_hps'))}"
            f" cores={_fmt_int(cal.get('ncpu_logical'))}"
            f" ram={_fmt_int(cal.get('total_ram_mb'))} MB"
        )
    return "\n".join(parts)


def _discover_platforms(results_root: str) -> List[str]:
    entries = sorted(
        glob.glob(os.path.join(results_root, "*"))
    )
    return [p for p in entries if os.path.isdir(p)]


def _meta_summary_for_scenarios(
    scenarios: Dict[str, Tuple[Optional[dict], Optional[dict]]],
) -> str:
    lines: List[str] = []
    for scen in SCENARIO_ORDER:
        if scen not in scenarios:
            continue
        _, meta = scenarios[scen]
        if not meta:
            continue
        flags = []
        if meta.get("enable_capture"):
            flags.append("capture")
        if meta.get("enable_lanscan"):
            flags.append("lanscan")
        if meta.get("enable_agentic"):
            flags.append("agentic")
        if meta.get("want_hub"):
            flags.append("hub")
        lines.append(
            f"  - `{scen}`: core {meta.get('core_version', 'unknown')},"
            f" flags: {', '.join(flags) if flags else 'none'};"
            f" start_args: `{meta.get('start_args', '')}`"
        )
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--results-dir", required=True, help="Root directory containing one subdir per platform")
    ap.add_argument("--output", required=True, help="Path to write the Markdown report")
    ap.add_argument(
        "--baseline",
        default="",
        help="Platform label to use as CPU baseline (default: first Ubuntu, then first platform with calibration)",
    )
    args = ap.parse_args()

    platform_dirs = _discover_platforms(args.results_dir)
    if not platform_dirs:
        print(f"error: no platform subdirectories in {args.results_dir}", file=sys.stderr)
        return 2

    loaded: Dict[str, Tuple[Optional[dict], Dict[str, Tuple[Optional[dict], Optional[dict]]]]] = {}
    calibrations: Dict[str, Optional[dict]] = {}
    platforms: List[str] = []
    for d in platform_dirs:
        label, cal, scen = _load_platform(d)
        loaded[label] = (cal, scen)
        calibrations[label] = cal
        platforms.append(label)

    baseline = args.baseline or _pick_baseline(platforms, calibrations)
    baseline_cal = calibrations.get(baseline)
    baseline_score = 0.0
    if baseline_cal:
        try:
            baseline_score = float(baseline_cal.get("composite_score") or 0.0)
        except Exception:
            baseline_score = 0.0

    lines: List[str] = []
    lines.append("# EDAMAME Posture Performance Report")
    lines.append("")
    lines.append(
        f"_Generated: {datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None).isoformat(timespec='seconds')}Z_"
    )
    lines.append("")
    lines.append(
        "This report is regenerated by `.github/workflows/perf.yml` on every weekly"
        " cron and on manual dispatch. It measures `edamame_posture` resource usage"
        " across six scenarios on GitHub-managed runners."
    )
    lines.append("")
    lines.append("## Scenarios")
    lines.append("")
    for scen in SCENARIO_ORDER:
        lines.append(f"- **{scen}** -- {SCENARIO_LABELS[scen]}")
    lines.append("")
    lines.append("Each scenario runs for five minutes after a brief warmup. The sampler"
                 " walks the daemon process and all of its descendants once per second.")
    lines.append("")
    lines.append("## CPU normalization methodology")
    lines.append("")
    lines.append(
        "GitHub-managed runners ship different CPU topologies, so raw CPU percent is"
        " not directly comparable. The report therefore presents three views for every"
        " scenario:"
    )
    lines.append("")
    lines.append("1. **CPU avg/max %** -- raw psutil values. 100% equals one fully busy"
                 " logical core regardless of how many cores the runner has.")
    lines.append("2. **Load avg/max %** -- raw CPU divided by logical core count. 100%"
                 " would mean every core on the machine is fully busy.")
    lines.append("3. **Work-norm avg** -- raw CPU multiplied by the per-platform"
                 " normalization factor derived from a deterministic SHA-256 + BLAKE3"
                 " benchmark. Higher means more real work per wall-clock second relative"
                 " to the baseline platform.")
    lines.append("")
    if baseline and baseline_cal:
        lines.append(
            f"The baseline platform used for work normalization is **`{baseline}`**"
            f" with composite work score `{_fmt_int(baseline_score)}` hashes/sec."
            " `normalization_factor = baseline_score / platform_score`, so the baseline"
            " platform always has factor `1.0`."
        )
    else:
        lines.append(
            "_No baseline calibration was available, so work-normalized CPU values fall"
            " back to the raw CPU percentage._"
        )
    lines.append("")
    lines.append("Per-platform normalization factors:")
    lines.append("")
    norm_factors: Dict[str, float] = {}
    for plat in platforms:
        cal = calibrations.get(plat)
        if cal and baseline_score > 0 and float(cal.get("composite_score") or 0) > 0:
            factor = baseline_score / float(cal["composite_score"])
        else:
            factor = 1.0
        norm_factors[plat] = factor
        lines.append(f"- `{plat}` -- factor `{_fmt_float(factor, 3)}`")
    lines.append("")

    lines.append("## Per-platform results")
    lines.append("")
    for plat in platforms:
        cal, scen_map = loaded[plat]
        lines.append(_platform_banner(plat, cal))
        lines.append(_scenario_table(plat, cal, scen_map, norm_factors.get(plat, 1.0)))
        meta_block = _meta_summary_for_scenarios(scen_map)
        if meta_block:
            lines.append("Scenario metadata:")
            lines.append("")
            lines.append(meta_block)
            lines.append("")

    lines.append("## Calibration summary")
    lines.append("")
    meta_md = _metadata_block(platforms, calibrations)
    if meta_md:
        lines.append(meta_md)
    else:
        lines.append("_No calibration data collected._")
    lines.append("")

    lines.append("## Reproducing locally")
    lines.append("")
    lines.append("```bash")
    lines.append("# one scenario, five minutes")
    lines.append("python3 tests/perf/calibrate.py --output calibration.json")
    lines.append(
        "bash tests/perf/run_scenario.sh --scenario idle --duration 300 --output-dir results/local/idle"
    )
    lines.append("```")
    lines.append("")
    lines.append("See `.github/workflows/perf.yml` for the full CI orchestration.")
    lines.append("")

    out_dir = os.path.dirname(os.path.abspath(args.output))
    if out_dir:
        pathlib.Path(out_dir).mkdir(parents=True, exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    print(f"Wrote {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
