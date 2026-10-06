"""Resource sampling of the candidate daemon during an FP lab run.

The lab drives the release candidate with real agent work for one to two
hours per host, which is also the cheapest realistic load test the release
gets. This module samples the posture daemon (the process whose image is
`edamame_posture`, the largest one when several run) every `interval`
seconds: resident memory and cumulative CPU time. Nothing here needs a
privilege the harness does not already have, and nothing is installed:

- Linux: `/proc/<pid>/stat` (utime + stime) and `/proc/<pid>/status` (VmRSS).
- macOS: `ps -axo pid=,rss=,time=,command=`.
- Windows: one CIM query (`Win32_Process`: WorkingSetSize, kernel and user
  time in 100 ns units).

The summary reports peak and end RSS, the RSS slope after warm-up (the leak
signal), mean and p95 CPU (percent of one core, from CPU-time deltas, not
the platform's own averaged %CPU), daemon restarts (a pid change mid-run is a
crash or a respawn), and the per-case peaks. Flags are for a human to look
at, never part of the false-positive verdict; `release.mdc` (Pre-Release FP
Lab Gate) says what blocks a release.
"""

from __future__ import annotations

import csv
import datetime as _dt
import os
import platform
import statistics
import subprocess
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

DAEMON_IMAGE = "edamame_posture"

# Investigation thresholds. They catch the big regressions this sampling can
# see in one window (a leak, a runaway loop, a crash); fine regressions are
# the CI perf gate's (tests.yml run_perf, per-scenario baselines).
PEAK_RSS_FLAG_MB = 1536.0
RSS_SLOPE_FLAG_MB_PER_HOUR = 200.0
RSS_SLOPE_MIN_SPAN_SECS = 1800.0
CPU_P95_FLAG_PERCENT = 150.0
CPU_MEAN_FLAG_PERCENT = 60.0
# Samples within the first `WARMUP_SECS` (initial loads, first scans) are not
# used for the slope.
WARMUP_SECS = 600.0


def _now() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


def _clock_seconds(text: str) -> Optional[float]:
    """`[DD-]HH:MM:SS[.ss]` or `MM:SS.ss` (ps `time`) to seconds."""
    text = text.strip()
    if not text:
        return None
    days = 0.0
    if "-" in text:
        d, text = text.split("-", 1)
        try:
            days = float(d)
        except ValueError:
            return None
    total = 0.0
    try:
        for part in text.split(":"):
            total = total * 60 + float(part)
    except ValueError:
        return None
    return days * 86400 + total


def _linux_daemons() -> List[Tuple[int, float, float]]:
    out = []
    tick = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            if (entry / "comm").read_text().strip() != DAEMON_IMAGE:
                continue
            stat = (entry / "stat").read_text()
            fields = stat[stat.rindex(")") + 2:].split()
            cpu = (int(fields[11]) + int(fields[12])) / tick
            rss_kb = 0.0
            for line in (entry / "status").read_text().splitlines():
                if line.startswith("VmRSS:"):
                    rss_kb = float(line.split()[1])
                    break
            out.append((int(entry.name), rss_kb * 1024, cpu))
        except (OSError, ValueError, IndexError):
            continue
    return out


def _macos_daemons() -> List[Tuple[int, float, float]]:
    out = []
    try:
        text = subprocess.run(["ps", "-axo", "pid=,rss=,time=,command="], capture_output=True,
                              text=True, timeout=20).stdout
    except (OSError, subprocess.SubprocessError):
        return out
    for line in text.splitlines():
        parts = line.split(None, 3)
        if len(parts) < 4:
            continue
        image = parts[3].split()[0] if parts[3].split() else ""
        if os.path.basename(image) != DAEMON_IMAGE:
            continue
        cpu = _clock_seconds(parts[2])
        try:
            out.append((int(parts[0]), float(parts[1]) * 1024, cpu or 0.0))
        except ValueError:
            continue
    return out


def _windows_daemons() -> List[Tuple[int, float, float]]:
    script = ("Get-CimInstance Win32_Process -Filter \"Name='%s.exe'\" | ForEach-Object { "
              "'{0} {1} {2} {3}' -f $_.ProcessId,$_.WorkingSetSize,$_.KernelModeTime,$_.UserModeTime }"
              % DAEMON_IMAGE)
    out = []
    try:
        text = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                              capture_output=True, text=True, timeout=40).stdout
    except (OSError, subprocess.SubprocessError):
        return out
    for line in text.splitlines():
        parts = line.split()
        if len(parts) != 4:
            continue
        try:
            out.append((int(parts[0]), float(parts[1]), (int(parts[2]) + int(parts[3])) / 1e7))
        except ValueError:
            continue
    return out


def sample_daemon() -> Optional[Tuple[int, float, float]]:
    """(pid, rss_bytes, cpu_seconds) of the posture daemon, the largest
    `edamame_posture` process (a short-lived CLI child of the same image is
    smaller), or None when none runs."""
    system = platform.system()
    if system == "Linux":
        found = _linux_daemons()
    elif system == "Darwin":
        found = _macos_daemons()
    elif system == "Windows":
        found = _windows_daemons()
    else:
        found = []
    return max(found, key=lambda row: row[1]) if found else None


class PerfSampler(threading.Thread):
    """Samples the daemon every `interval` seconds into `csv_path` until
    `stop()`; `samples` keeps the rows for the summary."""

    def __init__(self, csv_path: Path, interval: float = 30.0) -> None:
        super().__init__(daemon=True, name="fp-lab-perf")
        self.csv_path = csv_path
        self.interval = interval
        self.samples: List[dict] = []
        self._stop = threading.Event()

    def stop(self) -> None:
        self._stop.set()
        self.join(timeout=self.interval + 60)

    def run(self) -> None:
        self.csv_path.parent.mkdir(parents=True, exist_ok=True)
        with self.csv_path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(["at", "pid", "rss_mb", "cpu_seconds"])
            while not self._stop.is_set():
                row = sample_daemon()
                at = _now()
                if row:
                    pid, rss, cpu = row
                    sample = {"at": at, "pid": pid, "rss_mb": rss / 1048576, "cpu_seconds": cpu}
                    self.samples.append(sample)
                    writer.writerow([at.isoformat(), pid, f"{sample['rss_mb']:.1f}", f"{cpu:.2f}"])
                    fh.flush()
                self._stop.wait(self.interval)


def _parse(at: str) -> Optional[_dt.datetime]:
    try:
        return _dt.datetime.fromisoformat(str(at).replace("Z", "+00:00"))
    except ValueError:
        return None


def _slope_mb_per_hour(points: List[Tuple[float, float]]) -> Optional[float]:
    if len(points) < 3:
        return None
    xs = [p[0] for p in points]
    ys = [p[1] for p in points]
    mx, my = statistics.fmean(xs), statistics.fmean(ys)
    var = sum((x - mx) ** 2 for x in xs)
    if var == 0:
        return None
    return sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / var * 3600


def _p95(values: List[float]) -> Optional[float]:
    if not values:
        return None
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(round(0.95 * (len(ordered) - 1))))]


def summarize(samples: List[dict], cases: List[dict]) -> dict:
    """The run's resource summary and flags. `cases` carry `case_id`,
    `started_at` and `finished_at` (ISO)."""
    if not samples:
        return {"samples": 0, "flags": ["no daemon samples (the daemon process was not found)"]}
    t0 = samples[0]["at"]
    pids = []
    for s in samples:
        if not pids or pids[-1] != s["pid"]:
            pids.append(s["pid"])
    cpu_pct: List[Tuple[_dt.datetime, float]] = []
    for prev, cur in zip(samples, samples[1:]):
        wall = (cur["at"] - prev["at"]).total_seconds()
        if cur["pid"] != prev["pid"] or wall <= 0:
            continue
        cpu_pct.append((cur["at"], max(0.0, (cur["cpu_seconds"] - prev["cpu_seconds"]) / wall * 100)))
    steady = [((s["at"] - t0).total_seconds(), s["rss_mb"]) for s in samples
              if (s["at"] - t0).total_seconds() >= WARMUP_SECS and s["pid"] == samples[-1]["pid"]]
    span = (steady[-1][0] - steady[0][0]) if len(steady) >= 2 else 0.0
    slope = _slope_mb_per_hour(steady) if span >= RSS_SLOPE_MIN_SPAN_SECS else None
    cpu_values = [v for _, v in cpu_pct]
    summary = {
        "samples": len(samples),
        "duration_secs": round((samples[-1]["at"] - t0).total_seconds()),
        "daemon_pids": pids,
        "restarts": len(pids) - 1,
        "rss_mb": {"start": round(samples[0]["rss_mb"], 1), "end": round(samples[-1]["rss_mb"], 1),
                   "peak": round(max(s["rss_mb"] for s in samples), 1)},
        "rss_slope_mb_per_hour": None if slope is None else round(slope, 1),
        "rss_slope_span_secs": round(span),
        "cpu_percent": {"mean": None if not cpu_values else round(statistics.fmean(cpu_values), 1),
                        "p95": None if not cpu_values else round(_p95(cpu_values), 1),
                        "max": None if not cpu_values else round(max(cpu_values), 1)},
        "cases": [],
    }
    for case in cases:
        start, end = _parse(case.get("started_at") or ""), _parse(case.get("finished_at") or "")
        if not start or not end:
            continue
        rss = [s["rss_mb"] for s in samples if start <= s["at"] <= end]
        cpu = [v for at, v in cpu_pct if start <= at <= end]
        if not rss:
            continue
        summary["cases"].append({"case_id": case.get("case_id"), "peak_rss_mb": round(max(rss), 1),
                                 "mean_cpu_percent": None if not cpu else round(statistics.fmean(cpu), 1),
                                 "max_cpu_percent": None if not cpu else round(max(cpu), 1)})
    flags = []
    if summary["restarts"]:
        flags.append(f"the daemon restarted {summary['restarts']} time(s) (pids {pids}): a crash or a respawn")
    if summary["rss_mb"]["peak"] > PEAK_RSS_FLAG_MB:
        flags.append(f"peak RSS {summary['rss_mb']['peak']} MB > {PEAK_RSS_FLAG_MB:.0f} MB")
    if slope is not None and slope > RSS_SLOPE_FLAG_MB_PER_HOUR:
        flags.append(f"RSS grows {slope:.0f} MB/h over {span / 60:.0f} min after warm-up "
                     f"(> {RSS_SLOPE_FLAG_MB_PER_HOUR:.0f} MB/h): a leak until shown otherwise")
    p95 = summary["cpu_percent"]["p95"]
    mean = summary["cpu_percent"]["mean"]
    if p95 is not None and p95 > CPU_P95_FLAG_PERCENT:
        flags.append(f"CPU p95 {p95}% of a core > {CPU_P95_FLAG_PERCENT:.0f}%")
    if mean is not None and mean > CPU_MEAN_FLAG_PERCENT:
        flags.append(f"mean CPU {mean}% of a core > {CPU_MEAN_FLAG_PERCENT:.0f}%")
    summary["flags"] = flags
    return summary


def markdown(summary: dict, reference: Optional[dict] = None) -> List[str]:
    """The summary.md section."""
    lines = ["## Daemon resources", ""]
    if not summary.get("samples"):
        lines += [f"- {f}" for f in summary.get("flags", [])] + [""]
        return lines
    rss, cpu = summary["rss_mb"], summary["cpu_percent"]
    lines.append(f"- {summary['samples']} samples over {summary['duration_secs'] // 60} min; "
                 f"restarts: {summary['restarts']}")
    lines.append(f"- RSS start {rss['start']} MB, end {rss['end']} MB, peak {rss['peak']} MB; slope after "
                 f"warm-up: {summary['rss_slope_mb_per_hour']} MB/h over {summary['rss_slope_span_secs'] // 60} min")
    lines.append(f"- CPU (percent of one core): mean {cpu['mean']}, p95 {cpu['p95']}, max {cpu['max']}")
    if reference:
        lines.append(f"- Reference (released daemon on this host before the window): {reference}")
    lines.append(f"- Flags: {'; '.join(summary['flags']) if summary['flags'] else 'none'}")
    lines += ["", "| Case | Peak RSS MB | Mean CPU % | Max CPU % |", "|---|---|---|---|"]
    for c in summary["cases"]:
        lines.append(f"| `{c['case_id']}` | {c['peak_rss_mb']} | {c['mean_cpu_percent']} | {c['max_cpu_percent']} |")
    lines.append("")
    return lines
