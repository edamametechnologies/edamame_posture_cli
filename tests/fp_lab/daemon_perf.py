"""Resource sampling of the candidate daemon during an FP lab run.

The lab drives the release candidate with real agent work for one to two
hours per host, which is also the cheapest realistic load test the release
gets. This module samples the posture daemon (the process whose image is
`edamame_posture`, the largest one when several run) every `interval`
seconds: resident memory and cumulative CPU time. Nothing here needs a
privilege the harness does not already have, and nothing is installed:

- Linux: `/proc/<pid>/stat` (utime + stime) and `/proc/<pid>/status` (VmRSS).
- macOS: `ps -axo pid=,rss=,time=,command=`, and the physical footprint from
  `top -l 1 -pid <pid> -stats pid,mem` (what the OS charges the process,
  readable for a root daemon without a privilege).
- Windows: one CIM query (`Win32_Process`: WorkingSetSize, kernel and user
  time in 100 ns units).

The summary reports peak and end RSS, the memory slope after warm-up (the leak
signal: the physical footprint's on macOS, RSS's elsewhere), mean and p95 CPU (percent of one core, from CPU-time deltas, not
the platform's own averaged %CPU), daemon restarts (a pid change mid-run is a
crash or a respawn), and the per-case peaks. Flags are for a human to look
at, never part of the false-positive verdict; `release.mdc` (Pre-Release FP
Lab Gate) says what blocks a release.

Every `TABLE_SAMPLE_SECS` the sampler also reads, through `edamame_cli` (the
`rpc` callable the runner hands it), the sizes of what the daemon keeps in
memory: the session tables, the process lineage table, the engines' traces,
the file monitor's store (`TABLE_READS`). They go into `perf.csv` beside the
memory columns, and the summary's "What grew" line says which of them moved
with a memory slope. A daemon that does not answer leaves the columns empty;
the sampler never fails on it.
"""

from __future__ import annotations

import csv
import datetime as _dt
import json
import os
import platform
import re
import statistics
import subprocess
import threading
import time
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

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

# The in-memory tables read beside the memory samples, every
# `TABLE_SAMPLE_SECS` (`get_agentic_memory_stats` serializes the histories to
# measure them, so not on every sample). Column, RPC method, path into its
# answer, divisor (bytes to MB), unit, the label the summary prints.
TABLE_SAMPLE_SECS = 300.0
MB = 1048576.0
TABLE_READS: List[Tuple[str, str, Tuple[str, ...], float, str, str]] = [
    ("sessions_tracked", "get_analyzer_stats", ("session_stats", "total_sessions_tracked"), 1.0, "", "sessions tracked"),
    ("lan_sessions", "get_lan_sessions_status", ("session_count",), 1.0, "", "LAN sessions"),
    ("lineage_rows", "get_attack_pattern_detector_status", ("process_lineage_table_size",), 1.0, "", "lineage rows"),
    ("task_access_edges", "get_attack_pattern_detector_status", ("task_access_edges",), 1.0, "", "task-access edges"),
    ("process_events_lost", "get_attack_pattern_detector_status", ("process_events_lost_total",), 1.0, "",
     "process events lost (counter)"),
    ("detector_cache", "get_attack_pattern_detector_status", ("cache_size",), 1.0, "", "detector cache"),
    ("ap_trace_entries", "get_agentic_memory_stats", ("vulnerability", "history_trace_entries"), 1.0, "",
     "attack-pattern trace entries"),
    ("ap_trace_mb", "get_agentic_memory_stats", ("vulnerability", "history_trace_json_bytes"), MB, " MB",
     "attack-pattern traces"),
    ("div_trace_entries", "get_agentic_memory_stats", ("divergence", "verdict_history_trace_entries"), 1.0, "",
     "divergence trace entries"),
    ("div_trace_mb", "get_agentic_memory_stats", ("divergence", "verdict_history_trace_json_bytes"), MB, " MB",
     "divergence traces"),
    ("model_history_mb", "get_agentic_memory_stats", ("divergence", "model_history_json_bytes"), MB, " MB",
     "model history"),
    ("core_process_mb", "get_agentic_memory_stats", ("overall", "process_memory_bytes"), MB, " MB",
     "process memory as the core reads it"),
    ("fim_events", "get_file_monitor_status", ("event_count",), 1.0, "", "file events"),
]
TABLE_COLUMNS = [col for col, *_ in TABLE_READS]
TABLE_META = {col: (unit, label) for col, _m, _p, _d, unit, label in TABLE_READS}


def _now() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


def _as_obj(value: object) -> object:
    """The agentic RPCs answer with a JSON string carrying JSON."""
    if isinstance(value, str):
        try:
            return json.loads(value)
        except ValueError:
            return None
    return value


def _dig(obj: object, path: Tuple[str, ...]) -> Optional[float]:
    for key in path:
        if not isinstance(obj, dict):
            return None
        obj = obj.get(key)
    if isinstance(obj, bool) or not isinstance(obj, (int, float)):
        return None
    return float(obj)


def read_tables(rpc: Optional[Callable[[str], object]]) -> Dict[str, Optional[float]]:
    """One reading of every `TABLE_READS` column (None where the daemon did
    not answer or the field is missing). Each RPC is called once; an
    exception from the callable reads as no answer."""
    out: Dict[str, Optional[float]] = {col: None for col in TABLE_COLUMNS}
    if rpc is None:
        return out
    answers: Dict[str, object] = {}
    for col, method, path, divisor, _unit, _label in TABLE_READS:
        if method not in answers:
            try:
                answers[method] = _as_obj(rpc(method))
            except Exception:  # noqa: BLE001
                answers[method] = None
        value = _dig(answers[method], path)
        out[col] = None if value is None else value / divisor
    return out


def _fmt_table(col: str, value: Optional[float]) -> str:
    if value is None:
        return ""
    return f"{value:.1f}" if TABLE_META[col][0] else f"{value:.0f}"


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


# On macOS `ps` RSS keeps counting the pages malloc freed and marked
# reusable: the FP lab's installer case took it from 404 to 801 MB over four
# bursts while the physical footprint came back to 316 MB after each
# (2026-11-07, the seventh 2.3.2 candidate's build), and the RSS slope read
# that as growth. There the slope reads the footprint (Frank, 2026-11-09).
def _top_size_bytes(text: str) -> Optional[float]:
    """`top`'s MEM column (`316M`, `1024K`, `1.2G`, a trailing `+` / `-`
    when it changed since the previous sample) in bytes."""
    m = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)([BKMGT]?)[+-]?", text.strip())
    if not m:
        return None
    scale = {"": 1, "B": 1, "K": 1024, "M": 1024 ** 2, "G": 1024 ** 3, "T": 1024 ** 4}[m.group(2)]
    return float(m.group(1)) * scale


def macos_footprint_bytes(pid: int) -> Optional[float]:
    """The physical footprint of `pid` (`top`'s MEM), None when `top` does
    not report it."""
    try:
        text = subprocess.run(["top", "-l", "1", "-pid", str(pid), "-stats", "pid,mem"],
                              capture_output=True, text=True, timeout=20).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0] == str(pid):
            return _top_size_bytes(parts[1])
    return None


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
    `stop()`; `samples` keeps the rows for the summary. `rpc` (method name
    -> parsed answer or None, the runner's `rpc_or_none`) reads the tables
    every `TABLE_SAMPLE_SECS`; None leaves the table columns empty."""

    def __init__(self, csv_path: Path, interval: float = 30.0,
                 rpc: Optional[Callable[[str], object]] = None) -> None:
        super().__init__(daemon=True, name="fp-lab-perf")
        self.csv_path = csv_path
        self.interval = interval
        self.rpc = rpc
        self.table_every = max(1, int(round(TABLE_SAMPLE_SECS / interval))) if interval > 0 else 1
        self.samples: List[dict] = []
        self._halt = threading.Event()

    def stop(self) -> None:
        self._halt.set()
        self.join(timeout=self.interval + 60)

    def run(self) -> None:
        self.csv_path.parent.mkdir(parents=True, exist_ok=True)
        with self.csv_path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(["at", "pid", "rss_mb", "cpu_seconds", "footprint_mb"] + TABLE_COLUMNS)
            n = 0
            while not self._halt.is_set():
                row = sample_daemon()
                at = _now()
                if row:
                    pid, rss, cpu = row
                    footprint = macos_footprint_bytes(pid) if platform.system() == "Darwin" else None
                    # The first sample and every `table_every`th after it read
                    # the tables, so the window has a start and an end reading.
                    tables = read_tables(self.rpc) if n % self.table_every == 0 \
                        else {col: None for col in TABLE_COLUMNS}
                    sample = {"at": at, "pid": pid, "rss_mb": rss / 1048576, "cpu_seconds": cpu,
                              "footprint_mb": None if footprint is None else footprint / 1048576}
                    sample.update(tables)
                    self.samples.append(sample)
                    writer.writerow([at.isoformat(), pid, f"{sample['rss_mb']:.1f}", f"{cpu:.2f}",
                                     "" if footprint is None else f"{sample['footprint_mb']:.1f}"]
                                    + [_fmt_table(col, tables[col]) for col in TABLE_COLUMNS])
                    fh.flush()
                    n += 1
                self._halt.wait(self.interval)


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


def table_trends(samples: List[dict], t0: _dt.datetime, pid: int) -> Dict[str, dict]:
    """Per table column: the readings after warm-up on `pid` (the table
    columns are sparse: a reading every `TABLE_SAMPLE_SECS`, None between),
    their first and last value and the slope per hour over the same window
    the memory slope uses (None under three readings or a span under
    `RSS_SLOPE_MIN_SPAN_SECS`)."""
    trends: Dict[str, dict] = {}
    for col in TABLE_COLUMNS:
        unit, label = TABLE_META[col]
        points = [((s["at"] - t0).total_seconds(), s[col]) for s in samples
                  if s.get(col) is not None and (s["at"] - t0).total_seconds() >= WARMUP_SECS
                  and s["pid"] == pid]
        span = (points[-1][0] - points[0][0]) if len(points) >= 2 else 0.0
        slope = _slope_mb_per_hour(points) if span >= RSS_SLOPE_MIN_SPAN_SECS else None
        trends[col] = {
            "label": label, "unit": unit.strip(), "readings": len(points),
            "start": None if not points else round(points[0][1], 1 if unit else 0),
            "end": None if not points else round(points[-1][1], 1 if unit else 0),
            "span_secs": round(span),
            "slope_per_hour": None if slope is None else round(slope, 1 if unit else 0),
        }
    return trends


def what_grew(trends: Dict[str, dict]) -> str:
    """One sentence for the summary: the tables whose readings grew over
    the window, largest relative growth first, then the ones that stayed
    flat; or that nothing was read."""
    read = [t for t in trends.values() if t["readings"]]
    if not read:
        return "Tables: not sampled (edamame_cli did not answer during the run)"
    sloped = [t for t in read if t["slope_per_hour"] is not None]
    if not sloped:
        n = max(t["readings"] for t in read)
        return f"What grew after warm-up: too few table readings ({n}) over too short a window to say"
    span_min = max(t["span_secs"] for t in sloped) // 60

    def fmt(value: float, unit: str) -> str:
        return f"{value:.1f} {unit}".strip() if unit else f"{value:.0f}"

    def growth(t: dict) -> float:
        return (t["end"] - t["start"]) / (abs(t["start"]) or 1.0)

    grew = sorted([t for t in sloped if t["slope_per_hour"] > 0 and t["end"] > t["start"]], key=growth, reverse=True)
    flat = [t["label"] for t in sloped if t not in grew]
    parts = [f"{t['label']} {fmt(t['start'], t['unit'])} -> {fmt(t['end'], t['unit'])} "
             f"(+{fmt(t['slope_per_hour'], t['unit'])}/h)" for t in grew]
    line = f"What grew after warm-up ({span_min} min of table readings): "
    line += ", ".join(parts) if parts else "nothing in the sampled tables"
    if flat and parts:
        line += f"; flat: {', '.join(flat)}"
    return line


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
    def slope_of(key: str) -> Tuple[Optional[float], float]:
        steady = [((s["at"] - t0).total_seconds(), s[key]) for s in samples
                  if s.get(key) is not None and (s["at"] - t0).total_seconds() >= WARMUP_SECS
                  and s["pid"] == samples[-1]["pid"]]
        span = (steady[-1][0] - steady[0][0]) if len(steady) >= 2 else 0.0
        return (_slope_mb_per_hour(steady) if span >= RSS_SLOPE_MIN_SPAN_SECS else None), span

    rss_slope, rss_span = slope_of("rss_mb")
    footprints = [s["footprint_mb"] for s in samples if s.get("footprint_mb") is not None]
    footprint_slope, footprint_span = slope_of("footprint_mb") if footprints else (None, 0.0)
    # The leak signal: the footprint's slope where it was measured (macOS),
    # RSS's elsewhere or when too few footprints were read.
    if footprint_slope is not None:
        slope, span, basis = footprint_slope, footprint_span, "footprint"
    else:
        slope, span, basis = rss_slope, rss_span, "rss"
    cpu_values = [v for _, v in cpu_pct]
    summary = {
        "samples": len(samples),
        "duration_secs": round((samples[-1]["at"] - t0).total_seconds()),
        "daemon_pids": pids,
        "restarts": len(pids) - 1,
        "rss_mb": {"start": round(samples[0]["rss_mb"], 1), "end": round(samples[-1]["rss_mb"], 1),
                   "peak": round(max(s["rss_mb"] for s in samples), 1)},
        "rss_slope_mb_per_hour": None if rss_slope is None else round(rss_slope, 1),
        "rss_slope_span_secs": round(rss_span),
        "footprint_mb": None if not footprints else {
            "start": round(footprints[0], 1), "end": round(footprints[-1], 1), "peak": round(max(footprints), 1)},
        "footprint_slope_mb_per_hour": None if footprint_slope is None else round(footprint_slope, 1),
        "slope_basis": basis,
        "cpu_percent": {"mean": None if not cpu_values else round(statistics.fmean(cpu_values), 1),
                        "p95": None if not cpu_values else round(_p95(cpu_values), 1),
                        "max": None if not cpu_values else round(max(cpu_values), 1)},
        "cases": [],
    }
    # The tables beside the memory slope: same window, same pid.
    summary["tables"] = table_trends(samples, t0, samples[-1]["pid"])
    summary["what_grew"] = what_grew(summary["tables"])
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
        measure = "the physical footprint" if basis == "footprint" else "RSS"
        flags.append(f"{measure} grows {slope:.0f} MB/h over {span / 60:.0f} min after warm-up "
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
    footprint = summary.get("footprint_mb")
    if footprint:
        lines.append(f"- Physical footprint start {footprint['start']} MB, end {footprint['end']} MB, peak "
                     f"{footprint['peak']} MB; slope after warm-up: {summary.get('footprint_slope_mb_per_hour')} MB/h "
                     f"(the slope the flags read)")
    if summary.get("what_grew"):
        lines.append(f"- {summary['what_grew']}")
    lines.append(f"- CPU (percent of one core): mean {cpu['mean']}, p95 {cpu['p95']}, max {cpu['max']}")
    if reference:
        lines.append(f"- Reference (released daemon on this host before the window): {reference}")
    lines.append(f"- Flags: {'; '.join(summary['flags']) if summary['flags'] else 'none'}")
    lines += ["", "| Case | Peak RSS MB | Mean CPU % | Max CPU % |", "|---|---|---|---|"]
    for c in summary["cases"]:
        lines.append(f"| `{c['case_id']}` | {c['peak_rss_mb']} | {c['mean_cpu_percent']} | {c['max_cpu_percent']} |")
    lines.append("")
    return lines
