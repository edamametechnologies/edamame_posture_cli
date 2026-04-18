#!/usr/bin/env python3
"""Periodic process sampler for performance scenarios.

Samples a root process (by name or pid) and its descendants at a fixed
interval and writes aggregate metrics to a JSONL file, one sample per line.
At the end the sampler writes a final JSON summary file with average/max
values that the report generator consumes.

Metrics per sample (aggregated across root + descendants):
- wall_timestamp: ISO-8601 UTC timestamp
- elapsed_s: seconds since sampling started
- rss_bytes / rss_mb: resident set size sum
- vms_bytes / vms_mb: virtual memory size sum
- cpu_percent: sum across processes; one full core == 100
- num_threads: total OS threads
- num_fds: open file descriptors (Linux/macOS only; 0 on Windows)
- read_bytes / write_bytes: cumulative IO counters (best-effort; not available on macOS)
- proc_count: number of live processes in the tree

The JSON summary aggregates:
- duration_s: wall seconds actually sampled
- samples: number of successful samples
- cpu_percent_avg / cpu_percent_max
- rss_mb_avg / rss_mb_max
- vms_mb_avg / vms_mb_max
- threads_avg / threads_max
- fds_avg / fds_max
- ncpu_logical / ncpu_physical / total_ram_bytes (host context)

Intended to be launched in parallel with the scenario driver; stops cleanly
when it receives SIGTERM/SIGINT or when its --duration elapses.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import platform
import signal
import statistics
import sys
import time
from typing import List, Optional

import psutil


_STOP = False


def _handle_stop(_signum, _frame) -> None:
    global _STOP
    _STOP = True


def _find_root_by_name(name: str) -> Optional[psutil.Process]:
    """Return the first matching process whose name starts with `name`.

    On Windows the binary suffix is `.exe`; we match either form. If multiple
    processes match, the oldest one (lowest create_time) wins so that auxiliary
    children spawned later do not displace the root.
    """
    needle = name.lower()
    needle_exe = needle + ".exe"
    candidates: List[psutil.Process] = []
    for p in psutil.process_iter(attrs=["pid", "name", "create_time"]):
        try:
            pname = (p.info.get("name") or "").lower()
            if pname == needle or pname == needle_exe or pname.startswith(needle):
                candidates.append(p)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    if not candidates:
        return None
    candidates.sort(key=lambda p: (getattr(p, "info", {}) or {}).get("create_time") or 0)
    return candidates[0]


def _collect_tree(root: psutil.Process) -> List[psutil.Process]:
    try:
        return [root] + root.children(recursive=True)
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return [root]


def _prime_cpu(procs: List[psutil.Process]) -> None:
    for p in procs:
        try:
            p.cpu_percent(interval=None)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue


def _sample(procs: List[psutil.Process]) -> dict:
    rss = 0
    vms = 0
    cpu_total = 0.0
    threads = 0
    fds = 0
    read_b = 0
    write_b = 0
    live = 0
    for p in procs:
        try:
            with p.oneshot():
                mi = p.memory_info()
                rss += mi.rss
                vms += mi.vms
                cpu_total += p.cpu_percent(interval=None)
                try:
                    threads += p.num_threads()
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass
                try:
                    fds += p.num_fds()  # type: ignore[attr-defined]
                except (AttributeError, psutil.AccessDenied, psutil.NoSuchProcess):
                    pass
                try:
                    io = p.io_counters()
                    read_b += getattr(io, "read_bytes", 0) or 0
                    write_b += getattr(io, "write_bytes", 0) or 0
                except (psutil.AccessDenied, psutil.NoSuchProcess, AttributeError, NotImplementedError):
                    pass
                live += 1
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return {
        "rss_bytes": rss,
        "rss_mb": rss / (1024 * 1024),
        "vms_bytes": vms,
        "vms_mb": vms / (1024 * 1024),
        "cpu_percent": cpu_total,
        "num_threads": threads,
        "num_fds": fds,
        "read_bytes": read_b,
        "write_bytes": write_b,
        "proc_count": live,
    }


def _summarize(samples: List[dict], duration_s: float) -> dict:
    def _avg(key: str) -> float:
        vs = [s[key] for s in samples if key in s]
        return statistics.mean(vs) if vs else 0.0

    def _max(key: str) -> float:
        vs = [s[key] for s in samples if key in s]
        return max(vs) if vs else 0.0

    ncpu_logical = psutil.cpu_count(logical=True) or 0
    ncpu_physical = psutil.cpu_count(logical=False) or 0
    total_ram = 0
    try:
        total_ram = psutil.virtual_memory().total
    except Exception:
        pass
    return {
        "duration_s": duration_s,
        "samples": len(samples),
        "cpu_percent_avg": _avg("cpu_percent"),
        "cpu_percent_max": _max("cpu_percent"),
        "cpu_cores_used_avg": _avg("cpu_percent") / 100.0,
        "cpu_cores_used_max": _max("cpu_percent") / 100.0,
        "rss_mb_avg": _avg("rss_mb"),
        "rss_mb_max": _max("rss_mb"),
        "vms_mb_avg": _avg("vms_mb"),
        "vms_mb_max": _max("vms_mb"),
        "threads_avg": _avg("num_threads"),
        "threads_max": _max("num_threads"),
        "fds_avg": _avg("num_fds"),
        "fds_max": _max("num_fds"),
        "proc_count_avg": _avg("proc_count"),
        "proc_count_max": _max("proc_count"),
        "ncpu_logical": ncpu_logical,
        "ncpu_physical": ncpu_physical,
        "total_ram_bytes": total_ram,
        "total_ram_mb": int(total_ram / (1024 * 1024)) if total_ram else 0,
        "platform_system": platform.system(),
        "platform_release": platform.release(),
        "platform_machine": platform.machine(),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--name", type=str, help="Root process name (e.g. edamame_posture)")
    ap.add_argument("--pid", type=int, help="Root process PID (alternative to --name)")
    ap.add_argument("--interval", type=float, default=1.0, help="Sample interval in seconds (default: 1.0)")
    ap.add_argument(
        "--duration",
        type=float,
        default=0.0,
        help="Sampling duration in seconds; 0 means run until signal (default: 0)",
    )
    ap.add_argument(
        "--warmup",
        type=float,
        default=2.0,
        help="Wait this many seconds for the process to exist before giving up (default: 2.0)",
    )
    ap.add_argument(
        "--jsonl-output",
        type=str,
        required=True,
        help="Path to write JSONL of per-sample readings",
    )
    ap.add_argument(
        "--summary-output",
        type=str,
        required=True,
        help="Path to write final JSON summary",
    )
    ap.add_argument(
        "--scenario",
        type=str,
        default="",
        help="Scenario name to record in the summary",
    )
    args = ap.parse_args()

    if not args.name and not args.pid:
        print("error: provide --name or --pid", file=sys.stderr)
        return 2

    signal.signal(signal.SIGTERM, _handle_stop)
    signal.signal(signal.SIGINT, _handle_stop)

    root: Optional[psutil.Process] = None
    deadline = time.monotonic() + max(0.1, args.warmup)
    while root is None and time.monotonic() < deadline:
        try:
            if args.pid:
                root = psutil.Process(args.pid)
            else:
                root = _find_root_by_name(args.name)
        except psutil.NoSuchProcess:
            root = None
        if root is None:
            time.sleep(0.2)

    os.makedirs(os.path.dirname(os.path.abspath(args.jsonl_output)) or ".", exist_ok=True)
    os.makedirs(os.path.dirname(os.path.abspath(args.summary_output)) or ".", exist_ok=True)

    samples: List[dict] = []
    start_wall = time.time()
    start_mono = time.monotonic()
    end_mono = start_mono + args.duration if args.duration > 0 else None

    if root is None:
        summary = _summarize([], 0.0)
        summary.update(
            {
                "scenario": args.scenario,
                "error": f"process not found by name={args.name!r} or pid={args.pid}",
                "start_wall_utc": datetime.datetime.now(datetime.timezone.utc)
                .replace(tzinfo=None)
                .isoformat()
                + "Z",
            }
        )
        with open(args.summary_output, "w", encoding="utf-8") as sfh:
            json.dump(summary, sfh, indent=2)
        with open(args.jsonl_output, "w", encoding="utf-8"):
            pass
        return 1

    procs = _collect_tree(root)
    _prime_cpu(procs)
    time.sleep(0.5)

    refresh_every = max(3, int(5.0 / max(0.1, args.interval)))
    with open(args.jsonl_output, "w", encoding="utf-8") as jfh:
        i = 0
        while not _STOP:
            if i % refresh_every == 0:
                procs = _collect_tree(root)
                _prime_cpu(procs)
                time.sleep(min(0.2, args.interval / 2))
            try:
                if not root.is_running():
                    break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                break
            rec = _sample(procs)
            rec["elapsed_s"] = time.monotonic() - start_mono
            rec["wall_timestamp"] = (
                datetime.datetime.now(datetime.timezone.utc)
                .replace(tzinfo=None)
                .isoformat()
                + "Z"
            )
            samples.append(rec)
            try:
                jfh.write(json.dumps(rec) + "\n")
                jfh.flush()
            except Exception:
                pass
            i += 1
            if end_mono is not None and time.monotonic() >= end_mono:
                break
            sleep_for = args.interval - ((time.monotonic() - start_mono) % args.interval)
            if sleep_for <= 0:
                sleep_for = args.interval
            time.sleep(min(sleep_for, args.interval))

    duration = time.monotonic() - start_mono
    summary = _summarize(samples, duration)
    summary["scenario"] = args.scenario
    summary["start_wall_utc"] = (
        datetime.datetime.fromtimestamp(start_wall, tz=datetime.timezone.utc)
        .replace(tzinfo=None)
        .isoformat()
        + "Z"
    )
    summary["target_name"] = args.name or ""
    summary["target_pid"] = args.pid or 0
    summary["interval_s"] = args.interval

    with open(args.summary_output, "w", encoding="utf-8") as sfh:
        json.dump(summary, sfh, indent=2)
    return 0


if __name__ == "__main__":
    sys.exit(main())
