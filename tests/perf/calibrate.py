#!/usr/bin/env python3
"""Single-core deterministic CPU calibration benchmark.

Hashes a fixed 16 MB in-memory buffer repeatedly with SHA-256 and BLAKE3 for
approximately a fixed wall-clock budget, reporting hashes per second for each
algorithm plus a composite geometric mean. Two hashes are used so the composite
score is less sensitive to architecture-specific ISA accelerations
(ARMv8 crypto extensions vs x86 AES-NI / SHA-NI vs generic integer paths).

The composite score is the work-equivalence factor the performance report uses
to normalize CPU-seconds across heterogeneous GitHub-managed runners.

Output: a single JSON object on stdout.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import sys
import time
from typing import Callable, Tuple

import psutil

try:
    import blake3 as _blake3  # type: ignore

    def _blake3_hash(buf: bytes) -> None:
        _blake3.blake3(buf).digest()

    _HAS_BLAKE3 = True
except Exception:
    _HAS_BLAKE3 = False

    def _blake3_hash(buf: bytes) -> None:
        hashlib.blake2b(buf, digest_size=32).digest()


_BUFFER_SIZE_BYTES = 16 * 1024 * 1024


def _sha256_hash(buf: bytes) -> None:
    hashlib.sha256(buf).digest()


def _run_budgeted(hash_fn: Callable[[bytes], None], buf: bytes, budget_s: float) -> Tuple[int, float]:
    """Run `hash_fn(buf)` repeatedly for roughly `budget_s` seconds.

    Returns (iterations, elapsed_seconds).
    """
    iterations = 0
    start = time.perf_counter()
    deadline = start + budget_s
    while True:
        hash_fn(buf)
        iterations += 1
        now = time.perf_counter()
        if now >= deadline:
            return iterations, now - start


def _cpu_model() -> str:
    sysname = platform.system().lower()
    try:
        if sysname == "linux":
            with open("/proc/cpuinfo", "r", encoding="utf-8") as fh:
                for line in fh:
                    if line.lower().startswith("model name"):
                        return line.split(":", 1)[1].strip()
        elif sysname == "darwin":
            import subprocess

            out = subprocess.run(
                ["sysctl", "-n", "machdep.cpu.brand_string"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if out.returncode == 0 and out.stdout.strip():
                return out.stdout.strip()
        elif sysname == "windows":
            import subprocess

            out = subprocess.run(
                ["wmic", "cpu", "get", "Name", "/value"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            if out.returncode == 0:
                for line in out.stdout.splitlines():
                    if line.strip().lower().startswith("name="):
                        return line.split("=", 1)[1].strip()
    except Exception:
        pass
    return platform.processor() or platform.machine() or "unknown"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--budget", type=float, default=3.0, help="Wall-clock budget per algorithm in seconds (default: 3.0)")
    ap.add_argument(
        "--warmup-iterations",
        type=int,
        default=2,
        help="Number of warmup iterations per algorithm to prime caches (default: 2)",
    )
    ap.add_argument(
        "--output",
        type=str,
        default="-",
        help="Write JSON result to this path, or '-' for stdout (default: -)",
    )
    args = ap.parse_args()

    buf = os.urandom(_BUFFER_SIZE_BYTES)
    results: dict = {
        "buffer_bytes": _BUFFER_SIZE_BYTES,
        "budget_seconds": args.budget,
        "warmup_iterations": args.warmup_iterations,
    }

    for _ in range(max(0, args.warmup_iterations)):
        _sha256_hash(buf)
    sha_iters, sha_elapsed = _run_budgeted(_sha256_hash, buf, args.budget)
    results["sha256_iterations"] = sha_iters
    results["sha256_elapsed_s"] = sha_elapsed
    results["sha256_hps"] = sha_iters / sha_elapsed if sha_elapsed > 0 else 0.0

    for _ in range(max(0, args.warmup_iterations)):
        _blake3_hash(buf)
    b3_iters, b3_elapsed = _run_budgeted(_blake3_hash, buf, args.budget)
    results["blake3_iterations"] = b3_iters
    results["blake3_elapsed_s"] = b3_elapsed
    results["blake3_hps"] = b3_iters / b3_elapsed if b3_elapsed > 0 else 0.0
    results["blake3_available"] = _HAS_BLAKE3
    if not _HAS_BLAKE3:
        results["blake3_note"] = "blake3 package unavailable; fell back to hashlib.blake2b"

    if results["sha256_hps"] > 0 and results["blake3_hps"] > 0:
        results["composite_score"] = math.sqrt(results["sha256_hps"] * results["blake3_hps"])
    else:
        results["composite_score"] = 0.0

    try:
        total_ram = psutil.virtual_memory().total
    except Exception:
        total_ram = 0

    results["ncpu_logical"] = psutil.cpu_count(logical=True) or 0
    results["ncpu_physical"] = psutil.cpu_count(logical=False) or 0
    results["total_ram_bytes"] = total_ram
    results["total_ram_mb"] = int(total_ram / (1024 * 1024))
    results["platform_system"] = platform.system()
    results["platform_release"] = platform.release()
    results["platform_machine"] = platform.machine()
    results["python_version"] = platform.python_version()
    results["cpu_model"] = _cpu_model()

    payload = json.dumps(results, indent=2, sort_keys=True)
    if args.output == "-":
        print(payload)
    else:
        os.makedirs(os.path.dirname(os.path.abspath(args.output)) or ".", exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(payload)
        print(f"Wrote calibration result to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
