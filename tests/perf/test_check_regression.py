"""Unit tests for the sampler-integrity guard in check_regression.py.

The gate compares per-scenario summary.json values; a summary whose sample
count contradicts its own duration/interval came from a bursting or stalled
sampler and must never be used as a comparison basis (baseline -> skipped
with a warning; current -> hard failure, because a bursting sampler
under-reports CPU and would mask a real regression).

Run with:

    python3 -m unittest discover -s tests/perf -p 'test_*.py'
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "check_regression.py")


def _write_summary(root: str, platform: str, scenario: str, **overrides) -> None:
    summary = {
        "duration_s": 300.0,
        "samples": 300,
        "interval_s": 1.0,
        "cpu_percent_avg": 40.0,
        "cpu_percent_max": 120.0,
        "cpu_percent_p95": 100.0,
        "rss_mb_avg": 400.0,
        "rss_mb_max": 900.0,
        "scenario": scenario,
    }
    summary.update(overrides)
    d = os.path.join(root, platform, scenario)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "summary.json"), "w", encoding="utf-8") as fh:
        json.dump(summary, fh)


def _run_gate(current: str, baseline: str) -> tuple[int, str]:
    proc = subprocess.run(
        [sys.executable, SCRIPT, "--current", current, "--baseline", baseline, "--threshold", "1.00"],
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.returncode, proc.stdout


class SamplerIntegrityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.cur = os.path.join(self.tmp.name, "current")
        self.base = os.path.join(self.tmp.name, "baseline")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_healthy_pair_passes(self) -> None:
        _write_summary(self.cur, "windows-x64", "all")
        _write_summary(self.base, "windows-x64", "all")
        rc, out = _run_gate(self.cur, self.base)
        self.assertEqual(rc, 0, out)
        self.assertIn("PASS", out)
        self.assertNotIn("sampler", out)

    def test_bursting_baseline_is_skipped_not_compared(self) -> None:
        # The posture run 34019482048 windows-x64 `all` shape: 3,320 samples
        # in 300 s and a diluted 9.8% CPU average. A healthy 43% current run
        # must not be reported as a +343% regression against it.
        _write_summary(self.cur, "windows-x64", "all", cpu_percent_avg=43.4)
        _write_summary(self.base, "windows-x64", "all", samples=3320, cpu_percent_avg=9.8)
        rc, out = _run_gate(self.cur, self.base)
        self.assertEqual(rc, 0, out)
        self.assertIn("WARN", out)
        self.assertIn("sampler burst", out)
        self.assertIn("PASS", out)
        self.assertNotIn("+343", out)

    def test_bursting_current_fails_even_without_regression(self) -> None:
        _write_summary(self.cur, "windows-x64", "all", samples=3320, cpu_percent_avg=9.8)
        _write_summary(self.base, "windows-x64", "all")
        rc, out = _run_gate(self.cur, self.base)
        self.assertEqual(rc, 1, out)
        self.assertIn("FAIL", out)
        self.assertIn("CURRENT run failed sampler integrity", out)

    def test_stalled_current_fails(self) -> None:
        _write_summary(self.cur, "ubuntu-x64", "capture", samples=120)
        _write_summary(self.base, "ubuntu-x64", "capture")
        rc, out = _run_gate(self.cur, self.base)
        self.assertEqual(rc, 1, out)
        self.assertIn("sampler stalled", out)

    def test_real_regression_still_fails(self) -> None:
        _write_summary(self.cur, "ubuntu-x64", "idle", cpu_percent_avg=30.0, rss_mb_avg=400.0)
        _write_summary(self.base, "ubuntu-x64", "idle", cpu_percent_avg=5.0, rss_mb_avg=400.0)
        rc, out = _run_gate(self.cur, self.base)
        self.assertEqual(rc, 1, out)
        self.assertIn("regressed beyond", out)

    def test_hub_idle_360s_window_is_healthy(self) -> None:
        # run_scenario.sh bumps hub_idle to 360 s; 360 samples is the
        # expected count, not a burst.
        _write_summary(self.cur, "macos-arm64", "hub_idle", duration_s=360.0, samples=360)
        _write_summary(self.base, "macos-arm64", "hub_idle", duration_s=360.0, samples=360)
        rc, out = _run_gate(self.cur, self.base)
        self.assertEqual(rc, 0, out)
        self.assertNotIn("sampler", out)


if __name__ == "__main__":
    unittest.main()
