#!/usr/bin/env python3
"""Regression tests for the security release gate (``check_gate.py``).

The gate decides whether a release ships, so every way it can read a
non-detection as a pass is a security regression. These tests pin the
fail-closed contract:

- a skipped *required* scenario blocks,
- a scenario that "passed" with zero alertable findings blocks,
- a missing ``results.json`` after a clean baseline blocks,
- an unreadable artifact blocks,
- a dirty idle baseline blocks,
- and only a complete, all-alertable, clean-baseline run passes.

Run with::

    python3 -m unittest discover -s tests/security -p 'test_*.py'
    python3 tests/security/test_check_gate.py
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
GATE = os.path.join(HERE, "check_gate.py")

CLEAN_BASELINE = {
    "status": "pass",
    "finding_total": 0,
    "finding_current": 0,
    "finding_history": 0,
    "first_finding_sample": "",
}

DIRTY_BASELINE = {
    "status": "fail",
    "finding_total": 2,
    "finding_current": 2,
    "finding_history": 0,
    "first_finding_sample": "sandbox_exploitation:/tmp/rustup-init",
}


def scenario(
    name: str,
    status: str = "pass",
    *,
    check: str = "token_exfiltration",
    findings: int = 1,
    alertable: int | None = 1,
    severities: str = "HIGH:1",
    extra: str = "",
) -> dict:
    out = {
        "scenario": name,
        "status": status,
        "expected_check": check,
        "finding_total": findings,
        "severities": severities,
        "extra": extra,
    }
    if alertable is not None:
        out["finding_alertable"] = alertable
    return out


def results(*scenarios: dict) -> dict:
    passed = sum(1 for s in scenarios if s["status"] == "pass")
    failed = sum(1 for s in scenarios if s["status"] == "fail")
    skipped = sum(1 for s in scenarios if s["status"] == "skip")
    return {
        "scenarios": list(scenarios),
        "totals": {
            "passed": passed,
            "failed": failed,
            "skipped": skipped,
            "total": len(scenarios),
        },
    }


class GateTestCase(unittest.TestCase):
    """Drives check_gate.py as a subprocess against synthetic artifacts."""

    def run_gate(self, platforms: dict, required: str = "") -> tuple[int, str]:
        """Materialize ``platforms`` on disk and return ``(exit_code, stdout)``.

        ``platforms`` maps a platform label to a dict of artifact name ->
        payload. A dict payload is JSON-encoded; a string payload is written
        verbatim (used to inject unparseable JSON); ``None`` omits the file.
        """
        with tempfile.TemporaryDirectory() as tmp:
            for label, artifacts in platforms.items():
                pdir = os.path.join(tmp, label)
                os.makedirs(pdir, exist_ok=True)
                for fname, payload in artifacts.items():
                    if payload is None:
                        continue
                    path = os.path.join(pdir, fname)
                    with open(path, "w", encoding="utf-8") as fh:
                        if isinstance(payload, str):
                            fh.write(payload)
                        else:
                            json.dump(payload, fh)
            proc = subprocess.run(
                [
                    sys.executable,
                    GATE,
                    "--results-dir",
                    tmp,
                    "--required-scenarios",
                    required,
                ],
                capture_output=True,
                text=True,
            )
        return proc.returncode, proc.stdout + proc.stderr


class TestGatePasses(GateTestCase):
    def test_complete_run_with_alertable_findings_passes(self):
        rc, out = self.run_gate(
            {
                "macos-arm64": {
                    "baseline.json": CLEAN_BASELINE,
                    "results.json": results(
                        scenario("cve_token_exfil"), scenario("temp_modify")
                    ),
                },
                "ubuntu-x64": {
                    "baseline.json": CLEAN_BASELINE,
                    "results.json": results(
                        scenario("cve_token_exfil"), scenario("temp_modify")
                    ),
                },
            },
            required="cve_token_exfil,temp_modify",
        )
        self.assertEqual(rc, 0, out)
        self.assertIn("PASS", out)

    def test_legacy_results_without_alertable_field_passes(self):
        """Artifacts predating finding_alertable must not spuriously fail."""
        rc, out = self.run_gate(
            {
                "macos-arm64": {
                    "baseline.json": CLEAN_BASELINE,
                    "results.json": results(
                        scenario("cve_token_exfil", alertable=None)
                    ),
                }
            },
            required="cve_token_exfil",
        )
        self.assertEqual(rc, 0, out)

    def test_non_required_skip_is_tolerated(self):
        rc, out = self.run_gate(
            {
                "macos-arm64": {
                    "baseline.json": CLEAN_BASELINE,
                    "results.json": results(
                        scenario("cve_token_exfil"),
                        scenario("experimental_probe", status="skip", findings=0),
                    ),
                }
            },
            required="cve_token_exfil",
        )
        self.assertEqual(rc, 0, out)


class TestGateFailsClosed(GateTestCase):
    def test_required_scenario_skipped_blocks(self):
        rc, out = self.run_gate(
            {
                "macos-arm64": {
                    "baseline.json": CLEAN_BASELINE,
                    "results.json": results(
                        scenario(
                            "skill_supply_chain",
                            status="skip",
                            findings=0,
                            alertable=0,
                            extra="no trigger script",
                        )
                    ),
                }
            },
            required="skill_supply_chain",
        )
        self.assertEqual(rc, 1, out)
        self.assertIn("skill_supply_chain", out)

    def test_required_scenario_absent_blocks(self):
        rc, out = self.run_gate(
            {
                "macos-arm64": {
                    "baseline.json": CLEAN_BASELINE,
                    "results.json": results(scenario("cve_token_exfil")),
                }
            },
            required="cve_token_exfil,nonsensitive_path",
        )
        self.assertEqual(rc, 1, out)
        self.assertIn("nonsensitive_path", out)

    def test_pass_without_alertable_finding_blocks(self):
        """A CRS/LLM demotion to LOW must not read as a detection."""
        rc, out = self.run_gate(
            {
                "macos-arm64": {
                    "baseline.json": CLEAN_BASELINE,
                    "results.json": results(
                        scenario(
                            "cve_sandbox_escape",
                            findings=3,
                            alertable=0,
                            severities="LOW:3",
                        )
                    ),
                }
            },
            required="cve_sandbox_escape",
        )
        self.assertEqual(rc, 1, out)
        self.assertIn("alertable", out.lower())

    def test_scenario_failure_blocks(self):
        rc, out = self.run_gate(
            {
                "macos-arm64": {
                    "baseline.json": CLEAN_BASELINE,
                    "results.json": results(
                        scenario(
                            "memory_poisoning",
                            status="fail",
                            findings=0,
                            alertable=0,
                            severities="-",
                        )
                    ),
                }
            },
            required="memory_poisoning",
        )
        self.assertEqual(rc, 1, out)

    def test_unknown_status_blocks(self):
        rc, out = self.run_gate(
            {
                "macos-arm64": {
                    "baseline.json": CLEAN_BASELINE,
                    "results.json": results(scenario("file_events", status="error")),
                }
            },
            required="file_events",
        )
        self.assertEqual(rc, 1, out)

    def test_missing_results_with_clean_baseline_blocks(self):
        """CVE step crashed or timed out: no evidence is not a pass."""
        rc, out = self.run_gate(
            {
                "windows-x64": {
                    "baseline.json": CLEAN_BASELINE,
                    "results.json": None,
                }
            },
            required="cve_token_exfil",
        )
        self.assertEqual(rc, 1, out)
        self.assertIn("results.json", out)

    def test_missing_results_with_dirty_baseline_blocks_on_baseline_only(self):
        """A dirty baseline deliberately skips the CVE suite."""
        rc, out = self.run_gate(
            {
                "ubuntu-arm64": {
                    "baseline.json": DIRTY_BASELINE,
                    "results.json": None,
                }
            },
            required="cve_token_exfil",
        )
        self.assertEqual(rc, 1, out)
        self.assertIn("DIRTY", out)
        # The absent results.json is expected here, so it must not be
        # reported as a separate missing-artifact failure.
        self.assertNotIn("CVE step crashed", out)

    def test_missing_baseline_blocks(self):
        rc, out = self.run_gate(
            {
                "macos-arm64": {
                    "baseline.json": None,
                    "results.json": results(scenario("cve_token_exfil")),
                }
            },
            required="cve_token_exfil",
        )
        self.assertEqual(rc, 1, out)
        self.assertIn("baseline.json", out)

    def test_unreadable_results_blocks(self):
        rc, out = self.run_gate(
            {
                "macos-arm64": {
                    "baseline.json": CLEAN_BASELINE,
                    "results.json": '{"scenarios": [ truncated',
                }
            },
            required="cve_token_exfil",
        )
        self.assertEqual(rc, 1, out)
        self.assertIn("unreadable", out)

    def test_unreadable_baseline_blocks(self):
        rc, out = self.run_gate(
            {
                "macos-arm64": {
                    "baseline.json": "not json at all",
                    "results.json": results(scenario("cve_token_exfil")),
                }
            },
            required="cve_token_exfil",
        )
        self.assertEqual(rc, 1, out)
        self.assertIn("unreadable", out)

    def test_dirty_baseline_blocks_even_with_all_scenarios_passing(self):
        rc, out = self.run_gate(
            {
                "macos-arm64": {
                    "baseline.json": DIRTY_BASELINE,
                    "results.json": results(scenario("cve_token_exfil")),
                }
            },
            required="cve_token_exfil",
        )
        self.assertEqual(rc, 1, out)
        self.assertIn("DIRTY", out)

    def test_one_bad_platform_blocks_the_whole_gate(self):
        rc, out = self.run_gate(
            {
                "macos-arm64": {
                    "baseline.json": CLEAN_BASELINE,
                    "results.json": results(scenario("cve_token_exfil")),
                },
                "windows-x64": {
                    "baseline.json": CLEAN_BASELINE,
                    "results.json": results(
                        scenario(
                            "cve_token_exfil",
                            status="fail",
                            findings=0,
                            alertable=0,
                        )
                    ),
                },
            },
            required="cve_token_exfil",
        )
        self.assertEqual(rc, 1, out)
        self.assertIn("windows-x64", out)


class TestGateInputErrors(GateTestCase):
    def test_empty_results_dir_is_an_error_not_a_pass(self):
        rc, out = self.run_gate({}, required="cve_token_exfil")
        self.assertEqual(rc, 2, out)

    def test_platform_dir_with_no_artifacts_blocks(self):
        rc, out = self.run_gate(
            {"macos-arm64": {}},
            required="cve_token_exfil",
        )
        self.assertIn(rc, (1, 2), out)
        self.assertNotEqual(rc, 0, out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
