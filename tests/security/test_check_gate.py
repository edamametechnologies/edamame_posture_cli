#!/usr/bin/env python3
"""Regression tests for the security release gate (``check_gate.py``).

The gate decides whether a release ships, so every way it can read a
non-detection as a pass is a security regression. These tests pin the
fail-closed contract:

- a skipped *required* scenario blocks,
- a scenario that "passed" with zero alertable findings blocks (an
  adjudicator-demotable scenario: unless the detector graded it alertable and
  the adjudicator DEMOTEd it),
- a scenario that "passed" with no ``finding_alertable`` field blocks,
- an expected platform that produced no directory at all blocks,
- a missing ``results.json`` after a clean baseline blocks,
- an unreadable artifact blocks,
- a dirty idle baseline blocks,
- a missing, unreadable or failed kernel-ancestry check (``lineage.json``)
  blocks, and so does a ``status=pass`` without its checks,
- and only a complete, all-alertable, clean-baseline run with kernel
  ancestry resolved on every platform passes.

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


UNMEASURED_BASELINE = {
    "status": "unmeasured",
    "finding_total": 0,
    "finding_current": 0,
    "finding_history": 0,
    "first_finding_sample": "",
    "adjudication": {
        "ticks": 14,
        "withheld_ticks": 14,
        "mode": "llm",
        "last_status": "error",
        "last_raw_candidates": 3,
        "measured": False,
    },
}


# run_lineage_gate.py's verdict when edl_c -> edl_p -> python resolved.
PASSING_LINEAGE = {
    "status": "pass",
    "platform": "test",
    "checks": {
        "probe_answered": True,
        "child_recorded": True,
        "child_image": True,
        "ppid_not_self": True,
        "ppid_is_parent": True,
        "ancestry_parent": True,
        "ancestry_interpreter": True,
        "stream_names_parents": True,
        "no_self_parent_events": True,
        "status_no_self_parent_events": True,
    },
    "chain": {"interpreter_pid": 100, "parent_pid": 200, "child_pid": 300},
    "attempts": 1,
}

# The pre-2.0.5 macOS shape: every exec named itself as its parent.
FAILED_LINEAGE = {
    "status": "fail",
    "platform": "test",
    "reason": "edl_c (pid 300) is recorded with ppid 300: no parent, or itself",
    "checks": {**PASSING_LINEAGE["checks"], "ppid_not_self": False, "ppid_is_parent": False},
    "attempts": 48,
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

    def run_gate(
        self, platforms: dict, required: str = "", expected: str = ""
    ) -> tuple[int, str]:
        """Materialize ``platforms`` on disk and return ``(exit_code, stdout)``.

        ``platforms`` maps a platform label to a dict of artifact name ->
        payload. A dict payload is JSON-encoded; a string payload is written
        verbatim (used to inject unparseable JSON); ``None`` omits the file.
        A platform that names no ``lineage.json`` gets a passing one, so the
        tests of the other artifacts read only their own failure; an empty
        platform dict stays empty.
        """
        with tempfile.TemporaryDirectory() as tmp:
            for label, artifacts in platforms.items():
                pdir = os.path.join(tmp, label)
                os.makedirs(pdir, exist_ok=True)
                if artifacts and "lineage.json" not in artifacts:
                    artifacts = {**artifacts, "lineage.json": PASSING_LINEAGE}
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
                    "--expected-platforms",
                    expected,
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
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

    def test_pass_without_alertable_field_blocks(self):
        """A results.json missing finding_alertable is absent evidence.

        run_cve_detection.sh records the field on every result path and the
        gate only ever reads same-run artifacts, so an absent field means a
        malformed or hand-edited artifact -- which must not read as a pass.
        """
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
        self.assertEqual(rc, 1, out)
        self.assertIn("finding_alertable", out)

    def test_expected_platform_with_no_directory_blocks(self):
        """A matrix leg that produced no directory at all must block.

        The gate enumerates the directories that exist, so without the
        expected-platform list a cancelled or timed-out leg silently drops
        out of the gate and the run passes on the platforms that reported.
        """
        rc, out = self.run_gate(
            {
                "macos-arm64": {
                    "baseline.json": CLEAN_BASELINE,
                    "results.json": results(scenario("cve_token_exfil")),
                }
            },
            required="cve_token_exfil",
            expected="macos-arm64,windows-x64",
        )
        self.assertEqual(rc, 1, out)
        self.assertIn("windows-x64", out)
        self.assertIn("no results directory", out)

    def test_all_expected_platforms_present_passes(self):
        rc, out = self.run_gate(
            {
                "macos-arm64": {
                    "baseline.json": CLEAN_BASELINE,
                    "results.json": results(scenario("cve_token_exfil")),
                },
                "windows-x64": {
                    "baseline.json": CLEAN_BASELINE,
                    "results.json": results(scenario("cve_token_exfil")),
                },
            },
            required="cve_token_exfil",
            expected="macos-arm64,windows-x64",
        )
        self.assertEqual(rc, 0, out)
        self.assertIn("PASS", out)

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

    def _file_events(self, demoted):
        out = scenario(
            "file_events",
            check="file_system_tampering",
            findings=3,
            alertable=0,
            severities="LOW:3",
        )
        if demoted is not None:
            out["finding_adjudicator_demoted"] = demoted
        return out

    def test_adjudicator_demote_of_an_alertable_grade_passes(self):
        """file_events: the detector alerted, the adjudicator lowered it."""
        rc, out = self.run_gate(
            {
                "macos-arm64": {
                    "baseline.json": CLEAN_BASELINE,
                    "results.json": results(self._file_events(1)),
                }
            },
            required="file_events",
        )
        self.assertEqual(rc, 0, out)
        self.assertIn("1 with an alertable grade the adjudicator lowered", out)

    def test_a_grade_the_detector_lowered_still_blocks(self):
        for demoted in (0, None):
            rc, out = self.run_gate(
                {
                    "macos-arm64": {
                        "baseline.json": CLEAN_BASELINE,
                        "results.json": results(self._file_events(demoted)),
                    }
                },
                required="file_events",
            )
            self.assertEqual(rc, 1, out)
            self.assertIn("pass_without_alert_or_adjudicator_demote", out)

    def test_artifact_cannot_make_another_scenario_demotable(self):
        """The gate reads its own list, not fields of results.json."""
        demoted = scenario(
            "cve_sandbox_escape", findings=3, alertable=0, severities="LOW:3"
        )
        demoted["requirement"] = "alert_or_adjudicator_demote"
        demoted["finding_adjudicator_demoted"] = 3
        rc, out = self.run_gate(
            {
                "macos-arm64": {
                    "baseline.json": CLEAN_BASELINE,
                    "results.json": results(demoted),
                }
            },
            required="cve_sandbox_escape",
        )
        self.assertEqual(rc, 1, out)
        self.assertIn("pass_without_alertable_finding", out)

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

    def test_unmeasured_baseline_blocks_on_baseline_only(self):
        """A withheld last tick is not a clean host; the CVE suite was skipped."""
        rc, out = self.run_gate(
            {
                "windows-x64": {
                    "baseline.json": UNMEASURED_BASELINE,
                    "results.json": None,
                }
            },
            required="cve_token_exfil",
        )
        self.assertEqual(rc, 1, out)
        self.assertIn("unmeasured", out)
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


class TestLineageGate(GateTestCase):
    """The kernel process-ancestry check is a hard gate on every platform."""

    def _platform(self, lineage, baseline=CLEAN_BASELINE, with_results=True):
        out = {"baseline.json": baseline, "lineage.json": lineage}
        out["results.json"] = results(scenario("cve_token_exfil")) if with_results else None
        return out

    def test_resolved_ancestry_on_every_platform_passes(self):
        rc, out = self.run_gate(
            {
                "macos-arm64": self._platform(PASSING_LINEAGE),
                "windows-x64": self._platform(PASSING_LINEAGE),
            },
            required="cve_token_exfil",
            expected="macos-arm64,windows-x64",
        )
        self.assertEqual(rc, 0, out)
        self.assertIn("### Kernel process ancestry", out)
        self.assertIn("2/2 platforms resolved", out)

    def test_failed_ancestry_blocks(self):
        rc, out = self.run_gate(
            {
                "macos-arm64": self._platform(FAILED_LINEAGE),
                "ubuntu-x64": self._platform(PASSING_LINEAGE),
            },
            required="cve_token_exfil",
        )
        self.assertEqual(rc, 1, out)
        self.assertIn("| macos-arm64 | status=fail: edl_c (pid 300)", out)
        self.assertIn("1 kernel-ancestry check(s)", out)

    def test_missing_lineage_blocks(self):
        rc, out = self.run_gate(
            {"ubuntu-arm64": self._platform(None)},
            required="cve_token_exfil",
        )
        self.assertEqual(rc, 1, out)
        self.assertIn("`lineage.json`", out)
        self.assertIn("never ran", out)

    def test_unreadable_lineage_blocks(self):
        rc, out = self.run_gate(
            {"windows-x64": self._platform('{"status": "pass", "checks": {')},
            required="cve_token_exfil",
        )
        self.assertEqual(rc, 1, out)
        self.assertIn("lineage.json", out)
        self.assertIn("unreadable", out)

    def test_pass_without_checks_blocks(self):
        for lineage in (
            {"status": "pass"},
            {"status": "pass", "checks": {}},
            {"status": "pass", "checks": {**PASSING_LINEAGE["checks"], "ancestry_parent": False}},
            {"status": "pass", "checks": {**PASSING_LINEAGE["checks"], "child_recorded": "yes"}},
        ):
            rc, out = self.run_gate(
                {"macos-arm64": self._platform(lineage)},
                required="cve_token_exfil",
            )
            self.assertEqual(rc, 1, (lineage, out))
            self.assertIn("status=pass", out)

    def test_failed_ancestry_blocks_whatever_the_baseline_did(self):
        """The check runs before the baseline: a dirty or unmeasured baseline
        (which skips the CVE suite) does not excuse it."""
        for baseline in (DIRTY_BASELINE, UNMEASURED_BASELINE):
            rc, out = self.run_gate(
                {"ubuntu-x64": self._platform(FAILED_LINEAGE, baseline, with_results=False)},
                required="cve_token_exfil",
            )
            self.assertEqual(rc, 1, out)
            self.assertIn("status=fail", out)
            rc, out = self.run_gate(
                {"ubuntu-x64": self._platform(None, baseline, with_results=False)},
                required="cve_token_exfil",
            )
            self.assertEqual(rc, 1, out)
            self.assertIn("`lineage.json`", out)


class TestWarmBaselineAdvisory(unittest.TestCase):
    """The warm-host baseline (step 7.1) is advisory: it renders its own row in
    the report but NEVER changes the gate's exit code."""

    def _run_with_warm(
        self, warm: dict | None
    ) -> tuple[int, str]:
        # results-dir and warm-baseline-dir are SEPARATE sibling trees (as staged
        # by the security-report job), so the warm platforms never enter the
        # strict per-platform scan.
        with tempfile.TemporaryDirectory() as results_root, \
                tempfile.TemporaryDirectory() as warm_root:
            # One clean, complete platform so the strict gate would pass on its own.
            pdir = os.path.join(results_root, "ubuntu-x64")
            os.makedirs(pdir)
            with open(os.path.join(pdir, "baseline.json"), "w", encoding="utf-8") as fh:
                json.dump(CLEAN_BASELINE, fh)
            with open(os.path.join(pdir, "results.json"), "w", encoding="utf-8") as fh:
                json.dump(results(scenario("cve_token_exfil")), fh)
            with open(os.path.join(pdir, "lineage.json"), "w", encoding="utf-8") as fh:
                json.dump(PASSING_LINEAGE, fh)

            args = [
                sys.executable,
                GATE,
                "--results-dir",
                results_root,
                "--required-scenarios",
                "cve_token_exfil",
                "--expected-platforms",
                "ubuntu-x64",
            ]
            if warm is not None:
                for label, baseline in warm.items():
                    wdir = os.path.join(warm_root, label)
                    os.makedirs(wdir)
                    with open(os.path.join(wdir, "baseline.json"), "w", encoding="utf-8") as fh:
                        json.dump(baseline, fh)
                args += ["--warm-baseline-dir", warm_root]
            proc = subprocess.run(args, capture_output=True, text=True, encoding="utf-8", errors="replace")
        return proc.returncode, proc.stdout + proc.stderr

    def test_dirty_warm_baseline_is_advisory_not_blocking(self):
        # A DIRTY warm baseline must NOT block: the strict gate still passes and
        # the advisory section marks the warm platform DIRTY.
        rc, out = self._run_with_warm(
            {"warm-linux": DIRTY_BASELINE, "warm-windows": CLEAN_BASELINE}
        )
        self.assertEqual(rc, 0, out)
        self.assertIn("Warm-host baseline (advisory, non-gating)", out)
        self.assertIn("DIRTY", out)

    def test_absent_warm_dir_still_passes(self):
        rc, out = self._run_with_warm(None)
        self.assertEqual(rc, 0, out)
        self.assertIn("Warm-host baseline (advisory, non-gating)", out)


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
