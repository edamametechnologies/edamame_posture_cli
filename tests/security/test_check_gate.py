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

Reported without changing the verdict: the run attempt of each platform's
results (``run_stamp.json``), and the raw candidates of a clean idle
baseline, which fail the gate only with ``--fail-on-idle-raw-candidates``.

Run with::

    python3 -m unittest discover -s tests/security -p 'test_*.py'
    python3 tests/security/test_check_gate.py
"""

from __future__ import annotations

import json
import os
import shutil
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
        self, platforms: dict, required: str = "", expected: str = "", **kwargs
    ) -> tuple[int, str]:
        """Materialize ``platforms`` on disk and return ``(exit_code, stdout)``.

        ``platforms`` maps a platform label to a dict of artifact name ->
        payload. A dict payload is JSON-encoded; a string payload is written
        verbatim (used to inject unparseable JSON); ``None`` omits the file.
        A platform that names no ``lineage.json`` gets a passing one, so the
        tests of the other artifacts read only their own failure; an empty
        platform dict stays empty. ``kwargs`` go to ``run_gate_summary``.
        """
        rc, out, _summary = self.run_gate_summary(platforms, required, expected, **kwargs)
        return rc, out

    def run_gate_summary(
        self,
        platforms: dict,
        required: str = "",
        expected: str = "",
        extra_args: tuple = (),
        report_attempt: str | None = None,
    ) -> tuple[int, str, dict | None]:
        """``run_gate`` plus the ``--summary-json`` file the gate wrote.
        ``extra_args`` are added to the command line; ``report_attempt`` is
        the GITHUB_RUN_ATTEMPT of the report (unset when ``None``)."""
        env = {k: v for k, v in os.environ.items() if k != "GITHUB_RUN_ATTEMPT"}
        if report_attempt is not None:
            env["GITHUB_RUN_ATTEMPT"] = report_attempt
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as out_dir:
            summary_path = os.path.join(out_dir, "gate-summary.json")
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
                    "--summary-json",
                    summary_path,
                    *extra_args,
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                env=env,
            )
            summary = None
            if os.path.isfile(summary_path):
                with open(summary_path, encoding="utf-8") as fh:
                    summary = json.load(fh)
        return proc.returncode, proc.stdout + proc.stderr, summary


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

    def test_expected_clean_scenario_passes_quiet_and_fails_with_a_finding(self):
        """An expected-clean scenario (the harness's list) passes with zero
        alertable findings and nothing else; its runner records
        `clean_as_expected`."""
        quiet = scenario("poisoned_mcp_tool_maintenance_control", check="policy:evaluator_integrity",
                         findings=0, alertable=0, severities="none", extra="clean_as_expected")
        rc, out = self.run_gate(
            {"macos-arm64": {"baseline.json": CLEAN_BASELINE, "results.json": results(quiet)}},
            required="poisoned_mcp_tool_maintenance_control",
        )
        self.assertEqual(rc, 0, out)
        self.assertIn("1 expected-clean scenario(s) stayed clean", out)

        noisy = scenario("poisoned_mcp_tool_maintenance_control", check="policy:evaluator_integrity",
                         findings=1, alertable=1, severities="HIGH:1")
        rc, out = self.run_gate(
            {"macos-arm64": {"baseline.json": CLEAN_BASELINE, "results.json": results(noisy)}},
            required="poisoned_mcp_tool_maintenance_control",
        )
        self.assertEqual(rc, 1, out)
        self.assertIn("pass_with_finding_on_expected_clean_scenario", out)

        failed = scenario("poisoned_mcp_tool_maintenance_control", status="fail",
                          check="policy:evaluator_integrity", findings=2, alertable=0,
                          severities="none", extra="finding_on_expected_clean_scenario")
        rc, out = self.run_gate(
            {"macos-arm64": {"baseline.json": CLEAN_BASELINE, "results.json": results(failed)}},
            required="poisoned_mcp_tool_maintenance_control",
        )
        self.assertEqual(rc, 1, out)
        self.assertIn("finding_on_expected_clean_scenario", out)

    def test_artifact_cannot_declare_itself_expected_clean(self):
        """A quiet pass on a must-fire scenario still blocks: the clean list is
        the harness's, never a field of results.json."""
        quiet = scenario("poisoned_mcp_tool_two_sessions", check="policy:evaluator_integrity",
                         findings=0, alertable=0, severities="none", extra="clean_as_expected")
        rc, out = self.run_gate(
            {"macos-arm64": {"baseline.json": CLEAN_BASELINE, "results.json": results(quiet)}},
            required="poisoned_mcp_tool_two_sessions",
        )
        self.assertEqual(rc, 1, out)
        self.assertIn("pass_without_alertable_finding", out)

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


def stamp(attempt: object) -> dict:
    """``run_stamp.json`` as the ``security`` job writes it."""
    return {"run_id": 42, "run_attempt": attempt, "platform": "test", "job": "security"}


def clean_platform(attempt: object = None, baseline: dict = CLEAN_BASELINE) -> dict:
    """A platform that passes the gate, stamped with ``attempt`` (unless None)."""
    out = {"baseline.json": baseline, "results.json": results(scenario("cve_token_exfil"))}
    if attempt is not None:
        out["run_stamp.json"] = stamp(attempt)
    return out


def baseline_with_raw(ticks_with: int, peak: int, ticks: int = 12, base: dict = CLEAN_BASELINE) -> dict:
    """A baseline.json with the idle window's raw candidate counts."""
    return {
        **base,
        "raw_candidates_max": peak,
        "ticks_with_raw_candidates": ticks_with,
        "adjudication": {"ticks": ticks, "withheld_ticks": 0, "mode": "llm", "last_status": "adjudicated"},
    }


class TestRunAttempts(GateTestCase):
    """The attempt each platform's results come from is reported, never gated."""

    def test_single_attempt_lists_each_platform_without_a_note(self):
        rc, out, summary = self.run_gate_summary(
            {"macos-arm64": clean_platform(1), "windows-x64": clean_platform(1)},
            required="cve_token_exfil",
            expected="macos-arm64,windows-x64",
        )
        self.assertEqual(rc, 0, out)
        self.assertIn("### Run attempts", out)
        self.assertIn("- macos-arm64: attempt 1", out)
        self.assertIn("- windows-x64: attempt 1", out)
        self.assertNotIn("NOTE: the platform results come from", out)
        self.assertEqual(summary["verdict"], "pass")
        self.assertEqual(summary["attempts"]["platforms"], {"macos-arm64": 1, "windows-x64": 1})
        self.assertFalse(summary["attempts"]["mixed"])
        self.assertFalse(summary["attempts"]["rerun"])

    def test_mixed_attempts_get_a_note_and_keep_the_verdict(self):
        rc, out, summary = self.run_gate_summary(
            {
                "macos-arm64": clean_platform(1),
                "ubuntu-arm64": clean_platform(2),
                "windows-x64": clean_platform(1),
            },
            required="cve_token_exfil",
            report_attempt="2",
        )
        self.assertEqual(rc, 0, out)
        self.assertIn("- ubuntu-arm64: attempt 2", out)
        self.assertIn("- this report: attempt 2", out)
        self.assertIn(
            "NOTE: the platform results come from different attempts of this run"
            " (attempt 1: macos-arm64, windows-x64; attempt 2: ubuntu-arm64)",
            out,
        )
        self.assertIn("PASS - kernel ancestry resolved", out)
        self.assertEqual(summary["verdict"], "pass")
        attempts = summary["attempts"]
        self.assertEqual(
            (attempts["mixed"], attempts["rerun"], attempts["distinct"], attempts["report"]),
            (True, True, [1, 2], 2),
        )
        self.assertEqual(len(summary["notes"]), 1)

    def test_every_platform_from_a_later_attempt_gets_a_note(self):
        rc, out, summary = self.run_gate_summary(
            {"macos-arm64": clean_platform(2), "windows-x64": clean_platform(2)},
            required="cve_token_exfil",
        )
        self.assertEqual(rc, 0, out)
        self.assertIn(
            "NOTE: the platform results come from attempt 2 of this run, not from its first attempt", out
        )
        self.assertEqual((summary["attempts"]["mixed"], summary["attempts"]["rerun"]), (False, True))

    def test_a_failing_gate_reports_attempts_too(self):
        rc, out, summary = self.run_gate_summary(
            {
                "macos-arm64": clean_platform(1),
                "windows-x64": clean_platform(2, baseline=DIRTY_BASELINE),
            },
            required="cve_token_exfil",
        )
        self.assertEqual(rc, 1, out)
        self.assertIn("NOTE: the platform results come from different attempts", out)
        self.assertEqual(summary["verdict"], "fail")
        self.assertEqual(summary["failures"]["baselines"], 1)
        self.assertTrue(summary["attempts"]["mixed"])

    def test_a_missing_or_malformed_stamp_is_not_an_attempt(self):
        for bad in (None, {"run_attempt": "x"}, {"run_attempt": 0}, {"run_attempt": True}, "not json"):
            platform = clean_platform(None)
            if bad is not None:
                platform["run_stamp.json"] = bad
            rc, out, summary = self.run_gate_summary(
                {"macos-arm64": clean_platform(1), "windows-x64": platform},
                required="cve_token_exfil",
            )
            self.assertEqual(rc, 0, (bad, out))
            self.assertIn("- windows-x64: attempt not recorded", out)
            self.assertIn("NOTE: no attempt is recorded for windows-x64", out)
            self.assertIsNone(summary["attempts"]["platforms"]["windows-x64"])
            self.assertEqual(summary["attempts"]["unstamped"], ["windows-x64"])

    def test_a_stamp_written_as_a_string_is_read(self):
        platform = clean_platform(None)
        platform["run_stamp.json"] = {"run_attempt": "3"}
        rc, out, summary = self.run_gate_summary({"macos-arm64": platform}, required="cve_token_exfil")
        self.assertEqual(rc, 0, out)
        self.assertEqual(summary["attempts"]["platforms"], {"macos-arm64": 3})

    def test_an_error_exit_still_writes_the_summary(self):
        rc, out, summary = self.run_gate_summary({}, required="cve_token_exfil")
        self.assertEqual(rc, 2, out)
        self.assertEqual((summary["verdict"], summary["exit_code"]), ("error", 2))


class TestIdleRawCandidates(GateTestCase):
    """Raw candidates of a clean idle baseline: counts reported with a NOTE,
    a failure only with --fail-on-idle-raw-candidates."""

    STRICT = ("--fail-on-idle-raw-candidates",)

    def platforms(self, ubuntu_baseline: dict) -> dict:
        return {
            "macos-arm64": clean_platform(1, baseline_with_raw(0, 0)),
            "ubuntu-x64": clean_platform(1, ubuntu_baseline),
        }

    def test_quieted_candidates_are_reported_and_the_verdict_stays(self):
        rc, out, summary = self.run_gate_summary(
            self.platforms(baseline_with_raw(3, 2)), required="cve_token_exfil"
        )
        self.assertEqual(rc, 0, out)
        self.assertIn("CLEAN - 2/2 platforms", out)
        self.assertIn(
            "- ubuntu-x64 (clean baseline): 3 of 12 tick(s) had raw candidates, at most 2 on one tick", out
        )
        self.assertIn("- macos-arm64 (clean baseline): none in 12 tick(s)", out)
        self.assertIn("NOTE: 1 platform(s) (ubuntu-x64) had raw candidates on an idle runner", out)
        self.assertIn("This does not change the verdict", out)
        self.assertEqual(summary["verdict"], "pass")
        raw = summary["idle_raw_candidates"]
        self.assertEqual(raw["quieted"], ["ubuntu-x64"])
        self.assertFalse(raw["fail_on_idle_raw_candidates"])
        self.assertEqual(
            raw["platforms"]["ubuntu-x64"],
            {"baseline": "clean", "recorded": True, "ticks": 12,
             "ticks_with_raw_candidates": 3, "raw_candidates_max": 2},
        )
        self.assertEqual(summary["failures"]["idle_raw_candidates"], 0)

    def test_the_flag_fails_the_gate_on_quieted_candidates(self):
        rc, out, summary = self.run_gate_summary(
            self.platforms(baseline_with_raw(3, 2)), required="cve_token_exfil", extra_args=self.STRICT
        )
        self.assertEqual(rc, 1, out)
        self.assertIn("1 idle baseline(s) with raw candidates (--fail-on-idle-raw-candidates)", out)
        self.assertIn("| ubuntu-x64 | 3 idle tick(s) had raw candidates (at most 2 on one tick)", out)
        self.assertIn("`--fail-on-idle-raw-candidates` is set: this fails the gate.", out)
        self.assertEqual((summary["verdict"], summary["failures"]["idle_raw_candidates"]), ("fail", 1))
        self.assertTrue(summary["idle_raw_candidates"]["fail_on_idle_raw_candidates"])

    def test_no_raw_candidates_pass_with_the_flag(self):
        rc, out, summary = self.run_gate_summary(
            self.platforms(baseline_with_raw(0, 0)), required="cve_token_exfil", extra_args=self.STRICT
        )
        self.assertEqual(rc, 0, out)
        self.assertIn("Raw candidates during the idle window: none on the 2 platform(s) that recorded them", out)
        self.assertNotIn("NOTE: ", out)
        self.assertEqual(summary["idle_raw_candidates"]["quieted"], [])

    def test_counts_not_recorded(self):
        # A baseline without the counts: nothing reported, nothing changed...
        rc, out = self.run_gate({"macos-arm64": clean_platform(1)}, required="cve_token_exfil")
        self.assertEqual(rc, 0, out)
        self.assertNotIn("Raw candidates", out)
        # ...unless the flag asks for them: absent evidence fails closed.
        rc, out = self.run_gate(
            {"macos-arm64": clean_platform(1)}, required="cve_token_exfil", extra_args=self.STRICT
        )
        self.assertEqual(rc, 1, out)
        self.assertIn("did not record its raw candidate counts", out)

    def test_a_dirty_baseline_is_not_counted_as_quieted(self):
        dirty = baseline_with_raw(2, 4, base=DIRTY_BASELINE)
        rc, out, summary = self.run_gate_summary(
            {
                "macos-arm64": clean_platform(1, baseline_with_raw(0, 0)),
                "ubuntu-x64": {"baseline.json": dirty},
            },
            required="cve_token_exfil",
            extra_args=self.STRICT,
        )
        self.assertEqual(rc, 1, out)
        self.assertIn("- ubuntu-x64 (dirty baseline): 2 of 12 tick(s) had raw candidates", out)
        self.assertNotIn("NOTE: 1 platform(s)", out)
        self.assertEqual(summary["idle_raw_candidates"]["quieted"], [])
        self.assertEqual(summary["failures"]["idle_raw_candidates"], 0)
        self.assertEqual(summary["failures"]["baselines"], 1)


@unittest.skipIf(os.name == "nt" or not shutil.which("bash"), "needs bash")
class TestBaselineRecordsRawCandidates(GateTestCase):
    """run_false_positive_baseline.sh against a stub edamame_cli (no daemon):
    the counts it records are the ones the gate reads."""

    STUB = r'''#!{python}
import json, os, sys
method = sys.argv[2] if len(sys.argv) > 2 else ""
state = os.environ["STUB_STATE"]
if method == "debug_run_attack_pattern_detector_tick":
    seq = [int(x) for x in os.environ["STUB_RAW"].split(",")]
    n = int(open(state).read()) if os.path.exists(state) else 0
    with open(state, "w") as fh:
        fh.write(str(n + 1))
    out = {{"success": True, "executed": True, "adjudication_status": "adjudicated",
           "adjudication_mode": "llm", "raw_candidate_count": seq[min(n, len(seq) - 1)],
           "active_findings": 0, "active_alertable_findings": 0}}
elif method == "get_attack_pattern_findings":
    out = {{"findings": []}}
elif method == "get_attack_pattern_history":
    out = []
elif method == "get_attack_pattern_detector_status":
    out = {{"adjudication_status": "adjudicated", "adjudication_mode": "llm", "raw_candidate_count": 0,
           "active_findings": 0, "active_alertable_findings": 0}}
else:
    out = {{"success": True}}
print("Result: " + json.dumps(out))
'''

    def test_quieted_raw_candidates_reach_the_gate(self):
        with tempfile.TemporaryDirectory() as tmp:
            cli = os.path.join(tmp, "edamame_cli")
            with open(cli, "w", encoding="utf-8") as fh:
                fh.write(self.STUB.format(python=sys.executable))
            os.chmod(cli, 0o755)
            triggers = os.path.join(tmp, "triggers")
            os.makedirs(triggers)
            shutil.copy(os.path.join(HERE, "triggers", "_edamame_cli.py"), triggers)
            out_dir = os.path.join(tmp, "out")
            env = dict(os.environ, EDAMAME_CLI=cli, PYTHON=sys.executable, PYTHONDONTWRITEBYTECODE="1",
                       STUB_STATE=os.path.join(tmp, "ticks"), STUB_RAW="0,5,0")
            proc = subprocess.run(
                ["bash", os.path.join(HERE, "run_false_positive_baseline.sh"), "--triggers-dir", triggers,
                 "--output-dir", out_dir, "--duration", "2", "--tick-interval", "1"],
                capture_output=True, text=True, encoding="utf-8", errors="replace", env=env, timeout=120,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            with open(os.path.join(out_dir, "baseline.json"), encoding="utf-8") as fh:
                baseline = json.load(fh)
        # The second tick raised five candidates, the others none; nothing was
        # published, so the window is clean.
        self.assertEqual(baseline["status"], "pass")
        self.assertEqual((baseline["raw_candidates_max"], baseline["ticks_with_raw_candidates"]), (5, 1))
        self.assertGreaterEqual(baseline["adjudication"]["ticks"], 2)
        rc, out = self.run_gate({"ubuntu-x64": clean_platform(1, baseline)}, required="cve_token_exfil")
        self.assertEqual(rc, 0, out)
        self.assertIn("at most 5 on one tick", out)
        self.assertIn("NOTE: 1 platform(s) (ubuntu-x64) had raw candidates", out)


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
