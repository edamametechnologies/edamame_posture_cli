#!/usr/bin/env python3
"""Tests for tests/fp_lab/run_fp_lab.py's pure parts: which skips mean a case
was never planned on this host, which agents were planned and delivered
nothing (the INCOMPLETE verdict and its exit code), and the "Skipped by
configuration" list. Nothing here drives an agent or calls edamame_cli.

    python3 -m unittest discover -s tests/fp_lab -p 'test_*.py'
    python3 tests/fp_lab/test_run_fp_lab.py
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import run_fp_lab as lab  # noqa: E402


def agent_case(scenario: str, agent: str, status: str, reason: str = "", skip_kind: str | None = None,
               **extra) -> dict:
    case = {"case_id": f"{scenario}@{agent}", "scenario": scenario, "kind": "agent", "agent": agent,
            "status": status, "fp_class": "new", "attack_pattern": [], "divergence": [], "near_misses": [],
            "non_clean_verdicts": [], "llm_suppressed": []}
    if reason:
        case["reason"] = reason
    if skip_kind:
        case["skip_kind"] = skip_kind
    case.update(extra)
    return case


def direct_case(scenario: str, status: str, reason: str = "", skip_kind: str | None = None, **extra) -> dict:
    case = agent_case(scenario, "", status, reason, skip_kind, **extra)
    case.update(case_id=scenario, kind="direct")
    return case


NOT_DELIVERED = "stimulus not delivered (marker 'notes/status.md' missing, rc=[1, 1])"
NO_KEY = "claude_code: ANTHROPIC_API_KEY not set (no provider key to drive the real agent)"
NO_CLI = ("claude_code: claude CLI not on PATH with ANTHROPIC_API_KEY set "
          "(workflow install of the agent runtime failed)")


class SkipKinds(unittest.TestCase):
    def test_recorded_kind_wins_over_the_reason(self):
        case = agent_case("a", "claude_code", "SKIP", NOT_DELIVERED, lab.SKIP_AGENT_REFUSED)
        self.assertEqual(lab.skip_kind_of(case), lab.SKIP_AGENT_REFUSED)

    def test_kind_read_back_from_an_earlier_runners_reason(self):
        for reason, kind in (
            ("skipped by --skip", lab.SKIP_EXCLUDED),
            ("not a windows scenario", lab.SKIP_PLATFORM),
            ("agent claude_code not selected (--agents)", lab.SKIP_AGENT_NOT_SELECTED),
            ("missing tool(s): cargo", lab.SKIP_MISSING_TOOL),
            ("missing env: FP_LAB_LAN_SSH_HOST", lab.SKIP_MISSING_ENV),
            (NO_KEY, lab.SKIP_AGENT_UNAVAILABLE),
            (NO_CLI, lab.SKIP_AGENT_INSTALL_FAILED),
            ("agent refused: I can't help", lab.SKIP_AGENT_REFUSED),
            (NOT_DELIVERED, lab.SKIP_NOT_DELIVERED),
        ):
            self.assertEqual(lab.skip_kind_of(agent_case("a", "claude_code", "SKIP", reason)), kind, reason)

    def test_only_a_skip_has_a_kind(self):
        self.assertIsNone(lab.skip_kind_of(agent_case("a", "claude_code", "PASS")))
        self.assertIsNone(lab.skip_kind_of(agent_case("a", "claude_code", "ERROR", error="boom")))
        # A reason no rule recognizes has no kind: the case counts as planned.
        self.assertIsNone(lab.skip_kind_of(agent_case("a", "claude_code", "SKIP", "something new")))


class UndeliveredAgents(unittest.TestCase):
    def test_every_case_skipped_at_the_drive_is_undelivered(self):
        """The provider account out of credit: the CLI runs, nothing is delivered."""
        cases = [agent_case(f"s{i}", "claude_code", "SKIP", NOT_DELIVERED, lab.SKIP_NOT_DELIVERED)
                 for i in range(3)]
        cases.append(agent_case("s9", "claude_code", "SKIP", "agent refused: I can't help",
                                lab.SKIP_AGENT_REFUSED))
        cases.append(agent_case("s0", "codex", "PASS"))
        cases.append(direct_case("direct-git-lab-repo", "PASS"))
        out = lab.undelivered_agents(cases)
        self.assertEqual([u["agent"] for u in out], ["claude_code"])
        self.assertEqual(out[0]["planned"], 4)
        self.assertEqual(out[0]["why"], {lab.SKIP_NOT_DELIVERED: 3, lab.SKIP_AGENT_REFUSED: 1})
        self.assertEqual(out[0]["example"]["case_id"], "s0@claude_code")

    def test_a_host_without_the_agents_key_is_not_planned(self):
        cases = [agent_case(f"s{i}", "claude_code", "SKIP", NO_KEY, lab.SKIP_AGENT_UNAVAILABLE)
                 for i in range(3)]
        cases.append(agent_case("s0", "codex", "PASS"))
        self.assertEqual(lab.undelivered_agents(cases), [])
        self.assertEqual(lab.run_verdict(cases)[:2], ("PASS", 0))

    def test_an_agent_left_out_or_skipped_by_configuration_is_not_planned(self):
        cases = [
            agent_case("a", "codex", "SKIP", "agent codex not selected (--agents)", lab.SKIP_AGENT_NOT_SELECTED),
            agent_case("b", "claude_code", "SKIP", "missing env: FP_LAB_LAN_SSH_HOST", lab.SKIP_MISSING_ENV),
            agent_case("c", "claude_code", "SKIP", "missing tool(s): cargo", lab.SKIP_MISSING_TOOL),
            agent_case("d", "claude_code", "SKIP", "not a windows scenario", lab.SKIP_PLATFORM),
            agent_case("e", "claude_code", "SKIP", "skipped by --skip", lab.SKIP_EXCLUDED),
        ]
        self.assertEqual(lab.undelivered_agents(cases), [])
        self.assertEqual(lab.run_verdict(cases)[:2], ("PASS", 0))

    def test_one_delivered_case_is_enough(self):
        for status in ("PASS", "FAIL", "KNOWN-OPEN", "DECIDED"):
            cases = [agent_case("a", "claude_code", "SKIP", NOT_DELIVERED, lab.SKIP_NOT_DELIVERED),
                     agent_case("b", "claude_code", status)]
            self.assertEqual(lab.undelivered_agents(cases), [], status)

    def test_errors_deliver_nothing(self):
        cases = [agent_case("a", "codex", "ERROR", error="workspace failed"),
                 agent_case("b", "codex", "SKIP", NOT_DELIVERED, lab.SKIP_NOT_DELIVERED)]
        out = lab.undelivered_agents(cases)
        self.assertEqual(out[0]["why"], {"ERROR": 1, lab.SKIP_NOT_DELIVERED: 1})
        self.assertEqual(out[0]["example"]["reason"], "workspace failed")

    def test_key_present_and_cli_missing_is_planned(self):
        """The harness's install_failed class: the host holds the key to
        drive the agent and its CLI is not there."""
        cases = [agent_case("a", "claude_code", "SKIP", NO_CLI, lab.SKIP_AGENT_INSTALL_FAILED),
                 agent_case("b", "claude_code", "SKIP", "not a linux scenario", lab.SKIP_PLATFORM)]
        out = lab.undelivered_agents(cases)
        self.assertEqual((out[0]["agent"], out[0]["planned"]), ("claude_code", 1))

    def test_cases_of_an_earlier_runner_are_classified_by_their_reason(self):
        legacy = [agent_case("a", "claude_code", "SKIP", NOT_DELIVERED),
                  agent_case("b", "claude_code", "SKIP", "missing env: FP_LAB_LAN_SSH_HOST")]
        self.assertEqual(lab.undelivered_agents(legacy)[0]["planned"], 1)
        no_key = [agent_case("a", "claude_code", "SKIP", NO_KEY)]
        self.assertEqual(lab.undelivered_agents(no_key), [])

    def test_direct_and_drain_cases_never_count(self):
        cases = [direct_case("direct-npm-temp", "SKIP", "stimulus not delivered (npm failed)",
                             lab.SKIP_NOT_DELIVERED),
                 {"case_id": "post-run-drain", "kind": "drain", "agent": "", "status": "PASS"}]
        self.assertEqual(lab.undelivered_agents(cases), [])


class Verdict(unittest.TestCase):
    def test_incomplete_has_its_own_exit_code(self):
        cases = [agent_case("a", "claude_code", "SKIP", NOT_DELIVERED, lab.SKIP_NOT_DELIVERED),
                 direct_case("direct-git-lab-repo", "PASS")]
        verdict, code, undelivered = lab.run_verdict(cases)
        self.assertEqual((verdict, code), ("INCOMPLETE", lab.EXIT_INCOMPLETE))
        self.assertNotIn(lab.EXIT_INCOMPLETE, (0, lab.EXIT_FAIL, lab.EXIT_PREFLIGHT))
        self.assertEqual(lab.result_line(verdict, cases, undelivered),
                         "RESULT: INCOMPLETE (no claude_code case was delivered)")

    def test_a_finding_fails_the_run_even_when_an_agent_delivered_nothing(self):
        cases = [agent_case("a", "claude_code", "SKIP", NOT_DELIVERED, lab.SKIP_NOT_DELIVERED),
                 direct_case("direct-git-lab-repo", "FAIL")]
        verdict, code, undelivered = lab.run_verdict(cases)
        self.assertEqual((verdict, code), ("FAIL", lab.EXIT_FAIL))
        self.assertEqual([u["agent"] for u in undelivered], ["claude_code"])
        self.assertTrue(lab.result_line(verdict, cases, undelivered).startswith("RESULT: FAIL (1 case(s)"))

    def test_clean_run(self):
        cases = [agent_case("a", "claude_code", "PASS"), direct_case("direct-git-lab-repo", "PASS")]
        self.assertEqual(lab.run_verdict(cases), ("PASS", 0, []))
        self.assertEqual(lab.result_line("PASS", cases, []), "RESULT: PASS")

    def test_two_undelivered_agents_are_both_named(self):
        cases = [agent_case("a", "claude_code", "SKIP", NOT_DELIVERED, lab.SKIP_NOT_DELIVERED),
                 agent_case("a", "codex", "SKIP", NOT_DELIVERED, lab.SKIP_NOT_DELIVERED)]
        verdict, _code, undelivered = lab.run_verdict(cases)
        self.assertEqual(lab.result_line(verdict, cases, undelivered),
                         "RESULT: INCOMPLETE (no claude_code or codex case was delivered)")


class PlannedAgents(unittest.TestCase):
    def test_counts_runnable_cases_and_the_install_failed_class(self):
        plan = [
            {"case_id": "a@claude_code", "agent": "claude_code", "skip": None, "skip_kind": None},
            {"case_id": "b@claude_code", "agent": "claude_code", "skip": "not a linux scenario",
             "skip_kind": lab.SKIP_PLATFORM},
            {"case_id": "a@codex", "agent": "codex", "skip": "codex: codex CLI not on PATH with OPENAI_API_KEY set",
             "skip_kind": lab.SKIP_AGENT_INSTALL_FAILED},
            {"case_id": "direct-npm-temp", "agent": "", "skip": None, "skip_kind": None},
        ]
        self.assertEqual(lab.planned_agents(plan), {"claude_code": 1, "codex": 1})
        no_key = [{"case_id": "a@claude_code", "agent": "claude_code", "skip": NO_KEY,
                   "skip_kind": lab.SKIP_AGENT_UNAVAILABLE}]
        self.assertEqual(lab.planned_agents(no_key), {})


class ConfigurationSkips(unittest.TestCase):
    CASES = [
        agent_case("div-lan-ssh-delegated", "claude_code", "SKIP", "missing env: FP_LAB_LAN_SSH_HOST",
                   lab.SKIP_MISSING_ENV, missing=["FP_LAB_LAN_SSH_HOST"]),
        direct_case("direct-build-rust-temp", "SKIP", "missing tool(s): cargo, rustc"),  # an earlier runner's
        direct_case("direct-os-relay-keychain-sidecars", "SKIP", "not a linux scenario", lab.SKIP_PLATFORM),
        agent_case("a", "codex", "SKIP", "codex: OPENAI_API_KEY not set", lab.SKIP_AGENT_UNAVAILABLE),
        agent_case("b", "claude_code", "PASS"),
    ]

    def test_lists_missing_variables_and_tools_only(self):
        self.assertEqual(lab.configuration_skips(self.CASES), [
            {"case_id": "div-lan-ssh-delegated@claude_code", "kind": lab.SKIP_MISSING_ENV,
             "missing": ["FP_LAB_LAN_SSH_HOST"]},
            {"case_id": "direct-build-rust-temp", "kind": lab.SKIP_MISSING_TOOL, "missing": ["cargo", "rustc"]},
        ])

    def test_lines_name_the_case_and_what_is_missing(self):
        entries = lab.configuration_skips(self.CASES)
        console = lab.configuration_skip_lines(entries)
        self.assertTrue(console[0].startswith("Skipped by configuration (2)"))
        self.assertEqual(console[1], "  div-lan-ssh-delegated@claude_code: environment variable "
                                     "FP_LAB_LAN_SSH_HOST not set")
        self.assertEqual(console[2], "  direct-build-rust-temp: tool cargo, rustc not on PATH")
        markdown = lab.configuration_skip_lines(entries, markdown=True)
        self.assertTrue(markdown[0].startswith("- Skipped by configuration (2)"))
        self.assertEqual(markdown[1], "  - `div-lan-ssh-delegated@claude_code`: environment variable "
                                      "`FP_LAB_LAN_SSH_HOST` not set")
        self.assertEqual(lab.configuration_skip_lines([]), [])


class Summary(unittest.TestCase):
    """write_summary / summarize on a run directory: the files and the exit code."""

    PREFLIGHT = {"host": "lab-host", "platform": "linux", "core_version": "0.0.0", "leg": "llm", "llm_ok": True,
                 "attack_pattern_detector": {"adjudication_mode": "advisory"},
                 "divergence_engine": {"adjudication_mode": "advisory"}}

    def summarize(self, cases: list) -> tuple[int, dict, str, str]:
        with tempfile.TemporaryDirectory() as tmp:
            run = Path(tmp) / "run"
            plan = []
            for case in cases:
                plan.append({"case_id": case["case_id"]})
                lab.write_json(run / "cases" / lab.safe_name(case["case_id"].replace("@", "__")) / "case.json", case)
            lab.write_json(run / "plan.json", plan)
            lab.write_json(run / "preflight.json", self.PREFLIGHT)
            console = io.StringIO()
            with contextlib.redirect_stdout(console):
                code = lab.run_cmd_summarize(argparse.Namespace(run_dir=str(run), perf_reference=""))
            summary = json.loads((run / "summary.json").read_text(encoding="utf-8"))
            markdown = (run / "summary.md").read_text(encoding="utf-8")
        return code, summary, markdown, console.getvalue()

    def test_an_agent_that_never_delivered_makes_the_run_incomplete(self):
        code, summary, markdown, console = self.summarize([
            agent_case("div-instruction-files-read", "claude_code", "SKIP", NOT_DELIVERED, lab.SKIP_NOT_DELIVERED),
            agent_case("div-lan-ssh-delegated", "claude_code", "SKIP", "missing env: FP_LAB_LAN_SSH_HOST",
                       lab.SKIP_MISSING_ENV, missing=["FP_LAB_LAN_SSH_HOST"]),
            agent_case("div-instruction-files-read", "codex", "PASS"),
            direct_case("direct-git-lab-repo", "PASS"),
        ])
        self.assertEqual(code, 3)
        self.assertEqual((summary["verdict"], summary["exit_code"]), ("INCOMPLETE", 3))
        self.assertEqual([u["agent"] for u in summary["undelivered_agents"]], ["claude_code"])
        self.assertEqual(summary["skipped_by_configuration"], [
            {"case_id": "div-lan-ssh-delegated@claude_code", "kind": "missing_env",
             "missing": ["FP_LAB_LAN_SSH_HOST"]}])
        self.assertEqual([c["skip_kind"] for c in summary["cases"]],
                         ["not_delivered", "missing_env", None, None])
        self.assertIn("- Verdict: **INCOMPLETE** (PASS 2, SKIP 2)", markdown)
        self.assertIn("- Not delivered: no claude_code case was delivered (1 planned on this host", markdown)
        self.assertIn("- Skipped by configuration (1)", markdown)
        self.assertIn("  - `div-lan-ssh-delegated@claude_code`: environment variable `FP_LAB_LAN_SSH_HOST` not set",
                      markdown)
        lines = console.strip().splitlines()
        self.assertEqual(lines[-1], "RESULT: INCOMPLETE (no claude_code case was delivered)")
        # The configuration list again, once, after the summary.
        tail = lines[lines.index("RESULT: INCOMPLETE (no claude_code case was delivered)") - 3:]
        self.assertTrue(tail[0].startswith("Skipped by configuration (1)"), tail)
        self.assertEqual(sum(1 for line in lines if line.startswith("Skipped by configuration")), 1)

    def test_a_host_without_keys_still_passes(self):
        code, summary, markdown, console = self.summarize([
            agent_case("div-instruction-files-read", "claude_code", "SKIP", NO_KEY, lab.SKIP_AGENT_UNAVAILABLE),
            direct_case("direct-git-lab-repo", "PASS"),
        ])
        self.assertEqual(code, 0)
        self.assertEqual((summary["verdict"], summary["undelivered_agents"]), ("PASS", []))
        self.assertNotIn("Not delivered", markdown)
        self.assertNotIn("Skipped by configuration", markdown)
        self.assertEqual(console.strip().splitlines()[-1], "RESULT: PASS")

    def test_a_failing_case_keeps_exit_1(self):
        failing = direct_case("direct-git-lab-repo", "FAIL")
        failing["attack_pattern"] = [{"alertable": True, "check": "file_system_tampering", "severity": "HIGH"}]
        code, summary, _markdown, console = self.summarize([
            agent_case("div-instruction-files-read", "claude_code", "SKIP", NOT_DELIVERED, lab.SKIP_NOT_DELIVERED),
            failing,
        ])
        self.assertEqual(code, 1)
        self.assertEqual(summary["verdict"], "FAIL")
        self.assertEqual([u["agent"] for u in summary["undelivered_agents"]], ["claude_code"])
        self.assertTrue(console.strip().splitlines()[-1].startswith("RESULT: FAIL"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
