#!/usr/bin/env python3
"""Tests for the CVE harness's finding matcher and alertable classifier.

`_finding_match.is_alertable` mirrors `VulnerabilityFinding::is_alertable` in
`edamame_core/src/agentic/vulnerability_detector.rs`::

    !self.dismissed
        && (self.severity.eq_ignore_ascii_case("CRITICAL")
            || self.severity.eq_ignore_ascii_case("HIGH"))

If that Rust predicate changes, these tests must be updated in the same commit
-- otherwise the harness asserts on a different notion of "alerts in production"
than the daemon and `vulnerability-status --fail-on-findings` do.

Run with::

    python3 -m unittest discover -s tests/security -p 'test_*.py'
    python3 tests/security/test_finding_match.py
"""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "triggers"))

from _finding_match import (  # noqa: E402
    demoted_by_adjudicator,
    expects_clean,
    findings_of,
    format_histogram,
    graded_for_scenario,
    is_alertable,
    matches,
    normalize_severity,
    requires_alert,
    severity_histogram,
    summarize,
)


def finding(**kw) -> dict:
    base = {
        "check": "token_exfiltration",
        "severity": "HIGH",
        "dismissed": False,
        "description": "",
        "open_files": [],
    }
    base.update(kw)
    return base


class TestIsAlertable(unittest.TestCase):
    def test_high_and_critical_alert(self):
        for sev in ("HIGH", "CRITICAL"):
            self.assertTrue(is_alertable(finding(severity=sev)), sev)

    def test_case_insensitive_like_rust_eq_ignore_ascii_case(self):
        for sev in ("high", "Critical", "cRiTiCaL", " HIGH "):
            self.assertTrue(is_alertable(finding(severity=sev)), sev)

    def test_low_and_medium_do_not_alert(self):
        for sev in ("LOW", "MEDIUM", "low", "info", "NONE"):
            self.assertFalse(is_alertable(finding(severity=sev)), sev)

    def test_dismissed_never_alerts(self):
        for sev in ("HIGH", "CRITICAL"):
            self.assertFalse(is_alertable(finding(severity=sev, dismissed=True)), sev)

    def test_missing_or_malformed_severity_does_not_alert(self):
        self.assertFalse(is_alertable(finding(severity=None)))
        self.assertFalse(is_alertable(finding(severity="")))
        self.assertFalse(is_alertable(finding(severity=3)))
        self.assertFalse(is_alertable({}))
        self.assertFalse(is_alertable(None))
        self.assertFalse(is_alertable("not-a-finding"))

    def test_normalize_severity(self):
        self.assertEqual(normalize_severity(finding(severity=" high ")), "HIGH")
        self.assertEqual(normalize_severity(finding(severity="")), "UNKNOWN")
        self.assertEqual(normalize_severity(None), "UNKNOWN")


class TestMatches(unittest.TestCase):
    def test_check_must_match(self):
        f = finding(check="credential_harvest", open_files=["/tmp/x/npmrc"])
        self.assertFalse(matches(f, "token_exfiltration", ["npmrc"]))
        self.assertTrue(matches(f, "credential_harvest", ["npmrc"]))

    def test_no_markers_or_ports_matches_any_finding_of_the_check(self):
        self.assertTrue(matches(finding(), "token_exfiltration"))

    def test_marker_matches_open_files_case_insensitively(self):
        f = finding(open_files=["/Users/x/.npm/_Logs/NPMRC"])
        self.assertTrue(matches(f, "token_exfiltration", ["npmrc"]))

    def test_marker_matches_description(self):
        f = finding(description="Sensitive file create: _temp_staged_binary")
        self.assertTrue(matches(f, "token_exfiltration", ["_temp_staged_binary"]))

    def test_marker_matches_parent_script_path(self):
        """sandbox_exploitation attributes the dropper via parent_script_path."""
        f = finding(check="sandbox_exploitation", parent_script_path="/tmp/.hidden/exfil.py")
        self.assertTrue(matches(f, "sandbox_exploitation", ["/tmp/.hidden/"]))

    def test_marker_matches_subject_and_process_paths(self):
        self.assertTrue(
            matches(finding(subject_path="/home/u/project_secrets.env"),
                    "token_exfiltration", ["project_secrets.env"])
        )
        self.assertTrue(
            matches(finding(process_path="/tmp/pgserve/postinstall"),
                    "token_exfiltration", ["pgserve"])
        )

    def test_port_matches_when_marker_does_not(self):
        f = finding(destination_port=63174, open_files=["/unrelated"])
        self.assertTrue(matches(f, "token_exfiltration", ["nope"], [63174]))
        self.assertFalse(matches(f, "token_exfiltration", ["nope"], [63999]))

    def test_port_as_string_is_coerced(self):
        f = finding(destination_port="63174")
        self.assertTrue(matches(f, "token_exfiltration", [], [63174]))

    def test_absent_port_with_port_only_scenario_does_not_match(self):
        self.assertFalse(matches(finding(), "token_exfiltration", [], [63174]))

    def test_non_dict_finding_never_matches(self):
        self.assertFalse(matches(None, "token_exfiltration"))
        self.assertFalse(matches("x", "token_exfiltration"))


def episode(members, **kw) -> dict:
    """An episode (core 2.2) as `get_attack_pattern_findings` serves it: the
    strongest member's files, subject and destination, every member's
    sessions, and the member list."""
    base = finding(
        check="credential_harvest",
        severity="CRITICAL",
        open_files=["C:\\Users\\r\\.aws\\demo_openclaw_pgserve_credentials"],
        subject_path="C:\\Users\\r\\.aws\\demo_openclaw_pgserve_credentials",
        destination_port=63174,
        session_uid="lead-session",
        session_uids=["lead-session", "other-session", "scenario-session"],
        episode={"member_count": len(members), "members": members},
    )
    base.update(kw)
    return base


def member(severity, subject) -> dict:
    return {"finding_key": "vuln:" + subject, "severity": severity, "subject_path": subject}


class TestEpisodeMembers(unittest.TestCase):
    """The agent_cred_harvest miss of 2026-11-22 (windows-x64, posture
    f5b816f): the scenario's harvest joined an episode led by the pgserve
    harvest (same python.exe below the same .aws root), so the served finding
    carried the lead's files and none of the scenario's markers."""

    MARKERS = ["_ach_key", "_ach_secring.key", "_ach.mdc"]

    def members(self, scenario_grade="CRITICAL"):
        return [
            member("CRITICAL", "C:\\Users\\r\\.aws\\demo_openclaw_pgserve_credentials"),
            member("CRITICAL", "C:\\Users\\r\\.aws\\demo_openclaw_sc_credentials"),
            member(scenario_grade, "C:\\Users\\r\\.aws\\config"),
        ]

    def test_an_episode_led_by_another_finding_matches_through_the_scenario_session(self):
        f = episode(self.members())
        self.assertFalse(matches(f, "credential_harvest", self.MARKERS))
        self.assertTrue(
            matches(f, "credential_harvest", self.MARKERS, [], ["scenario-session"])
        )

    def test_no_shared_session_no_match(self):
        f = episode(self.members())
        self.assertFalse(
            matches(f, "credential_harvest", self.MARKERS, [], ["unrelated-session"])
        )

    def test_the_check_still_has_to_match(self):
        f = episode(self.members(), check="token_exfiltration")
        self.assertFalse(
            matches(f, "credential_harvest", self.MARKERS, [], ["scenario-session"])
        )

    def test_a_session_match_is_graded_at_the_weakest_member(self):
        graded = graded_for_scenario(episode(self.members()), "credential_harvest", self.MARKERS)
        self.assertEqual(normalize_severity(graded), "CRITICAL")
        self.assertTrue(is_alertable(graded))
        self.assertTrue(graded["scenario_graded_at_weakest_member"])

        weak = graded_for_scenario(
            episode(self.members(scenario_grade="LOW")), "credential_harvest", self.MARKERS
        )
        self.assertEqual(normalize_severity(weak), "LOW")
        self.assertFalse(is_alertable(weak))

    def test_an_own_marker_match_keeps_its_grade(self):
        f = episode(
            self.members(scenario_grade="LOW"),
            open_files=["C:\\Users\\r\\.ssh\\demo_openclaw_ach_key"],
        )
        graded = graded_for_scenario(f, "credential_harvest", self.MARKERS)
        self.assertIs(graded, f)
        self.assertEqual(normalize_severity(graded), "CRITICAL")

    def test_summarize_counts_a_session_match_at_its_grade(self):
        got = summarize(
            [episode(self.members(scenario_grade="LOW"))],
            "credential_harvest",
            self.MARKERS,
            [],
            ["scenario-session"],
        )
        self.assertEqual(got["matched"], 1)
        self.assertEqual(got["alertable"], 0)


class TestHistogram(unittest.TestCase):
    def test_ordered_most_severe_first(self):
        hist = severity_histogram(
            [finding(severity="LOW"), finding(severity="CRITICAL"), finding(severity="LOW")]
        )
        self.assertEqual(format_histogram(hist), "CRITICAL:1,LOW:2")

    def test_empty_renders_none(self):
        self.assertEqual(format_histogram(severity_histogram([])), "none")

    def test_no_pipe_in_output(self):
        """The harness appends this to a pipe-delimited counter line."""
        hist = severity_histogram(
            [finding(severity=s) for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "")]
        )
        self.assertNotIn("|", format_histogram(hist))

    def test_unknown_sorts_last(self):
        hist = severity_histogram([finding(severity=""), finding(severity="HIGH")])
        self.assertEqual(format_histogram(hist), "HIGH:1,UNKNOWN:1")


class TestSummarize(unittest.TestCase):
    def test_counts_matched_and_alertable_separately(self):
        findings = [
            finding(severity="HIGH", open_files=["/tmp/mark"]),
            finding(severity="LOW", open_files=["/tmp/mark"]),
            finding(severity="CRITICAL", open_files=["/tmp/mark"], dismissed=True),
            finding(severity="CRITICAL", open_files=["/other"]),
        ]
        summary = summarize(findings, "token_exfiltration", ["/tmp/mark"])
        self.assertEqual(summary["matched"], 3)
        self.assertEqual(summary["alertable"], 1)
        self.assertEqual(format_histogram(summary["severities"]), "CRITICAL:1,HIGH:1,LOW:1")

    def test_demoted_scenario_yields_matches_without_alertable(self):
        """The exact shape a CRS/LLM demotion takes -- must not read as a pass."""
        findings = [finding(severity="LOW", open_files=["/tmp/mark"])] * 3
        summary = summarize(findings, "token_exfiltration", ["/tmp/mark"])
        self.assertEqual(summary["matched"], 3)
        self.assertEqual(summary["alertable"], 0)


class TestFindingsOf(unittest.TestCase):
    def test_extracts_list(self):
        self.assertEqual(findings_of({"findings": [1, 2]}), [1, 2])

    def test_tolerates_missing_or_malformed_report(self):
        for report in ({}, {"findings": None}, {"findings": {}}, None, "x", []):
            self.assertEqual(findings_of(report), [])


def _export(raw_severity: str, verdict: str | None, key: str = "k1") -> dict:
    trace = {"raw_findings": [{"finding_key": key, "severity": raw_severity}]}
    if verdict is not None:
        trace["llm_decision"] = {
            "finding_verdicts": [{"finding_key": key, "verdict": verdict}]
        }
    return {"success": True, "details": {"debug_trace": trace}}


class TestAdjudicatorDemote(unittest.TestCase):
    def test_only_the_listed_scenarios_may_be_lowered_by_the_adjudicator(self):
        self.assertFalse(requires_alert("file_events"))
        self.assertFalse(requires_alert("sneakpeek_split"))
        self.assertTrue(requires_alert("sneakpeek"))
        self.assertTrue(requires_alert("cve_sandbox_escape"))

    def test_only_the_listed_scenarios_are_expected_clean(self):
        self.assertTrue(expects_clean("poisoned_mcp_tool_maintenance_control"))
        self.assertTrue(expects_clean(" poisoned_mcp_tool_maintenance_control "))
        self.assertFalse(expects_clean("poisoned_mcp_tool_two_sessions"))
        self.assertFalse(expects_clean("poisoned_mcp_tool_as_run"))
        self.assertFalse(expects_clean("file_events"))

    def test_an_alertable_grade_the_adjudicator_demoted(self):
        self.assertTrue(demoted_by_adjudicator("k1", _export("CRITICAL", "DEMOTE")))
        self.assertTrue(demoted_by_adjudicator("k1", _export("high", "demote")))

    def test_a_grade_the_detector_lowered_is_not(self):
        self.assertFalse(demoted_by_adjudicator("k1", _export("LOW", "DEMOTE")))

    def test_a_kept_or_unadjudicated_finding_is_not(self):
        self.assertFalse(demoted_by_adjudicator("k1", _export("HIGH", "KEEP")))
        self.assertFalse(demoted_by_adjudicator("k1", _export("HIGH", None)))

    def test_another_key_or_a_missing_trace_is_not(self):
        self.assertFalse(demoted_by_adjudicator("k2", _export("HIGH", "DEMOTE")))
        self.assertFalse(
            demoted_by_adjudicator("k1", {"success": True, "details": {"debug_trace": None}})
        )
        self.assertFalse(demoted_by_adjudicator("k1", {"success": False, "error": "x"}))


if __name__ == "__main__":
    unittest.main(verbosity=2)
