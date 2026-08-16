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
    findings_of,
    format_histogram,
    is_alertable,
    matches,
    normalize_severity,
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
