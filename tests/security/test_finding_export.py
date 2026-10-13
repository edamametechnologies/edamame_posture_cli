#!/usr/bin/env python3
"""Tests for the CVE harness's diagnostic exports (`triggers/_finding_export.py`)
and their wiring in `run_cve_detection.sh`.

The runner test drives the real `run_cve_detection.sh` through one scenario
against a fake `edamame_cli` (canned RPC answers, every call logged), so it
proves the alertable export lands in `findings/<scenario>.export.json`, slimmed
and newest first, and is taken before the post-scenario history clear. Its
scratch directory is under the repository's ignored `tests_temp/`, never OS
temp: the fake CLI and trigger are executables, and executables written to
temp are exactly what the attack-pattern detector flags on a developer Mac.

Run with::

    python3 -m unittest discover -s tests/security -p 'test_*.py'
    python3 tests/security/test_finding_export.py
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
TRIGGERS = HERE / "triggers"
REPO = HERE.parent.parent
sys.path.insert(0, str(TRIGGERS))

from _finding_export import (  # noqa: E402
    ALERTABLE_EXPORTS_KEY,
    DEMOTED_EXPORTS_KEY,
    alertable_by_key,
    export_entry,
    export_request_args,
    export_succeeded,
    matched_findings,
    scenario_meta,
    slim_export,
    update_export_document,
    utc_seconds,
)
from _finding_match import demoted_by_adjudicator  # noqa: E402

SCRATCH = REPO / "tests_temp"


def scratch_dir(prefix: str) -> Path:
    SCRATCH.mkdir(exist_ok=True)
    return Path(tempfile.mkdtemp(prefix=prefix, dir=str(SCRATCH)))


def drop_scratch(path: Path) -> None:
    shutil.rmtree(path, ignore_errors=True)
    try:
        SCRATCH.rmdir()  # only when no other test still uses it
    except OSError:
        pass


def finding(key: str, severity: str = "HIGH", **kw) -> dict:
    base = {
        "check": "token_exfiltration",
        "severity": severity,
        "finding_key": key,
        "dismissed": False,
        "open_files": [],
    }
    base.update(kw)
    return base


def export_response(key: str, prompt_chars: int = 10, other_slices: int = 1) -> dict:
    own = {"finding_key": key, "sessions": [{"session_uid": "sess-1"}]}
    others = [{"finding_key": f"vuln:other{i}", "sessions": [{"session_uid": f"o{i}"}]}
              for i in range(other_slices)]
    return {
        "success": True,
        "details": {
            "finding_key": key,
            "finding": finding(key, session_uid="sess-1"),
            "report_id": "r1",
            "debug_trace": {
                "input_slices": [own] + others,
                "raw_findings": [finding(key)],
                "final_findings": [finding(key)],
                "llm_prompt": "p" * prompt_chars,
                "llm_raw_answer": "short answer",
                "llm_decision": {"finding_verdicts": [{"finding_key": key, "verdict": "KEEP"}]},
            },
            "finding_input_slice": own,
            "finding_input_slice_source": "trace",
            "grading_evidence": None,
            "evaluated_at": "2026-10-13T10:00:00.123456789+00:00",
            "captured_at": "2026-10-13T10:01:00+00:00",
            "core_version": "2.0.8",
            "platform": "macos",
            "host_label": "lab-mac",
        },
    }


class TestUtcSeconds(unittest.TestCase):
    def test_zulu_and_offsets(self):
        z = utc_seconds("2026-10-13T10:00:00Z")
        self.assertEqual(utc_seconds("2026-10-13T12:00:00+02:00"), z)
        self.assertEqual(utc_seconds("2026-10-13T10:00:00+0000"), z)

    def test_nanosecond_fractions_order_correctly(self):
        # chrono writes up to nine fractional digits; a plain string compare
        # would order "10:00:00.5Z" before "10:00:00Z".
        self.assertGreater(utc_seconds("2026-10-13T10:00:00.500000001Z"),
                           utc_seconds("2026-10-13T10:00:00Z"))

    def test_garbage_is_none(self):
        for value in (None, "", "yesterday", 12, "2026-13-45T99:00:00Z"):
            self.assertIsNone(utc_seconds(value), value)


class TestAlertableByKey(unittest.TestCase):
    def test_only_alertable_keyed_findings(self):
        matched = [
            finding("vuln:low", "LOW"),
            finding("vuln:dismissed", dismissed=True),
            finding(""),
            finding("vuln:high"),
            "not a finding",
        ]
        self.assertEqual([k for k, _ in alertable_by_key(matched)], ["vuln:high"])

    def test_dedupes_current_and_history(self):
        matched = [finding("vuln:a"), finding("vuln:a", "CRITICAL")]
        rows = alertable_by_key(matched)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][1]["severity"], "HIGH", "the first occurrence is kept")

    def test_newest_first_then_undated_in_input_order(self):
        matched = [
            finding("vuln:undated-1"),
            finding("vuln:old", first_detected="2026-10-13T09:00:00Z"),
            finding("vuln:new", first_detected="2026-10-13T10:00:00.5Z"),
            finding("vuln:undated-2"),
            finding("vuln:mid", first_detected="2026-10-13T10:00:00Z"),
        ]
        self.assertEqual(
            [k for k, _ in alertable_by_key(matched)],
            ["vuln:new", "vuln:mid", "vuln:old", "vuln:undated-1", "vuln:undated-2"],
        )

    def test_matched_findings_reads_current_then_history(self):
        evidence = {"current": [finding("vuln:c")], "history": [finding("vuln:h")]}
        self.assertEqual([f["finding_key"] for f in matched_findings(evidence)], ["vuln:c", "vuln:h"])
        self.assertEqual(matched_findings(None), [])


class TestSlimExport(unittest.TestCase):
    def test_long_llm_text_is_replaced_by_its_length(self):
        response = export_response("vuln:a", prompt_chars=9000)
        slimmed, removed = slim_export(response, "vuln:a")
        trace = slimmed["details"]["debug_trace"]
        self.assertEqual(removed["llm_prompt_chars"], 9000)
        self.assertIn("9000 chars removed", trace["llm_prompt"])
        self.assertEqual(trace["llm_raw_answer"], "short answer", "short text stays")
        self.assertNotIn("llm_raw_answer_chars", removed)

    def test_trace_keeps_only_this_findings_slice(self):
        slimmed, removed = slim_export(export_response("vuln:a", other_slices=3), "vuln:a")
        slices = slimmed["details"]["debug_trace"]["input_slices"]
        self.assertEqual([s["finding_key"] for s in slices], ["vuln:a"])
        self.assertEqual(removed["input_slices_dropped"], 3)

    def test_replay_fields_survive(self):
        response = export_response("vuln:a", prompt_chars=9000, other_slices=2)
        slimmed, _ = slim_export(response, "vuln:a")
        for field in ("finding", "finding_input_slice", "finding_input_slice_source",
                      "grading_evidence", "evaluated_at", "captured_at", "core_version", "platform"):
            self.assertEqual(slimmed["details"][field], response["details"][field], field)
        trace = slimmed["details"]["debug_trace"]
        self.assertEqual(trace["raw_findings"], response["details"]["debug_trace"]["raw_findings"])
        self.assertEqual(trace["llm_decision"], response["details"]["debug_trace"]["llm_decision"])

    def test_input_is_not_modified(self):
        response = export_response("vuln:a", prompt_chars=9000, other_slices=2)
        before = json.dumps(response, sort_keys=True)
        slim_export(response, "vuln:a")
        self.assertEqual(json.dumps(response, sort_keys=True), before)

    def test_failed_and_traceless_exports_pass_through(self):
        failed = {"success": False, "error": "finding_key 'x' not found"}
        self.assertEqual(slim_export(failed, "x"), (failed, {}))
        traceless = export_response("vuln:a")
        traceless["details"]["debug_trace"] = None
        slimmed, removed = slim_export(traceless, "vuln:a")
        self.assertEqual(slimmed, traceless)
        self.assertEqual(removed, {})
        self.assertEqual(slim_export("not json", "x"), ("not json", {}))


class TestExportEntry(unittest.TestCase):
    def test_entry_records_what_slimming_removed(self):
        entry = export_entry("vuln:a", "HIGH", export_response("vuln:a", prompt_chars=9000))
        self.assertEqual(entry["finding_key"], "vuln:a")
        self.assertEqual(entry["severity"], "HIGH")
        self.assertIn("slimmed", entry)
        self.assertTrue(export_succeeded(entry))

    def test_nothing_removed_means_no_note(self):
        entry = export_entry("vuln:a", "HIGH", export_response("vuln:a", other_slices=0))
        self.assertNotIn("slimmed", entry)

    def test_failed_export(self):
        self.assertFalse(export_succeeded(export_entry("k", "HIGH", {"success": False})))
        self.assertFalse(export_succeeded(None))

    def test_request_args_wrap_the_request_as_a_string(self):
        args = json.loads(export_request_args("vuln:a"))
        self.assertEqual(json.loads(args["request_json"]), {"finding_key": "vuln:a"})


class TestUpdateExportDocument(unittest.TestCase):
    def setUp(self):
        self.dir = scratch_dir("test_finding_export_doc_")
        self.path = str(self.dir / "findings" / "s.export.json")

    def tearDown(self):
        drop_scratch(self.dir)

    def demoted_section(self):
        return {"exported_utc": "t1", "demoted_finding_keys": 1, "exported": 1,
                DEMOTED_EXPORTS_KEY: [{"finding_key": "vuln:d", "severity": "LOW", "export": {}}]}

    def alertable_section(self):
        return {"alertable_exported_utc": "t2", "alertable_finding_keys": 1, "alertable_exported": 1,
                ALERTABLE_EXPORTS_KEY: [{"finding_key": "vuln:a", "severity": "HIGH", "export": {}}]}

    def test_both_orders_keep_both_sections(self):
        for first, second in ((self.demoted_section, self.alertable_section),
                              (self.alertable_section, self.demoted_section)):
            if os.path.exists(self.path):
                os.remove(self.path)
            update_export_document(self.path, "s", "token_exfiltration", first())
            update_export_document(self.path, "s", "token_exfiltration", second())
            with open(self.path, encoding="utf-8") as fh:
                doc = json.load(fh)
            self.assertEqual(doc["scenario"], "s")
            self.assertEqual(doc["check"], "token_exfiltration")
            self.assertEqual(doc[DEMOTED_EXPORTS_KEY][0]["finding_key"], "vuln:d")
            self.assertEqual(doc[ALERTABLE_EXPORTS_KEY][0]["finding_key"], "vuln:a")

    def test_demoted_reader_still_reads_its_section(self):
        # count_adjudicator_demoted reads `exports` only: an alertable export
        # in the same document must not count as an adjudicator DEMOTE.
        key = "vuln:a"
        demoted = export_response(key)
        demoted["details"]["debug_trace"]["llm_decision"]["finding_verdicts"][0]["verdict"] = "DEMOTE"
        update_export_document(self.path, "file_events", "file_system_tampering",
                               {ALERTABLE_EXPORTS_KEY: [{"finding_key": key, "export": demoted}]})
        with open(self.path, encoding="utf-8") as fh:
            doc = json.load(fh)
        self.assertEqual(sum(1 for e in doc.get(DEMOTED_EXPORTS_KEY) or []
                             if demoted_by_adjudicator(e.get("finding_key", ""), e.get("export"))), 0)

    def test_unreadable_document_is_replaced(self):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.write("{not json")
        doc = update_export_document(self.path, "s", None, self.alertable_section())
        self.assertIsNone(doc["check"])
        self.assertEqual(doc["alertable_exported"], 1)


class TestScenarioMeta(unittest.TestCase):
    def test_shape(self):
        meta = scenario_meta("agent_memory_scrape", "process_memory_scrape", ["ssh-agent"], [63180, 53],
                             "critical", True, 3)
        self.assertEqual(meta, {
            "scenario": "agent_memory_scrape",
            "expected_check": "process_memory_scrape",
            "markers": ["ssh-agent"],
            "ports": [53, 63180],
            "expected_severity": "CRITICAL",
            "requires_alert": True,
            "alertable_export_limit": 3,
        })
        self.assertIsNone(scenario_meta("s", "c", [], [], "", False, 0)["expected_severity"])


FAKE_CLI = r'''
import json, os, sys

state = os.environ["FAKE_CLI_STATE"]
args = sys.argv[1:]
if args[:1] == ["--version"]:
    print("edamame_cli 0.0.0-test")
    raise SystemExit(0)
if args[:1] != ["rpc"] or len(args) < 2:
    print(f"unexpected invocation {args}", file=sys.stderr)
    raise SystemExit(2)
method = args[1]
with open(os.path.join(state, "calls.log"), "a", encoding="utf-8") as fh:
    fh.write(method + "\n")
with open(os.path.join(state, "answers.json"), encoding="utf-8") as fh:
    answers = json.load(fh)
if method == "export_attack_pattern_finding_details":
    request = json.loads(json.loads(args[2])["request_json"])
    answer = answers["exports"].get(request["finding_key"], {"success": False, "error": "not found"})
    if answer == "RPC_ERROR":
        print("rpc error: deadline exceeded", file=sys.stderr)
        raise SystemExit(1)
    print("Result: " + json.dumps(json.dumps(answer)))
elif method in answers["string"]:
    print("Result: " + json.dumps(json.dumps(answers["string"][method])))
elif method in answers["typed"]:
    print("Result: " + json.dumps(answers["typed"][method]))
else:
    print("Result: null")
'''

FAKE_TRIGGER = r'''
import argparse, time
p = argparse.ArgumentParser()
p.add_argument("--agent-type")
p.add_argument("--duration", type=int, default=1)
p.add_argument("--interval", type=int, default=1)
p.parse_known_args()
time.sleep(1)
'''


@unittest.skipUnless(shutil.which("bash"), "needs bash")
class TestRunnerAlertableExport(unittest.TestCase):
    """`run_cve_detection.sh` end to end against a fake edamame_cli."""

    def setUp(self):
        self.dir = scratch_dir("test_finding_export_runner_")
        self.triggers = self.dir / "triggers"
        self.triggers.mkdir()
        for name in ("_edamame_cli.py", "_finding_match.py", "_finding_export.py"):
            shutil.copy(TRIGGERS / name, self.triggers / name)
        (self.triggers / "trigger_cve_token_exfil.py").write_text(FAKE_TRIGGER, encoding="utf-8")
        self.state = self.dir / "cli_state"
        self.state.mkdir()
        self.cli = self.dir / "edamame_cli"
        self.cli.write_text(f"#!{sys.executable}\n" + textwrap.dedent(FAKE_CLI), encoding="utf-8")
        self.cli.chmod(0o755)
        self.out = self.dir / "out"

    def tearDown(self):
        drop_scratch(self.dir)

    def answers(self) -> dict:
        new = finding("vuln:new", first_detected="2026-10-13T10:05:00Z", session_uid="sess-1",
                      open_files=["/Users/u/.ssh/demo_openclaw_exfil_token"], destination_port=63169)
        old = finding("vuln:old", first_detected="2026-10-13T10:00:00Z", session_uid="sess-2",
                      destination_port=63169)
        low = finding("vuln:low", "LOW", destination_port=63169)
        unrelated = finding("vuln:unrelated", destination_port=443)
        return {
            "string": {
                "get_attack_pattern_detector_status": {"running": True},
                "get_attack_pattern_findings": {"findings": [old, low, unrelated]},
                "get_attack_pattern_history": [{"report_id": "r2", "findings": [new]},
                                               {"report_id": "r1", "findings": [old]}],
            },
            "typed": {
                "get_core_version": "2.0.8-test",
                "get_current_sessions": [],
            },
            "exports": {
                "vuln:new": export_response("vuln:new", prompt_chars=9000, other_slices=2),
                "vuln:old": export_response("vuln:old"),
            },
        }

    def run_runner(self, *extra: str, answers=None) -> subprocess.CompletedProcess:
        (self.state / "answers.json").write_text(json.dumps(answers or self.answers()), encoding="utf-8")
        env = dict(os.environ)
        env.update({"EDAMAME_CLI": str(self.cli), "EDAMAME_CLI_BIN": str(self.cli),
                    "FAKE_CLI_STATE": str(self.state), "PYTHON": sys.executable})
        return subprocess.run(
            ["bash", str(HERE / "run_cve_detection.sh"),
             "--triggers-dir", str(self.triggers), "--output-dir", str(self.out),
             "--trigger-duration", "1", "--post-wait", "0", "--cooldown", "0",
             "--poll-attempts", "1", "--poll-interval", "1", "--readiness-wait", "0",
             "--scenarios", "cve_token_exfil", *extra],
            env=env, capture_output=True, text=True, timeout=180,
        )

    def calls(self) -> list:
        path = self.state / "calls.log"
        return path.read_text(encoding="utf-8").split() if path.is_file() else []

    def test_alertable_findings_are_exported_before_the_history_clear(self):
        proc = self.run_runner()
        self.assertEqual(proc.returncode, 0, proc.stderr[-3000:])
        results = json.loads((self.out / "results.json").read_text(encoding="utf-8"))
        self.assertEqual(results["scenarios"][0]["status"], "pass")

        meta = json.loads((self.out / "findings" / "cve_token_exfil.meta.json").read_text(encoding="utf-8"))
        self.assertEqual(meta["expected_check"], "token_exfiltration")
        self.assertEqual(meta["ports"], [63169])
        self.assertIn("_exfil_token", meta["markers"])
        self.assertEqual(meta["alertable_export_limit"], 3)

        doc = json.loads((self.out / "findings" / "cve_token_exfil.export.json").read_text(encoding="utf-8"))
        self.assertNotIn(DEMOTED_EXPORTS_KEY, doc, "no demoted section on an alerting pass")
        self.assertEqual(doc["alertable_finding_keys"], 2, "the LOW and the unattributed finding are not exported")
        self.assertEqual([e["finding_key"] for e in doc[ALERTABLE_EXPORTS_KEY]], ["vuln:new", "vuln:old"])
        newest = doc[ALERTABLE_EXPORTS_KEY][0]
        self.assertTrue(export_succeeded(newest))
        self.assertEqual(newest["slimmed"], {"llm_prompt_chars": 9000, "input_slices_dropped": 2})
        self.assertEqual(newest["export"]["details"]["finding_input_slice"]["sessions"], [{"session_uid": "sess-1"}])

        calls = self.calls()
        exports = [i for i, m in enumerate(calls) if m == "export_attack_pattern_finding_details"]
        clears = [i for i, m in enumerate(calls) if m == "clear_attack_pattern_history"]
        self.assertEqual(len(exports), 2)
        self.assertTrue(clears and max(exports) < clears[-1],
                        f"the export must precede the post-scenario clear: {calls}")

    def test_limit_and_opt_out(self):
        proc = self.run_runner("--export-matched", "1")
        self.assertEqual(proc.returncode, 0, proc.stderr[-3000:])
        doc = json.loads((self.out / "findings" / "cve_token_exfil.export.json").read_text(encoding="utf-8"))
        self.assertEqual([e["finding_key"] for e in doc[ALERTABLE_EXPORTS_KEY]], ["vuln:new"])
        self.assertEqual(doc["alertable_finding_keys"], 2)

        shutil.rmtree(self.out)
        (self.state / "calls.log").unlink()
        proc = self.run_runner("--export-matched", "0")
        self.assertEqual(proc.returncode, 0, proc.stderr[-3000:])
        self.assertFalse((self.out / "findings" / "cve_token_exfil.export.json").exists())
        self.assertNotIn("export_attack_pattern_finding_details", self.calls())
        results = json.loads((self.out / "results.json").read_text(encoding="utf-8"))
        self.assertEqual(results["scenarios"][0]["status"], "pass", "exports never change a result")

    def test_an_export_the_daemon_does_not_answer_stops_the_scenarios_exports(self):
        answers = self.answers()
        answers["exports"]["vuln:new"] = "RPC_ERROR"
        proc = self.run_runner(answers=answers)
        self.assertEqual(proc.returncode, 0, proc.stderr[-3000:])
        doc = json.loads((self.out / "findings" / "cve_token_exfil.export.json").read_text(encoding="utf-8"))
        self.assertEqual(len(doc[ALERTABLE_EXPORTS_KEY]), 1, "no second attempt after a failed RPC")
        self.assertFalse(export_succeeded(doc[ALERTABLE_EXPORTS_KEY][0]))
        self.assertIn("rpc failed", doc[ALERTABLE_EXPORTS_KEY][0]["export"]["error"])
        self.assertEqual(self.calls().count("export_attack_pattern_finding_details"), 1)
        results = json.loads((self.out / "results.json").read_text(encoding="utf-8"))
        self.assertEqual(results["scenarios"][0]["status"], "pass", "a failed export never changes a result")


if __name__ == "__main__":
    unittest.main(verbosity=2)
