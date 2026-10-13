#!/usr/bin/env python3
"""Tests for tests/local_loop/local_loop_summary.py on synthetic run directories.

Each test lays out what run_local_loop.sh and its runners write (window.tsv,
steps.tsv, baseline/baseline.json, cve/results.json and its exports, the
attack shaper's report, fp_lab/summary.json) and checks the verdict, its line
and the rendered tables. Scratch directories are under the repository's
ignored tests_temp/, never OS temp.

    python3 -m unittest discover -s tests/local_loop -p 'test_*.py'
    python3 tests/local_loop/test_local_loop_summary.py
"""

from __future__ import annotations

import contextlib
import io
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRATCH = HERE.parent.parent / "tests_temp"
sys.path.insert(0, str(HERE))

import local_loop_summary as summary  # noqa: E402


class Run:
    """A synthetic run_local_loop.sh output directory."""

    def __init__(self, root: Path):
        self.dir = root / "dev-mac-20261013-101500"
        self.dir.mkdir()
        self.window = {"host": "dev-mac", "platform_label": "macos-arm64", "adjudication": "advisory",
                       "portal": "no", "posture_bin": "/w/edamame_posture/target/release/edamame_posture",
                       "posture_sha256": "ab" * 32, "core_version": "2.0.8", "helper_mode": "manual",
                       "app_bundle": "/w/app/Debug/EDAMAME Security.app", "started_utc": "2026-10-13T10:15:00Z",
                       "closed_utc": "2026-10-13T11:40:00Z", "restore_problems": "0",
                       "es_status": "log: /var/log/edamame/edamame_posture_1.log|ES client creation failed"}
        self.steps = []

    def step(self, name, status="ok", rc=0, seconds=10):
        self.steps.append((name, status, rc, seconds, str(self.dir / f"{name}.log")))
        return self

    def write_json(self, rel, data):
        path = self.dir / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data), encoding="utf-8")
        return self

    def baseline(self, status="pass", findings=()):
        return self.write_json("baseline/baseline.json", {
            "status": status, "duration_s": 120, "finding_total": len(findings),
            "adjudication": {"mode": "advisory"},
            "samples": [{"name": "sample_0001.json", "findings": {"current": list(findings), "history": list(findings)}}]})

    def cve(self, scenarios):
        self.write_json("cve/results.json", {"core_version": "2.0.8", "scenarios": scenarios,
                                             "totals": {"total": len(scenarios)}})
        for s in scenarios:
            if s.get("finding_alertable"):
                self.write_json(f"cve/findings/{s['scenario']}.export.json",
                                {"alertable_exported": 2, "alertable_finding_keys": 3, "alertable_exports": []})
        return self

    def shaped(self, rows):
        for r in rows:
            if r["status"] == "written":
                self.write_json(f"staging/attack_corpus/{r['scenario']}/{Path(r['path']).name}", {})
        return self.write_json("staging/attack_corpus.report.json", {"scenarios": rows})

    def fp_lab(self, cases, verdict="PASS"):
        return self.write_json("fp_lab/summary.json", {"verdict": verdict, "cases": cases,
                                                       "counts": {"PASS": len(cases)},
                                                       "adjudication": {"attack_pattern": "advisory"}})

    def finish(self):
        (self.dir / "window.tsv").write_text("".join(f"{k}\t{v}\n" for k, v in self.window.items()),
                                             encoding="utf-8")
        (self.dir / "steps.tsv").write_text("".join("\t".join(str(x) for x in row) + "\n" for row in self.steps),
                                            encoding="utf-8")
        return self


def scenario(name, status="pass", alertable=1, check="token_exfiltration", extra=""):
    return {"scenario": name, "expected_check": check, "status": status, "finding_alertable": alertable,
            "severities": "HIGH:1" if alertable else "none", "extra": extra, "elapsed_s": 60}


def written(name):
    return {"scenario": name, "status": "written",
            "path": f"/out/staging/attack_corpus/{name}/macos-arm64-local-dev-mac-20261013-101500.json"}


class SummaryTest(unittest.TestCase):
    def setUp(self):
        SCRATCH.mkdir(exist_ok=True)
        self.root = Path(tempfile.mkdtemp(prefix="test_local_loop_summary_", dir=str(SCRATCH)))

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)
        try:
            SCRATCH.rmdir()  # only when no other test still uses it
        except OSError:
            pass

    def run_summary(self, run: Run):
        run.finish()
        with contextlib.redirect_stdout(io.StringIO()) as printed:
            rc = summary.main(["local_loop_summary.py", str(run.dir)])
        data = json.loads((run.dir / "summary.json").read_text(encoding="utf-8"))
        md = (run.dir / "summary.md").read_text(encoding="utf-8")
        return rc, data, md, printed.getvalue()

    def clean_run(self) -> Run:
        return (Run(self.root)
                .step("baseline").step("cve").step("fp_lab").step("shape_attack")
                .baseline()
                .cve([scenario("cve_token_exfil"), scenario("blacklist_comm", check="blacklisted_sessions")])
                .shaped([written("cve_token_exfil"),
                         {"scenario": "blacklist_comm", "status": "skipped",
                          "reason": "blacklisted_sessions is asserted on the session list"}])
                .fp_lab([{"case_id": "direct-git-lab-repo", "status": "PASS", "alertable": [], "low": []}]))


class TestVerdicts(SummaryTest):
    def test_pass(self):
        rc, data, md, printed = self.run_summary(self.clean_run())
        self.assertEqual(rc, 0)
        self.assertEqual(data["verdict"], "PASS")
        self.assertEqual(printed.strip().splitlines()[0],
                         "VERDICT PASS: cve 2/2 passed; baseline clean (120 s); fp-lab 0 alertable, "
                         "0 incident(s); 1 attack envelope(s) staged")
        rows = {r["scenario"]: r for r in data["cve"]["scenarios"]}
        self.assertEqual(rows["cve_token_exfil"]["exported"], 2)
        self.assertEqual(rows["cve_token_exfil"]["envelope"], "macos-arm64-local-dev-mac-20261013-101500.json")
        self.assertTrue(rows["blacklist_comm"]["envelope"].startswith("skipped: blacklisted_sessions"))
        self.assertEqual(data["staged"]["attack_corpus"]["files"],
                         ["cve_token_exfil/macos-arm64-local-dev-mac-20261013-101500.json"])
        self.assertIn("| `cve_token_exfil` | token_exfiltration | pass | 1 | HIGH:1 | 2 |", md)
        self.assertIn("ES client creation failed", md)

    def test_failures_are_listed(self):
        alert = {"check": "file_system_tampering", "severity": "HIGH", "process": "/usr/bin/python3",
                 "subject_path": "/Users/u/fp-lab/ws/x/build.rs", "export_path": "/e.json",
                 "corpus_candidate": "/c/FP-LAB-DIRECT-BUILD-RUST-TEMP/x.json"}
        ambient = {"check": "sandbox_exploitation", "severity": "LOW", "finding_key": "vuln:amb",
                   "process_path": "/opt/homebrew/bin/node"}
        run = (Run(self.root)
               .step("baseline", "exit", 1).step("cve").step("fp_lab", "exit", 1).step("shape_attack")
               .baseline("fail", findings=[ambient])
               .cve([scenario("cve_token_exfil"),
                     scenario("process_memory_scrape", "fail", 0, "process_memory_scrape")])
               .shaped([written("cve_token_exfil")])
               .fp_lab([{"case_id": "direct-build-rust-temp", "status": "FAIL", "alertable": [alert], "low": []},
                        {"case_id": "post-run-drain", "status": "PASS", "alertable": [], "low": []}],
                       verdict="FAIL"))
        rc, data, md, printed = self.run_summary(run)
        self.assertEqual(rc, 1)
        self.assertEqual(data["verdict"], "FAIL")
        line = printed.strip().splitlines()[0]
        self.assertIn("cve 1/2 passed (failed: process_memory_scrape)", line)
        self.assertIn("baseline dirty (1 finding(s), 0 alertable)", line)
        self.assertIn("fp-lab 1 alertable, 0 incident(s)", line)
        self.assertEqual(data["baseline"]["findings"][0]["finding_key"], "vuln:amb", "deduplicated across lists")
        self.assertEqual(data["fp_lab"]["alertable"][0]["candidate"], "/c/FP-LAB-DIRECT-BUILD-RUST-TEMP/x.json")
        self.assertIn("ALERTABLE HIGH `file_system_tampering` in `direct-build-rust-temp`", md)
        self.assertIn("- failure: CVE scenario(s) failed: process_memory_scrape", md)

    def test_daemon_that_never_answered(self):
        run = Run(self.root)
        del run.window["core_version"]
        rc, data, _, _ = self.run_summary(run)
        self.assertEqual(rc, 2)
        self.assertEqual(data["verdict"], "INCOMPLETE")
        self.assertIn("the owned daemon never answered (no core version recorded)", data["incomplete"])
        self.assertIn("cve never ran", data["incomplete"])

    def test_fp_lab_preflight_refusal(self):
        run = self.clean_run()
        shutil.rmtree(run.dir / "fp_lab")
        run.steps = [s for s in run.steps if s[0] != "fp_lab"]
        run.step("fp_lab", "exit", 2)
        run.write_json("fp_lab/preflight.json", {"problems": ["file monitor is not running"]})
        rc, data, md, _ = self.run_summary(run)
        self.assertEqual(rc, 2)
        self.assertIn("FP lab wrote no summary (file monitor is not running)", data["incomplete"])
        self.assertIn("missing: file monitor is not running", md)

    def test_interrupted_cve_suite(self):
        run = self.clean_run()
        (run.dir / "cve" / "results.json").unlink()
        run.window["interrupted"] = "SIGINT"
        rc, data, _, _ = self.run_summary(run)
        self.assertEqual(rc, 2)
        self.assertIn("the run was interrupted (SIGINT)", data["incomplete"])
        self.assertIn("CVE suite wrote no results.json", data["incomplete"])

    def test_unmeasured_baseline(self):
        run = self.clean_run().baseline("unmeasured")
        rc, data, _, _ = self.run_summary(run)
        self.assertEqual(rc, 2)
        self.assertIn("baseline unmeasured", data["incomplete"])

    def test_skipped_steps_and_restore_warning(self):
        run = (Run(self.root).step("baseline", "skipped").step("cve", "skipped").step("fp_lab", "skipped"))
        run.window["restore_problems"] = "1"
        rc, data, _, printed = self.run_summary(run)
        self.assertEqual(rc, 0)
        self.assertIn("cve skipped; baseline skipped; fp-lab skipped", data["line"])
        self.assertIn("warning: the window's restore reported a problem", printed)

    def test_usage(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(summary.main(["local_loop_summary.py"]), 2)
            self.assertEqual(summary.main(["local_loop_summary.py", str(self.root / "missing")]), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
