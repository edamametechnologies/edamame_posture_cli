#!/usr/bin/env python3
"""Tests for the kernel process-ancestry gate's verdict (``run_lineage_gate.evaluate``).

The verdict is what ``lineage.json`` records and ``check_gate.py`` enforces,
so every shape of a broken ancestry must fail it -- above all the pre-2.0.5
macOS one, where each exec named itself as its parent.

Run with::

    python3 -m unittest discover -s tests/security -p 'test_*.py'
    python3 tests/security/test_run_lineage_gate.py
"""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from run_lineage_gate import evaluate, image_stem  # noqa: E402

INTERPRETER, PARENT, CHILD = 4000, 4001, 4002

HEALTHY = {
    "exec_total": 120,
    "exec_with_parent_total": 118,
    "exec_parent_resolved_total": 90,
    "self_parent_total": 0,
}


def probe(ppid=PARENT, ancestry=None, lineage=None, image="/w/edl_c", found=True):
    if ancestry is None:
        ancestry = [
            {"pid": PARENT, "image_path": "/w/edl_p", "process_name": "edl_p"},
            {"pid": INTERPRETER, "image_path": "/usr/bin/python3.12", "process_name": "python3.12"},
            {"pid": 1, "image_path": "/sbin/launchd", "process_name": "launchd"},
        ]
    return {
        "success": True,
        "pid": CHILD,
        "found": found,
        "kernel_exec": {"image_path": image, "ppid": ppid, "ancestry": ancestry} if found else None,
        "lineage": HEALTHY if lineage is None else lineage,
    }


STATUS = {"process_lineage_self_parent_total": 0, "process_lineage_exec_total": 120}


def run(p, status=STATUS):
    return evaluate(p, status, child_pid=CHILD, parent_pid=PARENT, interpreter_pid=INTERPRETER)


class TestEvaluate(unittest.TestCase):
    def test_resolved_chain_passes(self):
        checks, problems = run(probe())
        self.assertEqual(problems, [])
        self.assertTrue(checks)
        self.assertTrue(all(checks.values()), checks)

    def test_windows_paths_pass(self):
        ancestry = [
            {"pid": PARENT, "image_path": r"D:\a\_temp\g\edl_p.exe"},
            {"pid": INTERPRETER, "image_path": r"C:\hostedtoolcache\windows\Python\3.12.10\x64\python.exe"},
        ]
        checks, problems = run(probe(ancestry=ancestry, image=r"D:\a\_temp\g\EDL_C.EXE"))
        self.assertEqual(problems, [], checks)

    def test_macos_framework_interpreter_passes(self):
        ancestry = [
            {"pid": PARENT, "image_path": "/Users/runner/work/_temp/g/edl_p"},
            {
                "pid": INTERPRETER,
                "image_path": "/Library/Frameworks/Python.framework/Versions/3.12/Resources/"
                "Python.app/Contents/MacOS/Python",
            },
        ]
        _, problems = run(probe(ancestry=ancestry))
        self.assertEqual(problems, [])

    def test_exec_named_as_its_own_parent_fails(self):
        """The pre-2.0.5 macOS sensor: ppid == pid, so no ancestry at all."""
        checks, problems = run(
            probe(ppid=CHILD, ancestry=[], lineage={**HEALTHY, "self_parent_total": 5000}),
            {"process_lineage_self_parent_total": 5000},
        )
        for name in (
            "ppid_not_self",
            "ppid_is_parent",
            "ancestry_parent",
            "ancestry_interpreter",
            "no_self_parent_events",
            "status_no_self_parent_events",
        ):
            self.assertFalse(checks[name], name)
        self.assertTrue(problems)

    def test_ancestry_that_stops_at_the_parent_fails(self):
        checks, _ = run(probe(ancestry=[{"pid": PARENT, "image_path": "/w/edl_p"}]))
        self.assertTrue(checks["ancestry_parent"])
        self.assertFalse(checks["ancestry_interpreter"])

    def test_a_parent_of_another_image_fails(self):
        """A recycled parent pid running something else is not edl_p."""
        ancestry = [
            {"pid": PARENT, "image_path": "/usr/libexec/xpcproxy"},
            {"pid": INTERPRETER, "image_path": "/usr/bin/python3"},
        ]
        checks, _ = run(probe(ancestry=ancestry))
        self.assertFalse(checks["ancestry_parent"])

    def test_unrecorded_child_fails(self):
        checks, problems = run(probe(found=False))
        self.assertFalse(checks["child_recorded"])
        self.assertFalse(checks["ppid_not_self"])
        self.assertTrue(any("no record" in p for p in problems))

    def test_probe_error_fails(self):
        checks, problems = run({"success": False, "error": "lineage table busy"})
        self.assertFalse(checks["probe_answered"])
        self.assertIn("lineage table busy", problems[0])

    def test_daemon_without_the_counters_fails(self):
        """Absent evidence is not a pass: an older daemon has no counter."""
        checks, _ = run(probe(lineage={}), {})
        self.assertFalse(checks["stream_names_parents"])
        self.assertFalse(checks["no_self_parent_events"])
        self.assertFalse(checks["status_no_self_parent_events"])

    def test_a_stream_without_parents_fails(self):
        checks, _ = run(probe(lineage={**HEALTHY, "exec_with_parent_total": 0}))
        self.assertFalse(checks["stream_names_parents"])

    def test_image_stem(self):
        self.assertEqual(image_stem(r"C:\x\EDL_P.EXE"), "edl_p")
        self.assertEqual(image_stem("/w/edl_c"), "edl_c")
        self.assertEqual(image_stem(None), "")


if __name__ == "__main__":
    unittest.main(verbosity=2)
