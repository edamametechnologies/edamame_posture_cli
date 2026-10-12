#!/usr/bin/env python3
"""Headless tests for the EDAMAME Trigger Panel wrapper (tools/trigger_panel/app.py).

No Tk window and no real triggers: they exercise the pure, testable pieces of
the panel -- cleanup output classification, the streaming helper with its
timeout watchdog, state-dir agreement with the triggers' own _common, trigger
discovery and banner parsing. Run with any Python that has tkinter:

    python3 -m unittest discover -s tests/trigger_panel

tkinter is imported because app.py imports it at module load; the embedded
runtime the panel ships with always has it.
"""

from __future__ import annotations

import importlib.util
import os
import sys
import time
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
PANEL_DIR = REPO / "tools" / "trigger_panel"
TRIGGERS_DIR = REPO / "tests" / "security" / "triggers"
sys.path.insert(0, str(PANEL_DIR))

try:
    import tkinter  # noqa: F401  (app.py imports it at module load)
except Exception as exc:  # pragma: no cover - environment without Tk
    raise unittest.SkipTest(f"tkinter unavailable: {exc}")

import app  # noqa: E402  (from PANEL_DIR, after sys.path insert)


def _write(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    path.chmod(0o755)
    return path


class ClassifyCleanupLine(unittest.TestCase):
    def test_removed(self):
        self.assertEqual(app.classify_cleanup_line("  removed /tmp/x"), "removed")

    def test_blocked(self):
        for line in (
            "  cannot remove /usr/local/bin/standin: Permission denied",
            "  could not kill pid=5 (x.pid): permission denied",
            "  cannot kill pid=7 (permission denied)",
        ):
            self.assertEqual(app.classify_cleanup_line(line), "blocked", line)

    def test_info(self):
        self.assertEqual(
            app.classify_cleanup_line("Cleaning up demo state in /tmp/x"), "info"
        )


class RunAndStream(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(os.environ.get("RUNNER_TEMP", "/tmp")) / f"tp-test-{os.getpid()}"
        self.tmp.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        for p in self.tmp.glob("*"):
            p.unlink(missing_ok=True)
        self.tmp.rmdir()

    def test_streams_lines_and_returns_code(self):
        script = _write(
            self.tmp / "fake_cleanup.py",
            "import sys\n"
            "print('Cleaning up demo state in /tmp/x')\n"
            "print('  removed /tmp/x/a')\n"
            "print('  removed /tmp/x/b')\n"
            "print('  cannot remove /usr/local/bin/s: Permission denied')\n"
            "sys.exit(0)\n",
        )
        lines: list[str] = []
        code, timed_out = app.run_and_stream(
            [sys.executable, str(script)], self.tmp, lines.append, timeout_secs=30
        )
        self.assertEqual(code, 0)
        self.assertFalse(timed_out)
        self.assertEqual(sum(1 for l in lines if app.classify_cleanup_line(l) == "removed"), 2)
        self.assertEqual(sum(1 for l in lines if app.classify_cleanup_line(l) == "blocked"), 1)

    def test_timeout_kills_a_silent_hang(self):
        # Prints nothing and sleeps far past the timeout: the watchdog must kill
        # it and run_and_stream must return promptly (the "hang" the panel had).
        script = _write(
            self.tmp / "hang.py",
            "import time\ntime.sleep(600)\n",
        )
        started = time.monotonic()
        code, timed_out = app.run_and_stream(
            [sys.executable, str(script)], self.tmp, lambda _l: None, timeout_secs=2
        )
        elapsed = time.monotonic() - started
        self.assertTrue(timed_out)
        self.assertLess(elapsed, 20, "watchdog did not stop the hang promptly")

    def test_timeout_kills_a_chatty_hang(self):
        # Keeps printing forever: the read loop must still end at the timeout.
        script = _write(
            self.tmp / "chatty.py",
            "import time, sys\n"
            "while True:\n"
            "    print('  removed /tmp/x/tick'); sys.stdout.flush(); time.sleep(0.05)\n",
        )
        started = time.monotonic()
        code, timed_out = app.run_and_stream(
            [sys.executable, str(script)], self.tmp, lambda _l: None, timeout_secs=2
        )
        self.assertTrue(timed_out)
        self.assertLess(time.monotonic() - started, 20)


class StateDir(unittest.TestCase):
    def test_matches_triggers_common(self):
        spec = importlib.util.spec_from_file_location(
            "_common_under_test", TRIGGERS_DIR / "_common.py"
        )
        common = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(common)
        for agent in app.AGENT_TYPES:
            self.assertEqual(
                str(app.state_dir_for(agent, TRIGGERS_DIR)),
                str(common.state_dir_for(agent)),
                agent,
            )


class Discovery(unittest.TestCase):
    def test_finds_the_real_triggers(self):
        found = app.discover_triggers(TRIGGERS_DIR)
        self.assertGreaterEqual(len(found), 20)
        # Every discovered item points at an existing trigger_*.py.
        for _name, path in found:
            self.assertTrue(path.name.startswith("trigger_") and path.is_file())


if __name__ == "__main__":
    unittest.main()
