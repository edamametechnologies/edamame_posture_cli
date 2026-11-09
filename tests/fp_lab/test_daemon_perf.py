#!/usr/bin/env python3
"""Tests for tests/fp_lab/daemon_perf.py's pure parts: the table trends over
sparse readings (a reading every TABLE_SAMPLE_SECS, None between), the
"What grew" line of the summary, and the table reader when the daemon does
not answer. Nothing here samples a process or calls edamame_cli.

    python3 -m unittest discover -s tests/fp_lab -p 'test_*.py'
    python3 tests/fp_lab/test_daemon_perf.py
"""

from __future__ import annotations

import datetime as dt
import json
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import daemon_perf as perf  # noqa: E402

T0 = dt.datetime(2026, 11, 9, 12, 0, tzinfo=dt.timezone.utc)


def samples(count: int, interval: float = 30.0, pid: int = 4242, table_every: int = 10, **tables):
    """`count` memory samples `interval` s apart. Each table column named in
    `tables` is a function of the sample index, read on every
    `table_every`th sample and None between, as PerfSampler writes it."""
    rows = []
    for i in range(count):
        row = {"at": T0 + dt.timedelta(seconds=i * interval), "pid": pid, "rss_mb": 300.0 + i * 0.1,
               "cpu_seconds": i * 1.5, "footprint_mb": None}
        for col in perf.TABLE_COLUMNS:
            fn = tables.get(col)
            row[col] = fn(i) if (fn and i % table_every == 0) else None
        rows.append(row)
    return rows


class TableTrends(unittest.TestCase):
    def test_slope_over_sparse_readings(self):
        # 90 samples at 30 s are 45 min: warm-up (10 min) leaves the readings
        # of samples 20..80, a 30 min span, the slope's floor.
        rows = samples(90, sessions_tracked=lambda i: 100 + 2 * i, ap_trace_mb=lambda i: 1.5)
        trends = perf.table_trends(rows, rows[0]["at"], rows[-1]["pid"])
        s = trends["sessions_tracked"]
        self.assertEqual(s["readings"], 7)
        self.assertEqual((s["start"], s["end"]), (140, 260))
        self.assertAlmostEqual(s["slope_per_hour"], 240, delta=1)  # +2 every 30 s
        self.assertEqual(s["unit"], "")
        self.assertEqual(trends["ap_trace_mb"]["slope_per_hour"], 0.0)
        self.assertEqual(trends["ap_trace_mb"]["unit"], "MB")
        self.assertEqual(trends["lan_sessions"]["readings"], 0)
        self.assertIsNone(trends["lan_sessions"]["slope_per_hour"])

    def test_short_window_has_no_slope(self):
        rows = samples(40, sessions_tracked=lambda i: 100 + i)  # 20 min: 5 min of readings after warm-up
        t = perf.table_trends(rows, rows[0]["at"], rows[-1]["pid"])["sessions_tracked"]
        self.assertEqual(t["readings"], 2)
        self.assertEqual((t["start"], t["end"]), (120, 130))
        self.assertIsNone(t["slope_per_hour"])

    def test_readings_of_an_earlier_pid_are_left_out(self):
        rows = samples(90, sessions_tracked=lambda i: 100 + i)
        for r in rows[:50]:
            r["pid"] = 1  # a restart at sample 50: only the new daemon's readings count
        t = perf.table_trends(rows, rows[0]["at"], rows[-1]["pid"])["sessions_tracked"]
        self.assertEqual(t["readings"], 4)  # samples 50, 60, 70, 80
        self.assertIsNone(t["slope_per_hour"])  # a 15 min span


class WhatGrew(unittest.TestCase):
    def trends(self, **over):
        base = {col: {"label": perf.TABLE_META[col][1], "unit": perf.TABLE_META[col][0].strip(), "readings": 7,
                      "start": 10.0, "end": 10.0, "span_secs": 1800, "slope_per_hour": 0.0}
                for col in perf.TABLE_COLUMNS}
        for col, (start, end, slope) in over.items():
            base[col].update(start=start, end=end, slope_per_hour=slope)
        return base

    def test_names_growth_largest_first_then_flat(self):
        line = perf.what_grew(self.trends(sessions_tracked=(1200, 2100, 410.0), ap_trace_mb=(2.0, 8.4, 3.1)))
        self.assertTrue(line.startswith("What grew after warm-up (30 min of table readings): "), line)
        self.assertIn("attack-pattern traces 2.0 MB -> 8.4 MB (+3.1 MB/h), sessions tracked 1200 -> 2100 (+410/h)",
                      line)
        self.assertIn("; flat: LAN sessions, lineage rows, task-access edges", line)
        self.assertNotIn("sessions tracked", line.split("flat:")[1])

    def test_nothing_grew(self):
        line = perf.what_grew(self.trends())
        self.assertIn("nothing in the sampled tables", line)
        self.assertNotIn("flat:", line)

    def test_not_sampled(self):
        t = self.trends()
        for row in t.values():
            row.update(readings=0, start=None, end=None, slope_per_hour=None)
        self.assertEqual(perf.what_grew(t), "Tables: not sampled (edamame_cli did not answer during the run)")

    def test_too_few_readings(self):
        t = self.trends()
        for row in t.values():
            row.update(readings=2, slope_per_hour=None)
        self.assertIn("too few table readings (2)", perf.what_grew(t))


class ReadTables(unittest.TestCase):
    def test_no_rpc_is_all_empty(self):
        got = perf.read_tables(None)
        self.assertEqual(sorted(got), sorted(perf.TABLE_COLUMNS))
        self.assertEqual(set(got.values()), {None})

    def test_failing_rpc_is_all_empty(self):
        def rpc(_method):
            raise RuntimeError("no daemon")
        self.assertEqual(set(perf.read_tables(rpc).values()), {None})

    def test_answers_are_read_from_dicts_and_json_strings(self):
        answers = {
            "get_analyzer_stats": {"session_stats": {"total_sessions_tracked": 1234}},
            "get_lan_sessions_status": {"session_count": 7},
            "get_attack_pattern_detector_status": json.dumps({
                "process_lineage_table_size": 900, "task_access_edges": 12,
                "process_events_lost_total": 0, "cache_size": 3}),
            "get_agentic_memory_stats": json.dumps({
                "vulnerability": {"history_trace_entries": 40, "history_trace_json_bytes": 2 * perf.MB},
                "divergence": {"verdict_history_trace_entries": 5, "verdict_history_trace_json_bytes": perf.MB / 2,
                               "model_history_json_bytes": 0},
                "overall": {"process_memory_bytes": 512 * perf.MB}}),
            "get_file_monitor_status": None,
        }
        calls = []

        def rpc(method):
            calls.append(method)
            return answers[method]

        got = perf.read_tables(rpc)
        self.assertEqual(got["sessions_tracked"], 1234)
        self.assertEqual(got["lan_sessions"], 7)
        self.assertEqual(got["lineage_rows"], 900)
        self.assertEqual(got["process_events_lost"], 0)
        self.assertEqual(got["ap_trace_entries"], 40)
        self.assertEqual(got["ap_trace_mb"], 2.0)
        self.assertEqual(got["div_trace_mb"], 0.5)
        self.assertEqual(got["model_history_mb"], 0.0)
        self.assertEqual(got["core_process_mb"], 512.0)
        self.assertIsNone(got["fim_events"])
        self.assertEqual(len(calls), len(set(calls)), "each RPC is called once per reading")

    def test_csv_cell_format(self):
        self.assertEqual(perf._fmt_table("sessions_tracked", 1234.0), "1234")
        self.assertEqual(perf._fmt_table("ap_trace_mb", 2.04), "2.0")
        self.assertEqual(perf._fmt_table("fim_events", None), "")


class Summary(unittest.TestCase):
    def test_summary_and_markdown_carry_the_tables(self):
        rows = samples(90, sessions_tracked=lambda i: 100 + 2 * i)
        summary = perf.summarize(rows, [])
        self.assertEqual(summary["tables"]["sessions_tracked"]["end"], 260)
        self.assertTrue(summary["what_grew"].startswith("What grew after warm-up"))
        self.assertIn("sessions tracked 140 -> 260 (+240/h)", summary["what_grew"])
        lines = perf.markdown(summary)
        self.assertTrue(any(line.startswith("- What grew after warm-up") for line in lines), lines)

    def test_no_table_readings_is_said_not_raised(self):
        rows = samples(90)
        summary = perf.summarize(rows, [])
        self.assertEqual(summary["what_grew"], "Tables: not sampled (edamame_cli did not answer during the run)")
        self.assertEqual(summary["tables"]["fim_events"]["readings"], 0)


if __name__ == "__main__":
    unittest.main()
