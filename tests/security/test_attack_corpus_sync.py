#!/usr/bin/env python3
"""The attack replay corpus follows the CVE gate's scenarios.

edamame_core/tests/attack_corpus/ holds, per scenario of run_cve_detection.sh
and per gate platform, the detector inputs of one alertable finding the gate
captured; fp_replay asserts each still alerts (README there). This test keeps
the two in step (rule: trigger-catalog.mdc):

- every scenario of run_cve_detection.sh has an envelope for every gate
  platform (minus check_gate.py's PLATFORM_EXCLUDED_SCENARIOS), unless the
  corpus's coverage.json says why not;
- the corpus has no directory for a scenario the gate no longer runs, and
  coverage.json names only gate scenarios and platforms.

It needs the sibling edamame_core clone (EDAMAME_CORE_DIR overrides) and skips
without it, so it runs in the local offline gate (edamame_core
tools/fp_loop/offline_gate.sh) and on a workspace checkout:

    python3 -m unittest discover -s tests/security -p 'test_attack_corpus_sync.py' -v
"""

from __future__ import annotations

import json
import os
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import check_gate  # noqa: E402  (PLATFORM_EXCLUDED_SCENARIOS)
from test_trigger_catalog import _runner_scenarios  # noqa: E402

CVE_RUNNER = HERE / "run_cve_detection.sh"
CORE_DIR = Path(os.environ.get("EDAMAME_CORE_DIR", HERE.parents[2] / "edamame_core"))
CORPUS = CORE_DIR / "tests" / "attack_corpus"


class AttackCorpusSyncTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not (CORPUS / "coverage.json").is_file():
            raise unittest.SkipTest(f"no attack corpus at {CORPUS} (set EDAMAME_CORE_DIR)")
        cls.coverage = json.loads((CORPUS / "coverage.json").read_text(encoding="utf-8"))
        cls.scenarios = _runner_scenarios(CVE_RUNNER)
        cls.platforms = cls.coverage["platforms"]

    def _envelopes(self, scenario: str, platform: str) -> list:
        return sorted((CORPUS / scenario).glob(f"{platform}-*.json"))

    def test_every_gate_scenario_has_an_envelope_or_a_reason(self) -> None:
        not_replayable = self.coverage["not_replayable"]
        gaps = self.coverage["platform_gaps"]
        missing = []
        for scenario in self.scenarios:
            if scenario in not_replayable:
                continue
            for platform in self.platforms:
                if scenario in check_gate.PLATFORM_EXCLUDED_SCENARIOS.get(platform, set()):
                    continue
                if platform in gaps.get(scenario, {}):
                    continue
                if not self._envelopes(scenario, platform):
                    missing.append(f"{scenario} [{platform}]")
        self.assertEqual(
            missing, [],
            "gate scenarios without an attack-corpus envelope: shape them from the next "
            "gate run (edamame_core tools/attack_corpus_from_gate.py) or say why in "
            "tests/attack_corpus/coverage.json",
        )

    def test_corpus_and_coverage_name_only_gate_scenarios(self) -> None:
        gate = set(self.scenarios)
        dirs = {p.name for p in CORPUS.iterdir() if p.is_dir()}
        self.assertEqual(sorted(dirs - gate), [], "corpus directories for scenarios the gate no longer runs")
        listed = set(self.coverage["not_replayable"]) | set(self.coverage["platform_gaps"])
        self.assertEqual(sorted(listed - gate), [], "coverage.json names scenarios the gate does not run")
        for scenario, per_platform in self.coverage["platform_gaps"].items():
            self.assertEqual(sorted(set(per_platform) - set(self.platforms)), [], scenario)
            for platform, reason in per_platform.items():
                self.assertTrue(reason.strip(), f"{scenario} [{platform}] needs a reason")
                self.assertFalse(
                    self._envelopes(scenario, platform),
                    f"{scenario} [{platform}] has an envelope and a gap entry: remove the gap",
                )
        for scenario, reason in self.coverage["not_replayable"].items():
            self.assertTrue(reason.strip(), f"{scenario} needs a reason")
            self.assertNotIn(scenario, dirs, f"{scenario} is listed not replayable but has envelopes")


if __name__ == "__main__":
    unittest.main()
