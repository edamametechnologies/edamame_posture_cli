#!/usr/bin/env python3
"""The trigger catalog (triggers/catalog.json) against the triggers and the gate.

catalog.json is the source of truth of what each trigger does: what it
simulates, the real attack it reproduces, what EDAMAME shows, which detector
checks it is meant to raise, on which platforms it runs. The EDAMAME Attack
Simulator (edamame_security/tools/attack_simulator) renders it as it is, so a
trigger change that leaves it behind ships a wrong description to customers.
These tests make the structural part of that drift fail:

- every trigger_*.py has exactly one entry, and every entry names a trigger
  that exists;
- every scenario of the two gate runners (run_cve_detection.sh,
  run_divergence_detection.sh) is listed by the entry of the trigger it runs,
  with the check the runner expects from it;
- a platform the gate excludes a scenario on is not listed for its trigger;
- the texts are complete, the references are public https links, and the
  themes, glossary terms and demo path point at real entries.

What a trigger actually does (its prose) is the author's to keep true: update
catalog.json in the same commit as the trigger.

Run:  python3 -m unittest discover -s tests/security -p 'test_trigger_catalog.py' -v
"""

from __future__ import annotations

import json
import re
import sys
import unittest
from pathlib import Path
from typing import Dict, List

HERE = Path(__file__).resolve().parent
TRIGGERS_DIR = HERE / "triggers"
CATALOG_PATH = TRIGGERS_DIR / "catalog.json"
# The gate runners whose scenarios check_gate.py requires.
RUNNER_PATHS = (HERE / "run_cve_detection.sh", HERE / "run_divergence_detection.sh")

sys.path.insert(0, str(HERE))
import check_gate  # noqa: E402  (PLATFORM_EXCLUDED_SCENARIOS)

PLATFORMS = {"macos", "windows", "linux"}
SCENARIO_TEXT_FIELDS = ("title", "one_liner", "see_in_edamame", "appears_within", "talk_track")
REFERENCE_FIELDS = ("name", "url", "kind")
# An incident is dated; a technique (MITRE ATT&CK, OWASP, a public blocklist) is not.
REFERENCE_KINDS = {"incident", "technique"}
TOP_LEVEL_KEYS = {"catalog_version", "scenarios", "themes", "glossary", "demo_path", "safety"}


def _shell_function_body(runner: Path, name: str) -> str:
    text = runner.read_text(encoding="utf-8")
    match = re.search(r"^%s\(\)\s*\{\n(.*?)^\}" % re.escape(name), text, re.S | re.M)
    if not match:
        raise AssertionError(f"{runner.name}: function {name}() not found")
    return match.group(1)


def _runner_scenarios(runner: Path) -> List[str]:
    match = re.search(r'^SCENARIOS_CSV="([^"]+)"', runner.read_text(encoding="utf-8"), re.M)
    if not match:
        raise AssertionError(f"{runner.name}: SCENARIOS_CSV not found")
    return [s for s in match.group(1).split(",") if s]


def gate_scenarios() -> Dict[str, Dict[str, str]]:
    """Every gate scenario: {scenario: {"runner", "check", "trigger"}}.

    The check is the runner's expected_check_for(); the trigger is its
    trigger_script_for(): the named exceptions, else trigger_<scenario>.py.
    """
    out: Dict[str, Dict[str, str]] = {}
    for runner in RUNNER_PATHS:
        checks = dict(re.findall(
            r'^\s*([a-z0-9_]+)\)\s+echo "([a-z0-9_:]+)"',
            _shell_function_body(runner, "expected_check_for"), re.M,
        ))
        special = dict(re.findall(
            r'^\s*([a-z0-9_]+)\)\s+echo "\$TRIGGERS_DIR/(trigger_[a-z0-9_]+\.py)"',
            _shell_function_body(runner, "trigger_script_for"), re.M,
        ))
        for scenario in _runner_scenarios(runner):
            if scenario in out:
                raise AssertionError(f"{scenario} is a scenario of two runners")
            out[scenario] = {
                "runner": runner.name,
                "check": checks.get(scenario, ""),
                "trigger": special.get(scenario, f"trigger_{scenario}.py"),
            }
    return out


def load_catalog() -> dict:
    with CATALOG_PATH.open(encoding="utf-8") as handle:
        return json.load(handle)


class TriggerCatalogTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = load_catalog()
        cls.scenarios: Dict[str, dict] = cls.catalog.get("scenarios", {})
        cls.by_trigger: Dict[str, List[str]] = {}
        for scenario_id, entry in cls.scenarios.items():
            cls.by_trigger.setdefault(entry.get("trigger", ""), []).append(scenario_id)

    def test_top_level_shape(self) -> None:
        self.assertEqual(set(self.catalog), TOP_LEVEL_KEYS)
        self.assertTrue(str(self.catalog["catalog_version"]).strip())
        self.assertIsInstance(self.scenarios, dict)
        self.assertTrue(self.scenarios)

    def test_every_trigger_has_exactly_one_entry(self) -> None:
        on_disk = sorted(p.name for p in TRIGGERS_DIR.glob("trigger_*.py"))
        self.assertTrue(on_disk, "no trigger_*.py found")
        for name in on_disk:
            self.assertEqual(
                len(self.by_trigger.get(name, [])), 1,
                f"{name} must have exactly one catalog.json entry (update the catalog with the trigger)",
            )
        for scenario_id, entry in self.scenarios.items():
            self.assertTrue(
                (TRIGGERS_DIR / entry.get("trigger", "")).is_file(),
                f"{scenario_id}: trigger {entry.get('trigger')!r} does not exist",
            )
            self.assertEqual(
                entry["trigger"], f"trigger_{scenario_id}.py",
                f"{scenario_id}: the id is the trigger's stem without 'trigger_'",
            )

    def test_entries_are_complete(self) -> None:
        for scenario_id, entry in self.scenarios.items():
            for field in SCENARIO_TEXT_FIELDS:
                value = entry.get(field)
                self.assertIsInstance(value, str, f"{scenario_id}.{field}")
                self.assertTrue(value.strip(), f"{scenario_id}.{field} is empty")
            reference = entry.get("reference")
            self.assertIsInstance(reference, dict, f"{scenario_id}.reference")
            for field in REFERENCE_FIELDS:
                self.assertTrue(str(reference.get(field, "")).strip(), f"{scenario_id}.reference.{field}")
            self.assertIn(reference["kind"], REFERENCE_KINDS, f"{scenario_id}.reference.kind")
            if reference["kind"] == "incident":
                self.assertTrue(str(reference.get("year", "")).strip(),
                                f"{scenario_id}: an incident reference carries its year")
            self.assertTrue(
                reference["url"].startswith("https://"), f"{scenario_id}: reference url must be https"
            )
            self.assertIsInstance(entry.get("needs_admin"), bool, f"{scenario_id}.needs_admin")
            platforms = entry.get("platforms")
            self.assertIsInstance(platforms, list, f"{scenario_id}.platforms")
            self.assertTrue(platforms, f"{scenario_id}.platforms is empty")
            self.assertLessEqual(set(platforms), PLATFORMS, f"{scenario_id}.platforms")
            checks = entry.get("expected_checks")
            self.assertIsInstance(checks, list, f"{scenario_id}.expected_checks")
            self.assertTrue(checks and all(isinstance(c, str) and c.strip() for c in checks),
                            f"{scenario_id}.expected_checks must name at least one check")
            self.assertIsInstance(entry.get("gate_scenarios"), list, f"{scenario_id}.gate_scenarios")
            self.assertIsInstance(entry.get("terms", []), list, f"{scenario_id}.terms")

    def test_every_gate_scenario_is_listed_with_its_expected_check(self) -> None:
        scenarios = gate_scenarios()
        self.assertTrue(scenarios)
        for scenario, gate in scenarios.items():
            owners = self.by_trigger.get(gate["trigger"], [])
            self.assertEqual(len(owners), 1,
                             f"{gate['runner']} scenario {scenario}: no catalog entry for {gate['trigger']}")
            entry = self.scenarios[owners[0]]
            self.assertIn(scenario, entry["gate_scenarios"],
                          f"{owners[0]}.gate_scenarios must list the gate scenario {scenario}")
            self.assertTrue(gate["check"], f"{gate['runner']} has no expected_check_for {scenario}")
            self.assertIn(gate["check"], entry["expected_checks"],
                          f"{owners[0]}.expected_checks must include {gate['check']} (gate scenario {scenario})")

    def test_listed_gate_scenarios_exist_and_run_this_trigger(self) -> None:
        scenarios = gate_scenarios()
        for scenario_id, entry in self.scenarios.items():
            for scenario in entry["gate_scenarios"]:
                self.assertIn(scenario, scenarios, f"{scenario_id}: {scenario} is not a gate scenario")
                self.assertEqual(scenarios[scenario]["trigger"], entry["trigger"],
                                 f"{scenario_id}: gate scenario {scenario} runs another trigger")

    def test_platforms_respect_the_gate_exclusions(self) -> None:
        for platform_key, excluded in check_gate.PLATFORM_EXCLUDED_SCENARIOS.items():
            system = platform_key.split("-", 1)[0]
            self.assertIn(system, PLATFORMS, f"unknown platform key {platform_key}")
            gates = gate_scenarios()
            for scenario in excluded:
                trigger = gates[scenario]["trigger"] if scenario in gates else f"trigger_{scenario}.py"
                owners = self.by_trigger.get(trigger, [])
                for scenario_id in owners:
                    self.assertNotIn(
                        system, self.scenarios[scenario_id]["platforms"],
                        f"{scenario_id}: the gate excludes {scenario} on {platform_key}",
                    )

    def test_glossary_themes_and_demo_path_point_at_real_entries(self) -> None:
        glossary = self.catalog["glossary"]
        self.assertIsInstance(glossary, dict)
        for term, definition in glossary.items():
            self.assertTrue(isinstance(definition, str) and definition.strip(), f"glossary.{term}")
        for scenario_id, entry in self.scenarios.items():
            for term in entry.get("terms", []):
                self.assertIn(term, glossary, f"{scenario_id}: term {term!r} is not in the glossary")

        seen: Dict[str, str] = {}
        for theme in self.catalog["themes"]:
            for field in ("id", "title", "summary"):
                self.assertTrue(str(theme.get(field, "")).strip(), f"theme {theme.get('id')}.{field}")
            for scenario_id in theme.get("scenarios", []):
                self.assertIn(scenario_id, self.scenarios, f"theme {theme['id']}: unknown {scenario_id}")
                self.assertNotIn(scenario_id, seen, f"{scenario_id} is in two themes")
                seen[scenario_id] = theme["id"]
        self.assertEqual(set(seen), set(self.scenarios), "every scenario belongs to exactly one theme")

        demo = self.catalog["demo_path"]
        for field in ("title", "intro", "closing"):
            self.assertTrue(str(demo.get(field, "")).strip(), f"demo_path.{field}")
        self.assertTrue(demo.get("steps"))
        for step in demo["steps"]:
            self.assertIn(step.get("scenario"), self.scenarios, f"demo_path step {step}")
            self.assertTrue(str(step.get("note", "")).strip(), f"demo_path step {step.get('scenario')}")

        safety = self.catalog["safety"]
        # What the simulator shows on every screen: that nothing real is
        # attacked and the scenarios run on test data.
        for field in ("headline", "summary", "scenario_note"):
            self.assertTrue(str(safety.get(field, "")).strip(), f"safety.{field}")
        self.assertTrue(safety.get("points") and all(str(p).strip() for p in safety["points"]))

    def test_appears_within_reads_after_appears(self) -> None:
        # The simulator shows "Appears {appears_within}."
        for scenario_id, entry in self.scenarios.items():
            self.assertRegex(entry["appears_within"], r"^(usually )?within ",
                             f"{scenario_id}.appears_within must read after 'Appears'")

    def test_texts_make_no_timing_promise_the_detector_cannot_keep(self) -> None:
        # Findings land at the detector's tick: "instantly" is never true.
        pattern = re.compile(r"\binstant(ly)?\b|\bin real time\b", re.I)
        for scenario_id, entry in self.scenarios.items():
            for field in SCENARIO_TEXT_FIELDS:
                self.assertIsNone(pattern.search(entry[field]),
                                  f"{scenario_id}.{field}: use the appears_within wording")


if __name__ == "__main__":
    unittest.main()
