#!/usr/bin/env python3
"""Aggregate per-platform CVE detection results into a Markdown report.

Expected input directory layout:

    results/
      <platform>/
        results.json       # top-level per-platform report
        results.ndjson     # per-scenario stream
        detector_ticks.log # stdout/stderr from detector ticks
        <scenario>.trigger.log

The script reads each platform's `results.json` and renders a consolidated
report. Output is written to --output (default: VULNDETECTION.md).
"""

from __future__ import annotations

import argparse
import datetime
import glob
import json
import os
import pathlib
import sys
from typing import Dict, List, Optional


SCENARIO_ORDER = [
    "blacklist_comm",
    "cve_token_exfil",
    "cve_sandbox_escape",
    "memory_poisoning",
    "credential_sprawl",
    "tool_poisoning_effects",
    "supply_chain_exfil",
    "npm_rat_beacon",
    "file_events",
]

SCENARIO_LABELS = {
    "blacklist_comm": "Blacklisted traffic",
    "cve_token_exfil": "CVE-2025-52882 / CVE-2026-25253 token exfil",
    "cve_sandbox_escape": "Sandbox escape",
    "memory_poisoning": "Memory poisoning",
    "credential_sprawl": "Credential sprawl",
    "tool_poisoning_effects": "Tool poisoning",
    "supply_chain_exfil": "Supply-chain exfil (credential harvest)",
    "npm_rat_beacon": "npm RAT beacon",
    "file_events": "FIM tampering",
}

STATUS_SYMBOLS = {
    "pass": "PASS",
    "fail": "FAIL",
    "skip": "SKIP",
}


def _load_json(path: str) -> Optional[dict]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return None


def _discover_platforms(results_root: str) -> List[str]:
    entries = sorted(glob.glob(os.path.join(results_root, "*")))
    return [p for p in entries if os.path.isdir(p)]


def _platform_table(platform: str, report: Optional[dict]) -> str:
    lines: List[str] = []
    lines.append(f"### {platform}")
    lines.append("")
    if report is None:
        lines.append("_No results recorded for this platform._")
        lines.append("")
        return "\n".join(lines)

    meta = (
        f"- Core version: `{report.get('core_version', 'unknown')}`"
        f"  ·  Platform: `{report.get('platform_system','')} {report.get('platform_release','')}`"
        f"  ({report.get('platform_machine','')})"
    )
    lines.append(meta)
    totals = report.get("totals") or {}
    lines.append(
        f"- Totals: PASS `{totals.get('passed', 0)}` /"
        f" FAIL `{totals.get('failed', 0)}` /"
        f" SKIP `{totals.get('skipped', 0)}` /"
        f" TOTAL `{totals.get('total', 0)}`"
    )
    lines.append(
        f"- Trigger duration: {report.get('trigger_duration_s', '?')}s,"
        f" post-wait: {report.get('post_wait_s', '?')}s,"
        f" poll attempts: {report.get('poll_attempts', '?')}×{report.get('poll_interval_s', '?')}s"
    )
    lines.append("")
    scenarios = report.get("scenarios") or []
    by_scen: Dict[str, dict] = {s.get("scenario", ""): s for s in scenarios}
    lines.append("| Scenario | Expected check | Status | Total | Current | History | Elapsed (s) |")
    lines.append("|---|---|---|---|---|---|---|")
    for key in SCENARIO_ORDER:
        entry = by_scen.get(key)
        label = SCENARIO_LABELS.get(key, key)
        if entry is None:
            lines.append(f"| {label} (`{key}`) | - | - | - | - | - | - |")
            continue
        status = entry.get("status", "?")
        total = entry.get("finding_total", 0)
        current = entry.get("finding_current", 0)
        history = entry.get("finding_history", 0)
        elapsed = entry.get("elapsed_s", 0)
        check = entry.get("expected_check", "-")
        lines.append(
            f"| {label} (`{key}`) | `{check}` | `{STATUS_SYMBOLS.get(status, status)}`"
            f" | {total} | {current} | {history} | {elapsed:g} |"
        )
    lines.append("")
    return "\n".join(lines)


def _aggregate_table(reports: Dict[str, dict]) -> str:
    platforms = list(reports.keys())
    if not platforms:
        return "_No platform data._\n"
    header = "| Scenario | " + " | ".join(platforms) + " |"
    sep = "|" + "|".join(["---"] * (1 + len(platforms))) + "|"
    lines = [header, sep]
    for key in SCENARIO_ORDER:
        label = SCENARIO_LABELS.get(key, key)
        cells = [f"{label} (`{key}`)"]
        for plat in platforms:
            rep = reports.get(plat)
            scen = {s.get("scenario"): s for s in (rep.get("scenarios") or [])} if rep else {}
            entry = scen.get(key)
            if entry is None:
                cells.append("-")
            else:
                cells.append(STATUS_SYMBOLS.get(entry.get("status", ""), entry.get("status", "?")))
        lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines) + "\n"


def _totals_row(reports: Dict[str, dict]) -> str:
    lines = ["| Platform | Pass | Fail | Skip | Total |", "|---|---|---|---|---|"]
    for plat, rep in reports.items():
        if not rep:
            lines.append(f"| {plat} | - | - | - | - |")
            continue
        totals = rep.get("totals") or {}
        lines.append(
            f"| {plat} | {totals.get('passed', 0)} | {totals.get('failed', 0)}"
            f" | {totals.get('skipped', 0)} | {totals.get('total', 0)} |"
        )
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--results-dir", required=True)
    ap.add_argument("--output", required=True)
    args = ap.parse_args()

    platform_dirs = _discover_platforms(args.results_dir)
    if not platform_dirs:
        print(f"error: no platform subdirectories in {args.results_dir}", file=sys.stderr)
        return 2

    reports: Dict[str, Optional[dict]] = {}
    for d in platform_dirs:
        label = os.path.basename(os.path.normpath(d))
        reports[label] = _load_json(os.path.join(d, "results.json"))

    lines: List[str] = []
    lines.append("# EDAMAME Posture Vulnerability Detection Report")
    lines.append("")
    lines.append(
        f"_Generated: {datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None).isoformat(timespec='seconds')}Z_"
    )
    lines.append("")
    lines.append(
        "This report is regenerated by `.github/workflows/security.yml` on every"
        " weekly cron and on manual dispatch. Each scenario runs the matching"
        " attack trigger from"
        " [`agent_security/tests/e2e/triggers/`](https://github.com/edamametechnologies/agent_security/tree/main/tests/e2e/triggers)"
        " against a live `edamame_posture` daemon with packet capture enabled and"
        " verifies that the vulnerability detector raised the expected finding."
    )
    lines.append("")
    lines.append("## Scenarios covered")
    lines.append("")
    lines.append(
        "| Scenario | Expected check | Trigger script |"
    )
    lines.append("|---|---|---|")
    scenario_checks = {
        "blacklist_comm": "blacklisted_sessions",
        "cve_token_exfil": "token_exfiltration",
        "cve_sandbox_escape": "sandbox_exploitation",
        "memory_poisoning": "token_exfiltration",
        "credential_sprawl": "token_exfiltration",
        "tool_poisoning_effects": "token_exfiltration",
        "supply_chain_exfil": "credential_harvest",
        "npm_rat_beacon": "token_exfiltration",
        "file_events": "file_system_tampering",
    }
    for key in SCENARIO_ORDER:
        lines.append(
            f"| {SCENARIO_LABELS.get(key, key)} (`{key}`) |"
            f" `{scenario_checks.get(key, '-')}` |"
            f" [`trigger_{key}.py`](https://github.com/edamametechnologies/agent_security/blob/main/tests/e2e/triggers/trigger_{key}.py) |"
        )
    lines.append("")
    lines.append("## Detection verification")
    lines.append("")
    lines.append(
        "Detection is confirmed via `edamame_cli` RPCs against the running"
        " daemon. For most scenarios we call `debug_run_vulnerability_detector_tick`"
        " to force an immediate evaluation and then match findings by `check`,"
        " process markers (e.g. `_exfil_token`, `_sprawl_key`), and destination"
        " port (63169 for token exfil, 63171 for sprawl, 63172 for tool"
        " poisoning). Blacklisted-traffic detection queries"
        " `get_blacklisted_sessions` for the canonical FireHOL test IPs."
        " Findings are retrieved with `get_vulnerability_findings` plus"
        " `get_vulnerability_history` (last 50) so we catch scenarios that"
        " completed before the poll loop but are still in history, matching the"
        " vulnerability finding persistence invariant."
    )
    lines.append("")

    lines.append("## Totals per platform")
    lines.append("")
    lines.append(_totals_row(reports))
    lines.append("")

    lines.append("## Result matrix")
    lines.append("")
    lines.append(_aggregate_table(reports))
    lines.append("")

    lines.append("## Per-platform detail")
    lines.append("")
    for plat, rep in reports.items():
        lines.append(_platform_table(plat, rep))

    lines.append("## Reproducing locally")
    lines.append("")
    lines.append("```bash")
    lines.append("# Download trigger scripts")
    lines.append("TRIGGERS_DIR=$(mktemp -d)")
    lines.append(
        "for f in _common.py _native_udp_probe.py _edamame_cli.py cleanup.py \\"
    )
    lines.append(
        "  trigger_blacklist_comm.py trigger_cve_token_exfil.py trigger_cve_sandbox_escape.py \\"
    )
    lines.append(
        "  trigger_memory_poisoning.py trigger_credential_sprawl.py trigger_tool_poisoning_effects.py \\"
    )
    lines.append(
        "  trigger_supply_chain_exfil.py trigger_npm_rat_beacon.py trigger_file_events.py; do"
    )
    lines.append(
        '  curl -sfL "https://raw.githubusercontent.com/edamametechnologies/agent_security/main/tests/e2e/triggers/$f" -o "$TRIGGERS_DIR/$f"'
    )
    lines.append("done")
    lines.append("")
    lines.append("# Requires an already-running edamame_posture daemon with --packet-capture")
    lines.append("export EDAMAME_CLI=$(which edamame_cli)")
    lines.append(
        "bash tests/security/run_cve_detection.sh --triggers-dir \"$TRIGGERS_DIR\" --output-dir results/local --trigger-duration 90"
    )
    lines.append("python3 tests/security/generate_report.py --results-dir results --output VULNDETECTION.md")
    lines.append("```")
    lines.append("")
    lines.append(
        "See `.github/workflows/security.yml` for the full CI orchestration."
    )
    lines.append("")

    out_dir = os.path.dirname(os.path.abspath(args.output))
    if out_dir:
        pathlib.Path(out_dir).mkdir(parents=True, exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    print(f"Wrote {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
