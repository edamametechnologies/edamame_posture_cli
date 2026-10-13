#!/usr/bin/env python3
"""Summary of one local-loop run (tests/local_loop/run_local_loop.sh).

Reads the run directory the loop wrote:

  window.tsv                          host, platform, core version, adjudication, Portal,
                                      Endpoint Security lines, restore outcome
  steps.tsv                           step, status, exit code, seconds, log
  baseline/baseline.json              run_false_positive_baseline.sh
  cve/results.json                    run_cve_detection.sh, with cve/findings/<s>.export.json
  staging/attack_corpus.report.json   edamame_core/tools/attack_corpus_from_gate.py --report
  fp_lab/summary.json                 run_fp_lab.py run (fp_lab/preflight.json on a refusal)

writes summary.json and summary.md beside them and prints the one-line
verdict. Exit code: 0 PASS, 1 FAIL, 2 INCOMPLETE.

- INCOMPLETE: a step the run asked for left no result (the owned daemon never
  answered, a runner died, the FP lab preflight refused, the baseline was
  unmeasured).
- FAIL: a CVE scenario that ran did not pass, the idle baseline saw a finding,
  or the FP lab recorded an alertable finding or a divergence incident.
- PASS: none of these.

On a developer Mac the baseline and the FP lab also observe the workstation's
own activity (builds, agent sessions, other apps): a FAIL there lists each
finding for triage before anyone calls it a detector FP.

    python3 -I tests/local_loop/local_loop_summary.py <run-dir>
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

ALERTABLE = ("HIGH", "CRITICAL")


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def read_tsv(path: Path) -> List[List[str]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    return [line.split("\t") for line in lines if line.strip()]


def is_alertable(finding: Any) -> bool:
    return (isinstance(finding, dict) and not finding.get("dismissed")
            and str(finding.get("severity") or "").strip().upper() in ALERTABLE)


def cell(value: Any, limit: int = 120) -> str:
    text = "" if value is None else str(value)
    text = text.replace("|", "/").replace("\n", " ")
    return text if len(text) <= limit else text[: limit - 3] + "..."


# ── components ──────────────────────────────────────────────────────────

def load_steps(run: Path) -> Dict[str, dict]:
    steps: Dict[str, dict] = {}
    for row in read_tsv(run / "steps.tsv"):
        row += [""] * (5 - len(row))
        name, status, rc, seconds, log = row[:5]
        steps[name] = {"name": name, "status": status, "rc": int(rc) if rc.lstrip("-").isdigit() else None,
                       "seconds": int(seconds) if seconds.isdigit() else None, "log": log or None}
    return steps


def load_window(run: Path) -> Dict[str, str]:
    window: Dict[str, str] = {}
    for row in read_tsv(run / "window.tsv"):
        window[row[0]] = row[1] if len(row) > 1 else ""
    return window


def baseline_component(run: Path, step: Optional[dict]) -> dict:
    if step is None:
        return {"state": "not_run"}
    if step["status"] == "skipped":
        return {"state": "skipped"}
    data = read_json(run / "baseline" / "baseline.json")
    if not isinstance(data, dict):
        return {"state": "missing", "rc": step.get("rc")}
    findings: Dict[str, dict] = {}
    for sample in data.get("samples") or []:
        body = sample.get("findings") if isinstance(sample, dict) else None
        if not isinstance(body, dict):
            continue
        for f in list(body.get("current") or []) + list(body.get("history") or []):
            if isinstance(f, dict) and f.get("check"):
                key = str(f.get("finding_key") or f"{f.get('check')}|{f.get('process_path')}|{f.get('subject_path')}")
                findings[key] = f
    return {
        "state": str(data.get("status") or "unknown"),
        "duration_s": data.get("duration_s"),
        "finding_total": data.get("finding_total"),
        "alertable": sum(1 for f in findings.values() if is_alertable(f)),
        "adjudication": (data.get("adjudication") or {}).get("mode"),
        "findings": [{"check": f.get("check"), "severity": f.get("severity"),
                      "process": f.get("process_path") or f.get("process_name"),
                      "target": f.get("subject_path") or f.get("destination_domain") or f.get("destination_ip"),
                      "finding_key": f.get("finding_key")} for f in findings.values()],
    }


def cve_component(run: Path, step: Optional[dict]) -> dict:
    if step is None:
        return {"state": "not_run"}
    if step["status"] == "skipped":
        return {"state": "skipped"}
    results = read_json(run / "cve" / "results.json")
    if not isinstance(results, dict) or not isinstance(results.get("scenarios"), list):
        return {"state": "missing", "rc": step.get("rc"),
                "daemon_unreachable": (run / "cve" / "daemon_unreachable.log").is_file()}
    report = read_json(run / "staging" / "attack_corpus.report.json")
    shaped = {}
    if isinstance(report, dict):
        shaped = {r.get("scenario"): r for r in report.get("scenarios") or [] if isinstance(r, dict)}
    rows = []
    for rec in results["scenarios"]:
        if not isinstance(rec, dict):
            continue
        name = str(rec.get("scenario"))
        export = read_json(run / "cve" / "findings" / f"{name}.export.json")
        exported = export.get("alertable_exported") if isinstance(export, dict) else None
        shape = shaped.get(name) or {}
        if shape.get("status") in ("written", "would_write"):
            envelope = Path(str(shape.get("path"))).name
        elif shape:
            envelope = f"skipped: {shape.get('reason')}"
        else:
            envelope = None
        rows.append({"scenario": name, "expected_check": rec.get("expected_check"),
                     "status": rec.get("status"), "alertable": rec.get("finding_alertable"),
                     "severities": rec.get("severities"), "note": rec.get("extra") or None,
                     "elapsed_s": rec.get("elapsed_s"), "exported": exported, "envelope": envelope})
    totals = results.get("totals") or {}
    return {"state": "ran", "core_version": results.get("core_version"),
            "passed": sum(1 for r in rows if r["status"] == "pass"),
            "failed": sum(1 for r in rows if r["status"] == "fail"),
            "skipped": sum(1 for r in rows if r["status"] == "skip"),
            "total": totals.get("total", len(rows)), "scenarios": rows}


def fp_lab_component(run: Path, step: Optional[dict]) -> dict:
    if step is None:
        return {"state": "not_run"}
    if step["status"] == "skipped":
        return {"state": "skipped"}
    summary = read_json(run / "fp_lab" / "summary.json")
    if not isinstance(summary, dict):
        preflight = read_json(run / "fp_lab" / "preflight.json")
        problems = preflight.get("problems") if isinstance(preflight, dict) else None
        return {"state": "missing", "rc": step.get("rc"), "problems": problems or []}
    alertable, incidents = [], []
    for case in summary.get("cases") or []:
        if not isinstance(case, dict):
            continue
        for e in case.get("alertable") or []:
            alertable.append({"case_id": case.get("case_id"), "check": e.get("check"),
                              "severity": e.get("severity"), "process": e.get("process"),
                              "target": e.get("subject_path") or e.get("destination"),
                              "export": e.get("export_path"),
                              "candidate": e.get("corpus_candidate") or e.get("reason")})
        for e in case.get("divergence_incidents") or []:
            incidents.append({"case_id": case.get("case_id"), "severity": e.get("severity"),
                              "title": e.get("title"), "candidate": e.get("corpus_candidate")})
    return {"state": "pass" if summary.get("verdict") == "PASS" else "fail",
            "verdict": summary.get("verdict"), "counts": summary.get("counts"),
            "adjudication": summary.get("adjudication"),
            "cases": [{"case_id": c.get("case_id"), "status": c.get("status"), "reason": c.get("reason"),
                       "alertable": len(c.get("alertable") or []), "low": len(c.get("low") or [])}
                      for c in summary.get("cases") or [] if isinstance(c, dict)],
            "alertable": alertable, "incidents": incidents}


def staged_component(run: Path) -> dict:
    staging = run / "staging"
    report = read_json(staging / "attack_corpus.report.json")
    rows = report.get("scenarios") if isinstance(report, dict) else []
    rows = [r for r in rows or [] if isinstance(r, dict)]
    def files(name: str) -> List[str]:
        root = staging / name
        return sorted(str(p.relative_to(root)) for p in root.glob("*/*.json")) if root.is_dir() else []
    return {
        "attack_corpus": {"dir": str(staging / "attack_corpus"),
                          "written": sum(1 for r in rows if r.get("status") == "written"),
                          "skipped": sum(1 for r in rows if r.get("status") == "skipped"),
                          "files": files("attack_corpus")},
        "fp_corpus": {"dir": str(staging / "fp_corpus"), "files": files("fp_corpus")},
        "divergence_corpus": {"dir": str(staging / "divergence_corpus"), "files": files("divergence_corpus")},
    }


# ── verdict ─────────────────────────────────────────────────────────────

def verdict(window: Dict[str, str], steps: Dict[str, dict], baseline: dict, cve: dict,
            fp_lab: dict, staged: dict) -> dict:
    incomplete: List[str] = []
    failures: List[str] = []
    warnings: List[str] = []
    if not window.get("core_version"):
        incomplete.append("the owned daemon never answered (no core version recorded)")
    if window.get("interrupted"):
        incomplete.append(f"the run was interrupted ({window['interrupted']})")
    for name in ("build_posture", "build_cli"):
        if name in steps and steps[name]["status"] != "ok":
            incomplete.append(f"{name} exited {steps[name]['rc']}")
    # The loop records each measuring step, run or skipped, when it reaches
    # it: one it never reached is a measurement missing.
    for name, part in (("baseline", baseline), ("cve", cve), ("fp_lab", fp_lab)):
        if part["state"] == "not_run":
            incomplete.append(f"{name} never ran")

    if baseline["state"] == "fail":
        failures.append(f"baseline saw {baseline.get('finding_total')} finding(s), "
                        f"{baseline.get('alertable')} alertable")
    elif baseline["state"] in ("missing", "unmeasured", "unknown"):
        incomplete.append(f"baseline {baseline['state']}")

    if cve["state"] == "ran":
        failed = [r["scenario"] for r in cve["scenarios"] if r["status"] == "fail"]
        if failed:
            failures.append(f"CVE scenario(s) failed: {', '.join(failed)}")
    elif cve["state"] == "missing":
        incomplete.append("CVE suite wrote no results.json"
                          + (" (the daemon stopped answering)" if cve.get("daemon_unreachable") else ""))

    if fp_lab["state"] == "fail":
        cases = sorted({a["case_id"] for a in fp_lab["alertable"]} | {i["case_id"] for i in fp_lab["incidents"]})
        failures.append(f"FP lab: {len(fp_lab['alertable'])} alertable finding(s), "
                        f"{len(fp_lab['incidents'])} incident(s) ({', '.join(cases)})")
    elif fp_lab["state"] == "missing":
        why = "; ".join(fp_lab.get("problems") or []) or f"exit {fp_lab.get('rc')}"
        incomplete.append(f"FP lab wrote no summary ({why})")

    if "shape_attack" in steps and steps["shape_attack"]["status"] != "ok":
        warnings.append(f"attack shaping exited {steps['shape_attack']['rc']}")
    if window.get("restore_problems", "0") not in ("", "0"):
        warnings.append("the window's restore reported a problem: rerun run_local_loop.sh --restore <run-dir>")
    elif not window.get("closed_utc") and window.get("started_utc"):
        warnings.append("the window was not recorded closed: check the app and the helper")

    state = "INCOMPLETE" if incomplete else ("FAIL" if failures else "PASS")
    parts = []
    if cve["state"] == "ran":
        failed = [r["scenario"] for r in cve["scenarios"] if r["status"] == "fail"]
        ran = cve["passed"] + cve["failed"]
        parts.append(f"cve {cve['passed']}/{ran} passed" + (f" (failed: {', '.join(failed)})" if failed else ""))
    else:
        parts.append(f"cve {cve['state']}")
    if baseline["state"] == "fail":
        parts.append(f"baseline dirty ({baseline.get('finding_total')} finding(s), {baseline.get('alertable')} alertable)")
    elif baseline["state"] == "pass":
        parts.append(f"baseline clean ({baseline.get('duration_s')} s)")
    else:
        parts.append(f"baseline {baseline['state']}")
    if fp_lab["state"] in ("pass", "fail"):
        parts.append(f"fp-lab {len(fp_lab['alertable'])} alertable, {len(fp_lab['incidents'])} incident(s)")
    else:
        parts.append(f"fp-lab {fp_lab['state']}")
    parts.append(f"{staged['attack_corpus']['written']} attack envelope(s) staged")
    line = f"VERDICT {state}: " + "; ".join(parts)
    if incomplete:
        line += " -- incomplete: " + "; ".join(incomplete)
    return {"verdict": state, "line": line, "incomplete": incomplete, "failures": failures, "warnings": warnings}


# ── output ──────────────────────────────────────────────────────────────

def markdown(run: Path, s: dict) -> str:
    w, b, c, f, st = s["window"], s["baseline"], s["cve"], s["fp_lab"], s["staged"]
    out = [f"# Local loop {run.name}", "",
           f"- Host: {w.get('host', '?')} ({w.get('platform_label', '?')}), core {w.get('core_version', '?')}",
           f"- Posture: `{w.get('posture_bin', '?')}` (sha256 {w.get('posture_sha256', '?')[:16]})",
           f"- Adjudication: {w.get('adjudication', '?')}, Portal: {w.get('portal', '?')}",
           f"- Endpoint Security: {w.get('es_status') or 'not recorded'}",
           f"- Window: {w.get('started_utc', '?')} to {w.get('closed_utc', 'not closed')}, "
           f"helper {w.get('helper_mode', '?')}, app `{w.get('app_bundle') or 'not running'}`",
           f"- **{s['line']}**", ""]
    for kind in ("failures", "incomplete", "warnings"):
        for item in s[kind]:
            out.append(f"- {kind[:-1] if kind != 'incomplete' else 'incomplete'}: {item}")
    out += ["", "## Steps", "", "| Step | Status | Exit | Seconds | Log |", "|---|---|---|---|---|"]
    for step in s["steps"]:
        out.append(f"| {step['name']} | {step['status']} | {cell(step['rc'])} | {cell(step['seconds'])} | "
                   f"`{cell(step['log'])}` |")
    out += ["", "## Idle baseline", ""]
    if b["state"] in ("pass", "fail", "unmeasured"):
        out.append(f"{b['state']}: {b.get('finding_total')} finding(s) in {b.get('duration_s')} s, "
                   f"{b.get('alertable')} alertable (adjudication {b.get('adjudication')})")
        for x in b.get("findings") or []:
            out.append(f"- {x['severity']} `{x['check']}` {x['process']} -> {x['target']} (`{x['finding_key']}`)")
    else:
        out.append(b["state"])
    out += ["", "## CVE scenarios", ""]
    if c["state"] == "ran":
        out += [f"{c['passed']} passed, {c['failed']} failed, {c['skipped']} skipped (core {c.get('core_version')})", "",
                "| Scenario | Check | Status | Alertable | Severities | Exports | Envelope | Note |",
                "|---|---|---|---|---|---|---|---|"]
        for r in c["scenarios"]:
            out.append(f"| `{r['scenario']}` | {cell(r['expected_check'])} | {r['status']} | {cell(r['alertable'])} | "
                       f"{cell(r['severities'])} | {cell(r['exported'])} | {cell(r['envelope'], 90)} | {cell(r['note'])} |")
    else:
        out.append(c["state"])
    out += ["", "## FP lab (agent-free scenarios)", ""]
    if f["state"] in ("pass", "fail"):
        out += [f"{f['verdict']} ({', '.join(f'{k} {v}' for k, v in sorted((f.get('counts') or {}).items()))})", "",
                "| Case | Status | Alertable | LOW | Note |", "|---|---|---|---|---|"]
        for case in f["cases"]:
            out.append(f"| `{case['case_id']}` | {case['status']} | {case['alertable']} | {case['low']} | "
                       f"{cell(case['reason'])} |")
        for a in f["alertable"]:
            out.append(f"- ALERTABLE {a['severity']} `{a['check']}` in `{a['case_id']}`: {a['process']} -> "
                       f"{a['target']}; candidate `{a['candidate']}`")
        for i in f["incidents"]:
            out.append(f"- INCIDENT {i['severity']} in `{i['case_id']}`: {i['title']}; candidate `{i['candidate']}`")
    else:
        out.append(f["state"] + (": " + "; ".join(f.get("problems") or []) if f.get("problems") else ""))
    out += ["", "## Staged evidence", "",
            f"- Attack envelopes: {st['attack_corpus']['written']} in `{st['attack_corpus']['dir']}` "
            f"({st['attack_corpus']['skipped']} scenario(s) skipped, reasons above). Promote: "
            f"`tests/local_loop/run_local_loop.sh --promote-from {run}`",
            f"- FP candidates (review, then commit by hand): {len(st['fp_corpus']['files'])} in "
            f"`{st['fp_corpus']['dir']}`",
            f"- Divergence candidates: {len(st['divergence_corpus']['files'])} in `{st['divergence_corpus']['dir']}`",
            ""]
    return "\n".join(out)


def summarize(run: Path) -> dict:
    steps = load_steps(run)
    window = load_window(run)
    baseline = baseline_component(run, steps.get("baseline"))
    cve = cve_component(run, steps.get("cve"))
    fp_lab = fp_lab_component(run, steps.get("fp_lab"))
    staged = staged_component(run)
    result = verdict(window, steps, baseline, cve, fp_lab, staged)
    return {"run_dir": str(run), "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            **result, "window": window, "steps": list(steps.values()), "baseline": baseline,
            "cve": cve, "fp_lab": fp_lab, "staged": staged}


def main(argv: List[str]) -> int:
    if len(argv) != 2:
        print(__doc__.strip().splitlines()[-1].strip(), file=sys.stderr)
        return 2
    run = Path(argv[1]).expanduser().resolve()
    if not run.is_dir():
        print(f"local_loop_summary: no directory {run}", file=sys.stderr)
        return 2
    s = summarize(run)
    (run / "summary.json").write_text(json.dumps(s, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    (run / "summary.md").write_text(markdown(run, s) + "\n", encoding="utf-8")
    print(s["line"])
    for item in s["warnings"]:
        print(f"warning: {item}")
    return {"PASS": 0, "FAIL": 1}.get(s["verdict"], 2)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
