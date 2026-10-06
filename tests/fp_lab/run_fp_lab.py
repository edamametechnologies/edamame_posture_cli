#!/usr/bin/env python3
"""
EDAMAME FP lab runner.

Drives REAL coding agents (and agent-free scripts) through ordinary, benign
work against an EDAMAME posture daemon we own, and fails when any alertable
attack-pattern finding (HIGH / CRITICAL, not dismissed) or any divergence
incident appears. Each one is exported and shaped into a corpus candidate.

Agent installation and driving, observer ticks and the RPC wrapper are the
fleet E2E's own code (tests/e2e/agent_harness.py, tests/e2e/supported_agents.py,
tests/security/triggers/_edamame_cli.py); this file only orchestrates.

Subcommands:
  list                 print the scenario catalog
  validate             static checks of the catalog against the registry
  run [options]        preflight, warm-up/baseline, scenarios, drain, summary
  shape <run_dir>      (re)shape exported attack-pattern findings into corpus
                       candidates (needs jq + fp_corpus_from_export.sh); use it
                       on the operator machine when the lab host has no jq
  summarize <run_dir>  re-render summary.json / summary.md from the case files

Exit codes (run): 0 clean, 1 at least one alertable finding or divergence
incident, 2 preflight / infrastructure failure.

Provider keys: ANTHROPIC_API_KEY / OPENAI_API_KEY are read from the
environment at start, removed from it, and handed only to the agent that needs
them for the duration of its drive. Direct scenarios and the RPC CLI never see
them. The runner never prints or writes them.
"""

from __future__ import annotations

import argparse
import contextlib
import datetime as _dt
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import time
import traceback
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
    except (AttributeError, ValueError):
        pass

HERE = Path(__file__).resolve().parent
TESTS = HERE.parent
for _p in (TESTS / "security" / "triggers", TESTS / "e2e", HERE):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from _edamame_cli import cli_rpc, find_cli_binary  # noqa: E402
import supported_agents as reg  # noqa: E402
import daemon_perf  # noqa: E402
from agent_harness import (  # noqa: E402
    REAL_DRIVERS,
    _augment_path,
    _divergence_status,
    _llm_probe,
    cli_path,
    host_os,
    last_cmd_output_tail,
    log,
    observer_row,
    observer_status,
    observer_tick,
    real_driver_available,
    rpc_quiet,
    section,
)
from scenarios import SCENARIOS, Scenario, validate  # noqa: E402
from lab_workspace import make_workspace  # noqa: E402
from direct_actions import run_action  # noqa: E402

PROVIDER_KEY_VARS = ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "CODEX_API_KEY", "EDAMAME_LLM_API_KEY")
_KEYS: Dict[str, str] = {}

TICK_TIMEOUT = 300.0
READ_TIMEOUT = 90.0
ALERTABLE = ("HIGH", "CRITICAL")
SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

# A refusal is only believed when the stimulus marker is also missing: "I can't
# reach port 22" is a legitimate answer to a connectivity task.
REFUSAL_RE = re.compile(
    r"\bI(?:\s+(?:can(?:no|['\u2019])t|won['\u2019]t|will\s+not|must\s+decline|have\s+to\s+decline|"
    r"am\s+not\s+(?:able|comfortable)|am\s+unable)|['\u2019]m\s+(?:not\s+(?:able|comfortable)|unable))"
    r"(?:\s+\w+){0,4}\s+(?:help|assist|do\s+that|run|comply|perform|proceed|carry\s+out)",
    re.IGNORECASE,
)

# Corpus envelope fields (edamame_core/tests/divergence_replay.rs, deny_unknown_fields).
PREDICTION_SPEC_KEYS = (
    "session_key", "action", "tools_called",
    "scope_process_paths", "scope_parent_paths", "scope_grandparent_paths", "scope_any_lineage_paths",
    "expected_traffic", "expected_sensitive_files", "expected_lan_devices", "expected_local_open_ports",
    "expected_process_paths", "expected_parent_paths", "expected_grandparent_paths", "expected_open_files",
    "expected_l7_protocols", "expected_system_config", "expected_operations",
    "not_expected_traffic", "not_expected_sensitive_files", "not_expected_lan_devices",
    "not_expected_local_open_ports", "not_expected_process_paths", "not_expected_parent_paths",
    "not_expected_grandparent_paths", "not_expected_open_files", "not_expected_l7_protocols",
    "not_expected_system_config",
)
SCOPE_SPEC_KEYS = (
    "expected_traffic", "expected_sensitive_files", "expected_lan_devices", "expected_local_open_ports",
    "expected_process_paths", "expected_parent_paths", "expected_grandparent_paths", "expected_open_files",
    "expected_l7_protocols", "expected_system_config", "expected_operations",
)
TELEMETRY_KEYS = ("sessions", "anomalous", "blacklisted", "lan_devices", "host_device",
                  "file_events", "self_addresses", "self_names")


# ── small utilities ─────────────────────────────────────────────────────

def now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def write_json(path: Path, data: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False, default=str) + "\n", encoding="utf-8")
    return path


def safe_name(text: str, limit: int = 80) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", text)[:limit].strip("_") or "x"


def rpc(method: str, args: Optional[dict] = None, timeout: float = READ_TIMEOUT) -> object:
    """cli_rpc with dict args; raises on failure (callers decide)."""
    return cli_rpc(method, json.dumps(args) if args is not None else None, timeout=timeout)


def rpc_text(method: str, timeout: float = READ_TIMEOUT) -> str:
    """Plain-string RPCs (get_core_version, get_core_info): cli_rpc decodes a
    string result a second time as JSON, which fails on "2.0.5"; read the
    single JSON string here instead."""
    proc = subprocess.run([find_cli_binary(), "rpc", method], capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=timeout)
    if proc.returncode != 0:
        raise RuntimeError(f"edamame_cli rpc {method} failed (rc={proc.returncode}): {proc.stderr.strip()[-300:]}")
    text = proc.stdout.strip()
    text = text[len("Result: "):] if text.startswith("Result: ") else text
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        return text
    return value if isinstance(value, str) else json.dumps(value)


def rpc_or_none(method: str, args: Optional[dict] = None, timeout: float = READ_TIMEOUT) -> object:
    return rpc_quiet(method, json.dumps(args) if args is not None else None, timeout=timeout)


def as_obj(value: object) -> object:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value
    return value


def sev(f: dict) -> str:
    return str(f.get("severity") or "").strip().upper()


def is_alertable(f: dict) -> bool:
    return not f.get("dismissed") and sev(f) in ALERTABLE


def finding_key(f: dict) -> str:
    key = str(f.get("finding_key") or "").strip()
    if key:
        return key
    # Session findings can carry an empty key; synthesize a stable local one.
    parts = [str(f.get(k) or "") for k in ("check", "session_uid", "process_path", "destination_domain",
                                             "destination_ip", "subject_path")]
    return "local:" + "|".join(parts)


@contextlib.contextmanager
def provider_env(agent_type: Optional[str]):
    """Expose only the key this agent needs, only while it runs."""
    for var in PROVIDER_KEY_VARS:
        os.environ.pop(var, None)
    spec = REAL_DRIVERS.get(agent_type or "") or {}
    key_env = spec.get("key_env")
    if key_env and _KEYS.get(key_env):
        os.environ[key_env] = _KEYS[key_env]
    try:
        yield
    finally:
        for var in PROVIDER_KEY_VARS:
            os.environ.pop(var, None)


def stash_provider_keys() -> None:
    for var in PROVIDER_KEY_VARS:
        val = os.environ.pop(var, None)
        if val:
            _KEYS[var] = val
    # codex reads either name; the harness sets both from OPENAI_API_KEY.
    if "OPENAI_API_KEY" not in _KEYS and "CODEX_API_KEY" in _KEYS:
        _KEYS["OPENAI_API_KEY"] = _KEYS["CODEX_API_KEY"]


def tool_available(spec: str) -> bool:
    return any(cli_path(alt) for alt in spec.split("|"))


# ── daemon state snapshots ──────────────────────────────────────────────

class LabState:
    """What the run has already seen, so each collection reports only news."""

    def __init__(self) -> None:
        self.attack: Dict[str, dict] = {}        # key -> finding (last seen)
        self.reports: set = set()
        self.incidents: Dict[str, dict] = {}     # incident_id -> record
        self.verdicts: set = set()
        self.fp_candidates: set = set()

    def snapshot(self) -> dict:
        attack: Dict[str, dict] = {}
        reports: List[str] = []
        rep = as_obj(rpc_or_none("get_attack_pattern_findings", timeout=READ_TIMEOUT))
        if isinstance(rep, dict):
            for f in rep.get("findings") or []:
                if isinstance(f, dict):
                    attack[finding_key(f)] = f
        hist = as_obj(rpc_or_none("get_attack_pattern_history", {"limit": 100}, timeout=READ_TIMEOUT))
        if isinstance(hist, list):
            for r in hist:
                if not isinstance(r, dict):
                    continue
                if r.get("report_id"):
                    reports.append(str(r["report_id"]))
                for f in r.get("findings") or []:
                    if isinstance(f, dict):
                        attack.setdefault(finding_key(f), f)
        incidents: Dict[str, dict] = {}
        inc = as_obj(rpc_or_none("get_divergence_incidents", {"limit": 500}, timeout=READ_TIMEOUT))
        if isinstance(inc, list):
            for r in inc:
                if isinstance(r, dict) and r.get("incident_id"):
                    incidents[str(r["incident_id"])] = r
        verdicts: Dict[str, dict] = {}
        vh = as_obj(rpc_or_none("get_divergence_history", {"limit": 50}, timeout=READ_TIMEOUT))
        if isinstance(vh, list):
            for v in vh:
                if isinstance(v, dict) and v.get("entry_id"):
                    verdicts[str(v["entry_id"])] = v
        status = as_obj(rpc_or_none("get_attack_pattern_detector_status", timeout=READ_TIMEOUT))
        fp_cands = []
        if isinstance(status, dict):
            fp_cands = [c for c in status.get("fp_corpus_candidates_recent") or [] if isinstance(c, dict)]
        return {"attack": attack, "reports": reports, "incidents": incidents,
                "verdicts": verdicts, "fp_candidates": fp_cands, "detector_status": status}

    def absorb(self, snap: dict) -> None:
        self.attack.update(snap["attack"])
        self.reports.update(snap["reports"])
        self.incidents.update(snap["incidents"])
        self.verdicts.update(snap["verdicts"].keys())
        self.fp_candidates.update(f"{c.get('finding_key')}|{c.get('at')}" for c in snap["fp_candidates"])

    def diff(self, snap: dict) -> dict:
        new_alertable, new_low, escalated = [], [], []
        for key, f in snap["attack"].items():
            prev = self.attack.get(key)
            if prev is None:
                (new_alertable if is_alertable(f) else new_low).append(f)
            elif is_alertable(f) and not is_alertable(prev):
                escalated.append(f)
        new_incidents = []
        for iid, r in snap["incidents"].items():
            prev = self.incidents.get(iid)
            reopened = prev is not None and str(prev.get("status", "")).lower() != "active" \
                and str(r.get("status", "")).lower() == "active"
            if prev is None or reopened:
                new_incidents.append(r)
        new_reports = [r for r in snap["reports"] if r not in self.reports]
        new_verdicts = [v for eid, v in snap["verdicts"].items()
                        if eid not in self.verdicts and str(v.get("verdict", "")).upper() not in ("CLEAN", "CLEANHEARTBEAT", "NOMODEL", "STALE")]
        new_fp_cands = [c for c in snap["fp_candidates"]
                        if f"{c.get('finding_key')}|{c.get('at')}" not in self.fp_candidates]
        return {"alertable": new_alertable + escalated, "low": new_low, "incidents": new_incidents,
                "reports": new_reports, "verdicts": new_verdicts, "fp_candidates": new_fp_cands}


def tick_everything(observer_agents: Iterable[str]) -> None:
    for agent in observer_agents:
        observer_tick(agent, timeout=TICK_TIMEOUT)
    rpc_quiet("debug_run_vulnerability_detector_tick", timeout=TICK_TIMEOUT)
    rpc_quiet("debug_run_divergence_tick", timeout=TICK_TIMEOUT)


# ── evidence capture ────────────────────────────────────────────────────

def export_attack_finding(f: dict, out_dir: Path) -> dict:
    key = str(f.get("finding_key") or "")
    entry = {"finding_key": finding_key(f), "check": f.get("check"), "severity": sev(f),
             "alertable": is_alertable(f), "process": f.get("process_path") or f.get("process_name"),
             "destination": f.get("destination_domain") or f.get("destination_ip"),
             "subject_path": f.get("subject_path"), "detection_basis": f.get("detection_basis"),
             "description": f.get("description")}
    if not key:
        entry["export_error"] = "finding has no finding_key (session finding): not exportable"
        write_json(out_dir / f"{safe_name(finding_key(f))}.finding.json", f)
        return entry
    try:
        export = rpc("export_attack_pattern_finding_details",
                     {"request_json": json.dumps({"finding_key": key})}, timeout=180)
    except Exception as exc:  # noqa: BLE001
        entry["export_error"] = str(exc)
        write_json(out_dir / f"{safe_name(key)}.finding.json", f)
        return entry
    path = write_json(out_dir / f"{safe_name(key)}.export.json", export)
    entry["export_path"] = str(path)
    details = (export or {}).get("details") if isinstance(export, dict) else None
    if isinstance(details, dict):
        trace = details.get("debug_trace") or {}
        raw = [r for r in (trace.get("raw_findings") or []) if isinstance(r, dict) and r.get("finding_key") == key]
        if raw:
            raw_sev = max((sev(r) for r in raw), key=lambda s: SEV_RANK.get(s, 0))
            entry["detector_severity"] = raw_sev
            entry["adjudicator_demoted"] = SEV_RANK.get(raw_sev, 0) >= 3 and not is_alertable(f)
        decision = trace.get("llm_decision")
        if decision:
            entry["llm_decision"] = decision
        if trace.get("llm_error"):
            entry["llm_error"] = trace.get("llm_error")
    return entry


def capture_near_misses(report_ids: List[str], snap_attack: Dict[str, dict], out_dir: Path) -> List[dict]:
    """HIGH/CRITICAL raw detector findings that did not land as alertable:
    the adjudicator (or a deterministic suppression) caught them. Each is an
    FP that alerts whenever the Portal does not answer in advisory mode."""
    misses: List[dict] = []
    for rid in report_ids[:50]:
        trace = as_obj(rpc_or_none("get_attack_pattern_debug_trace", {"report_id": rid}, timeout=READ_TIMEOUT))
        if not isinstance(trace, dict):
            continue
        hits = []
        for r in trace.get("raw_findings") or []:
            if not isinstance(r, dict) or sev(r) not in ALERTABLE:
                continue
            final = snap_attack.get(finding_key(r))
            if final is not None and is_alertable(final):
                continue
            hits.append({"finding_key": finding_key(r), "check": r.get("check"), "raw_severity": sev(r),
                         "final_severity": sev(final) if final else "absent",
                         "process": r.get("process_path") or r.get("process_name"),
                         "subject_path": r.get("subject_path"),
                         "llm_decision": trace.get("llm_decision")})
        if hits:
            path = write_json(out_dir / f"{safe_name(rid)}.trace.json", trace)
            for h in hits:
                h["trace_path"] = str(path)
            misses.extend(hits)
    return misses


def _spec_from(obj: dict, keys: Tuple[str, ...]) -> dict:
    out = {}
    for k in keys:
        v = obj.get(k)
        if v not in (None, "", [], {}):
            out[k] = v
    return out


def _model_spec(model: dict) -> dict:
    preds = []
    for p in model.get("predictions") or []:
        if not isinstance(p, dict):
            continue
        spec = _spec_from(p, PREDICTION_SPEC_KEYS)
        for plane in ("human_scope", "agent_scope"):
            if isinstance(p.get(plane), dict):
                spec[plane] = _spec_from(p[plane], SCOPE_SPEC_KEYS)
        # The transcript's birth and last write: the policies that place a
        # write in the session's span (evaluator integrity) read them. The
        # decoded tool calls ride along: the policies that ask whether the
        # agent acted on a claim (growth, escalation) read those.
        raw = p.get("raw_input")
        if isinstance(raw, dict) and raw.get("started_at") and raw.get("modified_at"):
            span = {"started_at": raw["started_at"], "modified_at": raw["modified_at"]}
            events = [{"name": str(e.get("name") or ""), "target": str(e.get("target") or "")}
                      for e in raw.get("tool_events") or [] if isinstance(e, dict) and e.get("name")]
            if events:
                span["tool_events"] = events
            spec["transcript_span"] = span
        preds.append(spec)
    duration = 300
    try:
        start = _dt.datetime.fromisoformat(str(model["window_start"]).replace("Z", "+00:00"))
        end = _dt.datetime.fromisoformat(str(model["window_end"]).replace("Z", "+00:00"))
        duration = max(1, int((end - start).total_seconds()))
    except Exception:  # noqa: BLE001
        pass
    return {"agent_type": model.get("agent_type", ""), "agent_instance_id": model.get("agent_instance_id", ""),
            "window_age_secs": 0, "window_duration_secs": duration,
            "version": str(model.get("version") or "fp-lab"), "predictions": preds}


FILE_EVENT_KEYS = ("timestamp", "path", "event_type", "process_name", "process_path",
                   "parent_process_name", "parent_process_path", "is_sensitive", "labels")


def incident_file_events(incident: dict, fim: object) -> List[dict]:
    """The FIM events an incident's evidence names, by path. The debug trace's
    telemetry snapshot carries no FIM events, so a candidate built from it
    alone cannot replay a write-based finding (evaluator integrity) and would
    pass by vacuity."""
    events = fim.get("events") if isinstance(fim, dict) else None
    if not isinstance(events, list):
        return []
    texts = [str(e.get("description") or "") for e in incident.get("top_evidence") or []
             if isinstance(e, dict)]
    picked = []
    for ev in events:
        path = str(ev.get("path") or "") if isinstance(ev, dict) else ""
        if path and any(path in t for t in texts):
            picked.append({k: ev.get(k) for k in FILE_EVENT_KEYS if k in ev})
    return picked


def divergence_envelope(div_id: str, scenario: Scenario, case_id: str, incident: dict,
                        trace: object, model: object, history: object,
                        file_events: Optional[List[dict]] = None) -> dict:
    """Draft divergence corpus entry: the live model and telemetry, asserting
    the benign outcome (Clean, the fired categories absent). Review before
    committing: the replay corpus has no field for the parser hints, so a
    hint-dependent exemption may not replay identically."""
    categories = sorted({str(e.get("category")) for e in incident.get("top_evidence") or []
                         if isinstance(e, dict) and e.get("category")})
    inp: dict = {}
    if isinstance(model, dict) and model.get("predictions") is not None:
        inp["model"] = _model_spec(model)
        if isinstance(history, list):
            priors = [h for h in history if isinstance(h, dict)
                      and h.get("agent_instance_id") == model.get("agent_instance_id")
                      and h.get("hash") != model.get("hash") and h.get("predictions") is not None]
            priors.sort(key=lambda h: str(h.get("window_end") or ""))
            if priors:
                inp["prior_models"] = [_model_spec(h) for h in priors[-5:]]
    telemetry = (trace or {}).get("telemetry_snapshot") if isinstance(trace, dict) else None
    if isinstance(telemetry, dict):
        for k in TELEMETRY_KEYS:
            if k in telemetry and telemetry[k] not in (None, [], {}):
                inp[k] = telemetry[k]
    if file_events and not inp.get("file_events"):
        inp["file_events"] = file_events
    return {
        "div_id": div_id,
        "title": f"FP lab: {scenario.title}",
        "report_problem": f"benign agent work graded as {', '.join(categories) or 'divergence'}",
        "status": "detected",
        "platforms": [host_os()],
        "notes": (f"Captured by tests/fp_lab ({case_id}, fp_class {scenario.fp_class}) on "
                  f"{socket.gethostname()} at {now_iso()} from incident {incident.get('incident_id')} "
                  f"(severity {incident.get('severity')}). Draft: review the model and telemetry, trim "
                  "them to the evidence, and confirm the replay before committing."),
        "input": inp,
        "assertions": {"expected_verdict_kind": "Clean", "expected_evidence_present": [],
                       "expected_evidence_absent": categories},
    }


def capture_incident(incident: dict, scenario: Scenario, case_id: str, case_dir: Path,
                     run_dir: Path, agents: List[str]) -> dict:
    iid = str(incident.get("incident_id"))
    out = case_dir / "divergence"
    full = as_obj(rpc_or_none("get_divergence_incident", {"incident_id": iid})) or incident
    entry_id = str((full or {}).get("entry_id") or incident.get("entry_id") or "")
    trace = as_obj(rpc_or_none("get_divergence_debug_trace", {"entry_id": entry_id}, timeout=120)) if entry_id else None
    model = as_obj(rpc_or_none("get_behavioral_model", timeout=READ_TIMEOUT))
    history = as_obj(rpc_or_none("get_behavioral_model_history", {"limit": 20}, timeout=READ_TIMEOUT))
    file_events = incident_file_events(full if isinstance(full, dict) else incident,
                                       as_obj(rpc_or_none("get_file_events", timeout=READ_TIMEOUT)))
    raw_sessions = {}
    for agent in sorted(set((full or {}).get("agent_types") or []) | set(agents)):
        raw_sessions[agent] = as_obj(rpc_or_none(
            "get_raw_agent_activity", {"agent_type": agent, "active_window_minutes": 180, "limit": 5}, timeout=180))
    bundle = {"incident": full, "debug_trace": trace, "behavioral_model": model,
              "behavioral_model_history": history, "raw_agent_activity": raw_sessions,
              "file_events": file_events, "captured_at": now_iso()}
    bundle_path = write_json(out / f"{safe_name(iid)}.bundle.json", bundle)
    div_id = f"DIV-LAB-{safe_name(scenario.id, 60).upper()}"
    envelope = divergence_envelope(div_id, scenario, case_id, full if isinstance(full, dict) else incident,
                                   trace, model, history, file_events)
    cand_path = write_json(run_dir / "candidates" / "divergence" / div_id / f"{safe_name(case_id)}-{safe_name(iid)[-24:]}.json",
                           envelope)
    return {"incident_id": iid, "entry_id": entry_id, "severity": incident.get("severity"),
            "status": incident.get("status"), "title": incident.get("title"),
            "categories": envelope["assertions"]["expected_evidence_absent"],
            "top_evidence": [{"category": e.get("category"), "severity": e.get("severity"),
                              "description": str(e.get("description") or "")[:300]}
                             for e in incident.get("top_evidence") or [] if isinstance(e, dict)],
            "bundle_path": str(bundle_path), "corpus_candidate": str(cand_path)}


# ── corpus shaping (attack pattern) ─────────────────────────────────────

def find_corpus_tool(explicit: Optional[str]) -> Optional[Path]:
    for cand in (explicit, os.environ.get("FP_CORPUS_TOOL"),
                 str(HERE / "tools" / "fp_corpus_from_export.sh"),
                 str(TESTS.parent.parent / "edamame_core" / "tools" / "fp_corpus_from_export.sh")):
        if cand and Path(cand).is_file():
            return Path(cand)
    return None


def attack_fp_id(scenario_fp_class: str, scenario_id: str) -> str:
    if scenario_fp_class.startswith("FP-") and not scenario_fp_class.startswith("FP-DIV"):
        return scenario_fp_class
    return f"FP-LAB-{safe_name(scenario_id, 60).upper()}"


def shape_attack_candidate(export_path: Path, fp_id: str, case_id: str, run_dir: Path,
                           tool: Optional[Path]) -> dict:
    if tool is None:
        return {"shaped": False, "reason": "fp_corpus_from_export.sh not found (run `run_fp_lab.py shape` where it is)"}
    if not shutil.which("jq"):
        return {"shaped": False, "reason": "jq not installed (run `run_fp_lab.py shape` on the operator machine)"}
    key12 = safe_name(export_path.name.replace(".export.json", ""))[-12:]
    out = run_dir / "candidates" / "attack_pattern" / fp_id / f"{safe_name(case_id)}-{key12}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    proc = subprocess.run(["bash", str(tool), str(export_path), fp_id, "demoted_to_low"],
                          capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120)
    if proc.returncode != 0:
        return {"shaped": False, "reason": f"tool exit {proc.returncode}: {proc.stderr.strip()[-300:]}"}
    out.write_text(proc.stdout, encoding="utf-8")
    return {"shaped": True, "corpus_candidate": str(out)}


# ── preflight ───────────────────────────────────────────────────────────

def preflight(args: argparse.Namespace, lab_agents: List[str]) -> Tuple[bool, dict]:
    pf: dict = {"at": now_iso(), "host": socket.gethostname(), "platform": host_os(), "problems": []}
    problems: List[str] = pf["problems"]
    try:
        pf["edamame_cli"] = find_cli_binary()
        pf["core_version"] = rpc_text("get_core_version")
        pf["core_info"] = rpc_text("get_core_info")
    except Exception as exc:  # noqa: BLE001
        problems.append(f"daemon not reachable through edamame_cli: {exc}")
        return False, pf
    if args.expect_core_version and not str(pf["core_version"]).startswith(args.expect_core_version):
        problems.append(f"core version {pf['core_version']} is not the owned build {args.expect_core_version}")
    conn = as_obj(rpc_or_none("get_connection"))
    pf["hub_connected"] = bool(isinstance(conn, dict) and conn.get("is_connected"))
    if pf["hub_connected"] and not args.allow_hub:
        problems.append("daemon is connected to the Hub; the lab runs against a disconnected daemon (--allow-hub to override)")
    pf["llm_probe"] = _llm_probe()
    llm = as_obj(rpc_or_none("agentic_test_llm", timeout=120))
    pf["llm_ok"] = bool(isinstance(llm, dict) and llm.get("success"))
    if not pf["llm_ok"] and not args.allow_no_llm:
        problems.append(f"LLM/Portal not operating: {pf['llm_probe']}")
    if args.set_adjudication != "keep":
        for method in ("set_attack_pattern_adjudication_mode", "set_divergence_adjudication_mode"):
            pf.setdefault("adjudication_set", {})[method] = as_obj(rpc_or_none(method, {"mode": args.set_adjudication}))
    pf["protection"] = as_obj(rpc_or_none("agentic_get_protection_status"))
    det = as_obj(rpc_or_none("get_attack_pattern_detector_status"))
    div = as_obj(rpc_or_none("get_divergence_engine_status"))
    pf["attack_pattern_detector"] = {k: (det or {}).get(k) for k in (
        "running", "interval_secs", "adjudication_mode", "adjudication_auto", "capture_active",
        "content_scan_degraded", "active_findings", "active_alertable_findings")} if isinstance(det, dict) else det
    pf["divergence_engine"] = {k: (div or {}).get(k) for k in (
        "running", "interval_secs", "adjudication_mode", "adjudication_auto", "last_verdict",
        "contributor_count", "model_age_secs")} if isinstance(div, dict) else div
    pf["capturing"] = as_obj(rpc_or_none("is_capturing"))
    fim = as_obj(rpc_or_none("get_file_monitor_status"))
    pf["file_monitor"] = {k: (fim or {}).get(k) for k in ("is_monitoring", "watch_paths")} if isinstance(fim, dict) else fim
    obs = {}
    try:
        for row in observer_status().get("agents", []):
            if isinstance(row, dict):
                obs[row.get("agent_type")] = {k: row.get(k) for k in (
                    "enabled", "installed", "discovered", "transcripts_root_accessible", "last_transcripts_roots", "last_error")}
    except Exception as exc:  # noqa: BLE001
        problems.append(f"transcript observer status unavailable: {exc}")
    pf["transcript_observer"] = obs
    if not (isinstance(det, dict) and det.get("running")):
        problems.append("attack-pattern detector is not running")
    if not (isinstance(div, dict) and div.get("running")):
        problems.append("divergence engine is not running")
    if pf["capturing"] is not True:
        problems.append("packet capture is not running")
    if not (isinstance(fim, dict) and fim.get("is_monitoring")):
        problems.append("file monitor is not running")
    for agent in lab_agents:
        row = obs.get(agent)
        if row is None:
            problems.append(f"transcript observer does not know agent {agent}")
        elif row.get("enabled") is False:
            problems.append(f"transcript observer disabled for {agent}")
    for engine in ("attack_pattern_detector", "divergence_engine"):
        mode = (pf.get(engine) or {}).get("adjudication_mode") if isinstance(pf.get(engine), dict) else None
        if mode == "deterministic":
            problems.append(f"{engine} adjudication is deterministic: the lab measures what users see with the LLM")
    return not problems, pf


# ── case execution ──────────────────────────────────────────────────────

def drive_agent_case(s: Scenario, agent: str, ws: Path, case_dir: Path, args: argparse.Namespace) -> dict:
    spec = REAL_DRIVERS[agent]
    result: dict = {"requests": []}
    env_values = {name: os.environ.get(name, "") for name in s.requires_env}
    session_id: Optional[str] = None
    with provider_env(agent):
        for i, template in enumerate(s.requests):
            prompt = template.format_map(env_values) if s.requires_env else template
            extra_args: List[str] = []
            extra_env: Dict[str, str] = {}
            if agent == "claude_code":
                extra_args = ["--output-format", "json"]
                if args.claude_model:
                    extra_args += ["--model", args.claude_model]
                if session_id:
                    extra_args += ["--resume", session_id]
                extra_env = {"DISABLE_AUTOUPDATER": "1"}
            elif agent == "codex":
                if args.codex_model:
                    extra_args += ["-m", args.codex_model]
                if i > 0:
                    extra_args += ["resume", "--last"]
            started = time.time()
            rc = spec["drive"](ws, prompt, args.agent_timeout, False, None,
                               extra_args=extra_args, extra_env=extra_env)
            output = "\n".join(last_cmd_output_tail(10 ** 6))
            out_path = case_dir / "agent" / f"request_{i + 1}.out.txt"
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(output, encoding="utf-8")
            final_text = output
            if agent == "claude_code":
                for line in reversed(output.splitlines()):
                    line = line.strip()
                    if line.startswith("{") and '"session_id"' in line:
                        try:
                            obj = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        session_id = obj.get("session_id") or session_id
                        final_text = str(obj.get("result") or "")
                        result.setdefault("claude", []).append({k: obj.get(k) for k in (
                            "subtype", "is_error", "num_turns", "duration_ms", "total_cost_usd", "session_id")})
                        break
            else:
                final_text = "\n".join(output.splitlines()[-40:])
            result["requests"].append({"n": i + 1, "rc": rc, "secs": round(time.time() - started, 1),
                                       "output": str(out_path), "final_text": final_text[-1500:]})
            if rc is None:
                result["driver_unavailable"] = True
                break
    marker_ok = bool(s.marker) and (ws / s.marker).is_file() and (ws / s.marker).stat().st_size > 0
    result["marker_present"] = marker_ok
    joined = "\n".join(r["final_text"] for r in result["requests"])
    refusal = REFUSAL_RE.search(joined)
    if not marker_ok and refusal:
        result["refused"] = refusal.group(0)
    result["delivered"] = marker_ok
    return result


def settle(state: LabState, observer_agents: List[str], secs: int, every: int,
           on_news) -> None:
    deadline = time.time() + secs
    while True:
        tick_everything(observer_agents)
        snap = state.snapshot()
        news = state.diff(snap)
        on_news(news, snap)
        state.absorb(snap)
        if time.time() >= deadline:
            return
        time.sleep(max(1, min(every, int(deadline - time.time()) + 1)))


def run_cmd_run(args: argparse.Namespace) -> int:
    if hasattr(os, "geteuid") and os.geteuid() == 0 and not args.allow_root:
        log("FP lab: refusing to run as root. Agents must run as the lab user whose home the "
            "daemon's transcript observer reads (the console user). Use --allow-root only on a "
            "CI runner whose daemon observes /root.")
        return 2
    stash_provider_keys()
    _augment_path("~/.local/bin", "~/.cargo/bin", "~/.npm-global/bin")
    lab_root = Path(os.path.expanduser(args.lab_root)).resolve()
    stamp = time.strftime("%Y%m%d-%H%M%S")
    host = safe_name(socket.gethostname(), 40)
    run_dir = Path(args.out).resolve() if args.out else lab_root / "runs" / f"{host}-{stamp}"
    run_dir.mkdir(parents=True, exist_ok=True)
    ws_root = lab_root / "ws" / run_dir.name
    section(f"EDAMAME FP lab: {run_dir}")

    registry_types: Optional[List[str]] = None
    try:
        registry_types = [a["agent_type"] for a in reg.iter_agents(reg.load_registry())]
    except Exception as exc:  # noqa: BLE001
        log(f"  registry unavailable ({exc}); agent ids are checked against the daemon's observer instead")
    problems = validate(registry_types)
    if problems:
        for p in problems:
            log(f"  catalog problem: {p}")
        return 2

    lab_agents = [a.strip() for a in args.agents.split(",") if a.strip()]
    wanted = {x.strip() for x in args.scenarios.split(",") if x.strip()} if args.scenarios else set()
    skipped = {x.strip() for x in args.skip.split(",") if x.strip()} if args.skip else set()
    osn = host_os()

    # Plan.
    plan: List[dict] = []
    for s in SCENARIOS:
        agents = [a for a in s.agents if a in lab_agents] if s.kind == "agent" else [""]
        if s.kind == "agent" and not agents:
            agents = [s.agents[0]]
        for agent in agents:
            case_id = f"{s.id}@{agent}" if agent else s.id
            if wanted and s.id not in wanted and case_id not in wanted:
                continue
            item = {"case_id": case_id, "scenario": s.id, "agent": agent, "skip": None}
            if case_id in skipped or s.id in skipped:
                item["skip"] = "skipped by --skip"
            elif osn not in s.platforms:
                item["skip"] = f"not a {osn} scenario"
            elif s.kind == "agent" and agent not in lab_agents:
                item["skip"] = f"agent {agent} not selected (--agents)"
            else:
                missing = [t for t in s.requires if not tool_available(t)]
                missing_env = [e for e in s.requires_env if not os.environ.get(e)]
                if missing:
                    item["skip"] = f"missing tool(s): {', '.join(missing)}"
                elif missing_env:
                    item["skip"] = f"missing env: {', '.join(missing_env)}"
                elif s.kind == "agent":
                    with provider_env(agent):
                        status, reason = real_driver_available(agent)
                    if status != "ok":
                        item["skip"] = f"{agent}: {reason}"
            plan.append(item)
    write_json(run_dir / "plan.json", plan)
    for item in plan:
        log(f"  plan: {item['case_id']:<60} {'SKIP: ' + item['skip'] if item['skip'] else 'run'}")
    if args.dry_run:
        return 0

    ok, pf = preflight(args, lab_agents)
    write_json(run_dir / "preflight.json", pf)
    log(json.dumps({k: pf.get(k) for k in ("core_version", "hub_connected", "llm_ok", "llm_probe",
                                            "attack_pattern_detector", "divergence_engine", "capturing")},
                   default=str))
    if not ok:
        for p in pf["problems"]:
            log(f"  PREFLIGHT FAIL: {p}")
        return 2

    state = LabState()
    observer_agents = [a for a in lab_agents if a in (pf.get("transcript_observer") or {})]
    ambient: dict = {"alertable": [], "low": [], "incidents": []}
    # The candidate's memory and CPU through the whole run, warm-up included
    # (daemon_perf: the lab is also the release's realistic load test).
    sampler = daemon_perf.PerfSampler(run_dir / "perf.csv", interval=args.perf_interval)
    sampler.start()

    def keep_ambient(news: dict, _snap: dict) -> None:
        ambient["alertable"].extend(news["alertable"])
        ambient["low"].extend(news["low"])
        ambient["incidents"].extend(news["incidents"])

    section(f"Warm-up / baseline ({args.warmup_secs}s)")
    state.absorb(state.snapshot())
    baseline_counts = {"attack": len(state.attack), "incidents": len(state.incidents)}
    settle(state, observer_agents, args.warmup_secs, args.tick_every, keep_ambient)
    write_json(run_dir / "baseline.json", {
        "at": now_iso(), "before_warmup": baseline_counts,
        "after_warmup": {"attack": len(state.attack), "incidents": len(state.incidents)},
        "ambient_during_warmup": {
            "alertable": [{"finding_key": finding_key(f), "check": f.get("check"), "severity": sev(f),
                           "process": f.get("process_path")} for f in ambient["alertable"]],
            "low": [{"finding_key": finding_key(f), "check": f.get("check")} for f in ambient["low"]],
            "incidents": [{"incident_id": i.get("incident_id"), "severity": i.get("severity"),
                           "title": i.get("title")} for i in ambient["incidents"]],
        },
        "attack_keys": sorted(state.attack), "incident_ids": sorted(state.incidents)})

    tool = find_corpus_tool(args.corpus_tool)
    scen_by_id = {s.id: s for s in SCENARIOS}
    results: List[dict] = []

    def make_collector(case: dict, scenario: Scenario, case_dir: Path, agents_for_capture: List[str]):
        def collect(news: dict, snap: dict) -> None:
            for f in news["alertable"] + news["low"]:
                entry = export_attack_finding(f, case_dir / "attack_pattern")
                if entry.get("alertable") and entry.get("export_path"):
                    entry.update(shape_attack_candidate(Path(entry["export_path"]),
                                                        attack_fp_id(scenario.fp_class, scenario.id),
                                                        case["case_id"], run_dir, tool))
                case["attack_pattern"].append(entry)
                log(f"  [{case['case_id']}] {'ALERTABLE' if entry.get('alertable') else 'low'} "
                    f"{entry.get('severity')} {entry.get('check')} {entry.get('process')} -> {entry.get('subject_path') or entry.get('destination')}")
            for inc in news["incidents"]:
                entry = capture_incident(inc, scenario, case["case_id"], case_dir, run_dir, agents_for_capture)
                case["divergence"].append(entry)
                log(f"  [{case['case_id']}] DIVERGENCE INCIDENT {entry.get('severity')} {entry.get('title')}")
            if news["reports"]:
                case["near_misses"].extend(capture_near_misses(news["reports"], snap["attack"], case_dir / "near_miss"))
            case["non_clean_verdicts"].extend(
                {"entry_id": v.get("entry_id"), "verdict": v.get("verdict"),
                 "deterministic_verdict": v.get("deterministic_verdict"),
                 "categories": sorted({str(e.get("category")) for e in v.get("evidence") or [] if isinstance(e, dict)})}
                for v in news["verdicts"])
            case["llm_suppressed"].extend(news["fp_candidates"])
        return collect

    for item in plan:
        s = scen_by_id[item["scenario"]]
        case_dir = run_dir / "cases" / safe_name(item["case_id"].replace("@", "__"))
        case = {"case_id": item["case_id"], "scenario": s.id, "title": s.title, "fp_class": s.fp_class,
                "kind": s.kind, "agent": item["agent"], "temp_behaviour": s.temp_behaviour,
                "started_at": now_iso(), "attack_pattern": [], "divergence": [], "near_misses": [],
                "non_clean_verdicts": [], "llm_suppressed": []}
        if item["skip"]:
            case.update(status="SKIP", reason=item["skip"])
            results.append(case)
            write_json(case_dir / "case.json", case)
            continue
        section(f"Case {item['case_id']}: {s.title}")
        try:
            ws = make_workspace(s.fixture, item["agent"] or "direct", ws_root)
            case["workspace"] = str(ws)
            log(f"  workspace: {ws}")
            if s.kind == "agent":
                drive = drive_agent_case(s, item["agent"], ws, case_dir, args)
                case["drive"] = drive
            else:
                with provider_env(None):
                    delivered, detail = run_action(s.action, ws)
                case["drive"] = {"delivered": delivered, "detail": detail}
            observer = list(dict.fromkeys(([item["agent"]] if item["agent"] else []) + observer_agents))
            settle(state, observer, args.settle_secs, args.tick_every,
                   make_collector(case, s, case_dir, [item["agent"]] if item["agent"] else []))
            if item["agent"]:
                row = observer_row(item["agent"]) or {}
                case["observer"] = {k: row.get(k) for k in ("discovered", "last_session_count", "last_error",
                                                             "last_window_hash", "last_run_at")}
            running, contributors, age = _divergence_status()
            case["divergence_engine"] = {"running": running, "contributor_count": contributors, "model_age_secs": age}
        except Exception as exc:  # noqa: BLE001
            case["error"] = f"{exc}"
            case["traceback"] = traceback.format_exc()[-3000:]
            log(f"  ERROR: {exc}")
        alertable = [e for e in case["attack_pattern"] if e.get("alertable")]
        if alertable or case["divergence"]:
            case["status"] = "FAIL"
        elif case.get("error"):
            case["status"] = "ERROR"
        elif (case.get("drive") or {}).get("refused"):
            case.update(status="SKIP", reason=f"agent refused: {case['drive']['refused']}")
        elif not (case.get("drive") or {}).get("delivered", False):
            reqs = (case.get("drive") or {}).get("requests") or []
            rcs = [r.get("rc") for r in reqs]
            case.update(status="SKIP", reason=f"stimulus not delivered ({(case.get('drive') or {}).get('detail') or f'marker {s.marker!r} missing, rc={rcs}'})")
        else:
            case["status"] = "PASS"
        case["finished_at"] = now_iso()
        results.append(case)
        write_json(case_dir / "case.json", case)
        log(f"  => {case['status']} {case.get('reason', '')}")

    section(f"Drain ({args.drain_secs}s)")
    drain_scn = Scenario(id="post-run-drain", title="Findings that surfaced after the last case",
                         fp_class="new", kind="direct", platforms=(osn,), fixture="empty")
    drain_case = {"case_id": "post-run-drain", "scenario": "post-run-drain", "title": drain_scn.title,
                  "fp_class": "new", "kind": "drain", "agent": "", "attack_pattern": [], "divergence": [],
                  "near_misses": [], "non_clean_verdicts": [], "llm_suppressed": [], "started_at": now_iso()}
    drain_dir = run_dir / "cases" / "post-run-drain"
    settle(state, observer_agents, args.drain_secs, args.tick_every,
           make_collector(drain_case, drain_scn, drain_dir, observer_agents))
    drain_case["status"] = "FAIL" if ([e for e in drain_case["attack_pattern"] if e.get("alertable")]
                                      or drain_case["divergence"]) else "PASS"
    drain_case["finished_at"] = now_iso()
    write_json(drain_dir / "case.json", drain_case)
    results.append(drain_case)

    final_status = {
        "attack_pattern_detector": as_obj(rpc_or_none("get_attack_pattern_detector_status")),
        "divergence_engine": as_obj(rpc_or_none("get_divergence_engine_status")),
        "transcript_observer": as_obj(rpc_or_none("get_transcript_observer_status")),
    }
    write_json(run_dir / "final_status.json", final_status)
    sampler.stop()
    write_json(run_dir / "perf.json", daemon_perf.summarize(sampler.samples, results))
    return write_summary(run_dir, pf, results, args)


# ── summary ─────────────────────────────────────────────────────────────

def write_summary(run_dir: Path, pf: dict, results: List[dict], args: argparse.Namespace) -> int:
    counts: Dict[str, int] = {}
    for r in results:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    fails = [r for r in results if r["status"] == "FAIL"]
    perf_path = run_dir / "perf.json"
    perf = json.loads(perf_path.read_text(encoding="utf-8")) if perf_path.is_file() else None
    perf_reference = None
    reference_path = getattr(args, "perf_reference", "") or ""
    if reference_path and Path(reference_path).expanduser().is_file():
        try:
            perf_reference = json.loads(Path(reference_path).expanduser().read_text(encoding="utf-8"))
        except (OSError, ValueError):
            perf_reference = None
    summary = {
        "run_dir": str(run_dir), "host": pf.get("host"), "platform": pf.get("platform"),
        "core_version": pf.get("core_version"), "generated_at": now_iso(),
        "adjudication": {"attack_pattern": (pf.get("attack_pattern_detector") or {}).get("adjudication_mode"),
                         "divergence": (pf.get("divergence_engine") or {}).get("adjudication_mode")},
        "counts": counts, "verdict": "FAIL" if fails else "PASS",
        "perf": perf, "perf_reference": perf_reference,
        "cases": [{k: r.get(k) for k in ("case_id", "status", "reason", "fp_class", "kind", "agent", "error")}
                  | {"alertable": [e for e in r.get("attack_pattern", []) if e.get("alertable")],
                     "low": [e for e in r.get("attack_pattern", []) if not e.get("alertable")],
                     "divergence_incidents": r.get("divergence", []),
                     "near_misses": r.get("near_misses", []),
                     "non_clean_verdicts": r.get("non_clean_verdicts", []),
                     "llm_suppressed": r.get("llm_suppressed", [])}
                  for r in results],
    }
    write_json(run_dir / "summary.json", summary)

    lines = [f"# FP lab run {run_dir.name}", "",
             f"- Host: {pf.get('host')} ({pf.get('platform')}), core {pf.get('core_version')}",
             f"- Adjudication: attack pattern {summary['adjudication']['attack_pattern']}, "
             f"divergence {summary['adjudication']['divergence']}; LLM ok: {pf.get('llm_ok')}",
             f"- Verdict: **{summary['verdict']}** ({', '.join(f'{k} {v}' for k, v in sorted(counts.items()))})", "",
             "| Case | Status | Alertable | LOW | Incidents | Near misses | Note |",
             "|---|---|---|---|---|---|---|"]
    for c in summary["cases"]:
        note = (c.get("reason") or c.get("error") or "").replace("|", "/")[:120]
        lines.append(f"| `{c['case_id']}` | {c['status']} | {len(c['alertable'])} | {len(c['low'])} | "
                     f"{len(c['divergence_incidents'])} | {len(c['near_misses'])} | {note} |")
    lines.append("")
    for c in summary["cases"]:
        if not (c["alertable"] or c["divergence_incidents"] or c["low"] or c["near_misses"]
                or c["llm_suppressed"] or c["non_clean_verdicts"]):
            continue
        lines.append(f"## {c['case_id']} ({c['status']})")
        for e in c["alertable"]:
            lines.append(f"- ALERTABLE {e.get('severity')} `{e.get('check')}` {e.get('process')} -> "
                         f"{e.get('subject_path') or e.get('destination')}; export `{e.get('export_path')}`; "
                         f"candidate `{e.get('corpus_candidate') or e.get('reason')}`")
        for e in c["divergence_incidents"]:
            lines.append(f"- INCIDENT {e.get('severity')} {e.get('title')} ({', '.join(e.get('categories') or [])}); "
                         f"bundle `{e.get('bundle_path')}`; candidate `{e.get('corpus_candidate')}`")
        for e in c["low"]:
            demoted = " (detector HIGH+, adjudicator demoted)" if e.get("adjudicator_demoted") else ""
            lines.append(f"- low {e.get('severity')} `{e.get('check')}` {e.get('process')} -> "
                         f"{e.get('subject_path') or e.get('destination')}{demoted}; export `{e.get('export_path')}`")
        for e in c["near_misses"]:
            lines.append(f"- near miss: raw {e.get('raw_severity')} `{e.get('check')}` {e.get('process')} "
                         f"final {e.get('final_severity')}; trace `{e.get('trace_path')}`")
        for e in c["llm_suppressed"]:
            # The daemon keeps no report for a tick whose findings the LLM
            # suppressed, so only the key and time are available.
            lines.append(f"- detector hit SUPPRESSed by the LLM: `{e.get('finding_key')}` at {e.get('at')} "
                         f"({e.get('origin')}); no report retained, not exportable")
        for e in c["non_clean_verdicts"]:
            lines.append(f"- divergence verdict {e.get('verdict')} (deterministic {e.get('deterministic_verdict')}) "
                         f"without an incident: {', '.join(e.get('categories') or [])}")
        lines.append("")
    if perf is not None:
        lines += daemon_perf.markdown(perf, perf_reference)
    (run_dir / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    section(f"FP lab verdict: {summary['verdict']}")
    log((run_dir / "summary.md").read_text(encoding="utf-8"))
    for c in summary["cases"]:
        for e in c["alertable"]:
            log(f"FAIL {c['case_id']}: alertable {e.get('check')} -> {e.get('corpus_candidate') or e.get('export_path')}")
        for e in c["divergence_incidents"]:
            log(f"FAIL {c['case_id']}: divergence incident -> {e.get('corpus_candidate')}")
    return 1 if fails else 0


# ── shape subcommand ────────────────────────────────────────────────────

def run_cmd_shape(args: argparse.Namespace) -> int:
    run_dir = Path(args.run_dir).resolve()
    tool = find_corpus_tool(args.corpus_tool)
    shaped = 0
    for case_file in sorted((run_dir / "cases").glob("*/case.json")):
        case = json.loads(case_file.read_text(encoding="utf-8"))
        changed = False
        for e in case.get("attack_pattern", []):
            if not e.get("alertable") or not e.get("export_path"):
                continue
            export = Path(e["export_path"])
            if not export.is_file():  # artifacts copied to another machine
                export = case_file.parent / "attack_pattern" / Path(e["export_path"]).name
            res = shape_attack_candidate(export, attack_fp_id(case.get("fp_class", "new"), case.get("scenario", "")),
                                         case["case_id"], run_dir, tool)
            e.update(res)
            changed = True
            shaped += 1 if res.get("shaped") else 0
            log(f"  {case['case_id']}: {res}")
        if changed:
            write_json(case_file, case)
    log(f"shaped {shaped} candidate(s) under {run_dir / 'candidates' / 'attack_pattern'}")
    return 0


def run_cmd_summarize(args: argparse.Namespace) -> int:
    """Re-render summary.json / summary.md from the case files (after `shape`,
    or after copying a run to another machine)."""
    run_dir = Path(args.run_dir).resolve()
    pf = json.loads((run_dir / "preflight.json").read_text(encoding="utf-8"))
    plan = json.loads((run_dir / "plan.json").read_text(encoding="utf-8"))
    results = []
    for item in plan + [{"case_id": "post-run-drain"}]:
        name = "post-run-drain" if item["case_id"] == "post-run-drain" else safe_name(item["case_id"].replace("@", "__"))
        path = run_dir / "cases" / name / "case.json"
        if path.is_file():
            results.append(json.loads(path.read_text(encoding="utf-8")))
    return write_summary(run_dir, pf, results, args)


def main() -> int:
    p = argparse.ArgumentParser(description="EDAMAME FP lab: real agents, benign work, owned daemon.")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list")
    sub.add_parser("validate")
    r = sub.add_parser("run")
    r.add_argument("--lab-root", default=os.environ.get("FP_LAB_ROOT", "~/fp-lab"))
    r.add_argument("--out", default="", help="run directory (default <lab-root>/runs/<host>-<timestamp>)")
    r.add_argument("--scenarios", default="", help="CSV of scenario ids or case ids (id@agent)")
    r.add_argument("--skip", default="", help="CSV of scenario ids or case ids to skip")
    r.add_argument("--agents", default="claude_code,codex", help="agents for agent scenarios")
    r.add_argument("--warmup-secs", type=int, default=120)
    r.add_argument("--settle-secs", type=int, default=120)
    r.add_argument("--drain-secs", type=int, default=240)
    r.add_argument("--tick-every", type=int, default=30)
    r.add_argument("--agent-timeout", type=int, default=600, help="per request")
    r.add_argument("--claude-model", default="sonnet")
    r.add_argument("--codex-model", default="")
    r.add_argument("--set-adjudication", default="keep", choices=["keep", "auto", "llm", "advisory", "deterministic"])
    r.add_argument("--expect-core-version", default="")
    r.add_argument("--allow-root", action="store_true")
    r.add_argument("--allow-hub", action="store_true")
    r.add_argument("--allow-no-llm", action="store_true")
    r.add_argument("--corpus-tool", default="")
    r.add_argument("--dry-run", action="store_true", help="print the plan and exit")
    r.add_argument("--perf-interval", type=float, default=30.0,
                   help="seconds between daemon resource samples (daemon_perf)")
    r.add_argument("--perf-reference", default="",
                   help="JSON file: the released daemon's resources on this host, shown beside the run's")
    sh = sub.add_parser("shape")
    sh.add_argument("run_dir")
    sh.add_argument("--corpus-tool", default="")
    sm = sub.add_parser("summarize")
    sm.add_argument("run_dir")
    args = p.parse_args()

    if args.cmd == "list":
        for s in SCENARIOS:
            log(f"{s.id:<48} {s.kind:<6} {s.fp_class:<10} {','.join(s.platforms):<20} "
                f"{','.join(s.agents) or s.action}")
        return 0
    if args.cmd == "validate":
        try:
            types = [a["agent_type"] for a in reg.iter_agents(reg.load_registry())]
        except Exception as exc:  # noqa: BLE001
            log(f"registry unavailable: {exc}")
            types = None
        problems = validate(types)
        for prob in problems:
            log(f"problem: {prob}")
        log("catalog OK" if not problems else f"{len(problems)} problem(s)")
        return 1 if problems else 0
    if args.cmd == "shape":
        return run_cmd_shape(args)
    if args.cmd == "summarize":
        return run_cmd_summarize(args)
    return run_cmd_run(args)


if __name__ == "__main__":
    raise SystemExit(main())
