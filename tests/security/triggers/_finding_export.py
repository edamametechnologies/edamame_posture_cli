"""Diagnostic exports of a CVE scenario's matched findings.

`run_cve_detection.sh` saves `findings/<scenario>.export.json` per scenario:
the `export_attack_pattern_finding_details` records of its matched findings,
taken before the post-scenario `clear_attack_pattern_history` (the RPC looks
the key up in the detector history). Two steps write the document, each its
own keys, and each keeps the other's, so their order does not matter:

- `exports` (`exported_utc`, `demoted_finding_keys`, `exported`): the
  non-alertable matched findings, when the scenario ended
  `demoted_below_alertable` or an adjudicator-demotable scenario's finding is
  below alert. `count_adjudicator_demoted` reads this section
  (`_finding_match.demoted_by_adjudicator`).
- `alertable_exports` (`alertable_exported_utc`, `alertable_finding_keys`,
  `alertable_exported`): up to `--export-matched` alertable matched findings,
  newest first. Each export carries `details.finding_input_slice`, the
  detector's own input for that finding, which
  `edamame_core/tools/attack_corpus_from_gate.py` shapes into a replayable
  attack-corpus envelope.

An alertable export is saved slimmed (`slim_export`): a long LLM prompt or
raw answer is replaced by its length (the prompt carries the whole tick's
telemetry and dominates the size), and the debug trace keeps only this
finding's input slice. What a replay needs stays: `finding`,
`finding_input_slice`, `finding_input_slice_source`, `grading_evidence`,
`evaluated_at`, `captured_at`, `core_version`, `platform`, and the trace's
`raw_findings` and `llm_decision`.

`findings/<scenario>.meta.json` (`scenario_meta`) records what the runner
asserted for the scenario (expected check, markers, ports, expected tier), so
offline consumers read the runner's own table instead of a copy of it.

`findings/<scenario>.miss.json` (`miss_document`) is saved when a scenario
ends `fail`: the daemon's file events (`get_file_events`, newest first,
bounded), the detector status, the latest report and that report's debug
trace without the tick's prompt, raw answer and input slices
(`slim_miss_trace`). A miss then reads as "no events reached the detector"
(empty events, no raw findings) or "graded, then withheld" (raw findings
with an `llm_error` or a non-KEEP decision) instead of a bare counter.
Command lines (`cmd`, `argv`, ... `redact_command_lines`) are replaced by
their length: a CI runner's argv can carry its tokens.

Imported from the harness heredocs via `TRIGGERS_DIR_ENV` on `sys.path`, and
directly by `tests/security/test_finding_export.py`.
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import re
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from _finding_match import is_alertable

# Longer LLM text in a saved trace is replaced by its length.
MAX_TRACE_TEXT_CHARS = 4000

ALERTABLE_EXPORTS_KEY = "alertable_exports"
DEMOTED_EXPORTS_KEY = "exports"

# Bounds of the miss document: file events kept (newest first), sensitive
# events kept, findings kept per list (the latest report's, the trace's raw
# and final ones). A few hundred events and a hundred findings with their
# evidence packets stay around a megabyte.
MISS_FILE_EVENTS = 200
MISS_SENSITIVE_EVENTS = 100
MISS_FINDINGS = 50

# Keys whose values are command lines: exact names, and suffixes
# (`parent_cmd`, `grandparent_cmd`, ...).
COMMAND_LINE_KEYS = ("cmd", "argv", "args", "cmdline", "command_line")
COMMAND_LINE_KEY_SUFFIXES = ("_cmd", "_argv", "_cmdline", "_command_line")

_RFC3339 = re.compile(
    r"^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:?\d{2})?$"
)


def utc_seconds(value: Any) -> Optional[float]:
    """Epoch seconds of an RFC 3339 timestamp (chrono writes up to nine
    fractional digits, which `datetime.fromisoformat` does not take before
    Python 3.11), or None."""
    if not isinstance(value, str):
        return None
    m = _RFC3339.match(value.strip())
    if not m:
        return None
    day, clock, fraction, zone = m.groups()
    try:
        at = _dt.datetime.strptime(f"{day}T{clock}", "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        return None
    offset = 0
    if zone and zone != "Z":
        sign = -1 if zone[0] == "-" else 1
        digits = zone[1:].replace(":", "")
        offset = sign * (int(digits[:2]) * 3600 + int(digits[2:4]) * 60)
    seconds = at.replace(tzinfo=_dt.timezone.utc).timestamp() - offset
    if fraction:
        seconds += float("0." + fraction)
    return seconds


def matched_findings(evidence: Any) -> List[Any]:
    """The matched findings of a `findings/<scenario>.json` evidence dump:
    the current report's, then the history's (newest report first)."""
    if not isinstance(evidence, dict):
        return []
    return list(evidence.get("current") or []) + list(evidence.get("history") or [])


def alertable_by_key(matched: Sequence[Any]) -> List[Tuple[str, Dict[str, Any]]]:
    """Distinct alertable matched findings that carry a `finding_key` (the
    export RPC needs one), newest first.

    Newest is the latest `first_detected` (set on every finding read back
    from history); findings without it follow the dated ones in their input
    order, which is already the current report first, then history newest
    first. A key seen twice (the current report and a history entry) keeps
    its first occurrence."""
    first: Dict[str, Tuple[int, Dict[str, Any]]] = {}
    for idx, finding in enumerate(matched):
        if not isinstance(finding, dict) or not is_alertable(finding):
            continue
        key = str(finding.get("finding_key") or "").strip()
        if key and key not in first:
            first[key] = (idx, finding)
    dated = []
    undated = []
    for key, (idx, finding) in first.items():
        at = utc_seconds(finding.get("first_detected"))
        if at is None:
            undated.append((idx, key, finding))
        else:
            dated.append((-at, idx, key, finding))
    dated.sort(key=lambda row: (row[0], row[1]))
    undated.sort(key=lambda row: row[0])
    return [(key, finding) for _, _, key, finding in dated] + [
        (key, finding) for _, key, finding in undated
    ]


def export_request_args(finding_key: str) -> str:
    """The RPC takes one String argument, `request_json`, itself a JSON
    document: `{"finding_key": "<key>"}`."""
    return json.dumps({"request_json": json.dumps({"finding_key": finding_key})})


def slim_export(
    response: Any, finding_key: str, max_text_chars: int = MAX_TRACE_TEXT_CHARS
) -> Tuple[Any, Dict[str, int]]:
    """A copy of one export response bounded for the artifact, and what was
    removed. The input is not modified; a response without `details` (a
    failed export) comes back unchanged."""
    if not isinstance(response, dict):
        return response, {}
    out = json.loads(json.dumps(response, default=str))
    details = out.get("details")
    trace = details.get("debug_trace") if isinstance(details, dict) else None
    if not isinstance(trace, dict):
        return out, {}
    removed: Dict[str, int] = {}
    for field in ("llm_prompt", "llm_raw_answer"):
        text = trace.get(field)
        if isinstance(text, str) and len(text) > max_text_chars:
            trace[field] = f"[{len(text)} chars removed by the CVE harness]"
            removed[f"{field}_chars"] = len(text)
    slices = trace.get("input_slices")
    if isinstance(slices, list):
        own = [
            s for s in slices
            if isinstance(s, dict) and str(s.get("finding_key") or "").strip() == finding_key
        ]
        if len(own) != len(slices):
            removed["input_slices_dropped"] = len(slices) - len(own)
            trace["input_slices"] = own
    return out, removed


def export_entry(
    finding_key: str, severity: str, response: Any, max_text_chars: int = MAX_TRACE_TEXT_CHARS
) -> Dict[str, Any]:
    """One `alertable_exports` entry: the slimmed export and what slimming removed."""
    slimmed, removed = slim_export(response, finding_key, max_text_chars)
    entry: Dict[str, Any] = {"finding_key": finding_key, "severity": severity, "export": slimmed}
    if removed:
        entry["slimmed"] = removed
    return entry


def export_succeeded(entry: Any) -> bool:
    export = entry.get("export") if isinstance(entry, dict) else None
    return isinstance(export, dict) and bool(export.get("success"))


def write_json(path: str, data: Any) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, default=str)
        fh.write("\n")


def update_export_document(
    path: str, scenario: str, check: Optional[str], section: Dict[str, Any]
) -> Dict[str, Any]:
    """Write `section` into the scenario's export document and keep every
    other key already there (the other writer's section). An unreadable
    document is replaced."""
    doc: Dict[str, Any] = {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            loaded = json.load(fh)
        if isinstance(loaded, dict):
            doc = loaded
    except (OSError, ValueError):
        pass
    doc["scenario"] = scenario
    if check is not None or "check" not in doc:
        doc["check"] = check
    doc.update(section)
    write_json(path, doc)
    return doc


def scenario_meta(
    scenario: str,
    expected_check: str,
    markers: Iterable[str],
    ports: Iterable[int],
    expected_severity: str,
    requires_alert: bool,
    alertable_export_limit: int,
) -> Dict[str, Any]:
    """`findings/<scenario>.meta.json`: what the runner asserts for a scenario."""
    return {
        "scenario": scenario,
        "expected_check": expected_check,
        "markers": list(markers),
        "ports": sorted(int(p) for p in ports),
        "expected_severity": (expected_severity or "").strip().upper() or None,
        "requires_alert": bool(requires_alert),
        "alertable_export_limit": int(alertable_export_limit),
    }


def is_command_line_key(key: Any) -> bool:
    name = str(key).lower()
    return name in COMMAND_LINE_KEYS or name.endswith(COMMAND_LINE_KEY_SUFFIXES)


def redact_command_lines(value: Any) -> Any:
    """A copy of `value` with every command-line field (`is_command_line_key`)
    replaced by its length, at any depth. The input is not modified."""
    if isinstance(value, dict):
        out: Dict[Any, Any] = {}
        for key, item in value.items():
            if is_command_line_key(key) and item is not None:
                if isinstance(item, (list, tuple)):
                    out[key] = f"[redacted: {len(item)} items]"
                else:
                    out[key] = f"[redacted: {len(str(item))} chars]"
            else:
                out[key] = redact_command_lines(item)
        return out
    if isinstance(value, list):
        return [redact_command_lines(item) for item in value]
    return value


def _cap(items: Any, limit: int, removed: Dict[str, int], label: str) -> Any:
    if isinstance(items, list) and len(items) > limit:
        removed[f"{label}_dropped"] = len(items) - limit
        return items[:limit]
    return items


def slim_miss_trace(trace: Any, max_findings: int = MISS_FINDINGS) -> Any:
    """A copy of one tick's debug trace bounded for the miss document: the
    prompt and the raw answer are replaced by their length whatever their size
    (the prompt carries the whole tick's telemetry), the input slices are
    dropped (their count stays), the finding lists are capped. What a miss
    diagnosis reads stays: `raw_findings`, `final_findings`, `llm_decision`,
    `llm_error`, `suppressed_checks`, `alert_decision`, `evaluated_at`. A
    value that is not a trace comes back unchanged."""
    if not isinstance(trace, dict):
        return trace
    out = json.loads(json.dumps(trace, default=str))
    removed: Dict[str, int] = {}
    for field in ("llm_prompt", "llm_raw_answer"):
        text = out.get(field)
        if isinstance(text, str):
            out[field] = f"[{len(text)} chars removed by the CVE harness]"
            removed[f"{field}_chars"] = len(text)
    slices = out.get("input_slices")
    if isinstance(slices, list):
        removed["input_slices_dropped"] = len(slices)
        out["input_slices"] = []
    for field in ("raw_findings", "final_findings"):
        out[field] = _cap(out.get(field), max_findings, removed, field)
    if removed:
        out["slimmed"] = removed
    return out


def _newest_first(events: Any) -> List[Any]:
    """File events by `timestamp`, newest first; undated ones last, in their
    input order."""
    if not isinstance(events, list):
        return []
    dated = []
    undated = []
    for idx, event in enumerate(events):
        at = utc_seconds(event.get("timestamp")) if isinstance(event, dict) else None
        if at is None:
            undated.append((idx, event))
        else:
            dated.append((-at, idx, event))
    dated.sort(key=lambda row: (row[0], row[1]))
    return [event for _, _, event in dated] + [event for _, event in undated]


def miss_document(
    scenario: str,
    check: Optional[str],
    attempts: int,
    note: str,
    detector_status: Any,
    file_events: Any,
    latest_report: Any,
    report_id: Optional[str],
    trace: Any,
    errors: Dict[str, Optional[str]],
) -> Dict[str, Any]:
    """`findings/<scenario>.miss.json`: what the daemon held when a scenario
    ended without its alertable finding. `file_events` is the `get_file_events`
    snapshot (a `FimSnapshotAPI` object), `latest_report` the current report,
    `trace` that report's debug trace; each may be None (not answered) with
    the reason in `errors`. Bounded (`MISS_*`) and command lines redacted."""
    removed: Dict[str, int] = {}
    fim: Dict[str, Any]
    if isinstance(file_events, dict):
        events = _newest_first(file_events.get("events"))
        sensitive = _newest_first(file_events.get("sensitive_events"))
        fim = {
            key: file_events.get(key)
            for key in ("is_monitoring", "watch_paths", "event_count", "last_event_time", "has_suspicious_events")
        }
        fim["events_total"] = len(events)
        fim["events"] = _cap(events, MISS_FILE_EVENTS, removed, "events")
        fim["sensitive_events_total"] = len(sensitive)
        fim["sensitive_events"] = _cap(sensitive, MISS_SENSITIVE_EVENTS, removed, "sensitive_events")
    else:
        fim = {"snapshot": file_events}
    report: Any = latest_report
    if isinstance(latest_report, dict):
        report = {key: value for key, value in latest_report.items() if key != "trace"}
        findings = latest_report.get("findings")
        report["findings_total"] = len(findings) if isinstance(findings, list) else None
        report["findings"] = _cap(findings, MISS_FINDINGS, removed, "report_findings")
    doc: Dict[str, Any] = {
        "scenario": scenario,
        "check": check,
        "captured_utc": _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "attempts": int(attempts),
        "note": note,
        "detector_status": detector_status,
        "file_events": fim,
        "latest_report": report,
        "report_id": report_id,
        "trace": slim_miss_trace(trace),
        "errors": {key: value for key, value in errors.items() if value},
    }
    if removed:
        doc["slimmed"] = removed
    return redact_command_lines(doc)
