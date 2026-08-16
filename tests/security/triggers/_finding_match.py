"""Finding matching and alertable-severity classification for the CVE harness.

`is_alertable` mirrors `VulnerabilityFinding::is_alertable` in
`edamame_core/src/agentic/vulnerability_detector.rs`: a finding alerts only
when it is not dismissed and its severity is HIGH or CRITICAL. The CVE gate
asserts on that, not on bare finding presence, so a detection the CRS severity
path or the LLM adjudicator demoted to LOW/MEDIUM fails its scenario instead of
passing it. Presence-only assertions let a severity regression ship green while
`vulnerability-status --fail-on-findings` (which reads
`active_alertable_findings`) would have stayed silent in production.

Imported from the harness heredocs via `TRIGGERS_DIR_ENV` on `sys.path`, and
directly by `tests/security/test_finding_match.py`.
"""

from __future__ import annotations

from collections import Counter
from typing import Any, Dict, Iterable, List, Optional, Sequence

ALERTABLE_SEVERITIES = frozenset({"CRITICAL", "HIGH"})

UNKNOWN_SEVERITY = "UNKNOWN"


def normalize_severity(finding: Any) -> str:
    """Uppercase severity string, or UNKNOWN when absent/non-string."""
    if not isinstance(finding, dict):
        return UNKNOWN_SEVERITY
    severity = finding.get("severity")
    if not isinstance(severity, str) or not severity.strip():
        return UNKNOWN_SEVERITY
    return severity.strip().upper()


def is_dismissed(finding: Any) -> bool:
    """True when the finding carries an explicit truthy `dismissed`."""
    if not isinstance(finding, dict):
        return False
    return bool(finding.get("dismissed"))


def is_alertable(finding: Any) -> bool:
    """Would this finding count toward `active_alertable_findings` in production?"""
    return (
        not is_dismissed(finding)
        and normalize_severity(finding) in ALERTABLE_SEVERITIES
    )


def _marker_haystack(finding: Dict[str, Any]) -> str:
    parts: List[str] = []
    open_files = finding.get("open_files")
    if isinstance(open_files, (list, tuple)):
        parts.extend(str(p) for p in open_files)
    # Mirrors the attributed-path fields of `VulnerabilityFinding`, so a marker
    # matches whether the trigger's artifact shows up as an open file, in the
    # rendered description, or as the process / parent / script that touched it.
    for field in (
        "description",
        "subject_path",
        "process_name",
        "process_path",
        "parent_process_name",
        "parent_process_path",
        "parent_script_path",
    ):
        value = finding.get(field)
        if value:
            parts.append(str(value))
    return "\n".join(parts).lower()


def _destination_port(finding: Dict[str, Any]) -> Optional[int]:
    port = finding.get("destination_port")
    if port is None:
        return None
    try:
        return int(port)
    except (TypeError, ValueError):
        return None


def matches(
    finding: Any,
    check: str,
    markers: Sequence[str] = (),
    ports: Iterable[int] = (),
) -> bool:
    """Scenario-specific match: right check, plus a marker or port attribution.

    A scenario with neither markers nor ports matches any finding of its check
    type. Markers are matched case-insensitively as substrings.
    """
    if not isinstance(finding, dict) or finding.get("check") != check:
        return False
    lowered = [m.lower() for m in markers if m]
    port_set = set(ports)
    if not lowered and not port_set:
        return True
    if lowered:
        haystack = _marker_haystack(finding)
        if any(m in haystack for m in lowered):
            return True
    return _destination_port(finding) in port_set


def severity_histogram(findings: Iterable[Any]) -> "Counter[str]":
    return Counter(normalize_severity(f) for f in findings)


def format_histogram(counter: "Counter[str]") -> str:
    """Render a severity histogram as `CRITICAL:1,LOW:2` (empty -> `none`).

    Ordered most-severe-first so a demotion is obvious at a glance in CI logs.
    Contains no `|` so it is safe to append to the harness's pipe-delimited
    counter line.
    """
    if not counter:
        return "none"
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", UNKNOWN_SEVERITY]
    ranked = sorted(
        counter.items(),
        key=lambda kv: (order.index(kv[0]) if kv[0] in order else len(order), kv[0]),
    )
    return ",".join(f"{sev}:{count}" for sev, count in ranked)


def findings_of(report: Any) -> List[Any]:
    """Extract the `findings` list from a vulnerability report object."""
    if isinstance(report, dict):
        found = report.get("findings")
        if isinstance(found, list):
            return found
    return []


def summarize(
    findings: Iterable[Any],
    check: str,
    markers: Sequence[str] = (),
    ports: Iterable[int] = (),
) -> Dict[str, Any]:
    """Count scenario-matching findings and how many of them would alert."""
    matched = [f for f in findings if matches(f, check, markers, ports)]
    alertable = [f for f in matched if is_alertable(f)]
    return {
        "matched": len(matched),
        "alertable": len(alertable),
        "severities": severity_histogram(matched),
    }
