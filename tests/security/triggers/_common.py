"""
Shared constants and helpers for parameterized E2E trigger scripts.

Each trigger accepts --agent-type (optional; defaults to
``DEFAULT_AGENT_TYPE`` or the ``EDAMAME_AGENT_TYPE`` env var) to derive
STATE_DIR and file-name prefixes. This module centralizes that logic so
individual triggers stay focused on their detection scenario.
"""

from __future__ import annotations

import os
import platform
import shutil
from pathlib import Path

VALID_AGENT_TYPES = ("openclaw", "cursor", "claude_code", "claude_desktop", "codex", "hermes")
DEFAULT_AGENT_TYPE = "openclaw"

# Canonical help string for every trigger's --agent-type flag. Centralized so
# the optionality, the default, and the env-var fallback stay consistent.
AGENT_TYPE_ARG_HELP = (
    "Optional. Agent identity for state dir / file prefixes. "
    f"One of: {'|'.join(VALID_AGENT_TYPES)}. "
    f"Defaults to '{DEFAULT_AGENT_TYPE}' (override via EDAMAME_AGENT_TYPE env var)."
)


def resolve_agent_type(cli_value: str | None) -> str:
    raw = (cli_value or "").strip() or os.environ.get("EDAMAME_AGENT_TYPE", "").strip()
    agent_type = raw or DEFAULT_AGENT_TYPE
    if agent_type not in VALID_AGENT_TYPES:
        raise SystemExit(
            f"Invalid agent type '{agent_type}'. "
            f"Valid: {', '.join(VALID_AGENT_TYPES)}"
        )
    return agent_type


def state_dir_for(agent_type: str) -> Path:
    name = f"edamame_{agent_type}_demo"
    if platform.system() == "Windows":
        return Path(os.environ.get("TEMP", "C:\\Temp")) / name
    return Path(f"/tmp/{name}")


def file_prefix_for(agent_type: str) -> str:
    return f"demo_{agent_type}"


def upper_prefix_for(agent_type: str) -> str:
    return f"DEMO_{agent_type.upper()}"


BACKUP_DIR_NAME = "canonical_backups"


def _append_marker_line(marker: Path, line: str) -> None:
    existing = set()
    if marker.exists():
        existing = {
            entry.strip()
            for entry in marker.read_text("utf-8").splitlines()
            if entry.strip()
        }
    existing.add(line)
    marker.write_text("\n".join(sorted(existing)) + "\n", encoding="utf-8")


def claim_canonical_path(
    path: Path,
    state_dir: Path,
    created_marker: str,
    restore_marker: str,
) -> Path:
    """Take over a canonical config path without destroying a real copy.

    Some triggers cannot use a prefixed filename: the shipped
    `is_sensitive_path` patterns for `mcp.json`, `credentials.json` and the
    agent control configs are file-specific, so `demo_openclaw_mcp.json`
    classifies as nothing and the scenario tests nothing. Writing the
    canonical name means a trigger run on a developer workstation overwrites
    that developer's real configuration.

    Copy the original into the state dir and record `<original>\\t<backup>` in
    `restore_marker` so `cleanup.py` puts it back byte for byte. When there is
    no original, record the path in `created_marker` instead so cleanup
    deletes what the trigger made. Either way the host ends up as it started.
    """
    path = path.expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        _append_marker_line(state_dir / created_marker, str(path))
        return path

    backup_dir = state_dir / BACKUP_DIR_NAME
    backup_dir.mkdir(parents=True, exist_ok=True)
    flattened = str(path).replace("\\", "/").strip("/").replace("/", "__")
    backup = backup_dir / flattened
    if not backup.exists():
        # First claim wins: a trigger that re-claims the same path across
        # rounds must not overwrite the pristine copy with its own payload.
        shutil.copy2(path, backup)
    _append_marker_line(state_dir / restore_marker, f"{path}\t{backup}")
    return path
