#!/usr/bin/env python3
"""
Stop all running demo injectors and remove files they created.

Reads PID files and created-file markers from the shared state directory,
terminates processes, and deletes only files that demo scripts produced.
"""

from __future__ import annotations

import argparse
import os
import platform
import signal
import sys
from pathlib import Path

from _common import (
    AGENT_TYPE_ARG_HELP,
    file_prefix_for,
    resolve_agent_type,
    state_dir_for,
    upper_prefix_for,
)

PID_FILES = [
    "blacklist_comm.pid",
    "cve_token_exfil.pid",
    "cve_sandbox.pid",
    "divergence.pid",
    "memory_poisoning.pid",
    "goal_drift.pid",
    "credential_sprawl.pid",
    "supply_chain_exfil.pid",
    "npm_rat_beacon.pid",
    "pgserve_postinstall.pid",
    "file_events.pid",
    "temp_modify.pid",
    "nonsensitive_path.pid",
]

CREATED_MARKERS = [
    "blacklist_comm.created",
    "cve_token_exfil.created",
    "cve_sandbox.created",
    "divergence.created",
    "goal_drift.created",
    "memory_poisoning.created",
    "credential_sprawl.created",
    "supply_chain_exfil.created",
    "npm_rat_beacon.created",
    "pgserve_postinstall.created",
    "file_events.created",
    "temp_modify.created",
    "nonsensitive_path.created",
]


def parse_args():
    p = argparse.ArgumentParser(description="Clean up demo trigger state.")
    p.add_argument("--agent-type", default=None, help=AGENT_TYPE_ARG_HELP)
    p.add_argument("--state-dir", type=Path, default=None)
    return p.parse_args()


def kill_from_pid_file(pid_file: Path) -> None:
    if not pid_file.exists():
        return
    try:
        pid = int(pid_file.read_text("utf-8").strip())
    except (ValueError, OSError):
        pid_file.unlink(missing_ok=True)
        return

    try:
        if platform.system() == "Windows":
            os.kill(pid, signal.SIGTERM)
        else:
            os.kill(pid, signal.SIGTERM)
        print(f"  killed pid={pid} ({pid_file.name})")
    except ProcessLookupError:
        pass
    except PermissionError:
        print(f"  cannot kill pid={pid} (permission denied)")

    pid_file.unlink(missing_ok=True)


def remove_created_files(marker: Path) -> None:
    if not marker.exists():
        return
    removed_parents: set[Path] = set()
    for line in marker.read_text("utf-8").splitlines():
        path = line.strip()
        if not path:
            continue
        target = Path(path)
        if target.exists():
            try:
                target.unlink()
                print(f"  removed {target}")
            except OSError as e:
                print(f"  cannot remove {target}: {e}")
        # Track the parent so we can prune demo-created scratch directories
        # (e.g. ``~/<pfx>_workspace_demo/``) once their files are gone.  The
        # top-level state dir is pruned once at the end of main(); do not add
        # it here or one marker can remove it while later markers are still
        # being processed.
        if target.parent != marker.parent:
            removed_parents.add(target.parent)
    marker.unlink(missing_ok=True)
    # Attempt a bottom-up rmdir on every recorded parent.  ``rmdir`` only
    # succeeds if the directory is empty, so this is safe for real user
    # directories like ``~/.ssh``; it will silently fail there.
    for parent in sorted(removed_parents, key=lambda p: len(p.parts), reverse=True):
        try:
            parent.rmdir()
            print(f"  removed empty dir {parent}")
        except OSError:
            pass


def main() -> int:
    args = parse_args()
    agent_type = resolve_agent_type(args.agent_type)
    if args.state_dir is None:
        args.state_dir = state_dir_for(agent_type)
    state_dir = args.state_dir
    if not state_dir.exists():
        print("No demo state directory found; nothing to clean up.")
        return 0

    print(f"Cleaning up demo state in {state_dir}")

    for name in PID_FILES:
        kill_from_pid_file(state_dir / name)

    for name in CREATED_MARKERS:
        remove_created_files(state_dir / name)

    # Prune any empty subdirectories left behind by triggers that stage
    # nested layouts (e.g. node_modules/pgserve/scripts/).  Walks
    # bottom-up so child dirs go first.
    for root, dirs, files in os.walk(state_dir, topdown=False):
        if root == str(state_dir):
            continue
        if not dirs and not files:
            try:
                Path(root).rmdir()
                print(f"  removed empty dir {root}")
            except OSError:
                pass

    try:
        state_dir.rmdir()
        print(f"  removed {state_dir}")
    except FileNotFoundError:
        # Another cleanup path (or a concurrent cleanup process from a retried
        # scenario) already removed it. Cleanup is idempotent; this is success.
        pass
    except OSError:
        remaining = list(state_dir.iterdir())
        if remaining:
            print(f"  state dir not empty ({len(remaining)} files remain)")

    print("Cleanup complete.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
