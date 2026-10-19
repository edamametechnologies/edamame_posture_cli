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
import shutil
import signal
import subprocess
import sys
from pathlib import Path

from _common import (
    AGENT_TYPE_ARG_HELP,
    VALID_AGENT_TYPES,
    file_prefix_for,
    is_catalog_creatable_target,
    pid_file_is_trustworthy,
    read_trigger_manifest,
    regular_file_sha256,
    resolve_agent_type,
    state_dir_for,
    state_dir_is_safe,
    upper_prefix_for,
)
from _common import _within as _path_within

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
    "agent_config_tamper.pid",
    "agent_cred_harvest.pid",
    "agent_denylist_bypass.pid",
    "dns_tunnel.pid",
    "dns_tunnel_reconnect.pid",
    "ntp_tunnel.pid",
    "process_memory_scrape.pid",
    "package_install_lifecycle.pid",
    # loopback_relay spawns two siblings from a shared interpreter; kill the
    # orchestrator last so it does not respawn a child mid-cleanup.
    "loopback_relay_b.pid",
    "loopback_relay_a.pid",
    "loopback_relay.pid",
    # The stand-in daemon forwards SIGTERM to its egress child, so killing
    # this one pid stops both halves of the lineage.
    "daemon_lineage_egress.pid",
    "agent_rules_backdoor.pid",
    "sneakpeek.pid",
    "credential_courier.pid",
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
    "temp_modify.created",
    "nonsensitive_path.created",
    "sneakpeek.created",
    "credential_courier.created",
    "agent_config_tamper.created",
    "agent_cred_harvest.created",
    "agent_denylist_bypass.created",
    "dns_tunnel.created",
    "dns_tunnel_reconnect.created",
    "ntp_tunnel.created",
    "process_memory_scrape.created",
    "package_install_lifecycle.created",
    "loopback_relay.created",
    # Records a path OUTSIDE the state dir (the stand-in daemon installed into
    # /usr/sbin), which is why _PROTECTED_PARENTS below exists.
    "daemon_lineage_egress.created",
    "agent_rules_backdoor.created",
]

# Content-hashed manifests written by `_common.TriggerFileManifest`: a recorded
# file is removed only while it still holds the bytes the trigger wrote.
TRIGGER_MANIFESTS = [
    "file_events.manifest.json",
]

# Plain path lists written by trigger versions that predate their manifest.
# With no hash there is no telling whether a listed file still holds the
# trigger's bytes, so cleanup reports the paths and deletes none of them.
LEGACY_UNHASHED_MARKERS = [
    "file_events.created",
]

# Markers written by `_common.claim_canonical_path` for triggers that must use
# a canonical config filename (the shipped sensitive-path patterns for those
# are file-specific). Each line is `<original>\t<backup>`; restoring copies the
# backup back over the original. Processed BEFORE the created-file markers so a
# path can never be both restored and deleted in one run.
RESTORE_MARKERS = [
    "agent_config_tamper.restored",
    "agent_cred_harvest.restored",
]

# Directories that must never be rmdir'd even when a marker records a file
# inside them. `remove_created_files` prunes the parent of every removed file
# so triggers that stage nested scratch layouts leave nothing behind, but
# daemon_lineage_egress installs into a real system directory. `rmdir` only
# succeeds on an empty directory so this is belt-and-braces, not a live bug --
# and a cleanup script running as root should not be one empty directory away
# from removing /usr/sbin.
_PROTECTED_PARENTS = {
    Path(p)
    for p in (
        "/usr/sbin",
        "/usr/bin",
        "/usr/local/bin",
        "/usr/local/sbin",
        "/sbin",
        "/bin",
        "/opt/homebrew/bin",
        "/tmp",
        "/var/tmp",
    )
}


def parse_args():
    p = argparse.ArgumentParser(description="Clean up demo trigger state.")
    p.add_argument("--agent-type", default=None, help=AGENT_TYPE_ARG_HELP)
    p.add_argument("--state-dir", type=Path, default=None)
    p.add_argument(
        "--sweep",
        action="store_true",
        help="Also remove demo-prefixed files the catalog creates in your home "
             "config folders, even when the state directory is gone (e.g. a "
             "temporary directory that was cleared at reboot).",
    )
    return p.parse_args()


def kill_from_pid_file(pid_file: Path) -> None:
    if not pid_file.exists():
        return
    try:
        pid = int(pid_file.read_text("utf-8").splitlines()[0].strip())
    except (ValueError, IndexError, OSError):
        pid_file.unlink(missing_ok=True)
        return

    # A pid is reused after a reboot (and, rarely, within one). Do not signal a
    # process this cleanup did not start: if the pid file predates the current
    # boot, or the live process started after the file was written, the pid is
    # not the one the trigger recorded. Drop the stale file and move on.
    if not pid_file_is_trustworthy(pid, pid_file):
        print(f"  skipped pid={pid} ({pid_file.name}): not the process that wrote this "
              f"file (stale after reboot or pid reused); removed the stale pid file")
        pid_file.unlink(missing_ok=True)
        return

    # One trigger that cannot be killed must never abort the rest of cleanup:
    # every pid file and every created-file marker after it would be left in
    # place. On Windows `os.kill` is OpenProcess+TerminateProcess on that one
    # PID (no tree semantics) and reports a stale/foreign PID as a bare
    # OSError (WinError 87), which escaped the two handlers below and stopped
    # cleanup mid-run on the security gate's Windows leg; eight earlier
    # triggers were still alive an hour later (posture run 34033187381).
    # `taskkill /T /F` ends the whole tree and fails softly, matching what
    # run_scenario.sh already uses on Windows.
    try:
        if platform.system() == "Windows":
            result = subprocess.run(
                ["taskkill", "/PID", str(pid), "/T", "/F"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
            )
            if result.returncode == 0:
                print(f"  killed pid={pid} tree ({pid_file.name})")
            else:
                detail = (result.stderr or result.stdout or "").strip().replace("\n", " ")
                print(f"  could not kill pid={pid} ({pid_file.name}): {detail}")
        else:
            # Some triggers (cve_sandbox_escape, npm_rat_beacon) launch their
            # real payload through a wrapper started with start_new_session, so
            # the recorded pid leads its own process group. Kill the whole group
            # when that is the case -- signalling just the leader would orphan
            # the compiled probe / stage-2 beacon it spawned. Fall back to a
            # single-pid kill for ordinary triggers, and never kill a group this
            # process is a member of (that would signal the cleanup run itself).
            try:
                pgid = os.getpgid(pid)
            except ProcessLookupError:
                pgid = None
            if pgid == pid and pgid != os.getpgrp():
                os.killpg(pgid, signal.SIGTERM)
                print(f"  killed pgid={pgid} ({pid_file.name})")
            else:
                os.kill(pid, signal.SIGTERM)
                print(f"  killed pid={pid} ({pid_file.name})")
    except ProcessLookupError:
        pass
    except PermissionError:
        print(f"  cannot kill pid={pid} (permission denied)")
    except OSError as exc:
        print(f"  could not kill pid={pid} ({pid_file.name}): {exc}")

    pid_file.unlink(missing_ok=True)


def restore_backups(marker: Path) -> None:
    if not marker.exists():
        return
    state_dir = marker.parent
    for line in marker.read_text("utf-8").splitlines():
        entry = line.strip()
        if not entry or "\t" not in entry:
            continue
        original_raw, backup_raw = entry.split("\t", 1)
        original = Path(original_raw.strip())
        backup = Path(backup_raw.strip())
        # Only restore over a path a scenario could have taken over, and only
        # from a backup kept inside the state directory. Anything else in the
        # marker is left untouched and reported.
        if not is_catalog_creatable_target(original, state_dir):
            print(f"  left {original}: not a path a scenario creates; not restoring over it")
            continue
        if not _path_within(backup, state_dir):
            print(f"  left {original}: its recorded backup {backup} is not inside the state dir")
            continue
        if not backup.exists():
            # Nothing to put back. Leaving the trigger's payload in place
            # would be worse than removing it: the payload is a rogue MCP
            # entry or a weakened sandbox setting.
            try:
                original.unlink(missing_ok=True)
                print(f"  backup missing; removed trigger payload {original}")
            except OSError as exc:
                print(f"  cannot remove {original}: {exc}")
            continue
        try:
            original.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(backup, original)
            backup.unlink(missing_ok=True)
            print(f"  restored {original}")
        except OSError as exc:
            print(f"  cannot restore {original}: {exc}")
    marker.unlink(missing_ok=True)


def remove_created_files(marker: Path) -> None:
    if not marker.exists():
        return
    state_dir = marker.parent
    removed_parents: set[Path] = set()
    for line in marker.read_text("utf-8").splitlines():
        path = line.strip()
        if not path:
            continue
        target = Path(path)
        # Only delete something a catalog scenario could have created (inside
        # the state dir, a demo-prefixed name, or one of the canonical agent
        # paths the triggers write). A marker listing anything else is left
        # alone and reported.
        if not is_catalog_creatable_target(target, state_dir):
            print(f"  left {target}: not a path a scenario creates; not removing it")
            continue
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
        if target.parent != marker.parent and target.parent not in _PROTECTED_PARENTS:
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


def remove_manifest_files(manifest: Path) -> None:
    """Remove what a trigger recorded in its content-hashed manifest.

    A file goes only while it still hashes to the recorded value; anything
    else (changed content, replaced by a symlink or directory, unreadable) is
    left in place and reported. Directories the trigger created go when empty.
    """
    try:
        files, dirs = read_trigger_manifest(manifest)
    except FileNotFoundError:
        return
    except (OSError, ValueError) as exc:
        print(f"  cannot read {manifest} ({exc}); removed nothing it lists and kept it")
        return
    for path, recorded in sorted(files.items()):
        target = Path(path)
        try:
            current = regular_file_sha256(target)
        except FileNotFoundError:
            continue
        except OSError as exc:
            print(f"  left {target}: cannot verify it is the file the trigger wrote ({exc})")
            continue
        if current != recorded:
            print(f"  left {target}: its content changed since the trigger wrote it")
            continue
        try:
            target.unlink()
            print(f"  removed {target}")
        except OSError as exc:
            print(f"  cannot remove {target}: {exc}")
    for directory in sorted({Path(d) for d in dirs}, key=lambda p: len(p.parts), reverse=True):
        if directory in _PROTECTED_PARENTS:
            continue
        try:
            directory.rmdir()
            print(f"  removed empty dir {directory}")
        except FileNotFoundError:
            pass
        except OSError as exc:
            print(f"  left dir {directory}: {exc.strerror or exc}")
    manifest.unlink(missing_ok=True)


def report_legacy_marker(marker: Path) -> None:
    if not marker.exists():
        return
    for line in marker.read_text("utf-8").splitlines():
        path = line.strip()
        if path and os.path.lexists(path):
            print(f"  left {path}: listed by an older trigger without a content hash; remove it by hand if it is a test fixture")
    marker.unlink(missing_ok=True)


# Home-config folders where the catalog writes demo-prefixed decoy files. The
# --sweep fallback removes only demo-prefixed names here, so it cannot touch a
# user's real credentials.
_SWEEP_HOME_SUBDIRS = (
    ".ssh", ".aws", ".gnupg", ".kube", ".azure", ".docker",
    ".config/gcloud", ".config/solana", ".ethereum/keystore", ".bitcoin",
    ".cursor/rules",
)


def sweep_demo_artifacts(state_dir: Path) -> None:
    """Remove demo-prefixed files the catalog creates in the user's home,
    independent of the markers. The fallback for when the state directory (and
    its markers) is gone -- e.g. a temp dir cleared at reboot -- while the decoy
    files it caused in the home folders remain. Only ever removes catalog
    targets (``is_catalog_creatable_target``)."""
    print("  sweeping demo-prefixed files in home config folders")
    home = Path.home()

    def _remove(target: Path) -> None:
        if not os.path.lexists(str(target)):
            return
        if not is_catalog_creatable_target(target, state_dir):
            return
        try:
            if target.is_dir() and not target.is_symlink():
                shutil.rmtree(target)
            else:
                target.unlink()
            print(f"  removed {target}")
        except OSError as exc:
            print(f"  cannot remove {target}: {exc}")

    for agent in VALID_AGENT_TYPES:
        pfx = file_prefix_for(agent)
        upfx = upper_prefix_for(agent)
        for sub in _SWEEP_HOME_SUBDIRS:
            d = home / sub
            if not d.is_dir():
                continue
            for pattern in (f"{pfx}*", f"{upfx}*"):
                for match in sorted(d.glob(pattern)):
                    _remove(match)
        # Home-root decoys and demo workspaces/config dirs.
        for pattern in (f".env_{pfx}*", f".npmrc_{pfx}*", f".netrc_{pfx}*",
                        f".{pfx}_*", f"{pfx}_*"):
            for match in sorted(home.glob(pattern)):
                _remove(match)

    # The per-run Claude transcript probe (not demo-prefixed, but catalog-owned).
    _remove(home / ".claude" / "projects" / "edamame-denylist-bypass-probe")


def main() -> int:
    args = parse_args()
    agent_type = resolve_agent_type(args.agent_type)
    if args.state_dir is None:
        args.state_dir = state_dir_for(agent_type)
    state_dir = args.state_dir
    if not state_dir.exists():
        print("No demo state directory found.")
        if args.sweep:
            sweep_demo_artifacts(state_dir)
        else:
            print("Nothing to clean up (pass --sweep to also remove demo files left in your home folders).")
        print("Cleanup complete.")
        return 0

    ok, reason = state_dir_is_safe(state_dir)
    if not ok:
        print(f"  cannot clean up {state_dir}: {reason}; left it untouched. Remove it by hand after checking what it is.")
        if args.sweep:
            sweep_demo_artifacts(state_dir)
        print("Cleanup complete.")
        return 0

    print(f"Cleaning up demo state in {state_dir}")

    for name in PID_FILES:
        kill_from_pid_file(state_dir / name)

    for name in RESTORE_MARKERS:
        restore_backups(state_dir / name)

    for name in CREATED_MARKERS:
        remove_created_files(state_dir / name)

    for name in TRIGGER_MANIFESTS:
        remove_manifest_files(state_dir / name)
        # Left by a trigger killed between writing and renaming its manifest.
        remove_manifest_files(state_dir / f"{name}.tmp")

    for name in LEGACY_UNHASHED_MARKERS:
        report_legacy_marker(state_dir / name)

    if args.sweep:
        sweep_demo_artifacts(state_dir)

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
