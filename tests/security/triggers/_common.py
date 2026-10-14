"""
Shared constants and helpers for parameterized E2E trigger scripts.

Each trigger accepts --agent-type (optional; defaults to
``DEFAULT_AGENT_TYPE`` or the ``EDAMAME_AGENT_TYPE`` env var) to derive
STATE_DIR and file-name prefixes. This module centralizes that logic so
individual triggers stay focused on their detection scenario.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import stat
import subprocess
import time
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
    # The working directory is kept under the OS temp root on purpose: two
    # scenarios assert on a writer/parent executable path that matches the
    # detector's temp-dir patterns ("/tmp/", "\\Temp\\"), so moving it off the
    # temp root would change what those scenarios detect. On POSIX /tmp is
    # shared between users, so the leaf carries the owner's id and
    # `prepare_state_dir` refuses a symlinked or foreign-owned directory; on
    # Windows %TEMP% is already per-user.
    if platform.system() == "Windows":
        return Path(os.environ.get("TEMP", "C:\\Temp")) / f"edamame_{agent_type}_demo"
    return Path(f"/tmp/edamame_{agent_type}_demo_{os.geteuid()}")


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


# --- Content-hashed manifest of trigger-created files -----------------------
#
# A trigger that writes fixtures into real user directories (~/.ssh, ~/.aws,
# $HOME) must never truncate a file it did not create, and cleanup must never
# delete one. `TriggerFileManifest` creates each file with O_EXCL, records the
# sha256 of the bytes it wrote, rewrites a file only while the file still holds
# exactly those bytes, and records the directories it had to create.
# cleanup.py's `remove_manifest_files` deletes a recorded file only when its
# content still hashes to the recorded value and leaves (and reports) anything
# else.

MANIFEST_VERSION = 1

# O_BINARY keeps Windows from translating newlines inside os.write, so the bytes
# on disk are the bytes hashed. O_NOFOLLOW refuses a symlink planted at the
# path, O_NONBLOCK keeps the open of a FIFO planted there from blocking. All are
# no-ops for a regular file and absent where the platform has no such flag.
_O_BINARY = getattr(os, "O_BINARY", 0)
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def regular_file_sha256(path: Path) -> str:
    """sha256 of the regular file at `path`, without following a symlink.

    Raises FileNotFoundError when nothing is at `path`, and OSError when it is
    not a regular file (symlink, directory, FIFO, ...) or cannot be read.
    """
    if not stat.S_ISREG(os.lstat(path).st_mode):
        raise OSError(f"not a regular file: {path}")
    fd = os.open(str(path), os.O_RDONLY | _O_BINARY | _O_NOFOLLOW | _O_NONBLOCK)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(f"not a regular file: {path}")
        digest = hashlib.sha256()
        while True:
            chunk = os.read(fd, 1 << 16)
            if not chunk:
                break
            digest.update(chunk)
    finally:
        os.close(fd)
    return digest.hexdigest()


def read_trigger_manifest(manifest: Path) -> tuple[dict[str, str], list[str]]:
    """Return (files: path -> sha256, dirs) recorded in `manifest`.

    Raises FileNotFoundError when there is no manifest and ValueError when it
    does not parse as one.
    """
    raw = json.loads(manifest.read_text("utf-8"))
    if (
        not isinstance(raw, dict)
        or not isinstance(raw.get("files"), dict)
        or not isinstance(raw.get("dirs"), list)
    ):
        raise ValueError(f"not a trigger manifest: {manifest}")
    files = {str(path): digest for path, digest in raw["files"].items() if isinstance(digest, str)}
    dirs = [str(d) for d in raw["dirs"]]
    return files, dirs


def _apply_mode(fd: int, path: Path, mode: int | None) -> None:
    if mode is None:
        return
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(fd, mode)
        else:
            os.chmod(path, mode)
    except OSError:
        pass


class TriggerFileManifest:
    """The files (and directories) a trigger created, with content hashes.

    Entries left by an earlier run of the same trigger are loaded, so a file
    that run wrote and nobody changed since is still the trigger's to rewrite
    and cleanup's to remove.
    """

    def __init__(self, manifest: Path) -> None:
        self.manifest = manifest
        self.files: dict[str, str] = {}
        self.dirs: list[str] = []
        self.refused: dict[str, str] = {}
        try:
            self.files, self.dirs = read_trigger_manifest(manifest)
        except FileNotFoundError:
            pass
        except (OSError, ValueError) as exc:
            # Overwriting it would forget what an earlier run created, and
            # cleanup could then never remove those files.
            raise SystemExit(
                f"cannot read the trigger manifest {manifest} ({exc}); "
                "inspect it and the files it lists, then remove it"
            )

    def save(self) -> None:
        payload = {
            "version": MANIFEST_VERSION,
            "files": dict(sorted(self.files.items())),
            "dirs": self.dirs,
        }
        tmp = self.manifest.with_name(self.manifest.name + ".tmp")
        tmp.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        os.replace(tmp, self.manifest)

    def _refuse(self, path: str, reason: str) -> bool:
        if path not in self.refused:
            self.refused[path] = reason
            print(f"  REFUSED {path}: {reason}; left untouched", flush=True)
        return False

    def _make_parents(self, path: Path) -> None:
        missing = []
        parent = path.parent
        while not os.path.lexists(parent) and parent.parent != parent:
            missing.append(parent)
            parent = parent.parent
        created = False
        for directory in reversed(missing):
            try:
                directory.mkdir()
            except FileExistsError:
                continue
            if str(directory) not in self.dirs:
                self.dirs.append(str(directory))
                created = True
        if created:
            self.save()

    def write(self, path: Path, data: bytes, mode: int | None = None) -> bool:
        """Write `data` to `path` and record its hash; True when written.

        A new file is created with O_EXCL. An existing one is rewritten only
        when this manifest recorded it and it still holds exactly the recorded
        bytes; any other existing path is refused (reported once) and left as
        it is. `mode` is applied after the write (None leaves it alone).
        """
        key = str(path)
        if key in self.refused:
            return False
        self._make_parents(path)
        try:
            fd = os.open(key, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_BINARY, 0o666 if mode is None else mode)
        except FileExistsError:
            return self._rewrite_owned(path, data, mode)
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
                _apply_mode(fh.fileno(), path, mode)
        except BaseException:
            # Created a moment ago by this call: leave no partial, unrecorded file.
            try:
                os.unlink(key)
            except OSError:
                pass
            raise
        self.files[key] = sha256_hex(data)
        self.save()
        return True

    def _rewrite_owned(self, path: Path, data: bytes, mode: int | None) -> bool:
        key = str(path)
        recorded = self.files.get(key)
        if recorded is None:
            return self._refuse(key, "it already exists and this trigger did not create it")
        try:
            fd = os.open(key, os.O_RDWR | _O_BINARY | _O_NOFOLLOW | _O_NONBLOCK)
        except OSError as exc:
            # Possibly transient (a sharing violation on Windows): skip this
            # write, try again on the next one.
            print(f"  skipped {key}: cannot open it to check its content ({exc})", flush=True)
            return False
        with os.fdopen(fd, "r+b") as fh:
            if not stat.S_ISREG(os.fstat(fh.fileno()).st_mode):
                return self._refuse(key, "it is no longer a regular file")
            if sha256_hex(fh.read()) != recorded:
                return self._refuse(key, "its content changed since this trigger wrote it")
            fh.seek(0)
            fh.truncate()
            fh.write(data)
            _apply_mode(fh.fileno(), path, mode)
        self.files[key] = sha256_hex(data)
        self.save()
        return True


# --- Secure state directory -------------------------------------------------
#
# The state directory holds the control files cleanup.py trusts (pid files,
# created/restored markers, content-hashed manifests, canonical backups). On
# POSIX the leaf lives under the shared /tmp, so it is created privately
# (0700) and is used only when it is a real directory owned by the current
# user and not a symlink; the owner id is part of the leaf name
# (`state_dir_for`) so unrelated accounts do not share one directory.


class StateDirError(SystemExit):
    """Raised (as a fatal exit) when the state directory cannot be trusted."""


def _refuse_state_dir(state_dir: Path, reason: str) -> "StateDirError":
    return StateDirError(
        f"refusing to use state directory {state_dir}: {reason}. "
        "Remove it by hand after checking what it is, then re-run."
    )


def state_dir_is_safe(state_dir: Path) -> tuple[bool, str]:
    """(ok, reason) for an EXISTING state dir, without creating anything.

    Used by cleanup.py: a directory that is a symlink, is not a directory, or
    is owned by another user is not one this process created and must not be
    trusted to drive deletes/kills. ``reason`` is empty when ok.
    """
    sd = Path(state_dir)
    if os.path.islink(str(sd)):
        return False, "it is a symbolic link"
    try:
        st = os.lstat(str(sd))
    except FileNotFoundError:
        return True, ""
    except OSError as exc:
        return False, f"it cannot be inspected ({exc})"
    if not stat.S_ISDIR(st.st_mode):
        return False, "it is not a directory"
    if hasattr(os, "geteuid") and st.st_uid != os.geteuid():
        return False, f"it is owned by uid {st.st_uid}, not this user"
    return True, ""


def prepare_state_dir(state_dir: Path) -> Path:
    """Create ``state_dir`` privately (0700) and return it, refusing a
    symlinked or foreign-owned directory. Fatal (``SystemExit``) on refusal:
    a trigger must not run against a directory it cannot trust.
    """
    sd = Path(state_dir)
    # The parent (the OS temp root) is shared and system-owned; only the leaf
    # is made private.
    sd.parent.mkdir(parents=True, exist_ok=True)
    if os.path.islink(str(sd)):
        raise _refuse_state_dir(sd, "it is a symbolic link")
    if sd.exists():
        ok, reason = state_dir_is_safe(sd)
        if not ok:
            raise _refuse_state_dir(sd, reason)
    else:
        try:
            os.mkdir(str(sd), 0o700)
        except FileExistsError:
            ok, reason = state_dir_is_safe(sd)
            if not ok:
                raise _refuse_state_dir(sd, reason)
    # Force 0700 even when it pre-existed with looser bits (POSIX only).
    if hasattr(os, "geteuid"):
        try:
            os.chmod(str(sd), 0o700)
        except OSError:
            pass
    return sd


# --- Targets cleanup is allowed to touch ------------------------------------


def _within(child: Path, parent: Path) -> bool:
    try:
        child_r = os.path.realpath(str(child))
        parent_r = os.path.realpath(str(parent))
    except OSError:
        return False
    try:
        return os.path.commonpath([child_r, parent_r]) == parent_r
    except ValueError:
        return False


# Agent config files the triggers write under their canonical (non-prefixed)
# names, because the shipped sensitive-path patterns for them are
# file-specific. (basename, parent-directory name)
_CANONICAL_AGENT_FILES = {
    ("mcp.json", ".cursor"),
    ("credentials.json", ".claude"),
    ("auth.json", ".codex"),
    ("config", ".aws"),
}


def is_catalog_creatable_target(path: Path, state_dir: Path) -> bool:
    """True when ``path`` is something a catalog scenario could have created,
    so cleanup may restore or delete it. Everything else is left in place.

    Allowed: anything inside the (validated) state dir; a demo-prefixed name
    (``demo_*`` / ``DEMO_*``); the canonical agent-config files the triggers
    write by their real names; agent rule files under ``.cursor/rules``; the
    per-run Claude transcript probe under ``.claude/projects/edamame-*``; and
    the stand-in daemon installed for the lineage scenario.
    """
    p = Path(path).expanduser()
    if _within(p, state_dir):
        return True
    name = p.name
    if name.startswith("demo_") or name.startswith("DEMO_"):
        return True
    if (name, p.parent.name) in _CANONICAL_AGENT_FILES:
        return True
    if name.endswith(".mdc") and p.parent.name == "rules" and p.parent.parent.name == ".cursor":
        return True
    parts = p.parts
    if ".claude" in parts and "projects" in parts and any(part.startswith("edamame-") for part in parts):
        return True
    if name.endswith("_xz_sshd_standin"):
        return True
    return False


# --- Process identity (stale / reused pid guard) ----------------------------
#
# A pid file records a pid only. A pid is reused after a reboot (and, rarely,
# within one), so cleanup must not signal a process just because something with
# that pid is alive. Two reader-side checks, needing no cooperation from the
# writer: the pid file cannot predate the last boot, and the live process must
# not have started after the pid file was written (the trigger writes the file
# right after the process starts, so a legitimate target started no later).

_PID_SLACK_SECS = 5.0


def boot_time_epoch() -> "float | None":
    system = platform.system()
    try:
        if system == "Linux":
            with open("/proc/stat", "r", encoding="utf-8") as fh:
                for line in fh:
                    if line.startswith("btime "):
                        return float(line.split()[1])
            return None
        if system == "Darwin":
            out = subprocess.run(
                ["sysctl", "-n", "kern.boottime"],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=5, check=False,
            ).stdout
            # e.g. "{ sec = 1699999999, usec = 0 } Mon ..."
            import re
            m = re.search(r"sec\s*=\s*(\d+)", out)
            return float(m.group(1)) if m else None
        if system == "Windows":
            import ctypes
            ticks = ctypes.windll.kernel32.GetTickCount64()  # ms since boot
            return time.time() - (ticks / 1000.0)
    except Exception:
        return None
    return None


def process_start_epoch(pid: int) -> "float | None":
    system = platform.system()
    try:
        if system == "Linux":
            with open(f"/proc/{pid}/stat", "r", encoding="utf-8") as fh:
                data = fh.read()
            # Field 22 (starttime) in clock ticks since boot; the comm field
            # (in parens) can contain spaces, so split after the last ')'.
            rparen = data.rfind(")")
            fields = data[rparen + 2:].split()
            starttime_ticks = float(fields[19])
            clk = os.sysconf("SC_CLK_TCK")
            bt = boot_time_epoch()
            if bt is None or clk <= 0:
                return None
            return bt + starttime_ticks / clk
        if system == "Darwin":
            out = subprocess.run(
                ["ps", "-p", str(pid), "-o", "lstart="],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=5, check=False,
            ).stdout.strip()
            if not out:
                return None
            return time.mktime(time.strptime(out, "%a %b %d %H:%M:%S %Y"))
        if system == "Windows":
            import ctypes
            from ctypes import wintypes
            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            k32 = ctypes.windll.kernel32
            handle = k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid))
            if not handle:
                return None
            try:
                creation = wintypes.FILETIME()
                exit_t = wintypes.FILETIME()
                kernel_t = wintypes.FILETIME()
                user_t = wintypes.FILETIME()
                ok = k32.GetProcessTimes(
                    handle, ctypes.byref(creation), ctypes.byref(exit_t),
                    ctypes.byref(kernel_t), ctypes.byref(user_t),
                )
                if not ok:
                    return None
                ft = (creation.dwHighDateTime << 32) | creation.dwLowDateTime
                # FILETIME is 100ns ticks since 1601-01-01.
                return ft / 1e7 - 11644473600.0
            finally:
                k32.CloseHandle(handle)
    except Exception:
        return None
    return None


def pid_file_is_trustworthy(pid: int, pid_file: Path) -> bool:
    """True when the live ``pid`` is plausibly the process the trigger recorded
    in ``pid_file`` -- not a pid reused after a reboot or by an unrelated
    process. Conservative: when a fact cannot be read it does not block the
    kill (the alive check still gates it), it only blocks on positive evidence
    of a mismatch.
    """
    try:
        mtime = os.stat(str(pid_file)).st_mtime
    except OSError:
        return True
    bt = boot_time_epoch()
    if bt is not None and mtime < bt - _PID_SLACK_SECS:
        return False  # the pid file predates the current boot: pid is reused
    start = process_start_epoch(pid)
    if start is not None and start > mtime + _PID_SLACK_SECS:
        return False  # the live process started after the file was written
    return True
