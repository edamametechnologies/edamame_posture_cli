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
