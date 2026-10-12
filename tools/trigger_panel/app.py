#!/usr/bin/env python3
"""
Cross-platform control panel for EDAMAME security trigger scripts.

Start / stop each trigger under tests/security/triggers, and run cleanup.py.
Runs on macOS, Windows and Linux. For authorized local detection testing only.
"""

from __future__ import annotations

import importlib.util
import os
import platform
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
import tkinter as tk
import tkinter.font as tkfont
from pathlib import Path
from tkinter import messagebox, scrolledtext, ttk

IS_WINDOWS = platform.system() == "Windows"


AGENT_TYPES = ("openclaw", "cursor", "claude_code", "claude_desktop", "codex", "hermes")
DEFAULT_AGENT_TYPE = "openclaw"

# cleanup.py removes demo files and kills the injectors; it is normally quick,
# but a killed trigger can leave a process group in an odd state. Bound it so
# the panel never sits busy forever (what reads as a "hang").
CLEANUP_TIMEOUT_SECS = 120


def classify_cleanup_line(line: str) -> str:
    """Tag a cleanup.py output line: 'removed', 'blocked', or 'info'.

    'blocked' is a file/process cleanup could not touch as the current user
    (it printed and moved on) -- usually something a trigger installed as root,
    e.g. the stand-in under /usr/local/bin. The panel surfaces these so an
    incomplete cleanup is visible instead of looking silently stuck.
    """
    stripped = line.strip().lower()
    if stripped.startswith("removed ") or " removed " in stripped:
        return "removed"
    if (
        "cannot remove" in stripped
        or "could not" in stripped
        or "permission denied" in stripped
        or "cannot kill" in stripped
    ):
        return "blocked"
    return "info"


def _terminate_process_tree(proc: "subprocess.Popen") -> None:
    """Hard-stop a stuck child and its group, cross-platform."""
    try:
        if IS_WINDOWS:
            proc.kill()
        else:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (OSError, ProcessLookupError):
        try:
            proc.kill()
        except OSError:
            pass


def run_and_stream(cmd, cwd, on_line, timeout_secs=CLEANUP_TIMEOUT_SECS):
    """Run ``cmd``, deliver each output line to ``on_line``, enforce a timeout.

    A watchdog kills the process group after ``timeout_secs`` even when the
    child produces no output (a silent hang), so the read loop always ends.
    Returns ``(returncode, timed_out)``; ``returncode`` is ``None`` only if the
    process could not be waited on. Pure of any UI, so it is unit-testable with
    a fake cleanup script.
    """
    proc = subprocess.Popen(
        cmd,
        cwd=str(cwd),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        start_new_session=not IS_WINDOWS,
    )
    timed_out = threading.Event()

    def _watchdog() -> None:
        timed_out.set()
        _terminate_process_tree(proc)

    watchdog = threading.Timer(timeout_secs, _watchdog)
    watchdog.daemon = True
    watchdog.start()
    try:
        assert proc.stdout is not None
        for line in proc.stdout:
            text = line.rstrip()
            if text:
                on_line(text)
        returncode = proc.wait()
    finally:
        watchdog.cancel()
        if proc.stdout is not None:
            try:
                proc.stdout.close()
            except OSError:
                pass
    return returncode, timed_out.is_set()
POLL_MS = 1500


def app_resources_dir() -> Path:
    """Directory that holds app.py and the bundled ``python`` / ``triggers``.

    macOS: ``App.app/Contents/Resources`` (app.py sits beside ``python`` and
    ``triggers``). Windows / Linux: the directory the launcher ships app.py in,
    with ``python`` and ``triggers`` beside it. In every bundle layout this is
    simply the directory app.py lives in.
    """
    return Path(__file__).resolve().parent


def resolve_triggers_dir() -> Path:
    env = os.environ.get("EDAMAME_TRIGGERS_DIR", "").strip()
    if env:
        return Path(env).expanduser().resolve()

    here = app_resources_dir()
    candidates = [
        here / "triggers",
        here.parent.parent / "tests" / "security" / "triggers",
        Path.cwd() / "tests" / "security" / "triggers",
    ]
    for candidate in candidates:
        if (candidate / "cleanup.py").is_file():
            return candidate.resolve()
    raise SystemExit(
        "Could not find tests/security/triggers. "
        "Set EDAMAME_TRIGGERS_DIR or run from the edamame_posture checkout."
    )


def _path_inside_app_bundle(path: Path) -> bool:
    """True when a process path would look like a packaged macOS app.

    EDAMAME suppresses credential findings from a `.app` that is also holding
    files under the same user home (self-access). Triggers must not be that
    process, or cred-harvest / token-exfil never reach the app.
    """
    normalized = str(path).replace("\\", "/").lower()
    return ".app/" in normalized or normalized.endswith(".app")


def _usable_python(path: Path) -> bool:
    try:
        resolved = path.resolve()
    except OSError:
        return False
    return (
        resolved.is_file()
        and os.access(str(resolved), os.X_OK)
        and not _path_inside_app_bundle(resolved)
    )


def _bundled_python_executable(root: Path) -> Path:
    """The interpreter inside a bundled standalone CPython tree at ``root``.

    Windows places ``python.exe`` at the tree root; macOS / Linux use the
    POSIX ``bin/python3`` layout.
    """
    if IS_WINDOWS:
        return root / "python.exe"
    return root / "bin" / "python3"


def _cache_root() -> Path:
    """Per-user cache base, used only when the runtime must leave the bundle."""
    if IS_WINDOWS:
        base = os.environ.get("LOCALAPPDATA") or (Path.home() / "AppData" / "Local")
        return Path(base) / "edamame-trigger-panel"
    if platform.system() == "Darwin":
        return Path.home() / "Library" / "Caches" / "edamame-trigger-panel"
    base = os.environ.get("XDG_CACHE_HOME") or (Path.home() / ".cache")
    return Path(base) / "edamame-trigger-panel"


def _relocated_bundled_python(bundled_root: Path) -> Path:
    """Copy the embedded runtime to a path that is not inside a ``.app``.

    Only needed on macOS: a process whose path is inside a ``.app`` is
    classified as the app reading its own files and the findings are dropped.
    """
    dest = _cache_root() / "python"
    marker = dest / ".bundle-source"
    source_id = str(bundled_root.resolve())
    python = _bundled_python_executable(dest)
    if python.is_file() and marker.is_file() and marker.read_text(encoding="utf-8").strip() == source_id:
        return python
    if dest.exists():
        shutil.rmtree(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(bundled_root, dest, symlinks=True)
    marker.write_text(source_id + "\n", encoding="utf-8")
    return python


def runtime_python() -> str:
    """Python used to launch trigger and cleanup scripts.

    The shared bundle always uses the Python it shipped with. On macOS that
    runtime lives inside the ``.app``, so it is copied out first: a process
    path inside a ``.app`` is classified as the app reading its own files and
    the findings the triggers raise are dropped. On Windows / Linux the bundled
    interpreter's path is not a ``.app`` and is used in place. A checkout
    without the embedded runtime falls back to another interpreter whose path
    is also outside an app bundle.
    """
    bundled_root = app_resources_dir() / "python"
    bundled = _bundled_python_executable(bundled_root)
    if bundled.is_file():
        if _path_inside_app_bundle(bundled):
            relocated = _relocated_bundled_python(bundled_root)
            if _usable_python(relocated):
                return str(relocated.resolve())
        elif _usable_python(bundled):
            return str(bundled.resolve())

    if IS_WINDOWS:
        system_candidates = (
            Path(sys.base_prefix) / "python.exe",
            Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "Python" / "python.exe",
        )
    else:
        system_candidates = (
            Path("/opt/homebrew/bin/python3"),
            Path("/usr/local/bin/python3"),
            Path("/usr/bin/python3"),
        )
    for candidate in system_candidates:
        if _usable_python(candidate):
            return str(candidate.resolve())
    # Last resort: the interpreter running this panel, as long as it is not
    # itself inside a .app (on Windows / Linux it never is).
    return sys.executable


def state_dir_for(agent_type: str, triggers_dir: Path) -> Path:
    """Demo state directory for ``agent_type``.

    Must match what the triggers and cleanup.py compute, so the panel loads
    ``_common.state_dir_for`` from the bundled triggers and calls it. If that
    module cannot be loaded the logic is replicated inline (keep in sync with
    ``tests/security/triggers/_common.py::state_dir_for``): Windows uses
    ``%TEMP%``; every other platform uses ``/tmp``.
    """
    common_path = triggers_dir / "_common.py"
    if common_path.is_file():
        try:
            spec = importlib.util.spec_from_file_location(
                "_edamame_panel_common", str(common_path)
            )
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)  # type: ignore[union-attr]
            return Path(module.state_dir_for(agent_type))
        except Exception:
            pass
    name = f"edamame_{agent_type}_demo"
    if IS_WINDOWS:
        return Path(os.environ.get("TEMP", "C:\\Temp")) / name
    return Path(f"/tmp/{name}")


def _strip_prefix(value: str, prefix: str) -> str:
    return value[len(prefix) :] if value.startswith(prefix) else value


def _strip_suffix(value: str, suffix: str) -> str:
    return value[: -len(suffix)] if value.endswith(suffix) else value


def humanize(script_name: str) -> str:
    stem = _strip_suffix(_strip_prefix(script_name, "trigger_"), ".py")
    return stem.replace("_", " ")


def discover_triggers(triggers_dir: Path):
    items = []
    for path in sorted(triggers_dir.glob("trigger_*.py")):
        items.append((humanize(path.name), path))
    return items


def pid_file_for(script: Path, state_dir: Path):
    """Infer PID file name from the trigger module's PID_FILE constant."""
    try:
        for line in script.read_text(encoding="utf-8").splitlines():
            if line.startswith("PID_FILE") and "=" in line:
                value = line.split("=", 1)[1].strip().strip("\"'")
                if value:
                    return state_dir / value
    except OSError:
        pass
    stem = _strip_prefix(script.stem, "trigger_")
    return state_dir / f"{stem}.pid"


def read_pid(pid_file):
    if pid_file is None or not pid_file.exists():
        return None
    try:
        return int(pid_file.read_text(encoding="utf-8").strip())
    except (ValueError, OSError):
        return None


def _windows_process_alive(pid: int) -> bool:
    import ctypes

    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    STILL_ACTIVE = 259
    kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
    handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return False
    try:
        code = ctypes.c_ulong()
        if kernel32.GetExitCodeProcess(handle, ctypes.byref(code)) == 0:
            return False
        return code.value == STILL_ACTIVE
    finally:
        kernel32.CloseHandle(handle)


def process_alive(pid: int) -> bool:
    if IS_WINDOWS:
        # os.kill(pid, 0) on Windows calls TerminateProcess(handle, 0) -- it
        # would KILL the process, not probe it. Query the handle instead.
        try:
            return _windows_process_alive(pid)
        except OSError:
            return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def _unlink(path) -> None:
    if path is None:
        return
    try:
        path.unlink()
    except FileNotFoundError:
        pass


def _windows_kill_tree(pid) -> str:
    # taskkill ends the whole process tree and fails softly, matching
    # cleanup.py and tests/security/run_scenario.sh on Windows.
    result = subprocess.run(
        ["taskkill", "/PID", str(pid), "/T", "/F"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if result.returncode == 0:
        return f"stopped pid {pid} tree"
    detail = (result.stderr or result.stdout or "").strip().replace("\n", " ")
    return f"could not stop pid {pid}: {detail}" if detail else f"already stopped (pid {pid})"


def kill_pid(pid, pid_file) -> str:
    if IS_WINDOWS:
        detail = _windows_kill_tree(pid)
        _unlink(pid_file)
        return detail
    try:
        try:
            pgid = os.getpgid(pid)
        except ProcessLookupError:
            _unlink(pid_file)
            return f"already stopped (pid {pid})"
        if pgid == pid and pgid != os.getpgrp():
            os.killpg(pgid, signal.SIGTERM)
            detail = f"stopped process group {pgid}"
        else:
            os.kill(pid, signal.SIGTERM)
            detail = f"stopped pid {pid}"
    except ProcessLookupError:
        detail = f"already stopped (pid {pid})"
    except PermissionError:
        return f"permission denied killing pid {pid}"
    except OSError as exc:
        return f"could not stop pid {pid}: {exc}"

    _unlink(pid_file)
    return detail


# --- Presentation helpers ---------------------------------------------------
#
# Everything below here is pure UI: colors, text shaping and output parsing.
# None of it changes how triggers are discovered, launched, or stopped.

TICK_MS = 1000
MAX_RAW_LINES = 1200

# Check "families" -> a small, fixed palette. The pill backgrounds are chosen
# to carry white text legibly on both light and dark window chromes (the pill
# supplies its own background, so it does not depend on the theme).
FAMILY_COLORS = {
    "tamper": "#C2680E",        # file_system_tampering (amber)
    "credential": "#C0392B",    # credential / token exfiltration (red)
    "divergence": "#7D3C98",    # divergence / goal drift / memory poisoning (purple)
    "sandbox": "#117A8B",       # sandbox escape (teal)
    "supply_chain": "#2E6DB4",  # package / supply-chain compromise (blue)
    "egress": "#2E8B57",        # blacklisted / tunnelled / relayed network egress (green)
    "scrape": "#B03A79",        # process memory scrape (magenta)
    "agent_control": "#3F51B5", # agent config / rules / denylist tampering (indigo)
    "other": "#5A6472",         # anything else (slate)
}

FAMILY_LABEL = {
    "tamper": "file tampering",
    "credential": "credential / token",
    "divergence": "divergence",
    "sandbox": "sandbox escape",
    "supply_chain": "supply chain",
    "egress": "network egress",
    "scrape": "memory scrape",
    "agent_control": "agent control",
    "other": "detection",
}

# A detected `check=` value maps straight to a family.
CHECK_FAMILY = {
    "file_system_tampering": "tamper",
    "credential_harvest": "credential",
    "sensitive_material_egress": "credential",
    "divergence": "divergence",
    "sandbox_exploitation": "sandbox",
    "package_install_lifecycle": "supply_chain",
    "process_memory_scrape": "scrape",
    "agent_denylist_bypass": "agent_control",
}

# Otherwise the family is inferred from the script name. First match wins.
NAME_FAMILY = (
    ("file_events", "tamper"),
    ("temp_modify", "tamper"),
    ("nonsensitive_path", "tamper"),
    ("token", "credential"),
    ("cred", "credential"),
    ("sprawl", "credential"),
    ("sandbox", "sandbox"),
    ("divergence", "divergence"),
    ("goal_drift", "divergence"),
    ("memory_poison", "divergence"),
    ("process_memory", "scrape"),
    ("memory_scrape", "scrape"),
    ("supply_chain", "supply_chain"),
    ("npm_rat", "supply_chain"),
    ("pgserve", "supply_chain"),
    ("package_install", "supply_chain"),
    ("agent_config", "agent_control"),
    ("agent_rules", "agent_control"),
    ("agent_denylist", "agent_control"),
    ("backdoor", "agent_control"),
    ("blacklist", "egress"),
    ("dns_tunnel", "egress"),
    ("ntp_tunnel", "egress"),
    ("loopback", "egress"),
    ("daemon_lineage", "egress"),
    ("relay", "egress"),
)

# Dark "cyber" palette. Fixed, not derived from the OS appearance: the panel
# ships a single, consistent dark look on macOS / Windows / Linux by styling
# the configurable ``clam`` ttk theme explicitly. One restrained neon accent.
ACCENT = "#2BD6C6"       # teal/cyan -- accent, focus, running
ACCENT_DIM = "#1F9E93"   # pressed / hover of a filled accent control
ACCENT_INK = "#06211E"   # text on a filled accent control
AMBER = "#E3B341"        # transitional (starting / stopping)
DANGER = "#F85149"       # error / exited(non-zero)

PALETTE = {
    "window": "#0E1116",       # near-black slate
    "card": "#161B22",         # raised card
    "card_hover": "#1C222B",
    "card_border": "#2A313C",
    "detail": "#0B0E13",       # inset detail / log
    "fg": "#C9D1D9",           # body text (light grey)
    "heading": "#E6EDF3",      # titles
    "muted": "#8B949E",
    "faint": "#6E7681",
    "accent": ACCENT,
}

# Live status -> label shown beside the status dot, and the dot's color.
STATUS_LABEL = {
    "idle": "idle",
    "starting": "starting",
    "running": "running",
    "stopping": "stopping",
    "stopped": "stopped",
    "error": "exited",
}
DOT_COLORS = {
    "idle": "#6E7681",
    "starting": AMBER,
    "running": ACCENT,
    "stopping": AMBER,
    "stopped": "#8B949E",
    "error": DANGER,
}

# A banner line can carry several `key=value` tokens on one line
# (``target=.. host=..``). Split only at a whitespace-preceded identifier so
# values that themselves contain spaces (``threat=Meta AI inbox incident``)
# stay whole.
_KV_BOUNDARY = re.compile(r"(?:^|\s)([a-z][a-z0-9_]*)=")
_ROUND_RE = re.compile(r"\bround=(\d+)")


def family_for(check_value: str, script_name: str) -> str:
    if check_value and check_value in CHECK_FAMILY:
        return CHECK_FAMILY[check_value]
    lowered = script_name.lower()
    for needle, family in NAME_FAMILY:
        if needle in lowered:
            return family
    return "other"


def contrast_text(hex_color: str) -> str:
    """Black or white text for a solid badge background."""
    try:
        r = int(hex_color[1:3], 16)
        g = int(hex_color[3:5], 16)
        b = int(hex_color[5:7], 16)
    except (ValueError, IndexError):
        return "#ffffff"
    luminance = (0.299 * r + 0.587 * g + 0.114 * b) / 255.0
    return "#111111" if luminance > 0.6 else "#ffffff"


def doc_summary(script: Path) -> str:
    """First meaningful sentence of the trigger's module docstring.

    Gives each card a human subtitle before it is ever started. Purely
    cosmetic; failure just yields an empty subtitle.
    """
    try:
        text = script.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    marker = '"""'
    start = text.find(marker)
    if start == -1:
        return ""
    end = text.find(marker, start + 3)
    body = text[start + 3 : end if end != -1 else len(text)]
    for raw_line in body.splitlines():
        line = raw_line.strip()
        if line:
            return line
    return ""


def parse_kv_tokens(line: str):
    """Yield (key, value) pairs from a banner line. Order preserved."""
    matches = list(_KV_BOUNDARY.finditer(line))
    for index, match in enumerate(matches):
        key = match.group(1)
        value_start = match.end()
        value_end = matches[index + 1].start() if index + 1 < len(matches) else len(line)
        yield key, line[value_start:value_end].strip()


def _fmt_elapsed(seconds: float) -> str:
    seconds = int(max(0, seconds))
    hours, rem = divmod(seconds, 3600)
    minutes, secs = divmod(rem, 60)
    if hours:
        return f"{hours}:{minutes:02d}:{secs:02d}"
    return f"{minutes:02d}:{secs:02d}"


def _ellipsize(text: str, limit: int) -> str:
    text = text.replace("\n", " ").strip()
    if len(text) <= limit:
        return text
    return text[: limit - 1].rstrip() + "…"


class TriggerCard:
    """Per-trigger UI state and widgets. Mutated only on the Tk main thread."""

    def __init__(self, name: str, script: Path) -> None:
        self.name = name
        self.script = script
        self.summary = doc_summary(script)
        self.family = family_for("", script.name)
        self.check_label = FAMILY_LABEL.get(self.family, "detection")

        self.status = "idle"
        self.start_time = None
        self.frozen_elapsed = None
        self.banner = {}          # ordered key -> value
        self.banner_done = False
        self.raw = []             # capped list of output lines
        self.last_line = ""
        self.round = None
        self.progress_count = 0
        self.has_worker = False
        self.stop_requested = False
        self.expanded = False

        # Widgets, populated by TriggerPanel._build_card.
        self.widgets = {}

    def reset_run(self) -> None:
        self.banner = {}
        self.banner_done = False
        self.raw = []
        self.last_line = ""
        self.round = None
        self.progress_count = 0
        self.frozen_elapsed = None

    def elapsed(self) -> float:
        if self.frozen_elapsed is not None:
            return self.frozen_elapsed
        if self.start_time is None:
            return 0.0
        return time.monotonic() - self.start_time


class TriggerPanel(tk.Tk):
    def __init__(self, triggers_dir: Path) -> None:
        super().__init__()
        self.triggers_dir = triggers_dir
        self.cleanup_script = triggers_dir / "cleanup.py"
        self.cards = {}  # script.name -> TriggerCard
        for name, script in discover_triggers(triggers_dir):
            self.cards[script.name] = TriggerCard(name, script)
        self._busy = False

        self.title("EDAMAME Trigger Panel")
        self.geometry("900x760")
        self.minsize(560, 420)

        self.agent_type = tk.StringVar(value=DEFAULT_AGENT_TYPE)
        self.summary_var = tk.StringVar(value="")
        self.path_var = tk.StringVar(value="")

        self.palette = dict(PALETTE)
        self._build_fonts()
        self._setup_style()
        self._build_ui()
        self.after(300, self.refresh_statuses)
        self.after(TICK_MS, self._tick)

    # -- theming ------------------------------------------------------------

    def _build_fonts(self) -> None:
        """Proportional UI fonts, plus monospace (TkFixedFont) for telemetry."""
        mono_family = tkfont.nametofont("TkFixedFont").cget("family")
        self.mono = tkfont.Font(family=mono_family, size=11)
        self.mono_small = tkfont.Font(family=mono_family, size=10)

    def _setup_style(self) -> None:
        """Style the configurable ``clam`` theme into the dark palette.

        Explicit colors everywhere so the panel looks the same on macOS,
        Windows and Linux instead of inheriting each platform's native theme.
        """
        pal = self.palette
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        style.configure(
            ".",
            background=pal["window"],
            foreground=pal["fg"],
            bordercolor=pal["card_border"],
            focuscolor=ACCENT,
            fieldbackground=pal["card"],
        )
        style.configure("TFrame", background=pal["window"])
        style.configure("TLabel", background=pal["window"], foreground=pal["fg"])

        # Header buttons: flat dark chips that light to the accent on hover.
        style.configure(
            "Cyber.TButton",
            background=pal["card"],
            foreground=pal["fg"],
            bordercolor=pal["card_border"],
            relief="flat",
            padding=(12, 6),
        )
        style.map(
            "Cyber.TButton",
            background=[("active", pal["card_hover"]), ("pressed", pal["card_hover"])],
            foreground=[("active", ACCENT), ("pressed", ACCENT)],
            bordercolor=[("active", ACCENT)],
        )
        # Filled accent button (Stop all).
        style.configure(
            "Accent.TButton",
            background=ACCENT,
            foreground=ACCENT_INK,
            bordercolor=ACCENT,
            relief="flat",
            padding=(12, 6),
        )
        style.map(
            "Accent.TButton",
            background=[("active", ACCENT_DIM), ("pressed", ACCENT_DIM)],
            foreground=[("active", ACCENT_INK)],
        )

        # Readonly combobox.
        style.configure(
            "TCombobox",
            fieldbackground=pal["card"],
            background=pal["card"],
            foreground=pal["fg"],
            arrowcolor=ACCENT,
            bordercolor=pal["card_border"],
            selectbackground=pal["card"],
            selectforeground=pal["fg"],
            padding=(6, 4),
        )
        style.map(
            "TCombobox",
            fieldbackground=[("readonly", pal["card"])],
            foreground=[("readonly", pal["fg"])],
            bordercolor=[("focus", ACCENT), ("active", ACCENT)],
            arrowcolor=[("active", ACCENT)],
        )
        self.option_add("*TCombobox*Listbox.background", pal["card"])
        self.option_add("*TCombobox*Listbox.foreground", pal["fg"])
        self.option_add("*TCombobox*Listbox.selectBackground", ACCENT)
        self.option_add("*TCombobox*Listbox.selectForeground", ACCENT_INK)

        # Scrollbars.
        for orient in ("Vertical.TScrollbar", "Horizontal.TScrollbar"):
            style.configure(
                orient,
                background=pal["card"],
                troughcolor=pal["window"],
                bordercolor=pal["window"],
                arrowcolor=pal["muted"],
            )
            style.map(orient, background=[("active", pal["card_hover"])])

        # Panel-log label frame.
        style.configure("Cyber.TLabelframe", background=pal["window"], bordercolor=pal["card_border"])
        style.configure(
            "Cyber.TLabelframe.Label", background=pal["window"], foreground=pal["muted"]
        )

    def _pill(self, parent, text: str, bg: str, fg=None, small=False):
        return tk.Label(
            parent,
            text=text,
            bg=bg,
            fg=fg or contrast_text(bg),
            font=("", 10 if small else 11, "bold"),
            padx=8,
            pady=1,
        )

    # -- layout -------------------------------------------------------------

    def _build_ui(self) -> None:
        pal = self.palette
        self.configure(bg=pal["window"])

        header = tk.Frame(self, bg=pal["window"])
        header.pack(fill=tk.X, padx=16, pady=(14, 6))

        title_row = tk.Frame(header, bg=pal["window"])
        title_row.pack(fill=tk.X)
        tk.Label(
            title_row,
            text="EDAMAME",
            bg=pal["window"],
            fg=ACCENT,
            font=("", 18, "bold"),
        ).pack(side=tk.LEFT)
        tk.Label(
            title_row,
            text="  Trigger Panel",
            bg=pal["window"],
            fg=pal["heading"],
            font=("", 18, "bold"),
        ).pack(side=tk.LEFT)
        tk.Label(
            title_row,
            textvariable=self.summary_var,
            bg=pal["window"],
            fg=pal["muted"],
            font=self.mono,
        ).pack(side=tk.RIGHT)

        tk.Label(
            header,
            text="Authorized local detection testing only. Stop triggers or run cleanup when finished.",
            bg=pal["window"],
            fg=pal["muted"],
            font=("", 11),
            anchor=tk.W,
            justify=tk.LEFT,
            wraplength=840,
        ).pack(anchor=tk.W, pady=(4, 10))

        controls = tk.Frame(header, bg=pal["window"])
        controls.pack(fill=tk.X)
        tk.Label(controls, text="Agent type", bg=pal["window"], fg=pal["fg"]).pack(
            side=tk.LEFT
        )
        agent = ttk.Combobox(
            controls,
            textvariable=self.agent_type,
            values=AGENT_TYPES,
            state="readonly",
            width=15,
        )
        agent.pack(side=tk.LEFT, padx=(8, 16))
        agent.bind("<<ComboboxSelected>>", lambda _e: self._on_agent_change())

        ttk.Button(
            controls, text="Refresh", style="Cyber.TButton", command=self.refresh_statuses
        ).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(
            controls, text="■  Stop all", style="Accent.TButton", command=self.stop_all
        ).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(
            controls, text="Run cleanup", style="Cyber.TButton", command=self.run_cleanup
        ).pack(side=tk.LEFT)

        legend = tk.Frame(header, bg=pal["window"])
        legend.pack(fill=tk.X, pady=(10, 0))
        tk.Label(legend, text="Status", bg=pal["window"], fg=pal["faint"]).pack(
            side=tk.LEFT, padx=(0, 8)
        )
        for key in ("idle", "starting", "running", "stopping", "stopped", "error"):
            cell = tk.Frame(legend, bg=pal["window"])
            cell.pack(side=tk.LEFT, padx=(0, 12))
            tk.Label(
                cell, text="●", bg=pal["window"], fg=DOT_COLORS[key], font=("", 10)
            ).pack(side=tk.LEFT, padx=(0, 4))
            tk.Label(
                cell, text=STATUS_LABEL[key], bg=pal["window"], fg=pal["muted"], font=("", 10)
            ).pack(side=tk.LEFT)

        tk.Label(
            header,
            textvariable=self.path_var,
            bg=pal["window"],
            fg=pal["faint"],
            font=self.mono_small,
            anchor=tk.W,
            justify=tk.LEFT,
        ).pack(anchor=tk.W, pady=(10, 0))

        # Scrollable list of cards.
        body = tk.Frame(self, bg=pal["window"])
        body.pack(fill=tk.BOTH, expand=True, padx=12, pady=(4, 6))

        self.canvas = tk.Canvas(body, highlightthickness=0, bg=pal["window"])
        scrollbar = ttk.Scrollbar(body, orient=tk.VERTICAL, command=self.canvas.yview)
        self.list_frame = tk.Frame(self.canvas, bg=pal["window"])
        self.list_frame.bind(
            "<Configure>",
            lambda _e: self.canvas.configure(scrollregion=self.canvas.bbox("all")),
        )
        self._list_window = self.canvas.create_window(
            (0, 0), window=self.list_frame, anchor=tk.NW
        )
        self.canvas.bind(
            "<Configure>",
            lambda e: self.canvas.itemconfigure(self._list_window, width=e.width),
        )
        self.canvas.configure(yscrollcommand=scrollbar.set)
        self.canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self._bind_mousewheel(self.canvas)

        for card in self.cards.values():
            self._build_card(card)

        # Compact global log for cleanup output and panel-level messages.
        log_frame = ttk.LabelFrame(
            self, text="Panel log", padding=6, style="Cyber.TLabelframe"
        )
        log_frame.pack(fill=tk.X, expand=False, padx=12, pady=(0, 12))
        self.log = scrolledtext.ScrolledText(
            log_frame, height=6, wrap=tk.WORD, font=self.mono_small
        )
        self.log.pack(fill=tk.BOTH, expand=True)
        self.log.configure(
            state=tk.DISABLED,
            bg=pal["detail"],
            fg=pal["fg"],
            insertbackground=ACCENT,
            selectbackground=ACCENT_DIM,
            selectforeground=ACCENT_INK,
            highlightthickness=0,
            relief="flat",
            borderwidth=0,
        )

    def _bind_mousewheel(self, canvas: tk.Canvas) -> None:
        def on_wheel(event):
            if event.num == 4:
                delta = -1
            elif event.num == 5:
                delta = 1
            else:
                delta = -1 if event.delta > 0 else 1
            canvas.yview_scroll(delta, "units")

        for seq in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
            canvas.bind_all(seq, on_wheel)

    def _build_card(self, card: TriggerCard) -> None:
        pal = self.palette
        outer = tk.Frame(
            self.list_frame,
            bg=pal["card_border"],
            padx=1,
            pady=1,
        )
        outer.pack(fill=tk.X, pady=5, padx=2)
        inner = tk.Frame(outer, bg=pal["card"])
        inner.pack(fill=tk.X)

        top = tk.Frame(inner, bg=pal["card"], padx=12, pady=9)
        top.pack(fill=tk.X)

        arrow = tk.Label(
            top,
            text="▸",
            bg=pal["card"],
            fg=pal["muted"],
            font=("", 12),
            cursor="hand2",
            width=2,
        )
        arrow.pack(side=tk.LEFT)
        arrow.bind("<Button-1>", lambda _e, c=card: self._toggle_detail(c))

        name_lbl = tk.Label(
            top,
            text=card.name,
            bg=pal["card"],
            fg=pal["heading"],
            font=("", 13, "bold"),
            cursor="hand2",
        )
        name_lbl.pack(side=tk.LEFT, padx=(2, 8))
        name_lbl.bind("<Button-1>", lambda _e, c=card: self._toggle_detail(c))

        badge = self._pill(
            top, card.check_label, FAMILY_COLORS.get(card.family, FAMILY_COLORS["other"])
        )
        badge.pack(side=tk.LEFT)

        # Right-aligned: a single run/stop toggle, preceded by the status dot
        # and its label. One clear affordance per row.
        toggle = tk.Label(
            top,
            text="▶  Start",
            bg=pal["card"],
            fg=ACCENT,
            font=("", 11, "bold"),
            padx=12,
            pady=3,
            cursor="hand2",
            highlightthickness=1,
            highlightbackground=ACCENT,
            highlightcolor=ACCENT,
            borderwidth=0,
            relief="flat",
            width=7,
        )
        toggle.pack(side=tk.RIGHT, padx=(10, 0))
        toggle.bind("<Button-1>", lambda _e, c=card: self.toggle_trigger(c))
        toggle.bind("<Enter>", lambda _e, c=card: self._toggle_hover(c, True))
        toggle.bind("<Leave>", lambda _e, c=card: self._toggle_hover(c, False))

        status_text = tk.Label(
            top,
            text="idle",
            bg=pal["card"],
            fg=DOT_COLORS["idle"],
            font=self.mono_small,
            width=9,
            anchor=tk.W,
        )
        status_text.pack(side=tk.RIGHT, padx=(6, 0))
        dot = tk.Label(
            top, text="●", bg=pal["card"], fg=DOT_COLORS["idle"], font=("", 12)
        )
        dot.pack(side=tk.RIGHT, padx=(10, 0))

        summary_lbl = tk.Label(
            inner,
            text=_ellipsize(card.summary, 120) if card.summary else "",
            bg=pal["card"],
            fg=pal["muted"],
            font=("", 11),
            anchor=tk.W,
            justify=tk.LEFT,
        )
        summary_lbl.pack(fill=tk.X, padx=(40, 12), pady=(0, 2))

        meta_lbl = tk.Label(
            inner,
            text="",
            bg=pal["card"],
            fg=pal["faint"],
            font=self.mono_small,
            anchor=tk.W,
            justify=tk.LEFT,
        )
        meta_lbl.pack(fill=tk.X, padx=(40, 12), pady=(0, 9))

        card.widgets = {
            "outer": outer,
            "inner": inner,
            "top": top,
            "arrow": arrow,
            "name": name_lbl,
            "badge": badge,
            "dot": dot,
            "status_text": status_text,
            "toggle": toggle,
            "summary": summary_lbl,
            "meta": meta_lbl,
            "detail": None,
            "kv_frame": None,
            "raw_text": None,
        }
        self._apply_status(card)
        self._update_meta(card)

    def _ensure_detail(self, card: TriggerCard) -> None:
        if card.widgets.get("detail") is not None:
            return
        pal = self.palette
        detail = tk.Frame(card.widgets["inner"], bg=pal["detail"])
        kv_frame = tk.Frame(detail, bg=pal["detail"], padx=40, pady=8)
        kv_frame.pack(fill=tk.X)
        raw_label = tk.Label(
            detail,
            text="Raw output",
            bg=pal["detail"],
            fg=pal["faint"],
            font=("", 10, "bold"),
            anchor=tk.W,
        )
        raw_label.pack(fill=tk.X, padx=40, pady=(2, 2))
        raw_text = scrolledtext.ScrolledText(
            detail, height=8, wrap=tk.NONE, font=self.mono_small
        )
        raw_text.pack(fill=tk.BOTH, expand=True, padx=40, pady=(0, 10))
        raw_text.configure(
            state=tk.DISABLED,
            bg=pal["detail"],
            fg=pal["fg"],
            insertbackground=ACCENT,
            selectbackground=ACCENT_DIM,
            selectforeground=ACCENT_INK,
            highlightthickness=0,
            relief="flat",
            borderwidth=0,
        )
        card.widgets["detail"] = detail
        card.widgets["kv_frame"] = kv_frame
        card.widgets["raw_text"] = raw_text

    def _toggle_detail(self, card: TriggerCard) -> None:
        card.expanded = not card.expanded
        if card.expanded:
            self._ensure_detail(card)
            card.widgets["arrow"].configure(text="▾")
            card.widgets["detail"].pack(fill=tk.BOTH, expand=True)
            self._render_kv(card)
            self._fill_raw(card)
        else:
            card.widgets["arrow"].configure(text="▸")
            if card.widgets.get("detail") is not None:
                card.widgets["detail"].pack_forget()

    def _render_kv(self, card: TriggerCard) -> None:
        frame = card.widgets.get("kv_frame")
        if frame is None:
            return
        for child in frame.winfo_children():
            child.destroy()
        pal = self.palette
        if not card.banner:
            tk.Label(
                frame,
                text="No banner captured yet. Start the trigger to see its parameters.",
                bg=pal["detail"],
                fg=pal["faint"],
                font=("", 10),
                anchor=tk.W,
            ).grid(row=0, column=0, sticky=tk.W)
            return
        frame.columnconfigure(1, weight=1)
        for row, (key, value) in enumerate(card.banner.items()):
            tk.Label(
                frame,
                text=key,
                bg=pal["detail"],
                fg=ACCENT,
                font=self.mono_small,
                anchor=tk.NE,
            ).grid(row=row, column=0, sticky=tk.NE, padx=(0, 12), pady=1)
            tk.Label(
                frame,
                text=value,
                bg=pal["detail"],
                fg=pal["fg"],
                font=self.mono_small,
                anchor=tk.W,
                justify=tk.LEFT,
                wraplength=560,
            ).grid(row=row, column=1, sticky=tk.W, pady=1)

    def _fill_raw(self, card: TriggerCard) -> None:
        widget = card.widgets.get("raw_text")
        if widget is None:
            return
        widget.configure(state=tk.NORMAL)
        widget.delete("1.0", tk.END)
        widget.insert(tk.END, "\n".join(card.raw))
        widget.see(tk.END)
        widget.configure(state=tk.DISABLED)

    # -- status + meta rendering -------------------------------------------

    def _apply_status(self, card: TriggerCard) -> None:
        dot_color = DOT_COLORS.get(card.status, DOT_COLORS["idle"])
        label = STATUS_LABEL.get(card.status, "idle")
        if card.status == "error" and card.banner.get("_exit_code"):
            label = f"exit {card.banner['_exit_code']}"
        card.widgets["dot"].configure(fg=dot_color)
        card.widgets["status_text"].configure(text=label, fg=dot_color)
        self._style_toggle(card, hover=False)

    def _style_toggle(self, card: TriggerCard, hover: bool) -> None:
        """Render the single run/stop control for the card's current state.

        Idle/stopped/exited -> an outlined accent "Start"; running/starting ->
        a filled accent "Stop". Stopping is a dimmed, non-interactive "Stop".
        """
        toggle = card.widgets["toggle"]
        pal = self.palette
        if card.status in ("starting", "running"):
            bg = ACCENT_DIM if hover else ACCENT
            toggle.configure(
                text="■  Stop",
                bg=bg,
                fg=ACCENT_INK,
                highlightthickness=0,
                cursor="hand2",
            )
        elif card.status == "stopping":
            toggle.configure(
                text="■  Stop",
                bg=pal["card"],
                fg=pal["faint"],
                highlightthickness=1,
                highlightbackground=pal["card_border"],
                highlightcolor=pal["card_border"],
                cursor="arrow",
            )
        else:  # idle / stopped / error -> Start (outlined accent)
            toggle.configure(
                text="▶  Start",
                bg=pal["card_hover"] if hover else pal["card"],
                fg=ACCENT,
                highlightthickness=1,
                highlightbackground=ACCENT,
                highlightcolor=ACCENT,
                cursor="hand2",
            )

    def _toggle_hover(self, card: TriggerCard, entering: bool) -> None:
        if card.status == "stopping":
            return
        self._style_toggle(card, hover=entering)

    def _update_meta(self, card: TriggerCard) -> None:
        pal = self.palette
        parts = []
        if card.status in ("starting", "running", "stopping") or card.frozen_elapsed is not None:
            parts.append("⏱ " + _fmt_elapsed(card.elapsed()))
        if card.round is not None:
            parts.append(f"round {card.round}")
        elif card.progress_count:
            parts.append(f"{card.progress_count} updates")
        if card.last_line:
            parts.append(_ellipsize(card.last_line, 72))
        text = "   ·   ".join(parts)
        card.widgets["meta"].configure(text=text, fg=pal["faint"])

    def _set_status(self, card: TriggerCard, status: str) -> None:
        if status in ("starting", "running") and card.status not in ("starting", "running"):
            if card.start_time is None:
                card.start_time = time.monotonic()
            card.frozen_elapsed = None
        if status in ("stopped", "error", "idle"):
            if card.start_time is not None and card.frozen_elapsed is None:
                card.frozen_elapsed = card.elapsed()
        card.status = status
        self._apply_status(card)
        self._update_meta(card)
        self._update_summary_count()

    def _update_badge(self, card: TriggerCard) -> None:
        check_value = card.banner.get("check", "")
        family = family_for(check_value, card.script.name)
        card.family = family
        card.check_label = check_value if check_value else FAMILY_LABEL.get(family, "detection")
        color = FAMILY_COLORS.get(family, FAMILY_COLORS["other"])
        card.widgets["badge"].configure(
            text=card.check_label, bg=color, fg=contrast_text(color)
        )

    def _update_summary_count(self) -> None:
        running = sum(
            1 for c in self.cards.values() if c.status in ("starting", "running", "stopping")
        )
        self.summary_var.set(f"{running} running / {len(self.cards)} total")

    def append_log(self, text: str) -> None:
        self.log.configure(state=tk.NORMAL)
        self.log.insert(tk.END, text.rstrip() + "\n")
        self.log.see(tk.END)
        self.log.configure(state=tk.DISABLED)

    def current_state_dir(self) -> Path:
        return state_dir_for(self.agent_type.get(), self.triggers_dir)

    # -- periodic refresh ---------------------------------------------------

    def _tick(self) -> None:
        for card in self.cards.values():
            if card.status in ("starting", "running", "stopping"):
                self._update_meta(card)
        self.after(TICK_MS, self._tick)

    def refresh_statuses(self) -> None:
        state_dir = self.current_state_dir()
        self.path_var.set(f"Triggers: {self.triggers_dir}    State: {state_dir}")
        for card in self.cards.values():
            pid_file = pid_file_for(card.script, state_dir)
            pid = read_pid(pid_file)
            running = pid is not None and process_alive(pid)
            if card.has_worker:
                # The worker thread owns this card's transitions.
                continue
            if running:
                if card.status not in ("running", "starting", "stopping"):
                    # Started outside the panel (e.g. CLI); reflect it.
                    self._set_status(card, "running")
            else:
                if pid_file is not None and pid_file.exists():
                    _unlink(pid_file)
                if card.status in ("running", "starting", "stopping"):
                    self._set_status(card, "stopped")
        self._update_summary_count()
        self.after(POLL_MS, self.refresh_statuses)

    def _on_agent_change(self) -> None:
        # State dir changes with agent type; re-reconcile idle cards.
        for card in self.cards.values():
            if not card.has_worker and card.status != "error":
                card.status = "idle"
                card.start_time = None
                card.frozen_elapsed = None
                self._apply_status(card)
                self._update_meta(card)
        self.refresh_statuses()

    # -- output parsing -----------------------------------------------------

    def _ingest_line(self, card: TriggerCard, raw_line: str) -> None:
        line = raw_line.rstrip("\n")
        card.raw.append(line)
        if len(card.raw) > MAX_RAW_LINES:
            del card.raw[: len(card.raw) - MAX_RAW_LINES]

        stripped = line.strip()
        if stripped:
            card.last_line = stripped

        if not card.banner_done:
            tokens = list(parse_kv_tokens(line))
            if tokens:
                for key, value in tokens:
                    card.banner.setdefault(key, value)
                    if key == "stop_with":
                        card.banner_done = True
                if "check" in card.banner:
                    self._update_badge(card)
                if card.expanded:
                    self._render_kv(card)
        else:
            card.progress_count += 1
            match = _ROUND_RE.search(line)
            if match:
                card.round = int(match.group(1))

        if card.status == "starting" and (card.banner or stripped):
            self._set_status(card, "running")

        if card.expanded and card.widgets.get("raw_text") is not None:
            widget = card.widgets["raw_text"]
            widget.configure(state=tk.NORMAL)
            widget.insert(tk.END, line + "\n")
            widget.see(tk.END)
            widget.configure(state=tk.DISABLED)

        self._update_meta(card)

    # -- lifecycle ----------------------------------------------------------

    def toggle_trigger(self, card: TriggerCard) -> None:
        """Single per-row control: start when idle, stop when active."""
        if card.status in ("starting", "running"):
            self.stop_trigger(card)
        elif card.status == "stopping":
            return
        else:
            self.start_trigger(card)

    def start_trigger(self, card: TriggerCard) -> None:
        if self._busy or card.has_worker:
            return
        state_dir = self.current_state_dir()
        pid_file = pid_file_for(card.script, state_dir)
        pid = read_pid(pid_file)
        if pid is not None and process_alive(pid):
            messagebox.showinfo(
                "Already running", f"{card.name} is already running (pid {pid})."
            )
            return

        card.reset_run()
        card.stop_requested = False
        card.has_worker = True
        card.start_time = time.monotonic()
        self._set_status(card, "starting")
        if card.expanded:
            self._render_kv(card)
            self._fill_raw(card)

        cmd = [
            runtime_python(),
            str(card.script),
            "--agent-type",
            self.agent_type.get(),
            "--state-dir",
            str(state_dir),
        ]

        def worker() -> None:
            try:
                env = os.environ.copy()
                env["PYTHONUNBUFFERED"] = "1"
                proc = subprocess.Popen(
                    cmd,
                    cwd=str(self.triggers_dir),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    start_new_session=True,
                    env=env,
                )
                assert proc.stdout is not None
                for line in proc.stdout:
                    self.after(0, lambda l=line, c=card: self._ingest_line(c, l))
                code = proc.wait()
                self.after(0, lambda cd=code, c=card: self._finish_worker(c, cd))
            except OSError as exc:
                self.after(0, lambda e=exc, c=card: self._fail_worker(c, e))

        threading.Thread(target=worker, daemon=True).start()

    def _finish_worker(self, card: TriggerCard, code: int) -> None:
        card.has_worker = False
        if card.stop_requested or code == 0 or code < 0:
            self._set_status(card, "stopped")
        else:
            card.banner["_exit_code"] = str(code)
            self._set_status(card, "error")
            self.append_log(f"{card.name} exited with code {code}")

    def _fail_worker(self, card: TriggerCard, exc: OSError) -> None:
        card.has_worker = False
        card.banner["_exit_code"] = "launch failed"
        self._set_status(card, "error")
        self.append_log(f"{card.name}: failed to start: {exc}")

    def stop_trigger(self, card: TriggerCard) -> None:
        state_dir = self.current_state_dir()
        pid_file = pid_file_for(card.script, state_dir)
        pid = read_pid(pid_file)
        card.stop_requested = True
        if pid is None:
            self.append_log(f"{card.name} is not running")
            if not card.has_worker:
                self._set_status(card, "stopped")
            return
        self._set_status(card, "stopping")
        detail = kill_pid(pid, pid_file)
        self.append_log(f"{card.name}: {detail}")
        if not card.has_worker:
            self._set_status(card, "stopped")

    def stop_all(self) -> None:
        stopped = 0
        for card in self.cards.values():
            if card.status in ("starting", "running"):
                self.stop_trigger(card)
                stopped += 1
        if stopped == 0:
            self.append_log("Stop all: nothing running")

    def run_cleanup(self) -> None:
        if self._busy:
            return
        if not messagebox.askyesno(
            "Run cleanup",
            "Stop all running triggers and remove demo files for the selected agent type?",
        ):
            return

        cmd = [
            runtime_python(),
            str(self.cleanup_script),
            "--agent-type",
            self.agent_type.get(),
            "--state-dir",
            str(self.current_state_dir()),
        ]
        self.append_log(f"$ {' '.join(cmd)}")
        self._busy = True

        def worker() -> None:
            removed = 0
            blocked: list[str] = []

            def on_line(text: str) -> None:
                nonlocal removed
                kind = classify_cleanup_line(text)
                if kind == "removed":
                    removed += 1
                elif kind == "blocked":
                    blocked.append(text.strip())
                self.after(0, lambda t=text: self.append_log(t))

            try:
                code, timed_out = run_and_stream(
                    cmd, self.triggers_dir, on_line, CLEANUP_TIMEOUT_SECS
                )
            except OSError as exc:
                self.after(0, lambda: self._cleanup_done(
                    f"cleanup failed to run: {exc}", ok=False))
                return

            if timed_out:
                msg = (
                    f"cleanup timed out after {CLEANUP_TIMEOUT_SECS}s and was "
                    f"stopped; removed {removed} item(s). Some demo files may remain."
                )
                self.after(0, lambda: self._cleanup_done(
                    msg, ok=False, blocked=blocked))
            else:
                msg = f"cleanup finished (exit {code}); removed {removed} item(s)."
                self.after(0, lambda: self._cleanup_done(
                    msg, ok=(code == 0 and not blocked), blocked=blocked))

        threading.Thread(target=worker, daemon=True).start()

    def _cleanup_done(self, msg: str, ok: bool, blocked: list[str] | None = None) -> None:
        blocked = blocked or []
        self.append_log(msg)
        if blocked:
            self.append_log(
                "These need elevated rights -- rerun as: "
                "sudo python3 cleanup.py --agent-type <type>"
            )
            for line in blocked[:20]:
                self.append_log(f"  {line}")
        self._busy = False
        self.refresh_statuses()
        if ok:
            self.append_log("Cleanup complete.")
        else:
            detail = msg
            if blocked:
                detail += "\n\n" + "\n".join(blocked[:10])
                detail += "\n\nThese need root: sudo python3 cleanup.py"
            messagebox.showwarning("Cleanup", detail)


def main() -> int:
    if os.environ.get("EDAMAME_TRIGGER_PANEL_CHECK"):
        # Headless smoke test for the build scripts: exercise discovery without
        # ever constructing a Tk window, and exit 0.
        try:
            discover_triggers(resolve_triggers_dir())
        except SystemExit:
            pass
        return 0

    try:
        triggers_dir = resolve_triggers_dir()
    except SystemExit as exc:
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("Trigger Panel", str(exc))
        return 1

    app = TriggerPanel(triggers_dir)
    app.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
