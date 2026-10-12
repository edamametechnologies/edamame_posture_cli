#!/usr/bin/env python3
"""
Simple macOS control panel for EDAMAME security trigger scripts.

Start / stop each trigger under tests/security/triggers, and run cleanup.py.
For authorized local detection testing only.
"""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import messagebox, scrolledtext, ttk


AGENT_TYPES = ("openclaw", "cursor", "claude_code", "claude_desktop", "codex", "hermes")
DEFAULT_AGENT_TYPE = "openclaw"
POLL_MS = 1500


def app_resources_dir() -> Path:
    """Return Contents/Resources when running inside the macOS .app bundle."""
    here = Path(__file__).resolve().parent
    # .../App.app/Contents/Resources/app.py
    if here.name == "Resources" and (here / "python").is_dir():
        return here
    return here


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


def _relocated_bundled_python() -> Path:
    """Copy the embedded runtime to a path that is not inside the .app."""
    bundled_root = app_resources_dir() / "python"
    dest = Path.home() / "Library" / "Caches" / "edamame-trigger-panel" / "python"
    marker = dest / ".bundle-source"
    source_id = str(bundled_root.resolve())
    python = dest / "bin" / "python3"
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

    The shared .app always uses the Python it shipped with. That runtime is
    copied out of the bundle first, because a process path inside a ``.app``
    is classified as the app reading its own files and the findings are dropped.
    A checkout without the embedded runtime falls back to another interpreter
    whose path is also outside an app bundle.
    """
    bundled = app_resources_dir() / "python" / "bin" / "python3"
    if bundled.is_file():
        relocated = _relocated_bundled_python()
        if _usable_python(relocated):
            return str(relocated.resolve())

    for candidate in (
        Path("/opt/homebrew/bin/python3"),
        Path("/usr/local/bin/python3"),
        Path("/usr/bin/python3"),
    ):
        if _usable_python(candidate):
            return str(candidate.resolve())
    if not _path_inside_app_bundle(Path(sys.executable)):
        return sys.executable
    return sys.executable


def state_dir_for(agent_type: str) -> Path:
    return Path(f"/tmp/edamame_{agent_type}_demo")


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


def process_alive(pid: int) -> bool:
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


def kill_pid(pid, pid_file) -> str:
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


class TriggerPanel(tk.Tk):
    def __init__(self, triggers_dir: Path) -> None:
        super().__init__()
        self.triggers_dir = triggers_dir
        self.triggers = discover_triggers(triggers_dir)
        self.cleanup_script = triggers_dir / "cleanup.py"
        self.row_widgets: dict[str, dict] = {}
        self._busy = False

        self.title("EDAMAME Trigger Panel")
        self.geometry("820x720")
        self.minsize(640, 480)

        self.agent_type = tk.StringVar(value=DEFAULT_AGENT_TYPE)
        self.status_var = tk.StringVar(value=f"Triggers: {triggers_dir}")

        self._build_ui()
        self.after(300, self.refresh_statuses)

    def _build_ui(self) -> None:
        top = ttk.Frame(self, padding=12)
        top.pack(fill=tk.X)

        ttk.Label(top, text="EDAMAME Trigger Panel", font=("", 16, "bold")).pack(
            anchor=tk.W
        )
        ttk.Label(
            top,
            text="Authorized local detection testing only. Stop triggers or run cleanup when finished.",
            wraplength=780,
        ).pack(anchor=tk.W, pady=(4, 8))

        controls = ttk.Frame(top)
        controls.pack(fill=tk.X)
        ttk.Label(controls, text="Agent type").pack(side=tk.LEFT)
        agent = ttk.Combobox(
            controls,
            textvariable=self.agent_type,
            values=AGENT_TYPES,
            state="readonly",
            width=16,
        )
        agent.pack(side=tk.LEFT, padx=(8, 16))
        agent.bind("<<ComboboxSelected>>", lambda _e: self.refresh_statuses())

        ttk.Button(controls, text="Refresh", command=self.refresh_statuses).pack(
            side=tk.LEFT, padx=(0, 8)
        )
        ttk.Button(controls, text="Run cleanup", command=self.run_cleanup).pack(
            side=tk.LEFT
        )

        ttk.Label(top, textvariable=self.status_var, foreground="#555").pack(
            anchor=tk.W, pady=(8, 0)
        )

        body = ttk.Frame(self, padding=(12, 0, 12, 8))
        body.pack(fill=tk.BOTH, expand=True)

        canvas = tk.Canvas(body, highlightthickness=0)
        scrollbar = ttk.Scrollbar(body, orient=tk.VERTICAL, command=canvas.yview)
        self.list_frame = ttk.Frame(canvas)
        self.list_frame.bind(
            "<Configure>",
            lambda _e: canvas.configure(scrollregion=canvas.bbox("all")),
        )
        canvas.create_window((0, 0), window=self.list_frame, anchor=tk.NW)
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        header = ttk.Frame(self.list_frame)
        header.pack(fill=tk.X, pady=(0, 4))
        ttk.Label(header, text="Trigger", width=28).pack(side=tk.LEFT)
        ttk.Label(header, text="Status", width=12).pack(side=tk.LEFT)
        ttk.Label(header, text="Actions").pack(side=tk.LEFT)

        for name, script in self.triggers:
            self._add_trigger_row(name, script)

        log_frame = ttk.LabelFrame(self, text="Output", padding=8)
        log_frame.pack(fill=tk.BOTH, expand=False, padx=12, pady=(0, 12))
        self.log = scrolledtext.ScrolledText(log_frame, height=10, wrap=tk.WORD)
        self.log.pack(fill=tk.BOTH, expand=True)
        self.log.configure(state=tk.DISABLED)

    def _add_trigger_row(self, name: str, script: Path) -> None:
        row = ttk.Frame(self.list_frame)
        row.pack(fill=tk.X, pady=2)

        ttk.Label(row, text=name, width=28).pack(side=tk.LEFT)
        status = ttk.Label(row, text="stopped", width=12, foreground="#666")
        status.pack(side=tk.LEFT)

        start_btn = ttk.Button(
            row, text="Start", width=8, command=lambda s=script: self.start_trigger(s)
        )
        start_btn.pack(side=tk.LEFT, padx=(0, 4))
        stop_btn = ttk.Button(
            row, text="Stop", width=8, command=lambda s=script: self.stop_trigger(s)
        )
        stop_btn.pack(side=tk.LEFT)

        self.row_widgets[script.name] = {
            "script": script,
            "status": status,
            "start": start_btn,
            "stop": stop_btn,
        }

    def append_log(self, text: str) -> None:
        self.log.configure(state=tk.NORMAL)
        self.log.insert(tk.END, text.rstrip() + "\n")
        self.log.see(tk.END)
        self.log.configure(state=tk.DISABLED)

    def current_state_dir(self) -> Path:
        return state_dir_for(self.agent_type.get())

    def refresh_statuses(self) -> None:
        state_dir = self.current_state_dir()
        self.status_var.set(f"Triggers: {self.triggers_dir}  ·  State: {state_dir}")
        for widgets in self.row_widgets.values():
            script: Path = widgets["script"]
            pid_file = pid_file_for(script, state_dir)
            pid = read_pid(pid_file)
            running = pid is not None and process_alive(pid)
            label: ttk.Label = widgets["status"]
            if running:
                label.configure(text=f"running ({pid})", foreground="#0a7a2f")
            else:
                if pid_file is not None and pid_file.exists() and (
                    pid is None or not running
                ):
                    _unlink(pid_file)
                label.configure(text="stopped", foreground="#666")
        self.after(POLL_MS, self.refresh_statuses)

    def start_trigger(self, script: Path) -> None:
        if self._busy:
            return
        state_dir = self.current_state_dir()
        pid_file = pid_file_for(script, state_dir)
        pid = read_pid(pid_file)
        if pid is not None and process_alive(pid):
            messagebox.showinfo("Already running", f"{humanize(script.name)} is already running (pid {pid}).")
            return

        cmd = [
            runtime_python(),
            str(script),
            "--agent-type",
            self.agent_type.get(),
            "--state-dir",
            str(state_dir),
        ]
        self.append_log(f"$ {' '.join(cmd)}")

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
                self.after(
                    0,
                    lambda: self.append_log(
                        f"started {humanize(script.name)} (launcher pid {proc.pid})"
                    ),
                )
                assert proc.stdout is not None
                for line in proc.stdout:
                    self.after(0, lambda l=line: self.append_log(l))
                code = proc.wait()
                self.after(
                    0,
                    lambda: self.append_log(
                        f"{humanize(script.name)} exited with code {code}"
                    ),
                )
            except OSError as exc:
                self.after(0, lambda: self.append_log(f"failed to start: {exc}"))

        threading.Thread(target=worker, daemon=True).start()

    def stop_trigger(self, script: Path) -> None:
        state_dir = self.current_state_dir()
        pid_file = pid_file_for(script, state_dir)
        pid = read_pid(pid_file)
        if pid is None:
            self.append_log(f"{humanize(script.name)} is not running")
            return
        detail = kill_pid(pid, pid_file)
        self.append_log(f"{humanize(script.name)}: {detail}")
        self.refresh_statuses()

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
            try:
                result = subprocess.run(
                    cmd,
                    cwd=str(self.triggers_dir),
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    check=False,
                )
                output = (result.stdout or "") + (result.stderr or "")
                self.after(0, lambda: self.append_log(output or "(no output)"))
                self.after(
                    0,
                    lambda: self.append_log(
                        f"cleanup finished with code {result.returncode}"
                    ),
                )
            except OSError as exc:
                self.after(0, lambda: self.append_log(f"cleanup failed: {exc}"))
            finally:
                def done() -> None:
                    self._busy = False
                    self.refresh_statuses()

                self.after(0, done)

        threading.Thread(target=worker, daemon=True).start()


def main() -> int:
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
