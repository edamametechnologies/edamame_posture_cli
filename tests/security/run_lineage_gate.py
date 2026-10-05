#!/usr/bin/env python3
"""Kernel process-ancestry gate (HARD, every platform).

The attack-pattern detector binds a process to its kernel ancestry (the
``kernel_exec`` packet: image, ppid, ancestors, nearest AI-agent ancestor)
from the kernel process-event stream: Endpoint Security on macOS, eBPF on
Linux, ETW on Windows. Until 2.0.5 the macOS sensor named every exec'ing
process as its own parent, so no macOS process had an ancestry and the
agent-subtree binding never happened there -- with every scenario of the
security gate still green, because none of them asserted on ancestry.

This gate asserts it directly, against the running daemon:

1. It puts a launcher and a long-lived tool under short names (``edl_p``,
   ``edl_c``; Linux truncates ``comm`` to 15 characters) and starts the
   chain ``this interpreter -> edl_p -> edl_c``: Linux copies ``/bin/sh``
   and ``sleep``, Windows ``cmd.exe`` and ``PING.EXE`` (``ping -n`` is the
   classic wait). macOS kills a copy of any Apple binary at exec (launch
   constraints: SIGKILL), so there the gate compiles a ten-line C program
   that forks and execs exactly like a shell (``cc`` ships with Xcode on
   the macOS runners).
2. It forces a detector tick (``debug_run_attack_pattern_detector_tick``:
   the tick drains the kernel ring into the lineage table; it does not need
   the LLM) and reads ``debug_get_process_lineage`` for ``edl_c``'s pid.
3. It passes only when ``edl_c``'s record names ``edl_p`` as its parent
   (and not itself), its ancestry is ``edl_p`` then this interpreter, and
   the stream's counters show exec events carrying parents and no event
   that named a process as its own parent
   (``process_lineage_self_parent_total`` on the detector status too).

The sensor delivers asynchronously, so step 2 is retried until
``--timeout``; a timeout is a FAILURE, never a pass. ``lineage.json`` is
written up front as a failure and rewritten with the verdict, so a run
killed half-way still reads as a failure to ``check_gate.py``, which fails
the release gate on a missing, unreadable or failed ``lineage.json``.

Usage::

    python3 tests/security/run_lineage_gate.py \\
        --output-dir results/<platform> [--platform <label>] \\
        [--triggers-dir <dir>] [--work-dir <dir>] [--timeout 240]

Environment: ``EDAMAME_CLI`` (path to ``edamame_cli``).

Exit codes: 0 pass, 1 fail (``lineage.json`` says why).
"""

from __future__ import annotations

import argparse
import json
import os
import platform as platform_mod
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

PARENT_NAME = "edl_p"
CHILD_NAME = "edl_c"
# The chain runs at most this long; the gate kills it as soon as it is done.
CHAIN_LIFETIME_S = 600
IS_WINDOWS = os.name == "nt"


# ---------------------------------------------------------------------------
# Result file
# ---------------------------------------------------------------------------


def write_result(path: Path, result: dict) -> None:
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(tmp, path)


def image_stem(path: object) -> str:
    """Lower-case basename of an image path without ``.exe``."""
    text = str(path or "").replace("\\", "/").rstrip("/")
    base = text.rsplit("/", 1)[-1].lower()
    return base[:-4] if base.endswith(".exe") else base


# ---------------------------------------------------------------------------
# Evaluation (pure: unit-tested in test_run_lineage_gate.py)
# ---------------------------------------------------------------------------


def evaluate(
    probe: object,
    status: object,
    *,
    child_pid: int,
    parent_pid: int,
    interpreter_pid: int,
) -> Tuple[Dict[str, bool], List[str]]:
    """The gate's checks over one probe answer and one detector status.

    Returns ``(checks, problems)``: every check by name, and a sentence per
    failed one. All checks must hold for the gate to pass.
    """
    checks: Dict[str, bool] = {}
    problems: List[str] = []

    def check(name: str, ok: bool, problem: str) -> None:
        checks[name] = bool(ok)
        if not ok:
            problems.append(problem)

    probe = probe if isinstance(probe, dict) else {}
    status = status if isinstance(status, dict) else {}
    kernel = probe.get("kernel_exec") if isinstance(probe.get("kernel_exec"), dict) else {}
    lineage = probe.get("lineage") if isinstance(probe.get("lineage"), dict) else {}
    ancestry = kernel.get("ancestry") if isinstance(kernel.get("ancestry"), list) else []
    ancestry = [a for a in ancestry if isinstance(a, dict)]

    check(
        "probe_answered",
        probe.get("success") is True,
        f"debug_get_process_lineage did not answer: {probe.get('error') or probe!r}"[:300],
    )
    check(
        "child_recorded",
        probe.get("found") is True and bool(kernel),
        f"the lineage table holds no record of {CHILD_NAME} (pid {child_pid})",
    )
    check(
        "child_image",
        image_stem(kernel.get("image_path")) == CHILD_NAME,
        f"pid {child_pid} is recorded as {kernel.get('image_path')!r}, not {CHILD_NAME}",
    )
    ppid = kernel.get("ppid")
    check(
        "ppid_not_self",
        ppid is not None and ppid != child_pid,
        f"{CHILD_NAME} (pid {child_pid}) is recorded with ppid {ppid!r}: no parent, or itself",
    )
    check(
        "ppid_is_parent",
        ppid == parent_pid,
        f"{CHILD_NAME}'s ppid is {ppid!r}, expected {PARENT_NAME}'s pid {parent_pid}",
    )
    first = ancestry[0] if len(ancestry) > 0 else {}
    second = ancestry[1] if len(ancestry) > 1 else {}
    check(
        "ancestry_parent",
        first.get("pid") == parent_pid and image_stem(first.get("image_path")) == PARENT_NAME,
        f"ancestry[0] is {first or 'missing'}, expected {PARENT_NAME} (pid {parent_pid})",
    )
    check(
        "ancestry_interpreter",
        second.get("pid") == interpreter_pid
        and "python" in image_stem(second.get("image_path")),
        f"ancestry[1] is {second or 'missing'}, expected this Python interpreter"
        f" (pid {interpreter_pid})",
    )

    def counter(source: dict, key: str) -> Optional[int]:
        value = source.get(key)
        return value if isinstance(value, int) and not isinstance(value, bool) else None

    with_parent = counter(lineage, "exec_with_parent_total")
    self_parent = counter(lineage, "self_parent_total")
    status_self_parent = counter(status, "process_lineage_self_parent_total")
    check(
        "stream_names_parents",
        with_parent is not None and with_parent > 0,
        f"no ingested exec event named a parent (exec_with_parent_total={with_parent!r})",
    )
    check(
        "no_self_parent_events",
        self_parent == 0,
        f"{self_parent!r} exec/fork event(s) named the process as its own parent"
        " (sensor defect; must be 0)",
    )
    check(
        "status_no_self_parent_events",
        status_self_parent == 0,
        "detector status process_lineage_self_parent_total is"
        f" {status_self_parent!r} (absent = daemon predates the counter; must be 0)",
    )
    return checks, problems


def probe_summary(probe: object) -> str:
    """One line on what the lineage table holds for a pid, from a
    ``debug_get_process_lineage`` answer. A failed gate prints it for the
    parent and the interpreter, so the verdict says where the chain broke."""
    if not isinstance(probe, dict) or probe.get("success") is not True:
        error = probe.get("error") if isinstance(probe, dict) else probe
        return f"probe failed: {error!r}"[:300]
    if probe.get("found") is not True:
        return (
            "no record: the sensor never reported this process (it predates the"
            " sensor's session and no rundown named it, or its event was lost)"
        )
    kernel = probe.get("kernel_exec") if isinstance(probe.get("kernel_exec"), dict) else {}
    ancestry = kernel.get("ancestry") if isinstance(kernel.get("ancestry"), list) else []
    pids = [a.get("pid") for a in ancestry if isinstance(a, dict)]
    return (
        f"{image_stem(kernel.get('image_path')) or '?'} ppid={kernel.get('ppid')!r}"
        f" exited={kernel.get('exited')!r} ancestry={pids}"
    )


# ---------------------------------------------------------------------------
# The process chain
# ---------------------------------------------------------------------------


def _windows_process_table() -> List[Tuple[int, int, str]]:
    """``(pid, ppid, exe)`` for every process: Toolhelp32 snapshot through
    ctypes, so finding the child spawns nothing."""
    import ctypes
    from ctypes import wintypes

    class PROCESSENTRY32W(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ProcessID", wintypes.DWORD),
            ("th32DefaultHeapID", ctypes.c_void_p),
            ("th32ModuleID", wintypes.DWORD),
            ("cntThreads", wintypes.DWORD),
            ("th32ParentProcessID", wintypes.DWORD),
            ("pcPriClassBase", ctypes.c_long),
            ("dwFlags", wintypes.DWORD),
            ("szExeFile", ctypes.c_wchar * 260),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    kernel32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    snapshot = kernel32.CreateToolhelp32Snapshot(0x00000002, 0)  # TH32CS_SNAPPROCESS
    if snapshot in (None, wintypes.HANDLE(-1).value):
        raise OSError(f"CreateToolhelp32Snapshot failed: {ctypes.get_last_error()}")
    out: List[Tuple[int, int, str]] = []
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        ok = kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
        while ok:
            out.append((entry.th32ProcessID, entry.th32ParentProcessID, entry.szExeFile))
            ok = kernel32.Process32NextW(snapshot, ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(snapshot)
    return out


def _copy_windows_binary(system32: Path, name: str, dest_dir: Path, new_stem: str) -> Path:
    """Copy a System32 binary under a new name, with its MUI resources (a
    console tool loads its messages from ``<lang>\\<exe>.mui`` next to it)."""
    dest = dest_dir / f"{new_stem}.exe"
    shutil.copyfile(system32 / name, dest)
    for lang_dir in system32.iterdir():
        mui = lang_dir / f"{name}.mui"
        try:
            if lang_dir.is_dir() and mui.is_file():
                (dest_dir / lang_dir.name).mkdir(exist_ok=True)
                shutil.copyfile(mui, dest_dir / lang_dir.name / f"{new_stem}.exe.mui")
        except OSError:
            continue
    return dest


def _posix_tool() -> Tuple[Path, List[str]]:
    """``edl_c`` and how to run it. ``sleep`` unless it is a multi-call
    binary (it would dispatch on the name ``edl_c`` and exit); then a second
    copy of the shell, kept from exec'ing ``sleep`` in place by the ``:``."""
    sleep = shutil.which("sleep") or "/bin/sleep"
    real = os.path.realpath(sleep)
    if os.path.basename(real) == "sleep":
        return Path(real), [str(CHAIN_LIFETIME_S)]
    return Path(_posix_shell()), ["-c", f"sleep {CHAIN_LIFETIME_S}; :"]


# macOS launcher / tool (see the module docstring). `edl_p <child> <pidfile>
# <seconds>` forks, execs the child, records its pid and waits for it;
# `edl_c <seconds>` sleeps.
MACOS_LAUNCHER_C = r"""
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc == 4) {
        pid_t pid = fork();
        if (pid < 0) return 2;
        if (pid == 0) {
            execl(argv[1], argv[1], argv[3], (char *)NULL);
            _exit(127);
        }
        FILE *f = fopen(argv[2], "w");
        if (f) { fprintf(f, "%d\n", (int)pid); fclose(f); }
        int status = 0;
        waitpid(pid, &status, 0);
        return 0;
    }
    if (argc == 2) { sleep((unsigned)atoi(argv[1])); return 0; }
    return 64;
}
"""


def _compile_macos(work: Path, name: str) -> Path:
    compiler = shutil.which("cc") or shutil.which("clang")
    if not compiler:
        raise RuntimeError("no C compiler (cc) to build the macOS launcher")
    source = work / "edl.c"
    source.write_text(MACOS_LAUNCHER_C, encoding="utf-8")
    out = work / name
    proc = subprocess.run(
        [compiler, "-O0", "-o", str(out), str(source)],
        capture_output=True,
        text=True,
        timeout=120,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"cc failed for {name}: {proc.stderr.strip()[-400:]}")
    return out


def _posix_shell() -> str:
    # Linux: /bin/sh is a link to the real shell (dash on Ubuntu).
    return os.path.realpath("/bin/sh")


class Chain:
    """``this interpreter -> edl_p -> edl_c``."""

    def __init__(self, work: Path):
        self.work = work
        self.parent: Optional[subprocess.Popen] = None
        self.child_pid: Optional[int] = None

    @property
    def parent_pid(self) -> int:
        assert self.parent is not None
        return self.parent.pid

    def start(self, wait_s: float = 20.0) -> None:
        self.work.mkdir(parents=True, exist_ok=True)
        if IS_WINDOWS:
            self._start_windows()
            deadline = time.monotonic() + wait_s
            while time.monotonic() < deadline and self.child_pid is None:
                for pid, ppid, exe in _windows_process_table():
                    if ppid == self.parent.pid and image_stem(exe) == CHILD_NAME:
                        self.child_pid = pid
                        break
                else:
                    time.sleep(0.25)
        else:
            pidfile = self._start_posix()
            deadline = time.monotonic() + wait_s
            while time.monotonic() < deadline and self.child_pid is None:
                try:
                    text = pidfile.read_text(encoding="utf-8").strip()
                    self.child_pid = int(text) if text else None
                except (OSError, ValueError):
                    pass
                if self.child_pid is None:
                    time.sleep(0.25)
        if self.child_pid is None:
            raise RuntimeError(
                f"{CHILD_NAME} did not start under {PARENT_NAME} (pid {self.parent.pid},"
                f" exit code {self.parent.poll()!r}) within {wait_s:.0f}s"
            )

    def _start_posix(self) -> Path:
        pidfile = self.work / "edl_c.pid"
        pidfile.unlink(missing_ok=True)
        if sys.platform == "darwin":
            parent_bin = _compile_macos(self.work, PARENT_NAME)
            child_bin = _compile_macos(self.work, CHILD_NAME)
            self.parent = subprocess.Popen(
                [str(parent_bin), str(child_bin), str(pidfile), str(CHAIN_LIFETIME_S)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            return pidfile
        shell = Path(_posix_shell())
        parent_bin = self.work / PARENT_NAME
        # copyfile, not copy2: the copy needs the bytes, not the source's
        # stat flags or ownership.
        shutil.copyfile(shell, parent_bin)
        tool, tool_args = _posix_tool()
        child_bin = self.work / CHILD_NAME
        shutil.copyfile(tool, child_bin)
        for path in (parent_bin, child_bin):
            path.chmod(0o755)
        quoted_args = " ".join(f"'{a}'" for a in tool_args)
        # `&` forces a fork (a shell may exec a lone last command in place,
        # which would leave no edl_p process), `$!` is the child's pid, and
        # `wait` keeps edl_p alive as its parent.
        script = f"'{child_bin}' {quoted_args} & echo $! > '{pidfile}'; wait"
        self.parent = subprocess.Popen(
            [str(parent_bin), "-c", script],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        return pidfile

    def _start_windows(self) -> None:
        system32 = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"
        parent_bin = _copy_windows_binary(system32, "cmd.exe", self.work, PARENT_NAME)
        child_bin = _copy_windows_binary(system32, "PING.EXE", self.work, CHILD_NAME)
        # /s: strip the outer quotes and run the rest; cmd runs the external
        # command as its own child and waits for it.
        command = (
            f'"{parent_bin}" /d /s /c ""{child_bin}" -n {CHAIN_LIFETIME_S} -w 1000'
            f' 127.0.0.1 >NUL"'
        )
        self.parent = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
        )

    def alive(self) -> bool:
        if self.parent is None or self.parent.poll() is not None or self.child_pid is None:
            return False
        if IS_WINDOWS:
            return any(pid == self.child_pid for pid, _, _ in _windows_process_table())
        try:
            os.kill(self.child_pid, 0)
            return True
        except OSError:
            return False

    def stop(self) -> None:
        if self.parent is None:
            return
        try:
            if IS_WINDOWS:
                subprocess.run(
                    ["taskkill", "/F", "/T", "/PID", str(self.parent.pid)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=30,
                )
            else:
                os.killpg(self.parent.pid, signal.SIGKILL)
        except (OSError, subprocess.SubprocessError):
            pass
        try:
            self.parent.wait(timeout=10)
        except subprocess.SubprocessError:
            pass


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--output-dir", required=True)
    ap.add_argument("--platform", default="")
    ap.add_argument(
        "--triggers-dir",
        default=str(Path(__file__).resolve().parent / "triggers"),
        help="Directory holding _edamame_cli.py (default: tests/security/triggers)",
    )
    ap.add_argument(
        "--work-dir", default="", help="Where the renamed binaries go (default: a fresh temp dir)"
    )
    ap.add_argument(
        "--timeout", type=float, default=240.0, help="Seconds to wait for the sensor (default 240)"
    )
    ap.add_argument("--poll-interval", type=float, default=5.0)
    args = ap.parse_args()

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    result_path = out_dir / "lineage.json"
    result: dict = {
        "status": "fail",
        "reason": "the lineage gate did not finish (killed or crashed before its verdict)",
        "platform": args.platform or f"{platform_mod.system()}-{platform_mod.machine()}",
        "interpreter_pid": os.getpid(),
        "interpreter": sys.executable,
        "checks": {},
        "attempts": 0,
    }
    write_result(result_path, result)

    sys.path.insert(0, args.triggers_dir)
    try:
        from _edamame_cli import cli_rpc  # type: ignore
    except Exception as exc:  # noqa: BLE001
        result["reason"] = f"cannot import _edamame_cli from {args.triggers_dir}: {exc}"
        write_result(result_path, result)
        print(f"[lineage] FAIL: {result['reason']}", file=sys.stderr)
        return 1

    work = Path(args.work_dir) if args.work_dir else Path(
        tempfile.mkdtemp(prefix="edamame_lineage_gate_", dir=os.environ.get("RUNNER_TEMP") or None)
    )
    chain = Chain(work)
    started = time.monotonic()
    verdict = 1
    try:
        try:
            chain.start()
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError(
                f"could not start the {PARENT_NAME} -> {CHILD_NAME} chain: {exc}"
            ) from exc
        result["chain"] = {
            "interpreter_pid": os.getpid(),
            "parent_pid": chain.parent_pid,
            "child_pid": chain.child_pid,
            "work_dir": str(work),
        }
        print(
            f"[lineage] chain: python {os.getpid()} -> {PARENT_NAME} {chain.parent_pid}"
            f" -> {CHILD_NAME} {chain.child_pid}",
            file=sys.stderr,
        )
        deadline = started + args.timeout
        problems: List[str] = ["no probe completed"]
        while True:
            result["attempts"] += 1
            attempt = result["attempts"]
            if not chain.alive():
                problems = [f"the chain exited before the sensor reported it (attempt {attempt})"]
                break
            tick: object = None
            try:
                tick = cli_rpc("debug_run_attack_pattern_detector_tick", timeout=300)
            except Exception as exc:  # noqa: BLE001
                tick = {"error": str(exc)}
            probe: object
            status: object
            try:
                probe = cli_rpc(
                    "debug_get_process_lineage",
                    json.dumps({"pid": chain.child_pid}),
                    timeout=60,
                )
            except Exception as exc:  # noqa: BLE001
                probe = {"success": False, "error": str(exc)}
            try:
                status = cli_rpc("get_attack_pattern_detector_status", timeout=60)
            except Exception as exc:  # noqa: BLE001
                status = {"error": str(exc)}
            checks, problems = evaluate(
                probe,
                status,
                child_pid=chain.child_pid,
                parent_pid=chain.parent_pid,
                interpreter_pid=os.getpid(),
            )
            result["checks"] = checks
            result["last_tick"] = tick
            result["last_probe"] = probe
            result["lineage_status"] = {
                k: v
                for k, v in (status.items() if isinstance(status, dict) else [])
                if k.startswith("process_") or k in ("error", "capture_active")
            }
            outcome = "PASS" if not problems else "; ".join(problems)
            print(f"[lineage] attempt {attempt}: {outcome}", file=sys.stderr)
            if not problems:
                verdict = 0
                break
            # A daemon without the probe will not grow one: fail now.
            probe_error = str(probe.get("error", "")) if isinstance(probe, dict) else ""
            if "Command not found" in probe_error:
                problems.insert(0, "the daemon has no debug_get_process_lineage RPC (predates 2.0.5)")
                break
            if time.monotonic() + args.poll_interval >= deadline:
                problems.insert(0, f"timed out after {args.timeout:.0f}s")
                break
            time.sleep(args.poll_interval)
        result["elapsed_s"] = round(time.monotonic() - started, 1)
        if verdict == 0:
            result["status"] = "pass"
            result.pop("reason", None)
        else:
            result["reason"] = "; ".join(problems)
            # Where the chain broke: what the table holds for the parent and
            # for this interpreter (a pid with no record predates the sensor
            # or was lost; a record whose ancestry stops names the step).
            diagnostics = {}
            for label, pid in (("parent", chain.parent_pid), ("interpreter", os.getpid())):
                try:
                    answer = cli_rpc(
                        "debug_get_process_lineage", json.dumps({"pid": pid}), timeout=60
                    )
                except Exception as exc:  # noqa: BLE001
                    answer = {"success": False, "error": str(exc)}
                diagnostics[label] = {
                    "pid": pid,
                    "probe": answer,
                    "summary": probe_summary(answer),
                }
                print(
                    f"[lineage] {label} pid {pid}: {probe_summary(answer)}", file=sys.stderr
                )
            result["diagnostics"] = diagnostics
    except Exception as exc:  # noqa: BLE001
        result["status"] = "fail"
        result["reason"] = f"{type(exc).__name__}: {exc}"
        result["elapsed_s"] = round(time.monotonic() - started, 1)
        verdict = 1
    finally:
        chain.stop()
        if not args.work_dir:
            shutil.rmtree(work, ignore_errors=True)
        write_result(result_path, result)

    if verdict == 0:
        print(
            f"[lineage] PASS: {CHILD_NAME} -> {PARENT_NAME} -> python resolved"
            f" ({result['attempts']} attempt(s))"
        )
    else:
        print(f"[lineage] FAIL: {result['reason']}")
    return verdict


if __name__ == "__main__":
    sys.exit(main())
