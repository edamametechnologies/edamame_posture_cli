#!/usr/bin/env python3
"""
Trigger ``process_memory_scrape`` (BS-9): one process reaching into another
process's memory / task port.

Real threat: the TanStack ``@tanstack/*`` npm compromise (May 2026) stole the
GitHub Actions OIDC token straight out of ``Runner.Worker`` memory -- the
payload found the worker via ``/proc/*/cmdline``, then read
``/proc/<pid>/maps`` and ``/proc/<pid>/mem`` and regex-extracted the JWT.
Nothing touched disk, no credential file was opened, and the follow-on POST
went to ``registry.npmjs.org``, so every file-anchored check stayed quiet.

This trigger reproduces the *access* safely against a target it owns: it
spawns a sibling helper (a second interpreter that just sleeps, so it is a
non-platform binary the detector cannot exempt), then repeatedly reads that
helper's memory the way the real payload does. Nothing is exfiltrated and
nothing outside the two processes is touched.

Detection path (kernel route):
  Linux   eBPF kprobe on ``ptrace_may_access`` (fires on the attempt, even
          when the kernel then denies it) -> process ring -> core lineage
          table task-access edge
  macOS   Endpoint Security ``NOTIFY_GET_TASK`` / ``GET_TASK_READ`` when a
          task port is obtained (``task_for_pid`` needs root on macOS, so the
          read step re-executes itself under ``sudo -n`` when not root; the
          requester is still this interpreter, not ``sudo``)
  both    -> ``process_memory_scrape`` (HIGH: non-platform requester, target
          is a plain process; CRITICAL when the target is an agent or a
          credential holder -- deliberately not the case here)

Detection path (procfs route, Linux only): the reader holds
``/proc/<other pid>/maps`` open while a session of its own is live, so the
live-open-file enrichment also sees ``/proc/<pid>/{maps,mem}``.

Windows has no driverless source for this signal (``OpenProcess`` auditing
needs a kernel provider), so the scenario is platform-excluded there; this
script exits 0 with a clear message rather than pretending.

Cross-platform: macOS, Linux (Windows: no-op by design).
"""
from __future__ import annotations

import argparse
import ctypes
import os
import platform
import signal
import subprocess
import sys
import time
from pathlib import Path

from _common import AGENT_TYPE_ARG_HELP, resolve_agent_type, state_dir_for

PID_FILE = "process_memory_scrape.pid"
KEEP_RUNNING = True


def handle_signal(signum: int, _frame: object) -> None:
    global KEEP_RUNNING
    print(f"signal {signum}: stopping", flush=True)
    KEEP_RUNNING = False


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Trigger process_memory_scrape by reading a sibling "
                    "process's memory / task port (BS-9 shape)."
    )
    p.add_argument("--duration", type=float, default=120.0)
    p.add_argument("--interval", type=float, default=3.0)
    p.add_argument("--agent-type", default=None, help=AGENT_TYPE_ARG_HELP)
    p.add_argument("--state-dir", type=Path, default=None)
    # Internal: the privileged macOS read step re-executes this script.
    p.add_argument("--task-for-pid", type=int, default=None, help=argparse.SUPPRESS)
    return p.parse_args()


_TARGET_BIN: Path | None = None


def build_plain_sleeper(state_dir: Path) -> Path | None:
    """macOS: ``task_for_pid`` on a hardened-runtime process (python.org
    builds are) is refused even to root without the debugger entitlement,
    and Endpoint Security only reports a task port that was actually
    obtained. A tiny ad-hoc-signed, non-hardened sleeper built on the spot
    with the system compiler is a target root may open. Returns ``None``
    when no compiler is available (the python child is used instead)."""
    global _TARGET_BIN
    if _TARGET_BIN is not None and _TARGET_BIN.exists():
        return _TARGET_BIN
    src = state_dir / "edamame_bs9_sleeper.c"
    out = state_dir / "edamame_bs9_sleeper"
    try:
        src.write_text("#include <unistd.h>\nint main(void){for(;;)sleep(1);return 0;}\n",
                       encoding="utf-8")
        res = subprocess.run(["cc", "-O0", "-o", str(out), str(src)],
                             capture_output=True, text=True, timeout=120, check=False)
        if res.returncode != 0 or not out.exists():
            return None
        out.chmod(0o755)
        _TARGET_BIN = out
        return out
    except (OSError, subprocess.SubprocessError):
        return None


def spawn_target(state_dir: Path) -> subprocess.Popen:
    """A sibling process that sleeps: a non-platform, non-sensitive target
    whose memory we own and may read. macOS prefers a plain compiled
    sleeper (see build_plain_sleeper); elsewhere a second interpreter."""
    if platform.system() == "Darwin":
        sleeper = build_plain_sleeper(state_dir)
        if sleeper is not None:
            return subprocess.Popen(
                [str(sleeper)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
    return subprocess.Popen(
        [sys.executable, "-c", "import time\nwhile True:\n    time.sleep(1)"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


# --------------------------------------------------------------------------
# Linux: /proc/<pid>/maps + /proc/<pid>/mem (the TanStack shape)
# --------------------------------------------------------------------------
def linux_read_memory(pid: int) -> str:
    maps_path = f"/proc/{pid}/maps"
    mem_path = f"/proc/{pid}/mem"
    notes = []
    try:
        with open(maps_path, "r", encoding="utf-8", errors="replace") as maps:
            first = maps.readline().strip()
            # Hold the maps fd open for a moment so the live-open-file sample
            # (procfs route) can see it alongside the kernel route.
            time.sleep(0.5)
        notes.append(f"maps={first[:40]!r}")
    except OSError as exc:
        notes.append(f"maps: {exc.__class__.__name__}")
    try:
        # Read a few bytes at the first mapped region. The open alone goes
        # through ptrace_may_access(ATTACH); a denial is still an attempt.
        start = 0
        try:
            with open(maps_path, "r", encoding="utf-8", errors="replace") as maps:
                rng = maps.readline().split()[0]
                start = int(rng.split("-")[0], 16)
        except (OSError, ValueError, IndexError):
            pass
        with open(mem_path, "rb", buffering=0) as mem:
            if start:
                mem.seek(start)
                data = mem.read(64)
                notes.append(f"mem={len(data)}B")
    except OSError as exc:
        notes.append(f"mem: {exc.__class__.__name__}")
    return " ".join(notes)


# --------------------------------------------------------------------------
# macOS: task_for_pid (Endpoint Security GET_TASK)
# --------------------------------------------------------------------------
def macos_task_for_pid(pid: int) -> str:
    libc = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
    libc.mach_task_self.restype = ctypes.c_uint
    libc.task_for_pid.argtypes = [ctypes.c_uint, ctypes.c_int, ctypes.POINTER(ctypes.c_uint)]
    libc.task_for_pid.restype = ctypes.c_int
    port = ctypes.c_uint(0)
    kr = libc.task_for_pid(libc.mach_task_self(), pid, ctypes.byref(port))
    if kr == 0 and port.value:
        libc.mach_port_deallocate.argtypes = [ctypes.c_uint, ctypes.c_uint]
        libc.mach_port_deallocate(libc.mach_task_self(), port.value)
        return f"task_for_pid ok port={port.value}"
    return f"task_for_pid kern_return={kr}"


def macos_read_step(pid: int) -> str:
    if os.geteuid() == 0:
        return macos_task_for_pid(pid)
    # Re-execute the read step under sudo (passwordless on the CI lanes)
    # so the requester seen by Endpoint Security is this interpreter.
    try:
        out = subprocess.run(
            ["sudo", "-n", sys.executable, os.path.abspath(__file__), "--task-for-pid", str(pid)],
            capture_output=True, text=True, timeout=20, check=False,
        )
        return (out.stdout or out.stderr).strip() or f"sudo rc={out.returncode}"
    except (OSError, subprocess.SubprocessError) as exc:
        return f"sudo step failed: {exc.__class__.__name__}"


def main() -> int:
    args = parse_args()
    if args.task_for_pid is not None:
        print(macos_task_for_pid(args.task_for_pid))
        return 0

    system = platform.system()
    if system == "Windows":
        print("trigger_process_memory_scrape.py: no driverless source on Windows; "
              "scenario is platform-excluded (nothing to do)")
        return 0

    agent_type = resolve_agent_type(args.agent_type)
    state_dir = args.state_dir or state_dir_for(agent_type)
    state_dir.mkdir(parents=True, exist_ok=True)
    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)
    pid_file = state_dir / PID_FILE
    pid_file.write_text(f"{os.getpid()}\n", encoding="utf-8")

    target = spawn_target(state_dir)
    time.sleep(1.0)
    print("trigger_process_memory_scrape.py active")
    print("  check=process_memory_scrape")
    print(f"  requester={sys.executable} pid={os.getpid()}")
    print(f"  target={target.args[0] if isinstance(target.args, list) else target.args} pid={target.pid}")
    print(f"  route={'procfs+kprobe' if system == 'Linux' else 'endpoint_security_get_task'}")
    sys.stdout.flush()

    started = time.monotonic()
    duration = max(args.duration, 0.0)
    interval = max(args.interval, 1.0)
    reads = 0
    try:
        while KEEP_RUNNING:
            if duration > 0 and (time.monotonic() - started) >= duration:
                break
            if target.poll() is not None:
                target = spawn_target(state_dir)
                time.sleep(0.5)
            if system == "Linux":
                note = linux_read_memory(target.pid)
            else:
                note = macos_read_step(target.pid)
            reads += 1
            if reads <= 3 or reads % 20 == 0:
                print(f"  read #{reads}: {note}", flush=True)
            time.sleep(interval)
    finally:
        try:
            target.terminate()
            target.wait(timeout=5)
        except (OSError, subprocess.SubprocessError):
            pass
        try:
            pid_file.unlink()
        except FileNotFoundError:
            pass
    print(f"done: {reads} reads")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
