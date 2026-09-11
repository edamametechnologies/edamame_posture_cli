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

Detection path (Windows): ``OpenProcess`` with a debugger-grade mask
(``VM_READ | VM_WRITE | VM_OPERATION``, the analogue of ``task_for_pid`` /
ptrace attach) on the target -> the kernel's
``Microsoft-Windows-Kernel-Audit-API-Calls`` ETW provider (PsOpenProcess with
target PID and desired-access mask, consumed by flodbadd's audit session) ->
same task-access edge. A ``VM_READ``-only open is the read-only task-port
shape (graded READ, alertable only with corroboration such as an agent or
credential-holder target), which is what real scrapers of ``lsass`` get
caught by.

The target is started detached (re-parented away from this interpreter) and
runs a different executable: the detector drops a process reading its own
child or another instance of its own image unless that target is sensitive.

Cross-platform: macOS, Linux, Windows.
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
    p.add_argument("--sensitive-target", action="store_true",
                   help="name the target after a credential daemon / agent so the "
                        "access grades CRITICAL (EvidenceFloor).")
    # Internal: the privileged macOS read step re-executes this script.
    p.add_argument("--task-for-pid", type=int, default=None, help=argparse.SUPPRESS)
    return p.parse_args()


_TARGET_BIN: Path | None = None


def build_plain_sleeper(state_dir: Path, name: str = "edamame_bs9_sleeper") -> Path | None:
    """macOS: ``task_for_pid`` on a hardened-runtime process (python.org
    builds are) is refused even to root without the debugger entitlement,
    and Endpoint Security only reports a task port that was actually
    obtained. A tiny ad-hoc-signed, non-hardened sleeper built on the spot
    with the system compiler is a target root may open. Returns ``None``
    when no compiler is available (the python child is used instead)."""
    global _TARGET_BIN
    if _TARGET_BIN is not None and _TARGET_BIN.exists() and _TARGET_BIN.name == name:
        return _TARGET_BIN
    src = state_dir / "edamame_bs9_sleeper.c"
    out = state_dir / name
    try:
        src.write_text("#include <unistd.h>\nint main(void){for(;;)sleep(1);return 0;}\n",
                       encoding="utf-8")
        res = subprocess.run(["cc", "-O0", "-o", str(out), str(src)],
                             capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120, check=False)
        if res.returncode != 0 or not out.exists():
            return None
        out.chmod(0o755)
        _TARGET_BIN = out
        return out
    except (OSError, subprocess.SubprocessError):
        return None


class DetachedTarget:
    """A sleeping target that is neither our child nor our image.

    A scraper reads memory it does not own: the detector drops a process
    reading its own child (the parent already holds a full handle from
    CreateProcess / fork) or another instance of its own image (a browser
    and its renderers, an updater and the updater it launched) unless the
    target is an agent or a credential holder. So the target is started
    through an intermediate shell that exits, which re-parents it away from
    us, and runs a different executable: the ad-hoc compiled sleeper on
    macOS, ``sleep`` on Linux, ``ping`` on Windows.
    """

    def __init__(self, label: str, pid: int) -> None:
        self.label = label
        self.pid = pid

    def alive(self) -> bool:
        if platform.system() == "Windows":
            k32 = ctypes.WinDLL("kernel32", use_last_error=True)
            k32.OpenProcess.restype = ctypes.c_void_p
            k32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
            handle = k32.OpenProcess(0x1000, 0, self.pid)  # PROCESS_QUERY_LIMITED_INFORMATION
            if not handle:
                return False
            try:
                code = ctypes.c_uint32(0)
                k32.GetExitCodeProcess.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
                if not k32.GetExitCodeProcess(handle, ctypes.byref(code)):
                    return False
                return code.value == 259  # STILL_ACTIVE
            finally:
                k32.CloseHandle.argtypes = [ctypes.c_void_p]
                k32.CloseHandle(handle)
        try:
            os.kill(self.pid, 0)
            return True
        except OSError:
            return False

    def terminate(self) -> None:
        try:
            if platform.system() == "Windows":
                subprocess.run(["taskkill", "/PID", str(self.pid), "/F"],
                               capture_output=True, check=False, timeout=15)
            else:
                os.kill(self.pid, signal.SIGTERM)
        except (OSError, subprocess.SubprocessError):
            pass


def _posix_detached(argv: list[str]) -> int | None:
    """Start ``argv`` from a throwaway shell that prints the pid and exits."""
    quoted = " ".join(f"'{a}'" for a in argv)
    res = subprocess.run(
        ["sh", "-c", f"{quoted} </dev/null >/dev/null 2>&1 & echo $!"],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30, check=False,
    )
    try:
        return int(res.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return None


# Credential daemons / agents whose memory is a secret store; a scrape of
# one of these is CRITICAL (EvidenceFloor) rather than HIGH. Kept in sync
# with SENSITIVE_TARGET_BASENAMES in the core detector.
_SENSITIVE_BASENAME = {"Windows": "vault.exe", "Darwin": "ssh-agent"}


def _copy_executable(src: Path, dst: Path) -> Path | None:
    try:
        import shutil
        shutil.copy2(src, dst)
        if platform.system() != "Windows":
            dst.chmod(0o755)
        return dst
    except (OSError, ImportError):
        return None


def spawn_target(state_dir: Path, sensitive: bool = False) -> DetachedTarget:
    system = platform.system()
    if system == "Windows":
        image = "ping"
        image_arg = "'-n 3600 127.0.0.1'"
        if sensitive:
            src = Path(os.environ.get("WINDIR", "C:\\Windows")) / "System32" / "PING.EXE"
            dst = _copy_executable(src, state_dir / _SENSITIVE_BASENAME["Windows"])
            if dst is not None:
                image = str(dst)
                image_arg = "'-n 3600 127.0.0.1'"
        res = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             f"(Start-Process '{image}' -ArgumentList {image_arg} "
             "-WindowStyle Hidden -PassThru).Id"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60, check=False,
        )
        try:
            pid = int(res.stdout.strip().splitlines()[-1])
        except (ValueError, IndexError):
            pid = None
        if pid:
            return DetachedTarget(image, pid)
    elif system == "Darwin":
        sleeper = build_plain_sleeper(state_dir, name="ssh-agent" if sensitive else "edamame_bs9_sleeper")
        if sleeper is not None:
            pid = _posix_detached([str(sleeper)])
            if pid:
                return DetachedTarget(str(sleeper), pid)
    else:
        if sensitive:
            src = Path("/bin/sleep")
            if not src.exists():
                src = Path("/usr/bin/sleep")
            dst = _copy_executable(src, state_dir / "ssh-agent")
            if dst is not None:
                pid = _posix_detached([str(dst), "3600"])
                if pid:
                    return DetachedTarget("ssh-agent", pid)
        pid = _posix_detached(["sleep", "3600"])
        if pid:
            return DetachedTarget("sleep", pid)
    # Last resort (no shell / compiler): a second interpreter as a direct
    # child. Same image and our child -- the detector will not grade it.
    child = subprocess.Popen(
        [sys.executable, "-c", "import time\nwhile True:\n    time.sleep(1)"],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    print("  WARNING: detached target unavailable; falling back to a child interpreter",
          flush=True)
    return DetachedTarget(sys.executable, child.pid)


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
# Windows: OpenProcess(PROCESS_VM_READ) + ReadProcessMemory (ETW
# Microsoft-Windows-Kernel-Audit-API-Calls PsOpenProcess, desired-access mask)
# --------------------------------------------------------------------------
def windows_read_memory(pid: int) -> str:
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_VM_OPERATION = 0x0008
    PROCESS_VM_READ = 0x0010
    PROCESS_VM_WRITE = 0x0020
    k32.OpenProcess.restype = ctypes.c_void_p
    k32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
    # Debugger-grade mask: the Windows analogue of task_for_pid / ptrace
    # attach (VM_WRITE | VM_OPERATION alongside VM_READ). A VM_READ-only open
    # is the read-only task-port shape every updater and crash handler
    # takes, graded READ by the sensor and alertable only with corroboration.
    handle = k32.OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
        0,
        pid,
    )
    if not handle:
        return f"OpenProcess failed err={ctypes.get_last_error()}"
    try:
        buf = ctypes.create_string_buffer(64)
        read = ctypes.c_size_t(0)
        k32.ReadProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                          ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
        # The image base of a 64-bit process is a plausible readable page;
        # a failed read is still an OpenProcess with VM_READ, which is the
        # kernel-audited fact.
        ok = k32.ReadProcessMemory(handle, ctypes.c_void_p(0x7FF600000000), buf, 64, ctypes.byref(read))
        return f"OpenProcess ok, ReadProcessMemory={'ok' if ok else 'err'} bytes={read.value}"
    finally:
        k32.CloseHandle.argtypes = [ctypes.c_void_p]
        k32.CloseHandle(handle)


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
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=20, check=False,
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

    agent_type = resolve_agent_type(args.agent_type)
    state_dir = args.state_dir or state_dir_for(agent_type)
    state_dir.mkdir(parents=True, exist_ok=True)
    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)
    pid_file = state_dir / PID_FILE
    pid_file.write_text(f"{os.getpid()}\n", encoding="utf-8")

    target = spawn_target(state_dir, sensitive=args.sensitive_target)
    time.sleep(1.0)
    print("trigger_process_memory_scrape.py active")
    print("  check=process_memory_scrape")
    print(f"  requester={sys.executable} pid={os.getpid()}")
    print(f"  target={target.label} pid={target.pid}")
    route = {"Linux": "procfs+kprobe", "Windows": "etw_kernel_audit_api_calls"}.get(system, "endpoint_security_get_task")
    print(f"  route={route}")
    sys.stdout.flush()

    started = time.monotonic()
    duration = max(args.duration, 0.0)
    interval = max(args.interval, 1.0)
    reads = 0
    try:
        while KEEP_RUNNING:
            if duration > 0 and (time.monotonic() - started) >= duration:
                break
            if not target.alive():
                target = spawn_target(state_dir, sensitive=args.sensitive_target)
                time.sleep(0.5)
            if system == "Linux":
                note = linux_read_memory(target.pid)
            elif system == "Windows":
                note = windows_read_memory(target.pid)
            else:
                note = macos_read_step(target.pid)
            reads += 1
            if reads <= 3 or reads % 20 == 0:
                print(f"  read #{reads}: {note}", flush=True)
            time.sleep(interval)
    finally:
        target.terminate()
        try:
            pid_file.unlink()
        except FileNotFoundError:
            pass
    print(f"done: {reads} reads")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
