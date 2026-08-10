#!/usr/bin/env python3
"""
Trigger sandbox-exploitation detection for the CVE-2026-24763 behavior class.

Compiles a small C binary under /tmp (or %TEMP% on Windows) and launches it.
The binary generates sustained UDP egress.  The detector's sandbox heuristic
checks parent_process_path and triggers when it starts with /tmp/.

This script is designed to be run from an OpenClaw agent terminal -- the
Python process itself has normal OpenClaw parent lineage, but the spawned
network child has /tmp ancestry which is exactly what the sandbox_exploitation
check looks for.

Detection path:
  flodbadd L7 -> parent_process_path starts with /tmp/
  -> sandbox_exploitation finding

Reference:
  CVE-2026-24763 / GHSA-mc68-q9jw-2h3v: OpenClaw Docker command
  injection via unsafe PATH handling. This trigger models the post-escape
  runtime shape that EDAMAME detects: a temporary-path process with egress.

Cross-platform: macOS and Linux (requires a C compiler).
On Windows, uses a pure-Python /tmp-lineage fallback via subprocess.
"""

from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from _common import AGENT_TYPE_ARG_HELP, resolve_agent_type, state_dir_for

PID_FILE = "cve_sandbox.pid"
CREATED_MARKER = "cve_sandbox.created"

DEFAULT_TARGET_IP = "1.0.0.1"
DEFAULT_TARGET_HOST = "one.one.one.one"
DEFAULT_TARGET_PORT = 63169
DEFAULT_INTERVAL_MS = 200
DEFAULT_PAYLOAD_BYTES = 1200

KEEP_RUNNING = True

C_SOURCE = r"""
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <process.h>
#pragma comment(lib, "ws2_32.lib")
typedef int socklen_t;
#define getpid _getpid
static void usleep_ms(int ms) { Sleep(ms); }
#else
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
static void usleep_ms(int ms) { usleep((useconds_t)ms * 1000U); }
#endif

static volatile sig_atomic_t keep_running = 1;

static void on_signal(int sig) {
    (void)sig;
    keep_running = 0;
}

int main(int argc, char **argv) {
    if (argc < 5) {
        fprintf(stderr, "usage: %s IP PORT INTERVAL_MS PAYLOAD_BYTES\n", argv[0]);
        return 2;
    }

    const char *ip = argv[1];
    int port       = atoi(argv[2]);
    int interval   = atoi(argv[3]);
    int size       = atoi(argv[4]);

    signal(SIGINT,  on_signal);
    signal(SIGTERM, on_signal);

#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2,2), &wsa);
#endif

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) { perror("socket"); return 1; }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons((unsigned short)port);
    if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1) {
        fprintf(stderr, "bad ip: %s\n", ip);
        return 1;
    }
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror("connect");
        return 1;
    }

    char *buf = malloc((size_t)size);
    if (!buf) return 1;
    memset(buf, 'S', (size_t)size);

    printf("sandbox_probe active  pid=%d  target=%s:%d\n", (int)getpid(), ip, port);
    fflush(stdout);

    while (keep_running) {
        if (send(sock, buf, (size_t)size, 0) < 0) break;
        usleep_ms(interval);
    }

#ifdef _WIN32
    closesocket(sock);
    WSACleanup();
#else
    close(sock);
#endif
    free(buf);
    return 0;
}
"""


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Trigger sandbox_exploitation behavior for CVE-2026-24763 "
                    "by launching a network process from a /tmp parent path."
    )
    p.add_argument("--target-ip", default=DEFAULT_TARGET_IP)
    p.add_argument("--target-host", default=DEFAULT_TARGET_HOST)
    p.add_argument("--target-port", type=int, default=DEFAULT_TARGET_PORT)
    p.add_argument("--interval-ms", type=int, default=DEFAULT_INTERVAL_MS)
    p.add_argument("--payload-bytes", type=int, default=DEFAULT_PAYLOAD_BYTES)
    p.add_argument("--duration", type=float, default=0.0,
                   help="Runtime limit in seconds; 0 = until interrupted")
    p.add_argument("--agent-type", default=None, help=AGENT_TYPE_ARG_HELP)
    p.add_argument("--state-dir", type=Path, default=None)
    return p.parse_args()


def handle_signal(signum: int, _frame: object) -> None:
    global KEEP_RUNNING
    _ = signum
    KEEP_RUNNING = False


def ensure_state_dir(d: Path) -> None:
    d.mkdir(parents=True, exist_ok=True)


def record_created(state_dir: Path, path: Path) -> None:
    marker = state_dir / CREATED_MARKER
    existing = set()
    if marker.exists():
        existing = {l.strip() for l in marker.read_text("utf-8").splitlines() if l.strip()}
    existing.add(str(path))
    marker.write_text("\n".join(sorted(existing)) + "\n", encoding="utf-8")


_WINDOWS_GCC_CANDIDATES = [
    r"C:\msys64\mingw64\bin\gcc.exe",
    r"C:\msys64\ucrt64\bin\gcc.exe",
    r"C:\msys64\usr\bin\gcc.exe",
]


def find_cc() -> str | None:
    cc_env = os.environ.get("CC", "").strip()
    if cc_env:
        try:
            subprocess.check_call(
                [cc_env, "--version"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            return cc_env
        except Exception as exc:
            print(f"CC env ({cc_env}) failed: {exc}", file=sys.stderr)
    candidates: list[str] = ["cc", "gcc", "clang"]
    if sys.platform == "win32":
        candidates.extend(_WINDOWS_GCC_CANDIDATES)
    for candidate in candidates:
        try:
            subprocess.check_call(
                [candidate, "--version"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            return candidate
        except Exception as exc:
            print(f"CC candidate ({candidate}) failed: {exc}", file=sys.stderr)
            continue
    return None


def compile_probe(state_dir: Path) -> Path | None:
    cc = find_cc()
    if cc is None:
        print("compile_probe: no compiler found", file=sys.stderr)
        return None

    src = state_dir / "sandbox_probe.c"
    if sys.platform == "win32":
        binary = state_dir / "sandbox_probe.exe"
    else:
        binary = state_dir / "sandbox_probe"
    src.write_text(C_SOURCE, encoding="utf-8")
    record_created(state_dir, src)

    cmd = [cc, str(src), "-O2", "-o", str(binary)]
    if sys.platform == "win32":
        cmd.append("-lws2_32")

    print(f"compile_probe: running {cmd}", file=sys.stderr)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"compile_probe: compilation failed (rc={result.returncode})", file=sys.stderr)
            print(f"  stdout: {result.stdout[:500]}", file=sys.stderr)
            print(f"  stderr: {result.stderr[:500]}", file=sys.stderr)
            return None
    except Exception as exc:
        print(f"compile_probe: exception: {exc}", file=sys.stderr)
        return None

    binary.chmod(0o755)
    record_created(state_dir, binary)
    return binary


def create_launcher_wrapper(binary: Path, state_dir: Path) -> Path:
    """Create a launcher wrapper in the temp state dir that runs the binary as a child.

    The vuln detector checks l7.parent_process_path for temp-dir patterns.
    The wrapper runs the binary (without exec) so the binary's parent PID
    is the wrapper process, and parent_process_path points at the wrapper
    under %TEMP% or /tmp/. The wrapper waits for the child to exit so it
    stays alive as the parent throughout the binary's lifetime.

    On POSIX we emit a /bin/sh script (sandbox_launcher.sh).  On Windows we
    emit a .cmd batch file that cmd.exe can execute natively.
    """
    if sys.platform == "win32":
        wrapper = state_dir / "sandbox_launcher.cmd"
        wrapper.write_text(
            "@echo off\r\n"
            f'"{binary}" %*\r\n',
            encoding="utf-8",
        )
    else:
        wrapper = state_dir / "sandbox_launcher.sh"
        wrapper.write_text(
            f'#!/bin/sh\n"{binary}" "$@"\n',
            encoding="utf-8",
        )
        wrapper.chmod(0o755)
    record_created(state_dir, wrapper)
    return wrapper


def run_compiled(binary: Path, args: argparse.Namespace, state_dir: Path) -> int:
    wrapper = create_launcher_wrapper(binary, state_dir)
    pid_file = state_dir / PID_FILE
    # On Windows we invoke cmd.exe /c explicitly to execute the .cmd wrapper,
    # because Popen([".cmd", ...]) can still bubble up WinError 193 in some
    # Python distributions.  cmd.exe becomes the wrapper process and the
    # compiled .exe inherits it as parent, giving us the temp-dir lineage.
    if sys.platform == "win32":
        launch_argv = [
            "cmd.exe",
            "/c",
            str(wrapper),
            args.target_ip,
            str(args.target_port),
            str(args.interval_ms),
            str(args.payload_bytes),
        ]
    else:
        launch_argv = [
            str(wrapper),
            args.target_ip,
            str(args.target_port),
            str(args.interval_ms),
            str(args.payload_bytes),
        ]
    proc = subprocess.Popen(
        launch_argv,
        stdout=sys.stdout,
        stderr=sys.stderr,
    )
    pid_file.write_text(f"{proc.pid}\n", encoding="utf-8")
    print(f"trigger_cve_sandbox_escape.py  wrapper_pid={os.getpid()}  child_pid={proc.pid}")
    print(f"  wrapper={wrapper}")
    print(f"  binary={binary}")
    print(f"  target={args.target_ip}:{args.target_port} host={args.target_host}")
    print("  cve=CVE-2026-24763")
    print("  mode=compiled-tmp-parent (wrapper in /tmp/ -> sandbox_exploitation)")
    print("  stop_with=Ctrl-C or python3 cleanup.py")
    sys.stdout.flush()

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    duration = max(args.duration, 0.0)
    started = time.monotonic()
    try:
        while KEEP_RUNNING:
            ret = proc.poll()
            if ret is not None:
                return ret
            if duration > 0 and (time.monotonic() - started) >= duration:
                proc.terminate()
                proc.wait(timeout=5)
                return 0
            time.sleep(0.5)
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        try:
            pid_file.unlink()
        except FileNotFoundError:
            pass

    return 0


def run_python_fallback(args: argparse.Namespace, state_dir: Path) -> int:
    """Pure-Python fallback when no C compiler is available (Windows)."""
    import socket as _socket

    pid_file = state_dir / PID_FILE
    pid_file.write_text(f"{os.getpid()}\n", encoding="utf-8")

    print(f"trigger_cve_sandbox_escape.py active (python fallback)  pid={os.getpid()}")
    print(f"  target={args.target_ip}:{args.target_port} host={args.target_host}")
    print("  cve=CVE-2026-24763")
    print("  mode=python-udp (no /tmp lineage on this platform)")
    print("  stop_with=Ctrl-C or python3 cleanup.py")
    sys.stdout.flush()

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    sock = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
    sock.connect((args.target_ip, args.target_port))
    payload = b"S" * max(args.payload_bytes, 256)

    duration = max(args.duration, 0.0)
    started = time.monotonic()
    interval = args.interval_ms / 1000.0

    try:
        while KEEP_RUNNING:
            if duration > 0 and (time.monotonic() - started) >= duration:
                break
            try:
                sock.send(payload)
            except OSError:
                break
            time.sleep(interval)
    finally:
        sock.close()
        try:
            pid_file.unlink()
        except FileNotFoundError:
            pass

    return 0


def main() -> int:
    args = parse_args()
    agent_type = resolve_agent_type(args.agent_type)
    if args.state_dir is None:
        args.state_dir = state_dir_for(agent_type)
    state_dir = args.state_dir
    ensure_state_dir(state_dir)

    binary = compile_probe(state_dir)
    if binary is not None:
        return run_compiled(binary, args, state_dir)

    print("No C compiler found; using Python fallback", file=sys.stderr)
    return run_python_fallback(args, state_dir)


if __name__ == "__main__":
    raise SystemExit(main())
