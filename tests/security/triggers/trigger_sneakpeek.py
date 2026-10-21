#!/usr/bin/env python3
"""
Trigger the host-side credential-exfiltration detector for the SneakPeek shape.

SneakPeek (Noma Security, 14 Oct 2026; Anthropic fix 17 Aug 2026, CVSS 8.7):
Claude Desktop's HTML preview pane renders attacker HTML that reads local
credentials (~/.ssh, ~/.aws, the Claude token) and sends them out. It is
zero-click -- the agent takes no action; the render engine reads and sends --
so every control INSIDE the agent is blind by construction, and only a host
observer sees read-of-secret followed by a never-seen destination.

This trigger reproduces ONLY that host sequence: a process that stands in for
the render engine holds cold credential files open while generating sustained
outbound egress. It implements no part of the browser exploit (no preview pane,
no 256 KB threshold, no file:// / data: CSP bypass).

The stand-in runs under a render engine's process NAME ("Claude Helper
(Renderer)", Claude Desktop's macOS helper; "claude-renderer" on Linux and
Windows), by copying this interpreter to that name, so the finding names the
render engine rather than an interpreter.

Detection path:
  flodbadd iForest -> session marked anomalous (sustained high-port flow)
  L7 open_files holds cold credential paths -> token_exfiltration, naming the
  render-engine process.

References:
  SneakPeek (Noma Security disclosure, 2026) -- Claude Desktop preview-pane
  credential theft, CVSS 8.7.

Cross-platform: macOS, Linux, Windows.
"""

from __future__ import annotations

import argparse
import os
import platform
import shutil
import signal
import socket
import sys
import time
from pathlib import Path

from _common import (
    AGENT_TYPE_ARG_HELP,
    file_prefix_for,
    prepare_state_dir,
    resolve_agent_type,
    state_dir_for,
    upper_prefix_for,
)

PID_FILE = "sneakpeek.pid"
CREATED_MARKER = "sneakpeek.created"

DEFAULT_TARGET_HOST = "portquiz.net"
DEFAULT_TARGET_PORT = 61942
DEFAULT_PAYLOAD_BYTES = 4096
# The process NAME is the point of the scenario: EDAMAME names the render
# engine, not an interpreter. macOS: Claude Desktop's renderer helper. Linux
# shows at most 15 characters of a process name, so a short stand-in there and
# on Windows (".exe" is added on Windows).
DEFAULT_RENDERER_NAME = (
    "Claude Helper (Renderer)" if platform.system() == "Darwin" else "claude-renderer"
)

# --split: the published attack's own shape, read and send in two processes.
# In a Chromium-based app the main (browser) process serves file:// loads and
# the network-service helper sends; the stand-in parent reads the decoys and
# never opens a socket, its child holds no file and streams out. Names: Claude
# Desktop's main process and its helper on macOS, short stand-ins elsewhere
# (Linux shows 15 characters of a name).
SPLIT_TARGET_PORT = 61943
DEFAULT_MAIN_NAME = "Claude" if platform.system() == "Darwin" else "claude-desktop"
DEFAULT_HELPER_NAME = "Claude Helper" if platform.system() == "Darwin" else "claude-helper"
CHILD_PID_FILE = "sneakpeek_child.pid"
# The sensor remembers a closed credential read for a while
# (sensitive-paths-db credential_opens.open_ttl_secs); re-reading inside that
# window keeps the reads attached for the whole scenario.
SPLIT_REREAD_SECS = 120.0

KEEP_RUNNING = True


def handle_signal(signum: int, _frame: object) -> None:
    global KEEP_RUNNING
    _ = signum
    KEEP_RUNNING = False


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Trigger token_exfiltration for the SneakPeek shape: a render "
                    "engine holding credential files open while streaming out."
    )
    p.add_argument("--target-host", default=DEFAULT_TARGET_HOST)
    p.add_argument("--target-ip", default="", help="Pre-resolved IP; skips DNS if set")
    p.add_argument("--target-port", type=int, default=DEFAULT_TARGET_PORT)
    p.add_argument("--interval", type=float, default=0.2, help="Seconds between bursts")
    p.add_argument("--duration", type=float, default=0.0,
                   help="Runtime limit in seconds; 0 = until interrupted")
    p.add_argument("--payload-bytes", type=int, default=DEFAULT_PAYLOAD_BYTES)
    p.add_argument("--renderer-name", default=DEFAULT_RENDERER_NAME,
                   help="Process name to run the stand-in under (the render engine's name)")
    p.add_argument("--agent-type", default=None, help=AGENT_TYPE_ARG_HELP)
    p.add_argument("--state-dir", type=Path, default=None)
    p.add_argument("--split", action="store_true",
                   help="Two processes: a main process reads three credential types and "
                        "closes them, its network helper child streams out (credential_harvest "
                        "through the parent's reads)")
    p.add_argument("--main-name", default=DEFAULT_MAIN_NAME,
                   help="--split: process name of the main (reading) process")
    p.add_argument("--helper-name", default=DEFAULT_HELPER_NAME,
                   help="--split: process name of the network helper (sending) process")
    # Internal: the renderer-named child that holds the creds and egresses.
    p.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    p.add_argument("--cred-paths", default="", help=argparse.SUPPRESS)
    # Internal (--split): the main process, and the helper it starts.
    p.add_argument("--split-parent", action="store_true", help=argparse.SUPPRESS)
    p.add_argument("--helper-bin", default="", help=argparse.SUPPRESS)
    return p.parse_args()


def ensure_demo_sensitive_file(path: Path, content: str, state_dir: Path) -> Path:
    path = path.expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        return path
    path.write_text(content, encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass
    marker = state_dir / CREATED_MARKER
    existing = set()
    if marker.exists():
        existing = {l.strip() for l in marker.read_text("utf-8").splitlines() if l.strip()}
    existing.add(str(path))
    marker.write_text("\n".join(sorted(existing)) + "\n", encoding="utf-8")
    return path


def resolve_target(target_ip: str, target_host: str) -> str:
    if target_ip.strip():
        return target_ip.strip()
    return socket.gethostbyname(target_host)


def renderer_source() -> Path:
    """The interpreter binary to copy under the render engine's name.

    A macOS framework build's bin/python3.x only re-executes
    Resources/Python.app, so a renamed copy of it still runs as "Python": copy
    the binary it starts. A Windows venv's python.exe is a redirector to the
    base interpreter: copy the base.
    """
    if platform.system() == "Darwin" and getattr(sys, "_framework", ""):
        app_binary = (Path(sys.base_prefix) / "Resources" / "Python.app"
                      / "Contents" / "MacOS" / "Python")
        if app_binary.exists():
            return app_binary
    if platform.system() == "Windows":
        return Path(getattr(sys, "_base_executable", "") or sys.executable)
    return Path(sys.executable)


def renderer_env() -> dict[str, str]:
    """Environment that lets the relocated copy run this interpreter's runtime.

    A standalone runtime (the one the EDAMAME Attack Simulator ships) finds its
    standard library, and on Linux and Windows its shared library, next to its
    own executable; the copy runs from the state dir. No bytecode is written:
    the stdlib may sit inside a signed app bundle.
    """
    env = dict(os.environ)
    env["PYTHONHOME"] = sys.base_prefix
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    system = platform.system()
    if system == "Linux":
        lib_dir = str(Path(sys.base_prefix) / "lib")
        env["LD_LIBRARY_PATH"] = os.pathsep.join(
            p for p in (lib_dir, env.get("LD_LIBRARY_PATH", "")) if p)
    elif system == "Windows":
        exe_dir = str(renderer_source().resolve().parent)
        env["PATH"] = os.pathsep.join(p for p in (exe_dir, env.get("PATH", "")) if p)
    return env


def copy_renderer(state_dir: Path, renderer_name: str) -> Path | None:
    """Copy this interpreter under the render engine's name.

    The copy runs the same stdlib under the renderer's process name, which is
    the name EDAMAME reports. Returns None when the interpreter cannot be
    copied or the copy cannot run; the caller then runs the worker in-process,
    so the detection still fires, under this interpreter's own name.
    """
    src = renderer_source()
    if not src.exists():
        return None
    if platform.system() == "Windows" and not renderer_name.lower().endswith(".exe"):
        renderer_name += ".exe"
    dest = state_dir / renderer_name
    try:
        shutil.copy2(src, dest)
        if platform.system() != "Windows":
            dest.chmod(0o755)
    except OSError:
        return None
    # Record the copy so cleanup.py removes it with the staged creds.
    marker = state_dir / CREATED_MARKER
    existing = set()
    if marker.exists():
        existing = {l.strip() for l in marker.read_text("utf-8").splitlines() if l.strip()}
    existing.add(str(dest))
    marker.write_text("\n".join(sorted(existing)) + "\n", encoding="utf-8")
    # Confirm the copy can run this stdlib before relying on it.
    try:
        import subprocess
        r = subprocess.run([str(dest), "-c", "import socket,sys;print('ok')"],
                           capture_output=True, text=True, timeout=30, check=False,
                           env=renderer_env())
        if r.returncode != 0 or "ok" not in r.stdout:
            return None
    except (OSError, subprocess.SubprocessError):
        return None
    return dest


def run_worker(args: argparse.Namespace) -> int:
    """Hold the credential files open and stream sustained egress."""
    cred_paths = [Path(p) for p in args.cred_paths.split(",") if p]
    handles = []
    for p in cred_paths:
        if p.exists():
            h = p.open("rb")
            h.read(1)
            h.seek(0)
            handles.append(h)

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    payload = b"X" * max(args.payload_bytes, 256)
    target_ip = resolve_target(args.target_ip, args.target_host)
    started = time.monotonic()
    duration = max(args.duration, 0.0)
    interval = max(args.interval, 0.05)

    print(f"sneakpeek worker active  pid={os.getpid()}  exe={sys.executable}")
    for p in cred_paths:
        print(f"  open_path={p}")
    print(f"  target={target_ip}:{args.target_port} host={args.target_host}")
    sys.stdout.flush()

    sock: socket.socket | None = None
    try:
        while KEEP_RUNNING:
            if duration > 0 and (time.monotonic() - started) >= duration:
                break
            if sock is None:
                try:
                    sock = socket.create_connection((target_ip, args.target_port), timeout=10.0)
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                    sock.settimeout(30.0)
                except OSError:
                    time.sleep(min(interval, 1.0))
                    continue
            try:
                sock.sendall(payload)
            except OSError:
                try:
                    sock.close()
                except OSError:
                    pass
                sock = None
                time.sleep(min(interval, 0.5))
                continue
            try:
                sock.setblocking(False)
                try:
                    sock.recv(65536)
                except (BlockingIOError, OSError):
                    pass
                finally:
                    sock.setblocking(True)
                    sock.settimeout(30.0)
            except OSError:
                pass
            time.sleep(interval)
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        for h in handles:
            try:
                h.close()
            except OSError:
                pass
    return 0


def read_decoys(paths: list[Path]) -> int:
    """Open, read and close each decoy: the main process's file:// loads."""
    read = 0
    for p in paths:
        try:
            with p.open("rb") as fh:
                fh.read()
            read += 1
        except OSError:
            pass
    return read


def run_split_parent(args: argparse.Namespace) -> int:
    """The main process: read the decoys, start the helper, never connect."""
    import subprocess
    cred_paths = [Path(p) for p in args.cred_paths.split(",") if p]
    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)
    print(f"sneakpeek split main active  pid={os.getpid()}  exe={sys.executable}")
    print(f"  read {read_decoys(cred_paths)} of {len(cred_paths)} decoys and closed them")
    helper_cmd = [args.helper_bin or sys.executable, __file__, "--worker",
                  "--target-host", args.target_host, "--target-ip", args.target_ip,
                  "--target-port", str(args.target_port), "--interval", str(args.interval),
                  "--duration", str(args.duration), "--payload-bytes", str(args.payload_bytes)]
    child = subprocess.Popen(helper_cmd, env=renderer_env())
    child_pid_file = Path(args.state_dir) / CHILD_PID_FILE if args.state_dir else None
    if child_pid_file is not None:
        child_pid_file.write_text(f"{child.pid}\n", encoding="utf-8")
    print(f"  helper started pid={child.pid} (holds no file, streams to port {args.target_port})")
    sys.stdout.flush()
    last_read = time.monotonic()
    try:
        while KEEP_RUNNING and child.poll() is None:
            time.sleep(1.0)
            if time.monotonic() - last_read >= SPLIT_REREAD_SECS:
                read_decoys(cred_paths)
                last_read = time.monotonic()
        return child.returncode or 0
    finally:
        if child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
        if child_pid_file is not None:
            try:
                child_pid_file.unlink()
            except FileNotFoundError:
                pass


def run_split(args: argparse.Namespace, state_dir: Path, pfx: str, upfx: str) -> int:
    """Stage three credential types and run the main process and its helper."""
    import subprocess
    if args.target_port == DEFAULT_TARGET_PORT:
        args.target_port = SPLIT_TARGET_PORT
    # Three cold credential types (the harvest threshold), secret-bearing
    # names, classified by directory label (ssh / aws / gnupg).
    cred_paths = [
        ensure_demo_sensitive_file(
            Path(f"~/.ssh/{pfx}_sneakpeek_split_id"),
            f"-----BEGIN OPENSSH PRIVATE KEY-----\n{upfx}_SNEAKPEEK_SPLIT\n-----END OPENSSH PRIVATE KEY-----\n",
            state_dir),
        ensure_demo_sensitive_file(
            Path(f"~/.aws/{pfx}_sneakpeek_split_credentials"),
            f"[default]\naws_access_key_id = {upfx}_SNEAKPEEK_SPLIT\naws_secret_access_key = not-a-real-key\n",
            state_dir),
        ensure_demo_sensitive_file(
            Path(f"~/.gnupg/{pfx}_sneakpeek_split.key"),
            f"-----BEGIN PGP PRIVATE KEY BLOCK-----\n{upfx}_SNEAKPEEK_SPLIT\n-----END PGP PRIVATE KEY BLOCK-----\n",
            state_dir),
    ]
    main_bin = copy_renderer(state_dir, args.main_name)
    helper_bin = copy_renderer(state_dir, args.helper_name)
    pid_file = state_dir / PID_FILE

    print("trigger_sneakpeek.py active (--split)")
    print(f"  main_name='{args.main_name}' copied={main_bin is not None}  "
          f"helper_name='{args.helper_name}' copied={helper_bin is not None}")
    for p in cred_paths:
        print(f"  read_path={p}")
    print(f"  target={args.target_host}:{args.target_port}")
    print("  detection=credential_harvest on the helper's traffic, from its parent's reads")
    print("  stop_with=Ctrl-C or python3 cleanup.py")
    sys.stdout.flush()

    parent_args = [__file__, "--split-parent", "--cred-paths", ",".join(str(p) for p in cred_paths),
                   "--helper-bin", str(helper_bin or ""), "--state-dir", str(state_dir),
                   "--target-host", args.target_host, "--target-ip", args.target_ip,
                   "--target-port", str(args.target_port), "--interval", str(args.interval),
                   "--duration", str(args.duration), "--payload-bytes", str(args.payload_bytes)]
    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)
    if main_bin is None:
        # No usable copy: this interpreter is the main process (its own name).
        print("  WARNING: main copy unavailable; running the main process in-process")
        pid_file.write_text(f"{os.getpid()}\n", encoding="utf-8")
        args.cred_paths = ",".join(str(p) for p in cred_paths)
        args.helper_bin = str(helper_bin or "")
        args.state_dir = state_dir
        try:
            return run_split_parent(args)
        finally:
            try:
                pid_file.unlink()
            except FileNotFoundError:
                pass
    parent = subprocess.Popen([str(main_bin)] + parent_args, env=renderer_env())
    pid_file.write_text(f"{parent.pid}\n", encoding="utf-8")
    try:
        while KEEP_RUNNING and parent.poll() is None:
            time.sleep(0.5)
        return parent.returncode or 0
    finally:
        if parent.poll() is None:
            parent.terminate()
            try:
                parent.wait(timeout=10)
            except subprocess.TimeoutExpired:
                parent.kill()
        try:
            pid_file.unlink()
        except FileNotFoundError:
            pass


def main() -> int:
    args = parse_args()

    if args.worker:
        return run_worker(args)
    if args.split_parent:
        return run_split_parent(args)

    agent_type = resolve_agent_type(args.agent_type)
    if args.state_dir is None:
        args.state_dir = state_dir_for(agent_type)
    state_dir = args.state_dir
    prepare_state_dir(state_dir)

    pfx = file_prefix_for(agent_type)
    upfx = upper_prefix_for(agent_type)
    if args.split:
        return run_split(args, state_dir, pfx, upfx)
    # Cold credential stores an attacker reads, in their real home locations.
    # Classified by directory label (ssh / aws), never by these names.
    ssh_cred = ensure_demo_sensitive_file(
        Path(f"~/.ssh/{pfx}_sneakpeek_id"),
        f"-----BEGIN OPENSSH PRIVATE KEY-----\n{upfx}_SNEAKPEEK\n-----END OPENSSH PRIVATE KEY-----\n",
        state_dir,
    )
    aws_cred = ensure_demo_sensitive_file(
        Path(f"~/.aws/{pfx}_sneakpeek_credentials"),
        f"[default]\naws_access_key_id = {upfx}_SNEAKPEEK\naws_secret_access_key = not-a-real-key\n",
        state_dir,
    )
    cred_paths = [ssh_cred, aws_cred]

    worker_args = [
        __file__, "--worker",
        "--cred-paths", ",".join(str(p) for p in cred_paths),
        "--target-host", args.target_host,
        "--target-ip", args.target_ip,
        "--target-port", str(args.target_port),
        "--interval", str(args.interval),
        "--duration", str(args.duration),
        "--payload-bytes", str(args.payload_bytes),
    ]

    import subprocess
    renderer = copy_renderer(state_dir, args.renderer_name)
    pid_file = state_dir / PID_FILE

    print("trigger_sneakpeek.py active")
    print(f"  renderer_name='{args.renderer_name}' copied={renderer is not None}")
    for p in cred_paths:
        print(f"  open_path={p}")
    print("  reference=SneakPeek (Noma Security, 2026) -- Claude Desktop preview-pane theft")
    print("  detection=token_exfiltration, named on the render-engine process")
    print("  stop_with=Ctrl-C or python3 cleanup.py")
    sys.stdout.flush()

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    if renderer is not None:
        child = subprocess.Popen([str(renderer)] + worker_args, env=renderer_env())
        pid_file.write_text(f"{child.pid}\n", encoding="utf-8")
        try:
            return child.wait()
        finally:
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
            try:
                pid_file.unlink()
            except FileNotFoundError:
                pass

    # Fallback: no usable renderer copy (e.g. a relocated standalone
    # interpreter). Run the worker in-process so the detection still fires,
    # under this interpreter's own name.
    print("  WARNING: renderer copy unavailable; running in-process (name not spoofed)")
    pid_file.write_text(f"{os.getpid()}\n", encoding="utf-8")
    args.worker = True
    args.cred_paths = ",".join(str(p) for p in cred_paths)
    try:
        return run_worker(args)
    finally:
        try:
            pid_file.unlink()
        except FileNotFoundError:
            pass


if __name__ == "__main__":
    raise SystemExit(main())
