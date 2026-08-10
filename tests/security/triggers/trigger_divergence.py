#!/usr/bin/env python3
"""
Trigger divergence detection by generating sustained UDP egress to several
undeclared public IP:port pairs from a dedicated native probe process.

This avoids the hostname/TCP path that can be invisible to flodbadd on some
macOS setups and instead uses the same native UDP probe pattern that the
session feed already records reliably.
"""

from __future__ import annotations

import argparse
import os
import signal
import socket
import sys
import time
from pathlib import Path

from _common import AGENT_TYPE_ARG_HELP, resolve_agent_type, state_dir_for
from _native_udp_probe import (
    compile_udp_probe,
    ensure_state_dir,
    spawn_udp_children,
    terminate_children,
)

PID_FILE = "divergence.pid"
CREATED_MARKER = "divergence.created"
BINARY_NAME = "divergence_probe"
DEFAULT_INTERVAL_MS = 200
DEFAULT_PAYLOAD_BYTES = 1200

UNUSUAL_DESTINATIONS = [("1.0.0.1", port) for port in range(63169, 63184)]

KEEP_RUNNING = True


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Trigger divergence detection with a native UDP probe "
        "that generates unexplained public egress."
    )
    p.add_argument(
        "--interval-ms",
        type=int,
        default=DEFAULT_INTERVAL_MS,
        help="Milliseconds between outbound probe packets",
    )
    p.add_argument(
        "--payload-bytes",
        type=int,
        default=DEFAULT_PAYLOAD_BYTES,
        help="UDP payload size per packet",
    )
    p.add_argument(
        "--duration",
        type=float,
        default=0.0,
        help="Runtime limit in seconds; 0 = until interrupted",
    )
    p.add_argument(
        "--agent-type",
        default=None,
        help=AGENT_TYPE_ARG_HELP,
    )
    p.add_argument("--state-dir", type=Path, default=None)
    return p.parse_args()


def handle_signal(signum: int, _frame: object) -> None:
    global KEEP_RUNNING
    _ = signum
    KEEP_RUNNING = False


def run_python_fallback(args: argparse.Namespace, state_dir: Path) -> int:
    pid_file = state_dir / PID_FILE
    pid_file.write_text(f"{os.getpid()}\n", encoding="utf-8")

    socks: list[socket.socket] = []
    for ip, port in UNUSUAL_DESTINATIONS:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.connect((ip, port))
            socks.append(sock)
        except OSError:
            continue

    payload = b"D" * max(args.payload_bytes, 256)
    interval = max(args.interval_ms / 1000.0, 0.05)
    duration = max(args.duration, 0.0)
    started = time.monotonic()

    print(f"trigger_divergence.py active (python fallback)  pid={os.getpid()}")
    print(f"  destinations={len(UNUSUAL_DESTINATIONS)} unusual UDP targets (need >5 unexplained)")
    print("  mode=python-udp-fallback")
    print("  detection=divergence engine (unexplained destinations > 5)")
    print("  stop_with=Ctrl-C or python3 cleanup.py")
    sys.stdout.flush()

    try:
        while KEEP_RUNNING:
            if duration > 0 and (time.monotonic() - started) >= duration:
                break
            for sock in socks:
                try:
                    sock.send(payload)
                except OSError:
                    pass
            time.sleep(interval)
    finally:
        for sock in socks:
            try:
                sock.close()
            except OSError:
                pass
        try:
            pid_file.unlink()
        except FileNotFoundError:
            pass

    return 0


def run_compiled(args: argparse.Namespace, state_dir: Path) -> int:
    binary = compile_udp_probe(state_dir, CREATED_MARKER, BINARY_NAME)
    if binary is None:
        print("No C compiler found; using Python UDP fallback", file=sys.stderr)
        return run_python_fallback(args, state_dir)

    pid_file = state_dir / PID_FILE
    pid_file.write_text(f"{os.getpid()}\n", encoding="utf-8")
    children = spawn_udp_children(
        binary,
        UNUSUAL_DESTINATIONS,
        args.interval_ms,
        args.payload_bytes,
    )

    duration = max(args.duration, 0.0)
    started = time.monotonic()

    print(f"trigger_divergence.py active  pid={os.getpid()}")
    print(f"  probe={binary}")
    print(f"  child_pids={[child.pid for child in children]}")
    print(f"  destinations={len(UNUSUAL_DESTINATIONS)} unusual UDP targets (need >5 unexplained)")
    print("  detection=divergence engine (unexplained destinations > 5)")
    print("  scope=process_path */divergence_probe")
    print("  stop_with=Ctrl-C or python3 cleanup.py")
    sys.stdout.flush()

    try:
        while KEEP_RUNNING:
            if duration > 0 and (time.monotonic() - started) >= duration:
                break
            if any(child.poll() is not None for child in children):
                break
            time.sleep(1.0)
    finally:
        terminate_children(children)
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

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)
    return run_compiled(args, state_dir)


if __name__ == "__main__":
    raise SystemExit(main())
