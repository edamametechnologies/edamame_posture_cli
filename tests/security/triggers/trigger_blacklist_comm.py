#!/usr/bin/env python3
"""
Trigger blacklisted-site communication detection.

Generates sustained TCP egress to a known-blacklisted IP range while holding
a sensitive credential file open.  The same Python process owns both the
network flow and the file handles so that flodbadd's L7 attribution ties
them together.

Detection path:
  flodbadd blacklist DB  ->  session marked "blacklisted"
  L7 open_files contains sensitive path  ->  skill_supply_chain finding

The script targets IPs from well-known sinkhole / threat-intel ranges that
appear in the EDAMAME blacklists-db.  Two targets are tried in sequence so
the demo still works if the first is unreachable.

Designed to run under OpenClaw's process tree (python3 spawned by the
OpenClaw gateway) so parent lineage is a normal desktop app, not /tmp.
"""

from __future__ import annotations

import argparse
import os
import signal
import socket
import sys
import time
from pathlib import Path

from _common import (
    AGENT_TYPE_ARG_HELP,
    file_prefix_for,
    resolve_agent_type,
    state_dir_for,
    upper_prefix_for,
)

PID_FILE = "blacklist_comm.pid"
CREATED_MARKER = "blacklist_comm.created"

BLACKLISTED_IP_TARGETS = [
    ("5.188.11.1", 443),
    ("45.95.232.1", 443),
    ("2.57.122.1", 443),
]

# On non-eBPF platforms flodbadd attributes sockets to PIDs via periodic
# netstat/libproc polling, then scans open files on a separate cadence:
#   Linux  30s, macOS 60s, Windows 120s.
# Connections must stay alive long enough for both the socket-to-PID match
# and the sensitive-file scan to overlap on the same process.
MIN_HOLD_SECS = 10

KEEP_RUNNING = True


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Trigger blacklisted-site communication detection by generating "
                    "TLS egress to a sinkhole while holding credential files open."
    )
    p.add_argument("--interval", type=float, default=2.0,
                   help="Seconds between connection attempts (default: 2)")
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


def ensure_demo_ssh_key(state_dir: Path, pfx: str, upfx: str) -> Path:
    ssh_dir = Path.home() / ".ssh"
    key_path = ssh_dir / f"{pfx}_blacklist_key"
    if key_path.exists():
        return key_path
    ssh_dir.mkdir(parents=True, exist_ok=True)
    key_path.write_text(
        f"-----BEGIN DEMO KEY-----\n{upfx}_BLACKLIST_TRIGGER\n-----END DEMO KEY-----\n",
        encoding="utf-8",
    )
    try:
        key_path.chmod(0o600)
    except OSError:
        pass
    record_created(state_dir, key_path)
    return key_path


def open_sensitive_files(paths: list[Path]) -> list[object]:
    handles = []
    for p in paths:
        if p.exists():
            h = p.open("rb")
            h.read(1)
            h.seek(0)
            handles.append(h)
    return handles


def try_raw_connect(ip: str, port: int, timeout: float = 5.0) -> socket.socket | None:
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        sock.settimeout(timeout)
        return sock
    except OSError:
        return None


def main() -> int:
    args = parse_args()
    agent_type = resolve_agent_type(args.agent_type)
    if args.state_dir is None:
        args.state_dir = state_dir_for(agent_type)
    state_dir = args.state_dir
    ensure_state_dir(state_dir)

    pfx = file_prefix_for(agent_type)
    upfx = upper_prefix_for(agent_type)
    key_path = ensure_demo_ssh_key(state_dir, pfx, upfx)
    psk_path = Path.home() / ".edamame_psk"
    open_paths = [key_path]
    if psk_path.exists():
        open_paths.append(psk_path)

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    pid_file = state_dir / PID_FILE
    pid_file.write_text(f"{os.getpid()}\n", encoding="utf-8")

    handles = open_sensitive_files(open_paths)
    started = time.monotonic()
    duration = max(args.duration, 0.0)
    interval = max(args.interval, 0.5)

    print(f"trigger_blacklist_comm.py active  pid={os.getpid()}")
    for p in open_paths:
        print(f"  open_path={p}")
    print(f"  targets={BLACKLISTED_IP_TARGETS}")
    print("  detection=blacklisted session (FireHOL CIDR match) + skill_supply_chain (if L7 open_files)")
    print("  stop_with=Ctrl-C or python3 cleanup.py")
    sys.stdout.flush()

    try:
        while KEEP_RUNNING:
            if duration > 0 and (time.monotonic() - started) >= duration:
                break

            for ip, port in BLACKLISTED_IP_TARGETS:
                if not KEEP_RUNNING:
                    break
                sock = try_raw_connect(ip, port)
                if sock is not None:
                    try:
                        sock.sendall(b"\x16\x03\x01" + b"\x00" * 64)
                        hold_until = time.monotonic() + MIN_HOLD_SECS
                        while KEEP_RUNNING and time.monotonic() < hold_until:
                            try:
                                sock.sendall(b"X" * 64)
                            except OSError:
                                break
                            time.sleep(1.0)
                    except OSError:
                        pass
                    finally:
                        try:
                            sock.close()
                        except OSError:
                            pass

            time.sleep(interval)
    finally:
        for h in handles:
            try:
                h.close()
            except OSError:
                pass
        try:
            pid_file.unlink()
        except FileNotFoundError:
            pass

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
