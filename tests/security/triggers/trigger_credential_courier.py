#!/usr/bin/env python3
"""
Trigger the credential-misrouting detector: a credential carried to a service
it is never used with.

The courier shape: a process reads one credential and its only external
sessions go to an ordinary web port of a host that has nothing to do with
that credential. An SSH key is used on port 22 (or a forge's SSH host); a
process that holds one and talks only to a web server on port 443 has carried
the key somewhere it is never used. There is no breadth of credential reads,
no unusual port and no traffic burst: the quiet side of a single-key theft.
The s1ngularity compromise of Nx (August 2025) moved what it collected the
same way: over ordinary HTTPS, into a GitHub repository in the victim's own
account.

This trigger reproduces ONLY that host sequence: it holds a decoy SSH key
open (its own file, named with the demo prefix, never a real key) and keeps a
low-rate stream of filler bytes to a public port-test endpoint on port 443.
Nothing read from the decoy is sent.

Detection path:
  L7 open_files holds the decoy key -> the ssh credential class
  (credential_native_services in the params) -> no session of the holder
  reaches port 22 or a forge's SSH host -> credential_misrouted, naming the
  holder process.

Cross-platform: macOS, Linux, Windows.
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
    prepare_state_dir,
    resolve_agent_type,
    state_dir_for,
    upper_prefix_for,
)

PID_FILE = "credential_courier.pid"
CREATED_MARKER = "credential_courier.created"

# A public port-test endpoint on the ordinary HTTPS port: a resolved name on
# a routine port, so neither the destination nor the port is what flags it.
DEFAULT_TARGET_HOST = "portquiz.net"
DEFAULT_TARGET_PORT = 443
# Low rate on purpose: a trickle, not a burst.
DEFAULT_PAYLOAD_BYTES = 1024
DEFAULT_INTERVAL = 1.0

KEEP_RUNNING = True


def handle_signal(signum: int, _frame: object) -> None:
    global KEEP_RUNNING
    _ = signum
    KEEP_RUNNING = False


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Trigger credential_misrouted: a process holding a decoy SSH "
                    "key while talking only to a web host on port 443."
    )
    p.add_argument("--target-host", default=DEFAULT_TARGET_HOST)
    p.add_argument("--target-ip", default="", help="Pre-resolved IP; skips DNS if set")
    p.add_argument("--target-port", type=int, default=DEFAULT_TARGET_PORT)
    p.add_argument("--interval", type=float, default=DEFAULT_INTERVAL,
                   help="Seconds between sends")
    p.add_argument("--duration", type=float, default=0.0,
                   help="Runtime limit in seconds; 0 = until interrupted")
    p.add_argument("--payload-bytes", type=int, default=DEFAULT_PAYLOAD_BYTES)
    p.add_argument("--agent-type", default=None, help=AGENT_TYPE_ARG_HELP)
    p.add_argument("--state-dir", type=Path, default=None)
    return p.parse_args()


def ensure_decoy_key(path: Path, content: str, state_dir: Path) -> Path:
    """Create the decoy key once and record it for cleanup.py.

    An existing file of that name is left as it is and not recorded, so
    cleanup never removes something this trigger did not create.
    """
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


def run_courier(key_path: Path, args: argparse.Namespace) -> int:
    """Hold the decoy key open and trickle filler bytes to the endpoint."""
    handle = key_path.open("rb")
    handle.read(1)
    handle.seek(0)

    payload = b"X" * max(args.payload_bytes, 64)
    target_ip = resolve_target(args.target_ip, args.target_host)
    started = time.monotonic()
    duration = max(args.duration, 0.0)
    interval = max(args.interval, 0.1)

    print(f"credential courier active  pid={os.getpid()}  exe={sys.executable}")
    print(f"  open_path={key_path}")
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
                    time.sleep(min(interval, 2.0))
                    continue
            try:
                sock.sendall(payload)
            except OSError:
                # The endpoint may close a connection that does not speak its
                # protocol: open a new one, the session shape is the same.
                try:
                    sock.close()
                except OSError:
                    pass
                sock = None
                time.sleep(min(interval, 1.0))
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
        try:
            handle.close()
        except OSError:
            pass
    return 0


def main() -> int:
    args = parse_args()

    agent_type = resolve_agent_type(args.agent_type)
    if args.state_dir is None:
        args.state_dir = state_dir_for(agent_type)
    state_dir = args.state_dir
    prepare_state_dir(state_dir)

    pfx = file_prefix_for(agent_type)
    upfx = upper_prefix_for(agent_type)
    # One credential class only (more is credential_harvest's breadth), in
    # its real home location: a key file in ~/.ssh is an SSH credential by
    # its directory, whatever its name.
    key_path = ensure_decoy_key(
        Path(f"~/.ssh/{pfx}_courier_id"),
        f"-----BEGIN OPENSSH PRIVATE KEY-----\n{upfx}_COURIER\n-----END OPENSSH PRIVATE KEY-----\n",
        state_dir,
    )

    pid_file = state_dir / PID_FILE
    pid_file.write_text(f"{os.getpid()}\n", encoding="utf-8")

    print("trigger_credential_courier.py active")
    print(f"  open_path={key_path}")
    print("  reference=s1ngularity (malicious Nx versions, 2025) -- credentials moved over ordinary HTTPS")
    print("  detection=credential_misrouted, named on the holder process")
    print("  stop_with=Ctrl-C or python3 cleanup.py")
    sys.stdout.flush()

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    try:
        return run_courier(key_path, args)
    finally:
        try:
            pid_file.unlink()
        except FileNotFoundError:
            pass


if __name__ == "__main__":
    raise SystemExit(main())
