#!/usr/bin/env python3
"""
Trigger the DNS-tunnel exfiltration shape (blind spot BS-6/BS-5).

Holds sensitive credential files open while streaming a sustained,
high-volume run of DNS-shaped UDP datagrams to a public resolver on
port 53. Historically invisible: udp/53 was unconditionally classified
as a routine destination, so `token_exfiltration`'s deterministic
sustained-sensitive-egress path never fired. The CloudModel gate
`treat_high_volume_dns_ntp_as_non_routine` (with its
`dns_ntp_non_routine_min_outbound_bytes` floor) closes that; this
scenario proves the gate end to end.

Detection path (no anomaly flag required):
  single connected UDP socket -> one udp/53 session whose outbound_bytes
  climb past dns_ntp_non_routine_min_outbound_bytes (262144 by default)
  -> session_looks_non_routine() flips true
  -> is_recent && is_external && has_sustained_egress && non_routine
  -> L7 open_files carries the credential fixtures
  -> token_exfiltration (basis: sustained_sensitive_egress,
     non_routine_destination)

Every datagram is a well-formed DNS query (header + QNAME + QTYPE TXT +
QCLASS IN) whose labels carry base32-shaped filler, mimicking iodine /
dnscat2 / Cobalt Strike DNS beacons. The labels target non-existent
subdomains of example.com (IANA reserved) so the traffic is clearly
benign test data. A *single connected* UDP socket is used deliberately
so all datagrams collapse onto one 5-tuple session and its
`outbound_bytes` accumulate past the floor -- reconnecting would split
the volume across sessions and never trip the per-session gate.

References: iodine DNS tunnel, dnscat2, Cobalt Strike DNS C2 channel.

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

PID_FILE = "dns_tunnel.pid"
CREATED_MARKER = "dns_tunnel.created"

# Public DNS resolver. A single, well-known, always-responsive resolver
# keeps the connected UDP socket healthy (no ICMP port-unreachable that
# would reset a connected datagram socket) so its 5-tuple session -- and
# thus its accumulated outbound_bytes -- survives the whole run.
DEFAULT_TARGET_IP = "1.1.1.1"
DEFAULT_TARGET_PORT = 53

# One well-formed DNS query is ~270 bytes of QNAME-heavy payload. To clear
# the 262144-byte floor promptly (and stay well past it as a sustained
# flow) send a small burst each tick.
DEFAULT_BURST = 8

KEEP_RUNNING = True


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Trigger token_exfiltration via a sustained high-volume "
                    "DNS-shaped udp/53 flow while holding credential files open."
    )
    p.add_argument("--target-ip", default=DEFAULT_TARGET_IP,
                   help="Public DNS resolver IP (default: 1.1.1.1)")
    p.add_argument("--target-port", type=int, default=DEFAULT_TARGET_PORT)
    p.add_argument("--interval", type=float, default=0.05,
                   help="Seconds between query bursts")
    p.add_argument("--burst", type=int, default=DEFAULT_BURST,
                   help="DNS queries sent per burst")
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


def open_sensitive_files(paths: list[Path]) -> list[object]:
    handles = []
    for p in paths:
        if p.exists():
            h = p.open("rb")
            h.read(1)
            h.seek(0)
            handles.append(h)
    return handles


def encode_dns_label(label: str) -> bytes:
    encoded = label.encode("ascii")[:63]
    return struct.pack("B", len(encoded)) + encoded


_B32 = "abcdefghijklmnopqrstuvwxyz234567"


def _rand_label(n: int) -> str:
    return "".join(random.choice(_B32) for _ in range(n))


def build_dns_query(seq: int) -> bytes:
    """A well-formed DNS query (ID, flags=RD, QDCOUNT=1) whose QNAME packs
    ~230 bytes of base32-shaped filler across max-length labels beneath
    example.com, then QTYPE=TXT, QCLASS=IN. ~270 bytes on the wire."""
    header = struct.pack("!HHHHHH", seq & 0xFFFF, 0x0100, 1, 0, 0, 0)
    qname = b""
    # Three 63-byte labels of exfil-shaped filler -> ~195 bytes, plus a
    # per-query marker label, then the reserved parent domain.
    qname += encode_dns_label(f"t{seq:08x}")
    for _ in range(3):
        qname += encode_dns_label(_rand_label(63))
    qname += encode_dns_label("example")
    qname += encode_dns_label("com")
    qname += b"\x00"
    question = qname + struct.pack("!HH", 16, 1)  # QTYPE=TXT, QCLASS=IN
    return header + question


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
        Path(f"~/.ssh/{pfx}_dns_tunnel_key"),
        f"-----BEGIN OPENSSH PRIVATE KEY-----\n{upfx}_DNS_TUNNEL_PAYLOAD\n"
        "-----END OPENSSH PRIVATE KEY-----\n",
        state_dir,
    )
    env_path = ensure_demo_sensitive_file(
        Path(f"~/.env_{pfx}_dns_tunnel"),
        f"SECRET_TOKEN={pfx}_dns_tunnel_value\n",
        state_dir,
    )

    open_paths = [ssh_key, env_path]

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    pid_file = state_dir / PID_FILE
    pid_file.write_text(f"{os.getpid()}\n", encoding="utf-8")

    handles = open_sensitive_files(open_paths)
    started = time.monotonic()
    duration = max(args.duration, 0.0)
    interval = max(args.interval, 0.01)
    burst = max(args.burst, 1)

    # A single *connected* UDP socket: fixed src port -> one 5-tuple session
    # whose outbound_bytes accumulate past the non-routine floor.
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect((args.target_ip, args.target_port))
    except OSError as exc:
        print(f"ERROR: cannot connect udp socket to "
              f"{args.target_ip}:{args.target_port}: {exc}", file=sys.stderr)
        return 1

    print(f"trigger_dns_tunnel.py active  pid={os.getpid()}")
    for p in open_paths:
        print(f"  open_path={p}")
    print(f"  target={args.target_ip}:{args.target_port} (udp/53, single connected socket)")
    print(f"  burst={burst} interval={interval}s duration={duration}s")
    print("  gate=treat_high_volume_dns_ntp_as_non_routine "
          "floor=dns_ntp_non_routine_min_outbound_bytes (262144)")
    print("  threat=DNS tunnelling exfiltration (iodine/dnscat2/CS DNS beacon)")
    print("  stop_with=Ctrl-C or python3 cleanup.py")
    sys.stdout.flush()

    seq = 0
    sent_bytes = 0
    try:
        while KEEP_RUNNING:
            if duration > 0 and (time.monotonic() - started) >= duration:
                break
            for _ in range(burst):
                seq += 1
                query = build_dns_query(seq)
                try:
                    sent_bytes += sock.send(query)
                except OSError:
                    # A connected UDP socket rarely errors against a live
                    # resolver; on a transient error keep the SAME socket
                    # (recreating would split the 5-tuple and reset the
                    # accumulated per-session byte count) and retry next tick.
                    break
            # Drain any responses so the socket stays healthy.
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

            if seq % 200 == 0:
                elapsed = time.monotonic() - started
                print(f"  queries={seq} sent_bytes={sent_bytes} elapsed={elapsed:.0f}s")
                sys.stdout.flush()

            time.sleep(interval)
    finally:
        print(f"  total_queries={seq} total_sent_bytes={sent_bytes}")
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
