#!/usr/bin/env python3
"""
Trigger ``token_exfiltration`` via a DNS tunnel that RECONNECTS per query
(blind spot BS-5, evasion variant N-04).

Twin of ``trigger_dns_tunnel.py`` with one deliberate difference: instead of
a single *connected* UDP socket whose one 5-tuple session accumulates all the
outbound bytes, this trigger opens a **new UDP socket (new source port) for
every query**. Each datagram therefore lands on its own 5-tuple session whose
per-session ``outbound_bytes`` never reaches the 256 KiB floor -- the exact
shape a real reconnecting DNS-tunnel client (a fresh ephemeral port per lookup)
takes to slip under a per-session volume gate.

Detection path (no anomaly flag required, no single session over the floor):
  many udp/53 sessions to the SAME resolver, each tiny, but sharing one
  (process identity, dst_ip, dst_port=53, protocol=udp)
  -> the detector sums their outbound bytes across sessions
     (``build_session_evidence_catalog`` -> ``dns_ntp_volume_key`` ->
     ``session_looks_non_routine_with_volume``)
  -> the aggregate climbs past ``dns_ntp_non_routine_min_outbound_bytes``
     (262144) with the ``treat_high_volume_dns_ntp_as_non_routine`` gate on
  -> each recent session flips ``is_non_routine_destination`` true
  -> is_recent && is_external && has_sustained_egress && non_routine
  -> L7 open_files carries the credential fixture
  -> token_exfiltration (basis: sustained_sensitive_egress,
     non_routine_destination)

How this stays a faithful "reconnect" demonstration AND a deterministic gate:

  * Every query goes out on a freshly created socket, so the source port --
    and thus the 5-tuple / session -- is different each time. Volume is split
    across many sessions, never concentrated on one.
  * Each socket is held open but capped at ``--per-socket-cap`` bytes (32 KiB,
    an eighth of the floor), so no *single* session ever trips the per-session
    volume gate. Only the cross-session aggregate does. If a bug reverts the
    aggregation, every session is individually below the floor and the finding
    disappears -- which is precisely the regression this scenario guards.
  * A brand-new socket is opened every tick, so there is always a *recent*
    udp/53 session for ``token_exfiltration`` to fire on (a stale pool would
    age out of the sensitive-scan recency window).

Every datagram is a well-formed DNS query (header + QNAME + QTYPE TXT +
QCLASS IN) whose labels carry base32-shaped filler, mimicking iodine /
dnscat2 / Cobalt Strike DNS beacons. The labels target non-existent
subdomains of example.com (IANA reserved) so the traffic is clearly benign
test data.

References: iodine DNS tunnel (per-query reconnect), dnscat2, Cobalt Strike
DNS C2 channel.

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

PID_FILE = "dns_tunnel_reconnect.pid"
CREATED_MARKER = "dns_tunnel_reconnect.created"

# Public DNS resolver. Deliberately a DIFFERENT resolver IP (8.8.8.8) from
# the single-socket dns_tunnel scenario (1.1.1.1), so the reconnect
# finding's destination attribution is provably its own even though both
# scenarios share udp/53. A single always-responsive resolver keeps every
# connected UDP socket healthy (no ICMP port-unreachable resets) so its
# 5-tuple session survives long enough to be attributed and summed.
DEFAULT_TARGET_IP = "8.8.8.8"
DEFAULT_TARGET_PORT = 53

# One well-formed DNS query is ~270 bytes. Split the 262144-byte floor across
# many small sessions: a bulk of sockets that top up to a per-session cap well
# below the floor, plus a fresh socket every tick for recency.
DEFAULT_PER_SOCKET_CAP = 32768   # 32 KiB, an eighth of the 256 KiB floor
DEFAULT_MAX_SOCKETS = 64         # up to ~2 MiB aggregate, ~8x the floor
DEFAULT_NEW_PER_TICK = 2         # brand-new (recent) sessions opened each tick

KEEP_RUNNING = True


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Trigger token_exfiltration via a DNS tunnel that opens a "
                    "new UDP socket per query, so volume splits across many "
                    "udp/53 sessions and only the cross-session aggregate "
                    "trips the non-routine floor."
    )
    p.add_argument("--target-ip", default=DEFAULT_TARGET_IP,
                   help="Public DNS resolver IP (default: 8.8.8.8, distinct from the dns_tunnel scenario's 1.1.1.1)")
    p.add_argument("--target-port", type=int, default=DEFAULT_TARGET_PORT)
    p.add_argument("--interval", type=float, default=0.1,
                   help="Seconds between ticks")
    p.add_argument("--per-socket-cap", type=int, default=DEFAULT_PER_SOCKET_CAP,
                   help="Max outbound bytes per socket/session (kept below the "
                        "256 KiB per-session floor so only the aggregate trips)")
    p.add_argument("--max-sockets", type=int, default=DEFAULT_MAX_SOCKETS,
                   help="Max concurrently open sockets (aggregate = sum of "
                        "their bytes)")
    p.add_argument("--new-per-tick", type=int, default=DEFAULT_NEW_PER_TICK,
                   help="Fresh sockets opened per tick to keep a recent "
                        "udp/53 session available")
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


def raise_fd_limit(target: int) -> None:
    """Lift the soft file-descriptor limit so the socket pool fits. No-op on
    Windows (no RLIMIT_NOFILE); its default handle budget is ample."""
    try:
        import resource
    except ImportError:
        return
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        want = min(max(target, soft), hard) if hard != resource.RLIM_INFINITY else target
        if want > soft:
            resource.setrlimit(resource.RLIMIT_NOFILE, (want, hard))
    except (ValueError, OSError):
        pass


_B32 = "abcdefghijklmnopqrstuvwxyz234567"


def _rand_label(n: int) -> str:
    return "".join(random.choice(_B32) for _ in range(n))


def encode_dns_label(label: str) -> bytes:
    encoded = label.encode("ascii")[:63]
    return struct.pack("B", len(encoded)) + encoded


def build_dns_query(seq: int) -> bytes:
    """A well-formed DNS query (ID, flags=RD, QDCOUNT=1) whose QNAME packs
    ~230 bytes of base32-shaped filler across max-length labels beneath
    example.com, then QTYPE=TXT, QCLASS=IN. ~230 bytes of payload."""
    header = struct.pack("!HHHHHH", seq & 0xFFFF, 0x0100, 1, 0, 0, 0)
    qname = b""
    qname += encode_dns_label(f"t{seq:08x}")
    for _ in range(3):
        qname += encode_dns_label(_rand_label(63))
    qname += encode_dns_label("example")
    qname += encode_dns_label("com")
    qname += b"\x00"
    question = qname + struct.pack("!HH", 16, 1)  # QTYPE=TXT, QCLASS=IN
    return header + question


def new_socket(target_ip: str, target_port: int):
    """Open and connect a fresh UDP socket -- a new source port, hence a new
    5-tuple session. Returns None if the OS refuses (fd pressure)."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect((target_ip, target_port))
        return sock
    except OSError:
        return None


def drain(sock: socket.socket) -> None:
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
        Path(f"~/.ssh/{pfx}_dns_reconnect_key"),
        f"-----BEGIN OPENSSH PRIVATE KEY-----\n{upfx}_DNS_RECONNECT_PAYLOAD\n"
        "-----END OPENSSH PRIVATE KEY-----\n",
        state_dir,
    )

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    pid_file = state_dir / PID_FILE
    pid_file.write_text(f"{os.getpid()}\n", encoding="utf-8")

    max_sockets = max(args.max_sockets, 8)
    per_socket_cap = max(args.per_socket_cap, 4096)
    new_per_tick = max(args.new_per_tick, 1)
    raise_fd_limit(max_sockets + 256)

    # Hold the credential open so flodbadd's live-open-files poll attaches it
    # to every udp/53 session this process owns.
    handle = ssh_key.open("rb")
    handle.read(1)
    handle.seek(0)

    print(f"trigger_dns_tunnel_reconnect.py active  pid={os.getpid()}")
    print(f"  open_path={ssh_key}")
    print(f"  target={args.target_ip}:{args.target_port} (udp/53, NEW socket per query)")
    print(f"  per_socket_cap={per_socket_cap}B (< 262144 floor) max_sockets={max_sockets}")
    print(f"  new_per_tick={new_per_tick} interval={max(args.interval, 0.01)}s "
          f"duration={max(args.duration, 0.0)}s")
    print("  gate=treat_high_volume_dns_ntp_as_non_routine "
          "floor=dns_ntp_non_routine_min_outbound_bytes (262144, AGGREGATED)")
    print("  threat=DNS tunnelling exfiltration, per-query reconnect (iodine/dnscat2)")
    print("  stop_with=Ctrl-C or python3 cleanup.py")
    sys.stdout.flush()

    started = time.monotonic()
    duration = max(args.duration, 0.0)
    interval = max(args.interval, 0.01)
    seq = 0
    aggregate = 0
    # pool entries: [sock, bytes_sent]
    pool: list[list] = []

    try:
        while KEEP_RUNNING:
            if duration > 0 and (time.monotonic() - started) >= duration:
                break

            # 1) Fresh sockets => recent udp/53 sessions for the check to fire on.
            for _ in range(new_per_tick):
                if len(pool) >= max_sockets:
                    # Evict the oldest (its bytes leave the live aggregate).
                    old = pool.pop(0)
                    aggregate -= old[1]
                    try:
                        old[0].close()
                    except OSError:
                        pass
                sock = new_socket(args.target_ip, args.target_port)
                if sock is None:
                    continue
                seq += 1
                try:
                    n = sock.send(build_dns_query(seq))
                    pool.append([sock, n])
                    aggregate += n
                except OSError:
                    try:
                        sock.close()
                    except OSError:
                        pass

            # 2) Top up every open socket toward (but never past) its cap so
            #    the cross-session aggregate climbs while each session stays
            #    below the per-session floor.
            for entry in pool:
                sock, sent = entry
                if sent >= per_socket_cap:
                    continue
                seq += 1
                try:
                    n = sock.send(build_dns_query(seq))
                    entry[1] += n
                    aggregate += n
                except OSError:
                    pass

            for entry in pool:
                drain(entry[0])

            if seq % 500 == 0:
                elapsed = time.monotonic() - started
                per_max = max((e[1] for e in pool), default=0)
                print(f"  queries={seq} sockets={len(pool)} aggregate={aggregate}B "
                      f"max_session={per_max}B elapsed={elapsed:.0f}s")
                sys.stdout.flush()

            time.sleep(interval)
    finally:
        per_max = max((e[1] for e in pool), default=0)
        print(f"  total_queries={seq} final_sockets={len(pool)} "
              f"final_aggregate={aggregate}B max_session={per_max}B")
        for entry in pool:
            try:
                entry[0].close()
            except OSError:
                pass
        try:
            handle.close()
        except OSError:
            pass
        try:
            pid_file.unlink()
        except FileNotFoundError:
            pass

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
