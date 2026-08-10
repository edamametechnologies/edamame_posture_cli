#!/usr/bin/env python3
"""
Trigger multi-credential harvest + exfiltration detection.

Real threats: OpenClaw credential co-location / config-secret sprawl
(tracked through issue #14411 and related #9627 context) plus AMOS-
distributing OpenClaw skills. The common runtime shape is an agent or
malicious skill accessing multiple credential stores before exfiltrating data.

This script opens handles to five distinct credential categories
(SSH, AWS, kube, GnuPG, .env) while streaming data to an undeclared
high-port destination.  The multi-credential pattern produces richer
sensitive-path labels than the single-file trigger_cve_token_exfil.py.

Detection path:
  flodbadd iForest  ->  session marked "anomalous" (long-lived high-port flow)
  L7 open_files contains multiple sensitive paths  ->  token_exfiltration
  sensitive-path labels: ssh + aws + kube + gnupg + env

References:
  OpenClaw #14411: credential broker / config-secret co-location
  openclaw/clawhub #571: AMOS-distributing malicious OpenClaw skills

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
    resolve_agent_type,
    state_dir_for,
    upper_prefix_for,
)

PID_FILE = "credential_sprawl.pid"
CREATED_MARKER = "credential_sprawl.created"

DEFAULT_TARGET_HOST = "portquiz.net"
DEFAULT_TARGET_PORT = 63171
DEFAULT_PAYLOAD_BYTES = 4096

KEEP_RUNNING = True


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Trigger multi-credential harvest detection by holding "
                    "multiple credential files open while streaming to a high port."
    )
    p.add_argument("--agent-type", default=None, help=AGENT_TYPE_ARG_HELP)
    p.add_argument("--target-host", default=DEFAULT_TARGET_HOST)
    p.add_argument("--target-ip", default="",
                   help="Pre-resolved IP; skips DNS if set")
    p.add_argument("--target-port", type=int, default=DEFAULT_TARGET_PORT)
    p.add_argument("--interval", type=float, default=0.2,
                   help="Seconds between outbound bursts")
    p.add_argument("--duration", type=float, default=0.0,
                   help="Runtime limit in seconds; 0 = until interrupted")
    p.add_argument("--payload-bytes", type=int, default=DEFAULT_PAYLOAD_BYTES)
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


def resolve_target(target_ip: str, target_host: str) -> str:
    if target_ip.strip():
        return target_ip.strip()
    return socket.gethostbyname(target_host)


def open_sensitive_files(paths: list[Path]) -> list[object]:
    handles = []
    for p in paths:
        if p.exists():
            h = p.open("rb")
            h.read(1)
            h.seek(0)
            handles.append(h)
    return handles


def main() -> int:
    args = parse_args()
    agent_type = resolve_agent_type(args.agent_type)
    if args.state_dir is None:
        args.state_dir = state_dir_for(agent_type)
    pfx = file_prefix_for(agent_type)
    upfx = upper_prefix_for(agent_type)
    state_dir = args.state_dir
    ensure_state_dir(state_dir)

    ssh_key = ensure_demo_sensitive_file(
        Path(f"~/.ssh/{pfx}_sprawl_key"),
        f"-----BEGIN DEMO KEY-----\n{upfx}_CREDENTIAL_SPRAWL\n-----END DEMO KEY-----\n",
        state_dir,
    )
    aws_cred = ensure_demo_sensitive_file(
        Path(f"~/.aws/{pfx}_credentials"),
        f"[default]\naws_access_key_id = AKIA{upfx}_SPRAWL\naws_secret_access_key = {pfx}_sprawl_secret\n",
        state_dir,
    )
    kube_config = ensure_demo_sensitive_file(
        Path(f"~/.kube/{pfx}_config"),
        f"apiVersion: v1\nclusters:\n- cluster:\n    server: https://demo-{agent_type.replace('_', '-')}-sprawl.example.com\n  name: demo\n",
        state_dir,
    )
    gnupg_key = ensure_demo_sensitive_file(
        Path(f"~/.gnupg/{pfx}_sprawl.key"),
        f"-----BEGIN PGP PRIVATE KEY BLOCK-----\n{upfx}_SPRAWL_GPG\n-----END PGP PRIVATE KEY BLOCK-----\n",
        state_dir,
    )
    env_file = ensure_demo_sensitive_file(
        Path(f"~/.env_{pfx}_sprawl"),
        f"SECRET_TOKEN={pfx}_sprawl_value\nAPI_KEY={pfx}_sprawl_api\nDB_PASSWORD={pfx}_sprawl_db\n",
        state_dir,
    )

    open_paths = [ssh_key, aws_cred, kube_config, gnupg_key, env_file]
    psk_path = Path("~/.edamame_psk").expanduser()
    if psk_path.exists():
        open_paths.append(psk_path)

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    pid_file = state_dir / PID_FILE
    pid_file.write_text(f"{os.getpid()}\n", encoding="utf-8")

    payload = b"X" * max(args.payload_bytes, 256)
    target_ip = resolve_target(args.target_ip, args.target_host)
    handles = open_sensitive_files(open_paths)
    started = time.monotonic()
    duration = max(args.duration, 0.0)
    interval = max(args.interval, 0.05)

    print(f"trigger_credential_sprawl.py active  pid={os.getpid()}")
    print(f"  credential_categories=ssh,aws,kube,gnupg,env ({len(open_paths)} files)")
    for p in open_paths:
        print(f"  open_path={p}")
    print(f"  target={target_ip}:{args.target_port} host={args.target_host}")
    print("  threat=OpenClaw credential sprawl (#14411/#9627) + AMOS skills (#571)")
    print("  detection=token_exfiltration with multi-category labels")
    print("  stop_with=Ctrl-C or python3 cleanup.py")
    sys.stdout.flush()

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
            except OSError:
                try:
                    sock.close()
                except OSError:
                    pass
                sock = None
                time.sleep(min(interval, 0.5))
                continue

            # Drain any echoed data so the socket stays open and anomalous longer.
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
        try:
            pid_file.unlink()
        except FileNotFoundError:
            pass

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
