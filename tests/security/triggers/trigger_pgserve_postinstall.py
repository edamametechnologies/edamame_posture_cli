#!/usr/bin/env python3
"""
Trigger pgserve npm postinstall credential-harvest detection.

Real threat: pgserve 1.1.11 / 1.1.12 / 1.1.13 npm compromise (21 April
2026) -- malicious versions of the ``pgserve`` embedded-PostgreSQL
package injected a 1,143-line ``scripts/check-env.js`` that fires from
the ``postinstall`` hook on every ``npm install``.  The payload:

  1. Env-var harvest (TOKEN/SECRET/KEY/PASSWORD regex; AWS_/AZURE_/GCP_/
     NPM_/GITHUB_/DOCKER_/DATABASE_/OPENAI/ANTHROPIC/STRIPE/TWILIO/...).
  2. Filesystem secret collection: ``~/.npmrc``, ``~/.netrc``,
     ``~/.ssh/*``, ``~/.aws/credentials``, ``~/.azure/accessTokens.json``,
     GCP ADC + service-account key, Solana keypair, Ethereum keystore,
     MetaMask / Phantom / Exodus / Atomic Wallet data, Chrome
     ``Login Data`` (decrypted on Linux with the known ``peanuts`` key).
  3. RSA-4096 + AES-256-CBC hybrid encryption of the stolen blob.
  4. Dual-channel exfiltration:
       * primary:   POST https://cjn37-uyaaa-aaaac-qgnva-cai.raw.icp0.io/drop
                    (Internet Computer canister, immune to domain seizure)
       * secondary: POST https://telemetry.api-monitor.com/v1/telemetry
                    (webhook; only if ``TEL_SIGN_KEY`` env var is set)
  5. Supply-chain worm: if ``NPM_TOKEN`` is found, enumerate victim's
     packages and republish each one with ``scripts/check-env.js`` +
     ``scripts/public.pem`` injected + a patch-version bump.
  6. Cross-ecosystem jump: if a PyPI token is found, drop a ``.pth``
     file into the site-packages directory (the Shai-Hulud technique)
     so every Python interpreter invocation re-executes the payload.

Unlike the axios 1.14.1 RAT (see trigger_npm_rat_beacon.py), pgserve
does NOT write a stage-2 binary into /tmp -- the stealer runs directly
from ``node_modules/pgserve/scripts/`` under whatever user ran
``npm install``.  That choice deliberately dodges
``sandbox_exploitation``.  The primary detection path is therefore the
multi-category credential harvest, not process-lineage anomalies.

This script reproduces the steady-state behavior safely:

  * Drops ``check-env.js`` and ``public.pem`` decoys into
    ``<state_dir>/node_modules/pgserve/scripts/`` (mirroring the real
    payload location).
  * Creates demo credentials spanning >=6 sensitive-path label
    categories (ssh, aws, azure, gcp, crypto, browser_store, plus
    unlabeled /.npmrc and /.netrc).
  * Holds those handles open while sending periodic HTTPS-looking
    POSTs to a neutralized lab target, with the real canister /
    telemetry hostnames carried in the Host header so the session
    signature matches the IOC DNS fingerprint (without ever resolving
    or contacting them).

Detection path:
  flodbadd L7  ->  node/python child process with >=3 credential labels open
  vuln detector  ->  credential_harvest finding (CRITICAL)
  flodbadd iForest  ->  novel destination + credential files open
    -> token_exfiltration finding (HIGH)
  if IOCs on threatmodel blacklist  ->  skill_supply_chain finding (HIGH)
  divergence engine  ->  undeclared destination not in behavioral model

IOCs (defanged, NEVER contacted by this script):
  cjn37-uyaaa-aaaac-qgnva-cai[.]raw[.]icp0[.]io  (ICP canister)
  telemetry[.]api-monitor[.]com                  (webhook)

Reference: StepSecurity CanisterSprawl incident report (21 Apr 2026)
           https://www.stepsecurity.io/blog/pgserve-compromised-on-npm-malicious-versions-harvest-credentials

Cross-platform: macOS, Linux, Windows.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
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

PID_FILE = "pgserve_postinstall.pid"
CREATED_MARKER = "pgserve_postinstall.created"

DEFAULT_TARGET_HOST = "portquiz.net"
DEFAULT_TARGET_PORT = 63174

BLOCKED_HOSTS = {
    "cjn37-uyaaa-aaaac-qgnva-cai.raw.icp0.io",
    "telemetry.api-monitor.com",
}

IOC_CANISTER_HOST = "cjn37-uyaaa-aaaac-qgnva-cai.raw.icp0.io"
IOC_WEBHOOK_HOST = "telemetry.api-monitor.com"

MALICIOUS_VERSIONS = ("1.1.11", "1.1.12", "1.1.13")

PACKAGE_JSON_STUB = {
    "name": "pgserve",
    "version": "1.1.13",
    "description": "Embedded PostgreSQL server -- DEMO REPRODUCTION, NOT REAL MALWARE",
    "scripts": {
        "postinstall": "node scripts/check-env.cjs || true",
    },
}

CHECK_ENV_STUB = r"""#!/usr/bin/env node
// DEMO FILE -- NOT the real pgserve payload.
// This file exists purely to place a plausibly named artifact on disk so
// that FIM / path-based detection can observe it.  It performs no network
// activity, does not read any credentials, and exits immediately.
// See: https://www.stepsecurity.io/blog/pgserve-compromised-on-npm-malicious-versions-harvest-credentials
process.exit(0);
"""

PUBLIC_PEM_STUB = """-----BEGIN PUBLIC KEY-----
DEMO_EDAMAME_PGSERVE_TEST_PUBLIC_KEY_PLACEHOLDER_NOT_A_REAL_RSA_KEY
-----END PUBLIC KEY-----
"""

KEEP_RUNNING = True


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Trigger pgserve npm postinstall credential-harvest detection "
                    "by staging a fake check-env.js under node_modules/pgserve/scripts/ "
                    "and holding 6+ credential categories open while posting to a "
                    "neutralized target with the real IOC Host header."
    )
    p.add_argument("--agent-type", default=None, help=AGENT_TYPE_ARG_HELP)
    p.add_argument("--target-host", default=DEFAULT_TARGET_HOST)
    p.add_argument("--target-ip", default="",
                   help="Pre-resolved IP; skips DNS if set")
    p.add_argument("--target-port", type=int, default=DEFAULT_TARGET_PORT)
    p.add_argument("--interval", type=float, default=0.5,
                   help="Seconds between exfil POSTs")
    p.add_argument("--duration", type=float, default=0.0,
                   help="Runtime limit in seconds; 0 = until interrupted")
    p.add_argument("--payload-bytes", type=int, default=4468,
                   help="Exfil payload size (default 4468 matches StepSecurity report)")
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
            raise SystemExit(
                f"Refusing to target blocked IOC host: {blocked}. "
                "This trigger must NEVER contact the real pgserve exfil endpoints."
            )


def resolve_target(target_ip: str, target_host: str) -> str:
    if target_ip.strip():
        return target_ip.strip()
    return socket.gethostbyname(target_host)


def stage_pgserve_payload(state_dir: Path) -> Path:
    """Drop decoy check-env.js, public.pem, and package.json under
    ``<state_dir>/node_modules/pgserve/scripts/`` -- mirroring the
    on-disk layout of the real compromised tarball so detection /
    forensics paths see a realistic scripts/ directory."""
    pkg_root = state_dir / "node_modules" / "pgserve"
    scripts_dir = pkg_root / "scripts"
    scripts_dir.mkdir(parents=True, exist_ok=True)

    check_env = scripts_dir / "check-env.js"
    check_env.write_text(CHECK_ENV_STUB, encoding="utf-8")
    record_created(state_dir, check_env)

    pem = scripts_dir / "public.pem"
    pem.write_text(PUBLIC_PEM_STUB, encoding="utf-8")
    record_created(state_dir, pem)

    package_json = pkg_root / "package.json"
    package_json.write_text(json.dumps(PACKAGE_JSON_STUB, indent=2) + "\n", encoding="utf-8")
    record_created(state_dir, package_json)

    return scripts_dir


def open_sensitive_files(paths: list[Path]) -> list[object]:
    handles = []
    for p in paths:
        if p.exists():
            try:
                h = p.open("rb")
                h.read(1)
                h.seek(0)
                handles.append(h)
            except OSError:
                pass
    return handles


def wallet_data_dir(pfx: str) -> Path:
    """Platform-specific path under a wallet data directory so the
    sensitive-paths DB's crypto label fires for Exodus/Atomic/Phantom."""
    system = platform.system()
    if system == "Darwin":
        return Path("~/Library/Application Support/Exodus/").expanduser() / f"{pfx}_sc_wallet"
    if system == "Windows":
        appdata = os.environ.get("APPDATA", "")
        base = Path(appdata) if appdata else Path("~/AppData/Roaming").expanduser()
        return base / "Exodus" / f"{pfx}_sc_wallet"
    return Path("~/.config/Exodus/").expanduser() / f"{pfx}_sc_wallet"


def atomic_wallet_data_dir(pfx: str) -> Path:
    system = platform.system()
    if system == "Darwin":
        return Path("~/Library/Application Support/atomic/").expanduser() / f"{pfx}_sc_wallet"
    if system == "Windows":
        appdata = os.environ.get("APPDATA", "")
        base = Path(appdata) if appdata else Path("~/AppData/Roaming").expanduser()
        return base / "atomic" / f"{pfx}_sc_wallet"
    return Path("~/.config/atomic/").expanduser() / f"{pfx}_sc_wallet"


def phantom_extension_dir(pfx: str) -> Path:
    """Phantom's Chrome extension ID (bfnaelmomeimhlpmgjnjophhpkkoljpa).
    The Local Extension Settings folder is the highest-value target for
    a Solana-wallet stealer and is matched cross-platform by our
    common_patterns entry."""
    system = platform.system()
    if system == "Darwin":
        base = Path(
            "~/Library/Application Support/Google/Chrome/Default/"
            "Local Extension Settings/bfnaelmomeimhlpmgjnjophhpkkoljpa/"
        ).expanduser()
    elif system == "Windows":
        local = os.environ.get("LOCALAPPDATA", "")
        root = Path(local) if local else Path("~/AppData/Local").expanduser()
        base = root / "Google" / "Chrome" / "User Data" / "Default" / "Local Extension Settings" / "bfnaelmomeimhlpmgjnjophhpkkoljpa"
    else:
        base = Path(
            "~/.config/google-chrome/Default/"
            "Local Extension Settings/bfnaelmomeimhlpmgjnjophhpkkoljpa/"
        ).expanduser()
    return base / f"{pfx}_sc_state.ldb"


def build_exfil_payload(request_num: int, payload_size: int, target_host: str) -> bytes:
    """POST mimicking the pgserve ICP-canister drop request.

    We carry the real IOC hostname in the ``Host:`` header so the session
    signature matches StepSecurity's fingerprint; DNS resolution and the
    TCP connection both go to the lab target (neutralized)."""
    body = os.urandom(payload_size)
    request = (
        f"POST /drop HTTP/1.1\r\n"
        f"Host: {target_host}\r\n"
        f"User-Agent: node-fetch/1.0\r\n"
        f"Content-Type: application/octet-stream\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"X-Request-Id: {request_num}\r\n"
        f"X-Exfil-Target: {IOC_CANISTER_HOST}\r\n"
        f"X-Exfil-Webhook: {IOC_WEBHOOK_HOST}\r\n"
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

    validate_target(args.target_host, args.target_ip)

    scripts_dir = stage_pgserve_payload(state_dir)

    # Credential files spanning the categories the real pgserve payload
    # harvests.  We hit >=6 distinct sensitive-path label categories so
    # ``credential_harvest`` (threshold=3) fires unambiguously.
    ssh_key = ensure_demo_sensitive_file(
        Path(f"~/.ssh/{pfx}_pgserve_key"),
        f"-----BEGIN OPENSSH PRIVATE KEY-----\n{upfx}_PGSERVE_HARVEST\n-----END OPENSSH PRIVATE KEY-----\n",
        state_dir,
    )
    aws_cred = ensure_demo_sensitive_file(
        Path(f"~/.aws/{pfx}_pgserve_credentials"),
        f"[default]\naws_access_key_id = AKIA{upfx}_PGSERVE\naws_secret_access_key = {pfx}_pgserve_secret\n",
        state_dir,
    )
    azure_tokens = ensure_demo_sensitive_file(
        Path(f"~/.azure/{pfx}_pgserve_accessTokens.json"),
        json.dumps({"accessToken": f"{pfx}_pgserve_az_demo", "_clientId": "demo"}),
        state_dir,
    )
    gcp_adc = ensure_demo_sensitive_file(
        Path(f"~/.config/gcloud/{pfx}_pgserve_adc.json"),
        json.dumps({"type": "authorized_user", "client_id": f"{pfx}_pgserve_demo"}),
        state_dir,
    )
    solana_key = ensure_demo_sensitive_file(
        Path(f"~/.config/solana/{pfx}_pgserve_id.json"),
        f"[{','.join(str(i) for i in range(64))}]\n",
        state_dir,
    )
    eth_keystore = ensure_demo_sensitive_file(
        Path(f"~/.ethereum/keystore/{pfx}_pgserve_key.json"),
        json.dumps({"address": f"0x{pfx}_pgserve_demo", "crypto": {"cipher": "aes-128-ctr"}}),
        state_dir,
    )
    exodus_wallet = ensure_demo_sensitive_file(
        wallet_data_dir(pfx),
        f"{upfx}_DEMO_EXODUS_WALLET_BLOB\n",
        state_dir,
    )
    atomic_wallet = ensure_demo_sensitive_file(
        atomic_wallet_data_dir(pfx),
        f"{upfx}_DEMO_ATOMIC_WALLET_BLOB\n",
        state_dir,
    )
    phantom_ldb = ensure_demo_sensitive_file(
        phantom_extension_dir(pfx),
        f"{upfx}_DEMO_PHANTOM_EXT_LDB_BLOB\n",
        state_dir,
    )
    # browser_store label via Chrome "Login Data" basename.
    chrome_login = ensure_demo_sensitive_file(
        state_dir / f"{pfx}_Login Data",
        f"{upfx}_DEMO_CHROME_LOGIN_DATA_SQLITE_STUB\n",
        state_dir,
    )
    npmrc = ensure_demo_sensitive_file(
        Path(f"~/.npmrc_{pfx}_pgserve"),
        f"//registry.npmjs.org/:_authToken=npm_{pfx}_PGSERVE_DEMO_TOKEN\n",
        state_dir,
    )
    netrc = ensure_demo_sensitive_file(
        Path(f"~/.netrc_{pfx}_pgserve"),
        f"machine github.com login {pfx}_demo password {pfx}_pgserve_demo\n",
        state_dir,
    )

    open_paths = [
        ssh_key,
        aws_cred,
        azure_tokens,
        gcp_adc,
        solana_key,
        eth_keystore,
        exodus_wallet,
        atomic_wallet,
        phantom_ldb,
        chrome_login,
        npmrc,
        netrc,
    ]
    psk_path = Path("~/.edamame_psk").expanduser()
    if psk_path.exists():
        open_paths.append(psk_path)

    target_ip = resolve_target(args.target_ip, args.target_host)
    duration = max(args.duration, 0.0)
    interval = max(args.interval, 0.2)
    payload_bytes = max(args.payload_bytes, 64)

    categories = "ssh,aws,azure,gcp,crypto(solana+eth+exodus+atomic+phantom),browser_store,npmrc,netrc"
    print(f"trigger_pgserve_postinstall.py active  pid={os.getpid()}")
    print(f"  payload_staged_at={scripts_dir}")
    print(f"  credential_categories={categories} ({len(open_paths)} files)")
    for p in open_paths:
        print(f"  open_path={p}")
    print(f"  target={target_ip}:{args.target_port} host={args.target_host}")
    print(f"  threat=pgserve {'/'.join(MALICIOUS_VERSIONS)} npm supply chain (21 Apr 2026)")
    print("  reference=StepSecurity CanisterSprawl incident report")
    print(f"  ioc_canister={IOC_CANISTER_HOST} (DEFANGED -- carried in Host header only)")
    print(f"  ioc_webhook={IOC_WEBHOOK_HOST} (DEFANGED -- carried in Host header only)")
    print("  detection=credential_harvest(CRITICAL) + token_exfiltration(HIGH) + divergence")
    print(f"  mode=postinstall-steady-state HTTP POST every {interval}s payload={payload_bytes}B")
    print("  stop_with=Ctrl-C or python3 cleanup.py")
    sys.stdout.flush()

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    pid_file = state_dir / PID_FILE
    pid_file.write_text(f"{os.getpid()}\n", encoding="utf-8")

    handles = open_sensitive_files(open_paths)
    started = time.monotonic()
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
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                    sock.settimeout(10.0)
                except OSError:
                    time.sleep(min(interval, 1.0))
                    continue

            request_num += 1
            payload = build_exfil_payload(request_num, payload_bytes, IOC_CANISTER_HOST)
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

            try:
                sock.setblocking(False)
                try:
                    sock.recv(65536)
                except (BlockingIOError, OSError):
                    pass
                finally:
                    sock.setblocking(True)
                    sock.settimeout(10.0)
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
