#!/usr/bin/env python3
"""
Trigger file_system_tampering detection via FIM (File Integrity Monitoring).

Creates, modifies, and deletes sensitive credential files in monitored
directories (~/.ssh/, ~/.aws/) and suspicious files in temp directories.
The FIM watcher detects these changes and the vulnerability detector
classifies them as file_system_tampering findings.

Detection path:
  FIM watcher  ->  file event with is_sensitive=true  ->  file_system_tampering (CRITICAL)
  FIM watcher  ->  file created in /tmp/              ->  file_system_tampering (HIGH)
  CVE reference: CVE-2025-30066

Cross-platform: macOS, Linux, Windows (detection depends on the EDAMAME FIM
watch paths configured for that platform; the trigger itself uses
Path.expanduser(), tempfile.gettempdir(), and wraps chmod in try/except OSError).

File safety: the fixtures land in real user directories, so each one is created
with O_EXCL and recorded with the sha256 of the bytes written in
`file_events.manifest.json` (state dir). A path that already exists and is not
the trigger's own, unchanged file is refused and reported, never truncated;
cleanup.py removes only the recorded files that still hash to the recorded
value and reports anything else.
"""

from __future__ import annotations

import argparse
import os
import signal
import tempfile
import sys
import time
from pathlib import Path

from _common import (
    AGENT_TYPE_ARG_HELP,
    TriggerFileManifest,
    file_prefix_for,
    resolve_agent_type,
    state_dir_for,
    upper_prefix_for,
)

PID_FILE = "file_events.pid"
# Read by cleanup.py (TRIGGER_MANIFESTS).
MANIFEST = "file_events.manifest.json"

KEEP_RUNNING = True


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Trigger file_system_tampering by creating/modifying sensitive "
                    "files in FIM-monitored directories."
    )
    p.add_argument("--interval", type=float, default=5.0,
                   help="Seconds between file mutation rounds")
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


def text_bytes(content: str) -> bytes:
    # The bytes Path.write_text wrote before: text mode turns "\n" into
    # os.linesep, so the fixtures on disk are unchanged on every platform.
    return content.replace("\n", os.linesep).encode("utf-8")


def create_sensitive_file(path: Path, content: str, manifest: TriggerFileManifest) -> Path:
    path = path.expanduser()
    manifest.write(path, text_bytes(content), 0o600)
    return path


def modify_file(path: Path, content: str, manifest: TriggerFileManifest) -> None:
    if path.exists():
        manifest.write(path, text_bytes(content))


def main() -> int:
    args = parse_args()
    agent_type = resolve_agent_type(args.agent_type)
    if args.state_dir is None:
        args.state_dir = state_dir_for(agent_type)
    state_dir = args.state_dir
    ensure_state_dir(state_dir)

    pfx = file_prefix_for(agent_type)
    upfx = upper_prefix_for(agent_type)

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    manifest = TriggerFileManifest(state_dir / MANIFEST)

    pid_file = state_dir / PID_FILE
    pid_file.write_text(f"{os.getpid()}\n", encoding="utf-8")

    ssh_key = Path(f"~/.ssh/{pfx}_fim_test_key").expanduser()
    aws_cred = Path(f"~/.aws/{pfx}_fim_test_credentials").expanduser()
    env_file = Path(f"~/.env_{pfx}_fim_test").expanduser()
    tmp_file = Path(tempfile.gettempdir()) / f"{pfx}_fim_suspicious_binary"

    sensitive_paths = [ssh_key, aws_cred, env_file]
    all_paths = sensitive_paths + [tmp_file]

    started = time.monotonic()
    duration = max(args.duration, 0.0)
    interval = max(args.interval, 1.0)
    round_num = 0

    print(f"trigger_file_events.py active  pid={os.getpid()}")
    print(f"  cve=CVE-2025-30066")
    print(f"  check=file_system_tampering")
    for p in all_paths:
        print(f"  target={p}")
    print("  stop_with=Ctrl-C or python3 cleanup.py")
    sys.stdout.flush()

    try:
        while KEEP_RUNNING:
            if duration > 0 and (time.monotonic() - started) >= duration:
                break

            round_num += 1

            create_sensitive_file(
                Path(f"~/.ssh/{pfx}_fim_test_key"),
                f"{upfx}_FIM_SSH_KEY_ROUND_{round_num}\n-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n-----END OPENSSH PRIVATE KEY-----\n",
                manifest,
            )
            create_sensitive_file(
                Path(f"~/.aws/{pfx}_fim_test_credentials"),
                f"[default]\naws_access_key_id = {upfx}_FIM_AKID_{round_num}\naws_secret_access_key = {upfx}_FIM_SECRET_{round_num}\n",
                manifest,
            )
            create_sensitive_file(
                Path(f"~/.env_{pfx}_fim_test"),
                f"API_TOKEN={upfx}_FIM_TOKEN_{round_num}\nDB_PASSWORD={upfx}_FIM_DBPASS_{round_num}\n",
                manifest,
            )

            manifest.write(
                tmp_file,
                b"\x7fELF" + b"\x00" * 100 + f"round={round_num}".encode(),
                0o755,
            )

            if round_num > 1:
                modify_file(ssh_key, f"{upfx}_FIM_SSH_KEY_MODIFIED_{round_num}\n", manifest)
                modify_file(aws_cred, f"[default]\naws_access_key_id = {upfx}_FIM_AKID_MOD_{round_num}\n", manifest)

            print(f"  round={round_num} files created/modified")
            sys.stdout.flush()
            time.sleep(interval)
    finally:
        try:
            pid_file.unlink()
        except FileNotFoundError:
            pass

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
