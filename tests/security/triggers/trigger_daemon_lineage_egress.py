#!/usr/bin/env python3
"""
Trigger a divergence verdict for the XZ Utils (CVE-2024-3094) *exploitation-time*
shape: a process whose parent is a network-facing system daemon makes outbound
egress that the behavioral model forbids for that lineage.

What this actually tests, and what it does not
----------------------------------------------
This trigger installs a small self-contained binary into a system daemon
location (``/usr/sbin/<pfx>_xz_sshd_standin``) and has it fork/exec a child that
generates sustained UDP egress. The planted behavioral model lists the stand-in
under ``not_expected_parent_paths``, so the divergence engine records a
``correlation:not_expected`` observation reading::

    Parent path '/usr/sbin/<pfx>_xz_sshd_standin' matched forbidden pattern '...'

which sets the deterministic divergence floor.

**The stand-in is not sshd.** This exercises the *shape* of the XZ exploitation
step -- a process located in a system-daemon directory parenting egress the plan
forbids -- not the CVE itself. Driving real ``sshd`` would require mutating host
SSH configuration and is out of scope. Nothing here detects the backdoor at
rest, in the build, or in the tarball, and nothing here validates code
signatures: ``flodbadd::sessions::SessionL7`` carries no signature field and
nothing in core computes one, so the "unsigned code path" half of the original
incident claim has no sensor behind it at all.

Why the stand-in lives in a system location and not /tmp
--------------------------------------------------------
``divergence_engine::filter_effective_not_expected_matches`` drops a parent-path
match when the parent path sits in a soft-trusted location AND the parent's
basename passes ``looks_like_benign_system_tool`` -- a five-name allowlist
(``ntpd``, ``chronyd``, ``systemd-resolved``, ``systemd-timesyncd``,
``resolvectl``). ``sshd`` is not on that list, so a daemon-located parent named
like sshd survives the filter and reaches the floor. Installing into a
soft-trusted prefix tests that asymmetry deliberately. Installing to ``/tmp``
would pass trivially, prove nothing about the filter, and duplicate
``trigger_cve_sandbox_escape.py`` -- so there is deliberately no /tmp fallback.

Install location, per platform:

* Linux:  ``/usr/sbin/<pfx>_xz_sshd_standin``
* macOS:  ``/usr/local/bin/<pfx>_xz_sshd_standin``

macOS cannot use ``/usr/sbin``: it carries the SIP ``restricted`` flag, so even
root gets EPERM there (``ls -ldO /usr/sbin``). ``/usr/local/bin`` is the
documented fallback and is equally a soft-trusted prefix per
``path_is_soft_trusted_tooling_location``, and is not vetoed by
``path_is_suspicious_runtime_location``, so the filter assertion is identical on
both platforms. The model forbids both patterns.

Detection path:
  flodbadd L7 -> l7.parent_process_path == /usr/sbin/<pfx>_xz_sshd_standin
  -> divergence correlation, in scope via scope_process_paths */<pfx>_xz_egress
  -> not_expected_parent_paths match -> floor_divergence
  -> deterministic_verdict == DIVERGENCE

Elevation: installing into ``/usr/sbin`` needs root. The security suite already
runs elevated. If the copy fails this script exits non-zero with a distinct
message and does NOT degrade to a writable path -- a silent fallback to /tmp
would turn the scenario into a tautological pass.

Platforms: Linux and macOS. Windows is not implemented (needs a
``%WINDIR%\\System32`` write plus ETW parent attribution); the scenario is
platform-excluded there.
"""

from __future__ import annotations

import argparse
import os
import platform
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

from _common import AGENT_TYPE_ARG_HELP, file_prefix_for, resolve_agent_type, state_dir_for
from _native_udp_probe import compile_udp_probe, ensure_state_dir, find_cc, record_created

PID_FILE = "daemon_lineage_egress.pid"
CREATED_MARKER = "daemon_lineage_egress.created"

# Soft-trusted system-daemon locations per
# divergence_engine::path_is_soft_trusted_tooling_location. macOS ships
# /usr/sbin with the SIP `restricted` flag, so root cannot write there at all;
# /usr/local/bin is the documented fallback and is soft-trusted too, which keeps
# the filter assertion identical on both platforms.
INSTALL_DIR_BY_SYSTEM = {
    "Linux": "/usr/sbin",
    "Darwin": "/usr/local/bin",
}


def default_install_dir() -> str:
    return INSTALL_DIR_BY_SYSTEM.get(platform.system(), "/usr/local/bin")

# Distinct exit code for "could not install into the system location". The
# runner maps this to a loud failure, never a silent degrade.
EXIT_INSTALL_FAILED = 3
EXIT_UNSUPPORTED_PLATFORM = 4

DEFAULT_TARGET_IP = "1.0.0.1"
DEFAULT_TARGET_HOST = "one.one.one.one"
# Trigger-owned high, non-standard port. Distinct from the 63169-63183 range
# that trigger_divergence.py / trigger_cve_sandbox_escape.py use so a session
# from this scenario is never confused with theirs.
DEFAULT_TARGET_PORT = 63190
DEFAULT_INTERVAL_MS = 200
DEFAULT_PAYLOAD_BYTES = 1200

KEEP_RUNNING = True

# The stand-in daemon: fork/exec the child and stay alive as its parent for the
# child's whole lifetime, so flodbadd resolves l7.parent_process_path to this
# binary's own installed path rather than to an exited shim. Signals are
# forwarded so cleanup.py killing the stand-in also stops the egress child.
STANDIN_C_SOURCE = r"""
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile sig_atomic_t stop_signal = 0;
static volatile pid_t child_pid = -1;

static void on_signal(int sig) {
    stop_signal = sig;
    if (child_pid > 0) {
        kill(child_pid, sig);
    }
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s CHILD_BINARY [ARGS...]\n", argv[0]);
        return 2;
    }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    child_pid = fork();
    if (child_pid < 0) {
        perror("fork");
        return 1;
    }
    if (child_pid == 0) {
        execv(argv[1], &argv[1]);
        perror("execv");
        _exit(127);
    }

    printf("xz_sshd_standin active  pid=%d  child_pid=%d\n",
           (int)getpid(), (int)child_pid);
    fflush(stdout);

    int status = 0;
    for (;;) {
        pid_t reaped = waitpid(child_pid, &status, 0);
        if (reaped == child_pid) {
            break;
        }
        if (reaped < 0 && errno == EINTR) {
            continue;
        }
        if (reaped < 0) {
            perror("waitpid");
            return 1;
        }
    }

    return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}
"""


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Trigger a divergence verdict by generating egress from a "
        "child whose parent is a stand-in system daemon in /usr/sbin."
    )
    p.add_argument("--target-ip", default=DEFAULT_TARGET_IP)
    p.add_argument("--target-host", default=DEFAULT_TARGET_HOST)
    p.add_argument("--target-port", type=int, default=DEFAULT_TARGET_PORT)
    p.add_argument("--interval-ms", type=int, default=DEFAULT_INTERVAL_MS)
    p.add_argument("--payload-bytes", type=int, default=DEFAULT_PAYLOAD_BYTES)
    p.add_argument(
        "--install-dir",
        default=None,
        help="System-daemon directory to install the stand-in into (default: "
        f"{INSTALL_DIR_BY_SYSTEM['Linux']} on Linux, "
        f"{INSTALL_DIR_BY_SYSTEM['Darwin']} on macOS). Must be a soft-trusted "
        "tooling location for the filter assertion to hold.",
    )
    p.add_argument(
        "--duration",
        type=float,
        default=0.0,
        help="Runtime limit in seconds; 0 = until interrupted",
    )
    p.add_argument(
        "--interval",
        type=float,
        default=None,
        help="Alias for --interval-ms expressed in seconds (runner convenience).",
    )
    p.add_argument("--agent-type", default=None, help=AGENT_TYPE_ARG_HELP)
    p.add_argument("--state-dir", type=Path, default=None)
    return p.parse_args()


def handle_signal(signum: int, _frame: object) -> None:
    global KEEP_RUNNING
    _ = signum
    KEEP_RUNNING = False


def compile_standin(state_dir: Path, binary_name: str) -> Path | None:
    """Compile the stand-in daemon into the state dir (staging step)."""
    cc = find_cc()
    if cc is None:
        print("compile_standin: no compiler found", file=sys.stderr)
        return None

    src = state_dir / f"{binary_name}.c"
    binary = state_dir / binary_name
    src.write_text(STANDIN_C_SOURCE, encoding="utf-8")
    record_created(state_dir, CREATED_MARKER, src)

    cmd = [cc, str(src), "-O2", "-o", str(binary)]
    print(f"compile_standin: running {cmd}", file=sys.stderr)
    try:
        # encoding/errors are mandatory on every captured-output call in this
        # tree (see _edamame_cli.py): `text=True` alone decodes with the
        # locale codec and raises on the first byte it cannot map, which turns
        # a compiler diagnostic into an opaque crash.
        result = subprocess.run(
            cmd, capture_output=True, text=True, encoding="utf-8", errors="replace"
        )
        if result.returncode != 0:
            print(
                f"compile_standin: compilation failed (rc={result.returncode})",
                file=sys.stderr,
            )
            print(f"  stdout: {result.stdout[:500]}", file=sys.stderr)
            print(f"  stderr: {result.stderr[:500]}", file=sys.stderr)
            return None
    except Exception as exc:
        print(f"compile_standin: exception: {exc}", file=sys.stderr)
        return None

    try:
        binary.chmod(0o755)
    except OSError:
        pass
    record_created(state_dir, CREATED_MARKER, binary)
    return binary


def install_standin(staged: Path, install_dir: Path, state_dir: Path) -> Path | None:
    """Copy the stand-in into the system daemon location.

    Recorded in the created-file marker BEFORE the copy is attempted, so a
    partially written file is still removed by cleanup.py. Returns None on
    failure; the caller must exit non-zero rather than degrade to a writable
    path.
    """
    installed = install_dir / staged.name
    record_created(state_dir, CREATED_MARKER, installed)
    try:
        install_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(staged, installed)
        installed.chmod(0o755)
    except OSError as exc:
        print(
            f"install_standin: cannot install stand-in daemon to {installed}: {exc}",
            file=sys.stderr,
        )
        return None
    return installed


def main() -> int:
    args = parse_args()
    agent_type = resolve_agent_type(args.agent_type)
    if args.state_dir is None:
        args.state_dir = state_dir_for(agent_type)
    state_dir = args.state_dir
    pfx = file_prefix_for(agent_type)

    if platform.system() not in ("Linux", "Darwin"):
        print(
            "trigger_daemon_lineage_egress.py: unsupported platform "
            f"({platform.system()}); needs a system-daemon install path plus "
            "parent-path L7 attribution. Linux and macOS only.",
            file=sys.stderr,
        )
        return EXIT_UNSUPPORTED_PLATFORM

    if args.install_dir is None:
        args.install_dir = default_install_dir()

    if args.interval is not None:
        args.interval_ms = max(int(args.interval * 1000), 1)

    ensure_state_dir(state_dir)

    standin_name = f"{pfx}_xz_sshd_standin"
    egress_name = f"{pfx}_xz_egress"

    egress_binary = compile_udp_probe(state_dir, CREATED_MARKER, egress_name)
    if egress_binary is None:
        print(
            "trigger_daemon_lineage_egress.py: cannot build the egress child; "
            "a C compiler is required (the parent identity must be the "
            "stand-in's own path, so an interpreter copy will not do).",
            file=sys.stderr,
        )
        return EXIT_INSTALL_FAILED

    staged_standin = compile_standin(state_dir, standin_name)
    if staged_standin is None:
        print(
            "trigger_daemon_lineage_egress.py: cannot build the stand-in daemon; "
            "a C compiler is required.",
            file=sys.stderr,
        )
        return EXIT_INSTALL_FAILED

    installed = install_standin(staged_standin, Path(args.install_dir), state_dir)
    if installed is None:
        print(
            "trigger_daemon_lineage_egress.py: FATAL system_install_failed -- "
            f"could not install the stand-in daemon into {args.install_dir}. "
            "This scenario requires root and deliberately does NOT fall back to "
            "a writable path: a /tmp parent would make the assertion "
            "tautological and duplicate cve_sandbox_escape.",
            file=sys.stderr,
        )
        return EXIT_INSTALL_FAILED

    pid_file = state_dir / PID_FILE
    proc = subprocess.Popen(
        [
            str(installed),
            str(egress_binary),
            args.target_ip,
            str(args.target_port),
            str(args.interval_ms),
            str(args.payload_bytes),
        ],
        stdout=sys.stdout,
        stderr=sys.stderr,
    )
    pid_file.write_text(f"{proc.pid}\n", encoding="utf-8")

    print(f"trigger_daemon_lineage_egress.py active  pid={os.getpid()}  standin_pid={proc.pid}")
    print("  check=divergence")
    print(f"  standin={installed}")
    print(f"  child={egress_binary}")
    print(f"  target={args.target_ip}:{args.target_port} host={args.target_host}")
    print(f"  scope=process_path */{egress_name}")
    print(f"  model_rule=not_expected_parent_paths {args.install_dir}/*_xz_sshd_standin")
    print("  expected_evidence=Parent path '<standin>' matched forbidden pattern")
    print("  incident=CVE-2024-3094 (XZ Utils) exploitation-time shape, NOT the CVE itself")
    print("  stop_with=Ctrl-C or python3 cleanup.py")
    sys.stdout.flush()

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    duration = max(args.duration, 0.0)
    started = time.monotonic()
    try:
        while KEEP_RUNNING:
            ret = proc.poll()
            if ret is not None:
                print(
                    f"trigger_daemon_lineage_egress.py: stand-in exited early (rc={ret})",
                    file=sys.stderr,
                )
                return ret
            if duration > 0 and (time.monotonic() - started) >= duration:
                break
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
