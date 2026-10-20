#!/usr/bin/env python3
"""
Observe EDAMAME's attack pattern detector while the REAL Claude Desktop reads
decoy credentials and sends a message: the SneakPeek host shape produced by
the real application rather than by a stand-in (`trigger_sneakpeek.py` runs a
copy of the interpreter under the render engine's name, hands-off, for the
Attack Simulator and the CVE gate).

This is an operator-driven demo, so the simulator cannot start and stop it.
The tool never launches, drives, instruments, patches or exploits Claude
Desktop; the one action inside the app is the operator's, by hand: start a
new chat, attach the staged decoy files, send. Everything else is EDAMAME-side
observation over `edamame_cli rpc`:

  1. prerequisites (helper, capture, file monitor, agentic protection on,
     detector running, adjudication mode and model provider);
  2. a snapshot of the app's process tree (pid, parent pid, image name; never
     the command line, which can hold secrets);
  3. decoy credential files in the real credential directories, under the
     demo prefix the other triggers use (`~/.ssh/demo_<agent>_sneakpeek_desktop_id`,
     `~/.aws/demo_<agent>_sneakpeek_desktop_credentials`): the sensors label
     a read by its parent directory, so the files must live there. Their
     contents are labelled placeholders; nothing real is read, written or
     sent by this tool;
  4. a baseline of the active finding keys, then a watch over NATURAL
     detector cycles (no forced ticks) that prints every new finding with its
     attribution: process and pid, parent, destination, grade, basis tags,
     whether a decoy is in its evidence, and the time since the message was
     sent;
  5. an export of each new finding (`export_attack_pattern_finding_details`),
     written in the CVE gate's output shape (`results.json`,
     `findings/<scenario>.export.json`, `findings/<scenario>.meta.json`), so
     `edamame_core/tools/attack_corpus_from_gate.py` can shape a real-host
     capture into a replayable attack-corpus envelope;
  6. removal of the decoys (`cleanup`; the Attack Simulator's Run cleanup does
     not know this demo's files).

How to read the result:
  - `credential_misrouted` HIGH on an SSH or AWS decoy: the quiet form. The
    process that read the key also sent, to a service the key is never used
    with.
  - `credential_harvest` with basis `parent_credential_reads`: the two-process
    shape. The finding's process sent; its PARENT read the decoys. Needs
    three or more credential classes read by the main process.
  - `token_exfiltration` / `sensitive_material_egress`: the decoys held open
    while data streams.
  - nothing on the app tree after the full watch: a result too, keep the
    exports.

Platforms. macOS: the app is `Claude`, its helpers `Claude Helper`, `Claude
Helper (Renderer)`, `Claude Helper (GPU)`; the main process and the network
helper are distinct image names. Windows: every process of the app is
`claude.exe`; the split shows as pid / parent pid, not as a name. Linux: no
official Claude Desktop build; the stand-in trigger is the option there, and
this tool still runs for another app (`--app-name`).

Usage (python3, standard library only; `edamame_cli` 2.0.5 or later on PATH,
or `$EDAMAME_CLI_BIN`):
  observe_claude_desktop_sneakpeek.py run      [--creds ssh,aws] [--duration 600]
  observe_claude_desktop_sneakpeek.py check    (prerequisites and process tree only)
  observe_claude_desktop_sneakpeek.py stage    [--creds ssh,aws]
  observe_claude_desktop_sneakpeek.py watch    [--duration 600] [--poll 20]
  observe_claude_desktop_sneakpeek.py cleanup

Safe to interrupt: Ctrl-C ends the watch, writes the summary and removes the
decoys unless --keep-decoys. README.md in this directory is the runbook.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# The triggers' shared helpers: CLI resolution and RPC parsing, the per-agent
# state directory and demo prefix, the gate's export document shape.
TRIGGERS_DIR = Path(os.environ.get("EDAMAME_TRIGGERS_DIR") or
                    Path(__file__).resolve().parent.parent / "triggers")
sys.path.insert(0, str(TRIGGERS_DIR))
from _common import (  # noqa: E402
    AGENT_TYPE_ARG_HELP,
    file_prefix_for,
    prepare_state_dir,
    resolve_agent_type,
    state_dir_for,
    upper_prefix_for,
)
from _edamame_cli import cli_rpc, find_cli_binary  # noqa: E402
from _finding_export import (  # noqa: E402
    ALERTABLE_EXPORTS_KEY,
    DEMOTED_EXPORTS_KEY,
    export_entry,
    export_request_args,
    scenario_meta,
    update_export_document,
    write_json,
)

SCENARIO = "sneakpeek_desktop"
CREATED_MARKER = f"{SCENARIO}.created"
ALERTABLE = ("HIGH", "CRITICAL")
DEFAULT_AGENT_TYPE = "claude_desktop"
DEFAULT_CREDS = ["ssh", "aws"]
# The quiet form, which two decoy classes sent by the reader produce;
# `credential_harvest` needs three classes.
DEFAULT_EXPECTED_CHECK = "credential_misrouted"

# What a basis tag says about who read and who sent.
BASIS_READINGS = {
    "parent_credential_reads": "the PARENT of the sending process read the decoys (the two-process shape)",
    "breadth_credential_reads": "reads remembered after the files were closed (cold credential files)",
    "remembered_credential_reads": "reads remembered after the files were closed",
    "live_sensitive_scan": "the sending process held the decoys open",
    "provenance:read_then_send": "an earlier read by this process was linked to the send",
    "courier_to_own_provider": "an agent carried the credential to its own model provider",
    "non_routine_destination": "the destination is new to this process",
    "anomaly": "the session is anomalous",
    "blacklist": "the destination is blacklisted",
    "blacklisted_destination": "the destination is blacklisted",
    "sustained_egress": "the session carried real egress",
    "sustained_sensitive_egress": "the session streamed while sensitive files were open",
}


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def stamp(dt: datetime | None = None) -> str:
    return (dt or utc_now()).strftime("%Y-%m-%dT%H:%M:%SZ")


def platform_label() -> str:
    """The CVE gate's platform label (`macos-arm64`, `linux-x64`, `windows-x64`)."""
    family = {"darwin": "macos", "linux": "linux", "windows": "windows"}.get(
        platform.system().lower(), platform.system().lower())
    machine = platform.machine().lower()
    arch = {"arm64": "arm64", "aarch64": "arm64", "x86_64": "x64", "amd64": "x64"}.get(machine, machine)
    return f"{family}-{arch}"


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Observe the attack pattern detector while the real Claude Desktop "
                    "reads decoy credentials and sends a message")
    p.add_argument("command", nargs="?", choices=["run", "check", "stage", "watch", "cleanup"], default="run")
    p.add_argument("--agent-type", default=None, help=AGENT_TYPE_ARG_HELP + f" This demo defaults to '{DEFAULT_AGENT_TYPE}'.")
    p.add_argument("--state-dir", type=Path, default=None,
                   help="Where the created-file marker and the outputs go (default: the agent's demo state dir)")
    p.add_argument("--creds", default=",".join(DEFAULT_CREDS),
                   help="Decoy classes to stage: ssh, aws (default: %s). Two classes sent by the reader "
                        "are the quiet form; credential_harvest needs three" % ",".join(DEFAULT_CREDS))
    p.add_argument("--suffix", default="",
                   help="Suffix added to the decoy names (e.g. .txt) when the app's file picker "
                        "refuses a file without an extension. The directory label still applies")
    p.add_argument("--app-name", default="Claude",
                   help="Image name of the app under observation; its helpers are '<name> Helper*' "
                        "on macOS and '<name>.exe' on Windows (default: Claude)")
    p.add_argument("--duration", type=float, default=600.0,
                   help="Seconds to watch after the message was sent (default 600: ten natural "
                        "60 s detector cycles)")
    p.add_argument("--poll", type=float, default=20.0, help="Seconds between polls (default 20)")
    p.add_argument("--expected-check", default=DEFAULT_EXPECTED_CHECK,
                   help="Check whose alertable finding on the app tree makes the gate-shaped result "
                        "a pass (default: %s)" % DEFAULT_EXPECTED_CHECK)
    p.add_argument("--out", type=Path, default=None,
                   help="Output directory (default: <state dir>/%s/<UTC time>)" % SCENARIO)
    p.add_argument("--clear-history", action="store_true",
                   help="Clear vulnerability history and FIM events before the baseline (deletes the "
                        "host's current findings: lab and dev hosts only)")
    p.add_argument("--no-wait", action="store_true",
                   help="Do not wait for Enter; start the watch at once (the operator does the chat "
                        "step from elsewhere and the clock starts now)")
    p.add_argument("--stop-on-alertable", action="store_true",
                   help="End the watch at the first alertable finding on the app tree")
    p.add_argument("--keep-decoys", action="store_true", help="Leave the decoys in place at the end")
    return p.parse_args()


# ----------------------------------------------------------------------------
# prerequisites and the app's process tree
# ----------------------------------------------------------------------------

def as_bool(value) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().strip('"').lower() == "true"


def rpc_text(method: str) -> str:
    """A plain-string RPC (`get_core_version`, `get_helper_state`): the CLI
    prints `Result: <text>`, which `cli_rpc` would try to parse as JSON."""
    out = subprocess.run([find_cli_binary(), "rpc", method], capture_output=True, text=True,
                         encoding="utf-8", errors="replace", timeout=60)
    if out.returncode != 0:
        raise RuntimeError((out.stderr or out.stdout or "").strip()[:200])
    text = (out.stdout or "").strip()
    if text.startswith("Result: "):
        text = text[len("Result: "):].strip()
    return text.strip('"')


def check_prerequisites() -> dict:
    """What a published finding needs: the sensors on, protection on, the
    detector ticking, and a model when adjudication is `llm` (that mode
    publishes nothing without one). Each RPC failure is a problem, not a
    crash: `stage` and `cleanup` work with no daemon."""
    out: dict = {}
    problems: list[str] = []

    def get(method: str, args: str | None = None, text: bool = False):
        try:
            return rpc_text(method) if text else cli_rpc(method, args, timeout=60.0, retries=1)
        except Exception as exc:  # noqa: BLE001
            problems.append(f"{method}: {str(exc)[:160]}")
            return None

    try:
        out["edamame_cli"] = find_cli_binary()
    except FileNotFoundError as exc:
        out["problems"] = [str(exc)]
        return out
    out["core_version"] = get("get_core_version", text=True)
    if out["core_version"] is None:
        problems.append("no daemon answers: start the EDAMAME app or the posture daemon")
        out["problems"] = problems
        return out

    helper = get("get_helper_state", text=True)
    out["helper_state"] = helper
    # "Enabled", or "EnabledFullDisk" on a macOS helper with Full Disk Access.
    if not str(helper).strip('"').startswith("Enabled"):
        problems.append(f"helper state is {helper!r}, not Enabled")

    capturing = as_bool(get("is_capturing"))
    out["is_capturing"] = capturing
    if not capturing:
        problems.append("capture is not running (is_capturing false)")

    fim = get("get_file_monitor_status")
    out["file_monitor"] = fim if isinstance(fim, dict) else {"raw": fim}
    if not (isinstance(fim, dict) and as_bool(fim.get("is_monitoring"))):
        problems.append("file monitor is not running (get_file_monitor_status is_monitoring false)")

    protection = get("agentic_get_protection_status")
    out["protection"] = protection if isinstance(protection, dict) else {"raw": protection}
    if not (isinstance(protection, dict) and as_bool(protection.get("enabled"))):
        problems.append("agentic protection is off (the app's protection button, or "
                        "agentic_set_protection true)")

    status = get("get_attack_pattern_detector_status")
    out["detector"] = status if isinstance(status, dict) else {"raw": status}
    if isinstance(status, dict):
        if not as_bool(status.get("running")):
            problems.append("attack pattern detector is not running")
        if as_bool(status.get("ticker_stalled")):
            problems.append("the agentic ticker is stalled (last_run is old): restart the daemon")
        out["adjudication_mode"] = status.get("adjudication_mode")
    else:
        problems.append("attack pattern detector status unreadable")

    llm = get("agentic_get_llm_config")
    if isinstance(llm, dict):
        # Provider and model only: the Info type carries no key, and this
        # report must never carry one either.
        out["llm"] = {k: llm.get(k) for k in ("provider", "model", "is_operating") if k in llm}
    if out.get("adjudication_mode") == "llm" and isinstance(out.get("llm"), dict) \
            and str(out["llm"].get("provider", "")).lower() in ("", "none"):
        problems.append("adjudication is `llm` with no model configured: nothing is published; "
                        "connect a model or pin advisory / deterministic for the demo")
    out["problems"] = problems
    return out


def app_process_match(name: str, app_name: str) -> bool:
    """Is this image name or path one of the app's processes?

    macOS: the main executable and its helpers carry the app's exact,
    case-sensitive name (`Claude`, `Claude Helper (Renderer)`), and a path,
    when given, is inside an application bundle. The Claude Code CLI is
    `claude`, lower case, and is not the app. Windows: `<name>.exe` for
    every process. Linux: `<name>` or `<name>-*` (`claude-desktop`)."""
    raw = name.replace("\\", "/")
    base = Path(raw).name
    system = platform.system()
    if system == "Darwin":
        if "/" in raw and "/Contents/MacOS/" not in raw:
            return False
        return base == app_name or base.startswith(f"{app_name} Helper")
    low, app = base.lower(), app_name.lower()
    if system == "Windows":
        return low == f"{app}.exe" or low == app
    return low == app or low.startswith(f"{app}-")


def snapshot_app_tree(app_name: str) -> list[dict]:
    """pid, parent pid and image name of the app's processes. Never the
    command line: a session's argv can carry a whole environment."""
    rows: list[dict] = []
    try:
        if platform.system() == "Windows":
            ps = ("Get-CimInstance Win32_Process | ForEach-Object { "
                  "'{0}`t{1}`t{2}' -f $_.ProcessId, $_.ParentProcessId, $_.Name }")
            text = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                                  capture_output=True, text=True, encoding="utf-8",
                                  errors="replace", timeout=30).stdout or ""
            for line in text.splitlines():
                parts = line.strip().split("\t")
                if len(parts) == 3 and app_process_match(parts[2], app_name):
                    rows.append({"pid": int(parts[0]), "ppid": int(parts[1]), "name": parts[2]})
        else:
            text = subprocess.run(["ps", "-axo", "pid=,ppid=,comm="],
                                  capture_output=True, text=True, timeout=30).stdout
            for line in text.splitlines():
                parts = line.strip().split(None, 2)
                if len(parts) == 3 and app_process_match(parts[2], app_name):
                    rows.append({"pid": int(parts[0]), "ppid": int(parts[1]),
                                 "name": Path(parts[2]).name})
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        print(f"  (process tree unavailable: {exc})")
    return rows


# ----------------------------------------------------------------------------
# decoys
# ----------------------------------------------------------------------------

def decoy_paths(agent_type: str, suffix: str) -> dict[str, Path]:
    pfx = file_prefix_for(agent_type)
    return {
        "ssh": Path(f"~/.ssh/{pfx}_sneakpeek_desktop_id{suffix}").expanduser(),
        "aws": Path(f"~/.aws/{pfx}_sneakpeek_desktop_credentials{suffix}").expanduser(),
    }


def decoy_content(cred: str, agent_type: str) -> str:
    upfx = upper_prefix_for(agent_type)
    banner = (f"# EDAMAME demo decoy, staged {stamp()} by observe_claude_desktop_sneakpeek.py.\n"
              f"# A placeholder in a credential's shape. Not a credential. Safe to delete.\n")
    if cred == "ssh":
        return (f"{banner}-----BEGIN OPENSSH PRIVATE KEY-----\n{upfx}_SNEAKPEEK_DESKTOP\n"
                f"-----END OPENSSH PRIVATE KEY-----\n")
    return (f"{banner}[default]\naws_access_key_id = {upfx}_SNEAKPEEK_DESKTOP\n"
            f"aws_secret_access_key = not-a-real-key\n")


def record_created(state_dir: Path, path: Path) -> None:
    marker = state_dir / CREATED_MARKER
    existing: set[str] = set()
    if marker.exists():
        existing = {l.strip() for l in marker.read_text("utf-8").splitlines() if l.strip()}
    existing.add(str(path))
    marker.write_text("\n".join(sorted(existing)) + "\n", encoding="utf-8")


def stage_decoy(path: Path, content: str, state_dir: Path) -> Path:
    if path.is_symlink():
        raise SystemExit(f"refusing: {path} is a symlink")
    if path.exists():
        print(f"  using pre-existing decoy {path}")
        return path
    path.parent.mkdir(parents=True, exist_ok=True)
    # O_EXCL / O_NOFOLLOW: never replaces or follows a file that appeared
    # since the check above.
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(content)
    record_created(state_dir, path)
    print(f"  staged decoy {path}")
    return path


def remove_decoys(state_dir: Path) -> None:
    """Remove the files this demo recorded in its marker (demo-prefixed names
    only), then the marker; directories are left alone (they are the user's)."""
    marker = state_dir / CREATED_MARKER
    if not marker.exists():
        print("  nothing recorded to remove")
        return
    removed = 0
    for line in marker.read_text("utf-8").splitlines():
        raw = line.strip()
        if not raw:
            continue
        path = Path(raw)
        if not path.name.startswith("demo_"):
            print(f"  left {path}: not a demo-prefixed name")
            continue
        if path.is_symlink() or not path.exists():
            continue
        try:
            path.unlink()
            removed += 1
            print(f"  removed {path}")
        except OSError as exc:
            print(f"  cannot remove {path}: {exc}")
    marker.unlink(missing_ok=True)
    print(f"  decoys removed: {removed}")


# ----------------------------------------------------------------------------
# findings
# ----------------------------------------------------------------------------

def active_findings() -> list[dict]:
    data = cli_rpc("get_attack_pattern_findings", timeout=60.0, retries=1)
    if not isinstance(data, dict):
        return []
    items = data.get("findings") or []
    if isinstance(items, str):
        items = json.loads(items) if items != "null" else []
    return [f for f in items if isinstance(f, dict) and not f.get("dismissed")]


def finding_mentions_decoy(finding: dict, decoys: list[Path]) -> list[str]:
    hay = " ".join([
        " ".join(str(x) for x in finding.get("open_files") or []),
        str(finding.get("subject_path") or ""),
        str(finding.get("description") or ""),
    ]).replace("\\", "/")
    return [str(d) for d in decoys if str(d).replace("\\", "/") in hay]


def finding_on_app_tree(finding: dict, app_name: str, tree_pids: set[int]) -> bool:
    for key in ("process_name", "process_path", "parent_process_name", "parent_process_path"):
        value = finding.get(key)
        if value and app_process_match(str(value), app_name):
            return True
    pid = finding.get("process_pid")
    return isinstance(pid, int) and pid in tree_pids


def describe(finding: dict, elapsed: float, on_tree: bool, decoys_hit: list[str]) -> str:
    dest = finding.get("destination_domain") or finding.get("destination_ip") or "?"
    port = finding.get("destination_port")
    basis = ",".join(finding.get("detection_basis") or [])
    pid = finding.get("process_pid")
    who = f"{finding.get('process_name') or '?'}" + (f"({pid})" if pid else "")
    parent = finding.get("parent_process_name") or "?"
    flags = ("APP " if on_tree else "    ") + ("DECOY" if decoys_hit else "     ")
    return (f"  +{elapsed:6.0f}s {flags} [{finding.get('severity','?'):8}] {finding.get('check','?'):26} "
            f"{who} <- {parent}  -> {dest}:{port}  basis=[{basis}]")


def export_finding(key: str):
    try:
        doc = cli_rpc("export_attack_pattern_finding_details", export_request_args(key),
                      timeout=120.0, retries=1)
    except Exception as exc:  # noqa: BLE001
        print(f"  export failed for {key[:60]}: {exc}")
        return None
    if isinstance(doc, dict) and doc.get("success"):
        return doc
    print(f"  export refused for {key[:60]}: {doc.get('error') if isinstance(doc, dict) else doc}")
    return None


# ----------------------------------------------------------------------------
# the run
# ----------------------------------------------------------------------------

def print_operator_step(decoys: list[Path], app_name: str) -> None:
    print("")
    print("=" * 72)
    print(f"  OPERATOR STEP, in {app_name} (by hand; this tool touches the app in no way)")
    print("=" * 72)
    print("  1. Start a NEW chat.")
    print("  2. Attach these files (macOS Open dialog: Cmd+Shift+G and paste the path;")
    print("     Windows: paste the path in the file-name box; or show hidden files):")
    for d in decoys:
        print(f"       {d}")
    print("  3. Send this message:")
    print('       "EDAMAME detector demo: the attached files are decoys staged by our')
    print('        own test tool. Reply with one word."')
    print("  4. Come back here and press Enter the moment you sent it.")
    print("")
    print("  The decoys are labelled placeholders. Nothing else leaves this host because")
    print("  of this tool; the app sends what you attach to its own service.")
    print("")


def run(args: argparse.Namespace) -> int:
    creds = [c.strip() for c in args.creds.split(",") if c.strip()]
    unknown = [c for c in creds if c not in ("ssh", "aws")]
    if unknown:
        raise SystemExit(f"unknown decoy class(es): {unknown}; choose from ssh, aws")

    agent_type = resolve_agent_type(args.agent_type or DEFAULT_AGENT_TYPE)
    state_dir = prepare_state_dir(args.state_dir or state_dir_for(agent_type))
    if args.command == "cleanup":
        remove_decoys(state_dir)
        return 0

    out_dir = args.out or state_dir / SCENARIO / utc_now().strftime("%Y%m%dT%H%M%SZ")
    if args.command in ("run", "watch"):
        (out_dir / "findings").mkdir(parents=True, exist_ok=True)
        print(f"output: {out_dir}")

    print("\nprerequisites:")
    prereq = check_prerequisites()
    for k in ("edamame_cli", "core_version", "helper_state", "is_capturing", "adjudication_mode", "llm"):
        if k in prereq:
            print(f"  {k}: {prereq.get(k)}")
    det = prereq.get("detector") or {}
    if isinstance(det, dict) and det:
        print(f"  detector: running={det.get('running')} last_run={det.get('last_run')} "
              f"active={det.get('active_findings')} alertable={det.get('active_alertable_findings')} "
              f"content_scan_degraded={det.get('content_scan_degraded')}")
    for problem in prereq["problems"]:
        print(f"  PROBLEM: {problem}")
    if prereq["problems"] and args.command == "run":
        print("  fix the problems above, then run again (a finding cannot be published otherwise)")
        return 2

    tree = snapshot_app_tree(args.app_name)
    print(f"\n{args.app_name} process tree ({len(tree)} processes):")
    for row in sorted(tree, key=lambda r: r["pid"]):
        print(f"  pid {row['pid']:>7}  ppid {row['ppid']:>7}  {row['name']}")
    if not tree:
        print(f"  {args.app_name} is not running: start it and sign in before the operator step")
    tree_pids = {r["pid"] for r in tree}
    if args.command == "check":
        return 2 if prereq["problems"] else 0

    print("\ndecoys:")
    paths = decoy_paths(agent_type, args.suffix)
    decoys = [stage_decoy(paths[c], decoy_content(c, agent_type), state_dir) for c in creds]
    if args.command == "stage":
        print_operator_step(decoys, args.app_name)
        print("  (stage only: run `watch` to observe, `cleanup` to remove the decoys)")
        return 0

    if args.clear_history:
        print("\nclearing vulnerability history and FIM events (--clear-history)")
        cli_rpc("clear_attack_pattern_history", timeout=60.0, retries=1)
        try:
            cli_rpc("clear_file_events", timeout=60.0, retries=1)
        except Exception as exc:  # noqa: BLE001
            print(f"  clear_file_events: {exc}")

    baseline = {f.get("finding_key"): f for f in active_findings()}
    print(f"\nbaseline: {len(baseline)} active finding(s) before the operator step")

    if args.command == "run" and not args.no_wait:
        print_operator_step(decoys, args.app_name)
        try:
            input("  Press Enter right after you sent the message... ")
        except EOFError:
            print("  (no terminal: starting the watch now)")
    sent_at = utc_now()
    t0 = time.monotonic()
    print(f"\nwatch: {args.duration:.0f}s from {stamp(sent_at)}, polling every {args.poll:.0f}s "
          f"(natural detector cycles only; no forced ticks)")

    seen: dict[str, dict] = {}
    exports: dict[str, dict] = {}
    first_alertable: dict | None = None
    try:
        while True:
            elapsed = time.monotonic() - t0
            try:
                current = active_findings()
            except Exception as exc:  # noqa: BLE001
                print(f"  +{elapsed:6.0f}s poll failed: {exc}")
                current = []
            for f in current:
                key = f.get("finding_key")
                if not key or key in baseline:
                    continue
                on_tree = finding_on_app_tree(f, args.app_name, tree_pids)
                hits = finding_mentions_decoy(f, decoys)
                if key not in seen:
                    seen[key] = {"first_seen_s": round(elapsed), "severity": f.get("severity"),
                                 "check": f.get("check"), "on_app_tree": on_tree, "decoys": hits,
                                 "finding": f}
                    print(describe(f, elapsed, on_tree, hits))
                    for tag in f.get("detection_basis") or []:
                        if tag in BASIS_READINGS:
                            print(f"           {tag}: {BASIS_READINGS[tag]}")
                    doc = export_finding(key)
                    if doc:
                        exports[key] = doc
                    if on_tree and f.get("severity") in ALERTABLE and first_alertable is None:
                        first_alertable = {"key": key, "check": f.get("check"),
                                           "severity": f.get("severity"), "after_s": round(elapsed)}
                        print(f"           FIRST ALERTABLE FINDING ON THE APP TREE after {elapsed:.0f}s")
                        if args.stop_on_alertable:
                            raise KeyboardInterrupt
                elif seen[key]["severity"] != f.get("severity"):
                    print(f"  +{elapsed:6.0f}s grade changed {seen[key]['severity']} -> {f.get('severity')} "
                          f"for {f.get('check')} ({key[:48]})")
                    seen[key]["severity"] = f.get("severity")
                    seen[key]["finding"] = f
            if elapsed >= args.duration:
                break
            time.sleep(max(1.0, min(args.poll, args.duration - elapsed)))
    except KeyboardInterrupt:
        print("\n  watch ended early")

    # Final exports carry the grade the finding settled at.
    for key in list(seen):
        doc = export_finding(key)
        if doc:
            exports[key] = doc

    rc = write_outputs(args, out_dir, prereq, tree, decoys, sent_at, seen, exports, first_alertable)
    if args.keep_decoys:
        print("  decoys kept (--keep-decoys); remove them with `cleanup`")
    else:
        print("\ncleanup:")
        remove_decoys(state_dir)
    return rc


def write_outputs(args, out_dir: Path, prereq: dict, tree: list[dict], decoys: list[Path],
                  sent_at: datetime, seen: dict, exports: dict, first_alertable) -> int:
    on_tree = {k: v for k, v in seen.items() if v["on_app_tree"]}
    alertable_on_tree = [k for k, v in on_tree.items() if v["severity"] in ALERTABLE]
    expected_hit = [k for k in alertable_on_tree if seen[k]["check"] == args.expected_check]
    status = "pass" if expected_hit else "fail"

    # The CVE gate's output shape (`_finding_export`), so
    # edamame_core/tools/attack_corpus_from_gate.py shapes this capture like a
    # CI leg's: `--label local-<host>-<date>`.
    export_path = str(out_dir / "findings" / f"{SCENARIO}.export.json")
    now = stamp()
    update_export_document(export_path, SCENARIO, args.expected_check, {
        ALERTABLE_EXPORTS_KEY: [export_entry(k, seen[k]["severity"], exports[k])
                                for k in alertable_on_tree if k in exports],
        "alertable_exported_utc": now,
        "alertable_finding_keys": [k for k in alertable_on_tree if k in exports],
        "alertable_exported": sum(1 for k in alertable_on_tree if k in exports),
    })
    others = [k for k in seen if k in exports and k not in alertable_on_tree]
    update_export_document(export_path, SCENARIO, args.expected_check, {
        DEMOTED_EXPORTS_KEY: [export_entry(k, seen[k]["severity"], exports[k]) for k in others],
        "exported_utc": now,
        "demoted_finding_keys": others,
        "exported": len(others),
    })
    write_json(str(out_dir / "findings" / f"{SCENARIO}.meta.json"),
               scenario_meta(SCENARIO, args.expected_check, [], [], "HIGH", True, len(alertable_on_tree)))
    write_json(str(out_dir / "results.json"), {
        "generated_utc": now,
        "platform_system": platform.system(),
        "platform_machine": platform.machine(),
        "host": socket.gethostname(),
        "core_version": prereq.get("core_version"),
        "source": "observe_claude_desktop_sneakpeek.py (real desktop app, operator-driven)",
        "scenarios": [{"scenario": SCENARIO, "status": status, "expected_check": args.expected_check,
                       "first_alertable_after_s": first_alertable["after_s"] if first_alertable else None}],
    })
    write_json(str(out_dir / "summary.json"), {
        "sent_at": stamp(sent_at),
        "app_name": args.app_name,
        "app_tree": tree,
        "decoys": [str(d) for d in decoys],
        "prerequisites": prereq,
        "new_findings": {k: {kk: vv for kk, vv in v.items() if kk != "finding"} for k, v in seen.items()},
        "first_alertable_on_app_tree": first_alertable,
        "status": status,
    })

    print("\n" + "=" * 72)
    print(f"  RESULT: {status.upper()}  ({len(seen)} new finding(s), {len(on_tree)} on the "
          f"{args.app_name} tree, {len(alertable_on_tree)} alertable there)")
    print("=" * 72)
    if first_alertable:
        print(f"  first alertable on the app tree: {first_alertable['severity']} "
              f"{first_alertable['check']} after {first_alertable['after_s']}s")
    elif not on_tree:
        print(f"  no finding named the {args.app_name} tree: keep the exports with the result")
    for key, v in seen.items():
        f = v["finding"]
        print(f"  - [{v['severity']}] {v['check']} {f.get('process_name')} <- {f.get('parent_process_name')}"
              f" -> {f.get('destination_domain') or f.get('destination_ip')}  "
              f"{'app tree' if v['on_app_tree'] else 'other'}; decoys: {len(v['decoys'])}; "
              f"basis: {','.join(f.get('detection_basis') or [])}")
    print(f"\n  outputs: {out_dir}")
    print(f"  corpus envelope (from an edamame_core checkout): python3 -I tools/attack_corpus_from_gate.py "
          f"--platform {platform_label()} --label local-{socket.gethostname()}-{utc_now().strftime('%Y%m%d')} {out_dir}")
    return 0 if status == "pass" else 1


def main() -> int:
    return run(parse_args())


if __name__ == "__main__":
    sys.exit(main())
