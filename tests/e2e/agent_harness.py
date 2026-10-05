#!/usr/bin/env python3
"""
Shared real-agent harness for the EDAMAME agent tests.

Moved verbatim out of ``run_fleet_monitoring.py`` (the release-gating fleet
E2E) so the fleet E2E and the FP lab (``tests/fp_lab``) install, drive and
observe real agents through ONE copy of the code:

- logging and subprocess helpers (``log``, ``run_cmd``, ``popen_cmd``,
  ``last_cmd_output_tail``, ``cli_path``),
- transcript-observer RPC helpers (``rpc_quiet``, ``observer_status``,
  ``observer_row``, ``observer_tick``, ``set_observer_enabled``),
- the real agent drivers and installers (``drive_claude_code``,
  ``drive_codex``, ``drive_hermes``, ``drive_openclaw``,
  ``drive_claude_desktop``, ``ensure_*_installed``, ``REAL_DRIVERS``,
  ``real_driver_available``, ``AgentInstallUnavailable``),
- daemon-side model helpers (``ensure_daemon_llm_provider``,
  ``_force_model_build``, ``_divergence_status``, ``dump_model_scope``).

The RPC wrapper stays in ``tests/security/triggers/_edamame_cli.py`` and the
supported-agent registry reader in ``tests/e2e/supported_agents.py``; this
module imports them and never copies them.

Additions over the moved code, all with defaults that keep the fleet E2E's
behaviour unchanged: ``make_scratch_workspace(..., root=None)`` (the FP lab
keeps its workspaces under the lab user's home, not OS temp) and
``extra_args`` / ``extra_env`` on ``drive_claude_code`` and ``drive_codex``
(the FP lab resumes sessions and asks for machine-readable output).
"""

from __future__ import annotations

import json
import os
import platform
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

_HERE = Path(__file__).resolve().parent
# `_edamame_cli` ships with the CVE trigger corpus in tests/security/triggers;
# accept a co-located triggers/ too (same resolution as the fleet driver).
for _triggers in (_HERE / "triggers", _HERE.parent / "security" / "triggers"):
    if _triggers.is_dir() and str(_triggers) not in sys.path:
        sys.path.insert(0, str(_triggers))

from _edamame_cli import cli_rpc  # noqa: E402


# ── Logging ──────────────────────────────────────────────────────────────

def log(msg: str = "") -> None:
    print(msg, flush=True)


def section(msg: str) -> None:
    log("")
    log("=" * 70)
    log(msg)
    log("=" * 70)


def is_windows() -> bool:
    msystem = os.environ.get("MSYSTEM") or ""
    return platform.system() == "Windows" or msystem.startswith(("MINGW", "MSYS", "CYGWIN"))


# ── Subprocess helpers ───────────────────────────────────────────────────

# Combined stdout+stderr of the most recent run_cmd(), kept so an installer
# failure can quote its tail in the summary (the full stream is already echoed
# inline, but the summary is what a triager reads first).
_LAST_CMD_OUTPUT: list[str] = []
INSTALL_LOG_TAIL_LINES = 15


def last_cmd_output_tail(n: int = INSTALL_LOG_TAIL_LINES) -> list[str]:
    return [line.rstrip() for line in _LAST_CMD_OUTPUT[-n:]]


def _remember_output(*chunks: object) -> None:
    _LAST_CMD_OUTPUT.clear()
    for chunk in chunks:
        if not chunk:
            continue
        text = chunk if isinstance(chunk, str) else chunk.decode("utf-8", "replace")
        _LAST_CMD_OUTPUT.extend(text.splitlines())


def run_cmd(
    cmd: list[str],
    cwd: Path | None,
    env: dict | None,
    timeout: int | None,
    stdin_text: str | None = None,
) -> int:
    """Run a command, streaming output, returning the exit code (124 on timeout)."""
    log(f"  $ {' '.join(cmd)}")
    full_env = dict(os.environ)
    if env:
        full_env.update(env)
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            env=full_env,
            timeout=timeout,
            text=True,
            # Force UTF-8 decode: on the Windows runner text=True otherwise uses the
            # cp1252 locale codec, which raises UnicodeDecodeError on UTF-8 installer
            # output (Hermes prints box-drawing / emoji). errors="replace" keeps the
            # run alive even on undecodable bytes.
            encoding="utf-8",
            errors="replace",
            input=stdin_text,
            capture_output=True,
        )
    except subprocess.TimeoutExpired as exc:
        _remember_output(exc.stdout, exc.stderr, f"(timeout after {timeout}s)")
        if exc.stdout:
            sys.stdout.write(exc.stdout if isinstance(exc.stdout, str) else exc.stdout.decode("utf-8", "replace"))
        if exc.stderr:
            sys.stderr.write(exc.stderr if isinstance(exc.stderr, str) else exc.stderr.decode("utf-8", "replace"))
        log(f"  (timeout after {timeout}s)")
        return 124
    _remember_output(proc.stdout, proc.stderr)
    if proc.stdout:
        sys.stdout.write(proc.stdout)
    if proc.stderr:
        sys.stderr.write(proc.stderr)
    sys.stdout.flush()
    sys.stderr.flush()
    return proc.returncode


def popen_cmd(
    cmd: list[str],
    cwd: Path | None,
    env: dict | None,
    log_path: Path,
    stdin_text: str | None = None,
) -> subprocess.Popen:
    """Spawn a background command, redirecting combined output to log_path."""
    log(f"  $ (bg) {' '.join(cmd)}  > {log_path.name}")
    full_env = dict(os.environ)
    if env:
        full_env.update(env)
    fh = log_path.open("w", encoding="utf-8", errors="replace")
    proc = subprocess.Popen(
        cmd,
        cwd=str(cwd) if cwd else None,
        env=full_env,
        text=True,
        # Same UTF-8 forcing as run_cmd: avoid cp1252 decode crashes on the Windows
        # runner when the child streams UTF-8 output into the captured log.
        encoding="utf-8",
        errors="replace",
        stdin=subprocess.PIPE if stdin_text is not None else None,
        stdout=fh,
        stderr=subprocess.STDOUT,
    )
    if stdin_text is not None and proc.stdin is not None:
        try:
            proc.stdin.write(stdin_text)
            proc.stdin.close()
        except Exception:  # noqa: BLE001
            pass
    return proc


def cli_path(*candidates: str) -> str | None:
    """Resolve the first available CLI binary, tolerating .cmd/.exe shims."""
    for name in candidates:
        found = shutil.which(name) or shutil.which(name + ".cmd") or shutil.which(name + ".exe")
        if found:
            return found
    return None


# ── Observer / score RPC helpers ─────────────────────────────────────────

def rpc_quiet(method: str, args: str | None = None, timeout: float = 30.0) -> object | None:
    # `timeout` defaults to cli_rpc's own default; the FP lab raises it for ticks
    # that wait on an LLM round-trip.
    try:
        return cli_rpc(method, args, timeout=timeout)
    except Exception as exc:  # noqa: BLE001
        log(f"  WARN: {method} failed: {exc}")
        return None


def observer_status() -> dict:
    st = cli_rpc("get_transcript_observer_status")
    return st if isinstance(st, dict) else {}


def observer_row(agent_type: str) -> dict | None:
    for row in observer_status().get("agents", []):
        if isinstance(row, dict) and row.get("agent_type") == agent_type:
            return row
    return None


def observer_tick(agent_type: str, timeout: float = 30.0) -> None:
    """Run one observer tick. Returns nothing on purpose.

    `run_transcript_observer_tick_for` is a fallible MUTATOR: it answers with
    the `{"success": bool, "error": ...}` envelope and carries no payload, so
    the authoritative state must be re-read via `get_transcript_observer_status`
    (see `observer_row`). This used to return whatever the RPC produced, and
    the caller did `observer_tick(...) or observer_row(...)` -- once the RPC
    started returning the envelope that dict was still truthy, the fallback
    never ran, and every agent read back `discovered=None`, failing the
    real-coverage gate on all platforms even though the agents had been driven
    successfully (`real <agent> drive exit=0`).
    """
    rpc_quiet("run_transcript_observer_tick_for", json.dumps({"agent_type": agent_type}), timeout=timeout)


def set_observer_enabled(agent_type: str, enabled: bool) -> None:
    rpc_quiet("set_transcript_observer_enabled", json.dumps({"agent_type": agent_type, "enabled": enabled}))


# ── Real agent drivers ───────────────────────────────────────────────────
#
# Each driver installs nothing (the workflow installs the CLI); it just runs
# the real product non-interactively in a throwaway workspace with a real key,
# producing genuine on-disk transcripts the EDAMAME observer ingests.

NORMAL_PROMPT = (
    "You are in a small scratch project. Read README.md and hello.py, then "
    "write one short sentence describing what hello.py does into a new file "
    "named SUMMARY.txt. Keep it brief and do not access the network."
)

# Lighter prompt for agents we only need to produce a real transcript from
# (hermes / openclaw / claude_desktop). A single bounded reply still drives the
# real product end to end and lands a genuine session the observer can ingest.
NORMAL_PROMPT_SIMPLE = (
    "Reply with exactly one short sentence confirming you are running, then "
    "stop. Do not access the network."
)

def make_scratch_workspace(agent_type: str, root: Path | None = None) -> Path:
    # `root` None keeps the fleet E2E's OS-temp workspace; the FP lab passes a
    # directory under the lab user's home so only temp scenarios touch temp.
    # Neutral prefix: the representative agent flags telling working-directory
    # names (an earlier "edamame_fleet_..._divergence" path corroborated its
    # "coordinated fleet probing" refusal). A plain dev-scratch dir reads as an
    # ordinary throwaway project.
    if root is None:
        base = Path(tempfile.mkdtemp(prefix=f"dev_scratch_{agent_type}_"))
    else:
        Path(root).mkdir(parents=True, exist_ok=True)
        base = Path(tempfile.mkdtemp(prefix=f"dev_scratch_{agent_type}_", dir=str(root)))
    (base / "README.md").write_text(
        "# EDAMAME fleet E2E scratch project\n\nA tiny project used to exercise a real agent.\n",
        encoding="utf-8",
    )
    (base / "hello.py").write_text(
        "def main():\n    print('hello from the edamame fleet e2e scratch project')\n\n\n"
        "if __name__ == '__main__':\n    main()\n",
        encoding="utf-8",
    )
    return base


def drive_claude_code(
    workdir: Path,
    prompt: str,
    timeout: int,
    background: bool,
    log_path: Path | None,
    extra_args: list[str] | None = None,
    extra_env: dict | None = None,
):
    cli = cli_path("claude")
    if not cli:
        return None
    key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not key:
        return None
    cmd = [cli, "-p", "--dangerously-skip-permissions"]
    # FP lab: e.g. --output-format json, --model, --resume <session id>.
    cmd += list(extra_args or [])
    # On Linux this driver runs as root (so the root daemon's transcript observer
    # resolves /root/.claude). Claude Code hard-exits when --dangerously-skip-
    # permissions is used as uid 0 unless IS_SANDBOX=1 (the documented ephemeral-
    # sandbox escape hatch). Harmless for non-root macOS/Windows legs.
    # BASH_*_TIMEOUT_MS lift Claude Code's Bash-tool timeout (default 120s) so the
    # divergence probe's ~110s keep-alive command is not truncated mid-window.
    env = {
        "ANTHROPIC_API_KEY": key,
        "IS_SANDBOX": "1",
        "BASH_DEFAULT_TIMEOUT_MS": "200000",
        "BASH_MAX_TIMEOUT_MS": "200000",
    }
    env.update(extra_env or {})
    if background:
        assert log_path is not None
        return popen_cmd(cmd, workdir, env, log_path, stdin_text=prompt)
    return run_cmd(cmd, workdir, env, timeout, stdin_text=prompt)


def drive_codex(
    workdir: Path,
    prompt: str,
    timeout: int,
    background: bool,
    log_path: Path | None,
    extra_args: list[str] | None = None,
    extra_env: dict | None = None,
):
    cli = cli_path("codex")
    if not cli:
        return None
    key = os.environ.get("OPENAI_API_KEY", "")
    if not key:
        return None
    cmd = [
        cli, "exec",
        "--sandbox", "danger-full-access",
        "--skip-git-repo-check",
        "-C", str(workdir),
        # FP lab: e.g. `resume --last` to continue the session (goes before the prompt).
        *(extra_args or []),
        prompt,
    ]
    # Codex auth env var name varies across CLI versions (older codex-cli reads
    # OPENAI_API_KEY; newer codex-rs documents CODEX_API_KEY). Set both.
    env = {"OPENAI_API_KEY": key, "CODEX_API_KEY": key}
    env.update(extra_env or {})
    if background:
        assert log_path is not None
        return popen_cmd(cmd, workdir, env, log_path)
    return run_cmd(cmd, workdir, env, timeout)


def _augment_path(*dirs: str) -> None:
    """Prepend existing dirs to PATH so a just-installed CLI becomes resolvable
    in this process (and its children) without re-exec."""
    parts = os.environ.get("PATH", "").split(os.pathsep)
    changed = False
    for raw in dirs:
        if not raw:
            continue
        d = os.path.expanduser(raw)
        if os.path.isdir(d) and d not in parts:
            parts.insert(0, d)
            changed = True
    if changed:
        os.environ["PATH"] = os.pathsep.join(parts)


# Hermes (Nous Research) ships headless installers for EVERY desktop OS:
#   Linux / macOS / WSL2 / Android (Termux):  curl -fsSL .../install.sh | bash
#   Windows (native PowerShell):              iex (irm .../install.ps1)
# (https://hermes-agent.nousresearch.com/docs/getting-started/installation)
HERMES_INSTALL_SH = (
    "curl -fsSL https://hermes-agent.nousresearch.com/install.sh | bash -s -- --skip-browser"
)
# The scriptblock form passes the installer's switches, which `iex (irm ...)`
# cannot: -SkipBrowser mirrors the Unix --skip-browser (no browser tools on a
# CI runner), -NonInteractive skips the stages that would wait for input.
HERMES_INSTALL_PS1 = (
    "& ([scriptblock]::Create((irm https://hermes-agent.nousresearch.com/install.ps1)))"
    " -SkipBrowser -NonInteractive"
)
_HERMES_BIN_DIRS = ("~/.local/bin", "/usr/local/bin", "~/.hermes/bin")
# uv/console_scripts + the PS1 installer drop the launcher in one of these on Windows.
# The PS1 installer clones to ~/.hermes/hermes-agent and builds a venv next to it, so
# the real pip console_scripts shim is <venv>/Scripts/hermes.exe -- list those venv
# Scripts dirs FIRST so cli_path() resolves the .exe before the bare Unix launcher.
_HERMES_BIN_DIRS_WIN = (
    "~/.hermes/hermes-agent/venv/Scripts",
    "~/.hermes/venv/Scripts",
    "~/.local/bin",
    "~/.hermes/bin",
    "~/AppData/Local/Programs/hermes",
    "~/AppData/Local/hermes/bin",
    "~/AppData/Roaming/hermes/bin",
    "~/AppData/Roaming/Python/Scripts",
)


def _is_reparse_point(entry: os.DirEntry) -> bool:
    """True for Windows junctions / symlinks. %LOCALAPPDATA% on Windows holds
    legacy junctions ('Application Data' -> 'Local', 'Local Settings' -> 'Local',
    ...) that loop back on themselves; a naive recursive walk follows them forever
    and eventually yields a path over MAX_PATH (260), raising
    OSError [WinError 206] 'The filename or extension is too long'. Junctions are
    NOT reliably reported by is_symlink() on older Python, so also test the Windows
    reparse-point file attribute directly."""
    try:
        if entry.is_symlink():
            return True
        attrs = getattr(entry.stat(follow_symlinks=False), "st_file_attributes", 0)
        return bool(attrs & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))
    except OSError:
        # If we can't stat it, treat it as something to skip rather than recurse.
        return True


def _walk_for_names(root: Path, names: set[str], max_depth: int = 6):
    """Depth-bounded, junction-skipping directory walk that yields files whose
    basename is in `names`. Replaces Path.rglob, which on Windows follows the
    self-referential %LOCALAPPDATA% junctions into WinError 206 (see
    _is_reparse_point)."""
    stack: list[tuple[Path, int]] = [(root, 0)]
    while stack:
        cur, depth = stack.pop()
        try:
            it = os.scandir(cur)
        except OSError:
            continue
        with it:
            for entry in it:
                try:
                    if _is_reparse_point(entry):
                        continue
                    if entry.is_file(follow_symlinks=False):
                        if entry.name in names:
                            yield Path(entry.path)
                    elif depth < max_depth and entry.is_dir(follow_symlinks=False):
                        stack.append((Path(entry.path), depth + 1))
                except OSError:
                    continue


def _find_hermes_under_home() -> str | None:
    """Last-resort resolver: the Windows installer mutates the *user* PATH, which
    does NOT propagate into this already-running process, so search HOME for the
    freshly-installed launcher and prepend its dir to PATH. Uses a junction-safe
    bounded walk (NOT rglob) so the legacy AppData junctions can't crash it.

    On Windows ONLY the executable shims (hermes.exe / .cmd / .bat) are valid: the
    extensionless `hermes` under ~/.hermes/hermes-agent/ is a Unix shell launcher
    that Windows cannot exec, which surfaces as `[WinError 193] %1 is not a valid
    Win32 application` when the driver tries to run it. The pip console_scripts
    shim is hermes.exe under <venv>/Scripts, so rank Scripts hits first, then by
    extension (.exe > .cmd > .bat), and never return the bare launcher on Windows."""
    home = Path.home()
    names = {"hermes.exe", "hermes.cmd", "hermes.bat"} if is_windows() else {"hermes"}
    hits: list[Path] = []
    for root in (home / ".hermes", home / ".local", home / "AppData"):
        if not root.is_dir():
            continue
        try:
            hits.extend(_walk_for_names(root, names))
        except OSError:
            continue
    if not hits:
        return None

    def _rank(p: Path) -> tuple:
        ext_order = {".exe": 0, ".cmd": 1, ".bat": 2}
        in_scripts = 0 if "scripts" in str(p.parent).lower() else 1
        return (in_scripts, ext_order.get(p.suffix.lower(), 9), len(str(p)))

    best = min(hits, key=_rank)
    _augment_path(str(best.parent))
    return str(best)


class AgentInstallUnavailable(RuntimeError):
    """A self-installing agent's OWN installer failed, so the agent is absent.

    This is NOT an EDAMAME detection failure. With no agent on disk,
    `discovered=False sessions=0` is the correct observation, and asserting
    detection measures the third party's installer uptime rather than the
    observer. Hermes hit exactly this on windows-latest: upstream install.ps1
    failed to build the hermes-agent editable wheel, so nothing was ever
    installed to discover.

    Raised ONLY when the install itself did not produce a CLI. An agent that
    installs successfully and is then not discovered stays a hard failure --
    that is the regression this suite exists to catch.

    Gating: the driver only reaches an installer once the provider key has been
    verified present, so this is an "install failed with key present" case and
    is a HARD failure (see the per-agent floor in the module docstring). It
    carries the installer's output tail so the summary can quote the reason.
    """

    def __init__(self, message: str, tail: list[str] | None = None) -> None:
        super().__init__(message)
        self.tail = list(tail or [])


def ensure_hermes_installed() -> str | None:
    """Headlessly install Hermes into THIS uid's HOME (so the observer, running as
    the same uid, resolves ~/.hermes). Returns the resolved CLI path or None."""
    bin_dirs = _HERMES_BIN_DIRS_WIN if is_windows() else _HERMES_BIN_DIRS
    _augment_path(*bin_dirs)
    found = cli_path("hermes")
    if found:
        return found
    log("  installing Hermes (headless)")
    if is_windows():
        install_cmd = os.environ.get("HERMES_INSTALL_CMD_WIN", HERMES_INSTALL_PS1)
        run_cmd(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", install_cmd],
            None,
            None,
            1800,
        )
    else:
        install_cmd = os.environ.get("HERMES_INSTALL_CMD", HERMES_INSTALL_SH)
        run_cmd(["bash", "-lc", install_cmd], None, None, 1200)
    _augment_path(*bin_dirs)
    return cli_path("hermes") or _find_hermes_under_home()


def _hermes_home() -> Path:
    """Where Hermes keeps its home: HERMES_HOME when set, else the installer's
    default -- %LOCALAPPDATA%\\hermes on Windows (install.ps1), ~/.hermes
    elsewhere. Driving Hermes with any other HERMES_HOME makes its first run
    build a second runtime under that home (a fresh `uv sync`): forcing
    ~/.hermes on Windows did exactly that, and the rebuild failed installing
    pywin32 while the installer's own build of the same wheel had succeeded
    minutes earlier (fleet run 36260299827, 2026-09-26). The observer finds
    the default home on its own (foundation resolve_hermes_home falls back to
    %LOCALAPPDATA%\\hermes on Windows)."""
    custom = os.environ.get("HERMES_HOME", "").strip()
    if custom:
        return Path(custom)
    if is_windows():
        local = os.environ.get("LOCALAPPDATA", "").strip()
        if local:
            return Path(local) / "hermes"
    return Path.home() / ".hermes"


def drive_hermes(workdir: Path, prompt: str, timeout: int, background: bool, log_path: Path | None):
    cli = ensure_hermes_installed()
    if not cli:
        raise AgentInstallUnavailable(
            "upstream Hermes installer did not produce a CLI (see install output above)",
            tail=last_cmd_output_tail(),
        )
    key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not key:
        return None
    hermes_home = _hermes_home()
    hermes_home.mkdir(parents=True, exist_ok=True)
    # Hermes loads credentials from <HERMES_HOME>/.env even with --ignore-user-config.
    env_lines = [f"ANTHROPIC_API_KEY={key}"]
    if os.environ.get("OPENAI_API_KEY"):
        env_lines.append(f"OPENAI_API_KEY={os.environ['OPENAI_API_KEY']}")
    (hermes_home / ".env").write_text("\n".join(env_lines) + "\n", encoding="utf-8")
    env = {"ANTHROPIC_API_KEY": key, "HERMES_HOME": str(hermes_home)}
    cfg = os.environ.get("HERMES_CONFIG_SET", "")
    if cfg:  # best-effort: also leaves a config.yaml so ~/.hermes is discoverable
        run_cmd([cli, "config", "set", *shlex.split(cfg)], workdir, env, 120)
    provider = os.environ.get("HERMES_PROVIDER", "anthropic")
    model = os.environ.get("HERMES_MODEL", "")
    # `chat -q` persists a session under ~/.hermes (unlike `-z`, which suppresses it).
    cmd = [cli, "chat", "-q", prompt]
    if provider:
        cmd += ["--provider", provider]
    if model:
        cmd += ["--model", model]
    extra = os.environ.get("HERMES_DRIVE_EXTRA_ARGS", "")
    if extra:
        cmd += shlex.split(extra)
    if background:
        assert log_path is not None
        return popen_cmd(cmd, workdir, env, log_path)
    return run_cmd(cmd, workdir, env, timeout)


_OPENCLAW_ONBOARDED = {"done": False}


def ensure_openclaw_installed() -> str | None:
    found = cli_path("openclaw")
    if found:
        return found
    pkg = os.environ.get("OPENCLAW_NPM_PKG", "openclaw@latest")
    log("  installing OpenClaw CLI (npm -g)")
    run_cmd(["npm", "install", "-g", pkg], None, None, 900)
    try:
        # encoding/errors are MANDATORY here: npm emits UTF-8 (box-drawing chars in
        # update notices), and on Windows text=True defaults to the cp1252 charmap
        # codec, which raises UnicodeDecodeError on those bytes and kills the thread.
        r = subprocess.run(
            ["npm", "prefix", "-g"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
        )
        if r.returncode == 0 and r.stdout.strip():
            _augment_path(str(Path(r.stdout.strip()) / "bin"), r.stdout.strip())
    except Exception:  # noqa: BLE001
        pass
    return cli_path("openclaw")


def _openclaw_agent_name() -> str:
    override = os.environ.get("OPENCLAW_AGENT", "")
    if override:
        return override
    agents_dir = Path.home() / ".openclaw" / "agents"
    if agents_dir.is_dir():
        for cand in ("main", "default"):
            if (agents_dir / cand).is_dir():
                return cand
        subs = sorted(p.name for p in agents_dir.iterdir() if p.is_dir())
        if subs:
            return subs[0]
    return "main"


def _openclaw_env(key: str) -> dict:
    """The environment OpenClaw runs in. On Windows its SQLite read-only worker
    stages snapshots in a private directory under %LOCALAPPDATA%\\openclaw, and
    creating it failed on windows-latest ("Unable to create private Windows
    SQLite directory ... set XDG_CACHE_HOME to a writable filesystem", fleet
    run 36260299827 attempt 2; 2026.8.2 failed the same way earlier), so the
    CLI never started. Point the cache at the runner's scratch space, as the
    error advises; sessions stay under ~/.openclaw, where the observer reads
    them."""
    env = {"ANTHROPIC_API_KEY": key}
    if is_windows():
        cache = Path(os.environ.get("RUNNER_TEMP") or tempfile.gettempdir()) / "openclaw-xdg-cache"
        cache.mkdir(parents=True, exist_ok=True)
        env["XDG_CACHE_HOME"] = str(cache)
    return env


def _openclaw_onboard(cli: str, key: str, workdir: Path) -> None:
    if _OPENCLAW_ONBOARDED["done"] or os.environ.get("OPENCLAW_SKIP_ONBOARD") == "1":
        return
    args = [
        cli, "onboard", "--non-interactive", "--mode", "local",
        "--auth-choice", "apiKey", "--anthropic-api-key", key,
        "--secret-input-mode", "plaintext",
        "--gateway-port", os.environ.get("OPENCLAW_GATEWAY_PORT", "18789"),
        "--gateway-bind", "loopback",
        "--skip-skills", "--skip-bootstrap", "--accept-risk",
    ]
    extra = os.environ.get("OPENCLAW_ONBOARD_EXTRA_ARGS", "")
    if extra:
        args += shlex.split(extra)
    # Tolerate a non-zero/timeout onboarding; the drive below is the real gate.
    run_cmd(args, workdir, _openclaw_env(key), 300)
    _OPENCLAW_ONBOARDED["done"] = True


def drive_openclaw(workdir: Path, prompt: str, timeout: int, background: bool, log_path: Path | None):
    cli = ensure_openclaw_installed()
    if not cli:
        raise AgentInstallUnavailable(
            "upstream OpenClaw npm install did not produce a CLI (see install output above)",
            tail=last_cmd_output_tail(),
        )
    key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not key:
        return None
    _openclaw_onboard(cli, key, workdir)
    agent = _openclaw_agent_name()
    model = os.environ.get("OPENCLAW_MODEL", "")
    tmpl = os.environ.get("OPENCLAW_DRIVE_CMD", "")
    if tmpl:
        cmd = shlex.split(tmpl.format(cli=cli, agent=agent, prompt=prompt, model=model))
    else:
        cmd = [cli, "agent", "--agent", agent, "--message", prompt, "--local"]
        if model:
            cmd += ["--model", model]
        extra = os.environ.get("OPENCLAW_DRIVE_EXTRA_ARGS", "")
        if extra:
            cmd += shlex.split(extra)
    env = _openclaw_env(key)
    if background:
        assert log_path is not None
        return popen_cmd(cmd, workdir, env, log_path)
    return run_cmd(cmd, workdir, env, timeout)


def drive_claude_desktop(workdir: Path, prompt: str, timeout: int, background: bool, log_path: Path | None):
    # Claude Desktop is a GUI app with NO supported headless drive CLI. We do not
    # fabricate a transcript. Best-effort + non-gating: if a local-agent-mode
    # transcript root already exists on the box the observer will discover it;
    # otherwise this honestly reports "no headless drive available".
    log("  claude_desktop: no headless drive CLI (GUI app) -- best-effort, non-gating")
    return None


# agent_type -> driver spec. `gate` is "hard" (gated on detection once attempted)
# or "best_effort" (never gating). `self_install` drivers install their own CLI,
# so a missing CLI on PATH is not a skip reason.
#
# Per-agent real-coverage floor: every agent in REQUIRED_HARD_AGENTS must be driven
# AND detected on every leg, whatever the reason it would otherwise be skipped
# (absent key, missing CLI, --agents filter). hermes/openclaw stay HARD when
# attempted but are not floor members, so a run that only drives them cannot pass.
REAL_DRIVERS = {
    "claude_code": {
        "cli": ["claude"],
        "key_env": "ANTHROPIC_API_KEY",
        "drive": drive_claude_code,
        "gate": "hard",
        "prompt": NORMAL_PROMPT,
    },
    "codex": {
        "cli": ["codex"],
        "key_env": "OPENAI_API_KEY",
        "drive": drive_codex,
        "gate": "hard",
        "prompt": NORMAL_PROMPT,
    },
    "hermes": {
        "cli": ["hermes"],
        "key_env": "ANTHROPIC_API_KEY",
        "drive": drive_hermes,
        "gate": "hard",
        "self_install": True,
        "prompt": NORMAL_PROMPT_SIMPLE,
    },
    "openclaw": {
        "cli": ["openclaw"],
        "key_env": "ANTHROPIC_API_KEY",
        "drive": drive_openclaw,
        "gate": "hard",
        "self_install": True,
        "prompt": NORMAL_PROMPT_SIMPLE,
    },
    "claude_desktop": {
        "cli": [],
        "key_env": "ANTHROPIC_API_KEY",
        "drive": drive_claude_desktop,
        "gate": "best_effort",
        "prompt": NORMAL_PROMPT_SIMPLE,
    },
}

# Agents with no real driver at all in hosted CI -> non-gating skip.
SKIP_REASONS = {
    "cursor": "GUI IDE; no headless Cursor agent CLI + CURSOR_API_KEY wired in hosted CI",
}

# Per-agent OSes with no headless installer/runtime -> non-gating skip even for a
# HARD agent ("skip only if no OS installer"). Hermes now ships install.sh
# (Linux/macOS) AND install.ps1 (Windows); openclaw/codex/claude (npm) run
# everywhere -- so every HARD agent has a headless installer on all desktop OSes.
NO_INSTALLER: dict[str, set[str]] = {}


def host_os() -> str:
    if is_windows():
        return "windows"
    if platform.system() == "Darwin":
        return "macos"
    return "linux"


def gate_class(agent_type: str) -> str:
    spec = REAL_DRIVERS.get(agent_type)
    return spec["gate"] if spec else "skip"


def real_driver_available(agent_type: str) -> tuple[str, str]:
    """Classify whether the real driver can run: ("ok" | "skip" | "install_failed", reason).

    "skip" is the non-gating class (no driver at all, no OS installer, or no
    provider key). "install_failed" is the HARD class: the provider key IS present
    but the workflow-installed CLI is absent, i.e. the install step failed -- that
    is exactly the 2026-09-09 shape (one atomic `npm install -g claude codex
    openclaw` killed by openclaw's Node>=24 requirement) that must not read as a
    skip. Self-installing drivers raise AgentInstallUnavailable from inside the
    drive instead; both land in the same hard bucket."""
    spec = REAL_DRIVERS.get(agent_type)
    if not spec:
        return "skip", SKIP_REASONS.get(agent_type, "no real driver for this agent in hosted CI")
    osn = host_os()
    if osn in NO_INSTALLER.get(agent_type, set()):
        return "skip", f"no headless {agent_type} installer/runtime for {osn} in hosted CI"
    key_env = spec.get("key_env")
    if key_env and not os.environ.get(key_env, ""):
        return "skip", f"{key_env} not set (no provider key to drive the real agent)"
    # Self-installing drivers install their own CLI, so a missing binary is fine.
    if not spec.get("self_install") and spec["cli"] and not cli_path(*spec["cli"]):
        return (
            "install_failed",
            f"{spec['cli'][0]} CLI not on PATH with {key_env} set "
            f"(workflow install of the agent runtime failed)",
        )
    return "ok", "real driver available"


def _divergence_status() -> tuple[bool, int, int]:
    s = cli_rpc("get_divergence_engine_status")
    if not isinstance(s, dict):
        return False, 0, 0
    return (
        bool(s.get("running")),
        int(s.get("contributor_count") or 0),
        int(s.get("model_age_secs") or 0),
    )


def _llm_probe() -> str:
    """Probe the daemon's configured LLM provider. The behavioral-model build
    depends on it, so a failed probe pinpoints an LLM/Portal/config problem
    rather than a transcript-pipeline problem."""
    res = rpc_quiet("agentic_test_llm")
    if isinstance(res, dict):
        return (
            f"success={res.get('success')} provider={res.get('provider')!r} "
            f"message={res.get('message')!r}"
        )
    return f"(unparsed: {str(res)[:200]})"


def ensure_daemon_llm_provider() -> str:
    """Configure the daemon's LLM provider for the plugin-free observer path.

    The host-side observer builds behavioral models via
    upsert_behavioral_model_from_raw_sessions, which is a DAEMON-side LLM
    round-trip: it needs a provider configured ON THE DAEMON process. The posture
    action is asked to set `agentic_provider: edamame`, but that runs in the
    action's daemon-start path and has not reliably reached the live daemon
    (observed provider='none' via agentic_test_llm, while the plugin path used to
    push a pre-built window and never needed it). The driver holds
    EDAMAME_LLM_API_KEY in its own env, so it configures the daemon directly
    through the documented headless CI/CD auth RPC -- agentic_set_edamame_api_key
    -- which sets provider='internal' + the key and persists it core-side.
    Passing the actual key VALUE (not relying on the daemon inheriting the env)
    sidesteps any sudo env-forwarding gap on the daemon-start side. Idempotent;
    safe to call repeatedly. Returns the post-config probe string."""
    before = _llm_probe()
    key = os.environ.get("EDAMAME_LLM_API_KEY", "").strip()
    if not key:
        log(f"  WARN: EDAMAME_LLM_API_KEY unset -- cannot configure daemon LLM (probe: {before})")
        return before
    res = rpc_quiet("agentic_set_edamame_api_key", json.dumps({"api_key": key}))
    after = _llm_probe()
    log(f"  agentic_set_edamame_api_key -> {res!r} | before: {before} | after: {after}")
    return after


def _force_model_build(agent_type: str) -> tuple[bool, str]:
    """Force a fresh behavioral-model build, bypassing the observer's hash-skip.

    The observer tick hash-skips the LLM round-trip when the transcript payload
    is byte-identical to the last successful ingest, so repeated ticks cannot
    rebuild a model that failed to register the first time. This collects the
    agent's raw activity and feeds it straight to
    upsert_behavioral_model_from_raw_sessions (the exact payload the observer
    would use), so every call genuinely re-runs the build. Returns (ok, detail);
    on failure `detail` carries the VERBATIM core error so CI shows the real
    root cause instead of a silent 'model never reached the engine'."""
    raw = rpc_quiet(
        "get_raw_agent_activity",
        json.dumps({"agent_type": agent_type, "active_window_minutes": 0, "limit": 0}),
    )
    if not isinstance(raw, dict):
        return False, "get_raw_agent_activity returned no object"
    if raw.get("error"):
        return False, f"collect error: {raw.get('error')}"
    payload = raw.get("payload") or {}
    sessions = payload.get("sessions") or []
    diag = raw.get("diagnostics") or {}
    if not sessions:
        return False, (
            "no raw sessions to model "
            f"(root_accessible={diag.get('transcripts_root_accessible')} "
            f"roots={diag.get('transcripts_roots')})"
        )
    res = rpc_quiet(
        "upsert_behavioral_model_from_raw_sessions",
        json.dumps({"raw_sessions_json": json.dumps(payload)}),
    )
    if isinstance(res, dict) and res.get("success"):
        win = res.get("window") or {}
        return True, f"built from {len(sessions)} session(s) (hash={str(win.get('hash'))[:12]})"
    err = res.get("error") if isinstance(res, dict) else res
    return False, f"upsert failed from {len(sessions)} session(s): {err}"


def dump_model_scope() -> None:
    """Print the (truncated) frozen behavioral model so CI logs show the exact
    scope arrays the egress lineage must match."""
    raw = rpc_quiet("get_behavioral_model")
    if not isinstance(raw, str) or not raw.strip():
        log("  (behavioral model dump unavailable)")
        return
    try:
        pretty = json.dumps(json.loads(raw), separators=(",", ":"))
    except Exception:  # noqa: BLE001
        pretty = raw
    if len(pretty) > 4000:
        pretty = pretty[:4000] + " ...(truncated)"
    log(f"  model: {pretty}")
