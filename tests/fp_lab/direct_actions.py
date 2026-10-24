#!/usr/bin/env python3
"""Direct (agent-free) FP lab scenarios.

Each action performs one ordinary piece of developer work with no agent in
the loop, through the shared harness's ``run_cmd`` (the same subprocess
helper the fleet E2E uses; it echoes the command and its output into the run
log). An action returns ``(delivered, detail)``: ``delivered`` is False when
the stimulus did not happen (a tool failed before doing the thing the
scenario is about), which the runner reports as SKIP unless a finding
appeared anyway.

Temp scenarios create their own ``tempfile.mkdtemp`` directory (OS temp, as a
developer's ``mktemp -d`` would) and remove it afterwards. Everything else
stays in the case workspace under the lab root.

The operator's-day actions (end of the file) reproduce shapes seen on a
developer Mac on 2026-10-23. Their temp writes go to ``/tmp`` on Linux and
macOS, where those shapes were, and to ``%TEMP%`` on Windows; each uses
uniquely named paths and removes them.
"""

from __future__ import annotations

import io
import json
import os
import platform
import plistlib
import re
import secrets
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from agent_harness import cli_path, last_cmd_output_tail, log, run_cmd

ActionResult = Tuple[bool, str]

UA = "fp-lab/1.0 (+https://github.com/edamametechnologies/edamame_posture)"


def _is_windows() -> bool:
    return platform.system() == "Windows"


def _exe(path: Path) -> str:
    return str(path.with_suffix(".exe")) if _is_windows() else str(path)


def _rm(path: Path) -> None:
    shutil.rmtree(path, ignore_errors=True)


def _cargo() -> str | None:
    return cli_path("cargo") or (
        str(Path.home() / ".cargo" / "bin" / "cargo")
        if (Path.home() / ".cargo" / "bin" / "cargo").exists() else None
    )


# ── Rust ────────────────────────────────────────────────────────────────

def _build_rust(where: Path) -> ActionResult:
    cargo = _cargo()
    if not cargo:
        return False, "cargo not found"
    crate = where / "lab_clock"
    if run_cmd([cargo, "new", "--bin", "--vcs", "none", "--quiet", str(crate)], where, None, 300) != 0:
        return False, "cargo new failed"
    (crate / "src" / "main.rs").write_text(
        "use std::time::{SystemTime, UNIX_EPOCH};\n\n"
        "fn main() {\n"
        "    let secs = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);\n"
        "    println!(\"{secs}\");\n"
        "}\n",
        encoding="utf-8",
    )
    if run_cmd([cargo, "build", "--release", "--quiet"], crate, None, 900) != 0:
        return False, "cargo build failed"
    rc = run_cmd([_exe(crate / "target" / "release" / "lab_clock")], crate, None, 60)
    return rc == 0, f"built and ran lab_clock in {where}"


def build_rust_workspace(ws: Path) -> ActionResult:
    return _build_rust(ws)


def build_rust_temp(ws: Path) -> ActionResult:
    tmp = Path(tempfile.mkdtemp(prefix="rs-build-"))
    try:
        return _build_rust(tmp)
    finally:
        _rm(tmp)


# ── Python venv ─────────────────────────────────────────────────────────

def _venv_python(venv: Path) -> Path:
    return venv / ("Scripts/python.exe" if _is_windows() else "bin/python")


def _py_venv(where: Path) -> ActionResult:
    python = cli_path("python3", "python")
    if not python:
        return False, "python3 not found"
    venv = where / ".venv-lab"
    uv = cli_path("uv") or (str(Path.home() / ".local" / "bin" / "uv")
                            if (Path.home() / ".local" / "bin" / "uv").exists() else None)
    if run_cmd([python, "-c", "import ensurepip"], where, None, 60) == 0:
        if run_cmd([python, "-m", "venv", str(venv)], where, None, 300) != 0:
            return False, "python -m venv failed"
        if run_cmd([str(_venv_python(venv)), "-m", "pip", "install", "--quiet", "requests"], where, None, 600) != 0:
            return False, "pip install requests failed"
        tool = "venv+pip"
    elif uv:
        if run_cmd([uv, "venv", "--quiet", str(venv)], where, None, 300) != 0:
            return False, "uv venv failed"
        if run_cmd([uv, "pip", "install", "--quiet", "--python", str(_venv_python(venv)), "requests"],
                   where, None, 600) != 0:
            return False, "uv pip install requests failed"
        tool = "uv"
    else:
        return False, "neither python3 -m venv (ensurepip) nor uv is available"
    rc = run_cmd(
        [str(_venv_python(venv)), "-c",
         "import requests; r = requests.get('https://pypi.org/pypi/requests/json', timeout=30); "
         "print(r.json()['info']['version'])"],
        where, None, 120,
    )
    return rc == 0, f"{tool} venv in {where}, requests installed and used"


def py_venv_workspace(ws: Path) -> ActionResult:
    return _py_venv(ws)


def py_venv_temp(ws: Path) -> ActionResult:
    tmp = Path(tempfile.mkdtemp(prefix="py-try-"))
    try:
        return _py_venv(tmp)
    finally:
        _rm(tmp)


# ── npm ─────────────────────────────────────────────────────────────────

def _npm(where: Path) -> ActionResult:
    npm = cli_path("npm")
    node = cli_path("node")
    if not npm or not node:
        return False, "npm/node not found"
    if run_cmd([npm, "init", "-y"], where, None, 120) != 0:
        return False, "npm init failed"
    if run_cmd([npm, "install", "--no-audit", "--no-fund", "is-number"], where, None, 600) != 0:
        return False, "npm install failed"
    rc = run_cmd([node, "-e", "console.log(require('is-number')(5))"], where, None, 60)
    return rc == 0, f"npm project in {where}"


def npm_workspace(ws: Path) -> ActionResult:
    proj = ws / "npm-proj"
    proj.mkdir(parents=True, exist_ok=True)
    return _npm(proj)


def npm_temp(ws: Path) -> ActionResult:
    tmp = Path(tempfile.mkdtemp(prefix="npm-try-"))
    try:
        return _npm(tmp)
    finally:
        _rm(tmp)


# ── git ─────────────────────────────────────────────────────────────────

LAB_GIT_ENV = {
    "GIT_AUTHOR_NAME": "FP Lab",
    "GIT_AUTHOR_EMAIL": "fp-lab@example.invalid",
    "GIT_COMMITTER_NAME": "FP Lab",
    "GIT_COMMITTER_EMAIL": "fp-lab@example.invalid",
    "GIT_TERMINAL_PROMPT": "0",
}


def git_lab_repo(ws: Path) -> ActionResult:
    git = cli_path("git")
    if not git:
        return False, "git not found"
    env = dict(LAB_GIT_ENV)
    public = ws / "hello-world"
    if run_cmd([git, "clone", "--depth", "1", "https://github.com/octocat/Hello-World.git", str(public)],
               ws, env, 300) != 0:
        return False, "public clone failed"
    run_cmd([git, "-C", str(public), "fetch", "--depth", "1", "origin"], ws, env, 300)
    bare = ws / "remotes" / "lab.git"
    bare.parent.mkdir(parents=True, exist_ok=True)
    if run_cmd([git, "init", "--bare", "-q", "-b", "main", str(bare)], ws, env, 60) != 0:
        return False, "bare init failed"
    work = ws / "lab-clone"
    if run_cmd([git, "clone", "-q", str(bare), str(work)], ws, env, 120) != 0:
        return False, "lab clone failed"
    (work / "CHANGELOG.md").write_text("# Changelog\n\n- first entry\n", encoding="utf-8")
    run_cmd([git, "-C", str(work), "checkout", "-q", "-b", "main"], ws, env, 60)
    run_cmd([git, "-C", str(work), "add", "-A"], ws, env, 60)
    run_cmd([git, "-C", str(work), "commit", "-q", "-m", "Add changelog"], ws, env, 60)
    if run_cmd([git, "-C", str(work), "push", "-q", "origin", "main"], ws, env, 120) != 0:
        return False, "push to the lab bare repo failed"
    other = ws / "lab-clone-2"
    run_cmd([git, "clone", "-q", str(bare), str(other)], ws, env, 120)
    rc = run_cmd([git, "-C", str(other), "fetch", "-q", "origin"], ws, env, 120)
    return rc == 0, "GitHub HTTPS clone+fetch; lab bare repo clone/commit/push/fetch"


def git_credential_helper(ws: Path) -> ActionResult:
    """git reads a credential store through its helper, then talks to github.com.

    The store and the gitconfig are lab-local: GIT_CONFIG_GLOBAL points git at
    the lab gitconfig and GIT_CONFIG_NOSYSTEM drops /etc/gitconfig, so the
    user's real ~/.gitconfig and ~/.git-credentials are never read or written.
    The token is a placeholder, not a credential."""
    git = cli_path("git")
    if not git:
        return False, "git not found"
    cred_dir = ws / "git-cred-lab"
    cred_dir.mkdir(parents=True, exist_ok=True)
    store = cred_dir / ".git-credentials"
    store.write_text("https://fp-lab:placeholder-not-a-token@github.com\n", encoding="utf-8")
    try:
        os.chmod(store, 0o600)
    except OSError:
        pass
    gitconfig = cred_dir / "gitconfig"
    store_path = store.as_posix()
    gitconfig.write_text(
        "[credential]\n"
        f"\thelper = store --file={store_path}\n",
        encoding="utf-8",
    )
    env = dict(LAB_GIT_ENV)
    env["GIT_CONFIG_GLOBAL"] = str(gitconfig)
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    rc = run_cmd([git, "credential", "fill"], cred_dir, env, 60,
                 stdin_text="protocol=https\nhost=github.com\n\n")
    out = "\n".join(last_cmd_output_tail(50))
    if rc != 0 or "username=fp-lab" not in out:
        return False, "credential helper did not answer"
    rc = run_cmd([git, "ls-remote", "https://github.com/octocat/Hello-World.git", "HEAD"], cred_dir, env, 120)
    return rc == 0, "credential-store helper read, then git ls-remote to github.com"


# ── curl / installers ───────────────────────────────────────────────────

PUBLIC_API_URLS = (
    "https://api.github.com/zen",
    "https://pypi.org/pypi/requests/json",
    "https://registry.npmjs.org/left-pad",
    "https://crates.io/api/v1/crates/serde",
    "https://status.sentry.io/api/v2/status.json",
    "https://raw.githubusercontent.com/edamametechnologies/threatmodels/main/README.md",
)


def curl_public_apis(ws: Path) -> ActionResult:
    curl = cli_path("curl")
    if not curl:
        return False, "curl not found"
    ok = 0
    for url in PUBLIC_API_URLS:
        rc = run_cmd([curl, "-fsS", "-A", UA, "-o", os.devnull, "-w", "%{http_code}\\n", url], ws, None, 60)
        ok += 1 if rc == 0 else 0
    return ok > 0, f"{ok}/{len(PUBLIC_API_URLS)} public API calls succeeded"


def rustup_init_temp_staging(ws: Path) -> ActionResult:
    """The rustup bootstrap: a script downloaded to temp downloads rustup-init
    into another temp dir and runs it, which then talks to static.rust-lang.org.
    RUSTUP_HOME / CARGO_HOME are inside the staging dir, so the user's real
    toolchain is untouched, and no toolchain is installed."""
    curl = cli_path("curl")
    sh = cli_path("sh")
    if not curl or not sh:
        return False, "curl/sh not found"
    tmp = Path(tempfile.mkdtemp(prefix="rustup-stage-"))
    try:
        script = tmp / "rustup-init.sh"
        if run_cmd([curl, "-fsSL", "--proto", "=https", "--tlsv1.2", "-o", str(script), "https://sh.rustup.rs"],
                   tmp, None, 120) != 0:
            return False, "download of rustup-init.sh failed"
        env = {"RUSTUP_HOME": str(tmp / "rustup"), "CARGO_HOME": str(tmp / "cargo"), "RUSTUP_INIT_SKIP_PATH_CHECK": "yes"}
        rc = run_cmd([sh, str(script), "-y", "--no-modify-path", "--default-toolchain", "none", "--profile", "minimal"],
                     tmp, env, 600)
        if rc != 0:
            return False, "rustup-init failed"
        rc = run_cmd([str(tmp / "cargo" / "bin" / "rustup"), "--version"], tmp, env, 60)
        return rc == 0, "rustup-init staged and executed from OS temp"
    finally:
        _rm(tmp)


# ── operator's day (developer Mac, 2026-10-23) ─────────────────────────

STANDINS = Path(__file__).resolve().parent / "standins.py"


def _temp_root() -> Path:
    if not _is_windows() and Path("/tmp").is_dir():
        return Path("/tmp")
    return Path(tempfile.gettempdir())


# 1. A headless Chromium-family browser on its own --user-data-dir profile.

BROWSER_SITES = (
    "https://github.com/edamametechnologies",
    "https://www.wikipedia.org/",
    "https://www.python.org/",
    "https://www.mozilla.org/en-US/",
    "https://pypi.org/",
    "https://www.rust-lang.org/",
)
BROWSER_SECS_PER_SITE = 15


def _chromium_candidates() -> List[Path]:
    """Playwright's browsers first (the shape seen: its chrome-headless-shell
    and Chrome for Testing), then installed Chromium-family browsers.
    FP_LAB_BROWSER overrides."""
    home = Path.home()
    out: List[Path] = []
    if os.environ.get("FP_LAB_BROWSER"):
        out.append(Path(os.environ["FP_LAB_BROWSER"]))
    system = platform.system()
    if system == "Darwin":
        pw = home / "Library" / "Caches" / "ms-playwright"
        for pattern in ("chromium_headless_shell-*/*/chrome-headless-shell",
                        "chromium_headless_shell-*/*/headless_shell",
                        "chromium-*/*/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing",
                        "chromium-*/*/Chromium.app/Contents/MacOS/Chromium"):
            out += sorted(pw.glob(pattern), reverse=True)
        for app in ("Google Chrome", "Chromium", "Microsoft Edge", "Brave Browser"):
            for root in (Path("/Applications"), home / "Applications"):
                out.append(root / f"{app}.app" / "Contents" / "MacOS" / app)
    elif _is_windows():
        local = Path(os.environ.get("LOCALAPPDATA") or (home / "AppData" / "Local"))
        pw = local / "ms-playwright"
        for pattern in ("chromium_headless_shell-*/*/chrome-headless-shell.exe",
                        "chromium_headless_shell-*/*/headless_shell.exe",
                        "chromium-*/*/chrome.exe"):
            out += sorted(pw.glob(pattern), reverse=True)
        for base in (os.environ.get("ProgramFiles"), os.environ.get("ProgramFiles(x86)"), str(local)):
            if base:
                out.append(Path(base) / "Google" / "Chrome" / "Application" / "chrome.exe")
                out.append(Path(base) / "Microsoft" / "Edge" / "Application" / "msedge.exe")
                out.append(Path(base) / "BraveSoftware" / "Brave-Browser" / "Application" / "brave.exe")
    else:
        pw = home / ".cache" / "ms-playwright"
        for pattern in ("chromium_headless_shell-*/*/chrome-headless-shell",
                        "chromium_headless_shell-*/*/headless_shell",
                        "chromium-*/*/chrome"):
            out += sorted(pw.glob(pattern), reverse=True)
        for name in ("google-chrome", "google-chrome-stable", "chromium", "chromium-browser",
                     "microsoft-edge", "brave-browser"):
            found = shutil.which(name)
            if found:
                out.append(Path(found))
    return out


def _find_chromium() -> Optional[Path]:
    for cand in _chromium_candidates():
        if cand.is_file() and os.access(cand, os.X_OK):
            return cand
    return None


def _devtools(port: int, path: str, method: str = "GET") -> object:
    """The DevTools HTTP endpoint on loopback (no websocket needed)."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", method=method)
    with opener.open(req, timeout=20) as resp:
        body = resp.read().decode("utf-8", "replace")
    try:
        return json.loads(body)
    except ValueError:
        return body


def _open_tab(port: int, url: str) -> Optional[str]:
    for method in ("PUT", "GET"):  # PUT since Chrome 111; older builds take GET
        try:
            target = _devtools(port, f"/json/new?{url}", method)
        except urllib.error.HTTPError as exc:
            if exc.code == 405 and method == "PUT":
                continue
            raise
        return target.get("id") if isinstance(target, dict) else None
    return None


def _stop_process_tree(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    if _is_windows():
        subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"], capture_output=True)
    else:
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except OSError:
            proc.terminate()
    try:
        proc.wait(timeout=20)
    except subprocess.TimeoutExpired:
        if _is_windows():
            proc.kill()
        else:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except OSError:
                proc.kill()
        proc.wait(timeout=10)


def _browser_launch(browser: Path, profile: Path, sites: Sequence[str], log_path: Path) -> Tuple[int, str]:
    """One launch: headless, on its own profile, opening each site in turn
    and keeping it open BROWSER_SECS_PER_SITE seconds. Returns (sites
    opened, problem)."""
    headless = "--headless" if "headless" in browser.name.lower() else "--headless=new"
    args = [str(browser), headless, f"--user-data-dir={profile}", "--remote-debugging-port=0",
            "--no-first-run", "--no-default-browser-check", "--disable-extensions", "--disable-default-apps",
            "--disable-sync", "--disable-background-networking", "--disable-component-update",
            "--disable-breakpad", "--metrics-recording-only", "--enable-automation", "--mute-audio",
            # What Playwright passes too: keep the browser off the OS keychain
            # (macOS) and the desktop keyring (Linux); its cookie key stays
            # in the lab profile.
            "--use-mock-keychain", "--password-store=basic"]
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        args.append("--no-sandbox")  # Chromium refuses root without it (CI Linux leg)
    args.append("about:blank")
    log(f"  $ (bg) {' '.join(args)}  > {log_path.name}")
    port_file = profile / "DevToolsActivePort"
    port_file.unlink(missing_ok=True)
    with log_path.open("a", encoding="utf-8", errors="replace") as fh:
        kwargs: dict = {"stdout": fh, "stderr": subprocess.STDOUT, "stdin": subprocess.DEVNULL}
        if _is_windows():
            kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP  # type: ignore[attr-defined]
        else:
            kwargs["start_new_session"] = True
        proc = subprocess.Popen(args, **kwargs)
    opened = 0
    try:
        port = 0
        deadline = time.time() + 45
        while time.time() < deadline and proc.poll() is None:
            try:
                port = int(port_file.read_text(encoding="utf-8").splitlines()[0])
                break
            except (OSError, ValueError, IndexError):
                time.sleep(1)
        if not port:
            return 0, f"browser exited (rc={proc.poll()}) or opened no DevTools port within 45 s"
        previous: Optional[str] = None
        for url in sites:
            try:
                tab = _open_tab(port, url)
            except (OSError, urllib.error.URLError) as exc:
                log(f"  could not open {url}: {exc}")
                continue
            opened += 1
            log(f"  opened {url}")
            time.sleep(BROWSER_SECS_PER_SITE)
            if previous:
                try:
                    _devtools(port, f"/json/close/{previous}")
                except (OSError, urllib.error.URLError):
                    pass
            previous = tab
        return opened, ""
    finally:
        _stop_process_tree(proc)


def headless_browser_own_profile(ws: Path) -> ActionResult:
    """A headless Chromium-family browser (the Playwright shape) started with
    its own --user-data-dir test profile in the workspace, browsing real
    sites over HTTPS: the first launch creates the profile's cookie store,
    the second reads it back. The profile is the browser's own and holds
    only what those sites set; the user's real browser profiles are never
    opened."""
    browser = _find_chromium()
    if browser is None:
        return False, "no Chromium-family browser found (set FP_LAB_BROWSER to one)"
    profile = ws / "browser-test-profile"
    profile.mkdir(parents=True, exist_ok=True)
    log_path = ws / "browser.log"
    half = len(BROWSER_SITES) // 2
    try:
        first, problem = _browser_launch(browser, profile, BROWSER_SITES[:half], log_path)
        if problem or not first:
            return False, f"{browser.name}: {problem or 'no site opened'}"
        # Default/Network/Cookies in current Chromium, Default/Cookies before.
        cookies = next((p for p in sorted(profile.rglob("Cookies")) if p.is_file()), None)
        if cookies is None:
            return False, f"{browser.name}: no cookie store in the profile after the first launch"
        second, problem = _browser_launch(browser, profile, BROWSER_SITES[half:], log_path)
        if problem or not second:
            return False, f"{browser.name}: second launch: {problem or 'no site opened'}"
        return True, (f"{browser.name}: {first + second}/{len(BROWSER_SITES)} sites over two launches on its own "
                      f"profile ({cookies.relative_to(profile).as_posix()})")
    finally:
        _rm(profile)


# 2. macOS: an OS platform binary holding keychain sidecars during HTTPS.

APPLE_PROBE_URL = "https://www.apple.com/library/test/success.html"


def _wait_status_exit_code(status: int) -> int:
    """launchctl reports a job's last exit as a wait(2) status."""
    if status & 0x7F:
        return 128 + (status & 0x7F)
    return status >> 8


def _run_under_launchd(argv: List[str], cwd: Path, timeout: int) -> Tuple[int, str]:
    """Run argv as a one-shot job of the user's launchd domain, so its parent
    is launchd, as an OS daemon's is, and wait for it to exit. Returns its
    exit code (124 on timeout, 125 when the job could not be loaded) and its
    output."""
    label = f"tech.edamame.fplab.{secrets.token_hex(4)}"
    out_path = cwd / f"{label}.log"
    plist = cwd / f"{label}.plist"
    plist.write_bytes(plistlib.dumps({
        "Label": label,
        "ProgramArguments": argv,
        "RunAtLoad": True,
        "KeepAlive": False,
        "WorkingDirectory": str(cwd),
        "StandardOutPath": str(out_path),
        "StandardErrorPath": str(out_path),
    }))
    log(f"  $ launchctl load {plist.name}  ({' '.join(argv)})")
    loaded = subprocess.run(["launchctl", "load", str(plist)], capture_output=True, text=True)
    if loaded.returncode != 0:
        log((loaded.stdout or "") + (loaded.stderr or ""))
        plist.unlink(missing_ok=True)
        return 125, loaded.stderr or ""
    rc = 124
    try:
        deadline = time.monotonic() + timeout
        idle_polls = 0
        while time.monotonic() < deadline:
            time.sleep(2)
            q = subprocess.run(["launchctl", "list", label], capture_output=True, text=True)
            if q.returncode != 0:
                break
            if '"PID" =' in q.stdout:
                idle_polls = 0
                continue
            idle_polls += 1
            m = re.search(r'"LastExitStatus" = (-?\d+);', q.stdout)
            # Three polls without a PID: the job ran and exited (RunAtLoad
            # starts it at load), not "not started yet".
            if m and idle_polls >= 3:
                rc = _wait_status_exit_code(int(m.group(1)))
                break
        if rc == 124:
            log(f"  (timeout after {timeout}s)")
    finally:
        subprocess.run(["launchctl", "unload", str(plist)], capture_output=True)
        plist.unlink(missing_ok=True)
    out = out_path.read_text(encoding="utf-8", errors="replace") if out_path.is_file() else ""
    out_path.unlink(missing_ok=True)
    if out.strip():
        log(out.rstrip()[-2000:])
    return rc, out


def os_relay_keychain_sidecars(ws: Path) -> ActionResult:
    """Stand-in for an OS relay daemon (networkserviceproxy) holding the
    login keychain's lock and safe-save sidecars while it talks to Apple.
    /usr/bin/curl, an Apple platform binary, runs as a launchd job (launchd
    is its parent, as it is the daemon's) and holds open descriptors on two
    sidecar files of a TEST home's Library/Keychains (placeholders: an empty
    lock file and a copy of a placeholder database) while it requests
    Apple's connectivity page every 10 s for about 80 s. The job's shell
    opens the descriptors and execs curl. The real keychain and the user's
    Keychains directory are never opened; curl never reads the descriptors
    it holds."""
    if platform.system() != "Darwin":
        return False, "macOS only"
    curl = Path("/usr/bin/curl")
    if not curl.is_file():
        return False, "/usr/bin/curl not found"
    home = ws / "relay-home"
    keychains = home / "Library" / "Keychains"
    keychains.mkdir(parents=True, exist_ok=True)
    database = keychains / "login.keychain-db"
    database.write_bytes(b"fp-lab placeholder: not a keychain\n")
    lock = keychains / f".fl{secrets.token_hex(4).upper()}"
    lock.write_bytes(b"")
    sidecar = keychains / f"login.keychain-db.sb-{secrets.token_hex(4)}-{secrets.token_hex(3)}"
    shutil.copyfile(database, sidecar)
    hold = 'exec 3<"$1" 4<"$2"; shift 2; exec "$@"'
    try:
        cmd = [str(curl), "-sS", "-A", UA, "--rate", "6/m"]
        for _ in range(9):
            cmd += [APPLE_PROBE_URL, "-o", os.devnull]
        rc, out = _run_under_launchd(["/bin/sh", "-c", hold, "sh", str(lock), str(sidecar)] + cmd, ws, 240)
        if rc == 2 and "rate" in out:
            # curl older than 7.84 has no --rate: one slow transfer instead.
            slow = [str(curl), "-sS", "-A", UA, "--limit-rate", "2k", "--max-time", "90",
                    "-o", os.devnull, "https://www.apple.com/"]
            rc, _ = _run_under_launchd(["/bin/sh", "-c", hold, "sh", str(lock), str(sidecar)] + slow, ws, 180)
            rc = 0 if rc == 28 else rc  # 28: the 90 s budget ran out, the transfer was held
        if rc == 125:
            return False, "launchctl could not load the stand-in's job"
        return rc == 0, f"/usr/bin/curl (launchd job) held {lock.name} and {sidecar.name} during HTTPS to Apple (rc={rc})"
    finally:
        _rm(home)


# 3. A cloud-sync client renaming its own credential-store-like file.

def sync_client_store_rename(ws: Path) -> ActionResult:
    """A stand-in sync client (standins.py, run as its own process) creates
    its data directory under a TEST home in the workspace, at the platform's
    application-data layout, keeps a placeholder credentials.json there,
    holds it open while it syncs with googleapis.com over HTTPS for about
    80 s, and refreshes it three times with a safe-save rename. Its command
    line names the directory it owns."""
    home = ws / "sync-client-home"
    if platform.system() == "Darwin":
        data_dir = home / "Library" / "Application Support" / "FPLab Sync" / "account-0001"
    elif _is_windows():
        data_dir = home / "AppData" / "Local" / "FPLab Sync" / "account-0001"
    else:
        data_dir = home / ".config" / "fplab-sync" / "account-0001"
    client = ws / "sync-client" / "fplab_sync_client.py"
    client.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(STANDINS, client)
    try:
        rc = run_cmd([sys.executable, str(client), "sync-client", "--data-dir", str(data_dir), "--secs", "80"],
                     ws, None, 300)
        tail = "\n".join(last_cmd_output_tail(20))
        if rc == 3:
            return False, "this Python cannot verify TLS (no CA bundle, no certifi)"
        return rc == 0, next((ln for ln in tail.splitlines() if ln.startswith("sync-client:")), f"rc={rc}")
    finally:
        _rm(home)


# 4. A large installer staging into a sibling temp tree it creates.

INSTALLER_LOCALES = ("ar", "cs", "da", "de", "el", "en", "es", "fi", "fr", "he", "hu", "id", "it", "ja", "ko",
                     "nb", "nl", "pl", "pt", "ro", "ru", "sk", "sv", "th", "tr", "uk", "vi", "zh-CN", "zh-TW", "hi")
INSTALLER_COMPONENTS = 40
INSTALLER_PARTS = 10
INSTALLER_DOCS = ("README.txt", "LICENSE.txt", "NOTICE.txt", "CHANGES.txt", "THIRD-PARTY.txt",
                  "release.json", "checksums.json", "layout.json", "uninstall.json")


def _system_tar() -> Optional[Path]:
    if _is_windows():
        p = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "tar.exe"
    elif platform.system() == "Darwin":
        p = Path("/usr/bin/tar")
    else:
        found = shutil.which("tar")
        p = Path(found) if found else Path("/usr/bin/tar")
    return p if p.is_file() else None


def write_installer_payload(archive: Path, top: str) -> int:
    """A tar archive whose single top directory is `top`, holding inert data
    files (no executable bits, no scripts, no binaries): a manifest, 30
    locale string tables, 40 components of 1 descriptor and 10 data parts
    each, 9 documents. Returns the file count (480)."""
    count = 0

    def add(tf: tarfile.TarFile, rel: str, data: bytes) -> None:
        nonlocal count
        info = tarfile.TarInfo(f"{top}/{rel}")
        info.size = len(data)
        info.mode = 0o644
        info.mtime = int(time.time())
        tf.addfile(info, io.BytesIO(data))
        count += 1

    with tarfile.open(archive, "w", format=tarfile.PAX_FORMAT) as tf:
        add(tf, "manifest.xml", ("<?xml version=\"1.0\"?>\n<manifest product=\"FPLab Suite\" version=\"1.0.0\">\n"
                                 + "".join(f"  <component id=\"comp_{i:03d}\"/>\n" for i in range(INSTALLER_COMPONENTS))
                                 + "</manifest>\n").encode())
        for loc in INSTALLER_LOCALES:
            add(tf, f"resources/locales/{loc}/strings.json",
                json.dumps({"locale": loc, "title": "FPLab Suite", "welcome": "Installing FPLab Suite"}).encode())
        for i in range(INSTALLER_COMPONENTS):
            add(tf, f"payload/comp_{i:03d}/component.json",
                json.dumps({"id": f"comp_{i:03d}", "parts": INSTALLER_PARTS, "size": 4096 * INSTALLER_PARTS}).encode())
            for j in range(INSTALLER_PARTS):
                line = f"FPLAB-INSTALLER-ASSET comp={i:03d} part={j:02d}\n".encode()
                add(tf, f"payload/comp_{i:03d}/data_{j:02d}.dat", line * (64 + 16 * j))
        for name in INSTALLER_DOCS:
            add(tf, f"docs/{name}", f"FPLab Suite {name}\n".encode() * 20)
    return count


def installer_sibling_temp_staging(ws: Path) -> ActionResult:
    """The installer shape: a binary running from one per-invocation temp
    tree (<tmp>/<ID2>/FPLab Installer/) unpacks its payload into a sibling
    temp tree that it creates (<tmp>/<ID1>/, 480 files). The binary is a
    copy of the platform's own tar, the extractor a self-extracting
    installer carries; the payload is inert data. Both trees are removed."""
    tar_src = _system_tar()
    if tar_src is None:
        return False, "no system tar"
    root = _temp_root()
    run_tree = root / str(uuid.uuid4()).upper()
    staging_name = str(uuid.uuid4()).upper()
    staging = root / staging_name
    try:
        bindir = run_tree / "FPLab Installer"
        bindir.mkdir(parents=True)
        extractor = bindir / tar_src.name
        # copyfile, not copy2: copy2 also copies the file flags, and a
        # system binary's restricted flag cannot be set on the copy.
        shutil.copyfile(tar_src, extractor)
        extractor.chmod(0o755)
        payload = run_tree / "payload.tar"
        expected = write_installer_payload(payload, staging_name)
        try:
            rc = run_cmd([str(extractor), "-xf", str(payload), "-C", str(root)], run_tree, None, 300)
        except OSError as exc:  # a temp root mounted noexec
            return False, f"cannot run a binary from {root}: {exc}"
        staged = sum(1 for p in staging.rglob("*") if p.is_file()) if staging.is_dir() else 0
        return (rc == 0 and staged >= expected,
                f"{extractor} staged {staged}/{expected} files into {staging} (rc={rc})")
    finally:
        _rm(staging)
        _rm(run_tree)


# 5. A user's script writing a document in temp beside an unrelated request.

def script_document_in_temp(ws: Path) -> ActionResult:
    """A user's Python script (standins.py run as scripts/make_report.py)
    writes a PDF report into the temp directory, rewrites it once, and
    meanwhile requests pypi.org over HTTPS every few seconds for about 60 s.
    The PDF is text only; the file is removed afterwards."""
    script = ws / "scripts" / "make_report.py"
    script.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(STANDINS, script)
    out = _temp_root() / f"report-{secrets.token_hex(4)}.pdf"
    try:
        rc = run_cmd([sys.executable, str(script), "report", "--out", str(out), "--secs", "60"], ws, None, 240)
        tail = "\n".join(last_cmd_output_tail(20))
        if rc == 3:
            return False, "this Python cannot verify TLS (no CA bundle, no certifi)"
        return rc == 0, next((ln for ln in tail.splitlines() if ln.startswith("report:")), f"rc={rc}")
    finally:
        out.unlink(missing_ok=True)


ACTIONS: Dict[str, Callable[[Path], ActionResult]] = {
    "build_rust_workspace": build_rust_workspace,
    "build_rust_temp": build_rust_temp,
    "py_venv_workspace": py_venv_workspace,
    "py_venv_temp": py_venv_temp,
    "npm_workspace": npm_workspace,
    "npm_temp": npm_temp,
    "git_lab_repo": git_lab_repo,
    "git_credential_helper": git_credential_helper,
    "curl_public_apis": curl_public_apis,
    "rustup_init_temp_staging": rustup_init_temp_staging,
    "headless_browser_own_profile": headless_browser_own_profile,
    "os_relay_keychain_sidecars": os_relay_keychain_sidecars,
    "sync_client_store_rename": sync_client_store_rename,
    "installer_sibling_temp_staging": installer_sibling_temp_staging,
    "script_document_in_temp": script_document_in_temp,
}


def run_action(name: str, ws: Path) -> ActionResult:
    log(f"  direct action: {name} in {ws}")
    return ACTIONS[name](ws)
