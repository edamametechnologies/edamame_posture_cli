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
"""

from __future__ import annotations

import os
import platform
import shutil
import tempfile
from pathlib import Path
from typing import Callable, Dict, Tuple

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
}


def run_action(name: str, ws: Path) -> ActionResult:
    log(f"  direct action: {name} in {ws}")
    return ACTIONS[name](ws)
