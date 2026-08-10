#!/usr/bin/env python3
"""
Shared helper for calling edamame_cli RPC methods and parsing results.

RPC methods returning typed Rust structs (Vec<T>, ScoreAPI, etc.) produce
direct JSON.  Methods returning -> String (agentic domain: vuln findings,
divergence verdict, behavioral model) produce a JSON-encoded string
containing JSON, because the inner payload is pre-serialized.  This helper
detects which pattern was used and returns a parsed Python object in both
cases.

Usage as a library:
    from _edamame_cli import cli_rpc
    findings = cli_rpc("get_vulnerability_findings")

Usage from shell:
    python3 _edamame_cli.py get_vulnerability_findings
    python3 _edamame_cli.py get_anomalous_sessions
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path


TRANSIENT_ERROR_MARKERS = (
    "tcp connect error",
    "os error 10061",
    "os error 111",
    "Connection refused",
    "No connection could be made",
    "target machine actively refused",
    "transport error",
)


def _is_transient_error(stderr: str) -> bool:
    if not stderr:
        return False
    return any(marker in stderr for marker in TRANSIENT_ERROR_MARKERS)


def find_cli_binary() -> str:
    for candidate in [
        os.environ.get("EDAMAME_CLI_BIN", ""),
        os.environ.get("EDAMAME_CLI", ""),
    ]:
        if candidate and os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate

    workspace = Path(__file__).resolve().parent.parent.parent.parent.parent
    for name in ("edamame_cli", "edamame-cli"):
        for profile in ("release", "debug"):
            p = workspace / "edamame_cli" / "target" / profile / name
            if p.is_file() and os.access(str(p), os.X_OK):
                return str(p)

    for name in ("edamame_cli", "edamame-cli"):
        for d in os.environ.get("PATH", "").split(os.pathsep):
            p = Path(d) / name
            if p.is_file() and os.access(str(p), os.X_OK):
                return str(p)

    raise FileNotFoundError(
        "edamame_cli not found. Set EDAMAME_CLI_BIN or ensure it is on PATH."
    )


def cli_rpc(
    method: str,
    args: str | None = None,
    timeout: float = 30.0,
    retries: int = 4,
    retry_backoff: float = 2.0,
) -> object:
    """Call an edamame_cli RPC method and return the parsed Python object.

    Retries transient transport errors (e.g. "connection refused") with
    exponential backoff. The daemon RPC socket can momentarily refuse
    connections on Windows CI runners under load (post-capture cleanup,
    LLM adjudication bursts) even though the daemon process is alive;
    a short retry window rides over those bubbles without masking a
    genuinely crashed daemon (which stays unreachable across all retries).
    """
    cli = find_cli_binary()
    cmd = [cli, "rpc", method]
    if args:
        cmd.append(args)

    attempt = 0
    last_error: RuntimeError | None = None
    while attempt <= retries:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode == 0:
            return _parse_cli_output(result.stdout)

        stderr = result.stderr.strip()
        last_error = RuntimeError(
            f"edamame_cli rpc {method} failed (rc={result.returncode}): "
            f"{stderr}"
        )
        if attempt >= retries or not _is_transient_error(stderr):
            raise last_error

        wait = retry_backoff ** attempt
        sys.stderr.write(
            f"  cli_rpc {method} transient error (attempt {attempt + 1}/{retries + 1}), "
            f"retrying in {wait:.1f}s\n"
        )
        sys.stderr.flush()
        time.sleep(wait)
        attempt += 1

    assert last_error is not None
    raise last_error


def _parse_cli_output(raw: str) -> object:
    text = raw.strip()
    if text.startswith("Result: "):
        text = text[len("Result: "):]

    parsed = json.loads(text)

    if isinstance(parsed, str):
        return json.loads(parsed)

    return parsed


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <method> [json_args]", file=sys.stderr)
        sys.exit(1)

    method = sys.argv[1]
    rpc_args = sys.argv[2] if len(sys.argv) > 2 else None
    try:
        result = cli_rpc(method, rpc_args)
        print(json.dumps(result, indent=2, ensure_ascii=False))
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
