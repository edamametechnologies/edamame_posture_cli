#!/usr/bin/env python3
"""Redact well-known secret patterns from one or more files in-place.

Used from workflow `Sanitize logs` steps before uploading artifacts so that
accidental leaks (LLM API keys, hub PINs, bearer tokens) do not end up in
public CI artifacts.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

PATTERNS = [
    re.compile(r"PIN[=: ][0-9]+"),
    re.compile(r"(?i)api[_-]?key=\S+"),
    re.compile(r"(?i)token=\S+"),
    re.compile(r"edm_live_[A-Za-z0-9_\-]+"),
    re.compile(r"(?i)authorization:\s*bearer\s+\S+"),
    re.compile(r"sk-[A-Za-z0-9]{20,}"),
]


def _redact(text: str) -> str:
    out = text
    for pat in PATTERNS:
        out = pat.sub("[REDACTED]", out)
    return out


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        return 0
    for raw in argv[1:]:
        path = Path(raw)
        if not path.is_file():
            continue
        try:
            data = path.read_text(encoding="utf-8", errors="ignore")
        except Exception as exc:
            print(f"warn: unable to read {path}: {exc}", file=sys.stderr)
            continue
        redacted = _redact(data)
        if redacted != data:
            try:
                path.write_text(redacted, encoding="utf-8")
            except Exception as exc:
                print(f"warn: unable to write {path}: {exc}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
