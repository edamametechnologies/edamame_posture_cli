#!/usr/bin/env python3
"""Stand-in programs for the FP lab's operator's-day scenarios.

Two of the 2026-10-23 shapes come from programs the lab cannot install on a
CI runner: a cloud-sync client and a user's own script. The direct actions
copy this file into the case workspace under the role's name
(``sync-client/fplab_sync_client.py``, ``scripts/make_report.py``) and run
it with the role's subcommand, so the process the detector sees is a
separate program whose command line names what it owns.

Both roles are benign by construction:

- ``sync-client --data-dir D``: creates its own data directory ``D``, keeps
  a credential-store-like file there (``credentials.json``, a placeholder
  that holds no credential), holds it open while it talks to its service
  over HTTPS, and refreshes it with a safe-save rename (write a sibling,
  then replace) a few times. It never reads anything it did not write.
- ``report --out F``: a user's script that writes a small PDF document
  (text only: no JavaScript, no actions, no embedded files) to ``F`` in the
  temp directory, then rewrites it once, while it makes an unrelated HTTPS
  request every few seconds.

Standard library only. TLS is always verified: when this Python has no CA
bundle and ``certifi`` is not importable, the role exits 3 and says so (the
lab reports the case as not delivered). Nothing here prints a secret; the
placeholder token is a fixed string.
"""

from __future__ import annotations

import argparse
import http.client
import json
import os
import secrets
import ssl
import sys
import time
from pathlib import Path
from typing import Iterator, Optional

UA = "fp-lab/1.0 (+https://github.com/edamametechnologies/edamame_posture)"


class TlsUnavailable(RuntimeError):
    """This Python cannot verify certificates (no CA bundle, no certifi)."""


def _contexts() -> Iterator[ssl.SSLContext]:
    yield ssl.create_default_context()
    try:
        import certifi  # type: ignore[import-not-found]
    except ImportError:
        return
    yield ssl.create_default_context(cafile=certifi.where())


class Https:
    """One keep-alive HTTPS connection to one host, reopened when the server
    closes it. The process stays alive between requests, so every session
    it opens is attributed to a live process."""

    def __init__(self, host: str) -> None:
        self.host = host
        self._ctx_iter = _contexts()
        self._ctx: Optional[ssl.SSLContext] = next(self._ctx_iter)
        self._conn: Optional[http.client.HTTPSConnection] = None

    def get(self, path: str) -> int:
        for _ in range(3):
            if self._conn is None:
                self._conn = http.client.HTTPSConnection(self.host, timeout=30, context=self._ctx)
            try:
                self._conn.request("GET", path, headers={"User-Agent": UA, "Accept": "*/*"})
                resp = self._conn.getresponse()
                resp.read()
                return resp.status
            except ssl.SSLCertVerificationError as exc:
                self.close()
                nxt = next(self._ctx_iter, None)
                if nxt is None:
                    raise TlsUnavailable(f"certificate verification failed for {self.host}: {exc}") from exc
                self._ctx = nxt
            except (http.client.HTTPException, OSError):
                self.close()
        return 0

    def close(self) -> None:
        if self._conn is not None:
            try:
                self._conn.close()
            except OSError:
                pass
            self._conn = None


# ── sync-client ─────────────────────────────────────────────────────────

SYNC_HOST = "www.googleapis.com"
SYNC_PATH = "/discovery/v1/apis/drive/v3/rest"


def _write_store(data_dir: Path, generation: int) -> None:
    """Safe-save: write a sibling, flush it, replace the store with it."""
    store = data_dir / "credentials.json"
    sibling = data_dir / f"credentials.json.sb-{secrets.token_hex(4)}"
    body = json.dumps({
        "client": "fplab-sync",
        "account": "fp-lab@example.invalid",
        "generation": generation,
        "refresh_token": "fp-lab-placeholder-not-a-token",
        "updated_at": int(time.time()),
    }, indent=2)
    with open(sibling, "w", encoding="utf-8") as fh:
        fh.write(body + "\n")
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(sibling, store)


def sync_client(args: argparse.Namespace) -> int:
    data_dir = Path(args.data_dir)
    # Its own data directory: created here, never an existing one.
    data_dir.mkdir(parents=True, exist_ok=False)
    _write_store(data_dir, 0)
    store = data_dir / "credentials.json"
    https = Https(SYNC_HOST)
    requests_ok = renames = 0
    start = time.time()
    deadline = start + args.secs
    next_refresh = start + 20
    # Held open the whole time, as a client keeps its store open. Closed
    # around each replace: on Windows a file open without FILE_SHARE_DELETE
    # cannot be replaced, and a real client closes it the same way.
    hold = open(store, "rb")
    try:
        while time.time() < deadline:
            status = https.get(SYNC_PATH)
            if 200 <= status < 400:
                requests_ok += 1
            if time.time() >= next_refresh:
                hold.close()
                renames += 1
                _write_store(data_dir, renames)
                hold = open(store, "rb")
                next_refresh += 25
            time.sleep(8)
    except TlsUnavailable as exc:
        print(f"sync-client: {exc}", flush=True)
        return 3
    finally:
        hold.close()
        https.close()
    print(f"sync-client: data_dir={data_dir} requests_ok={requests_ok} renames={renames}", flush=True)
    return 0 if requests_ok and renames else 1


# ── report ──────────────────────────────────────────────────────────────

REPORT_HOST = "pypi.org"
REPORT_PATH = "/pypi/pip/json"


def _pdf_escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def build_pdf(pages: int) -> bytes:
    """A small, valid PDF 1.4 document: text pages in Helvetica, nothing
    else (no JavaScript, no actions, no annotations, no embedded files)."""
    objects: dict[int, bytes] = {
        1: b"<< /Type /Catalog /Pages 2 0 R >>",
        3: b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    }
    kids = []
    next_id = 4
    for page in range(1, pages + 1):
        lines = [f"Quarterly inventory report - page {page} of {pages}",
                 "Prepared by a local script for the FP lab. Figures are illustrative.", ""]
        lines += [f"Item {i:02d}    warehouse {(i % 4) + 1}    units {i * 37 % 500:4d}    value {i * 1234.5:10.2f}"
                  for i in range(1, 41)]
        stream = "BT /F1 10 Tf 60 750 Td 14 TL\n" + "".join(f"({_pdf_escape(t)}) Tj T*\n" for t in lines) + "ET\n"
        data = stream.encode("latin-1")
        page_id, content_id = next_id, next_id + 1
        next_id += 2
        objects[page_id] = (f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
                            f"/Resources << /Font << /F1 3 0 R >> >> /Contents {content_id} 0 R >>").encode("latin-1")
        objects[content_id] = b"<< /Length %d >>\nstream\n" % len(data) + data + b"endstream"
        kids.append(f"{page_id} 0 R")
    objects[2] = f"<< /Type /Pages /Kids [{' '.join(kids)}] /Count {pages} >>".encode("latin-1")

    out = bytearray(b"%PDF-1.4\n")
    offsets = {}
    for oid in sorted(objects):
        offsets[oid] = len(out)
        out += b"%d 0 obj\n" % oid + objects[oid] + b"\nendobj\n"
    xref_at = len(out)
    count = max(objects) + 1
    out += b"xref\n0 %d\n" % count
    out += b"0000000000 65535 f \n"
    for oid in range(1, count):
        out += b"%010d 00000 n \n" % offsets[oid]
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (count, xref_at)
    return bytes(out)


def report(args: argparse.Namespace) -> int:
    out = Path(args.out)
    https = Https(REPORT_HOST)
    requests_ok = writes = 0
    start = time.time()
    deadline = start + args.secs
    try:
        while time.time() < deadline:
            status = https.get(REPORT_PATH)
            if 200 <= status < 400:
                requests_ok += 1
            elapsed = time.time() - start
            # The document is written while the unrelated connection is
            # open, then rewritten once with a second page.
            if writes == 0 and elapsed >= 5:
                out.write_bytes(build_pdf(1))
                writes += 1
            elif writes == 1 and elapsed >= args.secs / 2:
                out.write_bytes(build_pdf(2))
                writes += 1
            time.sleep(8)
    except TlsUnavailable as exc:
        print(f"report: {exc}", flush=True)
        return 3
    finally:
        https.close()
    print(f"report: out={out} requests_ok={requests_ok} pdf_writes={writes}", flush=True)
    return 0 if requests_ok and writes else 1


def main() -> int:
    p = argparse.ArgumentParser(description="FP lab stand-in programs (operator's-day scenarios)")
    sub = p.add_subparsers(dest="role", required=True)
    s = sub.add_parser("sync-client", help="cloud-sync client keeping its own store in its own data directory")
    s.add_argument("--data-dir", required=True)
    s.add_argument("--secs", type=int, default=80)
    r = sub.add_parser("report", help="user script writing a PDF in temp beside an unrelated HTTPS request")
    r.add_argument("--out", required=True)
    r.add_argument("--secs", type=int, default=60)
    args = p.parse_args()
    if args.role == "sync-client":
        return sync_client(args)
    return report(args)


if __name__ == "__main__":
    sys.exit(main())
