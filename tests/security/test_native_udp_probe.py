#!/usr/bin/env python3
"""The native UDP probe the egress triggers compile and run.

A scenario that uses the probe has a flow to grade only while the probe keeps
sending. These tests compile the probe's source as the triggers do and run it
against a local listener:

- it sends, says nothing on stderr and ends with code 0 on the parent's
  signal;
- left without a peer (the state a failed connect leaves a datagram socket
  in), it connects again and keeps sending, and names both on stderr.

The second case is built with UDP_PROBE_TEST_DISSOLVE_AFTER, which makes the
probe drop its own association once. Skipped where no C compiler is found and
on Windows, where the test build's way of dropping the association does not
apply.

Run:  python3 -m unittest discover -s tests/security -p 'test_native_udp_probe.py' -v
"""

from __future__ import annotations

import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from typing import List, Optional, Tuple

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / "triggers"))
import _native_udp_probe  # noqa: E402

INTERVAL_MS = 20
PAYLOAD_BYTES = 64
DISSOLVE_AFTER = 3


def _build(directory: Path, name: str, defines: Optional[List[str]] = None) -> Path:
    cc = _native_udp_probe.find_cc()
    assert cc is not None
    source = directory / f"{name}.c"
    source.write_text(_native_udp_probe.C_SOURCE, encoding="utf-8")
    binary = directory / name
    command = [cc, str(source), "-O2", "-o", str(binary)] + (defines or [])
    subprocess.run(command, check=True, capture_output=True)
    return binary


def _run_until(binary: Path, wanted: int, timeout: float = 20.0) -> Tuple[int, int, str]:
    """Runs the probe against a local listener until `wanted` datagrams
    arrived, then stops it. Returns (datagrams received, exit code, stderr)."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listener.bind(("127.0.0.1", 0))
    listener.settimeout(0.5)
    port = listener.getsockname()[1]
    proc = subprocess.Popen(
        [str(binary), "127.0.0.1", str(port), str(INTERVAL_MS), str(PAYLOAD_BYTES)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    received = 0
    deadline = time.monotonic() + timeout
    try:
        while received < wanted and time.monotonic() < deadline and proc.poll() is None:
            try:
                data, _ = listener.recvfrom(4096)
            except socket.timeout:
                continue
            if len(data) == PAYLOAD_BYTES:
                received += 1
    finally:
        listener.close()
        if proc.poll() is None:
            proc.terminate()
        try:
            _, stderr = proc.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            _, stderr = proc.communicate()
    return received, proc.returncode, stderr.decode("utf-8", errors="replace")


@unittest.skipIf(sys.platform == "win32", "the test build does not apply on Windows")
@unittest.skipIf(_native_udp_probe.find_cc() is None, "no C compiler")
class NativeUdpProbeTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="edamame_udp_probe_test_")
        self.directory = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_the_probe_sends_and_stays_quiet(self) -> None:
        binary = _build(self.directory, "probe")
        received, code, stderr = _run_until(binary, wanted=5)
        self.assertGreaterEqual(received, 5)
        self.assertEqual(code, 0)
        self.assertEqual(stderr, "")

    def test_a_probe_left_without_a_peer_connects_again_and_keeps_sending(self) -> None:
        binary = _build(
            self.directory,
            "probe_dissolve",
            [f"-DUDP_PROBE_TEST_DISSOLVE_AFTER={DISSOLVE_AFTER}"],
        )
        received, code, stderr = _run_until(binary, wanted=DISSOLVE_AFTER + 5)
        # More datagrams than were sent before the association was dropped:
        # the probe went on.
        self.assertGreaterEqual(received, DISSOLVE_AFTER + 5)
        self.assertEqual(code, 0)
        self.assertIn(f"lost its peer after {DISSOLVE_AFTER} datagram(s)", stderr)
        self.assertIn("sending again after 1 connect attempt(s)", stderr)
        self.assertNotIn("stopping", stderr)


if __name__ == "__main__":
    unittest.main()
