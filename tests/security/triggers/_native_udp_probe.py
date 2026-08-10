"""
Shared helpers for native UDP probe-based E2E triggers.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

C_SOURCE = r"""
#include <signal.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
typedef int socklen_t;
static void usleep_ms(int ms) { Sleep(ms); }
#else
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
static void usleep_ms(int ms) { usleep((useconds_t)ms * 1000U); }
#endif

static volatile sig_atomic_t keep_running = 1;

static void on_signal(int sig) {
    (void)sig;
    keep_running = 0;
}

int main(int argc, char **argv) {
    if (argc < 5) {
        return 2;
    }

    const char *ip = argv[1];
    int port = atoi(argv[2]);
    int interval = atoi(argv[3]);
    int size = atoi(argv[4]);

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2,2), &wsa);
#endif

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        return 1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((unsigned short)port);
    if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1) {
        return 1;
    }
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        return 1;
    }

    char *buf = malloc((size_t)size);
    if (!buf) {
        return 1;
    }
    memset(buf, 'D', (size_t)size);

    while (keep_running) {
        if (send(sock, buf, (size_t)size, 0) < 0) {
            break;
        }
        usleep_ms(interval);
    }

#ifdef _WIN32
    closesocket(sock);
    WSACleanup();
#else
    close(sock);
#endif
    free(buf);
    return 0;
}
"""


def ensure_state_dir(state_dir: Path) -> None:
    state_dir.mkdir(parents=True, exist_ok=True)


def record_created(state_dir: Path, marker_name: str, path: Path) -> None:
    marker = state_dir / marker_name
    existing = set()
    if marker.exists():
        existing = {line.strip() for line in marker.read_text("utf-8").splitlines() if line.strip()}
    existing.add(str(path))
    marker.write_text("\n".join(sorted(existing)) + "\n", encoding="utf-8")


_WINDOWS_GCC_CANDIDATES = [
    r"C:\msys64\mingw64\bin\gcc.exe",
    r"C:\msys64\ucrt64\bin\gcc.exe",
    r"C:\msys64\usr\bin\gcc.exe",
]


def find_cc() -> str | None:
    cc_env = os.environ.get("CC", "").strip()
    if cc_env:
        try:
            subprocess.check_call(
                [cc_env, "--version"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return cc_env
        except Exception as exc:
            print(f"CC env ({cc_env}) failed: {exc}", file=sys.stderr)
    candidates: list[str] = ["cc", "gcc", "clang"]
    if sys.platform == "win32":
        candidates.extend(_WINDOWS_GCC_CANDIDATES)
    for candidate in candidates:
        try:
            subprocess.check_call(
                [candidate, "--version"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return candidate
        except Exception as exc:
            print(f"CC candidate ({candidate}) failed: {exc}", file=sys.stderr)
            continue
    return None


def compile_udp_probe(state_dir: Path, marker_name: str, binary_name: str) -> Path | None:
    cc = find_cc()
    if cc is None:
        print("compile_udp_probe: no compiler found", file=sys.stderr)
        return None

    src = state_dir / f"{binary_name}.c"
    if sys.platform == "win32":
        binary = state_dir / f"{binary_name}.exe"
    else:
        binary = state_dir / binary_name
    src.write_text(C_SOURCE, encoding="utf-8")
    record_created(state_dir, marker_name, src)

    cmd = [cc, str(src), "-O2", "-o", str(binary)]
    if sys.platform == "win32":
        cmd.append("-lws2_32")

    print(f"compile_udp_probe: running {cmd}", file=sys.stderr)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"compile_udp_probe: compilation failed (rc={result.returncode})", file=sys.stderr)
            print(f"  stdout: {result.stdout[:500]}", file=sys.stderr)
            print(f"  stderr: {result.stderr[:500]}", file=sys.stderr)
            return None
    except Exception as exc:
        print(f"compile_udp_probe: exception: {exc}", file=sys.stderr)
        return None

    try:
        binary.chmod(0o755)
    except OSError:
        pass
    record_created(state_dir, marker_name, binary)
    return binary


def spawn_udp_children(
    binary: Path,
    targets: list[tuple[str, int]],
    interval_ms: int,
    payload_bytes: int,
) -> list[subprocess.Popen[bytes]]:
    children: list[subprocess.Popen[bytes]] = []
    for ip, port in targets:
        children.append(
            subprocess.Popen(
                [str(binary), ip, str(port), str(interval_ms), str(payload_bytes)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        )
    return children


def terminate_children(children: list[subprocess.Popen[bytes]]) -> None:
    for proc in children:
        if proc.poll() is None:
            proc.terminate()

    for proc in children:
        if proc.poll() is not None:
            continue
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

    for proc in children:
        try:
            proc.wait(timeout=0.1)
        except (subprocess.TimeoutExpired, OSError):
            pass
