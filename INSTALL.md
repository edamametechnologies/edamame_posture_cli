## EDAMAME Posture Installer Guide

This document explains how `install.sh` provisions EDAMAME Posture across platforms, what flags are available, and how the GitHub Action consumes the installer output.

---

### Table of Contents
1. [Prerequisites](#prerequisites)
2. [Installer Flags](#installer-flags)
3. [Installation Flow by Platform](#installation-flow-by-platform)
   - [Linux](#linux)
   - [macOS](#macos)
   - [Windows](#windows)
4. [Binary Fallback Details](#binary-fallback-details)
5. [Service Configuration & Verification](#service-configuration--verification)
6. [GitHub Action Integration](#github-action-integration)

---

### Prerequisites
- Any platform: `curl` or `wget` to download the script.
- Linux/macOS: ability to run commands with root privileges (`sudo`, `doas`, or root shell). The installer will attempt to install `sudo` automatically on Alpine/Debian systems when possible.
- Windows (PowerShell or GitHub Actions Bash shell): Chocolatey preferred for package installation.

Run the installer:
```bash
curl --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/edamametechnologies/edamame_posture_cli/main/install.sh | sh -s -- [FLAGS]
```

---

### Installer Flags
| Flag | Description |
|------|-------------|
| `--user`, `--domain`, `--pin` | Optional EDAMAME Hub credentials. Trigger service auto-configuration when provided. |
| `--claude-api-key`, `--openai-api-key`, `--ollama-base-url` | AI backend configuration. |
| `--agentic-mode`, `--agentic-interval` | Agent execution control. |
| `--slack-bot-token`, `--slack-actions-channel`, `--slack-escalations-channel` | Slack integration. |
| `--install-dir <path>` | Destination for binary fallback (defaults to `/usr/local/bin` on Linux/macOS, `$HOME` elsewhere). |
| `--state-file <path>` | Writes installation metadata here (used by GitHub Actions). |
| `--ci-mode` | Stops packaged services after installation so CI jobs don’t leave background daemons running. |
| `--force-binary` / `--binary-only` | Skip package managers entirely. |
| `--debug-build` | Download debug artifacts (forces binary installation). |

---

### Installation Flow by Platform

#### Linux
1. **Privilege detection**  
   - If running as root, continue.  
   - Otherwise, try `sudo`, `doas`, or automatically install `sudo` (`apk add sudo` / `apt-get install sudo`) using `su` when available.

2. **Distribution-based package installs**  
   - **Alpine**: add EDAMAME APK repo/key → `apk add edamame-posture`.  
   - **Debian/Ubuntu & derivatives**: add EDAMAME APT repo/key → `apt-get install edamame-posture`.  
   - Services are enabled automatically (systemd/OpenRC) and restarted unless `--ci-mode`.

3. **Fallbacks**  
   - For unsupported distros or if package installation fails/`--force-binary`, download the correct release binary (GNU vs MUSL decided by GLIBC detection) and drop it into `--install-dir`.

#### macOS
1. Try installing/upgrading the [`edamametechnologies/tap`](https://github.com/edamametechnologies/homebrew-tap) formula via Homebrew.  
2. If Homebrew is unavailable or fails (or `--force-binary`), download the universal macOS binary to `--install-dir`.

#### Windows
1. Attempt to install/upgrade `edamame-posture` via Chocolatey.  
2. If Chocolatey is unavailable or errors (or `--force-binary`), download the `x86_64-pc-windows-msvc(.exe)` artifact to `--install-dir`.

---

### Binary Fallback Details
- The installer inspects architecture and GLIBC (`getconf GNU_LIBC_VERSION`) to select the correct artifact:
  - `x86_64-unknown-linux-gnu` (default) vs `x86_64-unknown-linux-musl` when GLIBC < 2.29 or running on Alpine.
  - `aarch64`, `armv7`, and `i686` variants are also supported.
- Debug builds pull versioned assets (`edamame_posture-<version>-<triple>-debug`), otherwise the installer uses the “latest release” redirect first and falls back to a pinned version.
- If the destination binary already exists (e.g., `/usr/local/bin/edamame_posture` or `$HOME/edamame_posture.exe`):
  - When **no** credentials are provided, the installer reuses the existing file.
  - When `--user/--domain/--pin` **are** supplied, the installer stops any running `edamame_posture` processes, removes the existing binary, and downloads a fresh copy before continuing.
- Each download path has a hard-coded fallback (`v0.9.75`) to avoid transient release issues.

---

### Service Configuration & Verification
- Package installs drop `/etc/edamame_posture.conf` and associated init scripts:
  - **systemd** (`/lib/systemd/system/edamame_posture.service`)
  - **OpenRC** (`/etc/init.d/edamame_posture`)
- When credentials/AI flags are supplied, the installer renders `edamame_posture.conf`, ensures it is `chmod 600`, and restarts the service under the appropriate init system.
- When systemd isn’t available (e.g., minimal containers where PID 1 isn’t `systemd`), the installer skips enable/restart steps and prints a warning. You can still launch the daemon manually via `sudo edamame_posture start ...` or rely on the GitHub Action to start it in the foreground.
- Post-install verification:
  - Prints CLI version/location (using either `$PATH` or the fallback binary path).
  - Displays Quick Start commands.
  - Shows systemd/OpenRC status if available.

---

### GitHub Action Integration
The composite Action delegates to `install.sh` and relies on the state file emitted via `--state-file`:

```
binary_path=/usr/bin/edamame_posture
install_method=apt
installed_via_package_manager=true
binary_already_present=false
platform=linux
```

- Subsequent steps read `binary_path` to set `EDAMAME_POSTURE_CMD` (with `sudo` on POSIX).
- An optional “Inspect service status” step runs `systemctl status` / `rc-service status` when available, emitting the configured service user so operators can confirm the daemon runs under the expected account (root by default).
- When `--ci-mode` is used (default inside the Action), any auto-started services are stopped immediately to avoid interfering with ephemeral runners; the CLI is then invoked directly via `EDAMAME_POSTURE_CMD`.

Use this doc as the canonical reference when debugging installer behavior or extending it with new distribution-specific paths.

