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

#### Connection & Device Configuration
| Flag | Description |
|------|-------------|
| `--user <user>` | EDAMAME Hub username (triggers service/daemon auto-start when provided with domain/pin). |
| `--domain <domain>` | EDAMAME Hub domain. |
| `--pin <pin>` | EDAMAME Hub PIN. |
| `--device-id <id>` | Device identifier for Hub tracking (e.g., `ci-runner-123`). Passed to daemon on start. |

#### Network Monitoring & Enforcement
| Flag | Description |
|------|-------------|
| `--start-lanscan` | Pass `--network-scan` to daemon (enables LAN device discovery). |
| `--start-capture` | Pass `--packet-capture` to daemon (enables traffic capture). |
| `--whitelist <name>` | Whitelist name to use (e.g., `github_ubuntu`). Passed to daemon on start. |
| `--fail-on-whitelist` | Pass `--fail-on-whitelist` to daemon (exit non-zero on whitelist violations). |
| `--fail-on-blacklist` | Pass `--fail-on-blacklist` to daemon (exit non-zero on blacklisted IPs). |
| `--fail-on-anomalous` | Pass `--fail-on-anomalous` to daemon (exit non-zero on anomalous connections). |
| `--cancel-on-violation` | Pass `--cancel-on-violation` to daemon (attempt pipeline cancellation on violations). |
| `--include-local-traffic` | Pass `--include-local-traffic` to daemon (include local traffic in capture). |

#### AI Assistant Configuration
| Flag | Description |
|------|-------------|
| `--claude-api-key <key>` | Claude API key for AI assistant. |
| `--openai-api-key <key>` | OpenAI API key for AI assistant. |
| `--ollama-base-url <url>` | Ollama base URL (default: `http://localhost:11434`). |
| `--agentic-mode <mode>` | AI mode: `auto`, `analyze`, or `disabled` (default: `disabled`). |
| `--agentic-interval <seconds>` | AI processing interval in seconds (default: `3600`). |
| `--slack-bot-token <token>` | Slack bot token for notifications. |
| `--slack-actions-channel <id>` | Slack channel ID for routine actions. |
| `--slack-escalations-channel <id>` | Slack channel ID for escalations. |

#### Installation Control
| Flag | Description |
|------|-------------|
| `--install-dir <path>` | Destination for binary installs (defaults to `/usr/local/bin` on Linux/macOS, `$HOME` on Windows). |
| `--state-file <path>` | Writes installation metadata (used by GitHub Actions to track install state). |
| `--force-binary` | Skip package managers, use direct binary download. |
| `--debug-build` | Download debug artifacts instead of release builds (implies `--force-binary`). |

---

### Usage Examples

#### Basic Installation with Credentials
```bash
curl --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/edamametechnologies/edamame_posture_cli/main/install.sh | sh -s -- \
  --user myuser \
  --domain example.com \
  --pin 123456
```

#### CI/CD Installation with Network Monitoring
```bash
curl --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/edamametechnologies/edamame_posture_cli/main/install.sh | sh -s -- \
  --user $EDAMAME_USER \
  --domain $EDAMAME_DOMAIN \
  --pin $EDAMAME_PIN \
  --device-id "ci-runner-${GITHUB_RUN_ID}" \
  --start-lanscan \
  --start-capture \
  --whitelist github_ubuntu \
  --fail-on-whitelist \
  --fail-on-blacklist \
  --cancel-on-violation
```

#### AI Assistant with Full Monitoring
```bash
curl --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/edamametechnologies/edamame_posture_cli/main/install.sh | sh -s -- \
  --user myuser \
  --domain example.com \
  --pin 123456 \
  --claude-api-key sk-ant-... \
  --agentic-mode auto \
  --agentic-interval 600 \
  --slack-bot-token xoxb-... \
  --slack-actions-channel C01234567 \
  --start-lanscan \
  --start-capture \
  --whitelist builder \
  --fail-on-whitelist \
  --fail-on-anomalous
```

#### Disconnected Mode (No Hub Connection)
```bash
curl --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/edamametechnologies/edamame_posture_cli/main/install.sh | sh -s -- \
  --start-lanscan \
  --start-capture \
  --whitelist github_ubuntu
```

Note: When credentials (`--user`, `--domain`, `--pin`) are omitted, the installer skips service configuration and the user can manually start the daemon with `edamame_posture background-start-disconnected`.

---

### Installation Flow by Platform

#### Pre-Installation Check (All Platforms)
**Before any package manager operations**, the installer performs an intelligent check:

1. **Locate existing binary** via `command -v edamame_posture`
   - If not found → proceed with installation

2. **Version/SHA verification**
   - **Package installations** (APT/APK/Homebrew/Choco): Check if upgrade is available
     - APT: `apt list --upgradable | grep edamame-posture`
     - APK: `apk version edamame-posture | grep "<"`
     - Homebrew: `brew outdated edamame-posture`
     - Chocolatey: `choco outdated edamame-posture`
   - **Binary installations**: Fetch latest release SHA from GitHub API and compare with existing binary
   - If outdated → proceed with upgrade/update
   - If up-to-date → proceed to credential check

3. **Credential verification** (only if credentials provided via `--user`/`--domain`/`--pin`)
   - Call `edamame_posture status` and parse output
   - Extract: Connected user, Connected domain, Connection status
   - If credentials match AND version is latest → **SKIP EVERYTHING** (zero package operations, zero service restarts)
   - If credentials differ → **SKIP INSTALLATION**, proceed to reconfiguration only
   - If not connected → **SKIP INSTALLATION**, proceed to reconfiguration only

This early check ensures:
- Idempotent behavior (running twice with same params does nothing on second run)
- Minimal operations (no unnecessary APT/APK/Homebrew/Choco calls)
- Fast execution (2-3 seconds vs 10-15 seconds for redundant operations)
- Smart updates (automatic upgrades when new versions available)

#### Linux
1. **Privilege detection**  
   - If running as root, continue.  
   - Otherwise, try `sudo`, `doas`, or automatically install `sudo` (`apk add sudo` / `apt-get install sudo`) using `su` when available.

2. **Distribution-based package installs** (only if pre-check determines installation needed)
   - **Alpine**: add EDAMAME APK repo/key → `apk add edamame-posture` or `apk upgrade edamame-posture`.  
   - **Debian/Ubuntu & derivatives**: add EDAMAME APT repo/key → `apt-get install edamame-posture` or `apt-get upgrade edamame-posture`.  
   - Services are enabled and started automatically (systemd/OpenRC).

3. **Fallbacks**  
   - For unsupported distros or if package installation fails/`--force-binary`, download the correct release binary (GNU vs MUSL decided by GLIBC detection) and drop it into `--install-dir`.

#### macOS
1. **Pre-check** (see above): If Homebrew installation exists and is up-to-date with matching credentials → skip everything
2. Try installing/upgrading the [`edamametechnologies/tap`](https://github.com/edamametechnologies/homebrew-tap) formula via Homebrew (only if needed)
3. If Homebrew is unavailable or fails (or `--force-binary`), download the universal macOS binary to `--install-dir`

#### Windows
1. **Pre-check** (see above): If Chocolatey installation exists and is up-to-date with matching credentials → skip everything
2. Attempt to install/upgrade `edamame-posture` via Chocolatey (only if needed)
3. If Chocolatey is unavailable or errors (or `--force-binary`), download the `x86_64-pc-windows-msvc(.exe)` artifact to `--install-dir`

---

### Binary Fallback Details
- The installer inspects architecture and GLIBC (`getconf GNU_LIBC_VERSION`) to select the correct artifact:
  - `x86_64-unknown-linux-gnu` (default) vs `x86_64-unknown-linux-musl` when GLIBC < 2.29 or running on Alpine.
  - `aarch64`, `armv7`, and `i686` variants are also supported.
- Debug builds pull versioned assets (`edamame_posture-<version>-<triple>-debug`), otherwise the installer uses the "latest release" redirect first and falls back to a pinned version.

#### Binary Version/SHA Verification
- **Pre-installation SHA check** (new optimization):
  - Before any download, the installer fetches the expected SHA256 digest from GitHub releases API
  - Computes SHA256 of the existing binary (if present)
  - If SHAs match → **reuses existing binary**, skips download entirely
  - If SHAs differ or binary doesn't exist → proceeds with download
- **Post-download SHA verification**:
  - After downloading, verifies the downloaded binary against the expected SHA
  - If verification fails → aborts with error
  - If verification succeeds → compares with existing binary one more time
  - Only replaces existing binary if they differ
- This two-stage verification ensures:
  - No unnecessary downloads (SHA checked before download)
  - No corrupted binaries (SHA verified after download)
  - Minimal disk writes (only replace if different)

- Download resolution order (non-debug builds): latest GitHub release tag → previous release tag → pinned fallback (`v0.9.75`). Windows adds one more safety net by retrying Chocolatey if every download attempt fails.
- Each download path has a hard-coded fallback (`v0.9.75`) to avoid transient release issues.

---

### Service Configuration & Verification

#### Configuration File Structure
Package installs create `/etc/edamame_posture.conf` which supports all daemon parameters:

**Connection Settings:**
- `edamame_user`: Hub username
- `edamame_domain`: Hub domain
- `edamame_pin`: Hub PIN
- `edamame_device_id`: Device identifier (optional)

**Network Monitoring:**
- `start_lanscan`: "true" → pass `--network-scan`
- `start_capture`: "true" → pass `--packet-capture`
- `whitelist_name`: Whitelist to use (e.g., "github_ubuntu")
- `fail_on_whitelist`: "true" → pass `--fail-on-whitelist`
- `fail_on_blacklist`: "true" → pass `--fail-on-blacklist`
- `fail_on_anomalous`: "true" → pass `--fail-on-anomalous`
- `cancel_on_violation`: "true" → pass `--cancel-on-violation`
- `include_local_traffic`: "true" → pass `--include-local-traffic`

**AI Assistant:**
- `agentic_mode`: "auto", "analyze", or "disabled"
- `claude_api_key`: Claude API key
- `openai_api_key`: OpenAI API key
- `ollama_base_url`: Ollama base URL
- `agentic_interval`: Processing interval in seconds
- `slack_bot_token`: Slack bot token
- `slack_actions_channel`: Slack actions channel ID
- `slack_escalations_channel`: Slack escalations channel ID

All parameters passed to `install.sh` via flags are written to this file, and the daemon script reads them to construct the appropriate `edamame_posture` command.

#### Service Management
- Package installs include init scripts:
  - **systemd** (`/lib/systemd/system/edamame_posture.service`)
  - **OpenRC** (`/etc/init.d/edamame_posture`)
- When credentials/network flags are supplied, the installer renders `edamame_posture.conf`, ensures it is `chmod 600`, and intelligently manages the service:
  - **First install**: Starts the service with the provided configuration
  - **Subsequent runs**: Checks if the service is already running with matching credentials before restarting
    - **Primary check**: Queries `edamame_posture status` and parses the output to extract:
      - Connected user
      - Connected domain
      - Connection status (is connected: true/false)
    - **Fallback check**: If status query fails (service not running/responding), reads `/etc/edamame_posture.conf` directly and parses:
      - `edamame_user: "..."`
      - `edamame_domain: "..."`
      - This ensures credential verification even when service is temporarily stopped
    - **Skips restart** if credentials match (via either method)
    - **Restarts service** if:
      - Service is running with different credentials
      - Service is not connected with current credentials
      - Config file has different credentials than provided
      - Service is not running (starts it with provided credentials)
      - Cannot verify credentials through either method (warns and reconfigures as safety measure)
  - This two-tier verification (runtime status + config file fallback) ensures robust idempotency across all service states
- Use `start_lanscan: "true"` to have the service launch with `--network-scan`, and `start_capture: "true"` for `--packet-capture`; you can also set these automatically during installation via `--start-lanscan` and `--start-capture`.
- When systemd isn't available (e.g., minimal containers where PID 1 isn't `systemd`), the installer skips enable/restart steps and prints a warning. You can still launch the daemon manually via `sudo edamame_posture start ...` or rely on the GitHub Action to start it in the foreground.
- Post-install verification:
  - Prints CLI version/location (using either `$PATH` or the fallback binary path).
  - Displays Quick Start commands.
  - Shows systemd/OpenRC status if available.

---

### GitHub Action Integration
The composite Action delegates ALL configuration to `install.sh`, passing action inputs as installer flags:

**Parameter Mapping:**
```bash
# Action inputs → install.sh flags
edamame_user → --user
edamame_domain → --domain  
edamame_pin → --pin
edamame_id → --device-id (with timestamp suffix)
network_scan → --start-lanscan
packet_capture → --start-capture
whitelist → --whitelist
check_whitelist → --fail-on-whitelist
check_blacklist → --fail-on-blacklist
check_anomalous → --fail-on-anomalous
cancel_on_violation → --cancel-on-violation
include_local_traffic → --include-local-traffic
```

**Workflow:**
1. Action calls `install.sh` with all parameters
2. `install.sh` handles:
   - Installation/upgrade (if needed)
   - Service/daemon configuration
   - Service/daemon start (with all parameters)
3. Action waits for connection (if credentials provided)
4. Work proceeds (build, test, etc.)

**State File Output:**
The installer emits state via `--state-file`:

```
binary_path=/usr/bin/edamame_posture
install_method=apt
installed_via_package_manager=true
binary_already_present=false
platform=linux
```

- Subsequent steps read `binary_path` to set `EDAMAME_POSTURE_CMD` (with `sudo` on POSIX)
- An optional "Inspect service status" step runs `systemctl status` / `rc-service status` when available
- The daemon is already running with all action-specified parameters (started by `install.sh`)

Use this doc as the canonical reference when debugging installer behavior or extending it with new distribution-specific paths.

