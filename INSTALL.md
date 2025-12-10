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
6. [Daemon Management Decision Tree](#daemon-management-decision-tree)
7. [GitHub Action Integration](#github-action-integration)
8. [Troubleshooting](#troubleshooting)

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

#### High-Level Flow Chart

```
┌─────────────────────────────────────────────────────────────────────┐
│                    INSTALLER START                                   │
└─────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│              1. CHECK EXISTING INSTALLATION                          │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │ • Locate binary via `command -v edamame_posture`            │    │
│  │ • Check default install dir ($HOME on Windows)              │    │
│  └─────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────┘
                                │
              Binary found?     │
           ┌────────────────────┼────────────────────┐
           │ NO                 │                    │ YES
           ▼                    │                    ▼
┌──────────────────────┐        │      ┌──────────────────────────────┐
│ SKIP_INSTALLATION=   │        │      │  2. VERSION/SHA CHECK        │
│   false              │        │      │  ┌────────────────────────┐  │
│ Proceed to install   │        │      │  │ Package: check upgrade │  │
└──────────────────────┘        │      │  │ Binary: compare SHA256 │  │
           │                    │      │  └────────────────────────┘  │
           │                    │      └──────────────────────────────┘
           │                    │                    │
           │                    │       Up to date?  │
           │                    │      ┌─────────────┼─────────────┐
           │                    │      │ NO          │             │ YES
           │                    │      ▼             │             ▼
           │                    │  ┌─────────────┐   │   ┌─────────────────────┐
           │                    │  │ Update      │   │   │ 3. CREDENTIAL CHECK │
           │                    │  │ needed      │   │   │ (if provided)       │
           │                    │  └─────────────┘   │   └─────────────────────┘
           │                    │      │             │             │
           │                    │      │             │   ┌─────────┼─────────┐
           │                    │      │             │   │ Daemon  │         │
           │                    │      │             │   │ status  │         │
           │                    │      │             │   │ check   │         │
           │                    │      │             │   └─────────┴─────────┘
           │                    │      │             │         │
           │                    │      │             │    ┌────┼────┐
           │                    │      │             │    │    │    │
           │                    │      │             │ SUCCESS FAIL
           │                    │      │             │    │    │
           │                    │      │             │    ▼    ▼
           │                    │      │             │  ┌──────────────────┐
           │                    │      │             │  │ Parse status or  │
           │                    │      │             │  │ check config     │
           │                    │      │             │  │ (Linux only)     │
           │                    │      │             │  └──────────────────┘
           │                    │      │             │         │
           ▼                    ▼      ▼             ▼         ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    4. DETERMINE ACTION                               │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │ SKIP_INSTALLATION: true/false                               │    │
│  │ SKIP_CONFIGURATION: true/false                              │    │
│  │ SHOULD_START_DAEMON: true/false                             │    │
│  └─────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│              5. PLATFORM-SPECIFIC INSTALLATION                       │
│  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐           │
│  │ Linux         │  │ macOS         │  │ Windows       │           │
│  │ APT/APK/Binary│  │ Homebrew/Bin  │  │ Choco/Binary  │           │
│  └───────────────┘  └───────────────┘  └───────────────┘           │
└─────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│              6. SERVICE/DAEMON MANAGEMENT                            │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │ Linux: configure_service() → systemd/OpenRC                   │  │
│  │ macOS/Windows: Manual daemon start via background process     │  │
│  └───────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    INSTALLER COMPLETE                                │
│  • Write state file (if --state-file provided)                      │
│  • Display Quick Start commands                                      │
│  • Show daemon status                                                │
└─────────────────────────────────────────────────────────────────────┘
```

#### Pre-Installation Check (All Platforms)
**Before any package manager operations**, the installer performs an intelligent check:

1. **Locate existing binary** via `command -v edamame_posture`
   - On Windows, also checks default install directory (`$HOME/edamame_posture.exe`)
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
   - Extract: Connected user, Connected domain, Device ID, Connection status
   - **Decision matrix:**

| Status Check | Credentials Match | Platform | Action |
|--------------|-------------------|----------|--------|
| Success | Yes | Any | SKIP EVERYTHING |
| Success | No | Linux | Reconfigure service |
| Success | No | Windows/macOS | Start daemon with new credentials |
| Failed (transport error) | N/A | Linux | Check config file, reconfigure if needed |
| Failed (transport error) | N/A | Windows/macOS | **Start daemon** (daemon not running) |

This early check ensures:
- Idempotent behavior (running twice with same params does nothing on second run)
- Minimal operations (no unnecessary APT/APK/Homebrew/Choco calls)
- Fast execution (2-3 seconds vs 10-15 seconds for redundant operations)
- Smart updates (automatic upgrades when new versions available)
- **Daemon auto-start on Windows/macOS when not running**

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

4. **Service configuration**
   - Creates/updates `/etc/edamame_posture.conf` with all provided parameters
   - Enables and starts systemd/OpenRC service
   - If systemd/OpenRC unavailable (containers), falls back to manual daemon start

#### macOS
1. **Pre-check** (see above): If Homebrew installation exists and is up-to-date with matching credentials → skip everything
2. Try installing/upgrading the [`edamametechnologies/tap`](https://github.com/edamametechnologies/homebrew-tap) formula via Homebrew (only if needed)
3. If Homebrew is unavailable or fails (or `--force-binary`), download the universal macOS binary to `--install-dir`
4. **Daemon management**: No system service; daemon started as background process when credentials provided

#### Windows
1. **Pre-check** (see above): If Chocolatey installation exists and is up-to-date with matching credentials → skip everything
2. Attempt to install/upgrade `edamame-posture` via Chocolatey (only if needed)
3. If Chocolatey is unavailable or errors (or `--force-binary`), download the `x86_64-pc-windows-msvc(.exe)` artifact to `--install-dir`
4. **Daemon management**: No system service; daemon started as background process when credentials provided

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

### Daemon Management Decision Tree

The installer uses a sophisticated decision tree to determine when and how to start the daemon:

```
┌─────────────────────────────────────────────────────────────────────┐
│                 DAEMON START DECISION                                │
└─────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
                    ┌───────────────────────┐
                    │ Credentials provided? │
                    │ (--user/--domain/--pin)│
                    └───────────────────────┘
                           │
              ┌────────────┼────────────┐
              │ NO         │            │ YES
              ▼            │            ▼
    ┌──────────────────┐   │   ┌──────────────────────────┐
    │ Network flags?   │   │   │ SKIP_CONFIGURATION set? │
    │ (lanscan/capture)│   │   │ (from pre-check)         │
    └──────────────────┘   │   └──────────────────────────┘
           │               │              │
      ┌────┼────┐          │         ┌────┼────┐
      │NO  │    │YES       │         │ NO │    │ YES
      ▼    │    ▼          │         ▼    │    ▼
   ┌─────┐ │ ┌──────────┐  │   ┌───────┐  │  ┌─────────────────────┐
   │DONE │ │ │Disconnect│  │   │Config │  │  │ SHOULD_START_DAEMON │
   │(no  │ │ │mode      │  │   │service│  │  │ already set?        │
   │start│ │ │daemon    │  │   │(Linux)│  │  └─────────────────────┘
   └─────┘ │ └──────────┘  │   └───────┘  │         │
           │               │              │    ┌────┼────┐
           │               │              │    │ NO │    │ YES
           │               │              │    ▼    │    ▼
           │               │              │  ┌────┐ │  ┌───────────┐
           │               │              │  │Skip│ │  │ START     │
           │               │              │  │    │ │  │ DAEMON    │
           │               │              │  └────┘ │  └───────────┘
           │               │              │         │
           └───────────────┴──────────────┴─────────┘
```

#### Key Variables

| Variable | Purpose | Set When |
|----------|---------|----------|
| `SKIP_INSTALLATION` | Skip package manager operations | Binary exists and is up-to-date |
| `SKIP_CONFIGURATION` | Skip `configure_service()` | Linux: credentials match; Windows/macOS: always (no config file) |
| `SHOULD_START_DAEMON` | Force manual daemon start | See table below |

#### When SHOULD_START_DAEMON is Set to True

| Scenario | Platform | Reason |
|----------|----------|--------|
| Status check failed (daemon not running) | Windows/macOS | No service manager, must start manually |
| Credentials mismatch | Windows/macOS | Need to restart with new credentials |
| Service start failed (OpenRC/systemd) | Linux | Fallback to manual start |
| Binary installation (no package) | Any | No service file installed |
| Homebrew/Chocolatey installation | macOS/Windows | No service file with these package managers |

#### Daemon Start Process

When `SHOULD_START_DAEMON=true`:

1. **Stop existing daemon** (if any)
   - Windows: `taskkill //F //IM edamame_posture.exe`
   - Linux/macOS: `edamame_posture stop` then `pkill -f edamame_posture`

2. **Export AI configuration** (if agentic mode enabled)
   - `EDAMAME_LLM_API_KEY`
   - `EDAMAME_LLM_BASE_URL` (for Ollama)
   - Slack tokens and channels

3. **Build command based on mode**
   - **Connected mode**: `edamame_posture start --user ... --domain ... --pin ...`
   - **Disconnected mode**: `edamame_posture background-start-disconnected`

4. **Add network flags**
   - `--network-scan` if `--start-lanscan`
   - `--packet-capture` if `--start-capture`
   - `--whitelist <name>` if `--whitelist`
   - Enforcement flags (`--fail-on-*`, `--cancel-on-violation`)

5. **Start in background**
   - Uses `nohup` if available
   - Redirects output to `/dev/null`
   - Uses `sudo` if needed (Linux/macOS)

6. **Wait and verify**
   - Sleep 5 seconds
   - Call `edamame_posture status` to verify startup

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

---

### Troubleshooting

#### Common Issues

##### "transport error" / "target machine actively refused it" (Windows)
**Symptom:** Status check fails with connection refused error.

**Cause:** The daemon is not running. This can happen when:
- First-time installation on a machine
- Daemon was stopped manually
- Previous installer run didn't start the daemon

**Solution:** The installer now automatically detects this condition and starts the daemon when credentials are provided. If you see this error in logs followed by "Will start daemon" or "Daemon not responding... will start daemon", the installer will handle it.

##### Credentials not matching (CI/CD)
**Symptom:** Installer reports "Existing installation has different credentials" but doesn't update.

**Cause:** On Windows/macOS, there's no config file to update (unlike Linux with `/etc/edamame_posture.conf`).

**Solution:** The installer will stop the existing daemon and start a new one with the provided credentials.

##### "Cannot get status from existing installation"
**Symptom:** Status check fails but binary exists.

**Cause:** Daemon is not running or not responding to RPC calls.

**Platform-specific behavior:**
- **Linux:** Checks `/etc/edamame_posture.conf` for credentials; reconfigures and restarts service if needed
- **Windows/macOS:** Sets `SHOULD_START_DAEMON=true` to start the daemon manually

##### Daemon not starting (Linux containers)
**Symptom:** "systemd is not available" warning.

**Cause:** Running in a container without systemd (PID 1 is not `systemd`).

**Solution:** The installer falls back to manual daemon start or you can run:
```bash
sudo edamame_posture start --user USER --domain DOMAIN --pin PIN [other flags]
```

##### Binary SHA mismatch
**Symptom:** "Binary SHA differs from latest release" message.

**Cause:** Existing binary is from an older version.

**Solution:** This is normal behavior - the installer will update the binary automatically.

#### Debug Information

The installer outputs detailed decision information:

```
[INFO] Daemon start decision:
[INFO]   Credentials provided: yes
[INFO]   SKIP_CONFIGURATION: true
[INFO]   INSTALLED_VIA_PACKAGE_MANAGER: false
[INFO]   INSTALL_METHOD: existing
[INFO]   SHOULD_START_DAEMON (current): true
[INFO]   Decision: Binary installation - will start daemon
[INFO]   SHOULD_START_DAEMON: true
```

Use this output to understand why the installer made specific decisions.

#### Manual Daemon Commands

If automatic daemon management fails, you can start the daemon manually:

**Connected mode:**
```bash
# Linux/macOS
sudo edamame_posture start --user USER --domain DOMAIN --pin PIN --device-id DEVICE_ID

# Windows (PowerShell as Admin)
.\edamame_posture.exe start --user USER --domain DOMAIN --pin PIN --device-id DEVICE_ID
```

**Disconnected mode:**
```bash
# Linux/macOS
sudo edamame_posture background-start-disconnected --network-scan --packet-capture

# Windows
.\edamame_posture.exe background-start-disconnected --network-scan --packet-capture
```

**Check status:**
```bash
edamame_posture status
```

**Stop daemon:**
```bash
# Linux/macOS
sudo edamame_posture stop

# Windows
.\edamame_posture.exe stop
# or
taskkill /F /IM edamame_posture.exe
```

---

Use this doc as the canonical reference when debugging installer behavior or extending it with new distribution-specific paths.
