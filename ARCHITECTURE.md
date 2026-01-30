# EDAMAME Posture Architecture

Cross-platform CLI tool for security posture assessment, remediation, and CI/CD integration.

## Overview

EDAMAME Posture provides security controls without requiring the full GUI application. Designed for developers and CI/CD pipelines, it offers policy enforcement, threat remediation, and network monitoring.

## Module Structure

```
src/
├── main.rs        # Entry point and command dispatch
├── cli.rs         # Command-line argument parsing (clap)
├── base.rs        # Core operations (score, threats, remediation)
├── background.rs  # Background daemon operations
└── daemon.rs      # Process lifecycle management
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      CLI Interface (clap)                       │
│               edamame-posture <command> [options]               │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Command Dispatcher (main.rs)                 │
│  • Parses arguments                                             │
│  • Initializes edamame_core                                     │
│  • Routes to appropriate handler                                │
└─────────────────────────────────────────────────────────────────┘
                              │
              ┌───────────────┼───────────────┐
              ▼               ▼               ▼
        ┌──────────┐   ┌──────────┐   ┌──────────────┐
        │ base.rs  │   │background│   │   daemon.rs  │
        │ (sync)   │   │  .rs     │   │  (process)   │
        └──────────┘   └──────────┘   └──────────────┘
              │               │               │
              └───────────────┼───────────────┘
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      edamame_core                               │
│            (Security assessment, network, AI)                   │
└─────────────────────────────────────────────────────────────────┘
```

## Command Categories

### Assessment Commands
```bash
edamame-posture get-score           # Security score (0-5 stars)
edamame-posture list-threats        # List all threats with status
edamame-posture get-device-info     # Device information
edamame-posture get-system-info     # System information
edamame-posture get-core-info       # Core version and build info
edamame-posture get-threat-info <ID> # Details about a specific threat
```

### Remediation Commands
```bash
edamame-posture remediate-all-threats       # Fix all threats (excludes remote login/firewall by default)
edamame-posture remediate-all-threats-force # Fix all threats including lockout risks
edamame-posture remediate-threat <ID>       # Fix specific threat
edamame-posture rollback-threat <ID>        # Undo specific fix
```

### Policy Commands (CI/CD)
```bash
edamame-posture check-policy <MIN_SCORE> "<THREATS>" "[TAGS]"
edamame-posture check-policy-for-domain <DOMAIN> <POLICY>
edamame-posture request-signature           # Get attestation
```

### Daemon Commands
```bash
edamame-posture start    # Start monitoring daemon
edamame-posture stop     # Stop daemon
edamame-posture status   # Check daemon status
edamame-posture logs     # View daemon logs
```

### Network Commands
```bash
edamame-posture lanscan          # Scan local network
edamame-posture get-sessions     # Network sessions
edamame-posture get-exceptions   # Whitelist exceptions
edamame-posture capture          # Real-time packet capture
```

### Dismiss Commands
```bash
edamame-posture dismiss-device <IP>            # Dismiss all ports on a device
edamame-posture dismiss-device-port <IP> <PORT> # Dismiss specific device port
edamame-posture dismiss-session <UID>          # Dismiss session by UID
edamame-posture dismiss-session-process <UID>  # Dismiss future sessions for a process
```

### Whitelist Commands
```bash
edamame-posture set-custom-whitelists <JSON>              # Set custom whitelists from JSON
edamame-posture set-custom-whitelists-from-file <FILE>    # Set from file
edamame-posture create-custom-whitelists                  # Create from current sessions
edamame-posture augment-custom-whitelists                 # Augment with current exceptions
edamame-posture merge-custom-whitelists <JSON1> <JSON2>   # Merge two whitelists
edamame-posture compare-custom-whitelists <JSON1> <JSON2> # Compare two whitelists
```

### MCP Server Commands
```bash
edamame-posture mcp-start        # Start MCP server
edamame-posture mcp-stop         # Stop MCP server
edamame-posture mcp-status       # Get MCP server status
edamame-posture mcp-generate-psk # Generate PSK
```

### AI Commands (via start flags)
```bash
# AI is configured via start command flags, not separate commands:
edamame-posture start --agentic-mode auto|analyze|disabled \
                      --agentic-provider edamame|claude|openai|ollama \
                      --agentic-interval 3600 \
                      --llm-api-key "your-api-key"

# Get agentic status summary:
edamame-posture agentic-summary  # Provider, mode, todos, actions, Slack config
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Policy/security check mismatch |
| 2 | Server error |
| 3 | Parameter error |
| 4 | Timeout |

## CI/CD Integration

```yaml
# GitHub Actions example
- name: Security Gate
  run: |
    edamame-posture check-policy 3.5 "firewall disabled" "PCI-DSS,HIPAA"
    # Exit 0: score >= 3.5, no critical threats, compliance met
    # Exit 1: Failed security check
```

## Background Daemon

```
┌─────────────────────────────────────────────────────────────────┐
│                    edamame-posture start                        │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                   Daemonize Process                             │
│  • Fork/detach from terminal                                    │
│  • Create PID file                                              │
│  • Redirect stdout/stderr to log file                           │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                   Background Monitoring                         │
│  • Periodic score computation                                   │
│  • Network session tracking                                     │
│  • Threat status updates                                        │
│  • Connection to EDAMAME Hub (if configured)                    │
└─────────────────────────────────────────────────────────────────┘
```

## Platform Support

| Platform | Package Format | Privileges |
|----------|---------------|------------|
| Linux x86_64 | .deb, .apk | sudo for remediation |
| Linux aarch64 | .deb, .apk | sudo for remediation |
| Linux armv7 | .deb | sudo for remediation |
| macOS | Homebrew | sudo for remediation |
| Windows | Chocolatey | Administrator |
| Alpine | .apk (musl) | sudo for remediation |

## Installation Methods

See [INSTALL.md](INSTALL.md) for complete installation instructions:
- APT repository (Debian/Ubuntu)
- APK repository (Alpine)
- Homebrew (macOS)
- Chocolatey (Windows)
- Direct binary download

## Dependencies

- `edamame_core` - Core security assessment
- `clap` - CLI framework
- `tokio` - Async runtime
- `daemonize` - Process daemonization

## Related Documentation

- [README.md](README.md) - Complete usage guide and examples
- [INSTALL.md](INSTALL.md) - Installation instructions
- [install.sh](install.sh) - Automated installation script
- [cve-2025-30066-explanation.md](cve-2025-30066-explanation.md) - CVE explanation
