# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

EDAMAME Posture is a cross-platform CLI tool for security posture assessment and remediation. Designed for developers and CI/CD pipelines, it provides security controls without requiring external connectivity.

Part of the EDAMAME ecosystem - see `../edamame_core/CLAUDE.md` for full ecosystem documentation.

## Documentation Index

- **[ARCHITECTURE.md](ARCHITECTURE.md)** - Module structure, command flow, daemon architecture
- **[README.md](README.md)** - Complete usage guide and examples
- **[INSTALL.md](INSTALL.md)** - Installation instructions for all platforms
- **[install.sh](install.sh)** - Automated installation script
- **[cve-2025-30066-explanation.md](cve-2025-30066-explanation.md)** - CVE explanation

## Build Commands

```bash
# Standard build
cargo build --release

# Platform-specific (via Makefile)
make macos_release
make linux_release
make linux_alpine_release    # MUSL-based
make windows_release

# Generate shell completions
make completions
```

## Testing

```bash
make test                      # Basic cargo tests
make commands_test             # CLI command integration tests
make test_integration_local    # Disconnected mode integration
make all_test                  # All local tests

# Connected tests (requires EDAMAME_USER, EDAMAME_DOMAIN, EDAMAME_PIN)
make test_integration_connected
```

## CLI Commands

### Score & System Info
```bash
edamame-posture get-score
edamame-posture get-device-info
edamame-posture list-threats
edamame-posture lanscan
```

### Remediation
```bash
edamame-posture remediate-all-threats
edamame-posture remediate-threat <THREAT_ID>
edamame-posture rollback-threat <THREAT_ID>
```

### Policy & Compliance
```bash
edamame-posture check-policy <MIN_SCORE> "<THREATS>" "[TAGS]"
edamame-posture check-policy-for-domain <DOMAIN> <POLICY>
edamame-posture request-signature
```

### Background Daemon
```bash
edamame-posture start          # Start monitoring daemon
edamame-posture stop           # Stop daemon
edamame-posture status         # Check daemon status
edamame-posture logs           # View daemon logs
```

### Network Monitoring
```bash
edamame-posture get-sessions
edamame-posture get-exceptions
edamame-posture capture
```

### MCP Server (AI Integration)
```bash
edamame-posture mcp-start
edamame-posture mcp-stop
edamame-posture mcp-generate-psk
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Policy/security check mismatch |
| 2 | Server error |
| 3 | Parameter error |
| 4 | Timeout |

## Architecture

### Source Files
- `main.rs` - CLI dispatch and initialization
- `cli.rs` - Command-line argument parsing (clap)
- `base.rs` - Core operations (score, threats, remediation)
- `background.rs` - Background daemon operations
- `daemon.rs` - Process lifecycle management

### Key Dependencies
- `edamame_core` - Security assessment engine
- `clap` - CLI framework
- `tokio` - Async runtime
- `daemonize` - Process daemonization

## Cross-Platform Support

- Linux: x86_64, aarch64, i686, armv7; Alpine, Debian, Ubuntu
- macOS: Native with code signing
- Windows: NPCAP integration

## Local Development

Use `../edamame_app/flip.sh local` to switch to local path dependencies.
