# EDAMAME Posture: Free CI/CD CLI

## What is it?
EDAMAME Posture is a lightweight, developer-friendly security posture assessment and remediation tool—perfect for those who want a straightforward way to secure their development environment and CI/CD pipelines without slowing down development.

## Table of Contents
- [What is it?](#what-is-it)
- [Quick Start: Background Mode with AI Security Assistant & Slack Alerts](#quick-start-background-mode-with-ai-security-assistant--slack-alerts)
- [Overview](#overview)
  - [Security Without Undermining Productivity](#security-without-undermining-productivity)
  - [Security Beyond Compliance](#security-beyond-compliance)
- [Key Features](#key-features)
- [Targeted Use Cases](#targeted-use-cases)
- [How It Works](#how-it-works)
- [Security Posture Assessment Methods](#security-posture-assessment-methods)
  - [1. Local Policy Check (check-policy)](#1-local-policy-check-check-policy)
  - [2. Domain-Based Policy Check (check-policy-for-domain)](#2-domain-based-policy-check-check-policy-for-domain)
  - [3. Continuous Monitoring with Access Control (start)](#3-continuous-monitoring-with-access-control-start)
- [Threat Models and Security Assessment](#threat-models-and-security-assessment)
  - [Threat Dimensions](#threat-dimensions)
  - [Compliance Frameworks](#compliance-frameworks)
  - [Assessment Methods](#assessment-methods)
  - [Whitelist Database](#whitelist-database)
- [Automation Options](#automation-options)
  - [Overview of Automation Capabilities](#overview-of-automation-capabilities)
  - [1. Auto-Remediation (One-Shot)](#1-auto-remediation-one-shot)
  - [2. AI Assistant (Continuous Remediation)](#2-ai-assistant-continuous-remediation)
  - [3. Network Violation Detection & Exit Codes](#3-network-violation-detection--exit-codes)
  - [4. Pipeline Cancellation (Real-Time)](#4-pipeline-cancellation-real-time)
  - [Combining Automation Options](#combining-automation-options)
- [CI/CD Integration and Workflow Controls](#cicd-integration-and-workflow-controls)
  - [1. Local-Only Assessment](#1-local-only-assessment)
  - [2. Domain-Based Policy Management](#2-domain-based-policy-management)
  - [3. Full Access Control Integration](#3-full-access-control-integration)
  - [4. Disconnected Background Mode](#4-disconnected-background-mode)
- [Preventing Supply Chain Attacks](#preventing-supply-chain-attacks)
- [CI/CD Integration Best Practices & Example Workflow](#cicd-integration-best-practices--example-workflow)
  - [1. Setup at Workflow Beginning](#1-setup-at-workflow-beginning)
  - [2. Perform Initial Assessment and Remediation](#2-perform-initial-assessment-and-remediation)
  - [3. Enforce Security Policies](#3-enforce-security-policies)
  - [4. Verify Network Conformance](#4-verify-network-conformance)
- [Jenkins Pipeline Integration](#jenkins-pipeline-integration)
- [Installation](#installation)
  - [Linux (Debian/Ubuntu)](#linux-debianubuntu)
  - [macOS](#macos)
  - [Windows](#windows)
- [Usage](#usage)
  - [Common Commands](#common-commands)
  - [All Available Commands](#all-available-commands)
- [Exit Codes and CI/CD Pipelines](#exit-codes-and-cicd-pipelines)
  - [Key Commands and Exit Codes](#key-commands-and-exit-codes)
  - [CI/CD Integration Example](#cicd-integration-example)
- [Whitelist System](#whitelist-system)
  - [Overview](#overview-1)
  - [Whitelist Structure](#whitelist-structure)
  - [Whitelist Building and Inheritance](#whitelist-building-and-inheritance)
  - [Matching Algorithm](#matching-algorithm)
  - [Domain Wildcard Matching](#domain-wildcard-matching)
  - [IP Address Matching](#ip-address-matching)
  - [AS Information Matching](#as-information-matching)
  - [Matching Process in Detail](#matching-process-in-detail)
  - [Best Practices for Whitelists](#best-practices-for-whitelists)
  - [Testing and Validation](#testing-and-validation)
  - [Troubleshooting](#troubleshooting)
  - [Reference](#reference)
  - [Embedded Whitelists](#embedded-whitelists)
    - [Base Whitelists](#base-whitelists)
    - [Development Whitelists](#development-whitelists)
    - [GitHub Workflow Whitelists](#github-workflow-whitelists)
      - [OS-Specific GitHub Whitelists](#os-specific-github-whitelists)
    - [Whitelist Inheritance Example](#whitelist-inheritance-example)
- [Blacklist System](#blacklist-system)
  - [Overview](#overview-2)
  - [Blacklist Structure](#blacklist-structure)
  - [IP Matching Algorithm](#ip-matching-algorithm)
  - [IPv4 and IPv6 Support](#ipv4-and-ipv6-support)
  - [Blacklist Usage Status](#blacklist-usage-status)
- [Network Behavior Anomaly Detection (NBAD)](#network-behavior-anomaly-detection-nbad)
  - [Overview](#overview-3)
  - [How NBAD Works](#how-nbad-works)
  - [Session Criticality Classification](#session-criticality-classification)
  - [Example Output](#example-output)
  - [NBAD Status and Integration](#nbad-status-and-integration)
  - [Autonomous Learning](#autonomous-learning)
- [Historical Security Posture Verification](#historical-security-posture-verification)
  - [Understanding Signatures and Historical Verification](#understanding-signatures-and-historical-verification)
  - [Signature Generation Methods](#signature-generation-methods)
  - [Git Integration Workflow Example](#git-integration-workflow-example)
  - [CI/CD Implementation Example](#cicd-implementation-example)
  - [Signature Verification in Release Processes](#signature-verification-in-release-processes)
- [Business Rules](#business-rules)
  - [Business Rules Visualization and Principles](#business-rules-visualization-and-principles)
- [Requirements](#requirements)
  - [eBPF Process Attribution (Linux)](#ebpf-process-attribution-linux)
- [Error Handling](#error-handling)
- [EDAMAME Ecosystem](#edamame-ecosystem)
- [Author](#author)

## Quick Start: Background Mode with AI Security Assistant & Slack Alerts

This guide walks you through the most common use case: running EDAMAME Posture in background mode with **EDAMAME Portal LLM** for AI-powered security remediation and **Slack alerts** for real-time notifications.

### What You'll Get

- **Continuous security monitoring** with automatic threat detection
- **AI-powered remediation** that analyzes and fixes security issues automatically
- **Network visibility** with LAN scanning and traffic capture
- **Slack notifications** for security actions and escalations

### Prerequisites

- EDAMAME Posture installed (see [Installation](#installation))
- Root/administrator privileges (required for network capture)
- A Slack workspace (for notifications)

### Step 1: Create an EDAMAME Portal Account

1. Go to **[portal.edamame.tech](https://portal.edamame.tech)**
2. Sign up for a free account
3. Verify your email address

### Step 2: Generate an API Key

1. Log in to **[portal.edamame.tech](https://portal.edamame.tech)**
2. Navigate to **API Keys** in the dashboard
3. Click **Create New API Key**
4. Give it a descriptive name (e.g., "workstation-security" or "ci-runner-prod")
5. Copy the generated key (it starts with `edm_` or `edak_`)

**Important**: Store your API key securely! It cannot be retrieved after creation.

### Step 3: Configure Environment Variables

Store your API key in a secure location and set it as an environment variable:

```bash
# Add to your shell profile (~/.bashrc, ~/.zshrc, or ~/.profile)
export EDAMAME_LLM_API_KEY="edm_live_your_api_key_here"

# Reload your shell profile
source ~/.bashrc  # or ~/.zshrc
```

For CI/CD environments, store the API key as a secret:
- **GitHub Actions**: Add as a repository secret named `EDAMAME_LLM_API_KEY`
- **GitLab CI**: Add as a CI/CD variable (masked)
- **Jenkins**: Add as a credential

### Step 4: Configure Slack Integration

To receive Slack notifications, you need to create a Slack Bot and set up channels:

#### 4.1 Create a Slack App

1. Go to **[api.slack.com/apps](https://api.slack.com/apps)**
2. Click **Create New App** → **From scratch**
3. Name it (e.g., "EDAMAME Security") and select your workspace
4. Under **OAuth & Permissions**, add these Bot Token Scopes:
   - `chat:write` - Post messages
   - `chat:write.public` - Post to public channels without joining
5. Click **Install to Workspace** and authorize
6. Copy the **Bot User OAuth Token** (starts with `xoxb-`)

#### 4.2 Create Slack Channels

Create two channels in your Slack workspace:
- `#security-actions` - For automated security actions (low/medium risk fixes)
- `#security-escalations` - For high-risk items requiring human review

Get the channel IDs:
1. Open each channel in Slack
2. Click the channel name → **View channel details**
3. Scroll to the bottom to find the **Channel ID** (starts with `C`)

#### 4.3 Set Slack Environment Variables

```bash
# Add to your shell profile
export EDAMAME_AGENTIC_SLACK_BOT_TOKEN="xoxb-your-bot-token"
export EDAMAME_AGENTIC_SLACK_ACTIONS_CHANNEL="C01234567890"        # #security-actions channel ID
export EDAMAME_AGENTIC_SLACK_ESCALATIONS_CHANNEL="C09876543210"   # #security-escalations channel ID
```

### Step 5: Start EDAMAME Posture with Network Monitoring

Now start EDAMAME Posture in background mode with all features enabled.

**Choose your agentic mode:**

| Mode | Description | Best For |
|------|-------------|----------|
| `auto` | AI automatically remediates low-risk issues, escalates high-risk to Slack | Hands-off security automation |
| `analyze` | AI analyzes and recommends fixes, but waits for human confirmation | Review-first approach, learning the system |

**Option A: Auto mode (recommended for production)**

```bash
sudo -E edamame_posture background-start-disconnected \
  --network-scan \
  --packet-capture \
  --agentic-mode auto \
  --agentic-provider edamame \
  --agentic-interval 300
```

In `auto` mode, the AI assistant will:
- Automatically fix low-risk security issues (e.g., enable firewall, update settings)
- Send notifications to Slack for actions taken
- Escalate high-risk items to Slack for human review before acting

**Option B: Analyze mode (recommended for initial setup)**

```bash
sudo -E edamame_posture background-start-disconnected \
  --network-scan \
  --packet-capture \
  --agentic-mode analyze \
  --agentic-provider edamame \
  --agentic-interval 300
```

In `analyze` mode, the AI assistant will:
- Analyze all security issues and provide recommendations
- Send all recommendations to Slack for review
- Wait for human confirmation before taking any action
- Good for understanding what the AI would do before enabling auto mode

**Command breakdown:**
| Flag | Description |
|------|-------------|
| `sudo -E` | Run with root privileges, preserving environment variables |
| `background-start-disconnected` | Run in background without connecting to EDAMAME Hub |
| `--network-scan` | Enable LAN device discovery (find devices on your network) |
| `--packet-capture` | Enable network traffic capture (monitor all connections) |
| `--agentic-mode auto/analyze` | Set AI behavior (see above) |
| `--agentic-provider edamame` | Use EDAMAME Portal LLM for AI analysis |
| `--agentic-interval 300` | Check for new security todos every 5 minutes |

### Step 6: Verify the Daemon is Running

```bash
# Check if daemon is responding (returns connection and AI assistant status)
edamame_posture background-status

# View real-time logs to confirm startup
edamame_posture background-logs
```

If the daemon is running, `background-status` will return:
- **Connection status**: user, domain, connection state, last report time
- **AI Assistant status**: mode (disabled/analyze/auto), interval, enabled state, last/next run times

If it fails with "Error getting connection status", the daemon is not running.

### Step 7: Monitor Agentic Behavior

Watch the AI assistant in action:

```bash
# Get a comprehensive summary of agentic status
edamame_posture agentic-summary

# Follow logs in real-time (Ctrl+C to stop)
edamame_posture background-logs -f
```

The `agentic-summary` command shows:
- LLM provider configuration and test status
- Auto-processing mode, interval, and next run time
- Subscription plan and usage
- Security todos breakdown by type (threats, policies, network issues, etc.)
- Action history counts (pending, executed, escalated, failed)
- Recent actions with timestamps
- Token usage statistics
- Slack integration status


### Step 8: Stop the Daemon (When Needed)

```bash
# Stop the background daemon
edamame_posture background-stop
```

### Complete Example Script

Here's a complete setup script you can save and run:

```bash
#!/bin/bash
# setup-edamame-security.sh

# Ensure environment variables are set
if [ -z "$EDAMAME_LLM_API_KEY" ]; then
    echo "Error: EDAMAME_LLM_API_KEY not set"
    echo "Get your API key at https://portal.edamame.tech/api-keys"
    exit 1
fi

if [ -z "$EDAMAME_AGENTIC_SLACK_BOT_TOKEN" ]; then
    echo "Warning: Slack integration not configured"
    echo "Set EDAMAME_AGENTIC_SLACK_BOT_TOKEN for notifications"
fi

# Start EDAMAME Posture with all features
sudo -E edamame_posture background-start-disconnected \
  --network-scan \
  --packet-capture \
  --agentic-mode auto \
  --agentic-provider edamame \
  --agentic-interval 300

# Verify it's running
sleep 2
edamame_posture background-status

echo ""
echo "EDAMAME Posture is now monitoring your system"
echo "View logs: edamame_posture background-logs -f"
echo "Stop: edamame_posture background-stop"
```

### Troubleshooting

| Issue | Solution |
|-------|----------|
| "EDAMAME_LLM_API_KEY not set" | Ensure you exported the variable and used `sudo -E` |
| "Permission denied" | Run with `sudo` for network capture features |
| No Slack messages | Verify bot token and channel IDs; check bot is in channels |
| "Daemon not running" | Check logs for errors: `edamame_posture background-logs` |

### Next Steps

- **Add whitelist enforcement**: Use `--whitelist github_ubuntu --fail-on-whitelist` for stricter network control
- **Enable blacklist checking**: Add `--fail-on-blacklist` to block known malicious IPs
- **Connect to EDAMAME Hub**: Use `start` command with `--user`, `--domain`, `--pin` for centralized management

---

## Alternative: MCP Server Mode with AI Assistants

Instead of (or in addition to) automatic background processing, you can use EDAMAME Posture as an **MCP (Model Context Protocol) server**. This lets AI assistants like **Claude Desktop**, **n8n**, or other MCP-compatible tools interact with your security posture directly.

### What is MCP?

MCP (Model Context Protocol) is an open standard for connecting AI assistants to external tools and data sources. EDAMAME Posture implements an MCP server that exposes security tools like:
- `advisor.get_todos` - List security issues that need attention
- `agentic.process_todos` - Run AI analysis on security issues
- `advisor.get_action_history` - View past security actions
- `advisor.undo_action` - Roll back automated fixes

### Step 1: Start the MCP Server

```bash
# Generate a secure pre-shared key (PSK) for authentication
edamame_posture mcp-generate-psk
# Output: YourSecurePSK123456789012345678901234

# Start the MCP server (localhost only, default)
sudo -E edamame_posture mcp-start --port 3000

# Or listen on all interfaces (for remote access, e.g., n8n on another host)
sudo -E edamame_posture mcp-start --port 3000 --all-interfaces
```

The server runs at `http://127.0.0.1:3000/mcp` by default, or `http://0.0.0.0:3000/mcp` with `--all-interfaces`.

### MCP Server Options

| Option | Description |
|--------|-------------|
| `--port <PORT>` | Port to listen on (default: 3000) |
| `--all-interfaces` | Listen on all network interfaces (0.0.0.0) instead of localhost only |
| `--enable-cors` | Enable CORS for browser-based clients |

### Integration Option A: Claude Desktop

Add the following to your Claude Desktop configuration file:

**macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
**Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
**Linux**: `~/.config/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "edamame": {
      "command": "npx",
      "args": [
        "mcp-remote",
        "http://127.0.0.1:3000/mcp",
        "--header",
        "Authorization: Bearer YourSecurePSK123456789012345678901234"
      ]
    }
  }
}
```

Replace `YourSecurePSK123456789012345678901234` with the PSK generated in Step 1. Restart Claude Desktop after updating the config.

### Integration Option B: n8n Workflow Automation

n8n is a workflow automation tool that can integrate with MCP servers for building security automation workflows.

**1. Start MCP server with network access (if n8n is on a different host):**

```bash
# On the EDAMAME host
sudo -E edamame_posture mcp-start --port 3000 --all-interfaces
```

**2. In n8n, use the HTTP Request node to call MCP tools:**

```
URL: http://<edamame-host>:3000/mcp/tools/advisor.get_todos
Method: POST
Headers:
  Authorization: Bearer YourSecurePSK123456789012345678901234
  Content-Type: application/json
Body: {}
```

**3. Example n8n workflow ideas:**
- Periodic security check: Schedule `advisor.get_todos` every hour, send results to Slack/email
- Auto-remediation pipeline: Get todos, filter by risk level, call `agentic.process_todos` for low-risk items
- Security dashboard: Aggregate security status across multiple EDAMAME endpoints
- Incident response: Trigger alerts when high-risk items are detected

### Example Conversations with Claude

Once connected, you can ask Claude to help with security:

**"What security issues need attention?"**
> Claude uses `advisor.get_todos` to list threats, vulnerable network devices, suspicious sessions, etc.

**"Fix all low-risk security issues"**
> Claude uses `agentic.process_todos` with auto mode to remediate safe issues.

**"Show me what security actions were taken today"**
> Claude uses `advisor.get_action_history` to display recent automated fixes.

**"Undo the last security action"**
> Claude uses `advisor.undo_action` to roll back if something went wrong.

### MCP Server Commands

| Command | Description |
|---------|-------------|
| `mcp-start --port <PORT>` | Start MCP server on specified port |
| `mcp-start --all-interfaces` | Listen on all interfaces (for remote access) |
| `mcp-stop` | Stop the MCP server |
| `mcp-status` | Check if MCP server is running |
| `mcp-generate-psk` | Generate a secure pre-shared key |

### Security Considerations

- The MCP server binds to `127.0.0.1` (localhost) by default for security
- Use `--all-interfaces` only when remote access is required (e.g., n8n on another host)
- PSK authentication is required - never share your PSK
- When using `--all-interfaces`, ensure proper firewall rules are in place
- All tool calls are logged for audit purposes
- Use with `sudo -E` to enable full security scanning capabilities

### Combining MCP with Background Mode

You can run both modes simultaneously:

```bash
# Terminal 1: Start background monitoring with Slack alerts
sudo -E edamame_posture background-start-disconnected \
  --network-scan \
  --packet-capture \
  --agentic-mode auto \
  --agentic-provider edamame \
  --agentic-interval 300

# Terminal 2: Start MCP server for interactive AI access
sudo -E edamame_posture mcp-start --port 3000
```

This gives you the best of both worlds:
- **Background mode**: Automatic continuous monitoring with Slack notifications
- **MCP mode**: On-demand AI-assisted security queries via Claude Desktop or n8n

---

## Overview
EDAMAME Posture is a cross-platform CLI that safeguards your software development lifecycle, making it easy to:
- Assess the security posture of your device or CI/CD environment
- Harden against common misconfigurations at the click of a button
- Monitor network traffic to detect and prevent supply chain attacks
- Generate compliance or audit reports, providing proof of a hardened setup

Whether you're an individual developer or part of a larger team, EDAMAME Posture offers flexible security options that grow with your needs—from completely local, disconnected controls to centralized policy management through EDAMAME Hub.

### Security Without Undermining Productivity
One of the key strengths of EDAMAME Posture is that it provides powerful security controls that work entirely locally, without requiring any external connectivity or registration:
- **Local Policy Checks**: Use the check-policy command to enforce security standards based on minimum score thresholds, specific threat detections, and security tag prefixes.
- **CI/CD Pipeline Gates**: Non-zero exit codes returned by these checks allow you to automatically fail pipelines when security requirements aren't met.
- **Disconnected Network Monitoring**: Monitor and enforce network traffic whitelists in air-gapped or restricted environments.
- **Zero-Configuration Integration**: Add security gates to your personal repositories with minimal setup.

This means you can immediately integrate security controls into your workflows, even before deciding to connect to EDAMAME Hub for more advanced features.

### Security Beyond Compliance
EDAMAME Posture enables powerful reporting and verification use cases:
- **Point-in-Time Signatures**: Generate cryptographically verifiable signatures that capture the security state of a device at a specific moment.
- **Historical Verification**: Verify that code was committed or released from environments that met security requirements.
- **Development Workflow Integration**: Embed signatures in Git commits, pull requests, or release artifacts for security traceability.
- **Continuous Compliance**: Maintain an audit trail of security posture across your development lifecycle.

These capabilities allow you not only to enforce security at build time but also to track and verify security posture throughout your entire development process.

## Key Features
- **Developer-Friendly CLI** – Straightforward commands allow you to quickly get things done with minimal fuss.
- **Cross-Platform Support** – Runs on macOS, Windows, and a variety of Linux environments.
- **Automated Remediation** – Resolve many security risks automatically with a single command.
- **Network & Egress Tracking** – Get clear visibility into local devices and outbound connections, detecting suspicious traffic that could indicate supply chain attacks.
- **Pipeline Security Gates** – Fail builds when security posture doesn't meet requirements, preventing insecure code deployment.
- **Compliance Reporting** – Generate tamper-proof reports for audits or personal assurance.
- **Optional Hub Integration** – Connect to EDAMAME Hub when you're ready for shared visibility and policy enforcement.
- **Versatile for CI/CD and Dev Machines** – Seamlessly integrates into CI/CD pipelines and developer workstations, via CLI and GitHub/GitLab Actions.

## Targeted Use Cases
- **Personal Device Hardening**: Quickly validate and remediate workstation security—ensuring it's safe for development work.
- **CI/CD Pipeline Security**: Insert edamame_posture checks to ensure ephemeral CI runners are properly secured before building or deploying code.
- **On-Demand Compliance Demonstrations**: Produce signed posture reports when working with clients or partners who require evidence of strong security practices.
- **Local Network Insights**: Run flodbadd to see what's on your subnet—no need for bulky network security tools.

## How It Works
1. **Install**: Place the edamame_posture binary in your system PATH (for example, /usr/local/bin on Linux/macOS) and make it executable.
2. **Run**: Use commands like `score` to check security posture or `remediate` to fix common issues automatically.
3. **Report**: Generate a signed report using `request-signature` and `request-report` to capture the current security posture in a verifiable format.
4. **Workflows**: Integrate EDAMAME Posture into CI pipelines. Check out the associated GitHub action to see how to integrate edamame_posture in GitHub workflows, and the associated GitLab workflow for GitLab CI/CD integration.

## Security Posture Assessment Methods
EDAMAME Posture offers three distinct approaches to ensure a device is compliant:

### 1. Local Policy Check (check-policy)
The `check-policy` command allows you to define and enforce security policies directly on your local system:

```
edamame_posture check-policy <MINIMUM_SCORE> "<THREAT_IDS>" "[TAG_PREFIXES]"
```

Example:
```
edamame_posture check-policy 2.0 "encrypted disk disabled" "SOC-2"
```

This command returns a non-zero exit code if the policy requirements are not met, making it suitable for gating CI/CD pipelines (fail the build if security requirements aren't satisfied).

### 2. Domain-Based Policy Check (check-policy-for-domain)
The `check-policy-for-domain` command validates the device's security posture against a policy defined for a specific domain in EDAMAME Hub:

```
edamame_posture check-policy-for-domain <DOMAIN> <POLICY_NAME>
```

Example:
```
edamame_posture check-policy-for-domain example.com standard_policy
```

This command also returns a non-zero exit code when the policy is not met, allowing CI/CD pipelines to halt if organization-wide security requirements aren't satisfied.

### 3. Continuous Monitoring with Access Control (start)
The `start` command initiates a background process that continuously monitors the device's security posture and can enable conditional access controls as defined in the EDAMAME Hub:

```
edamame_posture start --user <USER> --domain <DOMAIN> --pin <PIN> [--device-id <DEVICE_ID>] [--network-scan] [--packet-capture] [--whitelist <NAME>] [--fail-on-whitelist] [--fail-on-blacklist] [--fail-on-anomalous] [--include-local-traffic] [--cancel-on-violation] [--agentic-mode MODE] [--agentic-provider PROVIDER] [--agentic-interval SECONDS]
```

Example:
```
edamame_posture start --user user --domain example.com --pin 123456
```

This mode runs persistently (until stopped) and enforces policies in real-time, providing active protection of the environment.

> Tip: combine `--fail-on-whitelist` (and related checks) with `--cancel-on-violation` to automatically cancel CI pipelines whenever policy violations are detected.

## Threat Models and Security Assessment
EDAMAME Posture's security assessment capabilities are powered by comprehensive threat models that evaluate security across five key dimensions:

### Threat Dimensions

| Dimension | Description |
|-----------|-------------|
| Applications | Application authorizations, EPP/antivirus status, etc. |
| Network | Network configuration, exposed services, firewall settings... |
| Credentials | Password policies, biometric usage, 2FA enforcement, etc. |
| System Integrity | MDM profiles, signs of jailbreaking, unauthorized admin access |
| System Services | OS configuration, known service vulnerabilities, etc. |

### Compliance Frameworks
Security assessments incorporate industry-standard compliance frameworks, including:
- **CIS Benchmarks**: Center for Internet Security configuration guidelines
- **SOC-2**: Service Organization Control criteria for security, availability, and privacy
- **ISO 27001**: Information security management system requirements

Each threat detected by EDAMAME Posture is mapped to these compliance frameworks, allowing you to demonstrate alignment with specific security standards.

### Assessment Methods
EDAMAME Posture employs multiple assessment techniques to evaluate threats:
- **System Checks**: Direct inspection of system configurations, file presence, or settings.
- **Command Line Checks**: Safe, predefined system commands that gather security state information (with no malicious side effects).
- **Business Rules**: Optional custom script execution in user space for organization-specific policies or checks.

### Whitelist Database
Network security assessments leverage comprehensive whitelist databases that define allowable network connections. These whitelists can be tailored by environment and platform:
- **Base Whitelists**: Core connectivity needed for essential functionality.
- **Environment-Specific Whitelists**: Rules specialized for development or CI/CD environments.
- **Platform-Specific Whitelists**: Tailored allowed endpoints for macOS, Linux, and Windows.

Note: The whitelist system supports advanced pattern matching for domains, IP addresses (including CIDR ranges), ports, and protocols, enabling precise control over network communications.

## Automation Options

EDAMAME Posture provides multiple automation capabilities that can be combined to create a comprehensive, hands-off security workflow. These options range from one-time remediation to continuous AI-powered management and automatic pipeline enforcement.

### Overview of Automation Capabilities

| Capability | Type | Trigger | Scope | Use Case |
|-----------|------|---------|-------|----------|
| **Auto-Remediation** | One-shot | Manual command | Security posture | Fix security issues before/during build |
| **AI Assistant (Agentic)** | Continuous | Background daemon | Security todos | Automated "Do It For Me" security management |
| **Network Violation Detection** | One-shot | Command exit | Network traffic | Detect supply chain attacks, unauthorized connections |
| **Pipeline Cancellation** | Real-time | Violation detected | CI/CD pipeline | Stop builds immediately on security violations |

### 1. Auto-Remediation (One-Shot)

**Purpose**: Automatically fix common security issues in a single pass.

**How it works**: The `remediate` command scans for security threats and applies known-safe fixes immediately.

```bash
# Fix all security issues except remote login and firewall
edamame_posture remediate

# Fix ALL issues including potentially disruptive ones
edamame_posture remediate-all-threats-force

# Fix a specific threat by ID
edamame_posture remediate-threat "threat-id"
```

**Best for**:
- CI/CD pipeline initialization (harden the runner before build)
- Quick security posture improvement
- Automated compliance enforcement

**Limitations**:
- One-time action only (doesn't monitor for new issues)
- Skips potentially disruptive fixes by default (remote login, local firewall)

### 2. AI Assistant (Continuous Remediation)

**Purpose**: Continuous "Do It For Me" security management using LLM intelligence.

**How it works**: The background daemon monitors security todos and automatically processes them using AI reasoning.

**Modes**:
- **`auto`**: Automatically resolves safe/low-risk items; escalates high-risk items
- **`analyze`**: Provides recommendations without executing actions
- **`disabled`**: No AI processing (default)

```bash
# Option 1: EDAMAME Portal LLM (recommended for simplicity)
# Create an API key at portal.edamame.tech
edamame_posture start \
  --user myuser \
  --domain example.com \
  --pin 123456 \
  --network-scan \
  --packet-capture \
  --agentic-mode auto \
  --agentic-provider edamame \
  --agentic-interval 300

# Option 2: Bring Your Own LLM (e.g., Claude)
edamame_posture start \
  --user myuser \
  --domain example.com \
  --pin 123456 \
  --network-scan \
  --packet-capture \
  --agentic-mode auto \
  --agentic-provider claude \
  --agentic-interval 300

# Or in disconnected mode (no Hub connection)
edamame_posture background-start-disconnected \
  --network-scan \
  --packet-capture \
  --agentic-mode auto
```

**Environment Variables** (based on `--agentic-provider`):
```bash
# For --agentic-provider edamame (recommended - create API key at portal.edamame.tech)
export EDAMAME_LLM_API_KEY="edm_live_..."

# For --agentic-provider claude or openai (BYOLLM)
export EDAMAME_LLM_API_KEY="sk-ant-..."

# For --agentic-provider ollama
export EDAMAME_LLM_BASE_URL="http://localhost:11434"

# Slack integration (optional)
export EDAMAME_AGENTIC_SLACK_BOT_TOKEN="xoxb-..."
export EDAMAME_AGENTIC_SLACK_ACTIONS_CHANNEL="C01234567"
export EDAMAME_AGENTIC_SLACK_ESCALATIONS_CHANNEL="C07654321"
```

**Best for**:
- Long-running workstations or CI/CD runners
- Environments that need continuous security adaptation
- Teams wanting to reduce manual security work

**Cost**: ~$1-3/day for 24/7 operation with cloud LLMs; $0 with Ollama (local)

### 3. Network Violation Detection & Exit Codes

**Purpose**: Detect unauthorized network connections and fail pipelines when violations occur.

**How it works**: Compares captured network traffic against whitelists/blacklists and exits with non-zero code on violations.

**Detection Flags**:
```bash
# Fail if traffic doesn't conform to whitelist
edamame_posture get-sessions --fail-on-whitelist

# Fail if blacklisted IPs are contacted
edamame_posture get-sessions --fail-on-blacklist

# Fail if ML detects anomalous connections
edamame_posture get-sessions --fail-on-anomalous

# Combine all checks
edamame_posture get-sessions \
  --fail-on-whitelist \
  --fail-on-blacklist \
  --fail-on-anomalous
```

**Prevention During Capture**: You can also enable these checks when starting the background process:
```bash
edamame_posture start \
  --user myuser \
  --domain example.com \
  --pin 123456 \
  --network-scan \
  --packet-capture \
  --whitelist github_ubuntu \
  --fail-on-whitelist \
  --fail-on-blacklist \
  --fail-on-anomalous
```

**Exit Codes**:
- `0`: No violations detected
- `1`: Violation detected (whitelist/blacklist/anomalous as specified)
- `3`: No active sessions available

**Best for**:
- Supply chain attack prevention (like CVE-2025-30066)
- Zero-trust CI/CD networking
- Detecting malicious dependencies or compromised build steps

### 4. Pipeline Cancellation (Real-Time)

**Purpose**: Immediately stop CI/CD pipelines when security violations are detected during execution.

**How it works**: When `--cancel-on-violation` is enabled, EDAMAME actively monitors traffic in real-time and attempts to cancel the pipeline if violations occur.

```bash
# Start with automatic cancellation on violation
edamame_posture start \
  --user myuser \
  --domain example.com \
  --pin 123456 \
  --network-scan \
  --packet-capture \
  --whitelist github_ubuntu \
  --fail-on-whitelist \
  --fail-on-blacklist \
  --cancel-on-violation

# Or in disconnected mode
edamame_posture background-start-disconnected \
  --network-scan \
  --packet-capture \
  --whitelist github_ubuntu \
  --fail-on-whitelist \
  --cancel-on-violation
```

**Security Model**: The daemon executes an external cancellation script instead of having direct token access:
- **Script Location**: `$HOME/cancel_pipeline.sh` (default) or custom path via `EDAMAME_CANCEL_PIPELINE_SCRIPT`
- **Environment**: Script inherits original CI environment including `GITHUB_TOKEN` or `GITLAB_TOKEN`
- **Cross-Platform**: Uses bash even on Windows (Git Bash), macOS, and Linux
- **Auto-Detection**: Script automatically detects GitHub Actions vs GitLab CI and uses appropriate cancellation method
- **Secure by Design**: Daemon never has direct access to authentication tokens

**Environment Variables**:
- `EDAMAME_CANCEL_PIPELINE_SCRIPT`: Path to custom cancellation script (optional)
  - Default: `$HOME/cancel_pipeline.sh`
  - Script receives violation reason as first argument: `$1`
  - Must be executable (`chmod +x`)
  - Should exit 0 on success, non-zero on failure

**Example Custom Script**:
```bash
#!/bin/bash
# Custom cancellation with Slack notification
REASON="$1"

# Send alert to Slack
curl -X POST https://hooks.slack.com/... \
  -d "{\"text\":\"🚨 Pipeline cancelled: $REASON\"}"

# Cancel the pipeline
if [[ -n "$GITHUB_ACTIONS" ]]; then
  gh run cancel "$GITHUB_RUN_ID" --repo "$GITHUB_REPOSITORY"
fi
```

**Best for**:
- High-security environments where violations must stop immediately
- Preventing data exfiltration in progress
- Reducing wasted compute time on compromised builds

**Detection Interval**: The daemon checks for violations every 10 seconds, so cancellation typically occurs within 10-15 seconds of a violation.

**Note**: This provides defense-in-depth beyond exit code checking at workflow end.

### Combining Automation Options

You can combine these capabilities for comprehensive automation:

```bash
# Example: Full automation workflow

# 1. One-shot remediation at workflow start
edamame_posture remediate

# 2. Start continuous monitoring with AI assistant and real-time cancellation
edamame_posture start \
  --user myuser \
  --domain example.com \
  --pin 123456 \
  --network-scan \
  --packet-capture \
  --whitelist github_ubuntu \
  --fail-on-whitelist \
  --fail-on-blacklist \
  --fail-on-anomalous \
  --cancel-on-violation \
  --agentic-mode auto \
  --agentic-provider claude \
  --agentic-interval 600

# 3. Run your build/test steps
# ...

# 4. Final verification with network violation detection
edamame_posture get-sessions \
  --fail-on-whitelist \
  --fail-on-blacklist \
  --fail-on-anomalous
```

**Recommended Patterns**:

| Environment | Remediation | AI Assistant | Network Detection | Cancellation |
|------------|-------------|--------------|-------------------|--------------|
| **Personal Workstation** | Manual | `auto` mode | Optional | No |
| **Development CI** | Auto | `analyze` mode | `--fail-on-whitelist` | No |
| **Production CI** | Auto | `disabled` | All flags | Yes |
| **Air-Gapped CI** | Auto | `auto` (Ollama) | `--fail-on-whitelist` | Yes |

## CI/CD Integration and Workflow Controls
EDAMAME Posture offers multiple levels of security controls for CI/CD environments, allowing for gradual adoption and integration:

### 1. Local-Only Assessment
Using the `check-policy` approach, you can define and enforce security policies locally without any external connectivity or domain registration:

```
edamame_posture check-policy 2.0 "encrypted disk disabled,critical vulnerability" "SOC-2"
```

This approach is ideal for:
- Initial CI/CD security integration (quick wins early on)
- Air-gapped or highly restricted build environments
- Teams wanting full local control over security policies

### 2. Domain-Based Policy Management
Using `check-policy-for-domain`, you can centrally define policies in EDAMAME Hub while still enforcing them locally during builds (no constant cloud connection required):

```
edamame_posture check-policy-for-domain example.com standard_policy
```

This approach provides:
- **Centralized Policy Definition**: Define and manage policies organization-wide via EDAMAME Hub.
- **Consistent Enforcement**: Ensure all pipelines adhere to the same standards.
- **Offline Enforcement**: No need for continuous internet connectivity during the build to enforce the policy.

### 3. Full Access Control Integration
For maximum protection, use the background continuous monitoring with conditional access control via the `start` command:

```
edamame_posture start \
  --user <USER> \
  --domain <DOMAIN> \
  --pin <PIN> \
  --device-id "<DEVICE_ID>" \
  --network-scan \
  --packet-capture \
  --whitelist <WHITELIST_NAME> \
  --fail-on-whitelist \
  --fail-on-blacklist \
  --cancel-on-violation
```

(In practice, `--device-id`, `--network-scan`, `--packet-capture`, and `--whitelist` should be provided as needed for your setup. Additional flags such as `--fail-on-anomalous` or `--include-local-traffic` can further tailor behaviour.) This provides the most comprehensive CI/CD security controls:
- Real-time posture monitoring throughout the pipeline execution
- Dynamic access controls (e.g., block secrets/code access) based on current security posture
- Continuous conformance reporting to EDAMAME Hub (if connected)

### 4. Disconnected Background Mode
For environments where connecting to a domain or central service isn't possible or desired, you can run the background monitor in disconnected mode:

```
edamame_posture background-start-disconnected [--network-scan] [--packet-capture] [--whitelist <NAME>] [--fail-on-whitelist] [--fail-on-blacklist] [--fail-on-anomalous] [--include-local-traffic] [--cancel-on-violation] [--llm-api-key <KEY>] [--agentic-mode MODE] [--agentic-provider PROVIDER] [--agentic-interval SECONDS]
```

This enables all the monitoring and whitelist enforcement capabilities locally without requiring a registered domain:
- Fully local, real-time monitoring and network traffic capture (enable with `--packet-capture`)
- Whitelist enforcement without any external connectivity
- AI Assistant support with EDAMAME Portal LLM (`--agentic-provider edamame` + `EDAMAME_LLM_API_KEY` env) or BYOLLM
- Ideal for sensitive environments or isolated runners where external communication is not allowed

## Preventing Supply Chain Attacks
EDAMAME Posture provides critical protection against supply chain attacks in CI/CD pipelines:

- **Network Egress Monitoring**: Continuously monitors all outbound connections from your CI/CD runners.
- **Whitelist Enforcement**: Only allows connections to approved endpoints, blocking malicious or unexpected outbound traffic.
- **Real-Time Anomaly Detection**: Flags suspicious network activity that could indicate a compromised build step.
- **Exit Code Integration**: Automatically fails builds (via non-zero exit codes) when security violations are detected.

Real-world example: When the popular GitHub Action tj-actions/changed-files was compromised (CVE-2025-30066), attackers modified it to exfiltrate CI secrets by making unauthorized network calls to gist.githubusercontent.com. EDAMAME Posture's network monitoring would have detected and blocked this exact attack pattern, preventing the compromise by:

1. Identifying the unexpected connection to gist.githubusercontent.com
2. Recognizing that this domain was not on the approved whitelist
3. Failing the pipeline with a non-zero exit code
4. Providing detailed logs pinpointing the unauthorized connection

This zero-trust approach to CI/CD networking effectively prevents malicious payloads from executing, protecting your repositories from credential theft and further compromise.

## CI/CD Integration Best Practices & Example Workflow
For optimal security in your CI/CD workflows, follow these best practices regardless of the platform or CI system:

### 1. Setup at Workflow Beginning
Always place EDAMAME Posture setup at the very start of your workflow, before any build, test, or deployment steps run:
- This ensures that security monitoring is active throughout the entire pipeline.
- All network activity (even in early steps) is captured, including any malicious connections that might occur during dependency installation or build.
- It establishes a security posture baseline before any untrusted code runs.

Example (GitHub Actions):
```yaml
- name: Setup EDAMAME Posture
  run: |
    # Quick install using our installer script
    curl --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/edamametechnologies/edamame_posture_cli/main/install.sh | sh

    # Start background monitoring in disconnected mode (with LAN scanning + capture enabled)
    sudo edamame_posture background-start-disconnected --network-scan --packet-capture --whitelist github_ubuntu

# Or install and auto-configure with EDAMAME Portal LLM (recommended)
- name: Setup EDAMAME Posture with AI (Cloud LLM)
  run: |
    curl --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/edamametechnologies/edamame_posture_cli/main/install.sh | sh -s -- \
      --user ${{ vars.EDAMAME_USER }} \
      --domain ${{ vars.EDAMAME_DOMAIN }} \
      --pin ${{ secrets.EDAMAME_PIN }} \
      --agentic-mode auto \
      --agentic-provider edamame \
      --agentic-interval 600
    env:
      EDAMAME_LLM_API_KEY: ${{ secrets.EDAMAME_LLM_API_KEY }}

# Or with Bring Your Own LLM (e.g., Claude)
- name: Setup EDAMAME Posture with AI (BYOLLM)
  run: |
    curl --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/edamametechnologies/edamame_posture_cli/main/install.sh | sh -s -- \
      --user ${{ vars.EDAMAME_USER }} \
      --domain ${{ vars.EDAMAME_DOMAIN }} \
      --pin ${{ secrets.EDAMAME_PIN }} \
      --claude-api-key ${{ secrets.ANTHROPIC_API_KEY }} \
      --agentic-mode auto \
      --agentic-interval 600
```

Example (GitLab CI):
```yaml
setup_security:
  stage: setup
  script:
    - curl --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/edamametechnologies/edamame_posture_cli/main/install.sh | sh
    - sudo edamame_posture background-start-disconnected --network-scan --packet-capture --whitelist github_ubuntu
```

Important: In the above examples, `--network-scan` enables LAN discovery and `--packet-capture` starts traffic capture/whitelist enforcement. Omitting either flag limits network visibility.

### 2. Perform Initial Assessment and Remediation
Right after setup, assess the runner's security posture and optionally remediate any issues. This catches obvious problems early:
- Display the current security posture score for visibility.
- Automatically remediate common issues to harden the environment before proceeding.

Example (GitHub Actions):
```yaml
- name: Check and Remediate Security Posture
  run: |
    # Display current security posture score
    sudo edamame_posture score

    # Optional: Automatically remediate security issues
    sudo edamame_posture remediate
```

Example (GitLab CI):
```yaml
check_remediate:
  stage: verify
  script:
    - sudo edamame_posture score
    - sudo edamame_posture remediate
```

### 3. Enforce Security Policies
Apply security policy checks as a gate in your pipeline. If the environment doesn't meet your policy, fail fast:
- Use a local policy check to enforce minimum scores or specific threat conditions.
- (If using EDAMAME Hub) Optionally check against a centralized domain policy.

Example (GitHub Actions):
```yaml
- name: Enforce Security Policy
  run: |
    # Local policy check (fails if not compliant)
    sudo edamame_posture check-policy 2.0 "encrypted disk disabled,critical vulnerability" "SOC-2"

    # Or, if using EDAMAME Hub for team policy:
    # sudo edamame_posture check-policy-for-domain example.com standard_policy
```

Example (GitLab CI):
```yaml
enforce_policy:
  stage: verify
  script:
    - sudo edamame_posture check-policy 2.0 "encrypted disk disabled,critical vulnerability" "SOC-2"
  allow_failure: false  # Do not allow this job to fail without failing pipeline
```

(In GitLab, `allow_failure: false` ensures the pipeline fails if the policy check job fails.)

### 4. Verify Network Conformance
After build and tests, verify that no unauthorized network connections occurred by examining the captured sessions against the whitelist, and optionally checking for anomalous or blacklisted traffic:

```bash
# Fail the workflow if any network traffic violated the whitelist
# Also fail if any blacklisted connections are detected (default behaviour)
edamame_posture get-sessions --fail-on-whitelist --fail-on-blacklist

# To also fail when anomalous connections (machine learning detection) are observed
edamame_posture get-sessions --fail-on-whitelist --fail-on-blacklist --fail-on-anomalous

# To check only whitelist conformance and ignore blacklist/anomaly signals
edamame_posture get-sessions --fail-on-whitelist
```

Example (GitHub Actions):
```yaml
- name: Verify Network Conformance
  run: |
    # Fail the workflow if any network traffic violated the whitelist
    # or if any blacklisted connections are detected
    edamame_posture get-sessions --fail-on-whitelist --fail-on-blacklist
    
    # Optionally check for anomalous connections too
    # edamame_posture get-sessions --fail-on-whitelist --fail-on-blacklist --fail-on-anomalous
```

Example (GitLab CI):
```yaml
verify_network:
  stage: cleanup
  script:
    # Exits non-zero if whitelist was violated or blacklisted traffic detected
    - edamame_posture get-sessions
```

By following this pattern, you maintain a zero-trust security posture for all your CI/CD pipelines, effectively preventing supply chain attacks like the one described in CVE-2025-30066.

## Jenkins Pipeline Integration
For Jenkins users, EDAMAME Posture can be integrated into a scripted pipeline. Below is an example Jenkinsfile snippet that incorporates all the steps above:

```groovy
pipeline {
    agent any

    stages {
        stage('Setup Security') {
            steps {
                sh '''
                # Quick install EDAMAME Posture
                curl --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/edamametechnologies/edamame_posture_cli/main/install.sh | sh

                # Start background monitoring (disconnected mode with LAN scanning)
                sudo edamame_posture background-start-disconnected --network-scan --packet-capture --whitelist github_ubuntu

                # Initial posture assessment and optional remediation
                sudo edamame_posture score
                sudo edamame_posture remediate

                # Enforce security policy (local example)
                sudo edamame_posture check-policy 2.0 "encrypted disk disabled,critical vulnerability" "SOC-2"
                '''
            }
        }

        stage('Build') {
            steps {
                sh 'echo "Building the application..."'
                // ... build steps ...
            }
        }

        stage('Test') {
            steps {
                sh 'echo "Running tests..."'
                // ... test steps ...
            }
        }

        stage('Verify Security') {
            steps {
                script {
                    // Check network whitelist conformance
                    def exitCode = sh(script: 'edamame_posture get-sessions', returnStatus: true)
                    if (exitCode != 0) {
                        error "Network conformance check failed! Unauthorized network traffic detected."
                    }
                }
            }
        }

        stage('Deploy') {
            when {
                branch 'master'
            }
            steps {
                sh 'echo "Deploying application..."'
                // ... deployment steps ...
            }
        }
    }
}
```

In this Jenkins pipeline:
- **Setup Security**: Downloads the CLI, starts monitoring, performs a score check and remediate, and runs a policy check, failing the stage if any of these commands exit non-zero.
- **Build/Test**: Runs your normal build and test steps.
- **Verify Security**: After tests, uses get-sessions to ensure no unauthorized connections occurred. If any did, the pipeline is failed.
- **Deploy**: Only runs if on the master branch and if all prior stages (including security checks) passed.

## Installation
You can install EDAMAME Posture CLI on Linux, macOS, or Windows. Choose the method that fits your environment:

### Quick Install (Linux) - Recommended

For the fastest installation on Linux, use our universal installer script:

#### Basic Installation
```bash
curl --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/edamametechnologies/edamame_posture_cli/main/install.sh | sh
```

#### Install and Configure Service
```bash
curl --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/edamametechnologies/edamame_posture_cli/main/install.sh | sh -s -- \
  --user myuser \
  --domain example.com \
  --pin 123456
```

> The installer automatically enables and starts the service (systemd on Debian/Ubuntu, OpenRC on Alpine) as soon as configuration parameters are provided—no extra flag required.

> **How it installs:**  
> - Linux: prefers APK on Alpine and APT on Debian/Ubuntu-family distros, falling back to the correct GNU/MUSL binary when unavailable.  
> - macOS: tries Homebrew first, otherwise downloads the universal binary.  
> - Windows: tries Chocolatey first, otherwise downloads the standalone `.exe`.  
> See [`INSTALL.md`](INSTALL.md) for the full decision tree, supported flags (e.g., `--state-file`, `--debug-build`), and service-management details.

#### Install with AI Assistant (Claude)
```bash
curl --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/edamametechnologies/edamame_posture_cli/main/install.sh | sh -s -- \
  --user myuser \
  --domain example.com \
  --pin 123456 \
  --claude-api-key sk-ant-... \
  --agentic-mode auto \
  --agentic-interval 600 \
  --slack-bot-token xoxb-... \
  --slack-actions-channel C01234567
```

#### Install with AI Assistant (Ollama - Local/Privacy)
```bash
curl --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/edamametechnologies/edamame_posture_cli/main/install.sh | sh -s -- \
  --user myuser \
  --domain example.com \
  --pin 123456 \
  --ollama-base-url http://localhost:11434 \
  --agentic-mode auto \
  --agentic-interval 600
```

**Available Options:**
- `--user USER` - EDAMAME user
- `--domain DOMAIN` - EDAMAME domain
- `--pin PIN` - EDAMAME pin
- `--llm-api-key KEY` - LLM API key for AI assistant (all providers: edamame, claude, openai)
- `--claude-api-key KEY` - Claude API key (for Bring Your Own LLM)
- `--openai-api-key KEY` - OpenAI API key (for Bring Your Own LLM)
- `--ollama-base-url URL` - Ollama base URL (for local LLM)
- `--agentic-mode MODE` - AI mode: auto, analyze, or disabled
- `--agentic-interval SECONDS` - Processing interval
- `--slack-bot-token TOKEN` - Slack bot token
- `--slack-actions-channel ID` - Slack actions channel
- `--slack-escalations-channel ID` - Slack escalations channel
- `--start-lanscan` - Launch the service with `--network-scan`
- `--start-capture` - Launch the service with `--packet-capture`

Services installed via this script are automatically started and enabled for boot (systemd on Debian/Ubuntu, OpenRC on Alpine) whenever configuration parameters are supplied.

**What it does:**
-Automatically detects your Linux distribution
-Adds the appropriate EDAMAME repository (APT for Debian/Ubuntu, APK for Alpine)
-Imports signing keys securely
-Installs edamame-posture via package manager
-**Configures service with provided parameters**
-**Starts and enables the service automatically (systemd on Debian/Ubuntu, OpenRC on Alpine)**
-Verifies successful installation

**Supported distributions**: Alpine, Debian, Ubuntu, Raspbian (Raspberry Pi OS), Linux Mint, Pop!_OS, elementary OS, Zorin OS, and other Debian/Ubuntu derivatives

**What you get:**
- Package manager integration for easy updates
- Systemd service pre-configured with your settings
- AI Assistant ready to use (if configured)
- Command-line tool available system-wide
- Built-in helper functionality (no separate installation needed)

### Linux (Debian/Ubuntu/Raspbian)

#### APT Repository Method (Recommended)

> **Raspberry Pi Users**: EDAMAME Posture fully supports Raspberry Pi OS (formerly Raspbian) on all Raspberry Pi models. Use the APT repository method below or the quick install script.
The easiest way to install on Debian-based distributions is via our APT repository (this ensures you get updates automatically):

1. **Add the EDAMAME GPG Key**: Download and add the repository signing key:
   ```bash
   wget -O - https://edamame.s3.eu-west-1.amazonaws.com/repo/public.key | sudo gpg --dearmor -o /usr/share/keyrings/edamame.gpg
   ```

2. **Add the Repository**: Add EDAMAME's APT repository to your sources list:
   ```bash
   echo "deb [arch=amd64 signed-by=/usr/share/keyrings/edamame.gpg] https://edamame.s3.eu-west-1.amazonaws.com/repo stable main" | sudo tee /etc/apt/sources.list.d/edamame.list
   ```
   Note: Replace `arch=amd64` with your system architecture if needed (e.g., `arm64`, `i386`).

3. **Install EDAMAME Posture**:
   ```bash
   sudo apt update
   sudo apt install edamame-posture
   /usr/bin/edamame_posture --help
   ```

4. **Optional: Install EDAMAME Security GRPC GUI**  
   For a user-friendly graphical interface and enhanced control:
   ```bash
   sudo apt install edamame-security
   /usr/lib/edamame-security/edamame_security &
   ```
   The edamame-security package provides:
   - Rich graphical interface for controlling edamame-posture
   - Real-time monitoring and alerts through notifications
   - Easy configuration management
   - GRPC-based bidirectional communication with edamame-posture allowing for hybrid CLI/GUI operation
   - Integration with the system tray
   - Follows FreeDesktop standards for integration with the system

5. **Optional: Install EDAMAME Security GRPC CLI**
   ```bash
   sudo apt install edamame-cli
   /usr/bin/edamame_cli --help
   ```
   The edamame-cli is aimed at advanced users who want to integrate edamame-posture in their own scripts or workflows. It provides:
   - GRPC client for edamame-posture
  - Allows local RPC control of edamame-posture for automation (for example, driving checks/remediations from scripts). This is not “remote admin control” via EDAMAME Hub.

#### Alpine APK Repository Method
For Alpine Linux users, install via the APK repository:

1. **Add the EDAMAME Repository**: Add EDAMAME's APK repository and import the signing key:
   ```bash
   # Import the public key
   wget -O /tmp/edamame.rsa.pub https://edamame.s3.eu-west-1.amazonaws.com/repo/alpine/v3.15/x86_64/edamame.rsa.pub
   sudo cp /tmp/edamame.rsa.pub /etc/apk/keys/
   
   # Add the repository
   echo "https://edamame.s3.eu-west-1.amazonaws.com/repo/alpine/v3.15/main" | sudo tee -a /etc/apk/repositories
   ```
   Note: Replace `x86_64` with your system architecture if needed (e.g., `aarch64`).

2. **Install EDAMAME Posture**:
   ```bash
   sudo apk update
   sudo apk add edamame-posture
   /usr/bin/edamame_posture --help
   ```

#### Debian Package Installation
If you prefer not to add a repository, you can install the Debian package manually:

1. **Download** the Debian package for your platform:
   - **x86_64 (64-bit):** [edamame-posture_0.9.85-1_amd64.deb](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.85/edamame-posture_0.9.85-1_amd64.deb)
   - **i686 (32-bit):** [edamame-posture_0.9.85-1_i386.deb](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.85/edamame-posture_0.9.85-1_i386.deb)
   - **aarch64 (ARM 64-bit):** [edamame-posture_0.9.85-1_arm64.deb](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.85/edamame-posture_0.9.85-1_arm64.deb)
     - For Raspberry Pi 3/4/5 running 64-bit OS
   - **armv7 (ARM 32-bit):** [edamame-posture_0.9.85-1_armhf.deb](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.85/edamame-posture_0.9.85-1_armhf.deb)
     - For Raspberry Pi 2/3/4/Zero 2 running 32-bit OS (Raspberry Pi OS)

   > **Note**: These Debian packages have been tested on Linux Mint 20 and newer, Ubuntu 20.04 and newer, and Raspberry Pi OS (Raspbian).

2. **Install** the package using either method:
   ```bash
   sudo apt install ./edamame-posture_0.9.85-1_amd64.deb
   # or
   sudo dpkg -i edamame-posture_0.9.85-1_amd64.deb
   ```

3. **Configure** the service by editing the configuration file:
   ```bash
   sudo nano /etc/edamame_posture.conf
   ```

   **Basic Configuration** (Connected Mode):
   ```yaml
   edamame_user: "your_username"
   edamame_domain: "your.domain.com"
   edamame_pin: "your_pin"
   start_lanscan: "true"    # optional: pass --network-scan to the daemon
   start_capture: "false"   # optional: pass --packet-capture to the daemon
   ```

   **AI Assistant Configuration** (Optional):
   ```yaml
   # Enable AI Assistant
   agentic_mode: "auto"  # or "analyze" or "disabled"
   
   # Option 1: EDAMAME Portal LLM (recommended - create key at portal.edamame.tech)
   edamame_api_key: "edm_live_..."
   
   # Option 2: Bring Your Own LLM (choose ONE)
   claude_api_key: "sk-ant-..."     # Anthropic Claude
   openai_api_key: "sk-proj-..."   # OpenAI GPT
   ollama_base_url: "http://localhost:11434"  # Ollama (local)
   
   # Slack Notifications (optional)
   slack_bot_token: "xoxb-..."
   slack_actions_channel: "C01234567"
   slack_escalations_channel: "C07654321"
   
   # Processing interval (seconds)
   agentic_interval: "600"  # Check every 10 minutes
   ```

   **Disconnected Mode** (No Hub connection):
   Leave `edamame_user`, `edamame_domain`, and `edamame_pin` empty. The service will start in disconnected mode.

4. **Start** the service:
   ```bash
   sudo systemctl start edamame_posture.service
   # or if you installed the deb package, the service has been automatically started and you need to restart it:
   sudo systemctl restart edamame_posture.service
   ```

5. **Verify** the service status:
   ```bash
   sudo systemctl status edamame_posture.service
   ```

#### Manual Linux Binary Installation
For other Linux distributions or portable installation:

1. **Download Binary**: From the Releases page, download the binary for your architecture:
   - **x86_64 (64-bit)**: [edamame_posture-0.9.85-x86_64-unknown-linux-gnu](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.85/edamame_posture-0.9.85-x86_64-unknown-linux-gnu)  
   - **i686 (32-bit)**: [edamame_posture-0.9.85-i686-unknown-linux-gnu](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.85/edamame_posture-0.9.85-i686-unknown-linux-gnu)  
   - **aarch64 (ARM 64-bit)**: [edamame_posture-0.9.85-aarch64-unknown-linux-gnu](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.85/edamame_posture-0.9.85-aarch64-unknown-linux-gnu)  
   - **armv7 (ARM 32-bit)**: [edamame_posture-0.9.85-armv7-unknown-linux-gnueabihf](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.85/edamame_posture-0.9.85-armv7-unknown-linux-gnueabihf)
   - **x86_64 (64-bit) for Alpine Linux (musl)**: [edamame_posture-0.9.85-x86_64-unknown-linux-musl](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.85/edamame_posture-0.9.85-x86_64-unknown-linux-musl) 
   - **aarch64 (ARM 64-bit) for Alpine Linux (musl)**: [edamame_posture-0.9.85-aarch64-unknown-linux-musl](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.85/edamame_posture-0.9.85-aarch64-unknown-linux-musl)

2. **Install Binary**: Extract if needed and place the edamame_posture binary into a directory in your PATH (such as `/usr/local/bin`). For example:
```bash
chmod +x edamame_posture-0.9.85-x86_64-unknown-linux-gnu  
sudo mv edamame_posture-0.9.85-x86_64-unknown-linux-gnu /usr/local/bin/edamame_posture
```

### macOS

#### Homebrew Installation (Recommended)
The easiest way to install on macOS is via Homebrew:

```bash
# Add the EDAMAME tap
brew tap edamametechnologies/tap

# Install EDAMAME Posture
brew install edamame-posture

# Verify installation
edamame_posture --help
```

To update to the latest version:
```bash
brew update
brew upgrade edamame-posture
```

#### macOS Manual Binary Installation
For a manual installation on macOS:

1. **Download** the macOS universal binary:
   - [edamame_posture-0.9.85-universal-apple-darwin](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.85/edamame_posture-0.9.85-universal-apple-darwin)  

2. **Install** by placing the binary in your `PATH` and making it executable:
   ```bash
   sudo mv edamame_posture-* /usr/local/bin/edamame_posture
   sudo chmod +x /usr/local/bin/edamame_posture
   ```

3. **Run** a quick command like `edamame_posture score` to assess your device.

### Windows

#### Chocolatey Installation (Recommended)
The easiest way to install on Windows is via Chocolatey:

```powershell
# Install EDAMAME Posture
choco install edamame-posture

# Verify installation
edamame_posture get-core-version
```

To update to the latest version:
```powershell
choco upgrade edamame-posture
```

**Note**: You still need to install [Npcap](https://npcap.com/#download) separately for traffic capture functionality.

#### Windows Manual Binary Installation
For a manual installation on Windows:

1. **Download** the Windows binary:
   - [edamame_posture-0.9.85-x86_64-pc-windows-msvc.exe](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.85/edamame_posture-0.9.85-x86_64-pc-windows-msvc.exe)

2. **Install Npcap** (Required for traffic capture feature):
   - Install [Npcap](https://npcap.com/#download), the packet capture library from the Nmap team

3. **Add to PATH** (Optional but recommended):
   - Rename the downloaded file to `edamame_posture.exe`
   - Move it to a permanent location (e.g., `C:\Program Files\EDAMAME\`)
   - Add that location to your system PATH

4. **Run** a quick command to verify installation:
   ```cmd
   edamame_posture get-core-version
   ```
Note: Some commands require administrator privileges. Right-click on Command Prompt and select "Run as administrator" when needed or install Git Bash and use the provided sudo in an Administrator elevated terminal.

## Usage
Once installed, EDAMAME Posture is invoked via the `edamame_posture` command. Most commands will require administrator (root) privileges to run effectively. You can use `--help` on any subcommand to get more details.

### Common Commands
- **score**: Evaluate the current system security posture and output a score along with a summary of detected issues. This is a read-only check; it does not change system state. Use this regularly to gauge your security status.
- **remediate**: Automatically fix common security issues that have been detected. This may enable OS security features, adjust configurations, or apply patches as feasible. Always review what remediations are performed (the tool will log them) – it addresses issues that have known safe fixes.
- **dismiss-device** `<IP_ADDRESS>` / **dismiss-device-port** `<IP_ADDRESS>` `<PORT>`: Mark an entire device (or a single port) as intentionally allowed. These commands add the relevant dismiss rules so future network scans treat the traffic as expected—ideal when you intentionally allow a service but still want posture reporting for everything else.
- **dismiss-session** `<SESSION_UID>` / **dismiss-session-process** `<SESSION_UID>`: Silence a specific network session or every future session spawned by the same process. Use these commands after reviewing agentic/Slack summaries to acknowledge expected but noisy connections.
- **check-policy** `<min_score>` `"<threat_ids>"` `"[tag_prefixes]"`: Check whether the system meets a specified security policy. You provide a minimum score threshold, a comma-separated list of critical threat IDs to ensure are not present (or have specific states), and optional tag prefixes for compliance frameworks. This command exits with code 0 if the policy is met, or non-zero if not met (making it perfect for CI gating).
- **check-policy-for-domain** `<domain>` `<policy_name>`: Similar to check-policy, but retrieves the policy requirements from EDAMAME Hub for the given domain and policy name. This allows centralized policies to be enforced on the local machine. Requires that the machine is enrolled (or at least has a policy cached) for that domain.
- **start** `--user <USER>` `--domain <DOMAIN>` `--pin <PIN>` `[--device-id <ID>]` `[--network-scan]` `[--packet-capture]` `[--whitelist <NAME>]` `[--fail-on-whitelist]` `[--fail-on-blacklist]` `[--fail-on-anomalous]` `[--include-local-traffic]` `[--cancel-on-violation]` `[--llm-api-key <KEY>]` `[--agentic-mode <MODE>]` `[--agentic-provider <PROVIDER>]` `[--agentic-interval <SECONDS>]`: Start continuous monitoring and conditional access control. Typically run as a background service or daemon. You must supply your Hub user/email, domain, and one-time PIN (from Hub) to register the device session. Optional flags enable LAN scanning, packet capture, whitelist enforcement with failure conditions, local traffic inclusion, AI Assistant automation (with EDAMAME Portal LLM via `--llm-api-key` or BYOLLM), and pipeline cancellation on violations. This will keep running until stopped and enforce policy/network rules in real-time (e.g., locking down access if posture degrades).
- **background-start-disconnected** `[--network-scan]` `[--packet-capture]` `[--whitelist <NAME>]` `[--fail-on-whitelist]` `[--fail-on-blacklist]` `[--fail-on-anomalous]` `[--include-local-traffic]` `[--cancel-on-violation]` `[--llm-api-key KEY]` `[--agentic-mode MODE]` `[--agentic-provider PROVIDER]` `[--agentic-interval SECONDS]`: Start the background monitoring in a local-only mode (no connection to EDAMAME Hub). Combine `--network-scan` for LAN discovery with `--packet-capture` when you need traffic capture + whitelist enforcement. Optional flags enable whitelist/blacklist/anomaly enforcement with failure conditions, local traffic inclusion, pipeline cancellation on violations, AI Assistant mode (`auto`/`analyze`/`disabled`), provider selection (`edamame`, `claude`, `openai`, `ollama`, `none`), and processing interval. For AI, use `--llm-api-key` or set `EDAMAME_LLM_API_KEY` environment variable. This is useful for CI runners or standalone usage where you want monitoring without cloud integration. This process runs until killed; typically you'd run it in a screen/tmux or as a service.
- **get-sessions** `--fail-on-whitelist` `--fail-on-blacklist` `--fail-on-anomalous` `--zeek-format` `--include-local-traffic`: Report network sessions from the background process. Use the `--fail-on-*` flags to cause a non-zero exit code when violations are detected, optionally format output as Zeek, and include local traffic if desired. Returns exit code 0 when no fatal violations are detected.
- **flodbadd**: Perform a quick scan of the local network (LAN) to identify other devices on your subnet. This can reveal potential rogue devices or just provide situational awareness. It lists IP addresses and basic host info for devices it can detect.
- **request-signature**: Generate a security posture signature for the current device state. The output is a cryptographic signature (token) that represents the current posture (including all threat checks and scores). This signature can be stored or embedded (for example, in a Git commit message) as proof of posture at a point in time.
- **get-last-report-signature**: If the background process (start or background-start-disconnected) is running, this command fetches the most recently generated posture signature from that background monitor. This is useful to avoid generating a new one if one was already produced at the end of a build or a scheduled interval.
- **request-report**: Generate a full security report of the current system. This might output a file (e.g., PDF or JSON) containing the detailed posture assessment, including all findings and the signature. The report is signed so it can be verified later. Use this when you need to provide evidence of compliance or for auditing purposes.
- **create-custom-whitelists**: Outputs the current active whitelist definitions in JSON format to stdout. You can redirect this to a file to use as a base for a custom whitelist. This is often run at the end of a "learning mode" pipeline to capture allowed endpoints observed.
- **set-custom-whitelists** `"<json_string>"`: Loads a custom whitelist from a JSON string (or file content). Use this to apply a tailored whitelist (perhaps one created and edited from create-custom-whitelists) before running get-sessions. In practice, you might store a whitelist file in your repo and then do: `edamame_posture set-custom-whitelists "$(cat whitelist.json)"` to load it. The custom whitelist will override the default for the remainder of the session.
- **set-custom-whitelists-from-file** `<file_path>`: Loads a custom whitelist directly from a JSON file. This is more convenient than the string version when you have whitelist configuration files: `edamame_posture set-custom-whitelists-from-file whitelist.json`.
- **set-custom-blacklists-from-file** `<file_path>`: Loads a custom blacklist directly from a JSON file, similar to the whitelist file command.
- **merge-custom-whitelists-from-files** `<file1>` `<file2>`: Merges two whitelist JSON files into one consolidated whitelist, outputting the result to stdout. This is useful for combining base whitelists with environment-specific additions.
- **compare-custom-whitelists** `<whitelist_json_1>` `<whitelist_json_2>`: Compares two whitelist JSON strings and outputs the percentage difference. Returns 0 exit code. Useful for detecting whitelist stability during iterative refinement.
- **compare-custom-whitelists-from-files** `<file1>` `<file2>`: Compares two whitelist JSON files and outputs the percentage difference. Returns 0 exit code. Used by auto-whitelist mode to determine when baseline is stable.
- **get-anomalous-sessions** `[ZEEK_FORMAT]`: Display only anomalous network connections detected by the NBAD system. Returns non-zero exit code if anomalous sessions are found.
- **get-blacklisted-sessions** `[ZEEK_FORMAT]`: Display only blacklisted network connections. Returns non-zero exit code if blacklisted sessions are found.

### All Available Commands
For completeness, here is a list of EDAMAME Posture CLI subcommands with detailed information:

- **score** (alias for **get-score**) – Assess and output the security posture score and summary of issues. *Requires admin privileges*.
- **remediate** (alias for **remediate-all-threats**) – Apply recommended fixes to improve security posture (skips remote login and local firewall by default). *Requires admin privileges*.
- **remediate-all-threats-force** – Apply all fixes including those that could lock you out of the system (use with caution). *Requires admin privileges*.
- **remediate-threat** `<THREAT_ID>` – Remediate a specific threat by its threat ID. *Requires admin privileges*. Returns non-zero exit code if remediation fails.
- **dismiss-device** `<IP_ADDRESS>` – Dismiss every observed port on a device. Useful when you intentionally allow traffic from a host but still want other network violations to surface. *Requires admin privileges*.
- **dismiss-device-port** `<IP_ADDRESS>` `<PORT>` – Dismiss a single device port instead of the entire host. *Requires admin privileges*.
- **dismiss-session** `<SESSION_UID>` – Dismiss a specific session UID (as shown in `get-sessions` or agentic reports) so future runs treat it as expected. *Requires admin privileges*.
- **dismiss-session-process** `<SESSION_UID>` – Dismiss all future sessions spawned by the process behind the given session UID. *Requires admin privileges*.
- **rollback-threat** `<THREAT_ID>` – Roll back remediation for a specific threat by its threat ID. *Requires admin privileges*. Returns non-zero exit code if invalid parameters.
- **list-threats** – List all threat names available in the system. *Requires admin privileges*.
- **get-threat-info** `<THREAT_ID>` – Get detailed information about a specific threat. *Requires admin privileges*.
- **flodbadd** – Scan local network for connected devices. *Requires admin privileges*.
- **capture** `[SECONDS]` `[WHITELIST_NAME]` `[ZEEK_FORMAT]` `[LOCAL_TRAFFIC]` – Capture network traffic for a specified duration. *Requires admin privileges*.
- **check-policy** `<MINIMUM_SCORE>` `"<THREAT_IDS>"` `"[TAG_PREFIXES]"` – Local policy compliance check. *Requires admin privileges*. Returns non-zero exit code if policy not met.
- **check-policy-for-domain** `<DOMAIN>` `<POLICY_NAME>` – Policy check against a Hub-defined domain policy. *Requires admin privileges*. Returns non-zero exit code if policy not met.
- **check-policy-for-domain-with-signature** `"<SIGNATURE>"` `<DOMAIN>` `<POLICY_NAME>` – Verify a stored posture signature against a domain policy (for historical verification).
- **start** (alias for **background-start**) `--user <USER>` `--domain <DOMAIN>` `--pin <PIN>` `[--device-id <ID>]` `[--network-scan]` `[--packet-capture]` `[--whitelist <NAME>]` `[--fail-on-whitelist]` `[--fail-on-blacklist]` `[--fail-on-anomalous]` `[--include-local-traffic]` `[--cancel-on-violation]` `[--llm-api-key <KEY>]` `[--agentic-mode <MODE>]` `[--agentic-provider <PROVIDER>]` `[--agentic-interval <SECONDS>]` – Start continuous monitoring and Hub integration as a background daemon. *Requires admin privileges*.
- **foreground-start** – Start continuous monitoring in the foreground (used by systemd services). Accepts the same flags as `background-start` for device labeling, network configuration, and AI assistant behavior. *Requires admin privileges*.
- **background-start-disconnected** `[--network-scan]` `[--packet-capture]` `[--whitelist <NAME>]` `[--fail-on-whitelist]` `[--fail-on-blacklist]` `[--fail-on-anomalous]` `[--include-local-traffic]` `[--cancel-on-violation]` `[--llm-api-key <KEY>]` `[--agentic-mode MODE]` `[--agentic-provider PROVIDER]` `[--agentic-interval SECONDS]` – Start continuous monitoring in offline mode without Hub connection. *Requires admin privileges*.
- **stop** (alias for **background-stop**) – Stop a running background monitoring process.
- **status** (alias for **background-status**) – Check the status of the background monitoring process.
- **logs** (alias for **background-logs**) – Display logs from the background process.
- **get-sessions** (alias for **background-get-sessions**) `--fail-on-whitelist` `--fail-on-blacklist` `--fail-on-anomalous` – Report network sessions and optionally fail the command when violations are detected. Combine with `--zeek-format` or `--include-local-traffic` to adjust output. Returns exit code 0 when no fatal violations are detected, 1 when any selected fail-on condition is met, and 3 if no active sessions are available.
- **get-exceptions** (alias for **background-get-exceptions**) `[ZEEK_FORMAT]` `[LOCAL_TRAFFIC]` – Report network sessions that don't conform to whitelist rules.
- **get-background-score** (alias for **background-score**) – Get the current security score from the background process.
- **create-custom-whitelists** (alias for **background-create-custom-whitelists**) – Output template or current whitelist JSON.
- **set-custom-whitelists** (alias for **background-set-custom-whitelists**) `"<WHITELIST_JSON>"` – Load custom whitelist rules from input JSON.
- **set-custom-whitelists-from-file** (alias for **background-set-custom-whitelists-from-file**) `<WHITELIST_FILE>` – Load custom whitelist rules from a JSON file.
- **create-and-set-custom-whitelists** (alias for **background-create-and-set-custom-whitelists**) – Create custom whitelists from current sessions and apply them in one step.
- **set-custom-blacklists** (alias for **background-set-custom-blacklists**) `"<BLACKLIST_JSON>"` – Load custom blacklist rules from input JSON.
- **set-custom-blacklists-from-file** (alias for **background-set-custom-blacklists-from-file**) `<BLACKLIST_FILE>` – Load custom blacklist rules from a JSON file.
- **get-anomalous-sessions** (alias for **background-get-anomalous-sessions**) `[ZEEK_FORMAT]` – Display only anomalous network connections detected by the NBAD system. Returns non-zero exit code if anomalous sessions are found.
- **get-blacklisted-sessions** (alias for **background-get-blacklisted-sessions**) `[ZEEK_FORMAT]` – Display only blacklisted network connections. Returns non-zero exit code if blacklisted sessions are found.
- **get-blacklists** (alias for **background-get-blacklists**) – Get the current blacklists from the background process.
- **get-whitelists** (alias for **background-get-whitelists**) – Get the current whitelists from the background process.
- **get-whitelist-name** (alias for **background-get-whitelist-name**) – Get the name of the current active whitelist from the background process.
- **mcp-generate-psk** – Generate a cryptographically secure 32-character PSK for MCP server authentication.
- **mcp-start** `[PORT]` `[PSK]` `[--all-interfaces]` – Start MCP server for external AI clients (e.g., Claude Desktop). Port defaults to 3000. If PSK not provided, one is auto-generated. By default, binds to localhost only; use `--all-interfaces` to listen on all network interfaces.
- **mcp-stop** – Stop the running MCP server.
- **mcp-status** – Check MCP server status (running/stopped, port, URL).
- **request-signature** – Generate a cryptographic signature of current posture. *Requires admin privileges*.
- **get-last-report-signature** (alias for **background-last-report-signature**) – Retrieve the last posture signature from the background service.
- **request-report** `<EMAIL>` `<SIGNATURE>` – Generate a full security report. Returns non-zero exit code for invalid signature parameter.
- **get-core-info** – Retrieve core system information.
- **get-device-info** – Retrieve detailed device information. *Requires admin privileges*.
- **get-system-info** – Get system information. *Requires admin privileges*.
- **get-core-version** – Get the core version of EDAMAME Posture.
- **get-tag-prefixes** – Retrieve threat model tag prefixes. *Requires admin privileges*.
- **augment-custom-whitelists** – Augment the current custom whitelist locally using current whitelist exceptions. Outputs JSON to stdout. *Requires admin privileges*.
- **merge-custom-whitelists** `<WHITELIST_JSON_1>` `<WHITELIST_JSON_2>` – Merge two custom whitelist JSON strings into one consolidated whitelist.
- **merge-custom-whitelists-from-files** `<WHITELIST_FILE_1>` `<WHITELIST_FILE_2>` – Merge two custom whitelist JSON files into one consolidated whitelist.
- **compare-custom-whitelists** `<WHITELIST_JSON_1>` `<WHITELIST_JSON_2>` – Compare two custom whitelist JSON strings and output percentage difference.
- **compare-custom-whitelists-from-files** `<WHITELIST_FILE_1>` `<WHITELIST_FILE_2>` – Compare two custom whitelist JSON files and output percentage difference.
- **request-pin** `<USER>` `<DOMAIN>` – Request a PIN for domain connection. Returns non-zero exit code for invalid parameters.
- **wait-for-connection** (alias for **background-wait-for-connection**) `[TIMEOUT]` – Wait for connection of the background process with optional timeout. Returns exit code 4 for timeout.
- **completion** `<SHELL>` – Generate shell completion scripts for various shells (bash, zsh, fish, etc.).
- **help** – Show general help or help for a specific subcommand (e.g., `edamame_posture check-policy --help`).

Each command may have additional options and flags; run `edamame_posture <command> --help` for detailed usage information on that command. Commands marked with *Requires admin privileges* need to be run with elevated permissions (sudo on Linux/macOS, Run as Administrator on Windows).

## AI Assistant for Automated Security Management

EDAMAME Posture includes an **AI Assistant** that provides automated "Do It For Me" functionality for security posture management. The AI assistant can automatically process security todos using LLM (Large Language Model) analysis, reducing manual security work while maintaining safety.

### Background Daemon Integration (Recommended)

The AI Assistant runs continuously as part of the background daemon, automatically processing security todos at regular intervals.

#### Starting with AI Assistant

```bash
# Basic syntax
edamame_posture start \
  --user <USER> \
  --domain <DOMAIN> \
  --pin <PIN> \
  [--device-id <DEVICE_ID>] \
  [--network-scan] \
  [--packet-capture] \
  [--whitelist <NAME>] \
  [--fail-on-whitelist] \
  [--fail-on-blacklist] \
  [--fail-on-anomalous] \
  [--include-local-traffic] \
  [--cancel-on-violation] \
  [--agentic-mode MODE] \
  [--agentic-provider PROVIDER] \
  [--agentic-interval SECONDS]
```

**Agentic Parameters:**
- `AGENTIC_MODE`: `auto`, `analyze`, or `disabled` (default: `disabled`)
- `AGENTIC_PROVIDER`: `claude`, `openai`, `ollama`, or `none`
- `AGENTIC_INTERVAL`: Interval in seconds between processing runs (default: `3600`)

**Note:** CLI/daemon context supports `auto` (execute) and `analyze` (analyze & recommend without execution) in addition to `disabled`. The `semi` and `manual` modes still require interactive confirmation and remain exclusive to the GUI app (edamame_security).

#### Example: Automatic Mode with Claude

```bash
# Configure LLM via environment variable
export EDAMAME_LLM_API_KEY=sk-ant-...

# Start daemon with AI Assistant
edamame_posture start \
  --user myuser \
  --domain example.com \
  --pin 123456 \
  --network-scan \
  --packet-capture \
  --agentic-mode auto \
  --agentic-provider claude \
  --cancel-on-violation \
  --agentic-interval 300

# The AI will:
# - Monitor security todos continuously
# - Process them automatically every 5 minutes
# - Auto-resolve safe/low-risk items immediately
# - Escalate high-risk or complex items for manual review (logged in background-logs)
```

#### Example: Analyze Mode (Recommendations Only)

```bash
# Configure LLM via environment variable
export EDAMAME_LLM_API_KEY=sk-ant-...

# Start daemon in analyze mode
edamame_posture start \
  --user myuser \
  --domain example.com \
  --pin 123456 \
  --network-scan \
  --packet-capture \
  --agentic-mode analyze \
  --agentic-provider claude \
  --cancel-on-violation \
  --agentic-interval 600

# The AI will:
# - Review todos using the LLM every 10 minutes
# - Record decisions as "requires confirmation" without executing
# - Post the same Slack summaries as auto mode (actions + escalations)
# - Leave execution to a later manual approval step
```

#### Example: Slack Notifications

```bash
# Configure LLM via environment variable
export EDAMAME_LLM_API_KEY=sk-ant-...

# Configure Slack bot and channels (use channel IDs such as C01234567)
export EDAMAME_AGENTIC_SLACK_BOT_TOKEN="xoxb-your-slack-bot-token"
export EDAMAME_AGENTIC_SLACK_ACTIONS_CHANNEL="C01234567"
export EDAMAME_AGENTIC_SLACK_ESCALATIONS_CHANNEL="C07654321"  # Optional

# Start daemon
edamame_posture start \
  --user myuser \
  --domain example.com \
  --pin 123456 \
  --network-scan \
  --packet-capture \
  --agentic-mode auto \
  --agentic-provider claude \
  --cancel-on-violation \
  --agentic-interval 300

# The AI will:
# - Monitor security todos continuously
# - Process them automatically every 5 minutes
# - Auto-resolve safe/low-risk items immediately
# - Escalate high-risk or complex items for manual review (logged in background-logs)
# - Post summaries to your Slack channels (actions + escalations)
```

> Tip: If you only want alerts on failures, omit `EDAMAME_AGENTIC_SLACK_ACTIONS_CHANNEL` and set `EDAMAME_AGENTIC_SLACK_ESCALATIONS_CHANNEL` only.

#### Example: Local Privacy Mode with Ollama

```bash
# Setup Ollama (one-time)
brew install ollama
ollama serve &
ollama pull llama4

# Start with local LLM (no API calls, zero cost)
edamame_posture start \
  --user myuser \
  --domain example.com \
  --pin 123456 \
  --network-scan \
  --packet-capture \
  --agentic-mode auto \
  --agentic-provider ollama \
  --cancel-on-violation \
  --agentic-interval 300
```

### AI Assistant Modes

| Mode | Behavior | Best For |
|------|----------|----------|
| **auto** ⭐ | Automatically processes and resolves safe/low-risk todos; escalates high-risk items | CI/CD pipelines, development workstations, automated security management |
| **analyze** | Gathers LLM recommendations without executing changes; every decision is recorded as "requires confirmation" and posted to the actions Slack channel | Review workflows where humans approve actions, compliance-driven environments |
| **disabled** | No AI processing; all security items require manual review | When you want complete manual control |

**Note:** The GUI app (edamame_security) supports additional modes (`semi` and `manual`) that allow for user review before execution. These are not available in the CLI/daemon as there's no interactive UI for confirmation.

### LLM Provider Options

#### Claude (Anthropic) - Recommended ⭐
```bash
export EDAMAME_LLM_API_KEY=sk-ant-...
# Default model for background: claude-4-5-haiku (fast/cheap)
# Cost: ~$0.01 per run = ~$2.30/day with 5min interval
```

#### OpenAI
```bash
export EDAMAME_LLM_API_KEY=sk-proj-...
# Default model for background: gpt-5-mini
# Cost: ~$0.008 per run = ~$1.85/day with 5min interval
```

#### Ollama (Local) - Privacy First
```bash
brew install ollama && ollama pull llama4
# No API key needed, runs locally
# Cost: $0 (requires local resources)
```

#### None - Rule-Based
```bash
# No LLM, conservative rule-based decisions
# Escalates most items for manual review
# Cost: $0
```

### Configuration Details

The AI Assistant configuration is passed to the background daemon through environment variables:

**Environment Variables:**
- `EDAMAME_LLM_API_KEY` - Your LLM API key (required for Claude/OpenAI, not needed for Ollama)
- `EDAMAME_LLM_MODEL` - Override default model (optional)
  - Default for Claude: `claude-4-5-haiku`
  - Default for OpenAI: `gpt-5-mini-2025-08-07`
  - Default for Ollama: `llama4`
- `EDAMAME_LLM_BASE_URL` - Ollama base URL (optional, default: `http://localhost:11434`)
- `EDAMAME_AGENTIC_SLACK_BOT_TOKEN` - Slack bot token used for direct notifications (required for Slack integration)
- `EDAMAME_AGENTIC_SLACK_ACTIONS_CHANNEL` - Slack channel ID for routine summaries (optional)
- `EDAMAME_AGENTIC_SLACK_ESCALATIONS_CHANNEL` - Slack channel ID for escalations/alerts (optional)

**How it works:**
1. Set environment variables in the shell before starting the daemon
2. The daemon process inherits these environment variables
3. The daemon reads the env vars and configures the LLM provider via `agentic_set_llm_config`
4. Config is stored in CoreManager state (in-memory, not persisted to disk)

**Security Notes:**
- API keys are stored in the daemon's environment and memory during runtime
- Keys are never written to disk or log files
- For production deployments, consider using systemd's `LoadCredential=` or secrets management solutions
- When the daemon stops, all credentials are cleared from memory



### Slack Notifications

The AI Assistant now posts updates directly to Slack using the `chat.postMessage` API—no custom webhooks required.

**Environment variables**
- `EDAMAME_AGENTIC_SLACK_BOT_TOKEN` *(required)* – Slack bot token that starts with `xoxb-`. Create a Slack app, grant it `chat:write` (and optionally `chat:write.public`), install it in your workspace, and copy the bot token.
- `EDAMAME_AGENTIC_SLACK_ACTIONS_CHANNEL` *(optional)* – Channel ID for routine summaries (actions + pending reviews). Leave empty to disable daily chatter.
- `EDAMAME_AGENTIC_SLACK_ESCALATIONS_CHANNEL` *(optional)* – Channel ID for escalations/alerts. If omitted, escalations are sent to the actions channel when one is configured.

Each Slack card now includes the exact `edamame_posture` command needed to reproduce or acknowledge the action (for example, `dismiss-session-process` for a noisy process or `remediate-threat` for a targeted fix). Copy/paste it into any terminal with the CLI installed to apply the same remediation the agent suggested.

> Channel IDs look like `C01234567`. In Slack, open the channel → *Channel details* → *More* → *Copy channel ID*.

**Setup example**

```bash
export EDAMAME_AGENTIC_SLACK_BOT_TOKEN="xoxb-your-slack-bot-token"
export EDAMAME_AGENTIC_SLACK_ACTIONS_CHANNEL="C01234567"
export EDAMAME_AGENTIC_SLACK_ESCALATIONS_CHANNEL="C07654321"  # Optional

edamame_posture start --user myuser --domain example.com --pin 123456 --network-scan --packet-capture --agentic-mode auto --agentic-provider claude --agentic-interval 300
```

Messages include the same rich markdown payload used previously for webhooks, so Slack renders emojis, headings, and summaries automatically. Escalation alerts are only sent when items require attention.

**Validation & troubleshooting**

```bash
edamame_posture logs | grep -i "Slack"
```

- Make sure the bot has been invited to each target channel (`/invite @YourBot`).
- Confirm the bot token has the `chat:write` scope and is not expired.
- If nothing arrives, double-check that you're using channel IDs (not names) and that the daemon was restarted after exporting the variables.
- Use `curl -X POST https://slack.com/api/chat.postMessage` with your token to verify connectivity if needed.

Once the Slack integration is configured you can use Slack workflows or connectors to forward notifications to PagerDuty, email, or ticketing systems if desired.

### Monitoring AI Activity

```bash
# View AI Assistant activity
edamame_posture background-logs | grep "AI Assistant"

# Expected output:
# [INFO] AI Assistant enabled: mode=auto, provider=Some("claude"), interval=300s
# [INFO] AI Assistant configured: claude / claude-4-5-haiku
# [INFO] AI Assistant: Processed 5 todos - 4 auto-resolved, 1 escalated, 0 failed
```

### Systemd Integration

#### Using the Debian/Ubuntu/Alpine Package (Recommended)

If you installed via APT or APK, the service is already configured and enabled on boot (systemctl enable on Debian/Ubuntu, rc-update add default on Alpine). Simply edit `/etc/edamame_posture.conf`:

```bash
sudo nano /etc/edamame_posture.conf
```

```yaml
# Basic configuration
edamame_user: "myuser"
edamame_domain: "example.com"
edamame_pin: "123456"
start_lanscan: "true"
start_capture: "false"

# AI Assistant configuration
agentic_mode: "auto"
claude_api_key: "sk-ant-..."
slack_bot_token: "xoxb-..."
slack_actions_channel: "C01234567"
slack_escalations_channel: "C07654321"
agentic_interval: "600"
```

Then restart the service:

**Debian/Ubuntu:**
```bash
sudo systemctl restart edamame_posture
```

**Alpine:**
```bash
sudo rc-service edamame_posture restart
```

#### Manual Systemd Service

For custom installations, create a systemd service:

```ini
# /etc/systemd/system/edamame-posture.service

[Unit]
Description=EDAMAME Security Posture with AI Assistant
After=network.target

[Service]
Type=forking
Environment="EDAMAME_LLM_API_KEY=sk-ant-..."
Environment="EDAMAME_AGENTIC_SLACK_BOT_TOKEN=xoxb-your-bot-token"
Environment="EDAMAME_AGENTIC_SLACK_ACTIONS_CHANNEL=C01234567"
# Optional escalation-only channel (omit to reuse the actions channel)
Environment="EDAMAME_AGENTIC_SLACK_ESCALATIONS_CHANNEL=C07654321"
ExecStart=/usr/local/bin/edamame_posture start --user myuser --domain example.com --pin 123456 --network-scan --packet-capture --agentic-mode auto --agentic-provider claude --agentic-interval 600
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

### Cost Analysis

For 24/7 background operation:

| Interval | Runs/Day | Claude Haiku | OpenAI mini | Ollama |
|----------|----------|--------------|-------------|--------|
| 5 min    | 288      | ~$2.88/day   | ~$2.30/day  | $0     |
| 10 min   | 144      | ~$1.44/day   | ~$1.15/day  | $0     |
| 30 min   | 48       | ~$0.48/day   | ~$0.38/day  | $0     |

**Recommended**: Auto mode with 300-600s interval for balance of responsiveness and cost.

### Handling Escalated Items

When the AI escalates a todo (too risky or complex):
1. **Remains in advisor** - Still visible in app/CLI
2. **Logged for visibility** - Shows in background logs
3. **Manual review needed** - Handle when convenient

**Review via CLI:**
```bash
# Check what AI escalated
edamame_posture background-logs | grep "escalated"

# Review current todos
edamame_posture background-score

# Manually remediate if needed
edamame_posture remediate-threat "threat-name"
```

**Review via App:**
- Open edamame_app → Advisor tab → See escalated items with AI reasoning

## MCP Server for External AI Assistants

EDAMAME Posture can start an **MCP (Model Context Protocol) server** that allows external AI assistants like Claude Desktop to access EDAMAME's security automation tools remotely.

### What is MCP?

MCP (Model Context Protocol) is an open standard from Anthropic that enables AI assistants to interact with external tools and services. By enabling the MCP server in EDAMAME, you can:

- Ask Claude Desktop to analyze your security posture
- Automate security fixes through conversational AI
- Access all 9 EDAMAME security automation tools via natural language
- Process security todos with AI reasoning

### MCP Server Commands

#### Generate PSK (Authentication Key)

```bash
edamame_posture mcp-generate-psk

# Output:
# RJgYkzfteQGu0JIS4DWDl9cH8+ENeI0M
# # Save this PSK securely - it's required for MCP client authentication
```

Generates a cryptographically secure 32-character Pre-Shared Key (PSK) for authenticating MCP clients.

#### Start MCP Server

```bash
# With auto-generated PSK:
edamame_posture mcp-start

# With custom port:
edamame_posture mcp-start 3000

# With specific PSK:
edamame_posture mcp-start 3000 "your-32-char-psk-here"

# Listen on all network interfaces (for remote AI clients):
edamame_posture mcp-start 3000 "your-32-char-psk-here" --all-interfaces

# Output:
# ✅ MCP server started successfully
#    Port: 3000
#    URL: http://127.0.0.1:3000/mcp/
#    PSK: RJgYkzfteQGu...
# 
# Claude Desktop config:
# {
#   "mcpServers": {
#     "edamame": {
#       "command": "npx",
#       "args": [
#         "mcp-remote",
#         "http://127.0.0.1:3000/mcp",
#         "--header",
#         "Authorization: Bearer RJgYkzfteQGu..."
#       ]
#     }
#   }
# }
```

Starts the MCP server on specified port (default: 3000). If no PSK is provided, one is generated automatically and displayed.

**Security Note**: By default, the server binds to localhost (127.0.0.1) only and is not accessible from the network. Use the `--all-interfaces` flag to bind to all network interfaces (0.0.0.0), which allows remote AI clients to connect but requires proper network security measures.

#### Stop MCP Server

```bash
edamame_posture mcp-stop

# Output:
# ✅ MCP server stopped
```

Stops the running MCP server.

#### Check Server Status

```bash
edamame_posture mcp-status

# Output when running:
# ✅ MCP server is running
#    Port: 3000
#    URL: http://127.0.0.1:3000/mcp/

# Output when stopped:
# ○ MCP server is not running
```

Displays the current status of the MCP server.

### Available MCP Tools

When connected via MCP, AI assistants have access to 9 security automation tools:

**Advisor Tools (4):**
- `advisor_get_todos` - List security action items
- `advisor_get_action_history` - View AI action history with undo info
- `advisor_undo_action` - Undo a specific AI action
- `advisor_undo_all_actions` - Undo all AI actions (panic button)

**Agentic Tools (3):**
- `agentic_process_todos` - **"Do It For Me" workflow** - processes all security items
- `agentic_execute_action` - Execute a pending action
- `agentic_get_workflow_status` - Get processing status

**Score Tools (2):**
- `score_get` - Get current security score
- `score_compute` - Trigger score recomputation

### Claude Desktop Integration

1. **Start MCP Server:**
   ```bash
   # Generate and save PSK
   PSK=$(edamame_posture mcp-generate-psk | head -1)
   echo "PSK: $PSK" > ~/.edamame_mcp_psk
   
   # Start server
   edamame_posture mcp-start 3000 "$PSK"
   ```

2. **Configure Claude Desktop:**
   
   Edit `~/Library/Application Support/Claude/claude_desktop_config.json`:
   ```json
   {
     "mcpServers": {
       "edamame": {
         "command": "npx",
         "args": [
           "mcp-remote",
           "http://127.0.0.1:3000/mcp",
           "--header",
           "Authorization: Bearer <your-psk-here>"
         ]
       }
     }
   }
   ```

3. **Restart Claude Desktop**

4. **Ask Claude:**
   ```
   "Check my security posture and fix any safe issues"
   
   Claude will:
   - Call advisor.get_todos to see security items
   - Call agentic.process_todos to automatically handle safe items
   - Report: "Fixed 8 items, 2 need your review"
   ```

### MCP Use Cases

**Headless Server Mode:**
```bash
# Start daemon + MCP server
edamame_posture start --user user --domain domain.com --pin 123456 &
edamame_posture mcp-start 3000 "$PSK"

# Now remote AI can manage security via MCP
```

**CI/CD Automation:**
```bash
#!/bin/bash
# Generate PSK from environment
PSK="${MCP_PSK:-$(edamame_posture mcp-generate-psk | head -1)}"

# Start MCP server
edamame_posture mcp-start 3000 "$PSK"

# Run Python/Node MCP client for automated security checks
python3 ./security/mcp_client.py --psk "$PSK"

# Stop server
edamame_posture mcp-stop
```

**Security Note**: MCP server uses HTTP on localhost with PSK authentication. This is secure for local-only access (same security model as Jupyter Notebook, VS Code Server, Docker API). The server is NOT accessible from the network.

## Exit Codes and CI/CD Pipelines
EDAMAME Posture is designed to integrate seamlessly with CI/CD pipelines by using standardized exit codes that can control workflow execution. This allows for security-driven pipeline decisions without complex scripting.

### Key Commands and Exit Codes
The following commands are particularly useful in CI/CD because their exit code signals the pipeline what to do:

- **get-sessions**: Returns 0 if session data was retrieved and all network connections conformed to the whitelist. Returns a non-zero code if a whitelist violation occurred (meaning unauthorized network activity was detected). Specifically, an non-zero exit code indicates that sessions were found but some connection failed the whitelist check, and an non-zero exit code indicates that no active network sessions were found (which is not an error, but a special case).
- **check-policy**: Returns 0 if the local policy requirements are met, or 1 if the requirements are not met (policy check failed).
- **check-policy-for-domain**: Returns 0 if the domain policy requirements (fetched from EDAMAME Hub) are met, or 1 if not met.

These predictable exit codes mean you can directly use these commands in scripts to fail a job when needed (as shown in the examples above).

### CI/CD Integration Example
Below is a mini workflow snippet (GitHub Actions style) illustrating how these exit codes might be used:

```yaml
jobs:
  security-check:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Install EDAMAME Posture
        run: |
          curl --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/edamametechnologies/edamame_posture_cli/main/install.sh | sh

      - name: Start background monitor in disconnected mode
        run: sudo edamame_posture background-start-disconnected --network-scan --packet-capture --whitelist github_ubuntu

      - name: Run build steps
        run: |
          # (Your build commands here)
          npm install
          npm test

      - name: Verify network conformance
        run: |
          # Fail if network traffic violated the whitelist
          edamame_posture get-sessions

      - name: Enforce security policy
        run: |
          # Fail if security posture requirements aren't met
          sudo edamame_posture check-policy 2.0 "encrypted disk disabled,critical vulnerability" "SOC-2"
```

In this example, if either the network conformance step or the policy enforcement step finds an issue, the respective command will exit with a non-zero code, causing the workflow to fail. This way, you don't need additional logic to check outputs — the CLI's exit codes handle it. By leveraging these exit codes, you can create pipelines that automatically enforce security policies and network rules without custom scripting or conditional logic.

## Whitelist System

### Overview
The EDAMAME Posture whitelist system provides a flexible and powerful way to control network access, using a hierarchical whitelist structure with clear matching priorities. Understanding how to create and apply whitelists is key to using EDAMAME's network monitoring effectively.

### Whitelist Structure
Whitelists are defined in JSON and can inherit from one another for convenience. The structure is roughly:

```rust
// Main whitelist container
struct Whitelists {
    date: String,                    // Creation/update date
    signature: Option<String>,       // Optional cryptographic signature of the whitelist
    whitelists: Map<String, WhitelistInfo> // Named whitelist collection
}

// Individual whitelist definition
struct WhitelistInfo {
    name: String,                     // Unique identifier
    extends: Option<Vec<String>>,     // Parent whitelist names to inherit from
    endpoints: Vec<WhitelistEndpoint> // List of allowed endpoints
}

// Network endpoint specification
struct WhitelistEndpoint {
    domain: Option<String>,     // Domain name (supports wildcards)
    ip: Option<String>,         // IP address or CIDR range
    port: Option<u16>,          // Port number
    protocol: Option<String>,   // Protocol (TCP, UDP, etc.)
    as_number: Option<u32>,     // Autonomous System number
    as_country: Option<String>, // Country code of the AS
    as_owner: Option<String>,   // AS owner/organization name
    process: Option<String>,    // Process name initiating the connection
    description: Option<String> // Human-readable description of the entry
}

> **Note:** `process` is optional and primarily useful for handcrafted rules. Automatically generated or augmented custom whitelists intentionally leave this field empty because process names and usernames on CI runners change frequently and would otherwise cause noisy diffs.
```

### Whitelist Building and Inheritance

#### Basic Whitelist Setup
A simple whitelist JSON looks like:

```json
{
  "date": "October 24th 2023",
  "whitelists": [
    {
      "name": "basic_services",
      "endpoints": [
        {
          "domain": "api.example.com",
          "port": 443,
          "protocol": "TCP",
          "description": "Example API server"
        }
      ]
    }
  ]
}
```

This defines one whitelist named "basic_services" allowing TCP connections to api.example.com:443.

#### Inheritance System
Whitelists can inherit from others using the extends field, creating a hierarchy. For example:

```json
{
  "whitelists": [
    {
      "name": "base_services",
      "endpoints": [
        { "domain": "api.example.com", "port": 443, "protocol": "TCP" }
      ]
    },
    {
      "name": "extended_services",
      "extends": ["base_services"],
      "endpoints": [
        { "domain": "cdn.example.com", "port": 443, "protocol": "TCP" }
      ]
    }
  ]
}
```

Here, extended_services includes everything in base_services plus its own endpoints. Inheritance allows you to build whitelists in layers (base corporate services, extended project-specific services, etc.). When a whitelist extends another:
- **Endpoint Aggregation**: All endpoints from the parent whitelist(s) are included in the child.
- **Multiple Inheritance**: A whitelist can extend multiple parent whitelists.
- **Circular Reference Protection**: The system detects and prevents infinite loops in inheritance (no endless recursion).

When retrieving endpoints from a whitelist, the logic ensures all inherited endpoints are included exactly once. Pseudo-code for collecting all endpoints might look like:

```pseudo
function get_all_endpoints(whitelist_name, visited=set()):
    if whitelist_name in visited:
        return []
    visited.add(whitelist_name)

    info = whitelists[whitelist_name]
    endpoints = clone(info.endpoints)

    if info.extends exists:
        for parent in info.extends:
            endpoints += get_all_endpoints(parent, visited)

    return endpoints
```

### Matching Algorithm
The whitelist enforcement logic follows a specific order when determining if a network connection should be allowed:

#### 1. Fundamental Match Criteria
These criteria are checked first; if they don't pass, the entry is not considered a match:
- **Protocol**: If specified in the whitelist entry, it must match the connection's protocol (case-insensitive, e.g., "TCP" matches "tcp").
- **Port**: If specified, it must exactly match the connection's port.
- **Process**: If specified, the process name initiating the connection must match (case-insensitive).

If any specified fundamental criterion does not match, that whitelist entry is skipped (NO_MATCH for that entry).

#### 2. Hierarchical Match Order
If fundamental criteria pass for an entry, the system then evaluates domain, IP, and AS information in a strict priority order:
- **Domain Matching**: If a domain is specified in the whitelist entry and the connection's domain matches it, this entry is considered a match immediately.
- **IP Matching**: If no domain is specified or the domain didn't match, and an IP or CIDR is specified, check if the connection's IP matches. If yes, it's a match.
- **AS (Autonomous System) Info**: If neither domain nor IP matched (or were specified), and the whitelist entry includes AS number/country/owner criteria, evaluate those. All specified AS criteria must match the connection's attributes to count as a match.

Additionally, if a domain or IP was specified in the entry but the connection didn't match either, the entry is considered a failed match and AS info is not checked for that entry (since domain/IP are higher priority and didn't match). In summary, for each connection and each whitelist entry, the logic is:

```pseudo
if protocol/port/process don't match -> skip entry (no match)
if domain is specified:
    if connection.host matches domain (including wildcard logic) -> MATCH
    else -> if domain was specified and didn't match, this entry cannot match (skip)
if ip is specified:
    if connection.ip matches ip (or within CIDR) -> MATCH
    else -> if ip was specified and didn't match, skip (unless domain was also specified, which we handled above)
if AS info is specified (and we haven't matched yet):
    if any AS field specified does not match connection's AS info -> skip (no match)
if all specified fields match -> MATCH
```

If any whitelist entry yields a MATCH, the connection is allowed. If no entries match, the connection is unauthorized.

### Domain Wildcard Matching
The whitelist supports wildcards in domain entries in three forms:
- **Prefix wildcards (*.example.com)**: Matches any subdomain of example.com but not the root example.com itself. For example, *.example.com matches sub.example.com or a.b.example.com, but not example.com.
- **Suffix wildcards (example.*)**: Matches any top-level domain for the prefix. For example, example.* matches example.com, example.org, example.co.uk, etc., but would not match www.example.com (since that has a subdomain) or myexample.com (prefix must exactly be "example").
- **Middle wildcards (api.*.example.com)**: Matches one subdomain component in the middle. For example, api.*.example.com matches api.v1.example.com or api.staging.example.com, but not api.example.com (no segment in the middle) or v1.api.example.com (the "api" is not the first segment in that case).

These wildcard patterns allow flexible domain specification in whitelists.

### IP Address Matching
IP entries can be exact or CIDR ranges:
- An exact IP (e.g., 192.168.1.10) matches only that address.
- A CIDR range (e.g., 192.168.1.0/24) matches any address in that subnet (for /24, it matches 192.168.1.*). Both IPv4 and IPv6 CIDR notations are supported (e.g., 2001:db8::/32 for IPv6).

If the connection's IP falls within the CIDR or matches exactly, it's considered a match for that whitelist entry.

### AS Information Matching
Autonomous System criteria allow whitelisting by who owns the IP/network:
- **AS Number (as_number)**: If specified, the connection's ASN (as identified by EDAMAME's intelligence) must exactly match.
- **AS Country (as_country)**: If specified, the two-letter country code of the connection's ASN registration must match (e.g., "US" for United States).
- **AS Owner (as_owner)**: If specified, the organization name of the ASN must match (case-insensitive contains, typically).

All specified AS sub-criteria in an entry must match for the entry to count as a match on AS info.

### Matching Process in Detail
The overall process to determine if a connection is allowed:
1. **Collect Applicable Whitelist Entries**: Determine which whitelist(s) are in effect (e.g., the whitelist name you provided to background-start-disconnected or by default, the environment's platform whitelist). Gather all endpoints from those whitelists (including inherited entries).
2. **Empty Check**: If the effective whitelist has no endpoints, then no connection can match. In such a case, EDAMAME will treat everything as disallowed (and typically warn that the whitelist is empty).
3. **Iterate Connections vs Endpoints**: For each network connection observed, compare it against each whitelist endpoint entry using the criteria above. If any entry yields a match, the connection is allowed; otherwise it's not.
4. **Result**: If a connection is found that does not match any whitelist entry, get-sessions will consider the whitelist conformance failed and return a non-zero exit code (and indicate which connection was unauthorized in the output).

Pseudocode:
```pseudo
function is_session_allowed(session, whitelist_name):
    endpoints = get_all_endpoints(whitelist_name)
    if endpoints is empty:
        return (false, "Whitelist contains no endpoints")

    for endpoint in endpoints:
        if endpoint_matches(session, endpoint):  // apply rules as above
            return (true, null)  // allowed
    return (false, "No matching endpoint found")
```

### Best Practices for Whitelists
- **Start Specific**: Begin with specific rules where possible (domain and port, rather than broad IP ranges). Use domain names over IPs for services that have stable domains.
- **Use Inheritance**: Factor common allowed endpoints into base whitelists. For example, have a base whitelist for "common developer services" that can be extended by more specific ones per project or pipeline. This avoids duplication and makes maintenance easier.
- **Document Endpoints**: Provide a description for each endpoint entry to clarify why it's allowed. This helps during reviews and audits of your whitelist. Also document the purpose of each custom whitelist (e.g., in the JSON or README).
- **Regular Maintenance**: Update whitelists as services change. Remove endpoints that are no longer needed or have become unsafe. Periodically review inherited chains to ensure they still make sense.
- **Security Considerations**: Favor domain-based rules (they are easier to understand and audit) over raw IPs, unless necessary. Use the process field to lock down especially sensitive connections (e.g., ensure only a specific process can talk to a database). Always apply the principle of least privilege—only allow what is required.

### Building Comprehensive Whitelist Baselines for Supply Chain Attack Detection

The most effective way to use EDAMAME's whitelist system is to build a comprehensive baseline through multiple build iterations, then use it to detect unauthorized network activity that could indicate supply chain attacks.

#### Phase 1: Learning Mode - Build Your Baseline

1. **Start with Clean Builds**: Begin with fresh CI/CD runners to capture only necessary network connections. Generated entries purposely omit the originating process/user metadata so the whitelist remains stable even when runner process names change between jobs:

```bash
# GitHub Actions / CI environment
sudo edamame_posture background-start-disconnected --network-scan --packet-capture --whitelist github_ubuntu

# Your build process here - let it run normally
npm install
npm run build
npm test

# After build completes, create initial whitelist
edamame_posture create-custom-whitelists > baseline_whitelist_v1.json
```

2. **Iterate and Augment**: Run multiple builds with different configurations to capture all legitimate variations:

```bash
# Build 2: Different environment or test suite
sudo edamame_posture set-custom-whitelists-from-file baseline_whitelist_v1.json
# ... run build ...

# Augment with any new legitimate connections discovered
edamame_posture augment-custom-whitelists > additional_endpoints_v2.json
edamame_posture merge-custom-whitelists-from-files baseline_whitelist_v1.json additional_endpoints_v2.json > baseline_whitelist_v2.json
```

3. **Comprehensive Coverage**: Repeat for different scenarios:
   - Different dependency versions
   - Different build targets (debug vs release)
   - Different test suites
   - Weekend vs weekday builds (different CDN routing)

```bash
# Build 3: Another scenario
sudo edamame_posture set-custom-whitelists-from-file baseline_whitelist_v2.json
# ... run build ...
edamame_posture augment-custom-whitelists > additional_endpoints_v3.json
edamame_posture merge-custom-whitelists-from-files baseline_whitelist_v2.json additional_endpoints_v3.json > baseline_whitelist_v3.json

# Continue until you have comprehensive coverage
```

#### Phase 2: Production Enforcement - Detect Violations

Once you have a stable baseline (typically after 5-10 diverse build runs), switch to enforcement mode:

```bash
# Apply your finalized baseline
sudo edamame_posture set-custom-whitelists-from-file baseline_whitelist_final.json

# Run your build normally
npm install
npm run build
npm test

# Check for violations - this will exit non-zero if unauthorized connections occurred
edamame_posture get-sessions
```

#### Supply Chain Attack Detection

This approach effectively detects supply chain attacks like CVE-2025-30066 (tj-actions/changed-files compromise):

**Example Attack Detection**:
```bash
# Your baseline includes normal package registry connections:
# - registry.npmjs.org:443
# - github.com:443  
# - your-company-cdn.com:443

# But during a compromised build, you see:
$ edamame_posture get-sessions
# ERROR: Non-conforming connection detected!
# Connection: 10.0.0.100:45678 -> gist.githubusercontent.com:443 (node)
# Reason: No matching endpoint found in whitelist 'custom_whitelist'

# This immediately alerts you to unauthorized data exfiltration
```

#### Automation and CI/CD Integration

**Learning Phase Automation**:
```yaml
# .github/workflows/build-whitelist.yml
- name: Learning Mode Build
  run: |
    sudo edamame_posture background-start-disconnected --network-scan --packet-capture --whitelist github_ubuntu
    npm install && npm run build && npm test
    
- name: Update Baseline Whitelist  
  run: |
    # Download existing baseline
    curl -H "Authorization: token ${{ secrets.GITHUB_TOKEN }}" \
         -o current_baseline.json \
         https://api.github.com/repos/owner/repo/contents/security/baseline_whitelist.json
    
    # Create augmented version
    edamame_posture augment-custom-whitelists > new_endpoints.json
    edamame_posture merge-custom-whitelists-from-files current_baseline.json new_endpoints.json > updated_baseline.json
    
    # Commit back to repository
    # (implementation depends on your preferred method)
```

**Production Enforcement**:
```yaml
# Regular CI/CD workflow
- name: Security Enforcement
  run: |
    sudo edamame_posture background-start-disconnected --network-scan --packet-capture --whitelist github_ubuntu
    sudo edamame_posture set-custom-whitelists-from-file security/baseline_whitelist.json
    
- name: Build Application
  run: |
    npm install
    npm run build
    npm test
    
- name: Verify No Unauthorized Network Activity
  run: |
    # This fails the build if any unauthorized connections occurred
    edamame_posture get-sessions
```

#### Automated Baseline Building with GitHub Actions (Auto-Whitelist Mode)

The EDAMAME Posture GitHub Action includes an **auto-whitelist mode** that fully automates the baseline building process. This feature:

- **First run**: Operates in listen-only mode, capturing all network traffic without enforcement
- **Subsequent runs**: Automatically refines the whitelist by adding newly discovered endpoints
- **Stability detection**: Compares iterations and declares the whitelist stable when changes fall below a threshold
- **Enforcement**: Once stable, automatically enforces the whitelist and fails on violations

**Example GitHub Actions Workflow**:

```yaml
name: Build with Auto-Whitelist

on: [push, pull_request]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Setup EDAMAME with Auto-Whitelist
        uses: edamametechnologies/edamame_posture_action@main
        with:
          disconnected_mode: true
          network_scan: true
          packet_capture: true
          auto_whitelist: true
          auto_whitelist_artifact_name: my-project-whitelist
          # auto_whitelist_stability_threshold: 0  # Default: 0% (no new endpoints)
          # auto_whitelist_max_iterations: 10      # Default: 10 iterations
          dump_sessions_log: true
      
      - name: Build and Test
        run: |
          npm install
          npm run build
          npm test
```

**How it works**:

1. **Run 1** (Listen-Only):
   - Captures all network traffic during your build
   - Creates initial whitelist with all observed endpoints
   - Saves to GitHub artifact: `my-project-whitelist`
   - Does NOT enforce violations (exit code 0)

2. **Run 2-N** (Refinement):
   - Downloads previous whitelist from artifact
   - Applies it before your build starts
   - Captures traffic and discovers any new endpoints
   - Augments whitelist with new discoveries
   - Compares with previous iteration: `compare-custom-whitelists`
   - If difference > 0%: saves updated whitelist, resets stability counter, continues refining
   - If difference = 0%: increments consecutive stable runs counter
   - Declares stable only after N consecutive runs with 0% change (default: 3 runs)

3. **Stable State**:
   - Enforces whitelist with `--fail-on-whitelist`
   - Fails workflow on any unauthorized connections
   - Provides supply chain attack protection

**Configuration Options**:

| Parameter | Description | Default |
|-----------|-------------|---------|
| `auto_whitelist` | Enable auto-whitelist mode | `false` |
| `auto_whitelist_artifact_name` | GitHub artifact name for storing state | `edamame-auto-whitelist` |
| `auto_whitelist_stability_threshold` | Percentage change threshold for stability (0 = no new endpoints) | `0` |
| `auto_whitelist_stability_consecutive_runs` | Number of consecutive runs with 0% change required for stability | `3` |
| `auto_whitelist_max_iterations` | Maximum refinement iterations | `10` |

**Monitoring Progress**:

The action provides clear console output showing the progression to stability:

```
=== Iteration 5 ===
Whitelist difference: 0.00%
✅ Whitelist is STABLE for this run (diff: 0.00% <= threshold: 0%)
   Consecutive stable runs: 1 / 3 required
🔄 Whitelist is stable for this run, but need more consecutive confirmations

=== Iteration 6 ===
Whitelist difference: 0.00%
✅ Whitelist is STABLE for this run (diff: 0.00% <= threshold: 0%)
   Consecutive stable runs: 2 / 3 required
🔄 Whitelist is stable for this run, but need more consecutive confirmations

=== Iteration 7 ===
Whitelist difference: 0.00%
✅ Whitelist is STABLE for this run (diff: 0.00% <= threshold: 0%)
   Consecutive stable runs: 3 / 3 required
🎉 Whitelist is FULLY STABLE (3 consecutive runs with no changes)

✅ Whitelist has stabilized!
   Achieved 3 consecutive runs with no changes.
   Future runs will enforce this whitelist and fail on violations.
```

**Advantages over Manual Baseline Building**:

- **Zero manual intervention**: Fully automated from first run to enforcement
- **Artifact-based storage**: No repository commits needed during learning phase
- **Per-workflow isolation**: Different workflows can have different whitelists
- **Automatic stability detection**: Requires multiple consecutive runs with 0% change for true stability
- **Gradual enforcement**: Only enforces after high confidence is established
- **False positive prevention**: Consecutive runs requirement prevents premature enforcement
- **Deterministic behavior**: Only stable when network patterns are truly consistent

#### Best Practices for Baseline Management

1. **Version Control Your Baselines**: Store whitelist JSON files in your repository under version control
2. **Environment-Specific Baselines**: Maintain separate baselines for different environments (staging vs production)
3. **Regular Updates**: Review and update baselines when you intentionally add new dependencies
4. **Security Review Process**: Require security team approval for baseline changes
5. **Monitoring and Alerting**: Set up alerts for any whitelist violations in production builds
6. **Use Auto-Whitelist for New Projects**: Let automated mode build the initial baseline, then export to version control once stable

### Testing and Validation
To validate your whitelist configurations before enforcing them in production:
1. **Create a Test Whitelist**: Run `edamame_posture create-custom-whitelists > test_whitelist.json` after a typical build to capture all observed endpoints in that environment. Edit this JSON to remove anything that shouldn't be allowed generally.
2. **Apply and Test**: Apply the edited whitelist: `edamame_posture set-custom-whitelists-from-file test_whitelist.json`. Then run a typical workflow (or just get-sessions if the background was running) to see if any connection gets blocked.
3. **Monitor Results**: Review the output of get-sessions and logs:
   - If some expected connections were blocked, adjust the whitelist (add entries or correct patterns).
   - If extraneous endpoints are allowed that shouldn't be, tighten the whitelist (remove or make patterns stricter).
   - Verify that inheritance is working as expected (test scenarios for each extended whitelist if using multiple).

### Troubleshooting
Common issues and their solutions in managing whitelists:
- **Connection Blocked (but should be allowed)**:
  - Check that the protocol and port in the whitelist entry match the actual connection. A mismatch (e.g., whitelisting TCP 443 but the connection was on TCP 80 or UDP) will cause a block.
  - Verify the domain pattern. Perhaps a wildcard didn't match as expected (e.g., forgetting that *.example.com doesn't cover example.com itself).
  - Confirm the process name (if used) is correct. The process initiating the connection might have a different name or there may be multiple processes (ensure you allow all necessary ones).
- **Inheritance Issues**:
  - Make sure any parent whitelist names in extends actually exist and are spelled correctly.
  - Check for circular inheritance (WhA extends WhB, and WhB extends WhA). The system should prevent it, but if you see missing rules, review the chain.
  - If a child whitelist isn't getting parent rules, confirm you loaded the full JSON with all whitelists (the set-custom-whitelists should contain both parent and child in one JSON structure).
- **Pattern Matching Problems**:
  - Test wildcard patterns individually. If a domain isn't matching, try a specific entry without wildcards to see if that works, then refine.
  - Ensure CIDR ranges are correct (e.g., /24 vs /16 depending on needed scope).
  - Check case sensitivity: domain and process matching is case-insensitive, but best practice is to use lowercase in the whitelist to avoid any issues.

### Reference
- **Supported Protocols**: By default, the whitelist supports common protocols (exact list may depend on platform): TCP, UDP, ICMP (Others as configured or as they appear; unknown protocol types will be treated cautiously.)
- **Special Values**:
  - `"*"` (asterisk) – Used as part of domain patterns (as described in wildcards above).
  - `"0.0.0.0/0"` – Represents all IPv4 addresses (be careful with this; essentially no IP restriction).
  - `"::/0"` – Represents all IPv6 addresses.
  
  Using these broad patterns effectively disables filtering on that dimension, so use them sparingly.
- **Environment Variables**:
  - `EDAMAME_WHITELIST_PATH` – If set, points to a custom whitelist JSON file path that the CLI should use instead of the built-in defaults. Useful for pointing the CLI to your own whitelist definitions on startup.
  - `EDAMAME_WHITELIST_LOG_LEVEL` – Controls the verbosity of whitelist-related logging. For example, setting this to DEBUG might cause the CLI to output each connection check and which rule allowed/blocked it, which can help in debugging whitelist issues.

### Embedded Whitelists

EDAMAME includes the following embedded whitelists that are ready to use for different environments and workflows:

#### Base Whitelists

- **`edamame`**: Core whitelist with essential EDAMAME functionality
  - IP-API connections for IP geolocation
  - Mixpanel analytics services
  - IPify service for IP address detection
  - EDAMAME backend services on AWS

#### Development Whitelists

- **`builder`**: Extends `edamame`, designed for development environments
  - NTP time synchronization
  - Package repositories (Dart/Flutter, Ruby)
  - Source code repositories (Chromium)
  - CDN services (Fastly, CloudFront)
  - Cloud platforms (AWS, Google Cloud)
  - DNS services (Google DNS over TLS/HTTPS)

#### GitHub Workflow Whitelists

- **`github`**: Extends `builder`, adds GitHub-specific endpoints
  - GitHub.com and related domains
  - GitHub Actions services
  - GitHub raw content access
  - Microsoft Azure services

##### OS-Specific GitHub Whitelists

- **`github_macos`**: Extends `github`, optimized for macOS GitHub workflows
  - Homebrew package manager
  - Apple services and domains
  - Apple DNS and certificate services
  - Apple push notification services

- **`github_ubuntu`**: Extends `github`, optimized for Linux GitHub workflows
  - Ubuntu repositories
  - Snapcraft services
  - Microsoft Azure cloud mirror

- **`github_windows`**: Extends `github`, template for Windows GitHub workflows
  - Currently empty, ready for Windows-specific endpoints

#### Whitelist Inheritance Example

```
edamame (base)
   ↑
builder (extends edamame)
   ↑
github (extends builder)
   ↑
github_macos/github_ubuntu/github_windows (extends github)
```

To use these embedded whitelists, specify the whitelist name when starting EDAMAME Posture:

```bash
# For a macOS GitHub workflow environment
edamame_posture start --user user --domain example.com --pin 123456 --network-scan --packet-capture --whitelist github_macos --fail-on-whitelist --fail-on-blacklist --cancel-on-violation

# For a basic development environment
edamame_posture start --user user --domain example.com --pin 123456 --network-scan --packet-capture --whitelist builder --fail-on-whitelist --fail-on-blacklist --cancel-on-violation
```

## Blacklist System

### Overview
The EDAMAME blacklist system provides a reliable method to block connections to known malicious IP addresses and ranges. Unlike whitelists which define allowed connections, blacklists specifically identify IPs that should be blocked regardless of other rules.

### Blacklist Structure
Blacklists are defined in a JSON format similar to whitelists but with a focus on IP ranges to block:

```json
{
  "date": "March 29 2025",
  "signature": "signature_string",
  "blacklists": [
    {
      "name": "malicious_ips",
      "description": "Known malicious IP ranges",
      "last_updated": "2025-03-29",
      "source_url": "https://example.com/blacklist-source",
      "ip_ranges": [
        "192.168.0.0/16",
        "10.0.0.0/8"
      ]
    }
  ]
}
```

### IP Matching Algorithm
The blacklist system uses a precise matching algorithm to determine if an IP address is blocked:

1. Parse the IP address being checked
2. For each blacklist being used:
   - Get all IP ranges defined in that blacklist
   - Check if the IP falls within any of those ranges
   - If a match is found, the IP is considered blacklisted

### IPv4 and IPv6 Support
The blacklist system supports both IPv4 and IPv6 addresses and ranges:
- IPv4 addresses (e.g., `192.168.1.1`)
- IPv4 CIDR ranges (e.g., `192.168.0.0/16`)
- IPv6 addresses (e.g., `2001:db8::1`)
- IPv6 CIDR ranges (e.g., `2001:db8::/32`)

### Blacklist Usage Status
Currently, blacklists are implemented in the EDAMAME system but are not yet tied to an enforcement action. Unlike whitelists, which can fail a pipeline when a non-conforming connection is detected, blacklists are currently used for informational and reporting purposes only.

When a connection's IP address matches an entry in a blacklist, EDAMAME adds a `blacklist:<name of the blacklist>` tag to the connection's criticality field. For example, if an IP matches a blacklist named "malicious_ips", the connection's criticality field will include `blacklist:malicious_ips`. This allows you to see blacklist matches in the session output:

```
[2025-03-30T18:53:01.988471+00:00] runner edamame_posture - TCP 192.168.64.23:54495 -> 35.186.241.51:443 (https) ASN15169 / GOOGLE / US (960 bytes sent, 5311 bytes received, duration: ongoing, whitelisted: Conforming, criticality: anomaly:normal,blacklist:malicious_ips)
```

The blacklist tag appears alongside other criticality fields like the anomaly detection classification.

Future versions will add options to exit with non-zero exit codes or block connections when blacklisted IPs are detected, similar to the whitelist enforcement mechanism.

## Network Behavior Anomaly Detection (NBAD)

### Overview
EDAMAME Posture includes a sophisticated Network Behavior Anomaly Detection (NBAD) system that automatically identifies unusual network connections without relying on predefined rules. This machine learning-based approach complements the whitelist and blacklist systems by detecting anomalous traffic patterns that might indicate security threats.

### How NBAD Works
The NBAD system uses an Isolation Forest algorithm, a machine learning technique specifically designed for anomaly detection. It works by:

1. Collecting data about network sessions (without storing sensitive content)
2. Extracting relevant features like process information, ports, traffic volume, etc.
3. Building a model of what "normal" traffic looks like
4. Scoring new connections based on how unusual they appear compared to the baseline

### Session Criticality Classification
Each network connection is assigned a criticality level based on its anomaly score:

- **Normal**: Connections that match typical patterns
- **Suspicious**: Connections that seem somewhat unusual but may be legitimate
- **Abnormal**: Connections that strongly deviate from normal patterns

### Example Output
When viewing session data with `get-sessions`, you'll see criticality information:

```
[2025-03-30T18:52:51.408970+00:00] root edamame_posture - TCP 192.168.64.23:54487 -> 185.199.111.153:443 (https) ASN54113 / FASTLY / US (615 bytes sent, 6273 bytes received, duration: 0s, whitelisted: Conforming, criticality: anomaly:normal)

[2025-03-30T18:53:01.988287+00:00] runner edamame_posture - TCP 192.168.64.23:54494 -> 3.5.72.133:443 (https) ASN16509 / AMAZON-02 / US (276 bytes sent, 0 bytes received, duration: ongoing, whitelisted: Conforming, criticality: anomaly:normal)

[2025-03-30T18:53:01.123500+00:00] root edamame_posture - TCP 192.168.64.23:49165 -> 140.82.114.21:443 (https) ASN36459 / GITHUB / US (29117 bytes sent, 0 bytes received, duration: ongoing, whitelisted: NonConforming: No matching endpoint found in whitelist 'github' for domain: None, ip: Some("140.82.114.21"), port: 443, protocol: TCP, ASN: Some(36459), Country: Some("US"), Owner: Some("GITHUB"), Process: Some("edamame_posture"), criticality: anomaly:normal)
```

### NBAD Status and Integration
Like blacklists, the NBAD system is currently implemented for informational purposes but is not yet tied to enforcement actions (such as failing a pipeline). It provides valuable insights alongside whitelist checks, helping you identify potentially suspicious behavior even within connections that conform to whitelist rules.

Future versions will provide options to establish policies based on anomaly detection results, allowing for automatic action when abnormal traffic is detected.

### Autonomous Learning
The NBAD system automatically adapts to the environment where it runs:

- It learns normal traffic patterns for your specific workflows
- No manual configuration of rules or thresholds is needed
- It becomes more accurate over time as it observes more traffic

## Historical Security Posture Verification
EDAMAME Posture provides powerful capabilities for historical verification of security posture through its signature system. This enables organizations to maintain an audit trail of device security compliance over time.

### Understanding Signatures and Historical Verification
The `check-policy-for-domain-with-signature` command allows for verification of historical security posture by examining a previously generated signature. Unlike real-time policy checks (which assess the current state), this command verifies the security posture that existed at the time the signature was created. Key benefits of the signature system:
- Create an immutable audit record of a device's security posture at a given point (e.g., at commit time, or before a release).
- Offline verification: You can later verify that record against a policy without needing the original device present.
- Pipeline integration: Allows embedding security posture checks into version control or release processes (e.g., a Git hook or CI job that validates the commit was made from a secure device).

### Signature Generation Methods
There are two primary ways to obtain posture signatures representing a device's state:

1. **On-Demand Signature Generation**: Manually generate a signature on the spot using:
```bash
edamame_posture request-signature
```
This will output a signature string (typically a long base64 or hex token). You might store this or use it immediately (for example, in an environment variable or file).

2. **Retrieve Last Background Signature**: If the `edamame_posture start` background process is running (connected to a domain), it may periodically generate signatures (for example, on significant changes or on request). You can fetch the most recent one with:
```bash
edamame_posture get-last-report-signature
```
This returns the last captured signature without generating a new one.

Both methods yield a signature that can later be tested against policies.

### Git Integration Workflow Example
A powerful use case is embedding these security signatures into your Git workflow to ensure code integrity:
1. At commit time, generate and include a signature in the commit message:
```bash
# Generate a security posture signature
SIGNATURE=$(edamame_posture request-signature)

# Include the signature in your commit message
git commit -m "feat: implement new feature

EDAMAME-SIGNATURE: $SIGNATURE"
```
In the above, the commit message now contains a line with `EDAMAME-SIGNATURE: <signature>`. This ties that commit to the security state of the developer's machine at commit time.

2. At code review or before merging/deployment, verify the signature:
Suppose you have the commit hash (or in CI, you're on that commit). You can extract the signature and verify it:
```bash
# Extract signature from the commit message
COMMIT_SIGNATURE=$(git show -s --format=%B <commit-hash> | grep "EDAMAME-SIGNATURE:" | cut -d ' ' -f 2)

# Verify the signature meets the required policy
edamame_posture check-policy-for-domain-with-signature "$COMMIT_SIGNATURE" example.com production_policy
```
The `check-policy-for-domain-with-signature "<SIGNATURE>" <DOMAIN> <POLICY_NAME>` command takes the signature and checks what the posture was (per that signature) against the specified policy (for the given domain, e.g., your company's production policy). This returns 0 if the device that produced the signature was compliant with the policy, or non-zero if not.

This workflow ensures that code was committed from a device that met security requirements at the time of commit.

### CI/CD Implementation Example
You can automate the above verification in CI. For example, a GitHub Actions job could do:

```yaml
jobs:
  verify-security-signature:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0  # fetch full history to get commit messages

      - name: Install EDAMAME Posture
        run: |
          curl -LO https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.85/edamame_posture-0.9.85-x86_64-unknown-linux-gnu
          chmod +x edamame_posture-0.9.85-x86_64-unknown-linux-gnu
          sudo mv edamame_posture-0.9.85-x86_64-unknown-linux-gnu /usr/local/bin/edamame_posture

      - name: Extract and verify signature from last commit
        run: |
          $commit = "${{ github.sha }}"
          # Extract signature from the commit message
          $sig = $(git show -s --format=%B $commit | Select-String "EDAMAME-SIGNATURE:" | ForEach-Object { $_.ToString().Split()[1] })
          if (-not $sig) {
            echo "No EDAMAME security signature found in commit message"
            exit 1
          }
          # Verify the signature against the policy
          edamame_posture check-policy-for-domain-with-signature "$sig" company.com production_policy
```

(The above uses PowerShell syntax in a GitHub Actions step for demonstration, assuming edamame_posture is installed on the runner.) If the commit's signature does not exist or does not meet the policy, the job will exit with error, blocking the merge or deployment.

### Signature Verification in Release Processes
Organizations can implement signature verification at various stages of the SDLC:
- **Pre-Merge Checks**: Require that any commit merged into protected branches (e.g., main) has a valid EDAMAME signature that passes policy. This can be enforced via CI on pull requests.
- **Release Approval**: During a release pipeline, confirm that the code being released was authored on compliant devices. For instance, before deploying to production, verify the signatures of all commits since last release.
- **Continuous Compliance**: Periodically (or continuously) audit historical posture by scanning repository history for EDAMAME signatures and validating them. This provides assurance that over time, all code came from secure environments.

Using these signatures and verification steps provides a comprehensive audit trail of security posture throughout your development and release process.

## Business Rules

To enable business rules functionality as seen in [EDAMAME Threat Models](https://github.com/edamametechnologies/), set the `EDAMAME_BUSINESS_RULES_CMD` environment variable according to your platform:

- **Linux**: Add to `/usr/lib/systemd/system/edamame_posture.service` in the [service] section:
  ```
  Environment=EDAMAME_BUSINESS_RULES_CMD="/path/to/your/script.sh"
  ```

- **Windows**: Set in user environment variables through System Properties > Environment Variables > User variables. Note that the script is expected to be a Powershell script.

- **macOS**: Add to `~/.zshenv` or `~/.bash_profile`:
  ```
  export EDAMAME_BUSINESS_RULES_CMD="/path/to/your/script.sh"
  ```

The app on macOS and Windows or edamame_posture service on Linux need to be restarted in order for the environment variable to be accounted for.

For Linux:
- For systemd to account for the updated service file:
  ```
  systemctl daemon-reload
  ```
- For edamame_posture to account for the environment variable:
  ```
  service edamame_posture restart
  ```

The script specified by `EDAMAME_BUSINESS_RULES_CMD` should:
1. Solely rely on user space operations
2. Return an empty string when all rules are respected
3. Return a non empty message when any of the rules are not respected - it's advised to provide a self explanatory message on the reasons why the rules are not respected. This information will be displayed when computing a score in the app or through edamame_posture.
4. Exit with status code 0 for success, non-zero for errors (this is for internal use only - errors will lead to the threat being handled as "unknown" by EDAMAME).

### Business Rules Visualization and Principles

The CLI and UX (tooltip in remediation pages) display the output of the script execution. This output is purely local and is never communicated to EDAMAME.

There is only one rule because the logic is that companies could abuse this functionality if given too much granularity, which would prevent deployment on any devices. The principle is to position the company's chosen script on each user's workstation. The user will have the responsibility to verify and accept or reject this script. We can imagine assistance for automatically populating the script later.

The script is pure user space and is executed as another check. You can set a policy in the [EDAMAME Hub](https://hub.edamame.tech) that requires this script and sends an email notification if the rule fails.

The user sees the check in the UX and can look at the script output to determine which element of the script generates output and thus causes the check to fail.

Example script:
```bash
#!/bin/bash
check1 || echo "check 1 hasn't passed"
check2 || echo "check 2 hasn't passed"
# ... more checks ...
```

## Requirements
Most EDAMAME Posture commands require administrator or root privileges to run properly. If a command needs elevated privileges and you run it without them, the tool will typically exit with an error prompting for elevation. System requirements:

- **Dependencies**: On Windows, the open-source helper service and packet capture driver (Npcap) might be needed for full functionality (as noted on the EDAMAME download page). On Linux, tcpdump or similar capabilities are bundled in the CLI for network capture (no separate install needed). On macOS, the tool may use built-in system extensions for network capture.
- **Permissions**: The user running EDAMAME Posture should have the rights to perform system changes (install software, change configs) for `remediate` to be fully effective.

### eBPF Process Attribution (Linux)

On Linux, EDAMAME Posture uses eBPF (extended Berkeley Packet Filter) for high-performance Layer 7 process attribution during network capture. This provides accurate mapping of network connections to the processes that initiated them.

**Benefits:**
- **Near-zero overhead** - Runs directly in kernel space
- **Real-time visibility** - Captures process info at connection time
- **Accurate attribution** - Maps connections to PIDs, process names, and paths

**Requirements:**
- Linux kernel 4.18+ (5.x+ recommended)
- BTF (BPF Type Format) support in kernel
- Root privileges or `CAP_SYS_ADMIN` + `CAP_BPF`

**Platform Support:**

| Environment | eBPF Status | Notes |
|-------------|-------------|-------|
| Native Linux (Ubuntu 20.04+) | ✅ Full support | Best performance |
| Native Linux (Alpine 3.18+) | ✅ Full support | musl libc compatible |
| GitHub Actions (ubuntu-latest) | ✅ Full support | Works out of the box |
| Docker containers | ⚠️ Limited | Requires `--privileged` or specific caps |
| macOS / Windows | ❌ Not available | Falls back to netstat-based resolution |

**Automatic Fallback:**

When eBPF is unavailable (non-Linux platforms, containers without privileges, older kernels), EDAMAME Posture automatically falls back to traditional netstat-based process resolution. This ensures network capture and L7 attribution work across all platforms, with eBPF providing enhanced performance where available.

**CI/CD Integration:**

In GitHub Actions, eBPF works automatically on native Ubuntu runners. For container-based jobs, add capabilities:

```yaml
container:
  image: ubuntu:24.04
  options: --cap-add=SYS_ADMIN --cap-add=BPF --cap-add=NET_ADMIN
```

For detailed eBPF documentation including architecture, troubleshooting, and testing, see [flodbadd/EBPF.md](https://github.com/edamametechnologies/flodbadd/blob/main/EBPF.md).

## Error Handling
EDAMAME Posture CLI is designed to provide clear error messages and codes for common issues:

- If you enter an invalid command or subcommand, the CLI will display a usage summary or help message for the relevant section.
- If a required argument is missing for a subcommand, an error will indicate which parameter is needed and show the proper usage syntax.
- In case of runtime errors (e.g., failure to connect to EDAMAME Hub, inability to write to a log or output file, etc.), the tool will return a non-zero exit code and print a descriptive error message to STDERR.
- Remediation actions that fail will indicate the failure (for example, "Failed to enable firewall: <system error>"). The CLI will continue with other actions where possible, and at the end may return an error code indicating partial failure.

Always refer to `edamame_posture.log` (if such a log is generated in your working directory or system log location) for detailed debug information when troubleshooting an error. Many commands have a `-v` or verbose mode that can be enabled for more insights.

## EDAMAME Ecosystem
EDAMAME Posture is part of a broader ecosystem of tools and services provided by EDAMAME Technologies:

- **EDAMAME Core**: The core implementation used by all EDAMAME components (closed source)
- **[EDAMAME Security](https://github.com/edamametechnologies/edamame_security)**: Desktop/mobile security application with full UI and enhanced capabilities (closed source)
- **[EDAMAME Foundation](https://github.com/edamametechnologies/edamame_foundation)**: Foundation library providing security assessment functionality
- **[EDAMAME Posture](https://github.com/edamametechnologies/edamame_posture_cli)**: CLI tool for security posture assessment and remediation
- **[EDAMAME Helper](https://github.com/edamametechnologies/edamame_helper)**: Helper application for executing privileged security checks
- **[EDAMAME CLI](https://github.com/edamametechnologies/edamame_cli)**: Interface to EDAMAME core services
- **[GitHub Action](https://github.com/edamametechnologies/edamame_posture_action)**: CI/CD integration to enforce posture and network controls
- **[GitLab Action](https://gitlab.com/edamametechnologies/edamame_posture_action)**: CI/CD integration to enforce posture and network controls
- **[Threat Models](https://github.com/edamametechnologies/threatmodels)**: Threat model definitions used throughout the system
- **[EDAMAME Hub](https://hub.edamame.tech)**: Web portal for centralized management when using these components in team environments

By using EDAMAME Posture CLI in combination with other ecosystem components, you can scale from individual developer security up to organization-wide endpoint posture management, all while maintaining developer autonomy and privacy.

## Author
EDAMAME Technologies
