# EDAMAME Security (CLI: `edamame_posture`)

> **What?**: Lightweight, developer-friendly security posture assessment and remediation tool—perfect for those who want a straightforward way to secure their development environment.

## Table of Contents

1. [Overview](#overview)
2. [Key Features](#key-features)
3. [Targeted Use Cases](#targeted-use-cases)
4. [How It Works](#how-it-works)
5. [Security Posture Assessment Methods](#security-posture-assessment-methods)
6. [Installation](#installation)
   - [Linux (Debian/Ubuntu)](#linux-debianubuntu)
     - [APT Repository Method (Recommended)](#apt-repository-method-recommended)
     - [Debian Package Installation](#debian-package-installation)
     - [Debian Service Management](#debian-service-management)
     - [Debian Uninstallation](#debian-uninstallation)
     - [Manual Linux Binary Installation](#manual-linux-binary-installation)
   - [macOS](#macos)
     - [macOS Standard Installation](#macos-standard-installation)
     - [macOS CI/CD Installation](#macos-cicd-installation)
   - [Windows](#windows)
     - [Windows Standard Installation](#windows-standard-installation)
     - [Windows CI/CD Installation](#windows-cicd-installation)
7. [Usage](#usage)
   - [Common Commands](#common-commands)
   - [All Available Commands](#all-available-commands)
8. [Requirements](#requirements)
9. [Error Handling](#error-handling)

## Overview

`edamame_posture` is a cross-platform CLI that helps you quickly:
- **Assess** the security posture of your device or environment.
- **Harden** against common misconfigurations at the click of a button.
- **Generate** compliance or audit reports—giving you proof of a hardened setup.

And if your needs grow, you can seamlessly connect it to [EDAMAME Hub](https://hub.edamame.tech) for more advanced conditional access, centralized reporting, and enterprise-level features.

## Key Features

1. **Developer-Friendly CLI**  
   Straightforward commands allow you to quickly get things done with minimal fuss.  
2. **Cross-Platform Support**  
   Runs on macOS, Windows, and a variety of Linux environments.  
3. **Automated Remediation**  
   Resolve many security risks automatically with a single command.  
4. **Network & Egress Tracking**  
   Get clear visibility into local devices and outbound connections.  
5. **Compliance Reporting**  
   Generate tamper-proof reports for audits or personal assurance.  
6. **Optional Hub Integration**  
   Connect to [EDAMAME Hub](https://hub.edamame.tech) when you're ready for shared visibility and policy enforcement.

## Targeted Use Cases

1. **Personal Device Hardening**  
   Quickly validate and remediate workstation security—ensuring it's safe for development work.  
2. **CI/CD Pipeline Security**  
   Insert `edamame_posture` checks to ensure ephemeral runners are properly secured before building or deploying code.  
3. **On-Demand Compliance Demonstrations**  
   Produce signed posture reports when working with clients or partners who require evidence of strong security practices.  
4. **Local Network Insights**  
   Run `lanscan` to see what's on your subnet—no need for bulky network security tools.  

## How It Works

1. **Install**  
   Place the `edamame_posture` binary in your `PATH` (e.g., `/usr/local/bin` for Linux/macOS) and make it executable. 
2. **Run**  
   Use commands like `score` to check posture or `remediate` to fix common issues automatically.
3. **Report**  
   Generate a signed report using `request-signature` and `request-report`
4. **Workflows**  
   Check out the [associated GitHub action](https://github.com/edamametechnologies/edamame_posture_action) to see how to integrate `edamame_posture` directly in your GitHub CI/CD workflows and [associated GitLab workflow](https://gitlab.com/edamametechnologies/edamame_posture_action) to see how to integrate it in your GitLab CI/CD workflows.

## Security Posture Assessment Methods

EDAMAME Posture offers three distinct approaches to ensure a device is compliant:

### 1. Local Policy Check (`check-policy`)

The `check-policy` command allows you to define and enforce security policies directly on your local system:

```bash
edamame_posture check-policy <MINIMUM_SCORE> <THREAT_IDS> [TAG_PREFIXES]
```

**Example:**
```bash
edamame_posture check-policy 2.0 "encrypted disk disabled" "SOC-2"
```

### 2. Domain-Based Policy Check (`check-policy-for-domain`)

The `check-policy-for-domain` command validates the device security posture against a policy defined for specific a domain in the [EDAMAME Hub](https://hub.edamame.tech):

```bash
edamame_posture check-policy-for-domain <DOMAIN> <POLICY_NAME>
```

**Example:**
```bash
edamame_posture check-policy-for-domain example.com standard_policy
```

### 3. Continuous Monitoring with Access Control (`start`)

The `start` command initiates a background process that continuously monitors the device security posture and can enable conditional access controls as defined in the [EDAMAME Hub](https://hub.edamame.tech):

```bash
edamame_posture start <USER> <DOMAIN> <PIN> [DEVICE_ID] [LAN_SCANNING] [WHITELIST_NAME] [LOCAL_TRAFFIC]
```

**Example:**
```bash
edamame_posture start user example.com 123456
```

## Installation

### Linux (Debian/Ubuntu)

#### APT Repository Method (Recommended)

We provide a GPG-signed APT repository for `.deb` packages, ensuring secure and verified installation. Follow these steps:

1. **Import the EDAMAME GPG public key**:
   ```bash
   wget -O - https://edamame.s3.eu-west-1.amazonaws.com/repo/public.key | sudo gpg --dearmor -o /usr/share/keyrings/edamame.gpg
   ```

2. **Add the EDAMAME repository**:
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
   - Allows for remote control of all controls of edamame-posture

#### Debian Package Installation

1. **Download** the Debian package for your platform:

   - **x86_64 (64-bit):** [edamame-posture_0.9.20-1_amd64.deb](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.20/edamame-posture_0.9.20-1_amd64.deb)
   - **i686 (32-bit):** [edamame-posture_0.9.20-1_i386.deb](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.20/edamame-posture_0.9.20-1_i386.deb)
   - **aarch64 (ARM 64-bit):** [edamame-posture_0.9.20-1_arm64.deb](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.20/edamame-posture_0.9.20-1_arm64.deb)
   - **armv7 (ARM 32-bit):** [edamame-posture_0.9.20-1_armhf.deb](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.20/edamame-posture_0.9.20-1_armhf.deb)

2. **Install** the package using either method:
   ```bash
   sudo apt install ./edamame-posture_0.9.20-1_amd64.deb
   # or
   sudo dpkg -i edamame-posture_0.9.20-1_amd64.deb
   ```

3. **Configure** the service by editing the configuration file:
   ```bash
   sudo nano /etc/edamame_posture.conf
   ```

   Set the required values:
   ```yaml
   edamame_user: "your_username"
   edamame_domain: "your.domain.com"
   edamame_pin: "your_pin"
   ```

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

#### Debian Service Management

- **Stopping the Service**:
  ```bash
  sudo systemctl stop edamame_posture.service
  # or using the CLI command:
  sudo edamame_posture stop
  ```

- **Viewing Service Logs**:
  ```bash
  sudo journalctl -u edamame_posture.service
  # or using the CLI command:
  sudo edamame_posture logs
  ```

- **Configure** the edamame_posture service:
  - Through the edamame-security GUI.
  - Through the edamame-posture service configuration file: `/etc/edamame_posture.conf`

#### Debian Uninstallation

- **Remove the package**:
  ```bash
  sudo apt remove edamame-posture
  ```

- **Remove the package along with all configuration files**:
  ```bash
  sudo apt purge edamame-posture
  ```

#### Manual Linux Binary Installation

1. **Download** the Linux binary for your architecture:
   - **x86_64 (64-bit)**: [edamame_posture-0.9.20-x86_64-unknown-linux-gnu](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.20/edamame_posture-0.9.20-x86_64-unknown-linux-gnu)  
   - **i686 (32-bit)**: [edamame_posture-0.9.20-i686-unknown-linux-gnu](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.20/edamame_posture-0.9.20-i686-unknown-linux-gnu)  
   - **aarch64 (ARM 64-bit)**: [edamame_posture-0.9.20-aarch64-unknown-linux-gnu](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.20/edamame_posture-0.9.20-aarch64-unknown-linux-gnu)  
   - **armv7 (ARM 32-bit)**: [edamame_posture-0.9.20-armv7-unknown-linux-gnueabihf](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.20/edamame_posture-0.9.20-armv7-unknown-linux-gnueabihf)
   - **x86_64 (64-bit) for Alpine Linux (musl)**: [edamame_posture-0.9.20-x86_64-unknown-linux-musl](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.20/edamame_posture-0.9.20-x86_64-unknown-linux-musl) 
   - **aarch64 (ARM 64-bit) for Alpine Linux (musl)**: [edamame_posture-0.9.20-aarch64-unknown-linux-musl](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.20/edamame_posture-0.9.20-aarch64-unknown-linux-musl)

2. **Install** by placing the binary in your `PATH` and making it executable:
   ```bash
   sudo mv edamame_posture-* /usr/local/bin/edamame_posture
   sudo chmod +x /usr/local/bin/edamame_posture
   ```

3. **Run** a quick command like `edamame_posture score` to assess your device.

### macOS

#### macOS Installation

1. **Download** the macOS universal binary:
   - [edamame_posture-0.9.20-universal-apple-darwin](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.20/edamame_posture-0.9.20-universal-apple-darwin)  

2. **Install** by placing the binary in your `PATH` and making it executable:
   ```bash
   sudo mv edamame_posture-* /usr/local/bin/edamame_posture
   sudo chmod +x /usr/local/bin/edamame_posture
   ```

3. **Run** a quick command like `edamame_posture score` to assess your device.

#### macOS CI/CD Installation

Proceed with installation as stated above but make sure the binary is located within the home directory of the user used by the runner. 

### Windows

#### Windows Standard Installation

1. **Download** the Windows binary:
   - [edamame_posture-0.9.20-x86_64-pc-windows-msvc.exe](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.20/edamame_posture-0.9.20-x86_64-pc-windows-msvc.exe)

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

#### Windows CI/CD Installation

Proceed with installation as stated above but make sure the binary is located within the home directory of the user used by the runner.

## Usage

### Common Commands

- **Check your security posture**: `edamame_posture score`
- **Scan local network**: `edamame_posture lanscan`
- **Fix security issues**: `edamame_posture remediate`
- **Get system info**: `edamame_posture get-system-info`
- **Monitor network traffic**: `edamame_posture capture`
- **Create whitelist from sessions**: `edamame_posture create-custom-whitelists`
- **Apply custom whitelist**: `edamame_posture set-custom-whitelists <JSON_DATA>`

### All Available Commands

edamame_posture [SUBCOMMAND]

#### logs
Displays logs from the background process.  
(Does **NOT** require admin privileges.)

**Syntax**:  
```
edamame_posture logs
```

#### score
Retrieves score information based on device posture.  
(Requires **admin** privileges.)

**Syntax**:  
```
edamame_posture score
```

#### lanscan
Performs a Local Area Network (LAN) scan to detect devices on the network.  
(Requires **admin** privileges.)

**Syntax**:  
```
edamame_posture lanscan
```

#### wait-for-connection
Waits for a network connection within a specified timeout period.  
(Does **NOT** require admin privileges.)

**Syntax**:  
```
edamame_posture wait-for-connection [TIMEOUT]
```

#### get-sessions
Retrieves connection sessions.  
(Does **NOT** require admin privileges.)

**Syntax**:  
```
edamame_posture get-sessions [ZEEK_FORMAT] [LOCAL_TRAFFIC]
```

#### capture
Captures network traffic for a specified duration and formats it as a log.  
(Requires **admin** privileges.)

**Syntax**:  
```
edamame_posture capture [SECONDS] [WHITELIST_NAME] [ZEEK_FORMAT] [LOCAL_TRAFFIC]
```

**Example Usage**:
```bash
# Capture traffic for 5 minutes (300 seconds)
edamame_posture capture 300
```

#### get-core-info
Fetches core information of the device.  
(Does **NOT** require admin privileges.)

**Syntax**:  
```
edamame_posture get-core-info
```

#### get-device-info
Retrieves detailed device information.  
(Requires **admin** privileges.)

**Syntax**:  
```
edamame_posture get-device-info
```

#### get-system-info
Retrieves system information including OS details and network configuration.  
(Requires **admin** privileges.)

**Syntax**:  
```
edamame_posture get-system-info
```

#### request-pin
Requests a PIN for user authentication.  
(Does **NOT** require admin privileges.)

**Syntax**:  
```
edamame_posture request-pin <USER> <DOMAIN>
```

#### get-core-version
Retrieves the current version of the core.  
(Does **NOT** require admin privileges.)

**Syntax**:  
```
edamame_posture get-core-version
```

#### remediate
Performs remediation actions on the device.  
(Requires **admin** privileges.)

**Syntax**:  
```
edamame_posture remediate [REMEDIATIONS]
```

#### remediate-threat
Remediates a single threat by its threat ID.  
(Requires **admin** privileges.)

**Syntax**:  
```
edamame_posture remediate-threat <THREAT_ID>
```

#### rollback-threat
Rolls back a single threat by its threat ID.  
(Requires **admin** privileges.)

**Syntax**:  
```
edamame_posture rollback-threat <THREAT_ID>
```

#### request-signature
Reports the security posture (anonymously) and returns a signature for later retrieval.  
(Requires **admin** privileges.)

**Syntax**:  
```
edamame_posture request-signature
```

#### request-report
Sends a report, based on a previously retrieved signature, to a specified email address.  
(Does **NOT** require admin privileges.)

**Syntax**:  
```
edamame_posture request-report <EMAIL> <SIGNATURE>
```

#### get-threats-info
Fetches information about the threats detected by the background process.  
(Requires **admin** privileges.)

**Syntax**:  
```
edamame_posture get-threats-info
```

#### start
Starts the background process for continuous monitoring and reporting.  
(Requires **admin** privileges.)

**Syntax**:  
```
edamame_posture start <USER> <DOMAIN> <PIN> [DEVICE_ID] [LAN_SCANNING] [WHITELIST_NAME] [LOCAL_TRAFFIC]
```

#### stop
Stops the background reporting process.  
(Does **NOT** require admin privileges.)

**Syntax**:  
```
edamame_posture stop
```

#### status
Displays the current status of the background reporting process.  
(Does **NOT** require admin privileges.)

**Syntax**:  
```
edamame_posture status
```

#### get-last-report-signature
Retrieves the most recent report signature from the background process.  
(Does **NOT** require admin privileges.)

**Syntax**:  
```
edamame_posture get-last-report-signature
```

#### get-history
Retrieves the background process's history of score modifications.  
(Does **NOT** require admin privileges.)

**Syntax**:  
```
edamame_posture get-history
```

#### check-policy-for-domain
Checks if a the actual score meets the specified policy requirements of a domain.  
(Requires **admin** privileges.)

**Syntax**:  
```
edamame_posture check-policy-for-domain <DOMAIN> <POLICY_NAME>
```

#### check-policy-for-domain-with-signature
Checks if the score associated with the signature meets the specified policy requirements of a domain.  
(Does **NOT** require admin privileges.)

**Syntax**:  
```
edamame_posture check-policy-for-domain-with-signature <SIGNATURE> <DOMAIN> <POLICY_NAME>
```

#### check-policy
Checks locally if the current system meets the specified policy requirements.  
(Requires **admin** privileges.)

**Syntax**:  
```
edamame_posture check-policy <MINIMUM_SCORE> <THREAT_IDS> [TAG_PREFIXES]
```

#### get-tag-prefixes
Gets threat model tag prefixes.  
(Does **NOT** require admin privileges.)

**Syntax**:  
```
edamame_posture get-tag-prefixes
```

#### set-custom-whitelists
Sets custom network whitelists from a provided JSON string.  
(Does **NOT** require admin privileges.)  
**Requires** a background process started with `LAN_SCANNING` set to `true`.

**Syntax**:  
```
edamame_posture set-custom-whitelists <WHITELIST_JSON>
```

**Example Usage**:
```bash
# First start background process with LAN_SCANNING enabled
edamame_posture start <USER> <DOMAIN> <PIN> "" true

# Then apply custom whitelists from a file
edamame_posture set-custom-whitelists "$(cat my_whitelist.json)"
```

#### create-custom-whitelists
Creates custom network whitelists from current network sessions and returns the JSON.  
(Does **NOT** require admin privileges.)  
**Requires** a background process started with `LAN_SCANNING` set to `true`.

**Syntax**:  
```
edamame_posture create-custom-whitelists
```

**Example Usage**:
```bash
# First start background process with LAN_SCANNING enabled
edamame_posture start <USER> <DOMAIN> <PIN> "" true

# Then generate a whitelist and save to file
edamame_posture create-custom-whitelists > my_whitelist.json

# Or generate and apply in one step
edamame_posture set-custom-whitelists "$(edamame_posture create-custom-whitelists)"
```

## Whitelist Logic and Format

Whitelists are a powerful feature in EDAMAME that allow you to define which network connections are permitted. Understanding the whitelist logic and format is essential for effective network security management. EDAMAME comes with several [default whitelists](#default-whitelists) that you can use as-is or extend with your own custom rules.

### Typical Whitelist Workflow

The process of creating and using whitelists typically follows these steps:

1. **Initial Run with Background Process**:
   ```bash
   # Start the background process with LAN_SCANNING enabled
   edamame_posture start <USER> <DOMAIN> <PIN> "" true
   ```

2. **Perform Normal Workflow**:
   Run your normal development or CI/CD workflow activities to capture the network connections your process typically needs.

3. **Generate Whitelist at the End**:
   ```bash
   # Create a whitelist from the captured sessions
   edamame_posture create-custom-whitelists > my_workflow_whitelist.json
   ```

4. **Subsequent Runs**:
   In future executions, use the previously generated whitelist:
   ```bash
   # Start background process with LAN scanning enabled
   edamame_posture start <USER> <DOMAIN> <PIN> "" true
   
   # Apply your stored whitelist
   edamame_posture set-custom-whitelists "$(cat my_workflow_whitelist.json)"
   ```

#### Managed vs. Self-hosted Runners

There's an important difference in how whitelists are handled in different environments, especially in CI/CD contexts:

- **Managed Runners** (GitHub Actions, GitLab CI, etc.): 
  - Typically ephemeral environments without persistent storage between runs
  - Store your whitelist JSON in your repository and load it during each run
  - Example for GitHub/GitLab managed runners:
    ```yaml
    # In your CI configuration
    steps:
      - name: Checkout code
        uses: actions/checkout@v3
      
      - name: Set up EDAMAME Posture
        run: |
          # Start background process with LAN scanning enabled
          edamame_posture start $USER $DOMAIN $PIN "" true
          
          # Apply the stored whitelist from your repository
          edamame_posture set-custom-whitelists "$(cat .github/workflows/whitelist.json)"
    ```

- **Self-hosted Runners**:
  - Can store whitelists in persistent paths on the runner
  - Better for teams that need to maintain consistent security posture
  - Example workflow with persistent storage:
    ```bash
    # For initial whitelist creation (run once to establish baseline)
    edamame_posture start $USER $DOMAIN $PIN "" true
    # Run your typical workflow tasks
    # ...
    # Create and store the whitelist
    edamame_posture create-custom-whitelists > /opt/runner/whitelists/build_workflow.json
    
    # For subsequent runs (in your CI configuration)
    edamame_posture start $USER $DOMAIN $PIN "" true
    edamame_posture set-custom-whitelists "$(cat /opt/runner/whitelists/build_workflow.json)"
    # Run your regular workflow tasks
    ```

#### Integration with GitHub Action

If you're using the [EDAMAME Posture GitHub Action](https://github.com/edamametechnologies/edamame_posture_action), you can easily incorporate whitelist creation and usage:

```yaml
# Create and save a custom whitelist
- name: EDAMAME Posture with Custom Whitelist Creation
  uses: edamametechnologies/edamame_posture_action@v0
  with:
    network_scan: true                     # Enable LAN scanning
    create_custom_whitelists: true          # Generate whitelist from traffic
    custom_whitelists_path: ./whitelist.json # Save to this file

# Apply a previously created whitelist in future runs
- name: EDAMAME Posture with Custom Whitelist
  uses: edamametechnologies/edamame_posture_action@v0
  with:
    network_scan: true                     # Enable LAN scanning
    custom_whitelists_path: ./whitelist.json # Load and apply this whitelist
    whitelist_conformance: true            # Fail if non-compliant traffic detected
```

#### Complete CI/CD Workflow Example

For a complete CI/CD integration that includes whitelist management, security posture assessment, and remediation:

```yaml
- name: EDAMAME Posture Setup with Continuous Monitoring
  uses: edamametechnologies/edamame_posture_action@v0
  with:
    edamame_user: ${{ secrets.EDAMAME_USER }}
    edamame_domain: ${{ secrets.EDAMAME_DOMAIN }}
    edamame_pin: ${{ secrets.EDAMAME_PIN }}
    edamame_id: "cicd-runner"
    network_scan: true                     # Enable LAN scanning
    custom_whitelists_path: ./whitelist.json # Path for whitelist
    whitelist_conformance: true            # Enforce whitelist compliance
    auto_remediate: true                   # Fix security issues automatically
```

#### Whitelist Development Lifecycle

A recommended approach for developing and maintaining whitelists is:

1. **Discovery Phase**: Initially run without custom whitelists to observe required traffic patterns
   ```bash
   # Run once to observe normal traffic patterns
   edamame_posture start <USER> <DOMAIN> <PIN> "" true
   # Perform your normal workflow activities
   # Create whitelist from observed traffic
   edamame_posture create-custom-whitelists > baseline_whitelist.json
   ```

2. **Test Phase**: Apply the whitelist in test mode without enforcing compliance
   ```bash
   # Apply whitelist without strict enforcement
   edamame_posture start <USER> <DOMAIN> <PIN> "" true
   edamame_posture set-custom-whitelists "$(cat baseline_whitelist.json)"
   # Run workflow and check logs for any blocked connections
   ```

3. **Production Phase**: Apply the whitelist with strict compliance enforcement
   ```bash
   # For managed runners, store the whitelist in your repository
   # For self-hosted runners, store in a persistent location on the runner
   # Apply with enforcement in production environment
   ```

This approach allows you to create highly tuned whitelists for specific workflows and environments, minimizing the attack surface while ensuring your legitimate network connections continue to function properly.

### Best Practices

1. **Start Specific**: Begin with the most specific rules possible for security.
2. **Test Thoroughly**: Validate your whitelist with `capture` before applying it permanently.
3. **Use Descriptions**: Add clear descriptions to help understand the purpose of each endpoint.
4. **Regular Updates**: Review and update your whitelists as your network usage patterns change.
5. **Leverage Inheritance**: Use the `extends` field to build hierarchical whitelists for better organization.

## Embedded Whitelists

EDAMAME includes the following embedded whitelists that are ready to use for different environments and workflows:

### Base Whitelists

- **`edamame`**: Core whitelist with essential EDAMAME functionality
  - IP-API connections for IP geolocation
  - Mixpanel analytics services
  - IPify service for IP address detection
  - EDAMAME backend services on AWS

### Development Whitelists

- **`builder`**: Extends `edamame`, designed for development environments
  - NTP time synchronization
  - Package repositories (Dart/Flutter, Ruby)
  - Source code repositories (Chromium)
  - CDN services (Fastly, CloudFront)
  - Cloud platforms (AWS, Google Cloud)
  - DNS services (Google DNS over TLS/HTTPS)

### GitHub Workflow Whitelists

- **`github`**: Extends `builder`, adds GitHub-specific endpoints
  - GitHub.com and related domains
  - GitHub Actions services
  - GitHub raw content access
  - Microsoft Azure services

#### OS-Specific GitHub Whitelists

- **`github_macos`**: Extends `github`, optimized for macOS GitHub workflows
  - Homebrew package manager
  - Apple services and domains
  - Apple DNS and certificate services
  - Apple push notification services

- **`github_linux`**: Extends `github`, optimized for Linux GitHub workflows
  - Ubuntu repositories
  - Snapcraft services
  - Microsoft Azure cloud mirror

- **`github_windows`**: Extends `github`, template for Windows GitHub workflows
  - Currently empty, ready for Windows-specific endpoints

### Whitelist Inheritance Example

```
edamame (base)
   ↑
builder (extends edamame)
   ↑
github (extends builder)
   ↑
github_macos/github_linux/github_windows (extends github)
```

To use these embedded whitelists, specify the whitelist name when starting EDAMAME Posture:

```bash
# For a macOS GitHub workflow environment
edamame_posture start user example.com 123456 "" true github_macos

# For a basic development environment
edamame_posture start user example.com 123456 "" true builder
```

## Business rules

To enable business rules functionality as seen in [EDAMAME Threat Models](https://github.com/edamametechnologies/), set the `EDAMAME_BUSINESS_RULES_CMD` environment variable according to your platform:

- **Linux**: Add to `/usr/lib/systemd/system/edamame_posture.service` in the [service] section:
  ```
  Environment=EDAMAME_BUSINESS_RULES_CMD="/path/to/your/script.sh"
  ```

- **Windows**: Set in user environment variables through System Properties > Environment Variables > User variables

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

## Requirements

Most commands require administrator privileges. If a command requires admin privileges and they are not available, the tool will exit with an error message.

## Error Handling

- Invalid arguments or subcommands will prompt usage instructions.
- Missing arguments required for a subcommand will generate an error.

--------------------------------------------------------------------------------

## EDAMAME Ecosystem

EDAMAME Posture is part of the broader EDAMAME security ecosystem:

- **EDAMAME Core**: The core implementation used by all EDAMAME components (closed source)
- **[EDAMAME Security](https://github.com/edamametechnologies)**: Desktop/mobile security application with full UI and enhanced capabilities (closed source)
- **[EDAMAME Foundation](https://github.com/edamametechnologies/edamame_foundation)**: Foundation library providing security assessment functionality
- **[EDAMAME Helper](https://github.com/edamametechnologies/edamame_helper)**: Helper application for executing privileged security checks
- **[EDAMAME CLI](https://github.com/edamametechnologies/edamame_cli)**: Interface to EDAMAME core services
- **[GitHub Integration](https://github.com/edamametechnologies/edamame_posture_action)**: GitHub Action built on this CLI for integrating posture checks in CI/CD
- **[GitLab Integration](https://gitlab.com/edamametechnologies/edamame_posture_action)**: Integration for GitLab CI/CD workflows based on this CLI
- **[Threat Models](https://github.com/edamametechnologies/threatmodels)**: Threat model definitions used by this CLI
- **[EDAMAME Hub](https://hub.edamame.tech)**: Web portal for centralized management when using this CLI in team environments

## Author

EDAMAME Technologies