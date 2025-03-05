# EDAMAME Security (CLI: `edamame_posture`)

> **What?**: Lightweight, developer-friendly security posture assessment and remediation tool—perfect for those who want a straightforward way to secure their development environment.

## Table of Contents

1. [Overview](#overview)
2. [Key Features](#key-features)
3. [Targeted Use Cases](#targeted-use-cases)
4. [How It Works](#how-it-works)
5. [Installation](#installation)
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
6. [Usage](#usage)
   - [Common Commands](#common-commands)
   - [All Available Commands](#all-available-commands)
7. [Requirements](#requirements)
8. [Error Handling](#error-handling)

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

   - **x86_64 (64-bit):** [edamame-posture_0.9.19-1_amd64.deb](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.19/edamame-posture_0.9.19-1_amd64.deb)
   - **i686 (32-bit):** [edamame-posture_0.9.19-1_i386.deb](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.19/edamame-posture_0.9.19-1_i386.deb)
   - **aarch64 (ARM 64-bit):** [edamame-posture_0.9.19-1_arm64.deb](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.19/edamame-posture_0.9.19-1_arm64.deb)
   - **armv7 (ARM 32-bit):** [edamame-posture_0.9.19-1_armhf.deb](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.19/edamame-posture_0.9.19-1_armhf.deb)

2. **Install** the package using either method:
   ```bash
   sudo apt install ./edamame-posture_0.9.19-1_amd64.deb
   # or
   sudo dpkg -i edamame-posture_0.9.19-1_amd64.deb
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
   - **x86_64 (64-bit)**: [edamame_posture-0.9.19-x86_64-unknown-linux-gnu](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.19/edamame_posture-0.9.19-x86_64-unknown-linux-gnu)  
   - **i686 (32-bit)**: [edamame_posture-0.9.19-i686-unknown-linux-gnu](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.19/edamame_posture-0.9.19-i686-unknown-linux-gnu)  
   - **aarch64 (ARM 64-bit)**: [edamame_posture-0.9.19-aarch64-unknown-linux-gnu](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.19/edamame_posture-0.9.19-aarch64-unknown-linux-gnu)  
   - **armv7 (ARM 32-bit)**: [edamame_posture-0.9.19-armv7-unknown-linux-gnueabihf](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.19/edamame_posture-0.9.19-armv7-unknown-linux-gnueabihf)
   - **x86_64 (64-bit) for Alpine Linux (musl)**: [edamame_posture-0.9.19-x86_64-unknown-linux-musl](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.19/edamame_posture-0.9.19-x86_64-unknown-linux-musl) 
   - **aarch64 (ARM 64-bit) for Alpine Linux (musl)**: [edamame_posture-0.9.19-aarch64-unknown-linux-musl](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.19/edamame_posture-0.9.19-aarch64-unknown-linux-musl)

2. **Install** by placing the binary in your `PATH` and making it executable:
   ```bash
   sudo mv edamame_posture-* /usr/local/bin/edamame_posture
   sudo chmod +x /usr/local/bin/edamame_posture
   ```

3. **Run** a quick command like `edamame_posture score` to assess your device.

### macOS

#### macOS Installation

1. **Download** the macOS universal binary:
   - [edamame_posture-0.9.19-universal-apple-darwin](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.19/edamame_posture-0.9.19-universal-apple-darwin)  

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
   - [edamame_posture-0.9.19-x86_64-pc-windows-msvc.exe](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.19/edamame_posture-0.9.19-x86_64-pc-windows-msvc.exe)

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

## Requirements

Most commands require administrator privileges. If a command requires admin privileges and they are not available, the tool will exit with an error message.

## Error Handling

- Invalid arguments or subcommands will prompt usage instructions.
- Missing arguments required for a subcommand will generate an error.

--------------------------------------------------------------------------------

## Author

EDAMAME Technologies