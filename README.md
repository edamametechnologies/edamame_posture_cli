# EDAMAME Security (CLI: `edamame_posture`)

> **What?**: Lightweight, developer-friendly security posture assessment and remediation tool—perfect for those who want a straightforward way to secure their development environment.

## Overview

`edamame_posture` is a cross-platform CLI that helps you quickly:
- **Assess** the security posture of your device or environment.
- **Harden** against common misconfigurations at the click of a button.
- **Generate** compliance or audit reports—giving you proof of a hardened setup.

And if your needs grow, you can seamlessly connect it to [EDAMAME Hub](https://hub.edamame.tech) for more advanced conditional access, centralized reporting, and enterprise-level features.

---

## Targeted Use Cases

1. **Personal Device Hardening**  
   Quickly validate and remediate workstation security—ensuring it's safe for development work.  
2. **CI/CD Pipeline Security**  
   Insert `edamame_posture` checks to ensure ephemeral runners are properly secured before building or deploying code.  
3. **On-Demand Compliance Demonstrations**  
   Produce signed posture reports when working with clients or partners who require evidence of strong security practices.  
4. **Local Network Insights**  
   Run `lanscan` to see what's on your subnet—no need for bulky network security tools.  

---

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

---

## How It Works

1. **Install**  
   Place the `edamame_posture` binary in your `PATH` (e.g., `/usr/local/bin` for Linux/macOS).  
2. **Run**  
   Use commands like `score` to check posture or `remediate` to fix common issues automatically.
3. **Report**  
   Generate a signed report using `request-signature` and `request-report`
4. **Workflows**  
Check out the [associated GitHub action](https://github.com/edamametechnologies/edamame_posture_action) to see how to integrate `edamame_posture` directly in your GitHub CI/CD workflows and [associated GitLab workflow](https://gitlab.com/edamametechnologies/edamame_posture_action) to see how to integrate it in your GitLab CI/CD workflows.

---

## Quick Start

1. **Download** the official binary for your platform (links below).  
2. **Install** by placing the binary in your `PATH`.  
3. **Run** a quick command like `edamame_posture score` to assess your device.

---

## Installation

### Recommended Method: Using the Official GPG-Signed APT Repository

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

### Configuration

**Configure** the edamame_posture service:
   - Through the edamame-security GUI.
   - Through the edamame-posture service configuration file: `/etc/edamame_posture.conf` and edamame_posture commands as seen below.

### Binary Installation

1. **Download** the official binary for your platform (links below).  

- **Gnu Linux x86_64**: [edamame_posture-0.9.18-x86_64-unknown-linux-gnu](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.18/edamame_posture-0.9.18-x86_64-unknown-linux-gnu)  
- **Gnu Linux i686**: [edamame_posture-0.9.18-i686-unknown-linux-gnu](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.18/edamame_posture-0.9.18-i686-unknown-linux-gnu)  
- **Gnu Linux aarch64**: [edamame_posture-0.9.18-aarch64-unknown-linux-gnu](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.18/edamame_posture-0.9.18-aarch64-unknown-linux-gnu)  
- **Gnu Linux armv7**: [edamame_posture-0.9.18-armv7-unknown-linux-gnueabihf](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.18/edamame_posture-0.9.18-armv7-unknown-linux-gnueabihf)  
- **Alpine Linux x86_64**: [edamame_posture-0.9.18-x86_64-unknown-linux-musl](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.18/edamame_posture-0.9.18-x86_64-unknown-linux-musl)  
- **Alpine Linux aarch64**: [edamame_posture-0.9.18-aarch64-unknown-linux-musl](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.18/edamame_posture-0.9.18-aarch64-unknown-linux-musl)  
- **macOS universal (signed)**: [edamame_posture-0.9.18-universal-apple-darwin](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.18/edamame_posture-0.9.18-universal-apple-darwin)  
- **Windows x86_64 (signed)**: [edamame_posture-0.9.18-x86_64-pc-windows-msvc.exe](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.18/edamame_posture-0.9.18-x86_64-pc-windows-msvc.exe)

2. **Install** by placing the binary in your `PATH`.  
3. **Run** a quick command like `edamame_posture score` to assess your device.


### Debian Package Installation

1. **Download** the Debian package for your platform (links below).  

- **Gnu Linux x86_64:** [edamame-posture_0.9.17-1_amd64.deb](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.18/edamame-posture_0.9.17-1_amd64.deb)
- **Gnu Linux i686 (32-bit):** [edamame-posture_0.9.17-1_i386.deb](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.18/edamame-posture_0.9.17-1_i386.deb)
- **Gnu Linux aarch64:** [edamame-posture_0.9.17-1_arm64.deb](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.18/edamame-posture_0.9.17-1_arm64.deb)
- **Gnu Linux armv7:** [edamame-posture_0.9.17-1_armhf.deb](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.18/edamame-posture_0.9.17-1_armhf.deb)


1. **Install** the package using either method:

   ```bash
   sudo apt install ./edamame-posture_0.9.17-1_amd64.deb
   # or
   sudo dpkg -i edamame-posture_0.9.17-1_amd64.deb
   ```

2. **Configure** the service by editing the configuration file:

   ```bash
   sudo nano /etc/edamame_posture.conf
   ```

   Set the required values:

   ```yaml
   edamame_user: "your_username"
   edamame_domain: "your.domain.com"
   edamame_pin: "your_pin"
   ```

3. **Start** the service:

   ```bash
   sudo systemctl start edamame_posture.service
   # or if you installed the deb package, the service has been automatically started and you need to restart it so that it picks up the new configuration:
   sudo systemctl restart edamame_posture.service
   ```

4. **Verify** the service status:

   ```bash
   sudo systemctl status edamame_posture.service
   ```

---

## Service Management

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

---

## Uninstallation

- **Remove the package**:

  ```bash
  sudo apt remove edamame-posture
  ```

- **Remove the package along with all configuration files**:

  ```bash
  sudo apt purge edamame-posture
  ```

---

## Usage

edamame_posture [SUBCOMMAND]

--------------------------------------------------------------------------------

## Subcommands

### logs
Displays logs from the background process.  
(Does **NOT** require admin privileges.)

**Syntax**:  
```
edamame_posture logs
```

---

### score
Retrieves score information based on device posture.  
(Requires **admin** privileges.)

**Syntax**:  
```
edamame_posture score
```

---

### lanscan
Performs a Local Area Network (LAN) scan to detect devices on the network.  
(Requires **admin** privileges.)

**Syntax**:  
```
edamame_posture lanscan
```

---

### wait-for-connection
Waits for a network connection within a specified timeout period.  
(Does **NOT** require admin privileges.)

**Syntax**:  
```
edamame_posture wait-for-connection [TIMEOUT]
```

- **TIMEOUT**: Timeout in seconds (optional, defaults to 600 seconds if not provided)

---

### get-sessions
Retrieves connection sessions.  
(Does **NOT** require admin privileges.)

**Syntax**:  
```
edamame_posture get-sessions [ZEEK_FORMAT] [LOCAL_TRAFFIC]
```

- **ZEEK_FORMAT**: Format the output as Zeek log (optional, defaults to false if not provided)  
- **LOCAL_TRAFFIC**: Include local traffic (optional, defaults to false if not provided)

---

### capture
Captures network traffic for a specified duration and formats it as a log.  
(Requires **admin** privileges.)

**Syntax**:  
```
edamame_posture capture [SECONDS] [WHITELIST_NAME] [ZEEK_FORMAT] [LOCAL_TRAFFIC]
```

- **SECONDS**: Duration in seconds (optional, defaults to 600 seconds if not provided)  
- **WHITELIST_NAME**: Name of the whitelist to use (optional)  
- **ZEEK_FORMAT**: Format the output as Zeek log (optional, defaults to false if not provided)  
- **LOCAL_TRAFFIC**: Include local traffic (optional, defaults to false if not provided)

---

### get-core-info
Fetches core information of the device.  
(Does **NOT** require admin privileges.)

**Syntax**:  
```
edamame_posture get-core-info
```

---

### get-device-info
Retrieves detailed device information.  
(Requires **admin** privileges.)

**Syntax**:  
```
edamame_posture get-device-info
```

---

### get-system-info
Retrieves system information including OS details and network configuration.  
(Requires **admin** privileges.)

**Syntax**:  
```
edamame_posture get-system-info
```

---

### request-pin
Requests a PIN for user authentication.  
(Does **NOT** require admin privileges.)

**Syntax**:  
```
edamame_posture request-pin <USER> <DOMAIN>
```

- **USER**: User name (required)  
- **DOMAIN**: Domain name (required, must be a valid FQDN)

---

### get-core-version
Retrieves the current version of the core.  
(Does **NOT** require admin privileges.)

**Syntax**:  
```
edamame_posture get-core-version
```

---

### remediate
Performs remediation actions on the device.  
(Requires **admin** privileges.)

**Syntax**:  
```
edamame_posture remediate [REMEDIATIONS]
```

- **REMEDIATIONS**: Comma-separated list of threat IDs to **skip** (optional)

---

### remediate-threat
Remediates a single threat by its threat ID.  
(Requires **admin** privileges.)

**Syntax**:  
```
edamame_posture remediate-threat <THREAT_ID>
```

- **THREAT_ID**: The ID of the threat to be remediated (required)

---

### rollback-threat
Rolls back a single threat by its threat ID.  
(Requires **admin** privileges.)

**Syntax**:  
```
edamame_posture rollback-threat <THREAT_ID>
```

- **THREAT_ID**: The ID of the threat to be rolled back (required)

---

### request-signature
Reports the security posture (anonymously) and returns a signature for later retrieval.  
(Requires **admin** privileges.)

**Syntax**:  
```
edamame_posture request-signature
```

---

### request-report
Sends a report, based on a previously retrieved signature, to a specified email address.  
(Does **NOT** require admin privileges.)

**Syntax**:  
```
edamame_posture request-report <EMAIL> <SIGNATURE>
```

- **EMAIL**: Email address (required)  
- **SIGNATURE**: A signature string previously obtained (required)

---

### get-threats-info
Fetches information about the threats detected by the background process.  
(Requires **admin** privileges.)

**Syntax**:  
```
edamame_posture get-threats-info
```

---

### start
Starts the background process for continuous monitoring and reporting.  
(Requires **admin** privileges.)

**Syntax**:  
```
edamame_posture start <USER> <DOMAIN> <PIN> [DEVICE_ID] [LAN_SCANNING] [WHITELIST_NAME] [LOCAL_TRAFFIC]
```

- **USER**: User name (required)  
- **DOMAIN**: Domain name (required, must be a valid FQDN)  
- **PIN**: PIN for authentication (required, must contain digits only)  
- **DEVICE_ID**: Device ID suffix (optional, if not empty, it will be used to identify the device in the EDAMAME Hub and will flag it as a CI/CD runner - typically the job or pipeline ID)  
- **LAN_SCANNING**: Enable LAN scanning (optional, defaults to false)  
- **WHITELIST_NAME**: Name of the whitelist to use (optional)  
- **LOCAL_TRAFFIC**: Include local traffic (optional, defaults to false)

---

### stop
Stops the background reporting process.  
(Does **NOT** require admin privileges.)

**Syntax**:  
```
edamame_posture stop
```

---

### status
Displays the current status of the background reporting process.  
(Does **NOT** require admin privileges.)

**Syntax**:  
```
edamame_posture status
```

---

### get-last-report-signature
Retrieves the most recent report signature from the background process.  
(Does **NOT** require admin privileges.)

**Syntax**:  
```
edamame_posture get-last-report-signature
```

---

### get-history
Retrieves the background process's history of score modifications.  
(Does **NOT** require admin privileges.)

**Syntax**:  
```
edamame_posture get-history
```

---

## Requirements

Most commands require administrator privileges. If a command requires admin privileges and they are not available, the tool will exit with an error message.

--------------------------------------------------------------------------------

## Error Handling

- Invalid arguments or subcommands will prompt usage instructions.
- Missing arguments required for a subcommand will generate an error.

--------------------------------------------------------------------------------

## Author

EDAMAME Technologies