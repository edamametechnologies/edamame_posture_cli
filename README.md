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
Check out the [associated GitHub action](https://github.com/edamametechnologies/edamame_posture_action) to see how to integrate `edamame_posture` directly in your GitHub CI/CD workflows and [associated GitLab workflow](https://github.com/edamametechnologies/edamame_posture_action_gitlab) to see how to integrate it in your GitLab CI/CD workflows.

---

## Quick Start

1. **Download** the official binary for your platform (links below).  
2. **Install** by placing the binary in your `PATH`.  
3. **Run** a quick command like `edamame_posture score` to assess your device.

---

## Installation

### Binary Installation

1. **Download** the official binary for your platform (links below).  

- **Gnu Linux x86_64**: [edamame_posture-0.9.5-x86_64-unknown-linux-gnu](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.5/edamame_posture-0.9.5-x86_64-unknown-linux-gnu)  
- **Gnu Linux i686**: [edamame_posture-0.9.5-i686-unknown-linux-gnu](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.5/edamame_posture-0.9.5-i686-unknown-linux-gnu)  
- **Gnu Linux aarch64**: [edamame_posture-0.9.5-aarch64-unknown-linux-gnu](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.5/edamame_posture-0.9.5-aarch64-unknown-linux-gnu)  
- **Gnu Linux armv7**: [edamame_posture-0.9.5-armv7-unknown-linux-gnueabihf](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.5/edamame_posture-0.9.5-armv7-unknown-linux-gnueabihf)  
- **Alpine Linux x86_64**: [edamame_posture-0.9.5-x86_64-unknown-linux-musl](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.5/edamame_posture-0.9.5-x86_64-unknown-linux-musl)  
- **Alpine Linux aarch64**: [edamame_posture-0.9.5-aarch64-unknown-linux-musl](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.5/edamame_posture-0.9.5-aarch64-unknown-linux-musl)  
- **macOS universal (signed)**: [edamame_posture-0.9.5-universal-apple-darwin](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.5/edamame_posture-0.9.5-universal-apple-darwin)  
- **Windows x86_64 (signed)**: [edamame_posture-0.9.5-x86_64-pc-windows-msvc.exe](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.5/edamame_posture-0.9.5-x86_64-pc-windows-msvc.exe)

2. **Install** by placing the binary in your `PATH`.  
3. **Run** a quick command like `edamame_posture score` to assess your device.


### Debian Package Installation

1. **Download** the Debian package for your platform (links below).  

- **Gnu Linux x86_64:** [edamame_posture_0.9.13-1_amd64.deb](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.13/edamame_posture_0.9.13-1_amd64.deb)
- **Gnu Linux i686 (32-bit):** [edamame_posture_0.9.13-1_i386.deb](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.13/edamame_posture_0.9.13-1_i386.deb)
- **Gnu Linux aarch64:** [edamame_posture_0.9.13-1_arm64.deb](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.13/edamame_posture_0.9.13-1_arm64.deb)
- **Gnu Linux armv7:** [edamame_posture_0.9.13-1_armhf.deb](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.13/edamame_posture_0.9.13-1_armhf.deb)


1. **Install** the package using either method:

   ```bash
   sudo apt install ./edamame_posture_0.9.13_amd64.deb
   # or
   sudo dpkg -i edamame_posture_0.9.13_amd64.deb
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
  sudo apt remove edamame_posture
  ```

- **Remove the package along with all configuration files**:

  ```bash
  sudo apt purge edamame_posture
  ```

---

## Usage

edamame_posture [SUBCOMMAND]

--------------------------------------------------------------------------------

## Subcommands

### logs
Displays logs from the background process.
(Does NOT require admin privileges.)

Syntax:
edamame_posture logs

--------------------------------------------------------------------------------

### score
Retrieves score information based on device posture.
(Requires admin privileges.)

Syntax:
edamame_posture score

--------------------------------------------------------------------------------

### lanscan
Performs a Local Area Network (LAN) scan to detect devices on the network.
(Requires admin privileges.)

Syntax:
edamame_posture lanscan

--------------------------------------------------------------------------------

### wait-for-connection
Waits for a network connection within a specified timeout period.
(Does NOT require admin privileges.)

Syntax:
edamame_posture wait-for-connection [TIMEOUT]

• TIMEOUT: Timeout in seconds (optional, defaults to 600 seconds if not provided)

--------------------------------------------------------------------------------

### get-sessions
Retrieves connection sessions.
(Does NOT require admin privileges.)

Syntax:
edamame_posture get-sessions [ZEEK_FORMAT] [LOCAL_TRAFFIC]

• ZEEK_FORMAT: Format the output as Zeek log (optional, defaults to false if not provided)
• LOCAL_TRAFFIC: Include local traffic (optional, defaults to false if not provided)

--------------------------------------------------------------------------------

### capture
Captures network traffic for a specified duration and formats it as a log.
(Requires admin privileges.)

Syntax:
edamame_posture capture [SECONDS] [WHITELIST_NAME] [ZEEK_FORMAT] [LOCAL_TRAFFIC]

• SECONDS: Duration in seconds (optional, defaults to 600 seconds if not provided)
• WHITELIST_NAME: Name of the whitelist to use (optional)
• ZEEK_FORMAT: Format the output as Zeek log (optional, defaults to false if not provided)
• LOCAL_TRAFFIC: Include local traffic (optional, defaults to false if not provided)

--------------------------------------------------------------------------------

### get-core-info
Fetches core information of the device.
(Does NOT require admin privileges.)

Syntax:
edamame_posture get-core-info

--------------------------------------------------------------------------------

### get-device-info
Retrieves detailed device information.
(Requires admin privileges.)

Syntax:
edamame_posture get-device-info

--------------------------------------------------------------------------------

### get-system-info
Retrieves system information including OS details and network configuration.
(Requires admin privileges.)

Syntax:
edamame_posture get-system-info

--------------------------------------------------------------------------------

### request-pin
Requests a PIN for user authentication.
(Does NOT require admin privileges.)

Syntax:
edamame_posture request-pin <USER> <DOMAIN>

• USER: User name
• DOMAIN: Domain name (must be a valid FQDN)

--------------------------------------------------------------------------------

### get-core-version
Retrieves the current version of the core.
(Does NOT require admin privileges.)

Syntax:
edamame_posture get-core-version

--------------------------------------------------------------------------------

### remediate
Performs threat remediation actions on the device.
(Requires admin privileges.)

Syntax:
edamame_posture remediate [REMEDIATIONS]

• REMEDIATIONS: Comma-separated list of remediations to skip (optional)

--------------------------------------------------------------------------------

### request-signature
Reports the security posture (anonymously) and returns a signature for later retrieval.
(Requires admin privileges.)

Syntax:
edamame_posture request-signature

--------------------------------------------------------------------------------

### request-report
Sends a report, based on a previously retrieved signature, to a specified email address.
(Does NOT require admin privileges.)

Syntax:
edamame_posture request-report <EMAIL> <SIGNATURE>

• EMAIL: Email address (required)
• SIGNATURE: A signature string previously obtained (required)

--------------------------------------------------------------------------------

### get-threats-info
Fetches information about the threats detected by the background process.
(Requires admin privileges.)

Syntax:
edamame_posture get-threats-info

--------------------------------------------------------------------------------

### start
Starts the background process for continuous monitoring and reporting.
(Requires admin privileges.)

Syntax:
edamame_posture start <USER> <DOMAIN> <PIN> [DEVICE_ID] [LAN_SCANNING] [WHITELIST_NAME] [LOCAL_TRAFFIC]

• USER: User name (required)
• DOMAIN: Domain name (must be a valid FQDN)
• PIN: PIN for authentication (must contain digits only)
• DEVICE_ID: Device ID suffix (optional, if non empty, it will be used to identify the device in the EDAMAME Hub and will flag it as a CI/CD runner - typically the job or pipeline ID)
• LAN_SCANNING: Enable LAN scanning (optional, defaults to false)
• WHITELIST_NAME: Name of the whitelist to use (optional)
• LOCAL_TRAFFIC: Include local traffic (optional, defaults to false)

--------------------------------------------------------------------------------

### stop
Stops the background reporting process.
(Does NOT require admin privileges.)

Syntax:
edamame_posture stop

--------------------------------------------------------------------------------

### status
Displays the current status of the background reporting process.
(Does NOT require admin privileges.)

Syntax:
edamame_posture status

--------------------------------------------------------------------------------

### get-last-report-signature
Retrieves the most recent report signature from the background process.
(Does NOT require admin privileges.)

Syntax:
edamame_posture get-last-report-signature

--------------------------------------------------------------------------------

## Requirements

Most commands require administrator privileges. If a command requires admin privileges and they are not available, the tool will exit with an error message.

--------------------------------------------------------------------------------

## Error Handling

• Invalid arguments or subcommands will prompt usage instructions.
• Missing arguments required for a subcommand will generate an error.

--------------------------------------------------------------------------------

## Author

Frank Lyonnet