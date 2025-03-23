# EDAMAME Security (CLI: `edamame_posture`)

> **What?**: Lightweight, developer-friendly security posture assessment and remediation tool—perfect for those who want a straightforward way to secure their development environment.

## Table of Contents

1. [Overview](#overview)
2. [Key Features](#key-features)
3. [Targeted Use Cases](#targeted-use-cases)
4. [How It Works](#how-it-works)
5. [Security Posture Assessment Methods](#security-posture-assessment-methods)
6. [CI/CD Integration and Workflow Controls](#cicd-integration-and-workflow-controls)
7. [Installation](#installation)
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
8. [Usage](#usage)
   - [Common Commands](#common-commands)
   - [All Available Commands](#all-available-commands)
9. [Exit Codes and CI/CD Pipelines](#exit-codes-and-cicd-pipelines)
10. [Historical Security Posture Verification](#historical-security-posture-verification)
11. [Requirements](#requirements)
12. [Error Handling](#error-handling)

## Overview

`edamame_posture` is a cross-platform CLI that helps you quickly:
- **Assess** the security posture of your device or environment.
- **Harden** against common misconfigurations at the click of a button.
- **Generate** compliance or audit reports—giving you proof of a hardened setup.

And if your needs grow, you can seamlessly connect it to [EDAMAME Hub](https://hub.edamame.tech) for more advanced conditional access, centralized reporting, and enterprise-level features.

### Local Controls Without External Dependencies

One of the key strengths of EDAMAME Posture is that it provides powerful security controls that work entirely locally, without requiring any external connectivity or registration:

- **Local Policy Checks**: Use `check-policy` to enforce security standards based on minimum score thresholds, specific threat detections, and security tag prefixes.
- **CI/CD Pipeline Gates**: The non-zero exit codes returned by these checks allow you to automatically fail pipelines when security requirements aren't met.
- **Disconnected Network Monitoring**: Monitor and enforce network traffic whitelists in air-gapped or restricted environments.

This means you can immediately integrate security controls into your workflows, even before deciding to connect to EDAMAME Hub for more advanced features.

### Security Reporting and Verification

EDAMAME Posture enables powerful reporting use cases:

- **Point-in-Time Signatures**: Generate cryptographically verifiable signatures that capture the security state of a device at a specific moment.
- **Historical Verification**: Using `check-policy-for-domain-with-signature`, verify that code was committed or released from environments that met security requirements.
- **Development Workflow Integration**: Embed signatures in Git commits, pull requests, or release artifacts for security traceability.
- **Continuous Compliance**: Maintain an audit trail of security posture across your development lifecycle.

These capabilities allow you to not only enforce security at build time but also track and verify security posture throughout your entire development process.

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

This command returns a non-zero exit code when the policy is not met, making it suitable for CI/CD pipeline integration.

### 2. Domain-Based Policy Check (`check-policy-for-domain`)

The `check-policy-for-domain` command validates the device security posture against a policy defined for specific a domain in the [EDAMAME Hub](https://hub.edamame.tech):

```bash
edamame_posture check-policy-for-domain <DOMAIN> <POLICY_NAME>
```

**Example:**
```bash
edamame_posture check-policy-for-domain example.com standard_policy
```

This command returns a non-zero exit code when the policy is not met, allowing CI/CD pipelines to halt if security requirements aren't satisfied.

### 3. Continuous Monitoring with Access Control (`start`)

The `start` command initiates a background process that continuously monitors the device security posture and can enable conditional access controls as defined in the [EDAMAME Hub](https://hub.edamame.tech):

```bash
edamame_posture start <USER> <DOMAIN> <PIN> [DEVICE_ID] [LAN_SCANNING] [WHITELIST_NAME] [LOCAL_TRAFFIC]
```

**Example:**
```bash
edamame_posture start user example.com 123456
```

## CI/CD Integration and Workflow Controls

EDAMAME Posture offers multiple levels of security controls for CI/CD environments, allowing for gradual adoption and integration:

### 1. Local-Only Assessment

With `check-policy`, you can define and enforce local security policies without requiring external connectivity or domain registration:

```bash
edamame_posture check-policy 2.0 "encrypted disk disabled,critical vulnerability" "SOC-2"
```

This approach is ideal for:
- Initial CI/CD security integration
- Air-gapped or restricted environments
- Teams wanting full local control over security policies

### 2. Domain-Based Policy Management

Using `check-policy-for-domain`, you can centrally define policies in EDAMAME Hub, but still enforce them locally without continuous connectivity:

```bash
edamame_posture check-policy-for-domain example.com standard_policy
```

This approach provides:
- Centralized policy definition and management
- Consistent policy enforcement across pipelines
- No need for constant connectivity during builds

### 3. Full Access Control Integration

The full integration model uses the background process with continuous monitoring and access control:

```bash
edamame_posture start user example.com 123456 "ci-runner" true github_linux
```

This provides the most comprehensive security controls:
- Real-time monitoring throughout pipeline execution
- Dynamic access controls based on current security posture
- Conformance reporting to EDAMAME Hub

### 4. Disconnected Background Mode

For environments where domain connectivity isn't available or desired, use the disconnected background mode:

```bash
edamame_posture background-start-disconnected [LAN_SCANNING] [WHITELIST_NAME] [LOCAL_TRAFFIC]
```

This enables:
- Network monitoring and whitelist enforcement without external connectivity
- Local-only security controls for sensitive or air-gapped environments
- All the monitoring capabilities without domain registration

### Recommended CI/CD Integration Pattern

For optimal security monitoring in your CI/CD workflows, follow this recommended pattern regardless of platform:

#### 1. Setup at Workflow Beginning

Place EDAMAME Posture setup at the beginning of your workflow, before any build, test, or deployment steps:

```yaml
# GitHub Actions example
- name: Setup EDAMAME Posture
  run: |
    # Download and install EDAMAME Posture
    curl -LO https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.21/edamame_posture-0.9.21-x86_64-unknown-linux-gnu
    chmod +x edamame_posture-0.9.21-x86_64-unknown-linux-gnu
    sudo mv edamame_posture-0.9.21-x86_64-unknown-linux-gnu /usr/local/bin/edamame_posture
    
    # Start with network monitoring in disconnected mode
    sudo edamame_posture background-start-disconnected true github_linux
```

```yaml
# GitLab CI example
setup_security:
  stage: setup
  script:
    - curl -LO https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.21/edamame_posture-0.9.21-x86_64-unknown-linux-gnu
    - chmod +x edamame_posture-0.9.21-x86_64-unknown-linux-gnu
    - sudo mv edamame_posture-0.9.21-x86_64-unknown-linux-gnu /usr/local/bin/edamame_posture
    
    # Start background monitoring
    - sudo edamame_posture background-start-disconnected true github_linux
```

```groovy
// Jenkins Pipeline example
pipeline {
    agent any
    stages {
        stage('Setup Security') {
            steps {
                sh '''
                curl -LO https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.21/edamame_posture-0.9.21-x86_64-unknown-linux-gnu
                chmod +x edamame_posture-0.9.21-x86_64-unknown-linux-gnu
                sudo mv edamame_posture-0.9.21-x86_64-unknown-linux-gnu /usr/local/bin/edamame_posture
                
                sudo edamame_posture background-start-disconnected true github_linux
                '''
            }
        }
        // Other stages...
    }
}
```

#### 2. Initial Posture Assessment and Remediation

Check security posture and optionally remediate issues:

```yaml
# GitHub Actions example
- name: Check and Remediate Security Posture
  run: |
    # Display current security posture
    sudo edamame_posture score
    
    # Optional: Automatically remediate security issues
    sudo edamame_posture remediate
```

```yaml
# GitLab CI example
check_remediate:
  stage: verify
  script:
    - sudo edamame_posture score
    - sudo edamame_posture remediate
```

#### 3. Security Policy Enforcement

Define and enforce security policies to gate your pipeline:

```yaml
# GitHub Actions example
- name: Enforce Security Policy
  run: |
    # Check local policy compliance (exit with error if not compliant)
    sudo edamame_posture check-policy 2.0 "encrypted disk disabled,critical vulnerability" "SOC-2"
    
    # Or check domain-based policy if using EDAMAME Hub
    # sudo edamame_posture check-policy-for-domain example.com standard_policy
```

```yaml
# GitLab CI example
enforce_policy:
  stage: verify
  script:
    - sudo edamame_posture check-policy 2.0 "encrypted disk disabled,critical vulnerability" "SOC-2"
  allow_failure: false  # Fails the pipeline if policy check fails
```

#### 4. Network Activity Monitoring and Whitelist Enforcement

Throughout the workflow, EDAMAME Posture monitors network activity. After your build processes complete, check for whitelist conformance:

```yaml
# GitHub Actions example
- name: Verify Network Conformance
  run: |
    # This will fail the workflow if network traffic violates the whitelist
    edamame_posture get-sessions
```

```yaml
# GitLab CI example
verify_network:
  stage: cleanup
  script:
    - edamame_posture get-sessions  # Exits with non-zero code if whitelist is violated
  allow_failure: false  # Fails the pipeline if network conformance check fails
```

#### 5. Optional: Custom Whitelist Generation and Application

For more tailored network controls:

```yaml
# GitHub Actions example
- name: Generate Custom Whitelist
  run: |
    # Generate whitelist from current sessions
    edamame_posture create-custom-whitelists > ./whitelist.json
    
    # In future runs, apply the custom whitelist
    # edamame_posture set-custom-whitelists "$(cat ./whitelist.json)"
```

```yaml
# GitLab CI example
create_whitelist:
  stage: analyze
  script:
    - edamame_posture create-custom-whitelists > ./whitelist.json
  artifacts:
    paths:
      - whitelist.json
```

### Complete CI/CD Examples

#### GitHub Actions Integration (using edamame_posture_action)

The [edamame_posture_action](https://github.com/edamametechnologies/edamame_posture_action) provides a comprehensive GitHub Actions integration:

```yaml
name: Security Gated Workflow
on: [push, pull_request]

jobs:
  build-and-test:
    runs-on: ubuntu-latest
    steps:
      # Setup at workflow beginning
      - name: Setup EDAMAME Posture
        uses: edamametechnologies/edamame_posture_action@v0
        with:
          network_scan: true
          auto_remediate: true
          edamame_minimum_score: 2.0
          edamame_mandatory_threats: "encrypted disk disabled,critical vulnerability"
          custom_whitelists_path: ./.github/workflows/whitelist.json
          set_custom_whitelists: true
      
      # Your normal workflow steps
      - name: Checkout code
        uses: actions/checkout@v3
      
      - name: Build and test
        run: |
          # Your build and test commands
          npm install
          npm test
      
      # Network conformance check at the end
      - name: Check network conformance
        uses: edamametechnologies/edamame_posture_action@v0
        with:
          dump_sessions_log: true
          whitelist_conformance: true
```

#### Custom GitLab CI Integration

```yaml
stages:
  - setup
  - build
  - test
  - verify
  - deploy

setup_security:
  stage: setup
  script:
    # Download and install EDAMAME Posture
    - curl -LO https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.21/edamame_posture-0.9.21-x86_64-unknown-linux-gnu
    - chmod +x edamame_posture-0.9.21-x86_64-unknown-linux-gnu
    - sudo mv edamame_posture-0.9.21-x86_64-unknown-linux-gnu /usr/local/bin/edamame_posture
    
    # Start background monitoring
    - sudo edamame_posture background-start-disconnected true github_linux
    
    # Check and optionally remediate security posture
    - sudo edamame_posture score
    - sudo edamame_posture remediate
    
    # Check security policy
    - sudo edamame_posture check-policy 2.0 "encrypted disk disabled,critical vulnerability" "SOC-2"

build_job:
  stage: build
  script:
    - echo "Building the application..."
    # Your build commands here

test_job:
  stage: test
  script:
    - echo "Running tests..."
    # Your test commands here

verify_security:
  stage: verify
  script:
    # Network conformance check - fails pipeline if non-compliant
    - edamame_posture get-sessions
  allow_failure: false

deploy_job:
  stage: deploy
  script:
    - echo "Deploying application..."
  only:
    - master
```

#### Jenkins Pipeline Integration

```groovy
pipeline {
    agent any
    
    stages {
        stage('Setup Security') {
            steps {
                sh '''
                curl -LO https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.21/edamame_posture-0.9.21-x86_64-unknown-linux-gnu
                chmod +x edamame_posture-0.9.21-x86_64-unknown-linux-gnu
                sudo mv edamame_posture-0.9.21-x86_64-unknown-linux-gnu /usr/local/bin/edamame_posture
                
                sudo edamame_posture background-start-disconnected true github_linux
                sudo edamame_posture score
                sudo edamame_posture remediate
                sudo edamame_posture check-policy 2.0 "encrypted disk disabled,critical vulnerability" "SOC-2"
                '''
            }
        }
        
        stage('Build') {
            steps {
                sh 'echo "Building the application..."'
                // Your build steps here
            }
        }
        
        stage('Test') {
            steps {
                sh 'echo "Running tests..."'
                // Your test steps here
            }
        }
        
        stage('Verify Security') {
            steps {
                script {
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
                // Your deployment steps here
            }
        }
    }
}
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

   - **x86_64 (64-bit):** [edamame-posture_0.9.21-1_amd64.deb](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.21/edamame-posture_0.9.21-1_amd64.deb)
   - **i686 (32-bit):** [edamame-posture_0.9.21-1_i386.deb](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.21/edamame-posture_0.9.21-1_i386.deb)
   - **aarch64 (ARM 64-bit):** [edamame-posture_0.9.21-1_arm64.deb](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.21/edamame-posture_0.9.21-1_arm64.deb)
   - **armv7 (ARM 32-bit):** [edamame-posture_0.9.21-1_armhf.deb](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.21/edamame-posture_0.9.21-1_armhf.deb)

2. **Install** the package using either method:
   ```bash
   sudo apt install ./edamame-posture_0.9.21-1_amd64.deb
   # or
   sudo dpkg -i edamame-posture_0.9.21-1_amd64.deb
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
   - **x86_64 (64-bit)**: [edamame_posture-0.9.21-x86_64-unknown-linux-gnu](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.21/edamame_posture-0.9.21-x86_64-unknown-linux-gnu)  
   - **i686 (32-bit)**: [edamame_posture-0.9.21-i686-unknown-linux-gnu](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.21/edamame_posture-0.9.21-i686-unknown-linux-gnu)  
   - **aarch64 (ARM 64-bit)**: [edamame_posture-0.9.21-aarch64-unknown-linux-gnu](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.21/edamame_posture-0.9.21-aarch64-unknown-linux-gnu)  
   - **armv7 (ARM 32-bit)**: [edamame_posture-0.9.21-armv7-unknown-linux-gnueabihf](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.21/edamame_posture-0.9.21-armv7-unknown-linux-gnueabihf)
   - **x86_64 (64-bit) for Alpine Linux (musl)**: [edamame_posture-0.9.21-x86_64-unknown-linux-musl](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.21/edamame_posture-0.9.21-x86_64-unknown-linux-musl) 
   - **aarch64 (ARM 64-bit) for Alpine Linux (musl)**: [edamame_posture-0.9.21-aarch64-unknown-linux-musl](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.21/edamame_posture-0.9.21-aarch64-unknown-linux-musl)

2. **Install** by placing the binary in your `PATH` and making it executable:
   ```bash
   sudo mv edamame_posture-* /usr/local/bin/edamame_posture
   sudo chmod +x /usr/local/bin/edamame_posture
   ```

3. **Run** a quick command like `edamame_posture score` to assess your device.

### macOS

#### macOS Installation

1. **Download** the macOS universal binary:
   - [edamame_posture-0.9.21-universal-apple-darwin](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.21/edamame_posture-0.9.21-universal-apple-darwin)  

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
   - [edamame_posture-0.9.21-x86_64-pc-windows-msvc.exe](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.21/edamame_posture-0.9.21-x86_64-pc-windows-msvc.exe)

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

**Exit Codes**:
- **0**: Success - Sessions retrieved successfully
- **1**: Error retrieving sessions or whitelist conformance failure - Sessions were found but failed the whitelist check when a background process with a whitelist is active

This command is particularly useful in CI/CD pipelines to verify network activity conformance to defined whitelists.

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
Checks if the actual score meets the specified policy requirements of a domain.  
(Requires **admin** privileges.)

**Syntax**:  
```
edamame_posture check-policy-for-domain <DOMAIN> <POLICY_NAME>
```

**Exit Codes**:
- **0**: Success - Current posture meets or exceeds the policy requirements
- **!=0**: Failure - Current posture does not meet the policy requirements

This command is designed for CI/CD pipeline integration to enforce security policies.

#### check-policy-for-domain-with-signature
Checks if the score associated with the signature meets the specified policy requirements of a domain.  
(Does **NOT** require admin privileges.)

**Syntax**:  
```
edamame_posture check-policy-for-domain-with-signature <SIGNATURE> <DOMAIN> <POLICY_NAME>
```

**Exit Codes**:
- **0**: Success - Signature posture meets or exceeds the policy requirements
- **!=0**: Failure - Signature posture does not meet the policy requirements

#### check-policy
Checks locally if the current system meets the specified policy requirements.  
(Requires **admin** privileges.)

**Syntax**:  
```
edamame_posture check-policy <MINIMUM_SCORE> <THREAT_IDS> [TAG_PREFIXES]
```

**Exit Codes**:
- **0**: Success - Current posture meets or exceeds the specified policy
- **!=0***: Failure - Current posture does not meet the specified policy

Ideal for CI/CD pipelines where you want to enforce security requirements without requiring domain registration.

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

#### background-start-disconnected
Starts the background process in disconnected mode (without domain authentication).  
(Requires **admin** privileges.)

**Syntax**:  
```
edamame_posture background-start-disconnected [LAN_SCANNING] [WHITELIST_NAME] [LOCAL_TRAFFIC]
```

**Example Usage**:
```bash
# Start background process with LAN scanning and GitHub Linux whitelist
edamame_posture background-start-disconnected true github_linux

# Check if sessions conform to the whitelist
edamame_posture get-sessions
# (returns non-zero exit code if sessions don't conform to whitelist)
```

This command is a shortcut for starting the service without user, domain, and PIN credentials. Both `foreground-start` and `background-start` commands can also be used in disconnected mode by passing empty strings for these parameters:

```bash
# Equivalent to background-start-disconnected true github_linux false
edamame_posture background-start "" "" "" "" true github_linux false

# Similar approach for foreground mode
edamame_posture foreground-start "" "" ""
```

This is useful for CI/CD environments or air-gapped systems where domain connectivity isn't available or desired but you still want the network monitoring and whitelist enforcement capabilities.

## Exit Codes and CI/CD Pipelines

EDAMAME Posture is designed to integrate seamlessly with CI/CD pipelines by using standardized exit codes that can control workflow execution. This allows for security-driven pipeline decisions without complex scripting.

### Key Commands with Exit Codes for CI/CD Integration

| Command | Exit Code 0 | Exit Code 1 | Other Exit Codes |
|---------|-------------|-------------|------------------|
| `get-sessions` | Sessions retrieved successfully | Whitelist conformance failure | 3: No active sessions |
| `check-policy` | Policy requirements met | Policy requirements not met | - |
| `check-policy-for-domain` | Domain policy requirements met | Domain policy requirements not met | - |
| `lanscan` | Network scan completed | Network scan failed | - |
| `capture` | Capture completed | Capture failed or whitelist violation | - |

### CI/CD Integration Example

```yaml
# GitHub Actions example
jobs:
  security-check:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v3
      
      - name: Install EDAMAME Posture
        run: |
          curl -LO https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.21/edamame_posture-0.9.21-x86_64-unknown-linux-gnu
          chmod +x edamame_posture-0.9.21-x86_64-unknown-linux-gnu
          sudo mv edamame_posture-0.9.21-x86_64-unknown-linux-gnu /usr/local/bin/edamame_posture
      
      - name: Start background monitor in disconnected mode
        run: sudo edamame_posture background-start-disconnected true github_linux
      
      - name: Run build steps
        run: |
          # Your normal build steps here
          npm install
          npm test
      
      - name: Verify network conformance
        run: |
          # This will fail the workflow if network traffic violates the whitelist
          edamame_posture get-sessions
      
      - name: Verify security posture
        run: |
          # This will fail the workflow if security requirements aren't met
          sudo edamame_posture check-policy 2.0 "encrypted disk disabled,critical vulnerability" "SOC-2"
```

By leveraging these exit codes, you can create pipelines that automatically enforce security policies and network conformance without additional scripting or custom logic.

## Historical Security Posture Verification

EDAMAME Posture provides powerful capabilities for historical verification of security posture through its signature system. This enables organizations to maintain an audit trail of security compliance over time.

### Understanding Signatures and Historical Verification

The `check-policy-for-domain-with-signature` command allows for verification of historical security posture by examining previously generated signatures. Unlike real-time policy checks, this command verifies the security posture that existed at the time the signature was created.

**Key benefits:**
- Audit historical security posture without needing the original device
- Verify compliance at specific points in time (e.g., at release)
- Embed security verification in software delivery workflows

### Signature Generation Methods

There are two primary ways to obtain signatures that represent security posture:

1. **On-demand signature generation**:
   ```bash
   # Generate a new signature and store it
   edamame_posture request-signature
   ```

2. **Retrieve the last generated signature**:
   ```bash
   # Get the most recent signature from the background process
   edamame_posture get-last-report-signature
   ```

### Git Integration Workflow Example

A powerful use case is embedding security signatures in your Git workflow:

1. **At commit time, generate and include a signature**:
   ```bash
   # Generate a security posture signature
   SIGNATURE=$(edamame_posture request-signature)
   
   # Include the signature in your commit message
   git commit -m "feat: implement new feature 
   
   EDAMAME-SIGNATURE: $SIGNATURE"
   ```

2. **At review/deployment time, verify the signature**:
   ```bash
   # Extract signature from a specific commit
   COMMIT_SIGNATURE=$(git show -s --format=%B <commit-hash> | grep "EDAMAME-SIGNATURE:" | cut -d ' ' -f 2)
   
   # Verify it meets policy requirements
   edamame_posture check-policy-for-domain-with-signature "$COMMIT_SIGNATURE" example.com production_policy
   ```

This workflow ensures that code was committed from a device that met security requirements at the time of commit.

### CI/CD Implementation Example

```yaml
# GitHub Actions example for verifying commit signature
jobs:
  verify-security-signature:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v3
        with:
          fetch-depth: 0  # Fetch all history for examining commits
      
      - name: Install EDAMAME Posture
        run: |
          curl -LO https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.21/edamame_posture-0.9.21-x86_64-unknown-linux-gnu
          chmod +x edamame_posture-0.9.21-x86_64-unknown-linux-gnu
          sudo mv edamame_posture-0.9.21-x86_64-unknown-linux-gnu /usr/local/bin/edamame_posture
      
      - name: Extract and verify signature from last commit
        run: |
          # Extract signature from commit message
          COMMIT_SIGNATURE=$(git show -s --format=%B ${{ github.sha }} | grep "EDAMAME-SIGNATURE:" | cut -d ' ' -f 2)
          
          if [ -z "$COMMIT_SIGNATURE" ]; then
            echo "No EDAMAME security signature found in commit message"
            exit 1
          fi
          
          # Verify the signature meets security policy requirements
          edamame_posture check-policy-for-domain-with-signature "$COMMIT_SIGNATURE" company.com production_policy
```

### Signature Verification in Release Processes

Organizations can implement signature verification at various stages:

1. **Pre-merge checks**: Verify signatures before merging pull requests
2. **Release approval**: Confirm that the code was committed from secure environments 
3. **Continuous compliance**: Maintain historical verification of security posture throughout the software lifecycle

This provides a comprehensive audit trail of security posture throughout your development process.

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

#### `get-sessions`

- **0**: Success - Sessions retrieved successfully
- **1**: Error retrieving sessions or whitelist conformance failure - Sessions were found but failed the whitelist check when a whitelist is set
- **3**: No active network sessions found

#### `check-policy`