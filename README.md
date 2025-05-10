# EDAMAME Posture: Free CI/CD CLI

## What is it?
EDAMAME Posture is a lightweight, developer-friendly security posture assessment and remediation tool—perfect for those who want a straightforward way to secure their development environment and CI/CD pipelines without slowing down development.

## Table of Contents
- [What is it?](#what-is-it)
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
- [Error Handling](#error-handling)
- [EDAMAME Ecosystem](#edamame-ecosystem)
- [Author](#author)

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
- **Local Network Insights**: Run lanscan to see what's on your subnet—no need for bulky network security tools.

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
edamame_posture start <USER> <DOMAIN> <PIN> [DEVICE_ID] [LAN_SCANNING] [WHITELIST_NAME] [LOCAL_TRAFFIC]
```

Example:
```
edamame_posture start user example.com 123456
```

This mode runs persistently (until stopped) and enforces policies in real-time, providing active protection of the environment.

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
edamame_posture start <USER> <DOMAIN> <PIN> "<DEVICE_ID>" true <WHITELIST_NAME>
```

(In practice, `<DEVICE_ID>`, LAN_SCANNING (true/false), and `<WHITELIST_NAME>` may be provided as needed for your setup.) This provides the most comprehensive CI/CD security controls:
- Real-time posture monitoring throughout the pipeline execution
- Dynamic access controls (e.g., block secrets/code access) based on current security posture
- Continuous conformance reporting to EDAMAME Hub (if connected)

### 4. Disconnected Background Mode
For environments where connecting to a domain or central service isn't possible or desired, you can run the background monitor in disconnected mode:

```
edamame_posture background-start-disconnected [LAN_SCANNING] [WHITELIST_NAME] [LOCAL_TRAFFIC]
```

This enables all the monitoring and whitelist enforcement capabilities locally without requiring a registered domain:
- Fully local, real-time monitoring and network traffic capture
- Whitelist enforcement without any external connectivity
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
    # Download and install EDAMAME Posture (Linux example)
    curl -LO https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.34/edamame_posture-0.9.34-x86_64-unknown-linux-gnu
    chmod +x edamame_posture-0.9.34-x86_64-unknown-linux-gnu
    sudo mv edamame_posture-0.9.34-x86_64-unknown-linux-gnu /usr/local/bin/edamame_posture

    # Start background monitoring in disconnected mode (with LAN scanning enabled)
    sudo edamame_posture background-start-disconnected true github_linux
```

Example (GitLab CI):
```yaml
setup_security:
  stage: setup
  script:
    - curl -LO https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.34/edamame_posture-0.9.34-x86_64-unknown-linux-gnu
    - chmod +x edamame_posture-0.9.34-x86_64-unknown-linux-gnu
    - sudo mv edamame_posture-0.9.34-x86_64-unknown-linux-gnu /usr/local/bin/edamame_posture
    - sudo edamame_posture background-start-disconnected true github_linux
```

Important: In the above examples, the `true` parameter for background-start-disconnected enables LAN scanning. This is required for full network traffic capture and whitelist enforcement. Omitting this (or using false) will limit network monitoring capabilities.

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
# Also fail if any blacklisted connections are detected (default behavior)
edamame_posture get-sessions

# To also check for anomalous connections (using machine learning detection)
edamame_posture get-sessions false false true true true

# To explicitly check only for blacklisted connections but not anomalous ones
edamame_posture get-sessions false false true true false

# To check only whitelist conformance and disable both anomalous and blacklisted checks
edamame_posture get-sessions false false true false false
```

Example (GitHub Actions):
```yaml
- name: Verify Network Conformance
  run: |
    # Fail the workflow if any network traffic violated the whitelist
    # or if any blacklisted connections are detected
    edamame_posture get-sessions
    
    # Optionally check for anomalous connections too
    # edamame_posture get-sessions false false true true true
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
                # Download and install EDAMAME Posture (Linux Jenkins agent example)
                curl -LO https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.34/edamame_posture-0.9.34-x86_64-unknown-linux-gnu
                chmod +x edamame_posture-0.9.34-x86_64-unknown-linux-gnu
                sudo mv edamame_posture-0.9.34-x86_64-unknown-linux-gnu /usr/local/bin/edamame_posture

                # Start background monitoring (disconnected mode with LAN scanning)
                sudo edamame_posture background-start-disconnected true github_linux

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

### Linux (Debian/Ubuntu)

#### APT Repository Method (Recommended)
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
   - Allows for remote control of all controls of edamame-posture

#### Debian Package Installation
If you prefer not to add a repository, you can install the Debian package manually:

1. **Download** the Debian package for your platform:
   - **x86_64 (64-bit):** [edamame-posture_0.9.34-1_amd64.deb](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.34/edamame-posture_0.9.34-1_amd64.deb)
   - **i686 (32-bit):** [edamame-posture_0.9.34-1_i386.deb](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.34/edamame-posture_0.9.34-1_i386.deb)
   - **aarch64 (ARM 64-bit):** [edamame-posture_0.9.34-1_arm64.deb](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.34/edamame-posture_0.9.34-1_arm64.deb)
   - **armv7 (ARM 32-bit):** [edamame-posture_0.9.34-1_armhf.deb](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.34/edamame-posture_0.9.34-1_armhf.deb)

   > **Note**: These Debian packages have been tested on Linux Mint 20 and newer, and Ubuntu 20.04 and newer.

2. **Install** the package using either method:
   ```bash
   sudo apt install ./edamame-posture_0.9.34-1_amd64.deb
   # or
   sudo dpkg -i edamame-posture_0.9.34-1_amd64.deb
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

#### Manual Linux Binary Installation
For other Linux distributions or portable installation:

1. **Download Binary**: From the Releases page, download the binary for your architecture:
   - **x86_64 (64-bit)**: [edamame_posture-0.9.34-x86_64-unknown-linux-gnu](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.34/edamame_posture-0.9.34-x86_64-unknown-linux-gnu)  
   - **i686 (32-bit)**: [edamame_posture-0.9.34-i686-unknown-linux-gnu](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.34/edamame_posture-0.9.34-i686-unknown-linux-gnu)  
   - **aarch64 (ARM 64-bit)**: [edamame_posture-0.9.34-aarch64-unknown-linux-gnu](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.34/edamame_posture-0.9.34-aarch64-unknown-linux-gnu)  
   - **armv7 (ARM 32-bit)**: [edamame_posture-0.9.34-armv7-unknown-linux-gnueabihf](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.34/edamame_posture-0.9.34-armv7-unknown-linux-gnueabihf)
   - **x86_64 (64-bit) for Alpine Linux (musl)**: [edamame_posture-0.9.34-x86_64-unknown-linux-musl](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.34/edamame_posture-0.9.34-x86_64-unknown-linux-musl) 
   - **aarch64 (ARM 64-bit) for Alpine Linux (musl)**: [edamame_posture-0.9.34-aarch64-unknown-linux-musl](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.34/edamame_posture-0.9.34-aarch64-unknown-linux-musl)

2. **Install Binary**: Extract if needed and place the edamame_posture binary into a directory in your PATH (such as `/usr/local/bin`). For example:
```bash
chmod +x edamame_posture-0.9.34-x86_64-unknown-linux-gnu  
sudo mv edamame_posture-0.9.34-x86_64-unknown-linux-gnu /usr/local/bin/edamame_posture
```

### macOS

#### macOS Standard Installation
For a developer workstation on macOS:

1. **Download** the macOS universal binary:
   - [edamame_posture-0.9.34-universal-apple-darwin](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.34/edamame_posture-0.9.34-universal-apple-darwin)  

2. **Install** by placing the binary in your `PATH` and making it executable:
   ```bash
   sudo mv edamame_posture-* /usr/local/bin/edamame_posture
   sudo chmod +x /usr/local/bin/edamame_posture
   ```

3. **Run** a quick command like `edamame_posture score` to assess your device.

### Windows

#### Windows Standard Installation
For a Windows workstation or server:

1. **Download** the Windows binary:
   - [edamame_posture-0.9.34-x86_64-pc-windows-msvc.exe](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.34/edamame_posture-0.9.34-x86_64-pc-windows-msvc.exe)

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
- **check-policy** `<min_score>` `"<threat_ids>"` `"[tag_prefixes]"`: Check whether the system meets a specified security policy. You provide a minimum score threshold, a comma-separated list of critical threat IDs to ensure are not present (or have specific states), and optional tag prefixes for compliance frameworks. This command exits with code 0 if the policy is met, or non-zero if not met (making it perfect for CI gating).
- **check-policy-for-domain** `<domain>` `<policy_name>`: Similar to check-policy, but retrieves the policy requirements from EDAMAME Hub for the given domain and policy name. This allows centralized policies to be enforced on the local machine. Requires that the machine is enrolled (or at least has a policy cached) for that domain.
- **start** `<USER>` `<DOMAIN>` `<PIN>` `[DEVICE_ID]` `[LAN_SCANNING]` `[WHITELIST_NAME]` `[LOCAL_TRAFFIC]`: Start continuous monitoring and conditional access control. Typically run as a background service or daemon. You must supply your Hub user/email, domain, and one-time PIN (from Hub) to register the device session. Optional parameters: a custom device identifier, whether to enable LAN scanning (true/false for capturing local traffic), a named whitelist to enforce, and a flag for allowing local traffic. This will keep running until stopped and enforce policy/network rules in real-time (e.g., locking down access if posture degrades).
- **background-start-disconnected** `[LAN_SCANNING]` `[WHITELIST_NAME]` `[LOCAL_TRAFFIC]`: Start the background monitoring in a local-only mode (no connection to EDAMAME Hub). It will monitor security posture and network traffic, and enforce the provided whitelist. This is useful for CI runners or standalone usage where you want monitoring without cloud integration. This process runs until killed; typically you'd run it in a screen/tmux or as a service.
- **get-sessions** `[ZEEK_FORMAT]` `[LOCAL_TRAFFIC]` `[CHECK_WHITELIST]` `[CHECK_BLACKLIST]` `[CHECK_ANOMALOUS]`: Report network sessions and enforce whitelist compliance. The parameters control whether to use Zeek format output, include local traffic, check whitelist conformance (default true), check for blacklisted connections (default true), and check for anomalous connections (default false). Returns exit code 0 if successful, non-zero if whitelist violation or if anomalous/blacklisted sessions are detected (when those checks are enabled).
- **lanscan**: Perform a quick scan of the local network (LAN) to identify other devices on your subnet. This can reveal potential rogue devices or just provide situational awareness. It lists IP addresses and basic host info for devices it can detect.
- **request-signature**: Generate a security posture signature for the current device state. The output is a cryptographic signature (token) that represents the current posture (including all threat checks and scores). This signature can be stored or embedded (for example, in a Git commit message) as proof of posture at a point in time.
- **get-last-report-signature**: If the background process (start or background-start-disconnected) is running, this command fetches the most recently generated posture signature from that background monitor. This is useful to avoid generating a new one if one was already produced at the end of a build or a scheduled interval.
- **request-report**: Generate a full security report of the current system. This might output a file (e.g., PDF or JSON) containing the detailed posture assessment, including all findings and the signature. The report is signed so it can be verified later. Use this when you need to provide evidence of compliance or for auditing purposes.
- **create-custom-whitelists**: Outputs the current active whitelist definitions in JSON format to stdout. You can redirect this to a file to use as a base for a custom whitelist. This is often run at the end of a "learning mode" pipeline to capture allowed endpoints observed.
- **set-custom-whitelists** `"<json_string>"`: Loads a custom whitelist from a JSON string (or file content). Use this to apply a tailored whitelist (perhaps one created and edited from create-custom-whitelists) before running get-sessions. In practice, you might store a whitelist file in your repo and then do: `edamame_posture set-custom-whitelists "$(cat whitelist.json)"` to load it. The custom whitelist will override the default for the remainder of the session.
- **get-anomalous-sessions** `[ZEEK_FORMAT]`: Display only anomalous network connections detected by the NBAD system. Returns non-zero exit code if anomalous sessions are found.
- **get-blacklisted-sessions** `[ZEEK_FORMAT]`: Display only blacklisted network connections. Returns non-zero exit code if blacklisted sessions are found.

### All Available Commands
For completeness, here is a list of EDAMAME Posture CLI subcommands with detailed information:

- **score** (alias for **get-score**) – Assess and output the security posture score and summary of issues. *Requires admin privileges*.
- **remediate** (alias for **remediate-all-threats**) – Apply recommended fixes to improve security posture (skips remote login and local firewall by default). *Requires admin privileges*.
- **remediate-all-threats-force** – Apply all fixes including those that could lock you out of the system (use with caution). *Requires admin privileges*.
- **remediate-threat** `<THREAT_ID>` – Remediate a specific threat by its threat ID. *Requires admin privileges*. Returns non-zero exit code if remediation fails.
- **rollback-threat** `<THREAT_ID>` – Roll back remediation for a specific threat by its threat ID. *Requires admin privileges*. Returns non-zero exit code if invalid parameters.
- **list-threats** – List all threat names available in the system. *Requires admin privileges*.
- **get-threat-info** `<THREAT_ID>` – Get detailed information about a specific threat. *Requires admin privileges*.
- **lanscan** – Scan local network for connected devices. *Requires admin privileges*.
- **capture** `[SECONDS]` `[WHITELIST_NAME]` `[ZEEK_FORMAT]` `[LOCAL_TRAFFIC]` – Capture network traffic for a specified duration. *Requires admin privileges*.
- **check-policy** `<MINIMUM_SCORE>` `"<THREAT_IDS>"` `"[TAG_PREFIXES]"` – Local policy compliance check. *Requires admin privileges*. Returns non-zero exit code if policy not met.
- **check-policy-for-domain** `<DOMAIN>` `<POLICY_NAME>` – Policy check against a Hub-defined domain policy. *Requires admin privileges*. Returns non-zero exit code if policy not met.
- **check-policy-for-domain-with-signature** `"<SIGNATURE>"` `<DOMAIN>` `<POLICY_NAME>` – Verify a stored posture signature against a domain policy (for historical verification).
- **start** (alias for **background-start**) – Start continuous monitoring and Hub integration. *Requires admin privileges*.
- **background-start-disconnected** `[LAN_SCANNING]` `[WHITELIST_NAME]` `[LOCAL_TRAFFIC]` – Start continuous monitoring in offline mode. *Requires admin privileges*.
- **stop** (alias for **background-stop**) – Stop a running background monitoring process.
- **status** (alias for **background-status**) – Check the status of the background monitoring process.
- **logs** (alias for **background-logs**) – Display logs from the background process.
- **get-sessions** (alias for **background-get-sessions**) `[ZEEK_FORMAT]` `[LOCAL_TRAFFIC]` `[CHECK_WHITELIST]` `[CHECK_BLACKLIST]` `[CHECK_ANOMALOUS]` – Report network sessions and enforce whitelist compliance. The parameters control whether to use Zeek format output, include local traffic, check whitelist conformance (default true), check for blacklisted connections (default true), and check for anomalous connections (default false). Returns exit code 0 if successful, 1 if whitelist violation or if anomalous/blacklisted sessions are detected (when those checks are enabled), 3 if no active sessions found.
- **get-exceptions** (alias for **background-get-exceptions**) `[ZEEK_FORMAT]` `[LOCAL_TRAFFIC]` – Report network sessions that don't conform to whitelist rules.
- **get-background-score** (alias for **background-score**) – Get the current security score from the background process.
- **create-custom-whitelists** (alias for **background-create-custom-whitelists**) – Output template or current whitelist JSON.
- **set-custom-whitelists** (alias for **background-set-custom-whitelists**) `"<WHITELIST_JSON>"` – Load custom whitelist rules from input JSON.
- **create-and-set-custom-whitelists** (alias for **background-create-and-set-custom-whitelists**) – Create custom whitelists from current sessions and apply them in one step.
- **set-custom-blacklists** (alias for **background-set-custom-blacklists**) `"<BLACKLIST_JSON>"` – Load custom blacklist rules from input JSON.
- **get-anomalous-sessions** (alias for **background-get-anomalous-sessions**) `[ZEEK_FORMAT]` – Display only anomalous network connections detected by the NBAD system. Returns non-zero exit code if anomalous sessions are found.
- **get-blacklisted-sessions** (alias for **background-get-blacklisted-sessions**) `[ZEEK_FORMAT]` – Display only blacklisted network connections. Returns non-zero exit code if blacklisted sessions are found.
- **get-blacklists** (alias for **background-get-blacklists**) – Get the current blacklists from the background process.
- **get-whitelists** (alias for **background-get-whitelists**) – Get the current whitelists from the background process.
- **get-whitelist-name** (alias for **background-get-whitelist-name**) – Get the name of the current active whitelist from the background process.
- **request-signature** – Generate a cryptographic signature of current posture. *Requires admin privileges*.
- **get-last-report-signature** (alias for **background-last-report-signature**) – Retrieve the last posture signature from the background service.
- **request-report** `<EMAIL>` `<SIGNATURE>` – Generate a full security report. Returns non-zero exit code for invalid signature parameter.
- **get-core-info** – Retrieve core system information.
- **get-device-info** – Retrieve detailed device information. *Requires admin privileges*.
- **get-system-info** – Get system information. *Requires admin privileges*.
- **get-core-version** – Get the core version of EDAMAME Posture.
- **get-tag-prefixes** – Retrieve threat model tag prefixes. *Requires admin privileges*.
- **request-pin** `<USER>` `<DOMAIN>` – Request a PIN for domain connection. Returns non-zero exit code for invalid parameters.
- **wait-for-connection** (alias for **background-wait-for-connection**) `[TIMEOUT]` – Wait for connection of the background process with optional timeout. Returns exit code 4 for timeout.
- **completion** `<SHELL>` – Generate shell completion scripts for various shells (bash, zsh, fish, etc.).
- **help** – Show general help or help for a specific subcommand (e.g., `edamame_posture check-policy --help`).

Each command may have additional options and flags; run `edamame_posture <command> --help` for detailed usage information on that command. Commands marked with *Requires admin privileges* need to be run with elevated permissions (sudo on Linux/macOS, Run as Administrator on Windows).

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
        uses: actions/checkout@v3

      - name: Install EDAMAME Posture
        run: |
          curl -LO https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.34/edamame_posture-0.9.34-x86_64-unknown-linux-gnu
          chmod +x edamame_posture-0.9.34-x86_64-unknown-linux-gnu
          sudo mv edamame_posture-0.9.34-x86_64-unknown-linux-gnu /usr/local/bin/edamame_posture

      - name: Start background monitor in disconnected mode
        run: sudo edamame_posture background-start-disconnected true github_linux

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

### Testing and Validation
To validate your whitelist configurations before enforcing them in production:
1. **Create a Test Whitelist**: Run `edamame_posture create-custom-whitelists > test_whitelist.json` after a typical build to capture all observed endpoints in that environment. Edit this JSON to remove anything that shouldn't be allowed generally.
2. **Apply and Test**: Apply the edited whitelist: `edamame_posture set-custom-whitelists "$(cat test_whitelist.json)"`. Then run a typical workflow (or just get-sessions if the background was running) to see if any connection gets blocked.
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

- **`github_linux`**: Extends `github`, optimized for Linux GitHub workflows
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
github_macos/github_linux/github_windows (extends github)
```

To use these embedded whitelists, specify the whitelist name when starting EDAMAME Posture:

```bash
# For a macOS GitHub workflow environment
edamame_posture start user example.com 123456 "" true github_macos

# For a basic development environment
edamame_posture start user example.com 123456 "" true builder
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
        uses: actions/checkout@v3
        with:
          fetch-depth: 0  # fetch full history to get commit messages

      - name: Install EDAMAME Posture
        run: |
          curl -LO https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.34/edamame_posture-0.9.34-x86_64-unknown-linux-gnu
          chmod +x edamame_posture-0.9.34-x86_64-unknown-linux-gnu
          sudo mv edamame_posture-0.9.34-x86_64-unknown-linux-gnu /usr/local/bin/edamame_posture

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
- **[EDAMAME Security](https://github.com/edamametechnologies)**: Desktop/mobile security application with full UI and enhanced capabilities (closed source)
- **[EDAMAME Foundation](https://github.com/edamametechnologies/edamame_foundation)**: Foundation library providing security assessment functionality
- **[EDAMAME Posture](https://github.com/edamametechnologies/edamame_posture_cli)**: CLI tool for security posture assessment and remediation
- **[EDAMAME Helper](https://github.com/edamametechnologies/edamame_helper)**: Helper application for executing privileged security checks
- **[EDAMAME CLI](https://github.com/edamametechnologies/edamame_cli)**: Interface to EDAMAME core services
- **[GitHub Integration](https://github.com/edamametechnologies/edamame_posture_action)**: GitHub Action for integrating posture checks in CI/CD
- **[GitLab Integration](https://gitlab.com/edamametechnologies/edamame_posture_action)**: Similar integration for GitLab CI/CD workflows
- **[Threat Models](https://github.com/edamametechnologies/threatmodels)**: Threat model definitions used throughout the system
- **[EDAMAME Hub](https://hub.edamame.tech)**: Web portal for centralized management when using these components in team environments

By using EDAMAME Posture CLI in combination with other ecosystem components, you can scale from individual developer security up to organization-wide endpoint posture management, all while maintaining developer autonomy and privacy.

## Author
EDAMAME Technologies