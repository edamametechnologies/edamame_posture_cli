# EDAMAME Posture: Free CI/CD CLI

> **What?**: Lightweight, developer-friendly security posture assessment and remediation tool—perfect for those who want a straightforward way to secure their development environment and CI/CD pipelines without slowing down development.

## Table of Contents

1. [Overview](#overview)
2. [Key Features](#key-features)
3. [Targeted Use Cases](#targeted-use-cases)
4. [How It Works](#how-it-works)
5. [Security Posture Assessment Methods](#security-posture-assessment-methods)
6. [Threat Models and Security Assessment](#threat-models-and-security-assessment)
7. [CI/CD Integration and Workflow Controls](#cicd-integration-and-workflow-controls)
8. [Installation](#installation)
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
9. [Usage](#usage)
   - [Common Commands](#common-commands)
   - [All Available Commands](#all-available-commands)
10. [Exit Codes and CI/CD Pipelines](#exit-codes-and-cicd-pipelines)
11. [Whitelist System](#whitelist-system)
12. [Historical Security Posture Verification](#historical-security-posture-verification)
13. [Requirements](#requirements)
14. [Error Handling](#error-handling)

## Overview

EDAMAME Posture is a cross-platform CLI that safeguards your software development lifecycle—making it easy to:

- **Assess** the security posture of your device or CI/CD environment
- **Harden** against common misconfigurations at the click of a button
- **Monitor** network traffic to detect and prevent supply chain attacks
- **Generate** compliance or audit reports—giving you proof of a hardened setup

Whether you're an individual developer or part of a larger team, EDAMAME Posture offers flexible security options that grow with your needs—from completely local, disconnected controls to centralized policy management through [EDAMAME Hub](https://hub.edamame.tech).

### Security Without Undermining Productivity

One of the key strengths of EDAMAME Posture is that it provides powerful security controls that work entirely locally, without requiring any external connectivity or registration:

- **Local Policy Checks**: Use `check-policy` to enforce security standards based on minimum score thresholds, specific threat detections, and security tag prefixes
- **CI/CD Pipeline Gates**: Non-zero exit codes returned by these checks allow you to automatically fail pipelines when security requirements aren't met
- **Disconnected Network Monitoring**: Monitor and enforce network traffic whitelists in air-gapped or restricted environments
- **Zero-Configuration Integration**: Add security gates to your personal repositories with minimal setup

This means you can immediately integrate security controls into your workflows, even before deciding to connect to EDAMAME Hub for more advanced features.

### Security Beyond Compliance

EDAMAME Posture enables powerful reporting and verification use cases:

- **Point-in-Time Signatures**: Generate cryptographically verifiable signatures that capture the security state of a device at a specific moment
- **Historical Verification**: Verify that code was committed or released from environments that met security requirements
- **Development Workflow Integration**: Embed signatures in Git commits, pull requests, or release artifacts for security traceability
- **Continuous Compliance**: Maintain an audit trail of security posture across your development lifecycle

These capabilities allow you to not only enforce security at build time but also track and verify security posture throughout your entire development process.

## Key Features

1. **Developer-Friendly CLI**  
   Straightforward commands allow you to quickly get things done with minimal fuss.  
2. **Cross-Platform Support**  
   Runs on macOS, Windows, and a variety of Linux environments.  
3. **Automated Remediation**  
   Resolve many security risks automatically with a single command.  
4. **Network & Egress Tracking**  
   Get clear visibility into local devices and outbound connections, detecting suspicious traffic that could indicate supply chain attacks.  
5. **Pipeline Security Gates**  
   Fail builds when security posture doesn't meet requirements, preventing insecure code deployment.
6. **Compliance Reporting**  
   Generate tamper-proof reports for audits or personal assurance.
7. **Optional Hub Integration**  
   Connect to [EDAMAME Hub](https://hub.edamame.tech) when you're ready for shared visibility and policy enforcement.
8. **Versatile for CI/CD and Dev Machines**
   Seamlessly integrates into CI/CD pipelines and developer workstations with CLI and GitHub/GitLab Actions.

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

## Threat Models and Security Assessment

EDAMAME Posture's security assessment capabilities are powered by comprehensive threat models that evaluate security across five key dimensions:

### Threat Dimensions

| Dimension | Description |
|-----------|-------------|
| **Applications** | Application authorizations, EPP/antivirus, ... |
| **Network** | Network configuration, exposed services, ... |
| **Credentials** | Password policies, biometrics, 2FA, ... |
| **System Integrity** | MDM profiles, jailbreaking, 3rd party administrative access, ... |
| **System Services** | System configuration, service vulnerabilities, ... |

### Compliance Frameworks

Security assessments incorporate industry-standard compliance frameworks, including:

- **CIS Benchmarks**: Center for Internet Security configuration guidelines
- **SOC-2**: Service Organization Control criteria for security, availability, and privacy
- **ISO 27001**: Information security management system requirements

Each threat detected by EDAMAME Posture is mapped to these compliance frameworks, allowing you to demonstrate compliance with specific standards.

### Assessment Methods

EDAMAME Posture employs multiple assessment methods to evaluate threats:

1. **System Checks**: Direct evaluation of system configurations, file presence, or settings
2. **Command Line Checks**: Safe, predefined commands that gather system state information
3. **Business Rules**: Optional custom script execution in userspace for organization-specific policies

### Whitelist Database

Network security assessment uses comprehensive whitelist databases that define allowable network connections:

- **Base Whitelists**: Core connectivity for essential functionality
- **Environment-Specific Whitelists**: Specialized for development and CI/CD environments
- **Platform-Specific Whitelists**: Tailored for macOS, Linux, and Windows

These whitelists support advanced pattern matching for domains, IP addresses, ports, and protocols, enabling precise control over network communications.

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
- All the monitoring capabilities and whitelist enforcement without domain registration
- Local-only security controls for sensitive or air-gapped environments

### Preventing Supply Chain Attacks

EDAMAME Posture provides critical protection against supply chain attacks in CI/CD pipelines:

1. **Network Egress Monitoring**: Continuously monitors all outbound connections from your CI/CD runners
2. **Whitelist Enforcement**: Only allows connections to approved endpoints, blocking malicious outbound traffic
3. **Real-Time Anomaly Detection**: Flags suspicious network activity that could indicate compromise
4. **Exit Code Integration**: Automatically fails builds when security violations are detected

**Real-world example**: When the popular GitHub Action tj-actions/changed-files was compromised (CVE-2025-30066), attackers modified it to leak CI/CD secrets by making unauthorized network calls to fetch a malicious payload from gist.githubusercontent.com. EDAMAME Posture's network monitoring would have detected and blocked this exact attack pattern, preventing the compromise by:

1. Identifying the unexpected connection to gist.githubusercontent.com
2. Verifying this domain wasn't in the approved whitelist
3. Failing the pipeline with a non-zero exit code
4. Providing detailed logs showing the exact violation

This zero-trust approach to CI/CD networking effectively prevents malicious payloads from being executed, protecting your repositories from credential theft and further compromise.

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

### Optimal Usage Pattern for CI/CD Security

For optimal protection against supply chain attacks and other CI/CD security risks, follow these best practices regardless of the CI/CD platform you're using:

#### 1. Setup at Workflow Beginning

Always place EDAMAME Posture setup at the very beginning of your workflow, before any build, test, or deployment steps:
- This ensures that security monitoring is active throughout the entire pipeline execution
- Captures all network activity from the start, including any potential malicious connections
- Establishes security posture baseline before any code execution

#### 2. Enable Network Monitoring

Enable network monitoring with the appropriate whitelist for your environment:
```bash
sudo edamame_posture background-start-disconnected true github_linux
```

> **Important:** The `true` parameter enables LAN scanning, which is required for network traffic capture and whitelist enforcement. Without this setting, the network monitoring capabilities will be limited.

#### 3. Perform Initial Assessment and Remediation

Assess and optionally remediate security issues at the beginning:
```bash
sudo edamame_posture score
sudo edamame_posture remediate
```

#### 4. Enforce Security Policies

Apply appropriate security policies to create a security gate:
```bash
sudo edamame_posture check-policy 2.0 "encrypted disk disabled,critical vulnerability" "SOC-2"
```

#### 5. Verify Network Conformance at Workflow End

Always check network conformance at the end of your workflow to catch any suspicious activity:
```bash
edamame_posture get-sessions
```

This command will fail with a non-zero exit code if any unauthorized network traffic was detected during the workflow execution, preventing CI from completing successfully when security violations occur.

#### 6. Customize with Whitelists (Optional)

For more tailored security controls, create and apply custom whitelists:
```bash
# Create a whitelist from observed traffic
edamame_posture create-custom-whitelists > ./whitelist.json

# In future runs, apply the stored whitelist
edamame_posture set-custom-whitelists "$(cat ./whitelist.json)"
```

By following this pattern, you can maintain a zero-trust security posture for all your CI/CD pipelines, effectively preventing supply chain attacks like the one described in CVE-2025-30066.

## Exit Codes and CI/CD Pipelines

EDAMAME Posture is designed to integrate seamlessly with CI/CD pipelines by using standardized exit codes that can control workflow execution. This allows for security-driven pipeline decisions without complex scripting.

### Key Commands with Exit Codes for CI/CD Integration

| Command | Exit Code 0 | Other Exit Codes |
|---------|-------------|------------------|
| `get-sessions` | Sessions retrieved successfully | Whitelist conformance failure |
| `check-policy` | Policy requirements met | Policy requirements not met |
| `check-policy-for-domain` | Domain policy requirements met | Domain policy requirements not met |

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

## Whitelist System

### Overview

The EDAMAME whitelist system provides a flexible and powerful way to control network access through a hierarchical structure with clear matching priorities. This document explains how whitelists work, how to create them, and provides examples for common use cases.

### Whitelist Structure

#### Basic Components

```rust
// Main whitelist container
struct Whitelists {
    date: String,                    // Creation/update date
    signature: Option<String>,       // Optional cryptographic signature
    whitelists: Map<String, WhitelistInfo> // Named whitelist collection
}

// Individual whitelist definition
struct WhitelistInfo {
    name: String,                // Unique identifier
    extends: Option<Vec<String>>, // Parent whitelists to inherit from
    endpoints: Vec<WhitelistEndpoint> // List of allowed endpoints
}

// Network endpoint specification
struct WhitelistEndpoint {
    domain: Option<String>,     // Domain name (supports wildcards)
    ip: Option<String>,         // IP address or CIDR range
    port: Option<u16>,          // Port number
    protocol: Option<String>,   // Protocol (TCP, UDP, etc.)
    as_number: Option<u32>,     // Autonomous System number
    as_country: Option<String>, // Country code for the AS
    as_owner: Option<String>,   // AS owner/organization name
    process: Option<String>,    // Process name
    description: Option<String> // Human-readable description
}
```

### Whitelist Building and Inheritance

#### Basic Whitelist Setup

Whitelists are defined in JSON format and loaded at startup. Each whitelist consists of a unique name and a list of endpoint specifications:

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

#### Inheritance System

Whitelists can inherit from other whitelists using the `extends` field, creating a hierarchical structure:

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

When a whitelist extends another:

1. **Endpoint Aggregation**: All endpoints from the parent whitelist(s) are included in the child.
2. **Multiple Inheritance**: A whitelist can extend multiple parent whitelists.
3. **Circular Detection**: The system detects and prevents infinite recursion in circular inheritance patterns.
4. **Inheritance Depth**: There is no limit to the inheritance chain depth.

When retrieving endpoints from a whitelist:
```
function get_all_endpoints(whitelist_name):
    visited = HashSet()
    visited.add(whitelist_name)
    
    info = whitelists.get(whitelist_name)
    endpoints = info.endpoints.clone()
    
    if info.extends exists:
        for parent in info.extends:
            if parent not in visited:
                visited.add(parent)
                endpoints.extend(get_all_endpoints(parent, visited))
    
    return endpoints
```

### Matching Algorithm

The whitelist system follows a precise matching order when determining if a network connection should be allowed:

#### 1. Fundamental Match Criteria

These are always checked first and are required for any further matching:

```
if (!port_matches || !protocol_matches || !process_matches):
    return NO_MATCH
```

- **Protocol**: Must match case-insensitively if specified (e.g., "TCP" matches "tcp").
- **Port**: Must match exactly if specified.
- **Process**: Must match case-insensitively if specified.

#### 2. Hierarchical Match Order

If fundamental criteria pass, the system evaluates in this strict order:

1. **Domain Matching**: If domain is specified and matches, immediately accept.
2. **IP Matching**: If domain didn't match or wasn't specified, check IP.
3. **AS Information**: Only checked if neither domain nor IP matched, or AS info is specifically required.

```
// Domain priority
if (domain_specified && domain_matches):
    return MATCH

// IP priority
if (ip_specified && ip_matches):
    return MATCH

// Entity match validation
if ((domain_specified || ip_specified) && !(domain_matches || ip_matches)):
    return NO_MATCH

// AS info matching (when needed)
if (should_check_as_info && !as_info_matches):
    return NO_MATCH

// If we've made it this far, all checks have passed
return MATCH
```

### Pattern Matching Details

#### Domain Wildcard Matching

The system supports three types of domain wildcards with specific behaviors:

##### 1. Prefix Wildcards (`*.example.com`)

```
function prefix_wildcard_match(domain, pattern):
    // Remove "*."; remaining pattern is the suffix
    suffix = pattern.substring(2)
    
    // Domain must not exactly match suffix (requires subdomain)
    if (domain == suffix):
        return false
        
    // Domain must end with suffix
    if (!domain.endsWith(suffix)):
        return false
        
    // Ensure there's a dot before the suffix (valid subdomain boundary)
    prefixLen = domain.length - suffix.length - 1
    return prefixLen > 0 && domain[prefixLen] == '.'
```

**Examples:**
- `*.example.com` ✓ Matches: `sub.example.com`, `a.b.example.com`
- `*.example.com` ✗ Does NOT match: `example.com`, `otherexample.com`

##### 2. Suffix Wildcards (`example.*`)

```
function suffix_wildcard_match(domain, pattern):
    // Remove ".*"; remaining pattern is the prefix
    prefix = pattern.substring(0, pattern.length - 2)
    
    // Domain must start with prefix
    if (!domain.startsWith(prefix)):
        return false
        
    // Exact prefix match is valid
    if (domain.length == prefix.length):
        return true
        
    // If longer than prefix, next char must be a dot (TLD boundary)
    return domain.length > prefix.length && 
           domain[prefix.length] == '.'
```

**Examples:**
- `example.*` ✓ Matches: `example.com`, `example.org`, `example.co.uk`
- `example.*` ✗ Does NOT match: `www.example.com`, `myexample.com`

##### 3. Middle Wildcards (`api.*.example.com`)

```
function middle_wildcard_match(domain, pattern):
    parts = pattern.split('*')
    prefix = parts[0]
    suffix = parts[1]
    
    return domain.startsWith(prefix) && 
           domain.endsWith(suffix) && 
           domain.length > (prefix.length + suffix.length)
```

**Examples:**
- `api.*.example.com` ✓ Matches: `api.v1.example.com`, `api.staging.example.com`
- `api.*.example.com` ✗ Does NOT match: `api.example.com`, `v1.api.example.com`

#### IP Address Matching

IP matching supports both exact matching and CIDR notation:

```
function ip_matches(session_ip, whitelist_ip):
    if (whitelist_ip contains '/'):  // CIDR notation
        return session_ip is within CIDR range
    else:
        return session_ip == whitelist_ip exactly
```

**Examples:**
- Exact: `192.168.1.1` only matches that specific IP
- CIDR: `192.168.1.0/24` matches any IP from `192.168.1.0` to `192.168.1.255`
- IPv6 support: `2001:db8::/32` matches any IPv6 address in that prefix

#### AS Information Matching

AS matching includes number, country, and owner verification:

```
// Autonomous System Number
if (whitelist_asn_specified && session_asn != whitelist_asn):
    return NO_MATCH
    
// Country (case-insensitive)
if (whitelist_country_specified && !session_country.equalsIgnoreCase(whitelist_country)):
    return NO_MATCH
    
// Owner (case-insensitive)
if (whitelist_owner_specified && !session_owner.equalsIgnoreCase(whitelist_owner)):
    return NO_MATCH
```

### Matching Process In Detail

The complete matching process for determining if a session matches a whitelist:

1. **Retrieve Endpoints**: Collect all endpoints from the whitelist, including inherited ones.
2. **Empty Check**: If the whitelist contains no endpoints, immediate no-match.
3. **Iterate Endpoints**: For each endpoint in the whitelist:
   a. Check fundamental criteria (protocol, port, process)
   b. Check domain match if specified (highest priority)
   c. Check IP match if specified
   d. Check AS information if required
   e. If all required checks pass, return match
4. **Default**: If no endpoints match, return no-match with reason

```pseudocode
function is_session_in_whitelist(session, whitelist_name):
    visited = HashSet()
    visited.add(whitelist_name)
    
    endpoints = get_all_endpoints(whitelist_name, visited)
    
    if endpoints.isEmpty():
        return (false, "Whitelist contains no endpoints")
    
    for endpoint in endpoints:
        if endpoint_matches(session, endpoint):
            return (true, null)
    
    return (false, "No matching endpoint found")
```

### Best Practices

1. **Start Specific**
   - Begin with the most specific rules possible
   - Use domain names over IP addresses when available
   - Specify ports and protocols explicitly

2. **Use Inheritance**
   - Create base whitelists for common services
   - Extend for environment-specific needs
   - Keep whitelists modular and reusable

3. **Document Endpoints**
   - Use clear descriptions for each endpoint
   - Explain the purpose of each whitelist
   - Document inheritance relationships

4. **Regular Maintenance**
   - Review and update whitelists regularly
   - Remove unused endpoints
   - Audit inheritance chains

5. **Security Considerations**
   - Prefer domain matches over IP matches
   - Use process restrictions for sensitive connections
   - Implement the principle of least privilege

### Testing and Validation

To validate whitelist configurations:

1. **Create Test Whitelist**
```bash
edamame_posture create-custom-whitelists > test.json
```

2. **Apply and Test**
```bash
edamame_posture set-custom-whitelists "$(cat test.json)"
edamame_posture get-sessions
```

3. **Monitor Results**
   - Check logs for blocked connections
   - Verify expected connections work
   - Validate inheritance chains

### Troubleshooting

Common issues and solutions:

1. **Connection Blocked**
   - Check protocol and port match
   - Verify domain/IP pattern syntax
   - Confirm process name if specified

2. **Inheritance Issues**
   - Verify parent whitelist exists
   - Check for circular dependencies
   - Confirm whitelist names match

3. **Pattern Matching**
   - Test wildcard patterns individually
   - Verify CIDR notation
   - Check case sensitivity

### Reference

#### Supported Protocols
- TCP
- UDP
- ICMP
- (others as configured)

#### Special Values
- `"*"` - Wildcard in domain patterns
- `"0.0.0.0/0"` - All IPv4 addresses
- `::/0` - All IPv6 addresses

#### Environment Variables
- `EDAMAME_WHITELIST_PATH` - Custom whitelist location
- `EDAMAME_WHITELIST_LOG_LEVEL` - Logging verbosity

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