# edamame_posture

This is the CLI tool to compute and remediate the security posture of a device. This is designed to be used in CI/CD pipelines or test devices.
See the associated GitHub action for an example of how to use it. This covers a variety of security threats involving the device.

--------------------------------------------------------------------------------

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
edamame_posture start <USER> <DOMAIN> <PIN> <DEVICE_ID> [LAN_SCANNING] [WHITELIST_NAME] [LOCAL_TRAFFIC]

• USER: User name (required)
• DOMAIN: Domain name (must be a valid FQDN)
• PIN: PIN for authentication (must contain digits only)
• DEVICE_ID: Device ID suffix
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

## Download official binaries for edamame_posture

• [Gnu Linux x86_64](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.8.0/edamame_posture-0.8.0-x86_64-unknown-linux-gnu)
• [Gnu Linux i686](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.8.0/edamame_posture-0.8.0-i686-unknown-linux-gnu)
• [Gnu Linux aarch64](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.8.0/edamame_posture-0.8.0-aarch64-unknown-linux-gnu)
• [Gnu Linux armv7](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.8.0/edamame_posture-0.8.0-armv7-unknown-linux-gnueabihf)
• [Alpine Linux x86_64](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.8.0/edamame_posture-0.8.0-x86_64-unknown-linux-musl)
• [Alpine Linux aarch64](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.8.0/edamame_posture-0.8.0-aarch64-unknown-linux-musl)
• [macOS universal (signed)](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.8.0/edamame_posture-0.8.0-universal-apple-darwin)
• [Windows x86_64 (signed)](https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.8.0/edamame_posture-0.8.0-x86_64-pc-windows-msvc.exe)

--------------------------------------------------------------------------------

## Author

Frank Lyonnet