# edamame_posture
This is the CLI tool to compute and remediate the security posture of a device. This is designed to be used in CI/CD pipelines or test devices.
See the associated Github action for an example of how to use it. This covers a variety of security threats involving the device.
Network scans are performed by default when launching the background service, but can be disabled if needed.

## Usage
edamame_posture [SUBCOMMAND]

## Subcommands
### score
Retrieves score information based on device posture.

Syntax: edamame_posture score

### lanscan
Performs a Local Area Network (LAN) scan to detect devices on the network.

Syntax: edamame_posture lanscan

### wait-for-connection
Waits for a network connection within a specified timeout period.

Syntax: edamame_posture wait-for-connection [TIMEOUT]

TIMEOUT: Timeout in seconds (optional, defaults to 600 seconds if not provided)

### get-core-info
Fetches core information of the device.

Syntax: edamame_posture get-core-info

### get-device-info
Retrieves detailed device information.

Syntax: edamame_posture get-device-info

### get-threats-info
Fetches information about potential threats detected on the device.

Syntax: edamame_posture get-threats-info

### get-system-info
Retrieves system information including OS details and network configuration.

Syntax: edamame_posture get-system-info

### request-pin
Requests a PIN for user authentication.

Syntax: edamame_posture request-pin <USER> <DOMAIN>

USER: User name

DOMAIN: Domain name

### get-core-version
Retrieves the current version of the core.

Syntax: edamame_posture get-core-version

### remediate
Performs threat remediation actions on the device.

Syntax: edamame_posture remediate [REMEDIATIONS]

REMEDIATIONS: Comma-separated list of remediations to skip (optional)

### start
Starts the background process for continuous monitoring and reporting.

Syntax: edamame_posture start <USER> <DOMAIN> <PIN> <DEVICE_ID> [LAN_SCANNING]

USER: User name

DOMAIN: Domain name

PIN: PIN for authentication

DEVICE_ID: Device ID suffix

LAN_SCANNING: Enable LAN scanning (optional, defaults to false)

### stop
Stops the background reporting process.

Syntax: edamame_posture stop

### status
Displays the current status of the background reporting process.

Syntax: edamame_posture status

### Requirements
Administrator privileges are required for most commands.

### Error Handling
If a command requires admin privileges and they are not available, the tool will exit with an error message.
Invalid arguments or subcommands will prompt usage instructions.

## Author
Frank Lyonnet