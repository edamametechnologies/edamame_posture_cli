#!/bin/bash
set -eo pipefail # Exit on error, treat unset variables as error, pipefail

echo "--- Running Standalone Commands Test ---"

# --- Configuration ---
# These should be set externally or defaulted
BINARY_PATH="${BINARY_PATH:-./target/release/edamame_posture}"
RUNNER_OS="${RUNNER_OS:-$(uname)}" # Default to uname output if not set
SUDO_CMD="${SUDO_CMD:-sudo -E}"   # Default to sudo -E if not set
EDAMAME_LOG_LEVEL="${EDAMAME_LOG_LEVEL:-debug}"
VERBOSE_FLAG="-v" # Add verbosity

# Adjust binary path and sudo for Windows
if [[ "$RUNNER_OS" == "windows-latest" || "$RUNNER_OS" == "Windows_NT" || "$RUNNER_OS" == "MINGW"* || "$RUNNER_OS" == "CYGWIN"* ]]; then
    BINARY_NAME="edamame_posture.exe"
    BINARY_PATH="$(dirname "$BINARY_PATH")/$BINARY_NAME" # Ensure .exe extension and correct dir
    SUDO_CMD="" # No sudo on Windows
    HOME_DIR="$USERPROFILE"
    ARTIFACT_PATH="$HOME_DIR/passed_business_rule"
    # Set business rule cmd for Windows (PowerShell)
    # Ensure artifact path uses backslashes for PowerShell on Windows
    ARTIFACT_PATH_WIN=$(echo "$ARTIFACT_PATH" | sed 's|/|\|g')
    export EDAMAME_BUSINESS_RULES_CMD="Write-Output \"passed\" > \"$ARTIFACT_PATH_WIN\" 2>$null"
else
    BINARY_NAME="edamame_posture"
    BINARY_PATH="$(dirname "$BINARY_PATH")/$BINARY_NAME" # Ensure correct binary name
    HOME_DIR="$HOME"
    ARTIFACT_PATH="$HOME_DIR/passed_business_rule"
    # Set business rule cmd for Linux/macOS
    # Ensure artifact path is quoted if HOME has spaces, although unlikely in CI
    export EDAMAME_BUSINESS_RULES_CMD="{ echo passed > \"$ARTIFACT_PATH\"; } > /dev/null 2>&1"
    # Check if sudo is actually needed/available
    if ! command -v sudo &> /dev/null; then
        echo "Warning: sudo command not found. Running commands without sudo."
        SUDO_CMD=""
    elif [[ "$SUDO_CMD" == "sudo -E" ]] && [[ $EUID -eq 0 ]]; then
         echo "Running as root, removing sudo -E prefix."
         SUDO_CMD="" # Already root, no need for sudo
    fi
fi

# Ensure artifact doesn't exist before test
rm -f "$ARTIFACT_PATH"

echo "Using Binary: $BINARY_PATH"
echo "Runner OS: $RUNNER_OS"
echo "Sudo Command: $SUDO_CMD"
echo "Business Rule Artifact Path: $ARTIFACT_PATH"
echo "Business Rule Command: $EDAMAME_BUSINESS_RULES_CMD"

# Set log level for the script execution
export EDAMAME_LOG_LEVEL

# --- Tests ---

echo "Get core info:"
"$BINARY_PATH" $VERBOSE_FLAG get-core-info

echo "Get core version:"
"$BINARY_PATH" $VERBOSE_FLAG get-core-version

echo "Help:"
"$BINARY_PATH" $VERBOSE_FLAG help

# Perform a simple score computation (needs business rule cmd env var)
echo "Score:"
$SUDO_CMD "$BINARY_PATH" $VERBOSE_FLAG score

# Check if the business rule was passed
echo "Checking for business rule artifact at $ARTIFACT_PATH..."
# Use -f for files, works cross-platform better than [[ -f ]] in all shells
if ! [ -f "$ARTIFACT_PATH" ]; then
    echo "Error: Business rule artifact not found at $ARTIFACT_PATH"
    ls -la "$(dirname "$ARTIFACT_PATH")" # List directory contents for debugging
    exit 1
else
    echo "Business rule artifact found."
    rm -f "$ARTIFACT_PATH" # Clean up artifact
fi

# Test remediate command with skip_remediations
echo "Remediate (with skipped remediations):"
$SUDO_CMD "$BINARY_PATH" $VERBOSE_FLAG remediate "remote login enabled,local firewall disabled"

# Test request-signature command
echo "Request signature:"
# Don't use -v here for cleaner output capture
# Ensure command runs even if it fails, capture output
signature_output=$($SUDO_CMD "$BINARY_PATH" request-signature || echo "signature_error")
signature=$(echo "$signature_output" | grep Signature | awk '{print $2}' || echo "signature_error")
echo "Obtained signature: $signature"

# Test request-report command (using a test email)
if [[ "$signature" != "signature_error" && ! -z "$signature" ]]; then
    echo "Request report:"
    $SUDO_CMD "$BINARY_PATH" $VERBOSE_FLAG request-report "test@example.com" "$signature"
else
    echo "Skipping request-report due to signature error or empty signature."
fi

# Test check-policy command with float score
echo "Check policy (local):"
$SUDO_CMD "$BINARY_PATH" $VERBOSE_FLAG check-policy 1.0 "encrypted disk disabled"

# Test check-policy-for-domain command
echo "Check policy (with domain):"
# Domain value from tests.yml: edamame.tech, Context: Github
$SUDO_CMD "$BINARY_PATH" $VERBOSE_FLAG check-policy-for-domain "edamame.tech" "Github"

# Get device info
echo "Device info:"
$SUDO_CMD "$BINARY_PATH" $VERBOSE_FLAG get-device-info

# Get system info
echo "System info:"
$SUDO_CMD "$BINARY_PATH" $VERBOSE_FLAG get-system-info

# Perform a lanscan
echo "Lanscan:"
$SUDO_CMD "$BINARY_PATH" $VERBOSE_FLAG lanscan

# Perform a capture
echo "Capture:"
$SUDO_CMD "$BINARY_PATH" $VERBOSE_FLAG capture 5

echo "--- Standalone Commands Test Completed ---" 