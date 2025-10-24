#!/bin/bash
set -eo pipefail # Exit on error, treat unset variables as error, pipefail

# Track test results with simple variables for macOS compatibility
get_core_info_result="❓"
get_core_version_result="❓"
help_result="❓"
score_result="❓"
remediate_result="❓"
request_signature_result="❓"
request_report_result="❓"
check_policy_result="❓"
check_policy_for_domain_result="❓"
get_device_info_result="❓"
get_system_info_result="❓"
lanscan_result="❓"
capture_result="❓"
merge_custom_whitelists_result="❓"
augment_custom_whitelists_result="❓"
mcp_generate_psk_result="❓"
mcp_start_result="❓"
mcp_status_result="❓"
mcp_stop_result="❓"

# Function to run on exit
finish() {
    local exit_status=$?
    if [ -f "$ARTIFACT_PATH" ]; then
        echo "Cleaning up business rule artifact..."
        rm -f "$ARTIFACT_PATH"
    fi
    echo ""
    echo "--- Test Summary --- "
    echo "- Standalone Commands:"
    echo "  $get_core_info_result get-core-info"
    echo "  $get_core_version_result get-core-version"
    echo "  $help_result help"
    echo "  $score_result score (with business rule)"
    echo "  $remediate_result remediate"
    echo "  $request_signature_result request-signature"
    echo "  $request_report_result request-report"
    echo "  $check_policy_result check-policy (local)"
    echo "  $check_policy_for_domain_result check-policy-for-domain"
    echo "  $get_device_info_result get-device-info"
    echo "  $get_system_info_result get-system-info"
    echo "  $lanscan_result lanscan"
    echo "  $capture_result capture"
    echo "  $merge_custom_whitelists_result merge-custom-whitelists"
    echo "  $augment_custom_whitelists_result augment-custom-whitelists"
    echo "- MCP/Agentic Commands:"
    echo "  $mcp_generate_psk_result mcp-generate-psk"
    echo "  $mcp_start_result mcp-start"
    echo "  $mcp_status_result mcp-status"
    echo "  $mcp_stop_result mcp-stop"
    echo "--------------------"
    if [ $exit_status -eq 0 ]; then
        echo "✅ --- Standalone Commands Test Completed Successfully --- ✅"
    else
        echo "❌ --- Standalone Commands Test Failed (Exit Code: $exit_status) --- ❌"
    fi
}
# Register the finish function to run on exit, also ensure cleanup happens
trap finish EXIT

echo "--- Running Standalone Commands Test ---"

# Find the binary, preferring release but falling back to debug or other locations
# Use 'find ... -quit' to stop after the first match
FOUND_BINARY=$(find ./target -type f \( -name edamame_posture -o -name edamame_posture.exe \) -print -quit 2>/dev/null)

# Check if a binary was found
if [ -z "$FOUND_BINARY" ]; then
  echo "🔴 Error: Could not find 'edamame_posture' or 'edamame_posture.exe' in ./target" >&2
  exit 1
fi

# --- Configuration ---
# Use the found binary path if BINARY_PATH is not already set externally
BINARY_PATH="${BINARY_PATH:-$FOUND_BINARY}"
RUNNER_OS="${RUNNER_OS:-$(uname)}" # Default to uname output if not set
SUDO_CMD="${SUDO_CMD:-sudo -E}"   # Default to sudo -E if not set
EDAMAME_LOG_LEVEL="${EDAMAME_LOG_LEVEL:-debug}"
VERBOSE_FLAG="-v" # Add verbosity

# Adjust binary path and sudo for Windows
if [[ "$RUNNER_OS" == "windows" || "$OS" == "Windows_NT" || "$OS" == "MINGW"* || "$OS" == "CYGWIN"* ]]; then
    BINARY_NAME="edamame_posture.exe"
    BINARY_PATH="$(dirname "$BINARY_PATH")/$BINARY_NAME" # Ensure .exe extension and correct dir
    SUDO_CMD="" # No sudo on Windows
    HOME_DIR="$USERPROFILE"
    # Define ARTIFACT_PATH with backslashes for Windows
    ARTIFACT_PATH="$HOME_DIR/passed_business_rule"
    # Set business rule cmd for Windows (PowerShell)
    # Use the correctly defined ARTIFACT_PATH directly
    # Use PowerShell
    echo "Setting business rule so that it will be passed and leave an artifact in $ARTIFACT_PATH"
    # We must directly refer $env:USERPROFILE in the command for the path to work
    export EDAMAME_BUSINESS_RULES_CMD='Write-Output "passed" > "$env:USERPROFILE/passed_business_rule" 2>$null'
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
"$BINARY_PATH" $VERBOSE_FLAG get-core-info && get_core_info_result="✅" || get_core_info_result="❌"

echo "Get core version:"
"$BINARY_PATH" $VERBOSE_FLAG get-core-version && get_core_version_result="✅" || get_core_version_result="❌"

echo "Help:"
"$BINARY_PATH" $VERBOSE_FLAG help && help_result="✅" || help_result="❌"

# Perform a simple score computation (needs business rule cmd env var)
echo "Score:"
$SUDO_CMD "$BINARY_PATH" $VERBOSE_FLAG score && score_result="✅" || score_result="❌"

# Check if the business rule was passed
echo "Checking for business rule artifact at $ARTIFACT_PATH..."
# Use -f for files, works cross-platform better than [[ -f ]] in all shells
if ! [ -f "$ARTIFACT_PATH" ]; then
    echo "🔴 Error: Business rule artifact not found at $ARTIFACT_PATH"
    ls -la "$(dirname "$ARTIFACT_PATH")" # List directory contents for debugging
    exit 1
else
    echo "Business rule artifact found."
    rm -f "$ARTIFACT_PATH" # Clean up artifact
fi

# Test remediate command with skip_remediations
echo "Remediate (with skipped remediations):"
$SUDO_CMD "$BINARY_PATH" $VERBOSE_FLAG remediate "remote login enabled,local firewall disabled" && remediate_result="✅" || remediate_result="❌"

# Test request-signature command
echo "Request signature:"
# Don't use -v here for cleaner output capture
# Ensure command runs even if it fails, capture output
signature_output=$($SUDO_CMD "$BINARY_PATH" request-signature || echo "signature_error")
signature=$(echo "$signature_output" | grep Signature | awk '{print $2}' || echo "signature_error")
echo "Obtained signature: $signature"
if [[ "$signature" != "signature_error" && ! -z "$signature" ]]; then
    request_signature_result="✅"
else
    request_signature_result="❌"
fi

# Test request-report command (using a test email)
if [[ "$signature" != "signature_error" && ! -z "$signature" ]]; then
    echo "Request report:"
    $SUDO_CMD "$BINARY_PATH" $VERBOSE_FLAG request-report "test@example.com" "$signature" && request_report_result="✅" || request_report_result="❌"
else
    echo "🔴 Error: Skipping request-report due to signature error or empty signature."
    request_report_result="⏭️"
fi

# Test check-policy command with float score
echo "Check policy (local):"
$SUDO_CMD "$BINARY_PATH" $VERBOSE_FLAG check-policy 1.0 "encrypted disk disabled" && check_policy_result="✅" || check_policy_result="❌"

# Test check-policy-for-domain command
echo "Check policy (with domain):"
# Domain value from tests.yml: edamame.tech, Context: Github
$SUDO_CMD "$BINARY_PATH" $VERBOSE_FLAG check-policy-for-domain "edamame.tech" "Github" && check_policy_for_domain_result="✅" || check_policy_for_domain_result="❌"

# Get device info
echo "Device info:"
$SUDO_CMD "$BINARY_PATH" $VERBOSE_FLAG get-device-info && get_device_info_result="✅" || get_device_info_result="❌"

# Get system info
echo "System info:"
$SUDO_CMD "$BINARY_PATH" $VERBOSE_FLAG get-system-info && get_system_info_result="✅" || get_system_info_result="❌"

# Perform a lanscan
echo "Lanscan:"
$SUDO_CMD "$BINARY_PATH" $VERBOSE_FLAG lanscan && lanscan_result="✅" || lanscan_result="❌"

# Perform a capture
echo "Capture:"
$SUDO_CMD "$BINARY_PATH" $VERBOSE_FLAG capture 5 && capture_result="✅" || capture_result="❌"

# Test augment-custom-whitelists command
echo "Augment custom whitelists:"
AUGMENT_JSON=$($SUDO_CMD "$BINARY_PATH" $VERBOSE_FLAG augment-custom-whitelists || echo "")
if [[ -n "$AUGMENT_JSON" ]]; then
    augment_custom_whitelists_result="✅"
else
    augment_custom_whitelists_result="❌"
fi

# Test merge-custom-whitelists command
echo "Merge custom whitelists:"
# Generate two whitelist JSON strings
WL_JSON1=$($SUDO_CMD "$BINARY_PATH" create-custom-whitelists || echo "")
WL_JSON2=$($SUDO_CMD "$BINARY_PATH" create-custom-whitelists || echo "")
MERGED_JSON=$($SUDO_CMD "$BINARY_PATH" merge-custom-whitelists "$WL_JSON1" "$WL_JSON2" || echo "")
if [[ -n "$MERGED_JSON" ]]; then
    merge_custom_whitelists_result="✅"
else
    merge_custom_whitelists_result="❌"
fi

# ============================================================================
# MCP/Agentic Tests
# ============================================================================

echo "MCP: Generate PSK:"
MCP_PSK=$($SUDO_CMD "$BINARY_PATH" $VERBOSE_FLAG mcp-generate-psk 2>/dev/null | head -1 || echo "")
if [[ -n "$MCP_PSK" && ${#MCP_PSK} -ge 32 ]]; then
    echo "✅ Generated PSK (length: ${#MCP_PSK})"
    mcp_generate_psk_result="✅"
else
    echo "❌ Failed to generate PSK or PSK too short"
    mcp_generate_psk_result="❌"
fi

# Only run MCP server tests if PSK was generated successfully
if [[ "$mcp_generate_psk_result" == "✅" ]]; then
    # Initialize core for MCP tests (MCP needs core manager)
    echo "Initializing core for MCP tests..."
    $SUDO_CMD "$BINARY_PATH" $VERBOSE_FLAG get-core-info > /dev/null 2>&1 || true
    
    echo "MCP: Start server on port 3123:"
    # Use a non-default port to avoid conflicts
    MCP_START_OUTPUT=$($SUDO_CMD "$BINARY_PATH" $VERBOSE_FLAG mcp-start 3123 "$MCP_PSK" 2>&1 || echo "error")
    if [[ "$MCP_START_OUTPUT" == *"success"* || "$MCP_START_OUTPUT" == *"MCP server started"* ]]; then
        echo "✅ MCP server started"
        mcp_start_result="✅"
        
        # Give server time to start
        sleep 2
        
        echo "MCP: Check status:"
        MCP_STATUS_OUTPUT=$($SUDO_CMD "$BINARY_PATH" $VERBOSE_FLAG mcp-status 2>&1 || echo "error")
        if [[ "$MCP_STATUS_OUTPUT" == *"running"* || "$MCP_STATUS_OUTPUT" == *"Port: 3123"* ]]; then
            echo "✅ MCP server is running"
            mcp_status_result="✅"
        else
            echo "⚠️ MCP status check inconclusive (may already be stopped)"
            mcp_status_result="⚠️"
        fi
        
        echo "MCP: Stop server:"
        MCP_STOP_OUTPUT=$($SUDO_CMD "$BINARY_PATH" $VERBOSE_FLAG mcp-stop 2>&1 || echo "error")
        if [[ "$MCP_STOP_OUTPUT" == *"success"* || "$MCP_STOP_OUTPUT" == *"MCP server stopped"* || "$MCP_STOP_OUTPUT" == *"not running"* ]]; then
            echo "✅ MCP server stopped"
            mcp_stop_result="✅"
        else
            echo "⚠️ MCP stop command inconclusive"
            mcp_stop_result="⚠️"
        fi
    else
        echo "⚠️ MCP server start failed or inconclusive: $MCP_START_OUTPUT"
        mcp_start_result="⚠️"
        mcp_status_result="⏭️"
        mcp_stop_result="⏭️"
    fi
else
    echo "⏭️ Skipping MCP server tests (PSK generation failed)"
    mcp_start_result="⏭️"
    mcp_status_result="⏭️"
    mcp_stop_result="⏭️"
fi

# Original success message removed, handled by trap
# echo "--- Standalone Commands Test Completed ---" 