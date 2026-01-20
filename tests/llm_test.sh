#!/bin/bash
set -eo pipefail

# ============================================================================
# LLM Provider Integration Tests for edamame_posture
# ============================================================================
#
# This script tests the LLM provider configuration in edamame_posture.
# It verifies that providers can be configured and start correctly.
#
# Required environment variables:
#   - ANTHROPIC_API_KEY: For Claude tests
#   - OPENAI_API_KEY: For OpenAI tests  
#   - EDAMAME_LLM_API_KEY: For EDAMAME Internal LLM tests
#
# Tests will be skipped if the corresponding API key is not set.
#
# Usage:
#   ./tests/llm_test.sh
#
# ============================================================================

# Track test results
claude_result="?"
openai_result="?"
edamame_result="?"

# Save original EDAMAME_LLM_API_KEY if set (for EDAMAME provider test)
ORIGINAL_EDAMAME_LLM_API_KEY="${EDAMAME_LLM_API_KEY:-}"

echo "=============================================="
echo "  LLM Provider Integration Tests"
echo "=============================================="
echo ""

# --- Configuration ---
FOUND_BINARY=$(find ./target -type f \( -name edamame_posture -o -name edamame_posture.exe \) -print -quit 2>/dev/null)

if [ -z "$FOUND_BINARY" ]; then
    echo "Error: Could not find 'edamame_posture' binary in ./target"
    echo "   Please build the project first: cargo build --release"
    exit 1
fi

BINARY_PATH="${BINARY_PATH:-$FOUND_BINARY}"
RUNNER_OS="${RUNNER_OS:-$(uname)}"
SUDO_CMD="${SUDO_CMD:-sudo -E}"

# OS-specific adjustments
if [[ "$RUNNER_OS" == "windows" || "$OS" == "Windows_NT" || "$OS" == "MINGW"* || "$OS" == "CYGWIN"* ]]; then
    BINARY_NAME="edamame_posture.exe"
    SUDO_CMD=""
else
    BINARY_NAME="edamame_posture"
    if ! command -v sudo &> /dev/null; then
        SUDO_CMD=""
    fi
fi

echo "Binary: $BINARY_PATH"
echo "OS: $RUNNER_OS"
echo ""

# --- Helper Functions ---

cleanup() {
    echo ""
    echo "Cleaning up..."
    $SUDO_CMD "$BINARY_PATH" stop 2>/dev/null || true
    sleep 2
}

trap cleanup EXIT

print_result() {
    local test_name="$1"
    local result="$2"
    if [ "$result" = "PASSED" ]; then
        echo "  $test_name: PASSED"
    elif [ "$result" = "SKIPPED" ]; then
        echo "  $test_name: SKIPPED"
    else
        echo "  $test_name: FAILED"
    fi
}

# --- Test Functions ---

test_provider() {
    local provider_name="$1"
    local provider_arg="$2"
    local expected_provider="$3"
    local api_key="$4"
    local result_var="$5"
    
    echo "----------------------------------------------"
    echo "Testing $provider_name Provider"
    echo "----------------------------------------------"
    
    if [ -z "$api_key" ]; then
        echo "Skipping $provider_name tests - API key not set"
        eval "$result_var=SKIPPED"
        return 0
    fi
    
    echo "Setting up $provider_name provider..."
    
    # Use EDAMAME_LLM_API_KEY for the provider
    export EDAMAME_LLM_API_KEY="$api_key"
    
    # Start in disconnected mode with provider (no & - command daemonizes itself)
    if $SUDO_CMD "$BINARY_PATH" background-start-disconnected \
        --agentic-mode analyze \
        --agentic-provider "$provider_arg"
    then
        echo "Waiting for daemon to initialize..."
        sleep 10  # Wait for initialization
        
        # Check daemon status
        if ! $SUDO_CMD "$BINARY_PATH" status 2>&1 | grep -qi "running"; then
            echo "Daemon not running after start"
            # Try to get more info
            $SUDO_CMD "$BINARY_PATH" status 2>&1 || true
            eval "$result_var=FAILED"
            $SUDO_CMD "$BINARY_PATH" stop 2>/dev/null || true
            sleep 3
            export EDAMAME_LLM_API_KEY="$ORIGINAL_EDAMAME_LLM_API_KEY"
            return 1
        fi
        
        echo "Daemon is running, checking agentic configuration..."
        
        # Check for provider configuration
        if SUMMARY=$($SUDO_CMD "$BINARY_PATH" agentic-summary 2>&1); then
            echo "Agentic summary retrieved"
            # Verify provider is configured correctly
            if echo "$SUMMARY" | grep -qi "Provider: $expected_provider"; then
                echo "$provider_name provider configured correctly"
                eval "$result_var=PASSED"
            else
                echo "$provider_name provider not found in summary"
                echo "Summary: $SUMMARY"
                eval "$result_var=FAILED"
            fi
        else
            echo "Failed to get agentic summary"
            echo "Output: $SUMMARY"
            eval "$result_var=FAILED"
        fi
        
        # Stop the process
        $SUDO_CMD "$BINARY_PATH" stop 2>/dev/null || true
        sleep 3
    else
        echo "Failed to start posture with $provider_name (exit code: $?)"
        eval "$result_var=FAILED"
    fi
    
    # Restore original EDAMAME_LLM_API_KEY
    export EDAMAME_LLM_API_KEY="$ORIGINAL_EDAMAME_LLM_API_KEY"
}

test_api_key_via_cli() {
    echo ""
    echo "----------------------------------------------"
    echo "Testing --llm-api-key CLI flag"
    echo "----------------------------------------------"
    
    # Test with any available key
    local test_key=""
    local provider=""
    
    if [ -n "$EDAMAME_LLM_API_KEY" ]; then
        test_key="$EDAMAME_LLM_API_KEY"
        provider="edamame"
    elif [ -n "$ANTHROPIC_API_KEY" ]; then
        test_key="$ANTHROPIC_API_KEY"
        provider="claude"
    elif [ -n "$OPENAI_API_KEY" ]; then
        test_key="$OPENAI_API_KEY"
        provider="openai"
    else
        echo "Skipping API key CLI test - no API keys available"
        return 0
    fi
    
    echo "Testing --llm-api-key flag with $provider provider..."
    
    # Start with --llm-api-key flag (short form -k) - no & as command daemonizes itself
    if $SUDO_CMD "$BINARY_PATH" background-start-disconnected \
        --agentic-mode analyze \
        --agentic-provider "$provider" \
        -k "$test_key"
    then
        echo "Waiting for daemon to initialize..."
        sleep 10
        
        # Check agentic summary
        if SUMMARY=$($SUDO_CMD "$BINARY_PATH" agentic-summary 2>&1); then
            echo "--llm-api-key CLI flag working"
            echo "   Provider: $provider"
        else
            echo "Could not verify --llm-api-key flag"
        fi
        
        # Stop the process
        $SUDO_CMD "$BINARY_PATH" stop 2>/dev/null || true
        sleep 3
    else
        echo "Failed to start with --llm-api-key flag (exit code: $?)"
    fi
}

# --- Run Tests ---

# Ensure clean state
$SUDO_CMD "$BINARY_PATH" stop 2>/dev/null || true
sleep 2

# Run provider tests
echo ""
test_provider "Claude" "claude" "claude" "$ANTHROPIC_API_KEY" "claude_result"
echo ""
test_provider "OpenAI" "openai" "openai" "$OPENAI_API_KEY" "openai_result"
echo ""
test_provider "EDAMAME Internal" "edamame" "internal" "$ORIGINAL_EDAMAME_LLM_API_KEY" "edamame_result"
test_api_key_via_cli

# --- Print Summary ---

echo ""
echo "=============================================="
echo "  Test Summary"
echo "=============================================="
echo ""
print_result "Claude Provider" "$claude_result"
print_result "OpenAI Provider" "$openai_result"
print_result "EDAMAME Internal Provider" "$edamame_result"
echo ""

# Determine overall exit code
failed=0
for result in "$claude_result" "$openai_result" "$edamame_result"; do
    if [ "$result" = "FAILED" ]; then
        failed=1
        break
    fi
done

if [ $failed -eq 1 ]; then
    echo "Some tests FAILED"
    exit 1
else
    echo "All tests PASSED (or skipped)"
    exit 0
fi
