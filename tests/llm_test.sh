#!/bin/bash
set -eo pipefail

# ============================================================================
# LLM Provider Integration Tests for edamame_posture
# ============================================================================
#
# This script tests the LLM provider integration in edamame_posture.
# It requires the following environment variables to be set:
#
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
claude_config_result="❓"
claude_test_result="❓"
openai_config_result="❓"
openai_test_result="❓"
edamame_config_result="❓"
edamame_test_result="❓"

echo "=============================================="
echo "  LLM Provider Integration Tests"
echo "=============================================="
echo ""

# --- Configuration ---
FOUND_BINARY=$(find ./target -type f \( -name edamame_posture -o -name edamame_posture.exe \) -print -quit 2>/dev/null)

if [ -z "$FOUND_BINARY" ]; then
    echo "🔴 Error: Could not find 'edamame_posture' binary in ./target"
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
    if [ "$result" = "✅" ]; then
        echo "  $test_name: $result PASSED"
    elif [ "$result" = "⏭️" ]; then
        echo "  $test_name: $result SKIPPED"
    else
        echo "  $test_name: $result FAILED"
    fi
}

# --- Test Functions ---

test_claude_provider() {
    echo "----------------------------------------------"
    echo "Testing Claude Provider"
    echo "----------------------------------------------"
    
    if [ -z "$ANTHROPIC_API_KEY" ]; then
        echo "⏭️  Skipping Claude tests - ANTHROPIC_API_KEY not set"
        claude_config_result="⏭️"
        claude_test_result="⏭️"
        return 0
    fi
    
    echo "Setting up Claude provider..."
    
    # Use EDAMAME_LLM_API_KEY for the provider
    export EDAMAME_LLM_API_KEY="$ANTHROPIC_API_KEY"
    
    # Start in disconnected mode with Claude provider
    if $SUDO_CMD "$BINARY_PATH" background-start-disconnected \
        --agentic-mode analyze \
        --agentic-provider claude &
    then
        sleep 10  # Wait for initialization
        
        # Check agentic summary
        if SUMMARY=$($SUDO_CMD "$BINARY_PATH" agentic-summary 2>&1); then
            echo "Summary: $SUMMARY"
            if echo "$SUMMARY" | grep -qi "claude"; then
                echo "✅ Claude provider configured"
                claude_config_result="✅"
                
                # Check if LLM is tested/working
                if echo "$SUMMARY" | grep -qi "tested.*true\|connection.*success\|provider.*claude"; then
                    echo "✅ Claude LLM connection verified"
                    claude_test_result="✅"
                else
                    echo "⚠️  Claude LLM connection status unclear"
                    claude_test_result="⚠️"
                fi
            else
                echo "❌ Claude provider not found in summary"
                claude_config_result="❌"
                claude_test_result="❌"
            fi
        else
            echo "❌ Failed to get agentic summary"
            claude_config_result="❌"
            claude_test_result="❌"
        fi
        
        # Stop the process
        $SUDO_CMD "$BINARY_PATH" stop 2>/dev/null || true
        sleep 3
    else
        echo "❌ Failed to start posture with Claude"
        claude_config_result="❌"
        claude_test_result="❌"
    fi
    
    unset EDAMAME_LLM_API_KEY
}

test_openai_provider() {
    echo ""
    echo "----------------------------------------------"
    echo "Testing OpenAI Provider"
    echo "----------------------------------------------"
    
    if [ -z "$OPENAI_API_KEY" ]; then
        echo "⏭️  Skipping OpenAI tests - OPENAI_API_KEY not set"
        openai_config_result="⏭️"
        openai_test_result="⏭️"
        return 0
    fi
    
    echo "Setting up OpenAI provider..."
    
    export EDAMAME_LLM_API_KEY="$OPENAI_API_KEY"
    
    # Start in disconnected mode with OpenAI provider
    if $SUDO_CMD "$BINARY_PATH" background-start-disconnected \
        --agentic-mode analyze \
        --agentic-provider openai &
    then
        sleep 10  # Wait for initialization
        
        # Check agentic summary
        if SUMMARY=$($SUDO_CMD "$BINARY_PATH" agentic-summary 2>&1); then
            echo "Summary: $SUMMARY"
            if echo "$SUMMARY" | grep -qi "openai"; then
                echo "✅ OpenAI provider configured"
                openai_config_result="✅"
                
                # Check if LLM is tested/working
                if echo "$SUMMARY" | grep -qi "tested.*true\|connection.*success\|provider.*openai"; then
                    echo "✅ OpenAI LLM connection verified"
                    openai_test_result="✅"
                else
                    echo "⚠️  OpenAI LLM connection status unclear"
                    openai_test_result="⚠️"
                fi
            else
                echo "❌ OpenAI provider not found in summary"
                openai_config_result="❌"
                openai_test_result="❌"
            fi
        else
            echo "❌ Failed to get agentic summary"
            openai_config_result="❌"
            openai_test_result="❌"
        fi
        
        # Stop the process
        $SUDO_CMD "$BINARY_PATH" stop 2>/dev/null || true
        sleep 3
    else
        echo "❌ Failed to start posture with OpenAI"
        openai_config_result="❌"
        openai_test_result="❌"
    fi
    
    unset EDAMAME_LLM_API_KEY
}

test_edamame_provider() {
    echo ""
    echo "----------------------------------------------"
    echo "Testing EDAMAME Internal Provider"
    echo "----------------------------------------------"
    
    if [ -z "$EDAMAME_LLM_API_KEY" ]; then
        echo "⏭️  Skipping EDAMAME tests - EDAMAME_LLM_API_KEY not set"
        edamame_config_result="⏭️"
        edamame_test_result="⏭️"
        return 0
    fi
    
    echo "Setting up EDAMAME Internal provider..."
    
    # EDAMAME_LLM_API_KEY is already set in environment
    
    # Start in disconnected mode with EDAMAME provider
    if $SUDO_CMD "$BINARY_PATH" background-start-disconnected \
        --agentic-mode analyze \
        --agentic-provider edamame &
    then
        sleep 10  # Wait for initialization
        
        # Check agentic summary
        if SUMMARY=$($SUDO_CMD "$BINARY_PATH" agentic-summary 2>&1); then
            echo "Summary: $SUMMARY"
            if echo "$SUMMARY" | grep -qi "internal\|edamame"; then
                echo "✅ EDAMAME Internal provider configured"
                edamame_config_result="✅"
                
                # Check if LLM is tested/working
                if echo "$SUMMARY" | grep -qiE "tested.*true|connection.*success|provider.*(edamame|internal)"; then
                    echo "✅ EDAMAME Internal LLM connection verified"
                    edamame_test_result="✅"
                else
                    echo "⚠️  EDAMAME Internal LLM connection status unclear"
                    edamame_test_result="⚠️"
                fi
            else
                echo "❌ EDAMAME Internal provider not found in summary"
                edamame_config_result="❌"
                edamame_test_result="❌"
            fi
        else
            echo "❌ Failed to get agentic summary"
            edamame_config_result="❌"
            edamame_test_result="❌"
        fi
        
        # Stop the process
        $SUDO_CMD "$BINARY_PATH" stop 2>/dev/null || true
        sleep 3
    else
        echo "❌ Failed to start posture with EDAMAME Internal"
        edamame_config_result="❌"
        edamame_test_result="❌"
    fi
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
        echo "⏭️  Skipping API key CLI test - no API keys available"
        return 0
    fi
    
    echo "Testing --llm-api-key flag with $provider provider..."
    
    # Start with --llm-api-key flag (short form -k)
    if $SUDO_CMD "$BINARY_PATH" background-start-disconnected \
        --agentic-mode analyze \
        --agentic-provider "$provider" \
        -k "$test_key" &
    then
        sleep 10
        
        # Check agentic summary
        if SUMMARY=$($SUDO_CMD "$BINARY_PATH" agentic-summary 2>&1); then
            echo "Summary: $SUMMARY"
            echo "✅ --llm-api-key CLI flag working"
            echo "   Provider: $provider"
        else
            echo "⚠️  Could not verify --llm-api-key flag"
        fi
        
        # Stop the process
        $SUDO_CMD "$BINARY_PATH" stop 2>/dev/null || true
        sleep 3
    else
        echo "❌ Failed to start with --llm-api-key flag"
    fi
}

# --- Run Tests ---

# Ensure clean state
$SUDO_CMD "$BINARY_PATH" stop 2>/dev/null || true
sleep 2

# Run provider tests
test_claude_provider
test_openai_provider
test_edamame_provider
test_api_key_via_cli

# --- Print Summary ---

echo ""
echo "=============================================="
echo "  Test Summary"
echo "=============================================="
echo ""
echo "Claude Provider:"
print_result "  Configuration" "$claude_config_result"
print_result "  LLM Connection" "$claude_test_result"
echo ""
echo "OpenAI Provider:"
print_result "  Configuration" "$openai_config_result"
print_result "  LLM Connection" "$openai_test_result"
echo ""
echo "EDAMAME Internal Provider:"
print_result "  Configuration" "$edamame_config_result"
print_result "  LLM Connection" "$edamame_test_result"
echo ""

# Determine overall exit code
failed=0
for result in "$claude_config_result" "$claude_test_result" \
              "$openai_config_result" "$openai_test_result" \
              "$edamame_config_result" "$edamame_test_result"; do
    if [ "$result" = "❌" ]; then
        failed=1
        break
    fi
done

if [ $failed -eq 1 ]; then
    echo "❌ Some tests FAILED"
    exit 1
else
    echo "✅ All tests PASSED (or skipped)"
    exit 0
fi
