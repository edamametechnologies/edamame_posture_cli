#!/bin/bash
set -eo pipefail

list_result="?"
status_cursor_result="?"
status_claude_code_result="?"
status_claude_desktop_result="?"
status_openclaw_result="?"
status_invalid_result="?"
install_result="?"

finish() {
    local exit_status=$?
    echo ""
    echo "--- Agent Plugin Commands Test Summary ---"
    echo "  $list_result list-agent-plugins"
    echo "  $status_cursor_result agent-plugin-status cursor"
    echo "  $status_claude_code_result agent-plugin-status claude_code"
    echo "  $status_claude_desktop_result agent-plugin-status claude_desktop"
    echo "  $status_openclaw_result agent-plugin-status openclaw"
    echo "  $status_invalid_result agent-plugin-status invalid (expect error)"
    echo "  $install_result install-agent-plugin (network, optional)"
    echo "-------------------------------------------"
    if [ $exit_status -eq 0 ]; then
        echo "PASS --- Agent Plugin Commands Test Completed Successfully ---"
    else
        echo "FAIL --- Agent Plugin Commands Test Failed (Exit Code: $exit_status) ---"
    fi
}
trap finish EXIT

echo "--- Running Agent Plugin Commands Test ---"

FOUND_BINARY=$(find ./target -type f \( -name edamame_posture -o -name edamame_posture.exe \) -print -quit 2>/dev/null)
if [ -z "$FOUND_BINARY" ]; then
    echo "Error: Could not find edamame_posture binary in ./target" >&2
    exit 1
fi
BINARY_PATH="${BINARY_PATH:-$FOUND_BINARY}"
VERBOSE_FLAG="-v"

echo "Using binary: $BINARY_PATH"
echo ""

# --- Test: list-agent-plugins ---
echo "=== Testing list-agent-plugins ==="
LIST_OUTPUT=$("$BINARY_PATH" $VERBOSE_FLAG list-agent-plugins 2>&1) || {
    echo "FAIL: list-agent-plugins returned non-zero exit code"
    exit 1
}
echo "$LIST_OUTPUT"

FOUND_CURSOR=$(echo "$LIST_OUTPUT" | grep -c "cursor" || true)
FOUND_CLAUDE=$(echo "$LIST_OUTPUT" | grep -c "claude_code" || true)
FOUND_CLAUDE_DESKTOP=$(echo "$LIST_OUTPUT" | grep -c "claude_desktop" || true)
FOUND_OPENCLAW=$(echo "$LIST_OUTPUT" | grep -c "openclaw" || true)

if [ "$FOUND_CURSOR" -ge 1 ] && [ "$FOUND_CLAUDE" -ge 1 ] && [ "$FOUND_CLAUDE_DESKTOP" -ge 1 ] && [ "$FOUND_OPENCLAW" -ge 1 ]; then
    echo "PASS: list-agent-plugins output contains all four agent types"
    list_result="PASS"
else
    echo "FAIL: list-agent-plugins output missing agent types (cursor=$FOUND_CURSOR, claude_code=$FOUND_CLAUDE, claude_desktop=$FOUND_CLAUDE_DESKTOP, openclaw=$FOUND_OPENCLAW)"
    exit 1
fi
echo ""

# --- Test: agent-plugin-status for each valid type ---
for agent_type in cursor claude_code claude_desktop openclaw; do
    echo "=== Testing agent-plugin-status $agent_type ==="
    STATUS_OUTPUT=$("$BINARY_PATH" $VERBOSE_FLAG agent-plugin-status "$agent_type" 2>&1) || {
        echo "FAIL: agent-plugin-status $agent_type returned non-zero exit code"
        exit 1
    }
    echo "$STATUS_OUTPUT"

    if echo "$STATUS_OUTPUT" | grep -q "$agent_type"; then
        echo "PASS: agent-plugin-status $agent_type returned output containing agent type"
        eval "status_${agent_type}_result=PASS"
    else
        echo "FAIL: agent-plugin-status $agent_type output does not contain agent type"
        exit 1
    fi
    echo ""
done

# --- Test: agent-plugin-status with invalid type (should fail) ---
echo "=== Testing agent-plugin-status with invalid type ==="
if "$BINARY_PATH" $VERBOSE_FLAG agent-plugin-status invalid_type 2>&1; then
    echo "FAIL: agent-plugin-status invalid_type should have been rejected by clap"
    exit 1
else
    echo "PASS: agent-plugin-status invalid_type correctly rejected"
    status_invalid_result="PASS"
fi
echo ""

# --- Test: install-agent-plugin (optional, network-dependent) ---
if [ "${TEST_AGENT_INSTALL:-0}" = "1" ]; then
    echo "=== Testing install-agent-plugin openclaw (network required) ==="
    INSTALL_OUTPUT=$("$BINARY_PATH" $VERBOSE_FLAG install-agent-plugin openclaw 2>&1) || {
        echo "FAIL: install-agent-plugin openclaw returned non-zero exit code"
        install_result="FAIL"
        exit 1
    }
    echo "$INSTALL_OUTPUT"
    if echo "$INSTALL_OUTPUT" | grep -qi "success\|installed"; then
        echo "PASS: install-agent-plugin openclaw succeeded"
        install_result="PASS"
    else
        echo "WARN: install-agent-plugin output did not contain success marker"
        install_result="WARN"
    fi
else
    echo "=== Skipping install-agent-plugin (set TEST_AGENT_INSTALL=1 to enable) ==="
    install_result="SKIP"
fi
echo ""

echo "--- Agent Plugin Commands Test Complete ---"
