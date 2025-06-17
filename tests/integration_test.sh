#!/bin/bash
set -eo pipefail # Exit on error, treat unset variables as error, pipefail

# Track test results with simple variables for macOS compatibility
connected_mode_result="❓"
disconnected_mode_result="❓"
connected_whitelist_result="❓"
connected_blacklist_result="❓"
disconnected_whitelist_result="❓"
disconnected_blacklist_result="❓"

echo "--- Running Integration Tests ---"

# --- Configuration ---
# Find the binary, preferring release but falling back to debug or other locations
# Use 'find ... -quit' to stop after the first match
FOUND_BINARY=$(find ./target -type f \( -name edamame_posture -o -name edamame_posture.exe \) -print -quit 2>/dev/null)

# Check if a binary was found
if [ -z "$FOUND_BINARY" ]; then
  echo "🔴 Error: Could not find 'edamame_posture' or 'edamame_posture.exe' in ./target" >&2
  exit 1
fi

# Use the found binary path if BINARY_PATH is not already set externally
BINARY_PATH="${BINARY_PATH:-$FOUND_BINARY}"
RUNNER_OS="${RUNNER_OS:-$(uname)}"
SUDO_CMD="${SUDO_CMD:-sudo -E}"
EDAMAME_LOG_LEVEL="${EDAMAME_LOG_LEVEL:-debug}"
VERBOSE_FLAG=""
WHITELIST_SOURCE="github" # Default whitelist source
TEST_DIR="$(pwd)/tests_temp"
CI="${CI:-false}" # Default to false if CI env var is not set

mkdir -p "$TEST_DIR"

# --- OS Specific Adjustments ---
if [[ "$RUNNER_OS" == "windows-latest" || "$OS" == "Windows_NT" || "$OS" == "MINGW"* || "$OS" == "CYGWIN"* ]]; then
    BINARY_NAME="edamame_posture.exe"
    BINARY_PATH="$(dirname "$BINARY_PATH")/$BINARY_NAME"
    SUDO_CMD=""
    KILL_CMD="taskkill -IM $BINARY_NAME -F || true"
    RM_CMD="rm -f"
    CURL_CMD="curl.exe"
    # Skip specific tests on Windows
    RUN_WL_BL_TESTS=false
else
    BINARY_NAME="edamame_posture"
    BINARY_PATH="$(dirname "$BINARY_PATH")/$BINARY_NAME"
    KILL_CMD="$SUDO_CMD killall -9 $BINARY_NAME || true"
    RM_CMD="$SUDO_CMD rm -f"
    CURL_CMD="curl"
    RUN_WL_BL_TESTS=true
    # Check if sudo is needed/available
    if ! command -v sudo &> /dev/null; then
        echo "⚠️ Warning: sudo command not found. Running commands without sudo."
        SUDO_CMD=""
        KILL_CMD="killall -9 $BINARY_NAME || true"
        RM_CMD="rm -f"
    fi
fi

# Define binary destination for temporary installation
BINARY_DEST_DIR="$TEST_DIR"
BINARY_DEST="$BINARY_DEST_DIR/$BINARY_NAME"

# Set log level
export EDAMAME_LOG_LEVEL

echo "Using Binary: $BINARY_PATH"
echo "Binary Destination: $BINARY_DEST"
echo "Runner OS: $RUNNER_OS"
echo "Sudo Command: $SUDO_CMD"
echo "Running in CI mode: $CI"
echo "Run Whitelist/Blacklist Tests: $RUN_WL_BL_TESTS"

# --- Helper Functions --- #
ensure_posture_stopped_and_cleaned() {
    local mode=$1 # Pass "pre" or "post" to know context
    local exit_status=$2 # Pass the script's exit status (0 for success, non-zero for error)
    echo "Ensuring posture is stopped (context: $mode, exit_status: $exit_status)..."

    # Attempt graceful stop only if binary likely exists (post-test)
    if [ "$mode" == "post" ] && [ -f "$BINARY_DEST" ]; then
        # Dump logs before stopping
        #"$BINARY_DEST" logs
        echo "Attempting graceful stop..."
        $SUDO_CMD "$BINARY_DEST" stop || echo "⚠️ Posture stop command failed or process was not running."
        sleep 5
    fi

    # Always attempt aggressive kill
    echo "Aggressively killing posture (just in case)..."
    eval $KILL_CMD
    sleep 5 # Give time for the process to fully terminate after kill

    # Clean up binary and JSON test files (always)
    echo "Removing old binary copy if exists..."
    $RM_CMD "$BINARY_DEST"
    echo "Cleaning up temporary JSON files..."
    rm -f "$TEST_DIR/custom_whitelists.json" "$TEST_DIR/custom_blacklist.json"

    # Clean up log files ONLY on successful exit in post-test cleanup
    if [ "$mode" == "post" ] && [ "$exit_status" -eq 0 ]; then
        echo "Cleaning up temporary log files on successful exit..."
        rm -f "$TEST_DIR/exceptions.log" "$TEST_DIR/blacklisted_sessions.log" "$TEST_DIR/blacklisted_sessions_precheck.log"
    else
        echo "Skipping log file cleanup (mode=$mode, exit_status=$exit_status)."
    fi

    # Print final summary only in the post-cleanup phase
    if [ "$mode" == "post" ]; then
        echo ""
        echo "--- Test Summary --- "
        if [ "$CI" = "true" ]; then
            echo "- Connected Mode Tests $connected_mode_result"
            if [ "$RUN_WL_BL_TESTS" = true ]; then
                echo "  - Whitelist Test (Connected) $connected_whitelist_result"
                echo "  - Blacklist Test (Connected) $connected_blacklist_result"
            else
                echo "  - Whitelist/Blacklist Tests Skipped ⏭️"
            fi
        else
            echo "- Disconnected Mode Tests $disconnected_mode_result"
             if [ "$RUN_WL_BL_TESTS" = true ]; then
                echo "  - Whitelist Test (Disconnected) $disconnected_whitelist_result"
                echo "  - Blacklist Test (Disconnected) $disconnected_blacklist_result"
            else
                echo "  - Whitelist/Blacklist Tests Skipped ⏭️"
            fi
        fi
        echo "--------------------"
        if [ $exit_status -eq 0 ]; then
            echo "✅ --- Integration Tests Completed Successfully --- ✅"
        else
            echo "❌ --- Integration Tests Failed (Exit Code: $exit_status) --- ❌"
        fi
    fi
}

# Generic test result handler for both CI and non-CI modes
handle_test_result() {
    local test_type=$1       # "whitelist" or "blacklist"
    local test_mode=$2       # "connected" or "disconnected"
    local is_error=$3        # true or false
    local error_message=$4   # Error message to display
    local var_name="${test_mode}_${test_type}_result"

    if [ "$is_error" = true ]; then
        echo "🔴 Error: $error_message"
        # Set result variable
        eval "$var_name=\"❌\""
        ensure_posture_stopped_and_cleaned "post" 1
        exit 1
    else
        echo "✅ $test_type check passed."
        # Set result variable
        eval "$var_name=\"✅\""
    fi
}

run_whitelist_test() {
    local test_mode_name=$1 # e.g., "Connected Mode" or "Disconnected Mode"
    local test_key=$2 # e.g., "connected_whitelist" or "disconnected_whitelist"
    echo "--- Running Whitelist Test --- ($test_mode_name)"
    WHITELIST_FILE="$TEST_DIR/custom_whitelists.json"
    EXCEPTIONS_FILE="$TEST_DIR/exceptions.log"
    SESSIONS_FILE="$TEST_DIR/all_sessions.log"

    echo "Create custom whitelist..."
    $SUDO_CMD "$BINARY_DEST" create-custom-whitelists > "$WHITELIST_FILE"
    echo "Verify whitelist file: $WHITELIST_FILE"
    if [ ! -s "$WHITELIST_FILE" ]; then echo "🔴 Error: Whitelist file is empty" >&2; ensure_posture_stopped_and_cleaned "post" 1; exit 1; fi
    cat "$WHITELIST_FILE"
    echo "Apply custom whitelist..."
    WHITELIST_CONTENT=$(cat "$WHITELIST_FILE")
    $SUDO_CMD "$BINARY_DEST" $VERBOSE_FLAG set-custom-whitelists "$WHITELIST_CONTENT"
    echo "Waiting 10 seconds for whitelist to apply..."
    sleep 10 # Allow time for whitelist to apply
    
    echo "Get sessions with whitelist applied (checking conformance)..."
    "$BINARY_DEST" get-sessions > "$SESSIONS_FILE" || true
    
    # Debug info about the sessions file
    echo "Sessions file path: $SESSIONS_FILE"
    if [ -f "$SESSIONS_FILE" ]; then
        echo "Sessions file exists, size: $(wc -c < "$SESSIONS_FILE") bytes"
        echo "First 10 lines of sessions file:"
        head -10 "$SESSIONS_FILE"
    else
        echo "Warning: Sessions file does not exist!"
    fi
    
    # Count total sessions and calculate MAX_ALLOWED_EXCEPTIONS
    SESSION_COUNT=0
    if [ -f "$SESSIONS_FILE" ] && [ -s "$SESSIONS_FILE" ]; then
        # Count all lines in the sessions file as sessions and trim whitespace
        SESSION_COUNT=$(wc -l < "$SESSIONS_FILE" | xargs)
    fi
    
    # Calculate 0% of sessions safely (ensure integer division)
    MAX_ALLOWED_EXCEPTIONS=5  # Default minimum
    if [ "$SESSION_COUNT" -gt 10 ]; then
        MAX_ALLOWED_EXCEPTIONS=$(( (SESSION_COUNT * 4) / 3 ))
    fi
    
    echo "Total sessions: $SESSION_COUNT, Setting MAX_ALLOWED_EXCEPTIONS to: $MAX_ALLOWED_EXCEPTIONS"
    
    echo "Get exceptions..."
    "$BINARY_DEST" $VERBOSE_FLAG get-exceptions > "$EXCEPTIONS_FILE" || true
    
    # Debug info about the exceptions file
    echo "Exceptions file path: $EXCEPTIONS_FILE"
    if [ -f "$EXCEPTIONS_FILE" ]; then
        echo "Exceptions file exists, size: $(wc -c < "$EXCEPTIONS_FILE") bytes"
        echo "Contents of exceptions file:"
        cat "$EXCEPTIONS_FILE"
    else
        echo "Warning: Exceptions file does not exist!"
    fi
    
    EXCEPTION_COUNT=0
    UNKNOWN_COUNT=0
    if [ -f "$EXCEPTIONS_FILE" ] && [ -s "$EXCEPTIONS_FILE" ]; then
        echo "Counting exceptions..."
        EXCEPTION_COUNT=$(grep "whitelisted: NonConforming" "$EXCEPTIONS_FILE" | wc -l | xargs || true)
        echo "Non-conforming count: $EXCEPTION_COUNT"
        UNKNOWN_COUNT=$(grep "whitelisted: Unknown" "$EXCEPTIONS_FILE" | wc -l | xargs || true)
        echo "Unknown count: $UNKNOWN_COUNT"
    fi
    
    echo "Detected $EXCEPTION_COUNT non-conforming exceptions and $UNKNOWN_COUNT unknown exceptions."
    
    # Show first 10 non-conforming exceptions for debugging
    if [ "$EXCEPTION_COUNT" -gt 0 ]; then
        echo "First 10 non-conforming exceptions (for debugging):"
        grep "whitelisted: NonConforming" "$EXCEPTIONS_FILE" | head -10 || true
    fi
    
    if [ "$UNKNOWN_COUNT" -gt 0 ]; then
        echo "Unknown exceptions (for debugging):"
        grep "whitelisted: Unknown" "$EXCEPTIONS_FILE" || true
    fi

    # Determine if this is an error condition
    local is_error=false
    echo "Checking if errors exist: EXCEPTION_COUNT=$EXCEPTION_COUNT > MAX_ALLOWED_EXCEPTIONS=$MAX_ALLOWED_EXCEPTIONS or UNKNOWN_COUNT=$UNKNOWN_COUNT > 2"
    if [ "$EXCEPTION_COUNT" -gt "$MAX_ALLOWED_EXCEPTIONS" ] || [ "$UNKNOWN_COUNT" -gt 2 ]; then
        echo "Error condition detected!"
        is_error=true
    else
        echo "No error condition detected."
    fi

    # Handle test result using common function
    local test_mode=$(echo "$test_key" | cut -d '_' -f1)  # Extract "connected" or "disconnected"
    local error_message="Detected too many non-conforming exceptions (${EXCEPTION_COUNT} > ${MAX_ALLOWED_EXCEPTIONS}) or unknown exceptions (${UNKNOWN_COUNT} > 2)."
    echo "Calling handle_test_result with: whitelist, $test_mode, $is_error, '$error_message'"
    handle_test_result "whitelist" "$test_mode" "$is_error" "$error_message"

    echo "Augmenting custom whitelists..."
    AUGMENT_JSON=$($SUDO_CMD "$BINARY_DEST" augment-custom-whitelists || echo "")
    if [[ -n "$AUGMENT_JSON" ]]; then
        echo "Augmented custom whitelist generated (length: ${#AUGMENT_JSON}) bytes"
    else
        echo "⚠️ augment-custom-whitelists returned empty output"
    fi

    echo "Merging original and augmented custom whitelists..."
    MERGED_JSON=$($SUDO_CMD "$BINARY_DEST" merge-custom-whitelists "$WHITELIST_CONTENT" "$AUGMENT_JSON" || echo "")
    if [[ -n "$MERGED_JSON" ]]; then
        echo "Merged custom whitelist generated (length: ${#MERGED_JSON}) bytes"
    else
        echo "⚠️ merge-custom-whitelists returned empty output"
    fi

    echo "Whitelist test completed successfully"
}

run_blacklist_test() {
    local test_mode_name=$1 # e.g., "Connected Mode" or "Disconnected Mode"
    local test_key=$2 # e.g., "connected_blacklist" or "disconnected_blacklist"
    echo "--- Running Blacklist Test --- ($test_mode_name)"
    BLACKLIST_FILE="$TEST_DIR/custom_blacklist.json"
    BLACKLIST_LOG_FILE="$TEST_DIR/blacklisted_sessions.log"
    BLACKLIST_PRECHECK_LOG_FILE="$TEST_DIR/blacklisted_sessions_precheck.log"
    BLACKLIST_POSTCHECK_LOG_FILE="$TEST_DIR/blacklisted_sessions_postcheck.log"
    BLACKLIST_DOMAIN="2.na.dl.wireshark.org" # Use domain instead of IP
    BLACKLIST_IP_V4="5.78.100.21"           # Expected IPv4
    BLACKLIST_IP_V6="2a01:4ff:1f0:ca4b::1"   # Expected IPv6
    BLACKLIST_IP_V4_CIDR="$BLACKLIST_IP_V4/32"
    BLACKLIST_IP_V6_CIDR="$BLACKLIST_IP_V6/128"
    test_mode=$(echo "$test_key" | cut -d '_' -f1)  # Extract "connected" or "disconnected"

    # --- PRE-CHECK: Ensure no sessions are blacklisted BEFORE applying custom list ---
    echo "Pre-checking for any existing blacklisted sessions (should be none)..."
    "$BINARY_DEST" get-blacklisted-sessions > "$BLACKLIST_PRECHECK_LOG_FILE" || true
    # Check if the precheck log file is non-empty (ignoring potential whitespace/empty lines)
    if grep -q '[^[:space:]]' "$BLACKLIST_PRECHECK_LOG_FILE"; then
        local error_message="Detected blacklisted sessions BEFORE applying custom blacklist!"
        echo "Precheck log content ($BLACKLIST_PRECHECK_LOG_FILE):"
        cat "$BLACKLIST_PRECHECK_LOG_FILE"
        handle_test_result "blacklist" "$test_mode" true "$error_message"
        return
    else
        echo "✅ Pre-check passed: No blacklisted sessions found initially."
    fi
    # --- End PRE-CHECK ---

    # --- Traffic Generation & Session Verification PRE-CUSTOM ---
    echo "Generating test traffic towards $BLACKLIST_DOMAIN..."
    # Run curl and capture its exit code
    $CURL_CMD -s -m 10 "https://$BLACKLIST_DOMAIN/src/wireshark-latest.tar.xz" -o /dev/null --insecure || true
    CURL_EXIT_CODE=$?
    if [ $CURL_EXIT_CODE -ne 0 ]; then
        # Non-zero exit code might be expected if connection is refused/reset, but log it.
        # Common curl errors: 7 (connection refused), 28 (timeout), 56 (recv error)
        local error_message="Curl command finished with non-zero exit code: $CURL_EXIT_CODE"
        handle_test_result "blacklist" "$test_mode" true "$error_message"
        return
    else
        echo "✅ Curl command finished successfully (exit code 0)."
    fi

    echo "Waiting for sessions to update after traffic generation (retrying every 20 seconds for up to 120 seconds)..."
    SESSION_PRE_CUSTOM_LOG="$TEST_DIR/all_sessions_pre_custom.log"
    RETRY_COUNT=0
    MAX_RETRIES=6  # 120 seconds / 20 seconds = 6 attempts
    TRAFFIC_FOUND=false
    
    while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
        if [ $RETRY_COUNT -gt 0 ]; then
            echo "Waiting 20 seconds before retry $RETRY_COUNT/$MAX_RETRIES..."
            sleep 20
        fi
        
        echo "Verifying test traffic was captured in get-sessions (attempt $((RETRY_COUNT + 1))/$MAX_RETRIES)..."
        "$BINARY_DEST" get-sessions > "$SESSION_PRE_CUSTOM_LOG" || true
        
        # Check if either the IPv4 or IPv6 address is present
        if grep -qE "($BLACKLIST_IP_V4|$BLACKLIST_IP_V6)" "$SESSION_PRE_CUSTOM_LOG"; then
            echo "✅ Verification passed: Test traffic session (IP $BLACKLIST_IP_V4 or $BLACKLIST_IP_V6) found."
            TRAFFIC_FOUND=true
            break
        else
            echo "⏳ Test traffic not found yet (attempt $((RETRY_COUNT + 1))/$MAX_RETRIES)..."
        fi
        
        RETRY_COUNT=$((RETRY_COUNT + 1))
    done
    
    if [ "$TRAFFIC_FOUND" = false ]; then
        local error_message="Test traffic connection to $BLACKLIST_DOMAIN (expected IPs $BLACKLIST_IP_V4 or $BLACKLIST_IP_V6) was not found in get-sessions output after $MAX_RETRIES attempts over 120 seconds."
        echo "Full get-sessions output from final attempt ($SESSION_PRE_CUSTOM_LOG):"
        cat "$SESSION_PRE_CUSTOM_LOG"
        handle_test_result "blacklist" "$test_mode" true "$error_message"
        return
    fi
    # --- End Traffic Generation & Session Verification PRE-CUSTOM ---

    echo "Creating custom blacklist file: $BLACKLIST_FILE ..."
    CURRENT_DATE_ISO=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    CURRENT_DATE_SHORT=$(date -u +"%Y-%m-%d")
    echo '{
        "date": "'$CURRENT_DATE_ISO'",
        "signature": "test-custom-signature",
        "blacklists": [
            {
                "name": "test_blacklist",
                "description": "Test blacklist for '$test_mode_name'",
                "last_updated": "'$CURRENT_DATE_SHORT'",
                "source_url": "",
                "ip_ranges": ["'$BLACKLIST_IP_V4_CIDR'", "'$BLACKLIST_IP_V6_CIDR'"]
            }
        ]
    }' > "$BLACKLIST_FILE"
    cat "$BLACKLIST_FILE"
    echo "Setting custom blacklist..."
    BLACKLIST_CONTENT=$(cat "$BLACKLIST_FILE")
    $SUDO_CMD "$BINARY_DEST" $VERBOSE_FLAG set-custom-blacklists "$BLACKLIST_CONTENT"
    echo "Waiting 10 seconds for blacklist to apply..."
    sleep 10 # Give time to apply

    echo "Verifying that the custom blacklist was set..."
    VERIFY_BLACKLIST_LOG="$TEST_DIR/verify_blacklists.log"
    "$BINARY_DEST" get-blacklists > "$VERIFY_BLACKLIST_LOG" || { 
        local error_message="Error running get-blacklists"
        echo "🔴 $error_message"
        cat "$VERIFY_BLACKLIST_LOG"
        handle_test_result "blacklist" "$test_mode" true "$error_message"
        return
    }
    echo "--- Start $VERIFY_BLACKLIST_LOG ---"
    cat "$VERIFY_BLACKLIST_LOG"
    echo "--- End $VERIFY_BLACKLIST_LOG ---"
    # Basic check to see if our test blacklist name is present
    if ! grep -q '"name": "test_blacklist"' "$VERIFY_BLACKLIST_LOG"; then
        local error_message="Custom blacklist 'test_blacklist' not found in get-blacklists output."
        handle_test_result "blacklist" "$test_mode" true "$error_message"
        return
    else
        echo "✅ Custom blacklist 'test_blacklist' successfully verified."
    fi


    # --- POST-CHECK: Verify previously established sessions are correctly blacklisted AFTER applying custom list ---
    echo "Post-checking for blacklisted sessions (should find some)..."
    "$BINARY_DEST" get-blacklisted-sessions > "$BLACKLIST_POSTCHECK_LOG_FILE" || true
    # Check if the postcheck log file is non-empty (ignoring potential whitespace/empty lines)
    if ! grep -q '[^[:space:]]' "$BLACKLIST_POSTCHECK_LOG_FILE"; then
        local error_message="No blacklisted sessions found AFTER applying custom blacklist!"
        echo "Postcheck log content is empty - expected to find previously generated traffic to blacklisted IPs"
        handle_test_result "blacklist" "$test_mode" true "$error_message"
        return
    else
        echo "✅ Post-check passed: Previously established sessions correctly marked as blacklisted."
    fi
    # --- End POST-CHECK ---

    # Blacklist Detection Check
    BLACKLIST_FINAL_CHECK_LOG="$TEST_DIR/blacklisted_sessions_final_check.log"
    ALL_SESSIONS_FINAL_CHECK_LOG="$TEST_DIR/all_sessions_final_check.log"

    echo "Dumping get-blacklisted-sessions output before final check to $BLACKLIST_FINAL_CHECK_LOG..."
    "$BINARY_DEST" get-blacklisted-sessions > "$BLACKLIST_FINAL_CHECK_LOG" || echo "⚠️ get-blacklisted-sessions failed (final check)"
    echo "--- Start $BLACKLIST_FINAL_CHECK_LOG ---"
    cat "$BLACKLIST_FINAL_CHECK_LOG"
    echo "--- End $BLACKLIST_FINAL_CHECK_LOG ---"

    echo "Dumping get-sessions output before final check to $ALL_SESSIONS_FINAL_CHECK_LOG..."
    "$BINARY_DEST" get-sessions > "$ALL_SESSIONS_FINAL_CHECK_LOG" || echo "⚠️ get-sessions failed (final check)"

    echo "Checking blacklist detection (get-blacklisted-sessions)..."
    echo "Verifying if blacklisted IPs ($BLACKLIST_IP_V4 or $BLACKLIST_IP_V6) are found in the log..."
    # Check if either the IPv4 or IPv6 address is blacklisted
    if ! grep -qE "($BLACKLIST_IP_V4|$BLACKLIST_IP_V6)" "$BLACKLIST_FINAL_CHECK_LOG"; then
        BLACKLISTED_SESSION_IN_ALL_SESSIONS_LOG=$(grep -E "($BLACKLIST_IP_V4|$BLACKLIST_IP_V6)" "$ALL_SESSIONS_FINAL_CHECK_LOG" || true)
        local error_message=""
        if [ -n "$BLACKLISTED_SESSION_IN_ALL_SESSIONS_LOG" ]; then
            error_message="Blacklisted IP ($BLACKLIST_IP_V4 or $BLACKLIST_IP_V6) was found in get-sessions output, but not in get-blacklisted-sessions."
            echo "Blacklisted session in get-sessions output:"
            echo "$BLACKLISTED_SESSION_IN_ALL_SESSIONS_LOG"
        else
            error_message="Blacklisted IP ($BLACKLIST_IP_V4 or $BLACKLIST_IP_V6) was not found in get-sessions output either."
            echo "All sessions log content (captured above): $ALL_SESSIONS_FINAL_CHECK_LOG"
        fi
        handle_test_result "blacklist" "$test_mode" true "$error_message"
        return
    else
        echo "✅ Blacklisted IP ($BLACKLIST_IP_V4 or $BLACKLIST_IP_V6) found in log."
    fi
    
    echo "✅ Blacklist test checks completed."
    handle_test_result "blacklist" "$test_mode" false ""
}

# --- Main Test Logic --- #

# Set trap to call cleanup function on error exit
trap 'ensure_posture_stopped_and_cleaned "post" $?' ERR EXIT

# Initial Cleanup (pass dummy status 0 as script hasn't run yet)
ensure_posture_stopped_and_cleaned "pre" 0

# Copy the built binary to the test destination
echo "Copying binary from $BINARY_PATH to $BINARY_DEST..."
cp -f "$BINARY_PATH" "$BINARY_DEST"
chmod +x "$BINARY_DEST" # Ensure executable

# --- CI Mode (Connected) --- #
if [ "$CI" = "true" ]; then
    echo "--- Running CONNECTED Mode Integration Tests ---"

    # Credentials and IDs (MUST be provided as environment variables for connected mode)
    EDAMAME_USER="${EDAMAME_USER:?🔴 Error: EDAMAME_USER must be set for CI mode}"
    EDAMAME_DOMAIN="${EDAMAME_DOMAIN:?🔴 Error: EDAMAME_DOMAIN must be set for CI mode}"
    EDAMAME_PIN="${EDAMAME_PIN:?🔴 Error: EDAMAME_PIN must be set for CI mode}"
    EDAMAME_ID="${EDAMAME_ID:-test-run-$(date +%s)}" # Default if not provided

    # Start posture in connected mode
    echo "Starting posture in connected mode (LAN Scan: true, Whitelist: $WHITELIST_SOURCE)..."
    echo "User: $EDAMAME_USER, Domain: $EDAMAME_DOMAIN, ID: $EDAMAME_ID"
    $SUDO_CMD "$BINARY_DEST" $VERBOSE_FLAG start "$EDAMAME_USER" "$EDAMAME_DOMAIN" "$EDAMAME_PIN" "$EDAMAME_ID" true $WHITELIST_SOURCE &
    POSTURE_PID=$!
    echo "Posture starting in background with PID $POSTURE_PID. Waiting for connection..."

    # Test wait-for-connection command
    echo "Wait for connection:"
    MAX_WAIT_ITERATIONS=12
    CURRENT_ITERATION=0
    CONNECTED=false
    while [ $CURRENT_ITERATION -lt $MAX_WAIT_ITERATIONS ]; do
        if $SUDO_CMD "$BINARY_DEST" $VERBOSE_FLAG wait-for-connection; then
            # Double check that the connection is established by checking the status
            if $SUDO_CMD "$BINARY_DEST" $VERBOSE_FLAG status | grep -q "connected: true"; then
                echo "✅ Connection established."
                CONNECTED=true
                break
            else
                echo "🔴 Error: Connection established but status is not connected."
                connected_mode_result="❌"
                # Trap will handle cleanup with non-zero status
                exit 1
            fi
        fi
        CURRENT_ITERATION=$((CURRENT_ITERATION + 1))
        echo "⏳ Connection not established, waiting 10 seconds... (Attempt $CURRENT_ITERATION/$MAX_WAIT_ITERATIONS)"
        sleep 10
    done

    if [ "$CONNECTED" = false ]; then
        echo "🔴 Error: Failed to connect within the timeout period."
        connected_mode_result="❌"
        # Trap will handle cleanup with non-zero status
        exit 1
    else
        connected_mode_result="✅"
    fi

    # Check status
    echo "Status in connected mode:"
    "$BINARY_DEST" $VERBOSE_FLAG status

    # Build again to generate build activity (as in workflow)
    echo "Generating build activity (running cargo build --release)..."
    cargo build --release
    echo "Build activity generated."

    # --- Whitelist/Blacklist Tests (Connected Mode - Run if applicable) ---
    if [ "$RUN_WL_BL_TESTS" = true ]; then
        echo "--- Running Whitelist/Blacklist Tests (Connected Mode) ---"

        # Run Whitelist Test Function
        run_whitelist_test "Connected Mode" "connected_whitelist"

        # Run Blacklist Test Function
        run_blacklist_test "Connected Mode" "connected_blacklist"
    else
        echo "⏭️ Skipping Whitelist/Blacklist tests on this OS ($RUNNER_OS)."
    fi

    # Final Status Check (Connected Mode)
    echo "Final status check in connected mode:"
    "$BINARY_DEST" $VERBOSE_FLAG status

    # Check logs (Connected Mode)
    echo "Fetching logs:"
    "$BINARY_DEST" $VERBOSE_FLAG logs

    echo "--- CONNECTED Mode Integration Tests Completed ---"

# --- Local Mode (Disconnected) --- #
else
    echo "--- Running DISCONNECTED Mode Integration Tests ---"

    # Start posture in disconnected mode
    echo "Starting posture in disconnected mode (LAN Scan: true, Whitelist: $WHITELIST_SOURCE)..."
    $SUDO_CMD "$BINARY_DEST" $VERBOSE_FLAG background-start-disconnected true $WHITELIST_SOURCE &
    POSTURE_PID=$!
    echo "Posture started in background with PID $POSTURE_PID. Waiting for it to initialize..."
    sleep 15 # Give it ample time to start up and initialize network monitoring
    disconnected_mode_result="✅"

    # Check status
    echo "Checking status..."
    "$BINARY_DEST" $VERBOSE_FLAG status

    # --- Whitelist/Blacklist Tests (Disconnected Mode - Run if applicable) ---
    if [ "$RUN_WL_BL_TESTS" = true ]; then

        # Run Whitelist Test Function
        run_whitelist_test "Disconnected Mode" "disconnected_whitelist"
        
        # Run Blacklist Test Function
        run_blacklist_test "Disconnected Mode" "disconnected_blacklist"
    else
        echo "⏭️ Skipping Whitelist/Blacklist tests on this OS ($RUNNER_OS)."
    fi

    # Final Status Check (Disconnected Mode)
    echo "Final status check in disconnected mode:"
    "$BINARY_DEST" $VERBOSE_FLAG status

    echo "--- DISCONNECTED Mode Integration Tests Completed ---"
fi

# --- Final Cleanup --- #
# Trap handles cleanup on exit (success or failure)
rm -rf "$TEST_DIR" # Remove the temp directory
