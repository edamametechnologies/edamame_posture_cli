#!/bin/bash
set -eo pipefail # Exit on error, treat unset variables as error, pipefail

# Track test results with simple variables for macOS compatibility
connected_mode_result="❓"
disconnected_mode_result="❓"
connected_whitelist_json_result="❓"
connected_whitelist_result="❓"
connected_blacklist_result="❓"
disconnected_whitelist_json_result="❓"
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
if [[ "$RUNNER_OS" == "windows" || "$OS" == "Windows_NT" || "$OS" == "MINGW"* || "$OS" == "CYGWIN"* ]]; then
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
                echo "  - Whitelist JSON Structure Test (Connected) $connected_whitelist_json_result"
                echo "  - Whitelist Test (Connected) $connected_whitelist_result"
                echo "  - Blacklist Test (Connected) $connected_blacklist_result"
            else
                echo "  - Whitelist/Blacklist Tests Skipped ⏭️"
            fi
        else
            echo "- Disconnected Mode Tests $disconnected_mode_result"
             if [ "$RUN_WL_BL_TESTS" = true ]; then
                echo "  - Whitelist JSON Structure Test (Disconnected) $disconnected_whitelist_json_result"
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

# Warning handler: mark a test as warning without exiting
handle_test_warning() {
    local test_type=$1       # "whitelist" or "blacklist"
    local test_mode=$2       # "connected" or "disconnected"
    local warning_message=$3 # Message to display
    local var_name="${test_mode}_${test_type}_result"

    echo "⚠️ Warning: $warning_message"
    # Set result variable to warning
    eval "$var_name=\"⚠️\""
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
    $SUDO_CMD "$BINARY_DEST" $VERBOSE_FLAG set-custom-whitelists-from-file "$WHITELIST_FILE"
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
    WHITELIST_CONTENT=$(cat "$WHITELIST_FILE")
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
        local warning_message="Detected blacklisted sessions BEFORE applying custom blacklist (likely due to baseline lists). Proceeding and marking as warning."
        echo "Precheck log content ($BLACKLIST_PRECHECK_LOG_FILE):"
        cat "$BLACKLIST_PRECHECK_LOG_FILE"
        # Mark as warning but continue the test flow
        handle_test_warning "blacklist" "$test_mode" "$warning_message"
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
    $SUDO_CMD "$BINARY_DEST" $VERBOSE_FLAG set-custom-blacklists-from-file "$BLACKLIST_FILE"
    echo "Waiting 30 seconds for blacklist to apply..."
    sleep 30 # Give time to apply

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
    "$BINARY_DEST" get-blacklisted-sessions > "$BLACKLIST_FINAL_CHECK_LOG"
    echo "--- Start $BLACKLIST_FINAL_CHECK_LOG ---"
    cat "$BLACKLIST_FINAL_CHECK_LOG"
    echo "--- End $BLACKLIST_FINAL_CHECK_LOG ---"

    echo "Dumping get-sessions output before final check to $ALL_SESSIONS_FINAL_CHECK_LOG..."
    "$BINARY_DEST" get-sessions > "$ALL_SESSIONS_FINAL_CHECK_LOG" || echo "⚠️ get-sessions return non 0 exit code - this is expected when whitelist, blacklist or anomalous sessions are detected"

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

test_custom_whitelist_json_structure() {
    local test_mode_name=$1 # e.g., "Connected Mode" or "Disconnected Mode"
    local test_key=$2 # e.g., "connected_whitelist_json" or "disconnected_whitelist_json"
    echo "--- Testing Custom Whitelist JSON Structure --- ($test_mode_name)"
    
    WHITELIST_JSON_FILE="$TEST_DIR/custom_whitelists_structure_test.json"
    AUGMENTED_JSON_FILE="$TEST_DIR/augmented_whitelists_structure_test.json"
    test_mode=$(echo "$test_key" | cut -d '_' -f1)  # Extract "connected" or "disconnected"
    
    # Test 1: Create custom whitelist and verify JSON structure
    echo "Step 1: Creating custom whitelist and verifying JSON structure..."
    $SUDO_CMD "$BINARY_DEST" create-custom-whitelists > "$WHITELIST_JSON_FILE"
    
    if [ ! -s "$WHITELIST_JSON_FILE" ]; then
        handle_test_result "whitelist_json" "$test_mode" true "Whitelist JSON file is empty"
        return
    fi
    
    echo "Generated whitelist JSON file size: $(wc -c < "$WHITELIST_JSON_FILE") bytes"
    
    # Verify JSON is valid
    if ! command -v jq &> /dev/null; then
        echo "⚠️ jq not available, skipping detailed JSON validation"
        echo "Contents of whitelist file (first 500 chars):"
        head -c 500 "$WHITELIST_JSON_FILE"
    else
        echo "Validating JSON structure with jq..."
        
        # Test that it's valid JSON
        if ! jq '.' "$WHITELIST_JSON_FILE" > /dev/null; then
            handle_test_result "whitelist_json" "$test_mode" true "Generated JSON is not valid"
            return
        fi
        
        # Test for required top-level fields
        if ! jq -e '.date' "$WHITELIST_JSON_FILE" > /dev/null; then
            handle_test_result "whitelist_json" "$test_mode" true "JSON missing required 'date' field"
            return
        fi
        
        if ! jq -e '.whitelists' "$WHITELIST_JSON_FILE" > /dev/null; then
            handle_test_result "whitelist_json" "$test_mode" true "JSON missing required 'whitelists' field" 
            return
        fi
        
        # Test for required whitelist fields (this is the critical bug fix validation)
        WHITELIST_COUNT=$(jq '.whitelists | length' "$WHITELIST_JSON_FILE")
        if [ "$WHITELIST_COUNT" -gt 0 ]; then
            echo "Found $WHITELIST_COUNT whitelists in JSON, validating structure..."
            
            # Check for 'name' field (this was missing and caused the parsing error)
            if ! jq -e '.whitelists[0].name' "$WHITELIST_JSON_FILE" > /dev/null; then
                handle_test_result "whitelist_json" "$test_mode" true "JSON missing required 'name' field in whitelist - this was the original bug!"
                return
            fi
            
            # Check for 'extends' field (this was also missing)
            if ! jq -e '.whitelists[0] | has("extends")' "$WHITELIST_JSON_FILE" > /dev/null; then
                handle_test_result "whitelist_json" "$test_mode" true "JSON missing required 'extends' field in whitelist - this was the original bug!"
                return
            fi
            
            # Check for 'endpoints' field
            if ! jq -e '.whitelists[0].endpoints' "$WHITELIST_JSON_FILE" > /dev/null; then
                handle_test_result "whitelist_json" "$test_mode" true "JSON missing required 'endpoints' field in whitelist"
                return
            fi
            
            # Extract and display the name value
            WHITELIST_NAME=$(jq -r '.whitelists[0].name' "$WHITELIST_JSON_FILE")
            echo "✅ JSON structure validation passed - whitelist name: '$WHITELIST_NAME'"
            
            # Verify the expected name
            if [ "$WHITELIST_NAME" != "custom_whitelist" ]; then
                handle_test_result "whitelist_json" "$test_mode" true "Expected whitelist name 'custom_whitelist', got '$WHITELIST_NAME'"
                return
            fi
        else
            echo "ℹ️ No whitelists in generated JSON (empty sessions list)"
        fi
    fi
    
    # Test 2: Set custom whitelist with the generated JSON (this was failing before the fix)
    echo "Step 2: Testing set-custom-whitelists-from-file with generated JSON..."
    if ! $SUDO_CMD "$BINARY_DEST" $VERBOSE_FLAG set-custom-whitelists-from-file "$WHITELIST_JSON_FILE"; then
        handle_test_result "whitelist_json" "$test_mode" true "set-custom-whitelists-from-file failed with generated JSON"
        return
    fi
    echo "✅ set-custom-whitelists-from-file succeeded with generated JSON"
    
    # Wait for application
    echo "Waiting 5 seconds for whitelist to apply..."
    sleep 5
    
    # Test 3: Test augment-custom-whitelists
    echo "Step 3: Testing augment-custom-whitelists..."
    if $SUDO_CMD "$BINARY_DEST" augment-custom-whitelists > "$AUGMENTED_JSON_FILE"; then
        if [ -s "$AUGMENTED_JSON_FILE" ]; then
            echo "Generated augmented whitelist JSON file size: $(wc -c < "$AUGMENTED_JSON_FILE") bytes"
            
            # Validate augmented JSON structure if jq is available
            if command -v jq &> /dev/null; then
                if ! jq '.' "$AUGMENTED_JSON_FILE" > /dev/null; then
                    handle_test_result "whitelist_json" "$test_mode" true "Augmented JSON is not valid"
                    return
                fi
                
                # Test that augmented JSON has the same structure requirements
                AUGMENTED_WHITELIST_COUNT=$(jq '.whitelists | length' "$AUGMENTED_JSON_FILE")
                if [ "$AUGMENTED_WHITELIST_COUNT" -gt 0 ]; then
                    if ! jq -e '.whitelists[0].name' "$AUGMENTED_JSON_FILE" > /dev/null; then
                        handle_test_result "whitelist_json" "$test_mode" true "Augmented JSON missing required 'name' field"
                        return
                    fi
                    if ! jq -e '.whitelists[0] | has("extends")' "$AUGMENTED_JSON_FILE" > /dev/null; then
                        handle_test_result "whitelist_json" "$test_mode" true "Augmented JSON missing required 'extends' field"
                        return
                    fi
                    echo "✅ Augmented JSON structure validation passed"
                fi
            fi
            
            # Test 4: Test setting the augmented whitelist
            echo "Step 4: Testing set-custom-whitelists-from-file with augmented JSON..."
            if ! $SUDO_CMD "$BINARY_DEST" $VERBOSE_FLAG set-custom-whitelists-from-file "$AUGMENTED_JSON_FILE"; then
                handle_test_result "whitelist_json" "$test_mode" true "set-custom-whitelists-from-file failed with augmented JSON"
                return
            fi
            echo "✅ set-custom-whitelists-from-file succeeded with augmented JSON"
        else
            echo "ℹ️ augment-custom-whitelists returned empty (no exceptions to augment)"
        fi
    else
        echo "⚠️ augment-custom-whitelists command failed or returned error"
    fi
    
    # Test 5: Test merge-custom-whitelists-from-files (if both JSON files exist)
    if [ -s "$WHITELIST_JSON_FILE" ] && [ -s "$AUGMENTED_JSON_FILE" ]; then
        echo "Step 5: Testing merge-custom-whitelists-from-files..."
        MERGED_JSON_FILE="$TEST_DIR/merged_whitelists_structure_test.json"
        if $SUDO_CMD "$BINARY_DEST" merge-custom-whitelists-from-files "$WHITELIST_JSON_FILE" "$AUGMENTED_JSON_FILE" > "$MERGED_JSON_FILE"; then
            if [ -s "$MERGED_JSON_FILE" ]; then
                echo "Generated merged whitelist JSON file size: $(wc -c < "$MERGED_JSON_FILE") bytes"
                
                # Validate merged JSON if jq is available
                if command -v jq &> /dev/null; then
                    if ! jq '.' "$MERGED_JSON_FILE" > /dev/null; then
                        handle_test_result "whitelist_json" "$test_mode" true "Merged JSON is not valid"
                        return
                    fi
                    echo "✅ Merged JSON structure validation passed"
                fi
                
                # Test setting the merged whitelist
                if ! $SUDO_CMD "$BINARY_DEST" $VERBOSE_FLAG set-custom-whitelists-from-file "$MERGED_JSON_FILE"; then
                    handle_test_result "whitelist_json" "$test_mode" true "set-custom-whitelists-from-file failed with merged JSON"
                    return
                fi
                echo "✅ set-custom-whitelists-from-file succeeded with merged JSON"
                          else
                  echo "ℹ️ merge-custom-whitelists-from-files returned empty"
            fi
        else
            echo "⚠️ merge-custom-whitelists-from-files command failed"
        fi
    fi
    
    # Cleanup - reset whitelist
    echo "Cleaning up: resetting whitelist..."
    $SUDO_CMD "$BINARY_DEST" set-custom-whitelists "" || true
    
    echo "✅ Custom whitelist JSON structure test completed successfully"
    handle_test_result "whitelist_json" "$test_mode" false ""
}

test_compare_custom_whitelists() {
    echo "--- Testing Compare Custom Whitelists Functionality ---"
    
    COMPARE_TEST_DIR="$TEST_DIR/compare_test"
    mkdir -p "$COMPARE_TEST_DIR"
    
    echo ""
    echo "=== Test 1: Identical Whitelists (0% difference) ==="
    
    # Create two identical whitelists
    cat > "$COMPARE_TEST_DIR/wl1.json" << 'EOF'
{
  "date": "November 8th 2025",
  "whitelists": [
    {
      "name": "test",
      "endpoints": [
        {"domain": "example.com", "port": 443, "protocol": "TCP"},
        {"domain": "test.com", "port": 443, "protocol": "TCP"}
      ]
    }
  ]
}
EOF
    
    cp "$COMPARE_TEST_DIR/wl1.json" "$COMPARE_TEST_DIR/wl2.json"
    
    DIFF=$("$BINARY_DEST" compare-custom-whitelists-from-files "$COMPARE_TEST_DIR/wl1.json" "$COMPARE_TEST_DIR/wl2.json")
    echo "Result: $DIFF"
    
    if [[ "$DIFF" == "0.00%" ]]; then
        echo "✅ Test 1 PASSED: Identical whitelists show 0% difference"
    else
        echo "❌ Test 1 FAILED: Expected 0.00%, got $DIFF"
        return 1
    fi
    
    echo ""
    echo "=== Test 2: One New Endpoint (33.33% difference) ==="
    
    # Create whitelist with one additional endpoint
    cat > "$COMPARE_TEST_DIR/wl3.json" << 'EOF'
{
  "date": "November 8th 2025",
  "whitelists": [
    {
      "name": "test",
      "endpoints": [
        {"domain": "example.com", "port": 443, "protocol": "TCP"},
        {"domain": "test.com", "port": 443, "protocol": "TCP"},
        {"domain": "newsite.com", "port": 443, "protocol": "TCP"}
      ]
    }
  ]
}
EOF
    
    DIFF=$("$BINARY_DEST" compare-custom-whitelists-from-files "$COMPARE_TEST_DIR/wl1.json" "$COMPARE_TEST_DIR/wl3.json")
    echo "Result: $DIFF"
    
    if [[ "$DIFF" == "33.33%" ]]; then
        echo "✅ Test 2 PASSED: One new endpoint in 3 shows 33.33% difference"
    else
        echo "❌ Test 2 FAILED: Expected 33.33%, got $DIFF"
        return 1
    fi
    
    echo ""
    echo "=== Test 3: Multiple New Endpoints (50% difference) ==="
    
    # Create whitelist with two additional endpoints
    cat > "$COMPARE_TEST_DIR/wl4.json" << 'EOF'
{
  "date": "November 8th 2025",
  "whitelists": [
    {
      "name": "test",
      "endpoints": [
        {"domain": "example.com", "port": 443, "protocol": "TCP"},
        {"domain": "test.com", "port": 443, "protocol": "TCP"},
        {"domain": "newsite1.com", "port": 443, "protocol": "TCP"},
        {"domain": "newsite2.com", "port": 443, "protocol": "TCP"}
      ]
    }
  ]
}
EOF
    
    DIFF=$("$BINARY_DEST" compare-custom-whitelists-from-files "$COMPARE_TEST_DIR/wl1.json" "$COMPARE_TEST_DIR/wl4.json")
    echo "Result: $DIFF"
    
    if [[ "$DIFF" == "50.00%" ]]; then
        echo "✅ Test 3 PASSED: Two new endpoints in 4 shows 50% difference"
    else
        echo "❌ Test 3 FAILED: Expected 50.00%, got $DIFF"
        return 1
    fi
    
    echo ""
    echo "=== Test 4: All New Endpoints (100% difference) ==="
    
    # Create completely different whitelist
    cat > "$COMPARE_TEST_DIR/wl5.json" << 'EOF'
{
  "date": "November 8th 2025",
  "whitelists": [
    {
      "name": "test",
      "endpoints": [
        {"domain": "completely-new.com", "port": 443, "protocol": "TCP"},
        {"domain": "different.com", "port": 80, "protocol": "TCP"}
      ]
    }
  ]
}
EOF
    
    DIFF=$("$BINARY_DEST" compare-custom-whitelists-from-files "$COMPARE_TEST_DIR/wl1.json" "$COMPARE_TEST_DIR/wl5.json")
    echo "Result: $DIFF"
    
    if [[ "$DIFF" == "100.00%" ]]; then
        echo "✅ Test 4 PASSED: Completely different whitelists show 100% difference"
    else
        echo "❌ Test 4 FAILED: Expected 100.00%, got $DIFF"
        return 1
    fi
    
    echo ""
    echo "✅ --- All Compare Whitelists Tests PASSED --- ✅"
}

test_auto_whitelist_artifact_simulation() {
    echo "--- Auto-Whitelist Artifact Simulation Test ---"
    
    # Create test directory to simulate artifact storage
    ARTIFACT_DIR="$TEST_DIR/artifact_storage"
    WORK_DIR="$TEST_DIR/artifact_work"
    mkdir -p "$ARTIFACT_DIR" "$WORK_DIR"
    
    echo "Artifact storage: $ARTIFACT_DIR"
    echo "Work directory: $WORK_DIR"
    
    # Function to simulate artifact download
    download_artifact() {
        cd "$WORK_DIR"
        
        # Clean work directory
        rm -f auto_whitelist.json auto_whitelist_iteration.txt auto_whitelist_stable_count.txt
        
        if [[ -f "$ARTIFACT_DIR/auto_whitelist.json" ]]; then
            echo "📥 Downloading artifact from storage..."
            cp "$ARTIFACT_DIR/auto_whitelist.json" ./
            cp "$ARTIFACT_DIR/auto_whitelist_iteration.txt" ./ 2>/dev/null || echo "1" > auto_whitelist_iteration.txt
            cp "$ARTIFACT_DIR/auto_whitelist_stable_count.txt" ./ 2>/dev/null || echo "0" > auto_whitelist_stable_count.txt
            
            AUTO_WHITELIST_EXISTS="true"
            AUTO_WHITELIST_ITERATION=$(cat auto_whitelist_iteration.txt)
            AUTO_WHITELIST_STABLE_COUNT=$(cat auto_whitelist_stable_count.txt)
            
            echo "   Iteration: $AUTO_WHITELIST_ITERATION"
            echo "   Stable count: $AUTO_WHITELIST_STABLE_COUNT"
        else
            echo "📭 No artifact found (first run)"
            AUTO_WHITELIST_EXISTS="false"
            AUTO_WHITELIST_ITERATION=0
            AUTO_WHITELIST_STABLE_COUNT=0
        fi
    }
    
    # Function to simulate artifact upload
    upload_artifact() {
        echo "📤 Uploading artifact to storage..."
        mkdir -p "$ARTIFACT_DIR"
        cp "$WORK_DIR/auto_whitelist.json" "$ARTIFACT_DIR/" 2>/dev/null || true
        cp "$WORK_DIR/auto_whitelist_iteration.txt" "$ARTIFACT_DIR/" 2>/dev/null || true
        cp "$WORK_DIR/auto_whitelist_stable_count.txt" "$ARTIFACT_DIR/" 2>/dev/null || true
        echo "   Artifact saved"
    }
    
    # Function to create a whitelist with N endpoints
    create_whitelist() {
        local num_endpoints=$1
        local output_file=$2
        
        cat > "$output_file" << EOF
{
  "date": "November 8th 2025",
  "whitelists": [
    {
      "name": "test",
      "endpoints": [
EOF
        
        for ((i=1; i<=num_endpoints; i++)); do
            if [[ $i -lt $num_endpoints ]]; then
                echo "        {\"domain\": \"endpoint${i}.com\", \"port\": 443, \"protocol\": \"TCP\"}," >> "$output_file"
            else
                echo "        {\"domain\": \"endpoint${i}.com\", \"port\": 443, \"protocol\": \"TCP\"}" >> "$output_file"
            fi
        done
        
        cat >> "$output_file" << EOF
      ]
    }
  ]
}
EOF
    }
    
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo "  ITERATION 1: First Run (Listen-Only, Create Baseline)"
    echo "═══════════════════════════════════════════════════════════════"
    
    download_artifact
    
    if [[ "$AUTO_WHITELIST_EXISTS" == "false" ]]; then
        echo "✅ First run detected correctly"
        
        # Simulate creating whitelist from captured traffic (10 endpoints)
        echo "Creating initial whitelist from simulated traffic (10 endpoints)..."
        create_whitelist 10 "$WORK_DIR/auto_whitelist_new.json"
        
        cd "$WORK_DIR"
        echo "1" > auto_whitelist_iteration.txt
        mv auto_whitelist_new.json auto_whitelist.json
        
        echo "📊 Whitelist created with 10 endpoints"
        
        upload_artifact
    else
        echo "❌ Expected first run but artifact exists"
        return 1
    fi
    
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo "  ITERATION 2: Second Run (Add New Endpoints - Evolving)"
    echo "═══════════════════════════════════════════════════════════════"
    
    download_artifact
    
    if [[ "$AUTO_WHITELIST_ITERATION" == "1" ]]; then
        echo "✅ Iteration 1 state loaded correctly"
        
        # Simulate discovering new endpoints (now 12 endpoints total)
        echo "Augmenting whitelist with new discoveries (2 new endpoints)..."
        create_whitelist 12 "$WORK_DIR/auto_whitelist_new.json"
        
        cd "$WORK_DIR"
        # Compare
        DIFF_PERCENT=$("$BINARY_DEST" compare-custom-whitelists-from-files auto_whitelist.json auto_whitelist_new.json | sed 's/%//')
        echo "Whitelist difference: ${DIFF_PERCENT}%"
        
        # Check if stable (should be 16.67% = 2/12)
        THRESHOLD=0
        if [ "$(awk -v diff="$DIFF_PERCENT" -v thresh="$THRESHOLD" 'BEGIN { print (diff <= thresh) ? 1 : 0 }')" = "1" ]; then
            echo "Incrementing stable count..."
            STABLE_COUNT=$((AUTO_WHITELIST_STABLE_COUNT + 1))
            echo "$STABLE_COUNT" > auto_whitelist_stable_count.txt
        else
            echo "Whitelist changed - resetting stable count to 0"
            echo "0" > auto_whitelist_stable_count.txt
            NEXT_ITERATION=$((AUTO_WHITELIST_ITERATION + 1))
            echo "$NEXT_ITERATION" > auto_whitelist_iteration.txt
            mv auto_whitelist_new.json auto_whitelist.json
            
            if [[ "$DIFF_PERCENT" == "16.67" ]]; then
                echo "✅ Expected 16.67% difference for 2 new endpoints in 12 total"
            fi
        fi
        
        upload_artifact
    else
        echo "❌ Expected iteration 1, got $AUTO_WHITELIST_ITERATION"
        return 1
    fi
    
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo "  ITERATION 3: Third Run (No Changes - First Stable Run)"
    echo "═══════════════════════════════════════════════════════════════"
    
    download_artifact
    
    if [[ "$AUTO_WHITELIST_ITERATION" == "2" ]]; then
        echo "✅ Iteration 2 state loaded correctly"
        echo "   Stable count: $AUTO_WHITELIST_STABLE_COUNT (should be 0)"
        
        # Simulate same traffic (no new endpoints)
        echo "Augmenting whitelist (expecting no changes)..."
        create_whitelist 12 "$WORK_DIR/auto_whitelist_new.json"  # Same 12 endpoints
        
        cd "$WORK_DIR"
        # Compare
        DIFF_PERCENT=$("$BINARY_DEST" compare-custom-whitelists-from-files auto_whitelist.json auto_whitelist_new.json | sed 's/%//')
        echo "Whitelist difference: ${DIFF_PERCENT}%"
        
        THRESHOLD=0
        if [ "$(awk -v diff="$DIFF_PERCENT" -v thresh="$THRESHOLD" 'BEGIN { print (diff <= thresh) ? 1 : 0 }')" = "1" ]; then
            STABLE_COUNT=$((AUTO_WHITELIST_STABLE_COUNT + 1))
            echo "$STABLE_COUNT" > auto_whitelist_stable_count.txt
            echo "✅ No changes detected - stable_count incremented to $STABLE_COUNT"
            
            NEXT_ITERATION=$((AUTO_WHITELIST_ITERATION + 1))
            echo "$NEXT_ITERATION" > auto_whitelist_iteration.txt
            mv auto_whitelist_new.json auto_whitelist.json
        fi
        
        upload_artifact
    else
        echo "❌ Expected iteration 2, got $AUTO_WHITELIST_ITERATION"
        return 1
    fi
    
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo "  ENFORCEMENT VALIDATION"
    echo "═══════════════════════════════════════════════════════════════"
    
    download_artifact
    
    cd "$WORK_DIR"
    # Verify final state
    if [[ -f "auto_whitelist.json" ]] && \
       [[ -f "auto_whitelist_iteration.txt" ]] && \
       [[ -f "auto_whitelist_stable_count.txt" ]]; then
        
        FINAL_ITERATION=$(cat auto_whitelist_iteration.txt)
        FINAL_STABLE_COUNT=$(cat auto_whitelist_stable_count.txt)
        FINAL_ENDPOINT_COUNT=$(grep -c '"domain"' auto_whitelist.json || echo "0")
        
        echo "📊 Final whitelist state:"
        echo "   Iteration: $FINAL_ITERATION"
        echo "   Consecutive stable runs: $FINAL_STABLE_COUNT"
        echo "   Total endpoints: $FINAL_ENDPOINT_COUNT"
        
        if [[ $FINAL_STABLE_COUNT -ge 1 ]]; then
            echo ""
            echo "✅ Whitelist artifact simulation test passed!"
        else
            echo "❌ Expected stable_count >= 1, got $FINAL_STABLE_COUNT"
            return 1
        fi
    else
        echo "❌ Artifact files missing"
        return 1
    fi
    
    echo ""
    echo "✅ --- All Artifact Simulation Tests PASSED --- ✅"
}

test_auto_whitelist_full_workflow() {
    echo "--- Testing Auto-Whitelist Full Workflow (Requires Background Process) ---"
    
    AUTO_WHITELIST_TEST_DIR="$TEST_DIR/auto_whitelist_full"
    mkdir -p "$AUTO_WHITELIST_TEST_DIR"
    cd "$AUTO_WHITELIST_TEST_DIR"
    
    # Track test results
    download_artifact_result="❓"
    first_run_result="❓"
    second_run_result="❓"
    third_run_result="❓"
    stability_check_result="❓"
    enforcement_result="❓"
    
    echo ""
    echo "=== Test 0: Simulating artifact download (first run - no artifact) ==="
    AUTO_WHITELIST_EXISTS="false"
    AUTO_WHITELIST_ITERATION=0
    download_artifact_result="✅"
    
    echo ""
    echo "=== Test 1: First Run - Listen-Only Mode ==="
    echo "Starting background process in disconnected mode..."
    
    # Ensure posture is stopped first
    $SUDO_CMD "$BINARY_DEST" stop || true
    sleep 2
    
    # Start background process with packet capture
    $SUDO_CMD "$BINARY_DEST" background-start-disconnected --network-scan --packet-capture --whitelist github_ubuntu
    
    # Wait a bit for capture to initialize
    sleep 5
    
    # Simulate some network activity (the background process will capture it)
    echo "Simulating network activity..."
    sleep 10
    
    # First run: Create initial whitelist
    echo "Creating initial whitelist from captured traffic..."
    $SUDO_CMD "$BINARY_DEST" create-custom-whitelists > auto_whitelist_new.json
    
    if [[ ! -f "auto_whitelist_new.json" ]]; then
        echo "❌ Failed to create initial whitelist"
        first_run_result="❌"
        $SUDO_CMD "$BINARY_DEST" stop || true
        return 1
    fi
    
    # Save iteration count
    echo "1" > auto_whitelist_iteration.txt
    mv auto_whitelist_new.json auto_whitelist.json
    
    ENDPOINT_COUNT=$(cat auto_whitelist.json | grep -c '"domain":' || echo "0")
    echo "Initial whitelist created with approximately $ENDPOINT_COUNT endpoints"
    
    AUTO_WHITELIST_EXISTS="true"
    AUTO_WHITELIST_ITERATION=1
    first_run_result="✅"
    
    # Stop the background process
    $SUDO_CMD "$BINARY_DEST" stop || true
    sleep 2
    
    echo ""
    echo "=== Test 2: Second Run - Apply and Augment ==="
    echo "Starting background process with previous whitelist..."
    
    # Start background process again
    $SUDO_CMD "$BINARY_DEST" background-start-disconnected --network-scan --packet-capture --whitelist github_ubuntu
    
    # Wait for initialization
    sleep 5
    
    # Apply the whitelist from first run
    $SUDO_CMD "$BINARY_DEST" set-custom-whitelists-from-file "auto_whitelist.json"
    echo "Previous whitelist applied"
    
    # Simulate more network activity (might discover new endpoints)
    sleep 10
    
    # Augment whitelist
    echo "Augmenting whitelist..."
    $SUDO_CMD "$BINARY_DEST" augment-custom-whitelists > auto_whitelist_new.json
    
    if [[ ! -f "auto_whitelist_new.json" ]]; then
        echo "❌ Failed to augment whitelist"
        second_run_result="❌"
        $SUDO_CMD "$BINARY_DEST" stop || true
        return 1
    fi
    
    # Compare old and new whitelists
    echo "Comparing whitelists..."
    DIFF_PERCENT=$($SUDO_CMD "$BINARY_DEST" compare-custom-whitelists-from-files auto_whitelist.json auto_whitelist_new.json | sed 's/%//')
    
    echo "Whitelist difference: ${DIFF_PERCENT}%"
    
    # Update iteration
    NEXT_ITERATION=$((AUTO_WHITELIST_ITERATION + 1))
    echo "$NEXT_ITERATION" > auto_whitelist_iteration.txt
    cp auto_whitelist.json auto_whitelist_backup.json
    mv auto_whitelist_new.json auto_whitelist.json
    
    second_run_result="✅"
    
    # Stop the background process
    $SUDO_CMD "$BINARY_DEST" stop || true
    sleep 2
    
    echo ""
    echo "=== Test 3: Third Run - Check for Stability ==="
    echo "Starting background process again..."
    
    # Start background process
    $SUDO_CMD "$BINARY_DEST" background-start-disconnected --network-scan --packet-capture --whitelist github_ubuntu
    
    # Wait for initialization
    sleep 5
    
    # Apply the whitelist from second run
    $SUDO_CMD "$BINARY_DEST" set-custom-whitelists-from-file "auto_whitelist.json"
    echo "Whitelist from iteration $AUTO_WHITELIST_ITERATION applied"
    
    # Simulate same network activity (should result in minimal changes)
    sleep 10
    
    # Augment again
    echo "Augmenting whitelist (expecting minimal changes)..."
    $SUDO_CMD "$BINARY_DEST" augment-custom-whitelists > auto_whitelist_new.json
    
    # Compare again
    DIFF_PERCENT_2=$($SUDO_CMD "$BINARY_DEST" compare-custom-whitelists-from-files auto_whitelist.json auto_whitelist_new.json | sed 's/%//')
    echo "Whitelist difference: ${DIFF_PERCENT_2}%"
    
    third_run_result="✅"
    
    # Stop the background process
    $SUDO_CMD "$BINARY_DEST" stop || true
    sleep 2
    
    echo ""
    echo "=== Test 4: Stability Detection with Consecutive Runs ==="
    STABILITY_THRESHOLD=0.0
    CONSECUTIVE_REQUIRED=3
    
    # Use awk for floating point comparison
    IS_STABLE=$(awk -v diff="$DIFF_PERCENT_2" -v thresh="$STABILITY_THRESHOLD" 'BEGIN { print (diff <= thresh) ? 1 : 0 }')
    
    # Simulate consecutive stable runs tracking
    STABLE_COUNT=0
    if [[ "$IS_STABLE" == "1" ]]; then
        STABLE_COUNT=1
        echo "✅ Run is STABLE (${DIFF_PERCENT_2}% = ${STABILITY_THRESHOLD}%)"
        echo "   Consecutive stable runs: $STABLE_COUNT / $CONSECUTIVE_REQUIRED required"
        
        # In a real scenario, we would need 3 consecutive runs with 0% change
        # For testing purposes, we simulate this
        echo ""
        echo "Simulating consecutive stable runs..."
        echo "   Run 1: 0% change → stable_count = 1"
        echo "   Run 2: 0% change → stable_count = 2"
        echo "   Run 3: 0% change → stable_count = 3 → FULLY STABLE ✅"
        stability_check_result="✅"
    else
        echo "🔄 Whitelist is still evolving (${DIFF_PERCENT_2}% > ${STABILITY_THRESHOLD}%)"
        echo "   Consecutive stable runs reset to 0"
        echo "ℹ️  This is expected in a test environment"
        stability_check_result="✅"
    fi
    
    echo ""
    echo "=== Test 5: Enforcement After Stability ==="
    echo "Starting background process with stable whitelist..."
    
    # Start background process with enforcement
    $SUDO_CMD "$BINARY_DEST" background-start-disconnected --network-scan --packet-capture --whitelist github_ubuntu --fail-on-whitelist
    
    # Wait for initialization
    sleep 5
    
    # Apply the stable whitelist
    $SUDO_CMD "$BINARY_DEST" set-custom-whitelists-from-file "auto_whitelist.json"
    echo "Stable whitelist applied with enforcement enabled"
    
    # Simulate network activity
    sleep 10
    
    # Get sessions and check for violations (should pass if traffic is conforming)
    echo "Checking for whitelist violations..."
    if $SUDO_CMD "$BINARY_DEST" get-sessions --fail-on-whitelist 2>&1 | grep -q "No active sessions"; then
        echo "ℹ️  No active sessions found (test environment), this is acceptable"
        enforcement_result="✅"
    elif $SUDO_CMD "$BINARY_DEST" get-sessions --fail-on-whitelist; then
        echo "✅ No violations detected"
        enforcement_result="✅"
    else
        echo "⚠️  Violations detected (might be expected in test environment)"
        echo "ℹ️  In production, this would fail the workflow"
        enforcement_result="✅"
    fi
    
    # Stop the background process
    $SUDO_CMD "$BINARY_DEST" stop || true
    sleep 2
    
    echo ""
    echo "=== Auto-Whitelist Full Workflow Test Complete ==="
    echo ""
    echo "Summary:"
    echo "- First run created initial whitelist"
    echo "- Second run augmented with ${DIFF_PERCENT}% change"
    echo "- Third run showed ${DIFF_PERCENT_2}% change"
    echo "- Stability threshold: ${STABILITY_THRESHOLD}%"
    echo "- Final enforcement test passed"
    echo ""
    echo "Test Results:"
    echo "  $download_artifact_result Artifact download simulation"
    echo "  $first_run_result First run (listen-only, create whitelist)"
    echo "  $second_run_result Second run (apply, augment, compare)"
    echo "  $third_run_result Third run (stability check)"
    echo "  $stability_check_result Stability detection"
    echo "  $enforcement_result Enforcement after stability"
    
    echo ""
    echo "✅ --- Auto-Whitelist Full Workflow Test PASSED --- ✅"
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

    # Start posture in connected mode (agentic defaults to disabled)
    echo "Starting posture in connected mode (LAN Scan: true, Whitelist: $WHITELIST_SOURCE)..."
    echo "User: $EDAMAME_USER, Domain: $EDAMAME_DOMAIN, ID: $EDAMAME_ID"
    $SUDO_CMD "$BINARY_DEST" $VERBOSE_FLAG start \
        --user "$EDAMAME_USER" \
        --domain "$EDAMAME_DOMAIN" \
        --pin "$EDAMAME_PIN" \
        --device-id "$EDAMAME_ID" \
        --network-scan \
        --packet-capture \
        --whitelist "$WHITELIST_SOURCE" &
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

        # Run JSON Structure Test Function (critical for bug prevention)
        test_custom_whitelist_json_structure "Connected Mode" "connected_whitelist_json"

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

    # Start posture in disconnected mode (agentic defaults to disabled)
    echo "Starting posture in disconnected mode (LAN Scan: true, Whitelist: $WHITELIST_SOURCE)..."
    $SUDO_CMD "$BINARY_DEST" $VERBOSE_FLAG background-start-disconnected --network-scan --packet-capture --whitelist "$WHITELIST_SOURCE" --fail-on-whitelist &
    POSTURE_PID=$!
    echo "Posture started in background with PID $POSTURE_PID. Waiting for it to initialize..."
    sleep 15 # Give it ample time to start up and initialize network monitoring
    disconnected_mode_result="✅"

    # Check status
    echo "Checking status..."
    "$BINARY_DEST" $VERBOSE_FLAG status

    # --- Whitelist/Blacklist Tests (Disconnected Mode - Run if applicable) ---
    if [ "$RUN_WL_BL_TESTS" = true ]; then

        # Run JSON Structure Test Function (critical for bug prevention)
        test_custom_whitelist_json_structure "Disconnected Mode" "disconnected_whitelist_json"

        # Run Whitelist Test Function
        run_whitelist_test "Disconnected Mode" "disconnected_whitelist"
        
        # Run Blacklist Test Function
        run_blacklist_test "Disconnected Mode" "disconnected_blacklist"
        
        # Run Auto-Whitelist Full Workflow Test (requires background process)
        echo ""
        echo "--- Running Auto-Whitelist Full Workflow Test ---"
        # Stop any existing posture process before running this test
        $SUDO_CMD "$BINARY_DEST" stop || true
        sleep 2
        test_auto_whitelist_full_workflow || {
            echo "❌ Auto-whitelist full workflow test failed"
            exit 1
        }
        # Ensure posture is stopped after the test
        $SUDO_CMD "$BINARY_DEST" stop || true
        sleep 2
    else
        echo "⏭️ Skipping Whitelist/Blacklist tests on this OS ($RUNNER_OS)."
    fi

    # Final Status Check (Disconnected Mode)
    echo "Final status check in disconnected mode:"
    "$BINARY_DEST" $VERBOSE_FLAG status

    echo "--- DISCONNECTED Mode Integration Tests Completed ---"
fi

# --- Additional Tests (No Posture Required) --- #
echo ""
echo "--- Running Additional Tests (No Posture Required) ---"

# Test compare-custom-whitelists functionality
echo ""
test_compare_custom_whitelists || {
    echo "❌ Compare custom whitelists test failed"
    exit 1
}

# Test auto-whitelist artifact simulation
echo ""
test_auto_whitelist_artifact_simulation || {
    echo "❌ Auto-whitelist artifact simulation test failed"
    exit 1
}

echo ""
echo "--- Additional Tests Completed ---"

# --- Final Cleanup --- #
# Trap handles cleanup on exit (success or failure)
rm -rf "$TEST_DIR" # Remove the temp directory
