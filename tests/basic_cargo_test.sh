#!/bin/bash
set -e

# Test result tracking (simple variable instead of associative array for macOS compatibility)
cargo_tests_result="❓" # Default value

# Function to run on exit (invoked through the EXIT trap below)
# shellcheck disable=SC2329
finish() {
    local exit_status=$?
    echo ""
    echo "--- Test Summary --- "
    echo "- Basic Cargo Tests $cargo_tests_result"
    echo "--------------------"
    if [ "$exit_status" -eq 0 ]; then
        echo "✅ --- Basic Cargo Tests Completed Successfully --- ✅"
    else
        echo "❌ --- Basic Cargo Tests Failed (Exit Code: $exit_status) --- ❌"
    fi
}
trap finish EXIT # Register the finish function to run on exit

echo "--- Running Basic Cargo Tests ---"

# Run cargo tests with result tracking. The status is the script's exit code:
# tests.yml fails the job on this step's outcome, so a failed `cargo test`
# must exit non-zero (it used to be recorded and then exit 0).
cargo_tests_status=0
if cargo test -- --nocapture; then
    echo "✅ Cargo tests passed"
    cargo_tests_result="✅"
else
    echo "❌ Cargo tests failed"
    cargo_tests_result="❌"
    cargo_tests_status=1
fi

exit "$cargo_tests_status"
