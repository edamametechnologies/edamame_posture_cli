#!/bin/bash
set -e

# Test result tracking (simple variable instead of associative array for macOS compatibility)
cargo_tests_result="❓" # Default value

# Function to run on exit
finish() {
    local exit_status=$?
    echo ""
    echo "--- Test Summary --- "
    echo "- Basic Cargo Tests $cargo_tests_result"
    echo "--------------------"
    if [ $exit_status -eq 0 ]; then
        echo "✅ --- Basic Cargo Tests Completed Successfully --- ✅"
    else
        echo "❌ --- Basic Cargo Tests Failed (Exit Code: $exit_status) --- ❌"
    fi
}
trap finish EXIT # Register the finish function to run on exit

echo "--- Running Basic Cargo Tests ---"

# Run cargo tests with result tracking
if cargo test -- --nocapture; then
    echo "✅ Cargo tests passed"
    cargo_tests_result="✅"
else
    echo "❌ Cargo tests failed"
    cargo_tests_result="❌"
fi
