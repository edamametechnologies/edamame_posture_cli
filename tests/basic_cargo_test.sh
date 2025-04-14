#!/bin/bash
set -e

if [ -z "$1" ]; then
    echo "Usage: $0 <target>"
    exit 1
fi

# Function to run on exit
finish() {
    local exit_status=$?
    echo ""
    echo "--- Test Summary --- "
    echo "- Basic Cargo Tests"
    echo "--------------------"
    if [ $exit_status -eq 0 ]; then
        echo "✅ --- Basic Cargo Tests Completed Successfully --- ✅"
    else
        echo "❌ --- Basic Cargo Tests Failed (Exit Code: $exit_status) --- ❌"
    fi
}
trap finish EXIT # Register the finish function to run on exit

echo "--- Running Basic Cargo Tests ---"

cargo test -- --nocapture --target $1
