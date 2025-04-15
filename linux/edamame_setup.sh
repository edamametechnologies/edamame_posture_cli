#!/bin/bash

# Simple script to download and run edamame_posture
# Usage: ./edamame_setup.sh <edamame_user> <edamame_domain> <edamame_pin> <edamame_id>

# Check if required arguments are provided
if [ "$#" -ne 4 ]; then
    echo "Usage: $0 <edamame_user> <edamame_domain> <edamame_pin> <edamame_id>"
    exit 1
fi

EDAMAME_USER="$1"
EDAMAME_DOMAIN="$2"
EDAMAME_PIN="$3"
EDAMAME_ID="$4"

# Set VERSION to download
VERSION=0.9.28
FALLBACK_VERSION=0.9.24

# Determine OS
RUNNER_OS=$(uname)

# Install basic dependencies if needed
if [[ "$RUNNER_OS" == "Darwin" ]]; then
    # macOS
    command -v wget >/dev/null 2>&1 || brew install wget
    command -v jq >/dev/null 2>&1 || brew install jq
elif [[ "$RUNNER_OS" == "Linux" ]]; then
    # Linux
    command -v wget >/dev/null 2>&1 || sudo apt-get update && sudo apt-get install -y wget
    command -v jq >/dev/null 2>&1 || sudo apt-get install -y jq
else
    # Windows/Other
    echo "This script supports macOS and Linux only."
    exit 1
fi

# Navigate to home directory
cd ~

# Download the binary based on OS
if [[ "$RUNNER_OS" == "Darwin" ]]; then
    echo "Downloading EDAMAME Posture binary for macOS..."
    wget --no-verbose https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v${VERSION}/edamame_posture-${VERSION}-universal-apple-darwin -O edamame_posture || \
    wget --no-verbose https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v${FALLBACK_VERSION}/edamame_posture-${FALLBACK_VERSION}-universal-apple-darwin -O edamame_posture
    chmod u+x edamame_posture
    EDAMAME_POSTURE_CMD="sudo ./edamame_posture"
elif [[ "$RUNNER_OS" == "Linux" ]]; then
    echo "Downloading EDAMAME Posture binary for Linux..."
    # Get GLIBC version
    MIN_GLIBC_VERSION=0.9.28
    if command -v getconf >/dev/null 2>&1; then
        GLIBC_VERSION=0.9.28
        
        # Compare versions 
        if printf '%s\n%s\n' "$MIN_GLIBC_VERSION" "$GLIBC_VERSION" | sort -V | head -n 1 | grep -q "$MIN_GLIBC_VERSION"; then
            echo "Using x86_64-unknown-linux-gnu version"
            wget --no-verbose https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v${VERSION}/edamame_posture-${VERSION}-x86_64-unknown-linux-gnu -O edamame_posture || \
            wget --no-verbose https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v${FALLBACK_VERSION}/edamame_posture-${FALLBACK_VERSION}-x86_64-unknown-linux-gnu -O edamame_posture
        else
            echo "Using x86_64-unknown-linux-musl version" 
            wget --no-verbose https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v${VERSION}/edamame_posture-${VERSION}-x86_64-unknown-linux-musl -O edamame_posture || \
            wget --no-verbose https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v${FALLBACK_VERSION}/edamame_posture-${FALLBACK_VERSION}-x86_64-unknown-linux-musl -O edamame_posture
        fi
    else
        echo "Unable to detect GLIBC version, defaulting to musl build"
        wget --no-verbose https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v${VERSION}/edamame_posture-${VERSION}-x86_64-unknown-linux-musl -O edamame_posture || \
        wget --no-verbose https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v${FALLBACK_VERSION}/edamame_posture-${FALLBACK_VERSION}-x86_64-unknown-linux-musl -O edamame_posture
    fi
    chmod u+x edamame_posture
    EDAMAME_POSTURE_CMD="sudo -E ./edamame_posture"
fi

# Show initial posture
echo "Showing initial posture score..."
$EDAMAME_POSTURE_CMD score

# Start EDAMAME Posture process
echo "Starting EDAMAME Posture with provided credentials..."
export EDAMAME_LOG_LEVEL=debug
$EDAMAME_POSTURE_CMD start "$EDAMAME_USER" "$EDAMAME_DOMAIN" "$EDAMAME_PIN" "$EDAMAME_ID" "false"

# Wait for connection
echo "Waiting for connection..."
$EDAMAME_POSTURE_CMD wait-for-connection

echo "EDAMAME Posture started successfully."
