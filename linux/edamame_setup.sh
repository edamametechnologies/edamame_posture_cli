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

# Determine OS
RUNNER_OS=$(uname)

# Install basic dependencies if needed
if [[ "$RUNNER_OS" == "Darwin" ]]; then
    # macOS
    command -v wget >/dev/null 2>&1 || brew install wget
    command -v curl >/dev/null 2>&1 || brew install curl
elif [[ "$RUNNER_OS" == "Linux" ]]; then
    # Linux - detect package manager
    if command -v apt-get >/dev/null 2>&1; then
        # Debian/Ubuntu
        command -v wget >/dev/null 2>&1 || sudo apt-get update && sudo apt-get install -y wget
        command -v curl >/dev/null 2>&1 || sudo apt-get install -y curl
    elif command -v apk >/dev/null 2>&1; then
        # Alpine Linux
        command -v wget >/dev/null 2>&1 || sudo apk add --no-cache wget
        command -v curl >/dev/null 2>&1 || sudo apk add --no-cache curl
    else
        echo "Unsupported Linux distribution. Please install wget and curl manually."
        exit 1
    fi
else
    # Windows/Other
    echo "This script supports macOS and Linux only."
    exit 1
fi

# Set VERSION to download
# --- Determine Latest Version via Redirect ---
LATEST_VERSION=""
echo "Attempting to get latest version via redirect..."
REDIRECT_OUTPUT=$(curl -s -L -I -o /dev/null -w '%{url_effective}:%{http_code}' https://github.com/edamametechnologies/edamame_posture_cli/releases/latest)

# Extract status code and URL
HTTP_STATUS="${REDIRECT_OUTPUT##*:}"
LATEST_RELEASE_URL="${REDIRECT_OUTPUT%:$HTTP_STATUS}"

echo "Redirect URL: $LATEST_RELEASE_URL"
echo "HTTP Status: $HTTP_STATUS"

if [[ "$HTTP_STATUS" == "200" && "$LATEST_RELEASE_URL" == *"/releases/tag/"* ]]; then
  LATEST_VERSION=$(basename "$LATEST_RELEASE_URL")
  LATEST_VERSION=${LATEST_VERSION#v} # Remove v prefix
  echo "Latest version found via redirect: $LATEST_VERSION"
else
  echo "Failed to get latest version via redirect (Status: $HTTP_STATUS, URL: $LATEST_RELEASE_URL). Will use hardcoded version."
  LATEST_VERSION="" # Ensure LATEST_VERSION is empty if redirect fails
fi

HARDCODED_FALLBACK_VERSION="0.9.60" # Define hardcoded fallback

# --- Set VERSION and FALLBACK_VERSION for Download ---
if [[ -n "$LATEST_VERSION" ]]; then
  VERSION="$LATEST_VERSION"
else
  # Latest version via redirect failed, use hardcoded fallback as primary
  echo "Using hardcoded version as primary version."
  VERSION="$HARDCODED_FALLBACK_VERSION"
fi
# Always use the hardcoded fallback version
FALLBACK_VERSION="$HARDCODED_FALLBACK_VERSION"

echo "VERSION to download: $VERSION"
echo "FALLBACK_VERSION to download: $FALLBACK_VERSION"

# Navigate to home directory
cd ~

# Download the binary based on OS
if [[ "$RUNNER_OS" == "Darwin" ]]; then
    echo "Downloading EDAMAME Posture binary for macOS..."
    wget --no-verbose https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v${VERSION}/edamame_posture-${VERSION}-universal-apple-darwin -O ./edamame_posture || \
    wget --no-verbose https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v${FALLBACK_VERSION}/edamame_posture-${FALLBACK_VERSION}-universal-apple-darwin -O ./edamame_posture
    chmod u+x ./edamame_posture
    EDAMAME_POSTURE_CMD="sudo ./edamame_posture"
elif [[ "$RUNNER_OS" == "Linux" ]]; then
    echo "Downloading EDAMAME Posture binary for Linux..."
    # Get GLIBC version
    MIN_GLIBC_VERSION="2.29" # Use a real GLIBC version threshold
    echo "Minimum required GLIBC version: $MIN_GLIBC_VERSION"
    if command -v getconf >/dev/null 2>&1; then
        echo "Using getconf to determine GLIBC version"
        GLIBC_VERSION=$(getconf GNU_LIBC_VERSION | awk '{print $2}')
        echo "Detected GLIBC version: $GLIBC_VERSION"
        
        # Compare versions using sort
        if printf '%s\n%s\n' "$MIN_GLIBC_VERSION" "$GLIBC_VERSION" | sort -V | head -n 1 | grep -q "$MIN_GLIBC_VERSION"; then
            echo "GLIBC version $GLIBC_VERSION is sufficient (minimum required: $MIN_GLIBC_VERSION)"
            echo "Using x86_64-unknown-linux-gnu version"
            wget --no-verbose https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v${VERSION}/edamame_posture-${VERSION}-x86_64-unknown-linux-gnu -O ./edamame_posture || \
            wget --no-verbose https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v${FALLBACK_VERSION}/edamame_posture-${FALLBACK_VERSION}-x86_64-unknown-linux-gnu -O ./edamame_posture
        else
            echo "Warning: GLIBC version $GLIBC_VERSION is older than minimum required version $MIN_GLIBC_VERSION"
            echo "Using x86_64-unknown-linux-musl version" 
            wget --no-verbose https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v${VERSION}/edamame_posture-${VERSION}-x86_64-unknown-linux-musl -O ./edamame_posture || \
            wget --no-verbose https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v${FALLBACK_VERSION}/edamame_posture-${FALLBACK_VERSION}-x86_64-unknown-linux-musl -O ./edamame_posture
        fi
    else
        echo "Unable to detect GLIBC version using getconf, defaulting to musl build"
        wget --no-verbose https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v${VERSION}/edamame_posture-${VERSION}-x86_64-unknown-linux-musl -O ./edamame_posture || \
        wget --no-verbose https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v${FALLBACK_VERSION}/edamame_posture-${FALLBACK_VERSION}-x86_64-unknown-linux-musl -O ./edamame_posture
    fi
    chmod u+x ./edamame_posture
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
