#!/bin/bash
set -e # Exit immediately if a command exits with a non-zero status.

if [ -f ../../secrets/docker.env ]; then
  source ../../secrets/docker.env
fi

# --- Configuration ---
# Check if DEV_GITHUB_TOKEN is provided and configure Git if it is
if [ -n "$DEV_GITHUB_TOKEN" ]; then
  echo "Configuring Git authentication..."
  git config --global user.email "dev@edamame.tech"
  git config --global user.name "EDAMAME Dev Local"
  git config --global url."https://edamamedev:${DEV_GITHUB_TOKEN}@github.com/".insteadOf "https://github.com/"
else
  echo "DEV_GITHUB_TOKEN not provided, skipping Git authentication configuration."
  echo "Build might fail if private crates are required."
fi

# Ensure cargo is in path (should be set by Dockerfile ENV)
export PATH="/root/.cargo/bin:$PATH"
echo "Using cargo at: $(which cargo)"
echo "Using rustc at: $(which rustc)"
rustc --version
cargo --version

# --- Build ---
echo "Building application..."
cargo build --release

# --- Run Tests ---
# Environment variables required by test scripts (passed via docker run -e)
# EDAMAME_USER, EDAMAME_DOMAIN, EDAMAME_PIN are needed for integration_test.sh
# Others might be needed depending on the specific tests executed by the scripts.
# Set SUDO_CMD to empty as we are running as root in the container.
export SUDO_CMD=""

echo "Running Basic Cargo Tests..."
if ./tests/basic_cargo_test.sh; then
  echo "✅ Basic Cargo Tests Passed"
else
  echo "❌ Basic Cargo Tests Failed"
  exit 1
fi

echo "Running Standalone Commands Test..."
if ./tests/standalone_commands_test.sh; then
  echo "✅ Standalone Commands Test Passed"
else
  echo "❌ Standalone Commands Test Failed"
  exit 1
fi

echo "Running Integration Tests..."
if [ -z "$EDAMAME_USER" ] || [ -z "$EDAMAME_DOMAIN" ] || [ -z "$EDAMAME_PIN" ]; then
  echo "⚠️ WARNING: EDAMAME_USER, EDAMAME_DOMAIN, or EDAMAME_PIN not set."
  echo "Skipping Integration Tests as they require these environment variables."
else
  if ./tests/integration_test.sh; then
    echo "✅ Integration Tests Passed"
  else
    echo "❌ Integration Tests Failed"
    exit 1
  fi
fi

echo "All tests passed successfully!"
exit 0 
