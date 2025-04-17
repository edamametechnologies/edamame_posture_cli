#!/bin/bash
set -e

# --- Configuration ---
# This script should be run from the root of the edamame_posture repository.
UBUNTU_VERSION=${1:-ubuntu20.04} # Default to ubuntu20.04 if no argument provided
DOCKERFILE="docker/Dockerfile.${UBUNTU_VERSION}"
IMAGE_NAME="edamame-posture-test:${UBUNTU_VERSION}"

# Check if Dockerfile exists
if [ ! -f "$DOCKERFILE" ]; then
    echo "Error: Dockerfile not found at ${DOCKERFILE}"
    echo "Usage: $0 [ubuntu20.04|ubuntu18.04]"
    exit 1
fi

# Check for required environment variables for integration tests
if [ -z "$EDAMAME_USER" ] || [ -z "$EDAMAME_DOMAIN" ] || [ -z "$EDAMAME_PIN" ]; then
  echo "Warning: EDAMAME_USER, EDAMAME_DOMAIN, or EDAMAME_PIN environment variables are not set."
  echo "Integration tests will be skipped inside the container."
  echo "Set them before running this script to include integration tests."
  # Example:
  # export EDAMAME_USER="your_user"
  # export EDAMAME_DOMAIN="your_domain"
  # export EDAMAME_PIN="your_pin"
  # export DEV_GITHUB_TOKEN="your_github_token" # Optional
fi

# Optional: Check for Git token
if [ -z "$DEV_GITHUB_TOKEN" ]; then
    echo "Info: DEV_GITHUB_TOKEN is not set. Git authentication will be skipped in the container."
    echo "Set this if your build requires private GitHub repositories."
fi

# --- Build Docker Image ---
echo "Building Docker image ${IMAGE_NAME} using ${DOCKERFILE}..."
# Pass build context from the parent directory (edamame_posture)
# This allows the Dockerfile to COPY . /app correctly
docker build -t "${IMAGE_NAME}" -f "${DOCKERFILE}" .

# --- Run Docker Container ---
echo "Running container tests in ${IMAGE_NAME}..."

# Prepare environment variables to pass to the container
# Only pass variables if they are set
ENV_VARS=""
[ -n "$EDAMAME_USER" ] && ENV_VARS="$ENV_VARS -e EDAMAME_USER=$EDAMAME_USER"
[ -n "$EDAMAME_DOMAIN" ] && ENV_VARS="$ENV_VARS -e EDAMAME_DOMAIN=$EDAMAME_DOMAIN"
[ -n "$EDAMAME_PIN" ] && ENV_VARS="$ENV_VARS -e EDAMAME_PIN=$EDAMAME_PIN"
[ -n "$DEV_GITHUB_TOKEN" ] && ENV_VARS="$ENV_VARS -e DEV_GITHUB_TOKEN=$DEV_GITHUB_TOKEN"
# Add other environment variables from the workflow file if needed by tests
[ -n "$EDAMAME_APP_SENTRY" ] && ENV_VARS="$ENV_VARS -e EDAMAME_APP_SENTRY=$EDAMAME_APP_SENTRY"
[ -n "$PWNED_API_KEY" ] && ENV_VARS="$ENV_VARS -e PWNED_API_KEY=$PWNED_API_KEY"
[ -n "$EDAMAME_TARGET" ] && ENV_VARS="$ENV_VARS -e EDAMAME_TARGET=$EDAMAME_TARGET"
[ -n "$EDAMAME_CORE_TARGET" ] && ENV_VARS="$ENV_VARS -e EDAMAME_CORE_TARGET=$EDAMAME_CORE_TARGET"
[ -n "$EDAMAME_CORE_SERVER" ] && ENV_VARS="$ENV_VARS -e EDAMAME_CORE_SERVER=$EDAMAME_CORE_SERVER"
[ -n "$EDAMAME_CA_PEM" ] && ENV_VARS="$ENV_VARS -e EDAMAME_CA_PEM=$EDAMAME_CA_PEM"
[ -n "$EDAMAME_CLIENT_PEM" ] && ENV_VARS="$ENV_VARS -e EDAMAME_CLIENT_PEM=$EDAMAME_CLIENT_PEM"
[ -n "$EDAMAME_CLIENT_KEY" ] && ENV_VARS="$ENV_VARS -e EDAMAME_CLIENT_KEY=$EDAMAME_CLIENT_KEY"
[ -n "$EDAMAME_SERVER_PEM" ] && ENV_VARS="$ENV_VARS -e EDAMAME_SERVER_PEM=$EDAMAME_SERVER_PEM"
[ -n "$EDAMAME_SERVER_KEY" ] && ENV_VARS="$ENV_VARS -e EDAMAME_SERVER_KEY=$EDAMAME_SERVER_KEY"
[ -n "$EDAMAME_CLIENT_CA_PEM" ] && ENV_VARS="$ENV_VARS -e EDAMAME_CLIENT_CA_PEM=$EDAMAME_CLIENT_CA_PEM"
[ -n "$LAMBDA_SIGNATURE" ] && ENV_VARS="$ENV_VARS -e LAMBDA_SIGNATURE=$LAMBDA_SIGNATURE"
[ -n "$MIXPANEL_TOKEN" ] && ENV_VARS="$ENV_VARS -e MIXPANEL_TOKEN=$MIXPANEL_TOKEN"
ENV_VARS="$ENV_VARS -e EDAMAME_LOG_LEVEL=debug"

docker run --rm -it \
    --cap-add=NET_ADMIN \
    --cap-add=NET_RAW \
    $ENV_VARS \
    "${IMAGE_NAME}"

EXIT_CODE=$?

if [ $EXIT_CODE -eq 0 ]; then
    echo "✅ Docker container tests completed successfully for ${UBUNTU_VERSION}."
else
    echo "❌ Docker container tests failed for ${UBUNTU_VERSION} with exit code ${EXIT_CODE}."
fi

exit $EXIT_CODE 