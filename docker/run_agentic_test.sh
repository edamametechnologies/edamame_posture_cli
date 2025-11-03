#!/bin/bash
set -euo pipefail

# --- Configuration ---
# This script should be run from the root of the edamame_posture repository.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
# Load all secrets from ../secrets/*.env
for env_file in ../secrets/*.env; do
    if [ -f "$env_file" ]; then
        echo "Sourcing secrets from ${env_file}"
        # shellcheck disable=SC1090
        source "$env_file"
    fi
done

required_vars=(
  EDAMAME_LLM_API_KEY
  EDAMAME_AGENTIC_SLACK_BOT_TOKEN
  DEV_GITHUB_TOKEN
  EDAMAME_USER
  EDAMAME_DOMAIN
  EDAMAME_PIN
)

missing_vars=()
for var in "${required_vars[@]}"; do
  if [ -z "${!var:-}" ]; then
    missing_vars+=("${var}")
  fi
done

if [ ${#missing_vars[@]} -ne 0 ]; then
  echo "Error: The following required environment variables are missing: ${missing_vars[*]}" >&2
  exit 1
fi

# Export required vars (ensures docker run -e VAR picks them up)
for var in "${required_vars[@]}"; do
  export "$var"
done

UBUNTU_VERSION=${1:-ubuntu24.04}
DOCKERFILE="docker/Dockerfile.${UBUNTU_VERSION}"
IMAGE_NAME="edamame-agentic-test:${UBUNTU_VERSION}"

cd "${REPO_ROOT}"

if [ ! -f "${DOCKERFILE}" ]; then
  echo "Error: Dockerfile not found at ${DOCKERFILE}" >&2
  echo "Usage: $0 [ubuntu25.04|ubuntu24.04|ubuntu22.04]" >&2
  exit 1
fi

echo "Building Docker image ${IMAGE_NAME} using ${DOCKERFILE}..."
docker build -t "${IMAGE_NAME}" -f "${DOCKERFILE}" .

echo "Running agentic analysis container (${IMAGE_NAME})..."

# Prepare environment variables to pass through
docker_args=(
  --rm
  -it
  --cap-add=NET_ADMIN
  --cap-add=NET_RAW
)

add_env_if_set() {
  local var_name="$1"
  if [ -n "${!var_name:-}" ]; then
    export "$var_name"
    docker_args+=(-e "$var_name")
  fi
}

# Required (already exported above, but add to docker args)
for var in "${required_vars[@]}"; do
  add_env_if_set "$var"
done

# Optional LLM/slack overrides
add_env_if_set EDAMAME_LLM_MODEL
add_env_if_set EDAMAME_LLM_BASE_URL
add_env_if_set EDAMAME_AGENTIC_SLACK_ACTIONS_CHANNEL
add_env_if_set EDAMAME_AGENTIC_SLACK_ESCALATIONS_CHANNEL
add_env_if_set EDAMAME_AGENTIC_PROVIDER
add_env_if_set EDAMAME_AGENTIC_INTERVAL

# Other secrets used by tests / telemetry
add_env_if_set EDAMAME_APP_SENTRY
add_env_if_set PWNED_API_KEY
add_env_if_set EDAMAME_TARGET
add_env_if_set EDAMAME_CORE_TARGET
add_env_if_set EDAMAME_CORE_SERVER
add_env_if_set EDAMAME_CA_PEM
add_env_if_set EDAMAME_CLIENT_PEM
add_env_if_set EDAMAME_CLIENT_KEY
add_env_if_set EDAMAME_SERVER_PEM
add_env_if_set EDAMAME_SERVER_KEY
add_env_if_set EDAMAME_CLIENT_CA_PEM
add_env_if_set LAMBDA_SIGNATURE
add_env_if_set MIXPANEL_TOKEN

export EDAMAME_LOG_LEVEL=${EDAMAME_LOG_LEVEL:-debug}
docker_args+=(-e EDAMAME_LOG_LEVEL)
export AGENTIC_TEST_MODE=1
docker_args+=(-e AGENTIC_TEST_MODE)

docker_args+=("${IMAGE_NAME}")

docker run "${docker_args[@]}"

EXIT_CODE=$?

if [ ${EXIT_CODE} -eq 0 ]; then
  echo "✅ Agentic test completed successfully for ${UBUNTU_VERSION}."
else
  echo "❌ Agentic test failed for ${UBUNTU_VERSION} with exit code ${EXIT_CODE}."
fi

exit ${EXIT_CODE}

