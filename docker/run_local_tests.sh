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
    echo "Usage: $0 [ubuntu25.04|ubuntu24.04|ubuntu20.04|ubuntu18.04]"
    exit 1
fi

# Load all secrets from ../secrets/*.env
for env_file in ../secrets/*.env; do
    if [ -f "$env_file" ]; then
        echo "Sourcing secrets from ${env_file}"
        # shellcheck disable=SC1090
        source "$env_file"
    fi
done

required_vars=(
  EDAMAME_USER
  EDAMAME_DOMAIN
  EDAMAME_PIN
  DEV_GITHUB_TOKEN
)

missing_vars=()
for var in "${required_vars[@]}"; do
  if [ -z "${!var:-}" ]; then
    missing_vars+=("${var}")
  fi
done

if [ ${#missing_vars[@]} -ne 0 ]; then
  echo "Error: The following required environment variables are missing: ${missing_vars[*]}" >&2
  echo "Populate them in ../secrets/*.env or export them before running this script." >&2
  exit 1
fi

# Export required vars so docker run -e VAR picks them up without leaking values into the command line
for var in "${required_vars[@]}"; do
  export "$var"
done

# --- Build Docker Image ---
echo "Building Docker image ${IMAGE_NAME} using ${DOCKERFILE}..."
# Pass build context from the parent directory (edamame_posture)
# This allows the Dockerfile to COPY . /app correctly
docker build -t "${IMAGE_NAME}" -f "${DOCKERFILE}" .

# --- Run Docker Container ---
echo "Running container tests in ${IMAGE_NAME}..."

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

for var in "${required_vars[@]}"; do
    add_env_if_set "$var"
done

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
add_env_if_set EDAMAME_LOG_LEVEL

docker_args+=("${IMAGE_NAME}")

docker run "${docker_args[@]}"

EXIT_CODE=$?

if [ $EXIT_CODE -eq 0 ]; then
    echo "✅ Docker container tests completed successfully for ${UBUNTU_VERSION}."
else
    echo "❌ Docker container tests failed for ${UBUNTU_VERSION} with exit code ${EXIT_CODE}."
fi

exit $EXIT_CODE 