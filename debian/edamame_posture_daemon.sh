#!/bin/bash
# File: debian/edamame_posture.sh
# This script reads /etc/edamame_posture.conf and starts the service using the main binary.

CONF="/etc/edamame_posture.conf"

if [[ ! -f "$CONF" ]]; then
  echo "Configuration file $CONF not found!"
  exit 1
fi

# Function to extract a configuration value by key from a YAML-formatted file.
get_config_value() {
  local key="$1"
  # This regex handles both quoted and unquoted values.
  local value=$(grep -E "^${key}:" "$CONF" | head -n1 | sed -E "s/^${key}:[[:space:]]*\"?([^\"\n]+)\"?.*/\1/")
  echo "$value"
}

edamame_user=$(get_config_value "edamame_user" | xargs)
edamame_domain=$(get_config_value "edamame_domain" | xargs)
edamame_pin=$(get_config_value "edamame_pin" | xargs)

if [[ -z "$edamame_user" || -z "$edamame_domain" || -z "$edamame_pin" ]]; then
  echo "One or more required configuration values are empty:"
  echo "  edamame_user='${edamame_user}', edamame_domain='${edamame_domain}', edamame_pin='${edamame_pin}'"
  exit 1
fi

echo "Starting edamame_posture daemon with configuration:"
echo "  edamame_user: $edamame_user"
echo "  edamame_domain: $edamame_domain"
echo "  edamame_pin: $edamame_pin"

# Execute the main binary with the "start" subcommand and pass the parameters.
exec /usr/bin/edamame_posture start "$edamame_user" "$edamame_domain" "$edamame_pin"