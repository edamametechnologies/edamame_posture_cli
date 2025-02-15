#!/bin/bash
# This script reads /etc/edamame_posture.conf and launches edamame_posture
# in foreground mode. Systemd will manage the lifecycle.

set -euo pipefail

CONF="/etc/edamame_posture.conf"

if [[ ! -f "$CONF" ]]; then
  echo "Configuration file $CONF not found!"
  exit 1
fi

# Extract a configuration value by key from a YAML-formatted file.
get_config_value() {
  local key="$1"
  grep -E "^${key}:" "$CONF" | head -n1 | sed -E "s/^${key}:[[:space:]]*\"?([^\"\n]+)\"?.*/\1/"
}

edamame_user="$(get_config_value "edamame_user" | xargs)"
edamame_domain="$(get_config_value "edamame_domain" | xargs)"
edamame_pin="$(get_config_value "edamame_pin" | xargs)"

if [[ -z "$edamame_user" || -z "$edamame_domain" || -z "$edamame_pin" ]]; then
  echo "One or required configuration values are empty:"
  echo "  edamame_user='${edamame_user}', edamame_domain='${edamame_domain}', edamame_pin='${edamame_pin}'"
  echo "Service will start disconnected."
fi

echo "Starting edamame_posture service with configuration:"
echo "  edamame_user: $edamame_user"
echo "  edamame_domain: $edamame_domain"
echo "  edamame_pin: $edamame_pin"

# Execute the main binary in foreground mode (systemd manages daemonization)
exec /usr/bin/edamame_posture foreground-start "$edamame_user" "$edamame_domain" "$edamame_pin"