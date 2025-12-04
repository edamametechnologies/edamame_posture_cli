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
  awk -v search="$key" '
    $0 ~ "^" search ":[[:space:]]*" {
      line=$0
      sub("^" search ":[[:space:]]*", "", line)
      if (line ~ /^"/) {
        match(line, /^"([^"]*)"/, captured)
        val=captured[1]
      } else {
        sub(/[[:space:]]+#.*$/, "", line)
        val=line
      }
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", val)
      print val
      exit
    }
  ' "$CONF"
}

edamame_user="$(get_config_value "edamame_user")"
edamame_domain="$(get_config_value "edamame_domain")"
edamame_pin="$(get_config_value "edamame_pin")"
edamame_device_id="$(get_config_value "edamame_device_id")"
start_lanscan="$(get_config_value "start_lanscan")"
start_capture="$(get_config_value "start_capture")"

# Network configuration
whitelist_name="$(get_config_value "whitelist_name")"
fail_on_whitelist="$(get_config_value "fail_on_whitelist")"
fail_on_blacklist="$(get_config_value "fail_on_blacklist")"
fail_on_anomalous="$(get_config_value "fail_on_anomalous")"
cancel_on_violation="$(get_config_value "cancel_on_violation")"
include_local_traffic="$(get_config_value "include_local_traffic")"

# Agentic configuration
agentic_mode="$(get_config_value "agentic_mode")"
agentic_interval="$(get_config_value "agentic_interval")"
claude_api_key="$(get_config_value "claude_api_key")"
openai_api_key="$(get_config_value "openai_api_key")"
ollama_base_url="$(get_config_value "ollama_base_url")"
slack_bot_token="$(get_config_value "slack_bot_token")"
slack_actions_channel="$(get_config_value "slack_actions_channel")"
slack_escalations_channel="$(get_config_value "slack_escalations_channel")"

# Set defaults
agentic_mode="${agentic_mode:-disabled}"
agentic_interval="${agentic_interval:-3600}"
start_lanscan="${start_lanscan,,}"
start_capture="${start_capture,,}"
fail_on_whitelist="${fail_on_whitelist,,}"
fail_on_blacklist="${fail_on_blacklist,,}"
fail_on_anomalous="${fail_on_anomalous,,}"
cancel_on_violation="${cancel_on_violation,,}"
include_local_traffic="${include_local_traffic,,}"

# Determine LLM provider based on which API key is configured (first non-empty wins)
agentic_provider="none"
if [[ -n "$claude_api_key" ]]; then
  agentic_provider="claude"
  export EDAMAME_LLM_API_KEY="$claude_api_key"
  echo "Using Claude as LLM provider"
elif [[ -n "$openai_api_key" ]]; then
  agentic_provider="openai"
  export EDAMAME_LLM_API_KEY="$openai_api_key"
  echo "Using OpenAI as LLM provider"
elif [[ -n "$ollama_base_url" ]]; then
  agentic_provider="ollama"
  export EDAMAME_LLM_BASE_URL="$ollama_base_url"
  echo "Using Ollama as LLM provider at: $ollama_base_url"
fi

# Set Slack environment variables if configured
if [[ -n "$slack_bot_token" ]]; then
  export EDAMAME_AGENTIC_SLACK_BOT_TOKEN="$slack_bot_token"
  echo "Slack bot token configured"
fi

if [[ -n "$slack_actions_channel" ]]; then
  export EDAMAME_AGENTIC_SLACK_ACTIONS_CHANNEL="$slack_actions_channel"
  echo "Slack actions channel: $slack_actions_channel"
fi

if [[ -n "$slack_escalations_channel" ]]; then
  export EDAMAME_AGENTIC_SLACK_ESCALATIONS_CHANNEL="$slack_escalations_channel"
  echo "Slack escalations channel: $slack_escalations_channel"
fi

# Build command arguments
CMD_ARGS=(foreground-start -v)

# Add user/domain/pin if configured
if [[ -n "$edamame_user" && -n "$edamame_domain" && -n "$edamame_pin" ]]; then
  CMD_ARGS+=(--user "$edamame_user" --domain "$edamame_domain" --pin "$edamame_pin")
  echo "Starting in connected mode:"
  echo "  User: $edamame_user"
  echo "  Domain: $edamame_domain"
  
  # Add device ID if configured
  if [[ -n "$edamame_device_id" ]]; then
    CMD_ARGS+=(--device-id "$edamame_device_id")
    echo "  Device ID: $edamame_device_id"
  fi
else
  echo "Starting in disconnected mode (user/domain/pin not configured)"
fi

# Add agentic configuration if not disabled
if [[ "$agentic_mode" != "disabled" && "$agentic_provider" != "none" ]]; then
  CMD_ARGS+=(--agentic-mode "$agentic_mode")
  CMD_ARGS+=(--agentic-provider "$agentic_provider")
  CMD_ARGS+=(--agentic-interval "$agentic_interval")
  echo "AI Assistant enabled:"
  echo "  Mode: $agentic_mode"
  echo "  Provider: $agentic_provider"
  echo "  Interval: ${agentic_interval}s"
fi

# Network monitoring flags
if [[ "$start_lanscan" == "true" ]]; then
  CMD_ARGS+=(--network-scan)
  echo "LAN scan enabled via configuration"
fi

if [[ "$start_capture" == "true" ]]; then
  CMD_ARGS+=(--packet-capture)
  echo "Packet capture enabled via configuration"
fi

# Whitelist configuration
if [[ -n "$whitelist_name" ]]; then
  CMD_ARGS+=(--whitelist "$whitelist_name")
  echo "Whitelist: $whitelist_name"
fi

if [[ "$fail_on_whitelist" == "true" ]]; then
  CMD_ARGS+=(--fail-on-whitelist)
  echo "Fail on whitelist violations: enabled"
fi

if [[ "$fail_on_blacklist" == "true" ]]; then
  CMD_ARGS+=(--fail-on-blacklist)
  echo "Fail on blacklist matches: enabled"
fi

if [[ "$fail_on_anomalous" == "true" ]]; then
  CMD_ARGS+=(--fail-on-anomalous)
  echo "Fail on anomalous sessions: enabled"
fi

# Violation handling
if [[ "$cancel_on_violation" == "true" ]]; then
  CMD_ARGS+=(--cancel-on-violation)
  echo "Cancel on violation: enabled"
fi

if [[ "$include_local_traffic" == "true" ]]; then
  CMD_ARGS+=(--include-local-traffic)
  echo "Include local traffic: enabled"
fi

echo "Starting edamame_posture service..."

# Execute the main binary in foreground mode (systemd manages daemonization)
exec /usr/bin/edamame_posture "${CMD_ARGS[@]}"