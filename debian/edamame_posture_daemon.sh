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

# Agentic configuration
agentic_mode="$(get_config_value "agentic_mode" | xargs)"
agentic_interval="$(get_config_value "agentic_interval" | xargs)"
claude_api_key="$(get_config_value "claude_api_key" | xargs)"
openai_api_key="$(get_config_value "openai_api_key" | xargs)"
ollama_base_url="$(get_config_value "ollama_base_url" | xargs)"
slack_bot_token="$(get_config_value "slack_bot_token" | xargs)"
slack_actions_channel="$(get_config_value "slack_actions_channel" | xargs)"
slack_escalations_channel="$(get_config_value "slack_escalations_channel" | xargs)"

# Set defaults
agentic_mode="${agentic_mode:-disabled}"
agentic_interval="${agentic_interval:-3600}"

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

echo "Starting edamame_posture service..."

# Execute the main binary in foreground mode (systemd manages daemonization)
exec /usr/bin/edamame_posture "${CMD_ARGS[@]}"