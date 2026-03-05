#!/bin/sh
# This script reads /etc/edamame_posture.conf and launches edamame_posture
# in foreground mode. Systemd will manage the lifecycle.

set -e

CONF="/etc/edamame_posture.conf"

if [ ! -f "$CONF" ]; then
  echo "Configuration file $CONF not found!"
  exit 1
fi

# Extract a configuration value by key from a YAML-formatted file.
get_config_value() {
  key="$1"
  awk -v search="$key" -F':' '
    {
      k=$1
      gsub(/^[[:space:]]+/, "", k)
      gsub(/[[:space:]]+$/, "", k)
      if (k != search) {
        next
      }

      # Capture everything after the first colon so we keep inline comments separate
      val=substr($0, index($0, ":") + 1)
      gsub(/^[[:space:]]+/, "", val)
      sub(/[[:space:]]+#.*$/, "", val)

      # Handle quoted values
      if (val ~ /^"/) {
        sub(/^"/, "", val)
        sub(/".*$/, "", val)
      }

      # Trim any remaining surrounding whitespace
      gsub(/^[[:space:]]+/, "", val)
      gsub(/[[:space:]]+$/, "", val)

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
llm_api_key="$(get_config_value "llm_api_key")"
claude_api_key="$(get_config_value "claude_api_key")"
openai_api_key="$(get_config_value "openai_api_key")"
ollama_base_url="$(get_config_value "ollama_base_url")"

# Unified notification configuration (preferred)
notification_provider="$(get_config_value "notification_provider")"
notification_slack_bot_token="$(get_config_value "notification_slack_bot_token")"
notification_slack_channel="$(get_config_value "notification_slack_channel")"
notification_telegram_bot_token="$(get_config_value "notification_telegram_bot_token")"
notification_telegram_chat_id="$(get_config_value "notification_telegram_chat_id")"

# Legacy notification configuration (kept for backward compatibility)
slack_bot_token="$(get_config_value "slack_bot_token")"
slack_actions_channel="$(get_config_value "slack_actions_channel")"
slack_escalations_channel="$(get_config_value "slack_escalations_channel")"
telegram_bot_token="$(get_config_value "telegram_bot_token")"
telegram_chat_id="$(get_config_value "telegram_chat_id")"

first_non_empty() {
  for value in "$@"; do
    if [ -n "$value" ]; then
      printf "%s" "$value"
      return
    fi
  done
}

# Set defaults
agentic_mode="${agentic_mode:-disabled}"
agentic_interval="${agentic_interval:-3600}"
notification_provider="${notification_provider:-auto}"
# Lowercase conversion using tr since ${var,,} is bash-specific
start_lanscan=$(echo "$start_lanscan" | tr '[:upper:]' '[:lower:]')
start_capture=$(echo "$start_capture" | tr '[:upper:]' '[:lower:]')
fail_on_whitelist=$(echo "$fail_on_whitelist" | tr '[:upper:]' '[:lower:]')
fail_on_blacklist=$(echo "$fail_on_blacklist" | tr '[:upper:]' '[:lower:]')
fail_on_anomalous=$(echo "$fail_on_anomalous" | tr '[:upper:]' '[:lower:]')
cancel_on_violation=$(echo "$cancel_on_violation" | tr '[:upper:]' '[:lower:]')
include_local_traffic=$(echo "$include_local_traffic" | tr '[:upper:]' '[:lower:]')
notification_provider=$(echo "$notification_provider" | tr '[:upper:]' '[:lower:]')

# Resolve unified + legacy notification values (new keys win).
effective_slack_bot_token="$(first_non_empty "$notification_slack_bot_token" "$slack_bot_token")"
effective_slack_actions_channel="$(first_non_empty "$slack_actions_channel" "$notification_slack_channel")"
effective_slack_escalations_channel="$(first_non_empty "$slack_escalations_channel" "$notification_slack_channel" "$effective_slack_actions_channel")"
effective_telegram_bot_token="$(first_non_empty "$notification_telegram_bot_token" "$telegram_bot_token")"
effective_telegram_chat_id="$(first_non_empty "$notification_telegram_chat_id" "$telegram_chat_id")"

case "$notification_provider" in
  ""|auto|both)
    ;;
  slack)
    effective_telegram_bot_token=""
    effective_telegram_chat_id=""
    ;;
  telegram)
    effective_slack_bot_token=""
    effective_slack_actions_channel=""
    effective_slack_escalations_channel=""
    ;;
  *)
    echo "Unknown notification_provider '$notification_provider', using auto"
    ;;
esac

# Determine LLM provider based on which API key is configured (first non-empty wins)
# Priority: edamame > claude > openai > ollama
agentic_provider="none"
if [ -n "$llm_api_key" ]; then
  agentic_provider="edamame"
  export EDAMAME_LLM_API_KEY="$llm_api_key"
  echo "Using EDAMAME Portal as LLM provider"
elif [ -n "$claude_api_key" ]; then
  agentic_provider="claude"
  export EDAMAME_LLM_API_KEY="$claude_api_key"
  echo "Using Claude as LLM provider"
elif [ -n "$openai_api_key" ]; then
  agentic_provider="openai"
  export EDAMAME_LLM_API_KEY="$openai_api_key"
  echo "Using OpenAI as LLM provider"
elif [ -n "$ollama_base_url" ]; then
  agentic_provider="ollama"
  export EDAMAME_LLM_BASE_URL="$ollama_base_url"
  echo "Using Ollama as LLM provider at: $ollama_base_url"
fi

# Set unified notification environment variables if configured
if [ -n "$effective_slack_bot_token" ]; then
  export EDAMAME_AGENTIC_SLACK_BOT_TOKEN="$effective_slack_bot_token"
  # Legacy aliases kept for older builds/scripts.
  export EDAMAME_AGENTIC_WEBHOOK_ACTIONS_TOKEN="$effective_slack_bot_token"
  echo "Slack bot token configured"
fi

if [ -n "$effective_slack_actions_channel" ]; then
  export EDAMAME_AGENTIC_SLACK_ACTIONS_CHANNEL="$effective_slack_actions_channel"
  export EDAMAME_AGENTIC_WEBHOOK_ACTIONS_CHANNEL="$effective_slack_actions_channel"
  echo "Slack actions channel: $effective_slack_actions_channel"
fi

if [ -n "$effective_slack_escalations_channel" ]; then
  export EDAMAME_AGENTIC_SLACK_ESCALATIONS_CHANNEL="$effective_slack_escalations_channel"
  export EDAMAME_AGENTIC_WEBHOOK_ESCALATIONS_CHANNEL="$effective_slack_escalations_channel"
  echo "Slack escalations channel: $effective_slack_escalations_channel"
fi

if [ -n "$effective_telegram_bot_token" ] && [ -n "$effective_telegram_chat_id" ]; then
  export EDAMAME_TELEGRAM_BOT_TOKEN="$effective_telegram_bot_token"
  export EDAMAME_TELEGRAM_CHAT_ID="$effective_telegram_chat_id"
  echo "Telegram notifications configured (chat_id: $effective_telegram_chat_id)"
fi

# Build command arguments using set --
set -- foreground-start -v

# Add user/domain/pin if configured
if [ -n "$edamame_user" ] && [ -n "$edamame_domain" ] && [ -n "$edamame_pin" ]; then
  set -- "$@" --user "$edamame_user" --domain "$edamame_domain" --pin "$edamame_pin"
  echo "Starting in connected mode:"
  echo "  User: $edamame_user"
  echo "  Domain: $edamame_domain"
  
  # Add device ID if configured
  if [ -n "$edamame_device_id" ]; then
    set -- "$@" --device-id "$edamame_device_id"
    echo "  Device ID: $edamame_device_id"
  fi
else
  echo "Starting in disconnected mode (user/domain/pin not configured)"
fi

# Add agentic configuration if not disabled
if [ "$agentic_mode" != "disabled" ] && [ "$agentic_provider" != "none" ]; then
  set -- "$@" --agentic-mode "$agentic_mode"
  set -- "$@" --agentic-provider "$agentic_provider"
  set -- "$@" --agentic-interval "$agentic_interval"
  echo "AI Assistant enabled:"
  echo "  Mode: $agentic_mode"
  echo "  Provider: $agentic_provider"
  echo "  Interval: ${agentic_interval}s"
fi

# Network monitoring flags
if [ "$start_lanscan" = "true" ]; then
  set -- "$@" --network-scan
  echo "LAN scan enabled via configuration"
fi

if [ "$start_capture" = "true" ]; then
  set -- "$@" --packet-capture
  echo "Packet capture enabled via configuration"
fi

# Whitelist configuration
if [ -n "$whitelist_name" ]; then
  set -- "$@" --whitelist "$whitelist_name"
  echo "Whitelist: $whitelist_name"
fi

if [ "$fail_on_whitelist" = "true" ]; then
  set -- "$@" --fail-on-whitelist
  echo "Fail on whitelist violations: enabled"
fi

if [ "$fail_on_blacklist" = "true" ]; then
  set -- "$@" --fail-on-blacklist
  echo "Fail on blacklist matches: enabled"
fi

if [ "$fail_on_anomalous" = "true" ]; then
  set -- "$@" --fail-on-anomalous
  echo "Fail on anomalous sessions: enabled"
fi

# Violation handling
if [ "$cancel_on_violation" = "true" ]; then
  set -- "$@" --cancel-on-violation
  echo "Cancel on violation: enabled"
fi

if [ "$include_local_traffic" = "true" ]; then
  set -- "$@" --include-local-traffic
  echo "Include local traffic: enabled"
fi

echo "Starting edamame_posture service..."

# Execute the main binary in foreground mode (systemd manages daemonization)
exec /usr/bin/edamame_posture "$@"