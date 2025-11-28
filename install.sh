#!/bin/sh
# EDAMAME Posture Installer
# Usage: curl --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/edamametechnologies/edamame_posture_cli/main/install.sh | sh -s -- [OPTIONS]
#
# Options:
#   --user USER                    EDAMAME user
#   --domain DOMAIN                EDAMAME domain
#   --pin PIN                      EDAMAME pin
#   --claude-api-key KEY           Claude API key
#   --openai-api-key KEY           OpenAI API key
#   --ollama-api-key KEY           Ollama API key (deprecated, use base URL)
#   --ollama-base-url URL          Ollama base URL (default: http://localhost:11434)
#   --agentic-mode MODE            AI mode: auto, analyze, or disabled (default: disabled)
#   --agentic-interval SECONDS     Processing interval in seconds (default: 3600)
#   --slack-bot-token TOKEN        Slack bot token
#   --slack-actions-channel ID     Slack actions channel ID
#   --slack-escalations-channel ID Slack escalations channel ID
#   --start-service                Start/restart systemd service after configuration
#
# Example:
#   curl -sSf https://raw.githubusercontent.com/.../install.sh | sh -s -- \
#     --user myuser --domain example.com --pin 123456 \
#     --claude-api-key sk-ant-... --agentic-mode auto \
#     --start-service

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

info() {
    printf "${GREEN}[INFO]${NC} %s\n" "$1"
}

warn() {
    printf "${YELLOW}[WARN]${NC} %s\n" "$1"
}

error() {
    printf "${RED}[ERROR]${NC} %s\n" "$1"
    exit 1
}

# Parse command line arguments
CONFIG_USER=""
CONFIG_DOMAIN=""
CONFIG_PIN=""
CONFIG_CLAUDE_KEY=""
CONFIG_OPENAI_KEY=""
CONFIG_OLLAMA_URL=""
CONFIG_AGENTIC_MODE="disabled"
CONFIG_AGENTIC_INTERVAL="3600"
CONFIG_SLACK_BOT_TOKEN=""
CONFIG_SLACK_ACTIONS_CHANNEL=""
CONFIG_SLACK_ESCALATIONS_CHANNEL=""
START_SERVICE=false

while [ $# -gt 0 ]; do
    case "$1" in
        --user)
            CONFIG_USER="$2"
            shift 2
            ;;
        --domain)
            CONFIG_DOMAIN="$2"
            shift 2
            ;;
        --pin)
            CONFIG_PIN="$2"
            shift 2
            ;;
        --claude-api-key)
            CONFIG_CLAUDE_KEY="$2"
            shift 2
            ;;
        --openai-api-key)
            CONFIG_OPENAI_KEY="$2"
            shift 2
            ;;
        --ollama-api-key)
            # Deprecated but kept for compatibility
            warn "Note: --ollama-api-key is deprecated, Ollama doesn't use API keys"
            shift 2
            ;;
        --ollama-base-url)
            CONFIG_OLLAMA_URL="$2"
            shift 2
            ;;
        --agentic-mode)
            CONFIG_AGENTIC_MODE="$2"
            shift 2
            ;;
        --agentic-interval)
            CONFIG_AGENTIC_INTERVAL="$2"
            shift 2
            ;;
        --slack-bot-token)
            CONFIG_SLACK_BOT_TOKEN="$2"
            shift 2
            ;;
        --slack-actions-channel)
            CONFIG_SLACK_ACTIONS_CHANNEL="$2"
            shift 2
            ;;
        --slack-escalations-channel)
            CONFIG_SLACK_ESCALATIONS_CHANNEL="$2"
            shift 2
            ;;
        --start-service)
            START_SERVICE=true
            shift
            ;;
        *)
            warn "Unknown option: $1"
            shift
            ;;
    esac
done

# Check if running as root
if [ "$(id -u)" -eq 0 ]; then
    SUDO=""
else
    if command -v sudo >/dev/null 2>&1; then
        SUDO="sudo"
    else
        error "This script requires sudo privileges. Please install sudo or run as root."
    fi
fi

info "EDAMAME Posture Installer"
info "========================="

# Detect OS
if [ ! -f /etc/os-release ]; then
    error "/etc/os-release not found. Unable to detect Linux distribution."
fi

. /etc/os-release

info "Detected OS: $ID"
ARCH=$(uname -m)
info "Architecture: $ARCH"

# Install based on distribution
case "$ID" in
    "alpine")
        info "Installing via Alpine APK..."
        
        # Determine Alpine repository URL
        REPO_URL="https://edamame.s3.eu-west-1.amazonaws.com/repo/alpine/v3.15/main"
        
        # Check if repository is already configured
        if ! grep -q "$REPO_URL" /etc/apk/repositories 2>/dev/null; then
            info "Adding EDAMAME APK repository..."
            
            # Download and install signing key
            if command -v wget >/dev/null 2>&1; then
                wget -q -O /tmp/edamame.rsa.pub "https://edamame.s3.eu-west-1.amazonaws.com/repo/alpine/v3.15/${ARCH}/edamame.rsa.pub" || \
                    warn "Failed to download signing key"
            elif command -v curl >/dev/null 2>&1; then
                curl -sL -o /tmp/edamame.rsa.pub "https://edamame.s3.eu-west-1.amazonaws.com/repo/alpine/v3.15/${ARCH}/edamame.rsa.pub" || \
                    warn "Failed to download signing key"
            else
                error "Neither wget nor curl found. Please install one of them."
            fi
            
            if [ -f /tmp/edamame.rsa.pub ]; then
                $SUDO cp /tmp/edamame.rsa.pub /etc/apk/keys/edamame.rsa.pub
                info "Signing key installed"
            fi
            
            # Add repository
            echo "$REPO_URL" | $SUDO tee -a /etc/apk/repositories >/dev/null
            info "Repository added"
        fi
        
        # Update package list
        info "Updating package list..."
        $SUDO apk update
        
        # Install edamame-posture
        info "Installing edamame-posture..."
        $SUDO apk add edamame-posture
        
        info "Installation complete!"
        ;;
    
    "ubuntu"|"debian"|"raspbian"|"pop"|"linuxmint"|"elementary"|"zorin")
        info "Installing via APT..."
        
        # Check if repository is already configured
        if ! grep -q "edamame.s3.eu-west-1.amazonaws.com/repo" /etc/apt/sources.list.d/edamame.list 2>/dev/null; then
            info "Adding EDAMAME APT repository..."
            
            # Install required tools
            if ! command -v gpg >/dev/null 2>&1; then
                info "Installing gnupg..."
                $SUDO apt-get update -qq
                $SUDO apt-get install -y gnupg
            fi
            
            if ! command -v wget >/dev/null 2>&1 && ! command -v curl >/dev/null 2>&1; then
                info "Installing wget..."
                $SUDO apt-get update -qq
                $SUDO apt-get install -y wget
            fi
            
            # Import GPG key
            if command -v wget >/dev/null 2>&1; then
                wget -q -O - https://edamame.s3.eu-west-1.amazonaws.com/repo/public.key | \
                    $SUDO gpg --dearmor -o /usr/share/keyrings/edamame.gpg
            else
                curl -sL https://edamame.s3.eu-west-1.amazonaws.com/repo/public.key | \
                    $SUDO gpg --dearmor -o /usr/share/keyrings/edamame.gpg
            fi
            info "GPG key imported"
            
            # Add repository
            DEB_ARCH=$(dpkg --print-architecture 2>/dev/null || echo "amd64")
            echo "deb [arch=${DEB_ARCH} signed-by=/usr/share/keyrings/edamame.gpg] https://edamame.s3.eu-west-1.amazonaws.com/repo stable main" | \
                $SUDO tee /etc/apt/sources.list.d/edamame.list >/dev/null
            info "Repository added"
        fi
        
        # Update package list
        info "Updating package list..."
        $SUDO apt-get update -qq
        
        # Install edamame-posture
        info "Installing edamame-posture..."
        $SUDO apt-get install -y edamame-posture
        
        info "Installation complete!"
        info "Configure /etc/edamame_posture.conf and restart service, or run 'edamame_posture --help'"
        ;;
    
    *)
        error "Unsupported distribution: $ID. Supported: Alpine, Debian, Ubuntu and derivatives."
        ;;
esac

# Configure service if configuration parameters were provided
configure_service() {
    CONF_FILE="/etc/edamame_posture.conf"
    
    # Only configure if config file exists (Debian/Ubuntu/Raspbian/Alpine with service)
    if [ ! -f "$CONF_FILE" ]; then
        info "No service configuration file found at $CONF_FILE"
        info "Service configuration only available for APT/APK installations"
        return 0
    fi
    
    # Check if any configuration was provided
    if [ -z "$CONFIG_USER" ] && [ -z "$CONFIG_CLAUDE_KEY" ] && [ -z "$CONFIG_OPENAI_KEY" ] && [ -z "$CONFIG_OLLAMA_URL" ] && [ "$CONFIG_AGENTIC_MODE" = "disabled" ]; then
        info "No configuration parameters provided, skipping service configuration"
        return 0
    fi
    
    info "Configuring EDAMAME Posture service..."
    
    # Create temporary config file
    TMP_CONF=$(mktemp)
    cat > "$TMP_CONF" << 'EOF'
# EDAMAME Posture Service Configuration
# This file is read by the systemd service to configure edamame_posture

# ============================================================================
# Connection Settings (leave empty for disconnected mode)
# ============================================================================
edamame_user: "CONFIG_USER_PLACEHOLDER"
edamame_domain: "CONFIG_DOMAIN_PLACEHOLDER"
edamame_pin: "CONFIG_PIN_PLACEHOLDER"

# ============================================================================
# AI Assistant (Agentic) Configuration
# ============================================================================

# Agentic Mode
# - auto: Automatically process and resolve safe/low-risk todos; escalate high-risk items
# - analyze: Gather recommendations without executing changes
# - disabled: No AI processing (default)
agentic_mode: "CONFIG_AGENTIC_MODE_PLACEHOLDER"

# ============================================================================
# LLM Provider Configuration (first non-empty API key/URL will be used)
# ============================================================================

# Claude (Anthropic) - Recommended
claude_api_key: "CONFIG_CLAUDE_KEY_PLACEHOLDER"

# OpenAI
openai_api_key: "CONFIG_OPENAI_KEY_PLACEHOLDER"

# Ollama (Local) - Privacy First
ollama_base_url: "CONFIG_OLLAMA_URL_PLACEHOLDER"

# ============================================================================
# Slack Notifications (optional)
# ============================================================================

# Slack Bot Token (starts with xoxb-)
slack_bot_token: "CONFIG_SLACK_BOT_TOKEN_PLACEHOLDER"

# Slack Actions Channel (channel ID, e.g., C01234567)
slack_actions_channel: "CONFIG_SLACK_ACTIONS_CHANNEL_PLACEHOLDER"

# Slack Escalations Channel (channel ID, e.g., C07654321)
slack_escalations_channel: "CONFIG_SLACK_ESCALATIONS_CHANNEL_PLACEHOLDER"

# ============================================================================
# Agentic Processing Configuration
# ============================================================================

# Processing interval in seconds
agentic_interval: "CONFIG_AGENTIC_INTERVAL_PLACEHOLDER"
EOF
    
    # Replace placeholders with actual values (using portable sed syntax)
    sed "s|CONFIG_USER_PLACEHOLDER|${CONFIG_USER}|g" "$TMP_CONF" > "${TMP_CONF}.new" && mv "${TMP_CONF}.new" "$TMP_CONF"
    sed "s|CONFIG_DOMAIN_PLACEHOLDER|${CONFIG_DOMAIN}|g" "$TMP_CONF" > "${TMP_CONF}.new" && mv "${TMP_CONF}.new" "$TMP_CONF"
    sed "s|CONFIG_PIN_PLACEHOLDER|${CONFIG_PIN}|g" "$TMP_CONF" > "${TMP_CONF}.new" && mv "${TMP_CONF}.new" "$TMP_CONF"
    sed "s|CONFIG_CLAUDE_KEY_PLACEHOLDER|${CONFIG_CLAUDE_KEY}|g" "$TMP_CONF" > "${TMP_CONF}.new" && mv "${TMP_CONF}.new" "$TMP_CONF"
    sed "s|CONFIG_OPENAI_KEY_PLACEHOLDER|${CONFIG_OPENAI_KEY}|g" "$TMP_CONF" > "${TMP_CONF}.new" && mv "${TMP_CONF}.new" "$TMP_CONF"
    sed "s|CONFIG_OLLAMA_URL_PLACEHOLDER|${CONFIG_OLLAMA_URL}|g" "$TMP_CONF" > "${TMP_CONF}.new" && mv "${TMP_CONF}.new" "$TMP_CONF"
    sed "s|CONFIG_AGENTIC_MODE_PLACEHOLDER|${CONFIG_AGENTIC_MODE}|g" "$TMP_CONF" > "${TMP_CONF}.new" && mv "${TMP_CONF}.new" "$TMP_CONF"
    sed "s|CONFIG_AGENTIC_INTERVAL_PLACEHOLDER|${CONFIG_AGENTIC_INTERVAL}|g" "$TMP_CONF" > "${TMP_CONF}.new" && mv "${TMP_CONF}.new" "$TMP_CONF"
    sed "s|CONFIG_SLACK_BOT_TOKEN_PLACEHOLDER|${CONFIG_SLACK_BOT_TOKEN}|g" "$TMP_CONF" > "${TMP_CONF}.new" && mv "${TMP_CONF}.new" "$TMP_CONF"
    sed "s|CONFIG_SLACK_ACTIONS_CHANNEL_PLACEHOLDER|${CONFIG_SLACK_ACTIONS_CHANNEL}|g" "$TMP_CONF" > "${TMP_CONF}.new" && mv "${TMP_CONF}.new" "$TMP_CONF"
    sed "s|CONFIG_SLACK_ESCALATIONS_CHANNEL_PLACEHOLDER|${CONFIG_SLACK_ESCALATIONS_CHANNEL}|g" "$TMP_CONF" > "${TMP_CONF}.new" && mv "${TMP_CONF}.new" "$TMP_CONF"
    
    # Copy to final location
    $SUDO cp "$TMP_CONF" "$CONF_FILE"
    $SUDO chmod 600 "$CONF_FILE"  # Protect API keys
    rm -f "$TMP_CONF"
    
    info "✓ Service configuration updated at $CONF_FILE"
    
    # Start or restart service if requested
    if [ "$START_SERVICE" = true ]; then
        info "Starting/restarting EDAMAME Posture service..."
        
        case "$ID" in
            "alpine")
                if command -v rc-service >/dev/null 2>&1; then
                    $SUDO rc-service edamame_posture restart 2>/dev/null || \
                    $SUDO rc-service edamame_posture start 2>/dev/null || \
                    warn "Failed to start service via rc-service"
                fi
                ;;
            "ubuntu"|"debian"|"raspbian"|"pop"|"linuxmint"|"elementary"|"zorin")
                if command -v systemctl >/dev/null 2>&1; then
                    $SUDO systemctl daemon-reload 2>/dev/null || true
                    $SUDO systemctl enable edamame_posture.service 2>/dev/null || true
                    $SUDO systemctl restart edamame_posture.service 2>/dev/null || \
                    warn "Failed to restart service. Check: sudo systemctl status edamame_posture"
                fi
                ;;
        esac
        
        info "✓ Service started"
        
        # Show service status
        case "$ID" in
            "alpine")
                if command -v rc-service >/dev/null 2>&1; then
                    $SUDO rc-service edamame_posture status 2>/dev/null || true
                fi
                ;;
            "ubuntu"|"debian"|"raspbian"|"pop"|"linuxmint"|"elementary"|"zorin")
                if command -v systemctl >/dev/null 2>&1; then
                    $SUDO systemctl status edamame_posture.service --no-pager || true
                fi
                ;;
        esac
    fi
}

# Verify installation
info ""
info "Verifying installation..."
if command -v edamame_posture >/dev/null 2>&1; then
    VERSION=$(edamame_posture get-core-version 2>/dev/null || echo "unknown")
    info "✓ EDAMAME Posture installed successfully!"
    info "  Version: $VERSION"
    info "  Location: $(command -v edamame_posture)"
    
    # Configure service if parameters provided
    configure_service
    
    info ""
    info "Quick Start:"
    info "  sudo edamame_posture score          # Check security posture"
    info "  sudo edamame_posture remediate      # Auto-fix security issues"
    info "  edamame_posture --help              # See all commands"
    
    if [ -f "/etc/edamame_posture.conf" ]; then
        info ""
        info "Service Management:"
        info "  sudo systemctl status edamame_posture   # Check service status"
        info "  sudo systemctl restart edamame_posture  # Restart service"
        info "  sudo nano /etc/edamame_posture.conf     # Edit configuration"
    fi
else
    error "Installation verification failed. edamame_posture command not found."
fi

