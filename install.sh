#!/bin/sh
# EDAMAME Posture Installer
# Usage: curl --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/edamametechnologies/edamame_posture_cli/main/install.sh | sh

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
    
    "ubuntu"|"debian"|"pop"|"linuxmint"|"elementary"|"zorin")
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

# Verify installation
info ""
info "Verifying installation..."
if command -v edamame_posture >/dev/null 2>&1; then
    VERSION=$(edamame_posture get-core-version 2>/dev/null || echo "unknown")
    info "✓ EDAMAME Posture installed successfully!"
    info "  Version: $VERSION"
    info "  Location: $(command -v edamame_posture)"
    info ""
    info "Quick Start:"
    info "  sudo edamame_posture score          # Check security posture"
    info "  sudo edamame_posture remediate      # Auto-fix security issues"
    info "  edamame_posture --help              # See all commands"
else
    error "Installation verification failed. edamame_posture command not found."
fi

