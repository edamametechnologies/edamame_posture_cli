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

detect_platform() {
    local uname_out
    uname_out=$(uname -s 2>/dev/null || echo "unknown")
    case "$uname_out" in
        Linux) echo "linux" ;;
        Darwin) echo "macos" ;;
        MINGW*|MSYS*|CYGWIN*) echo "windows" ;;
        *) echo "unknown" ;;
    esac
}

download_file() {
    # $1 -> url, $2 -> destination
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$1" -o "$2"
    elif command -v wget >/dev/null 2>&1; then
        wget -q "$1" -O "$2"
    else
        return 1
    fi
}

version_lt() {
    # returns 0 if $1 < $2
    [ "$1" = "$2" ] && return 1
    local smallest
    smallest=$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1)
    [ "$smallest" = "$1" ] && [ "$1" != "$2" ]
}

detect_glibc_version() {
    if command -v getconf >/dev/null 2>&1; then
        getconf GNU_LIBC_VERSION 2>/dev/null | awk '{print $2}'
    else
        echo ""
    fi
}

REPO_BASE_URL="https://github.com/edamametechnologies/edamame_posture_cli"
FALLBACK_VERSION="0.9.75"
LATEST_RELEASE_TAG_PRIMARY=""
LATEST_RELEASE_TAG_SECONDARY=""
ARTIFACT_SECONDARY_URL=""

systemd_available() {
    if [ -d /run/systemd/system ]; then
        return 0
    fi
    local init_cmd
    init_cmd=$(ps -p 1 -o comm= 2>/dev/null | tr -d ' ')
    [ "$init_cmd" = "systemd" ]
}

credentials_provided() {
    [ -n "$CONFIG_USER" ] && [ -n "$CONFIG_DOMAIN" ] && [ -n "$CONFIG_PIN" ]
}

stop_existing_posture() {
    info "Stopping existing edamame_posture instances..."
    if [ "$PLATFORM" = "windows" ]; then
        taskkill //F //IM edamame_posture.exe >/dev/null 2>&1 || true
    else
        if command -v edamame_posture >/dev/null 2>&1; then
            if [ -n "$SUDO" ]; then
                $SUDO edamame_posture stop >/dev/null 2>&1 || true
            else
                edamame_posture stop >/dev/null 2>&1 || true
            fi
        fi
        pkill -f edamame_posture >/dev/null 2>&1 || true
    fi
}

fetch_latest_version() {
    local api_url="${REPO_BASE_URL}/releases/latest"
    local json=""
    if command -v curl >/dev/null 2>&1; then
        json=$(curl -fsSL "$api_url" 2>/dev/null || echo "")
    elif command -v wget >/dev/null 2>&1; then
        json=$(wget -q -O - "$api_url" 2>/dev/null || echo "")
    fi
    echo "$json" | grep -m1 '"tag_name"' | sed -E 's/.*"v?([^"]+)".*/\1/' | sed 's/^v//'
}

determine_linux_suffix() {
    # $1 -> arch, $2 -> libc flavor (gnu|musl)
    local arch="$1"
    local libc="$2"
    case "$arch" in
        x86_64)
            if [ "$libc" = "musl" ]; then
                echo "x86_64-unknown-linux-musl"
            else
                echo "x86_64-unknown-linux-gnu"
            fi
            ;;
        i686)
            echo "i686-unknown-linux-gnu"
            ;;
        aarch64)
            if [ "$libc" = "musl" ]; then
                echo "aarch64-unknown-linux-musl"
            else
                echo "aarch64-unknown-linux-gnu"
            fi
            ;;
        armv7|armv7l|armhf)
            echo "armv7-unknown-linux-gnueabihf"
            ;;
        *)
            error "Unsupported Linux architecture: $arch"
            ;;
    esac
}

fetch_latest_release_tag() {
    if [ -n "$LATEST_RELEASE_TAG_PRIMARY" ]; then
        return 0
    fi
    local api="https://api.github.com/repos/edamametechnologies/edamame_posture_cli/releases?per_page=2"
    local response=""
    if command -v curl >/dev/null 2>&1; then
        response=$(curl -fsSL "$api" 2>/dev/null || echo "")
    elif command -v wget >/dev/null 2>&1; then
        response=$(wget -q -O - "$api" 2>/dev/null || echo "")
    fi
    if [ -n "$response" ]; then
        local tags
        tags=$(printf '%s\n' "$response" | awk -F\" '/"tag_name"/ {gsub(/^v/, "", $4); if($4!="") print $4}')
        LATEST_RELEASE_TAG_PRIMARY=$(printf '%s\n' "$tags" | sed -n '1p')
        LATEST_RELEASE_TAG_SECONDARY=$(printf '%s\n' "$tags" | sed -n '2p')
        if [ -n "$LATEST_RELEASE_TAG_PRIMARY" ]; then
            return 0
        fi
    fi
    return 1
}

prepare_binary_artifact() {
    # Sets ARTIFACT_NAME, ARTIFACT_URL, ARTIFACT_FALLBACK_NAME, ARTIFACT_FALLBACK_URL, ARTIFACT_EXT
    local platform="$1"
    local libc_flavor="$2"
    ARTIFACT_EXT=""
    local suffix=""
    local version=""

    case "$platform" in
        linux)
            suffix=$(determine_linux_suffix "$LINUX_ARCH_NORMALIZED" "$libc_flavor")
            ;;
        macos)
            suffix="universal-apple-darwin"
            ;;
        windows)
            suffix="x86_64-pc-windows-msvc"
            ARTIFACT_EXT=".exe"
            ;;
        *)
            error "Unsupported platform for binary installation: $platform"
            ;;
    esac

    ARTIFACT_SECONDARY_URL=""
    # All binaries include version number in the filename
    if fetch_latest_release_tag; then
        if [ -n "$LATEST_RELEASE_TAG_PRIMARY" ]; then
            version="$LATEST_RELEASE_TAG_PRIMARY"
        else
            version=$(fetch_latest_version)
            if [ -z "$version" ]; then
                warn "Failed to determine latest release version, using $FALLBACK_VERSION"
                version="$FALLBACK_VERSION"
            fi
        fi
    else
        version=$(fetch_latest_version)
        if [ -z "$version" ]; then
            warn "Failed to determine latest release version, using $FALLBACK_VERSION"
            version="$FALLBACK_VERSION"
        fi
    fi

    if [ "$CONFIG_DEBUG_BUILD" = "true" ]; then
        ARTIFACT_NAME="edamame_posture-${version}-${suffix}-debug${ARTIFACT_EXT}"
        ARTIFACT_FALLBACK_NAME="edamame_posture-${FALLBACK_VERSION}-${suffix}-debug${ARTIFACT_EXT}"
        ARTIFACT_URL="${REPO_BASE_URL}/releases/download/v${version}/${ARTIFACT_NAME}"
        ARTIFACT_FALLBACK_URL="${REPO_BASE_URL}/releases/download/v${FALLBACK_VERSION}/${ARTIFACT_FALLBACK_NAME}"
    else
        ARTIFACT_NAME="edamame_posture-${version}-${suffix}${ARTIFACT_EXT}"
        ARTIFACT_FALLBACK_NAME="edamame_posture-${FALLBACK_VERSION}-${suffix}${ARTIFACT_EXT}"
        if fetch_latest_release_tag; then
            if [ -n "$LATEST_RELEASE_TAG_PRIMARY" ]; then
                ARTIFACT_URL="${REPO_BASE_URL}/releases/download/v${LATEST_RELEASE_TAG_PRIMARY}/${ARTIFACT_NAME}"
            else
                ARTIFACT_URL="${REPO_BASE_URL}/releases/latest/download/${ARTIFACT_NAME}"
            fi
            if [ -n "$LATEST_RELEASE_TAG_SECONDARY" ]; then
                ARTIFACT_SECONDARY_NAME="edamame_posture-${LATEST_RELEASE_TAG_SECONDARY}-${suffix}${ARTIFACT_EXT}"
                ARTIFACT_SECONDARY_URL="${REPO_BASE_URL}/releases/download/v${LATEST_RELEASE_TAG_SECONDARY}/${ARTIFACT_SECONDARY_NAME}"
            fi
        else
            ARTIFACT_URL="${REPO_BASE_URL}/releases/latest/download/${ARTIFACT_NAME}"
        fi
        ARTIFACT_FALLBACK_URL="${REPO_BASE_URL}/releases/download/v${FALLBACK_VERSION}/${ARTIFACT_FALLBACK_NAME}"
    fi
}

install_binary_release() {
    local platform="$1"
    local libc_flavor="$2"
    prepare_binary_artifact "$platform" "$libc_flavor"

    local tmp_bin
    tmp_bin=$(mktemp)

    info "Downloading binary from ${ARTIFACT_URL}"
    if ! download_file "$ARTIFACT_URL" "$tmp_bin"; then
        warn "Primary binary download failed (URL: ${ARTIFACT_URL}), attempting fallback..."
        local downloaded="false"
        if [ -n "$ARTIFACT_SECONDARY_URL" ]; then
            info "Attempting previous release tag at ${ARTIFACT_SECONDARY_URL}"
            if download_file "$ARTIFACT_SECONDARY_URL" "$tmp_bin"; then
                info "Downloaded EDAMAME Posture from previous release tag."
                downloaded="true"
            else
                warn "Previous release tag download failed (URL: ${ARTIFACT_SECONDARY_URL})"
            fi
        fi
        if [ "$downloaded" = "false" ]; then
            info "Attempting pinned fallback at ${ARTIFACT_FALLBACK_URL}"
            if download_file "$ARTIFACT_FALLBACK_URL" "$tmp_bin"; then
                downloaded="true"
            else
                warn "Pinned fallback download failed (URL: ${ARTIFACT_FALLBACK_URL})"
            fi
        fi
        if [ "$downloaded" = "false" ]; then
            if [ "$platform" = "windows" ] && [ "$CONFIG_FORCE_BINARY" != "true" ]; then
                warn "Binary download failed on Windows, retrying via Chocolatey..."
                rm -f "$tmp_bin"
                if install_windows_via_choco; then
                    return 0
                fi
            fi
            rm -f "$tmp_bin"
            error "Failed to download EDAMAME Posture binary."
        fi
    fi

    if [ "$platform" != "windows" ]; then
        chmod +x "$tmp_bin" || true
    fi

    local target_dir="$INSTALL_DIR"
    if [ -z "$target_dir" ]; then
        target_dir="$HOME"
    fi

    local target_name="edamame_posture${ARTIFACT_EXT}"
    local target_path="$target_dir/$target_name"

    if [ -f "$target_path" ]; then
        if credentials_provided; then
            info "Existing binary detected at $target_path with credentials supplied. Refreshing binary..."
            stop_existing_posture || true
            rm -f "$target_path" || warn "Failed to remove existing binary at $target_path"
        else
            info "Existing binary detected at $target_path; reusing (remove it to force a fresh download)."
            FINAL_BINARY_PATH="$target_path"
            BINARY_PATH="$target_path"
            if [ -z "$INSTALL_METHOD" ] || [ "$INSTALL_METHOD" = "binary" ]; then
                INSTALL_METHOD="existing-binary"
            fi
            INSTALLED_VIA_PACKAGE_MANAGER="false"
            return 0
        fi
    fi

    if [ "$platform" = "windows" ]; then
        mkdir -p "$target_dir"
        cp "$tmp_bin" "$target_path"
        chmod +x "$target_path" 2>/dev/null || true
    else
        if [ -n "$SUDO" ]; then
            $SUDO mkdir -p "$target_dir"
            if command -v install >/dev/null 2>&1; then
                $SUDO install -m 755 "$tmp_bin" "$target_path"
            else
                $SUDO cp "$tmp_bin" "$target_path"
                $SUDO chmod 755 "$target_path"
            fi
        else
            mkdir -p "$target_dir"
            if command -v install >/dev/null 2>&1; then
                install -m 755 "$tmp_bin" "$target_path"
            else
                cp "$tmp_bin" "$target_path"
                chmod 755 "$target_path"
            fi
        fi
    fi

    rm -f "$tmp_bin"

    FINAL_BINARY_PATH="$target_path"
    BINARY_PATH="$target_path"
    INSTALL_METHOD="binary"
    INSTALLED_VIA_PACKAGE_MANAGER="false"
    info "Binary installed at $target_path"
}

ci_stop_services() {
    if [ "$CONFIG_CI_MODE" != "true" ]; then
        return 0
    fi
    info "CI mode enabled - stopping packaged edamame_posture service"
    if command -v systemctl >/dev/null 2>&1; then
        $SUDO systemctl stop edamame_posture.service 2>/dev/null || true
        $SUDO systemctl disable edamame_posture.service 2>/dev/null || true
    fi
    if command -v rc-service >/dev/null 2>&1; then
        $SUDO rc-service edamame_posture stop 2>/dev/null || true
    fi
}

write_state_file() {
    if [ -z "$STATE_FILE" ]; then
        return 0
    fi
    local state_dir
    state_dir=$(dirname "$STATE_FILE")
    mkdir -p "$state_dir" 2>/dev/null || true
    cat > "$STATE_FILE" <<EOF
binary_path=${BINARY_PATH}
install_method=${INSTALL_METHOD:-unknown}
installed_via_package_manager=${INSTALLED_VIA_PACKAGE_MANAGER:-false}
binary_already_present=${BINARY_ALREADY_PRESENT}
platform=${PLATFORM}
EOF
}

install_linux_via_apk() {
    info "Installing via Alpine APK..."

    REPO_URL="https://edamame.s3.eu-west-1.amazonaws.com/repo/alpine/v3.15/main"

    if ! grep -q "$REPO_URL" /etc/apk/repositories 2>/dev/null; then
        info "Adding EDAMAME APK repository..."

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

        echo "$REPO_URL" | $SUDO tee -a /etc/apk/repositories >/dev/null
        info "Repository added"
    fi

    info "Updating package list..."
    $SUDO apk update

    info "Installing edamame-posture..."
    $SUDO apk add edamame-posture

    info "Installation complete!"
    BINARY_PATH=$(command -v edamame_posture 2>/dev/null || echo "/usr/bin/edamame_posture")
    FINAL_BINARY_PATH="$BINARY_PATH"
}

install_linux_via_apt() {
    info "Installing via APT..."

    if ! grep -q "edamame.s3.eu-west-1.amazonaws.com/repo" /etc/apt/sources.list.d/edamame.list 2>/dev/null; then
        info "Adding EDAMAME APT repository..."

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

        if command -v wget >/dev/null 2>&1; then
            wget -q -O - https://edamame.s3.eu-west-1.amazonaws.com/repo/public.key | \
                $SUDO gpg --dearmor -o /usr/share/keyrings/edamame.gpg
        else
            curl -sL https://edamame.s3.eu-west-1.amazonaws.com/repo/public.key | \
                $SUDO gpg --dearmor -o /usr/share/keyrings/edamame.gpg
        fi
        info "GPG key imported"

        DEB_ARCH=$(dpkg --print-architecture 2>/dev/null || echo "amd64")
        echo "deb [arch=${DEB_ARCH} signed-by=/usr/share/keyrings/edamame.gpg] https://edamame.s3.eu-west-1.amazonaws.com/repo stable main" | \
            $SUDO tee /etc/apt/sources.list.d/edamame.list >/dev/null
        info "Repository added"
    fi

    info "Updating package list..."
    $SUDO apt-get update -qq

    # Fix any broken package states before installation (edamame-posture may be half-configured)
    # This handles cases where a previous installation failed due to systemd not being available
    if dpkg -l 2>/dev/null | grep -q "iU.*edamame-posture"; then
        warn "Detected broken edamame-posture package state (likely due to systemd unavailability)"
        info "Attempting to fix broken package state..."
        $SUDO dpkg --configure --force-depends edamame-posture 2>/dev/null || \
        echo "edamame-posture install" | $SUDO dpkg --set-selections 2>/dev/null || true
        $SUDO dpkg --configure -a 2>/dev/null | grep -v "edamame-posture" || true
    fi

    info "Installing edamame-posture..."
    $SUDO apt-get install -y edamame-posture || {
        INSTALL_EXIT_CODE=$?
        # Check if installation failed due to package configuration error (systemd issue in containers)
        if dpkg -l 2>/dev/null | grep -q "iU.*edamame-posture"; then
            warn "edamame-posture package installation failed during configuration (expected in containers without systemd)"
            warn "Package is installed but service configuration was skipped"
            info "Marking package as configured to allow system to proceed..."
            $SUDO dpkg --configure --force-depends edamame-posture 2>/dev/null || \
            echo "edamame-posture install" | $SUDO dpkg --set-selections 2>/dev/null || true
            $SUDO apt-get install -f -y 2>/dev/null || true
        else
            exit $INSTALL_EXIT_CODE
        fi
    }

    # Ensure libpcap runtime library is installed (needed for packet capture)
    install_libpcap_runtime() {
        if apt-cache show libpcap0.8t64 >/dev/null 2>&1; then
            info "Installing libpcap runtime library (libpcap0.8t64)..."
            if ! $SUDO apt-get install -y libpcap0.8t64 2>/dev/null; then
                warn "Failed to install libpcap0.8t64, falling back to libpcap0.8"
                $SUDO apt-get install -y libpcap0.8 2>/dev/null || true
            fi
        else
            info "Installing libpcap runtime library (libpcap0.8)..."
            $SUDO apt-get install -y libpcap0.8 2>/dev/null || true
        fi
    }

    # Ensure libpcap legacy soname is available (needed on Ubuntu 20.04)
    ensure_libpcap_soname() {
        if ldconfig -p 2>/dev/null | grep -q 'libpcap\.so\.0\.8'; then
            return 0
        fi

        info "Ensuring libpcap legacy soname compatibility..."
        find_libpcap_shared() {
            local candidate=""
            for pkg in libpcap0.8t64 libpcap0.8; do
                if dpkg -s "$pkg" >/dev/null 2>&1; then
                    candidate=$(dpkg -L "$pkg" 2>/dev/null | grep -E 'libpcap\.so([0-9\.]*)?$' | head -n1)
                    if [ -n "$candidate" ] && [ -f "$candidate" ]; then
                        echo "$candidate"
                        return 0
                    fi
                fi
            done

            if command -v ldconfig >/dev/null 2>&1; then
                candidate=$(ldconfig -p 2>/dev/null | awk '/libpcap\.so/{print $NF; exit}')
            fi

            if [ -n "$candidate" ] && [ -f "$candidate" ]; then
                echo "$candidate"
                return 0
            fi

            for dir in /usr/lib /usr/lib64 /usr/lib/x86_64-linux-gnu /usr/lib/aarch64-linux-gnu /lib /lib64 /lib/x86_64-linux-gnu /lib/aarch64-linux-gnu; do
                candidate=$(ls "$dir"/libpcap.so.* 2>/dev/null | head -n1)
                if [ -n "$candidate" ] && [ -f "$candidate" ]; then
                    echo "$candidate"
                    return 0
                fi
            done

            return 1
        }

        local latest_pcap
        if ! latest_pcap=$(find_libpcap_shared); then
            warn "Could not locate libpcap shared library for soname compatibility"
            return 1
        fi

        local pcap_dir
        pcap_dir=$(dirname "$latest_pcap")
        local target="$pcap_dir/libpcap.so.0.8"

        if [ -f "$target" ]; then
            return 0
        else
            info "Creating libpcap compatibility symlink: $target -> $latest_pcap"
            $SUDO ln -sf "$latest_pcap" "$target"
            $SUDO ldconfig 2>/dev/null || true
        fi
    }

    install_libpcap_runtime
    ensure_libpcap_soname || true

    info "Installation complete!"
    info "Configure /etc/edamame_posture.conf and restart service, or run 'edamame_posture --help'"
    BINARY_PATH=$(command -v edamame_posture 2>/dev/null || echo "/usr/bin/edamame_posture")
    FINAL_BINARY_PATH="$BINARY_PATH"
}

install_windows_via_choco() {
    if ! command -v choco >/dev/null 2>&1; then
        return 1
    fi

    info "Installing via Chocolatey..."
    if choco list --local-only --exact edamame-posture 2>/dev/null | grep -q "^edamame-posture "; then
        info "edamame-posture already present via Chocolatey, attempting upgrade..."
        if ! choco upgrade edamame-posture -y 2>/dev/null; then
            warn "Chocolatey upgrade failed, continuing..."
        fi
    else
        if ! choco install edamame-posture -y 2>/dev/null; then
            warn "Chocolatey installation failed"
            return 1
        fi
    fi

    BINARY_PATH=$(command -v edamame_posture.exe 2>/dev/null || command -v edamame_posture 2>/dev/null || echo "")
    if [ -z "$BINARY_PATH" ]; then
        BINARY_PATH="C:/ProgramData/chocolatey/bin/edamame_posture.exe"
    fi
    FINAL_BINARY_PATH="$BINARY_PATH"
    INSTALL_METHOD="chocolatey"
    INSTALLED_VIA_PACKAGE_MANAGER="true"
    info "Chocolatey installation complete"
    return 0
}

install_macos_via_brew() {
    if ! command -v brew >/dev/null 2>&1; then
        return 1
    fi

    info "Installing via Homebrew..."

    if ! brew tap | grep -q "edamametechnologies/tap"; then
        if ! brew tap edamametechnologies/tap >/dev/null 2>&1; then
            warn "Failed to tap edamametechnologies/tap"
            return 1
        fi
    fi

    if brew list edamame-posture >/dev/null 2>&1; then
        info "edamame-posture already installed via Homebrew, attempting upgrade..."
        brew upgrade edamame-posture >/dev/null 2>&1 || true
    else
        if ! brew install edamame-posture >/dev/null 2>&1; then
            warn "Homebrew installation failed"
            return 1
        fi
    fi

    BINARY_PATH=$(command -v edamame_posture 2>/dev/null || echo "/usr/local/bin/edamame_posture")
    FINAL_BINARY_PATH="$BINARY_PATH"
    INSTALL_METHOD="homebrew"
    INSTALLED_VIA_PACKAGE_MANAGER="true"
    info "Homebrew installation complete"
    return 0
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
CONFIG_INSTALL_DIR=""
CONFIG_STATE_FILE=""
CONFIG_FORCE_BINARY="false"
CONFIG_DEBUG_BUILD="false"
CONFIG_CI_MODE="false"

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
        --install-dir)
            CONFIG_INSTALL_DIR="$2"
            shift 2
            ;;
        --state-file)
            CONFIG_STATE_FILE="$2"
            shift 2
            ;;
        --binary-only|--force-binary)
            CONFIG_FORCE_BINARY="true"
            shift
            ;;
        --debug-build)
            CONFIG_DEBUG_BUILD="true"
            CONFIG_FORCE_BINARY="true"
            shift
            ;;
        --ci-mode)
            CONFIG_CI_MODE="true"
            shift
            ;;
        *)
            warn "Unknown option: $1"
            shift
            ;;
    esac
done

PLATFORM=$(detect_platform)
ARCH=$(uname -m 2>/dev/null || echo "unknown")
LINUX_ARCH_NORMALIZED="$ARCH"
LINUX_LIBC_FLAVOR="gnu"
STATE_FILE="$CONFIG_STATE_FILE"
INSTALL_DIR="$CONFIG_INSTALL_DIR"
INSTALL_METHOD=""
INSTALLED_VIA_PACKAGE_MANAGER="false"
FINAL_BINARY_PATH=""
BINARY_PATH=""

if [ -n "$STATE_FILE" ]; then
    info "Installer state will be written to $STATE_FILE"
fi

case "$PLATFORM" in
    linux)
        if [ ! -f /etc/os-release ]; then
            error "/etc/os-release not found. Unable to detect Linux distribution."
        fi
        . /etc/os-release
        case "$ARCH" in
            armv7l|armhf)
                LINUX_ARCH_NORMALIZED="armv7"
                ;;
            *)
                LINUX_ARCH_NORMALIZED="$ARCH"
                ;;
        esac
        if [ "$ID" = "alpine" ]; then
            LINUX_LIBC_FLAVOR="musl"
        else
            GLIBC_VERSION=$(detect_glibc_version)
            if [ -n "$GLIBC_VERSION" ] && version_lt "$GLIBC_VERSION" "2.29"; then
                LINUX_LIBC_FLAVOR="musl"
                PLATFORM="linux-musl"
            fi
        fi
        ;;
    macos)
        ID="macos"
        ;;
    windows)
        ID="windows"
        ;;
    *)
        error "Unsupported platform detected."
        ;;
esac

if [ -z "$INSTALL_DIR" ]; then
    case "$PLATFORM" in
        linux|macos)
            INSTALL_DIR="/usr/local/bin"
            ;;
        windows)
            INSTALL_DIR="$HOME"
            ;;
        *)
            INSTALL_DIR="$HOME"
            ;;
    esac
fi

BINARY_ALREADY_PRESENT="false"
if command -v edamame_posture >/dev/null 2>&1; then
    BINARY_ALREADY_PRESENT="true"
fi

ensure_privileged_runner() {
    if [ "$PLATFORM" = "windows" ]; then
        SUDO=""
        return 0
    fi

    if [ "$(id -u)" -eq 0 ]; then
        SUDO=""
        return 0
    fi

    if command -v sudo >/dev/null 2>&1; then
        SUDO="sudo"
        return 0
    fi

    if command -v doas >/dev/null 2>&1; then
        SUDO="doas"
        return 0
    fi

    if command -v su >/dev/null 2>&1; then
        if command -v apk >/dev/null 2>&1; then
            info "sudo not found. Attempting to install via apk (requires root credentials)..."
            if su -c "apk add --no-cache sudo" >/dev/null 2>&1; then
                SUDO="sudo"
                return 0
            else
                warn "Automatic sudo installation via apk failed."
            fi
        elif command -v apt-get >/dev/null 2>&1; then
            info "sudo not found. Attempting to install via apt-get (requires root credentials)..."
            if su -c "apt-get update -qq && apt-get install -y sudo" >/dev/null; then
                SUDO="sudo"
                return 0
            else
                warn "Automatic sudo installation via apt-get failed."
            fi
        fi
    fi

    error "This script requires sudo/doas privileges. Please install sudo (e.g., 'apk add sudo') or run as root."
}

ensure_privileged_runner

info "EDAMAME Posture Installer"
info "========================="
info "Platform: $PLATFORM"
info "Architecture: $ARCH"
if [ "$PLATFORM" = "linux" ]; then
    info "Detected OS: $ID"
fi

if [ "$PLATFORM" = "linux" ]; then
    linux_pkg_installed="false"

    if [ "$CONFIG_FORCE_BINARY" != "true" ]; then
        case "$ID" in
            "alpine")
                if install_linux_via_apk; then
                    linux_pkg_installed="true"
                    INSTALL_METHOD="apk"
                    INSTALLED_VIA_PACKAGE_MANAGER="true"
                    ci_stop_services
                fi
                ;;
            "ubuntu"|"debian"|"raspbian"|"pop"|"linuxmint"|"elementary"|"zorin")
                if install_linux_via_apt; then
                    linux_pkg_installed="true"
                    INSTALL_METHOD="apt"
                    INSTALLED_VIA_PACKAGE_MANAGER="true"
                    ci_stop_services
                fi
                ;;
            *)
                warn "Unsupported distribution for package installation: $ID"
                ;;
        esac
    fi

    if [ "$linux_pkg_installed" != "true" ]; then
        warn "Using direct binary installation for Linux..."
        install_binary_release "linux" "$LINUX_LIBC_FLAVOR"
    fi
elif [ "$PLATFORM" = "linux-musl" ]; then
    warn "Package install not supported or glibc < 2.29 detected. Using musl binary."
    install_binary_release "linux" "musl"
elif [ "$PLATFORM" = "macos" ]; then
    if [ "$CONFIG_FORCE_BINARY" != "true" ] && install_macos_via_brew; then
        :
    else
        warn "Using direct binary installation for macOS..."
        install_binary_release "macos" ""
    fi
elif [ "$PLATFORM" = "windows" ]; then
    if [ "$CONFIG_FORCE_BINARY" != "true" ] && install_windows_via_choco; then
        :
    else
        warn "Using direct binary installation for Windows..."
        install_binary_release "windows" ""
    fi
else
    info "Installing via direct binary download for $PLATFORM..."
    install_binary_release "$PLATFORM" ""
fi

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
    
    # Start or restart service
    info "Starting/restarting EDAMAME Posture service..."
    
    case "$ID" in
            "alpine")
                if command -v rc-service >/dev/null 2>&1; then
                    if command -v rc-update >/dev/null 2>&1; then
                        if rc-update show default 2>/dev/null | grep -q "edamame_posture"; then
                            info "EDAMAME Posture already enabled in OpenRC default runlevel"
                        else
                            info "Enabling EDAMAME Posture in OpenRC default runlevel..."
                            $SUDO rc-update add edamame_posture default 2>/dev/null || \
                                warn "Failed to add service to OpenRC default runlevel"
                        fi
                    fi
                    $SUDO rc-service edamame_posture restart 2>/dev/null || \
                    $SUDO rc-service edamame_posture start 2>/dev/null || \
                    warn "Failed to start service via rc-service"
                fi
                ;;
            "ubuntu"|"debian"|"raspbian"|"pop"|"linuxmint"|"elementary"|"zorin")
                if command -v systemctl >/dev/null 2>&1 && systemd_available; then
                    $SUDO systemctl daemon-reload 2>/dev/null || true
                    $SUDO systemctl enable edamame_posture.service 2>/dev/null || true
                    $SUDO systemctl restart edamame_posture.service 2>/dev/null || \
                    warn "Failed to restart service. Check: sudo systemctl status edamame_posture"
                else
                    warn "systemd is not available in this environment (PID 1: $(ps -p 1 -o comm= 2>/dev/null | tr -d ' ' || echo 'unknown')). Skipping service enablement; start edamame_posture manually if needed."
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
                if command -v systemctl >/dev/null 2>&1 && systemd_available; then
                    $SUDO systemctl status edamame_posture.service --no-pager || true
                fi
                ;;
        esac
}

# Verify installation
info ""
info "Verifying installation..."
RESOLVED_BINARY_PATH=$(command -v edamame_posture 2>/dev/null || true)
if [ -z "$RESOLVED_BINARY_PATH" ] && [ -n "$BINARY_PATH" ] && [ -x "$BINARY_PATH" ]; then
    RESOLVED_BINARY_PATH="$BINARY_PATH"
fi

if [ -z "$RESOLVED_BINARY_PATH" ]; then
    error "Installation verification failed. edamame_posture command not found."
fi

BINARY_PATH="$RESOLVED_BINARY_PATH"
VERSION=$("$RESOLVED_BINARY_PATH" get-core-version 2>/dev/null || echo "unknown")
info "✓ EDAMAME Posture installed successfully!"
info "  Version: $VERSION"
info "  Location: $RESOLVED_BINARY_PATH"

if [ "$PLATFORM" = "linux" ]; then
    configure_service
fi

info ""
info "Quick Start:"
if [ "$PLATFORM" = "windows" ]; then
    info "  ${BINARY_PATH} score                 # Check security posture"
    info "  ${BINARY_PATH} remediate             # Auto-fix security issues"
    info "  ${BINARY_PATH} --help                # See all commands"
else
    info "  sudo edamame_posture score          # Check security posture"
    info "  sudo edamame_posture remediate      # Auto-fix security issues"
    info "  edamame_posture --help              # See all commands"
fi

if [ -f "/etc/edamame_posture.conf" ]; then
    info ""
    info "Service Management:"
    info "  sudo systemctl status edamame_posture   # Check service status"
    info "  sudo systemctl restart edamame_posture  # Restart service"
    info "  sudo nano /etc/edamame_posture.conf     # Edit configuration"
fi

write_state_file

