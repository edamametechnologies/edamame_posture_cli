#!/bin/sh
# EDAMAME Posture Installer
# Usage: curl --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/edamametechnologies/edamame_posture_cli/main/install.sh | sh -s -- [OPTIONS]
#
# Connection & Device Options:
#   --user USER                    EDAMAME Hub username
#   --domain DOMAIN                EDAMAME Hub domain
#   --pin PIN                      EDAMAME Hub PIN
#   --device-id ID                 Device identifier (e.g., ci-runner-123)
#
# Network Monitoring & Enforcement:
#   --start-lanscan                Pass --network-scan to daemon (LAN device discovery)
#   --start-capture                Pass --packet-capture to daemon (traffic capture)
#   --whitelist NAME               Whitelist name (e.g., github_ubuntu)
#   --fail-on-whitelist            Pass --fail-on-whitelist (exit on whitelist violations)
#   --fail-on-blacklist            Pass --fail-on-blacklist (exit on blacklisted IPs)
#   --fail-on-anomalous            Pass --fail-on-anomalous (exit on anomalous connections)
#   --cancel-on-violation          Pass --cancel-on-violation (cancel pipeline on violations)
#   --include-local-traffic        Pass --include-local-traffic (include local traffic)
#
# AI Assistant Options:
#   --claude-api-key KEY           Claude API key
#   --openai-api-key KEY           OpenAI API key
#   --ollama-base-url URL          Ollama base URL (default: http://localhost:11434)
#   --agentic-mode MODE            AI mode: auto, analyze, or disabled (default: disabled)
#   --agentic-interval SECONDS     AI processing interval in seconds (default: 3600)
#   --slack-bot-token TOKEN        Slack bot token
#   --slack-actions-channel ID     Slack actions channel ID
#   --slack-escalations-channel ID Slack escalations channel ID
#
# Installation Control:
#   --install-dir PATH             Binary install directory (default: /usr/local/bin)
#   --state-file PATH              Write installation state to file (for CI/CD)
#   --force-binary                 Skip package managers, use binary download
#   --debug-build                  Download debug binaries (implies --force-binary)
#
# Examples:
#
#   Basic installation:
#     curl -sSf https://raw.githubusercontent.com/.../install.sh | sh -s -- \
#       --user myuser --domain example.com --pin 123456
#
#   CI/CD with network monitoring:
#     curl -sSf https://raw.githubusercontent.com/.../install.sh | sh -s -- \
#       --user $USER --domain $DOMAIN --pin $PIN \
#       --device-id "ci-runner-${RUN_ID}" \
#       --start-lanscan --start-capture \
#       --whitelist github_ubuntu --fail-on-whitelist
#
#   AI Assistant with full monitoring:
#     curl -sSf https://raw.githubusercontent.com/.../install.sh | sh -s -- \
#       --user myuser --domain example.com --pin 123456 \
#       --claude-api-key sk-ant-... --agentic-mode auto \
#       --start-lanscan --start-capture --whitelist builder

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color
# POSIX-safe way to represent a non-breaking space (0xC2 0xA0 in UTF-8)
NBSP_CHAR="$(printf '\302\240')"

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

show_daemon_status() {
    local binary="$1"
    info "Daemon status:"
    set +e  # Temporarily disable exit on error
    STATUS=$($binary status 2>&1)
    STATUS_EXIT=$?
    set -e  # Re-enable exit on error
    if [ $STATUS_EXIT -ne 0 ]; then
        warn "Failed to get daemon status (exit code: $STATUS_EXIT)"
    else
        echo "$STATUS" | while IFS= read -r line; do
            info "  $line"
        done
    fi
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

normalize_cli_option() {
    local value="$1"
    if [ -z "$value" ]; then
        echo ""
        return 0
    fi
    # Strip any leading Unicode non-breaking spaces introduced by copy/paste.
    while [ "${value#"$NBSP_CHAR"}" != "$value" ]; do
        value="${value#"$NBSP_CHAR"}"
    done
    echo "$value"
}

compute_sha256() {
    local file="$1"
    if [ ! -f "$file" ]; then
        echo ""
        return 1
    fi
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$file" | awk '{print $1}'
        return 0
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$file" | awk '{print $1}'
        return 0
    elif command -v certutil >/dev/null 2>&1; then
        certutil -hashfile "$file" SHA256 2>/dev/null | sed -n '2p' | tr -d '\r'
        return 0
    fi
    echo ""
    return 1
}

files_have_same_checksum() {
    local file_a="$1"
    local file_b="$2"
    local checksum_a checksum_b

    checksum_a=$(compute_sha256 "$file_a") || checksum_a=""
    checksum_b=$(compute_sha256 "$file_b") || checksum_b=""

    if [ -z "$checksum_a" ] || [ -z "$checksum_b" ]; then
        warn "Unable to compute checksum for comparison; assuming binaries differ."
        return 1
    fi

    [ "$checksum_a" = "$checksum_b" ]
}

get_file_size_bytes() {
    local file="$1"
    if [ ! -f "$file" ]; then
        echo ""
        return 1
    fi
    local size=""
    if command -v stat >/dev/null 2>&1; then
        case "$PLATFORM" in
            macos)
                size=$(stat -f '%z' "$file" 2>/dev/null || true)
                ;;
            *)
                size=$(stat -c '%s' "$file" 2>/dev/null || true)
                ;;
        esac
    fi
    if [ -z "$size" ] && command -v wc >/dev/null 2>&1; then
        size=$(wc -c < "$file" 2>/dev/null | tr -d ' ' || true)
    fi
    printf '%s\n' "$size"
    [ -n "$size" ]
}

get_file_timestamp() {
    local file="$1"
    local type="$2"
    if [ ! -f "$file" ]; then
        echo ""
        return 1
    fi
    local ts=""
    if command -v stat >/dev/null 2>&1; then
        case "$PLATFORM" in
            macos)
                if [ "$type" = "modified" ]; then
                    ts=$(stat -f '%Sm' -t '%Y-%m-%d %H:%M:%S %z' "$file" 2>/dev/null || true)
                else
                    ts=$(stat -f '%SB' -t '%Y-%m-%d %H:%M:%S %z' "$file" 2>/dev/null || true)
                fi
                ;;
            *)
                if [ "$type" = "modified" ]; then
                    ts=$(stat -c '%y' "$file" 2>/dev/null || true)
                else
                    ts=$(stat -c '%w' "$file" 2>/dev/null || true)
                    if [ "$ts" = "-" ]; then
                        ts=""
                    fi
                    if [ -z "$ts" ]; then
                        local epoch=""
                        epoch=$(stat -c '%W' "$file" 2>/dev/null || true)
                        if [ -n "$epoch" ] && [ "$epoch" != "-1" ] && [ "$epoch" != "0" ]; then
                            ts=$(date -d "@$epoch" '+%Y-%m-%d %H:%M:%S %z' 2>/dev/null || true)
                        fi
                    fi
                fi
                ;;
        esac
    fi
    printf '%s\n' "$ts"
    [ -n "$ts" ]
}

log_file_metadata() {
    local file="$1"
    local label="$2"
    local expected_digest="$3"
    if [ -z "$label" ]; then
        label="edamame_posture binary"
    fi
    if [ ! -f "$file" ]; then
        warn "Cannot collect metadata for ${label}: file not found at $file"
        return 1
    fi
    local checksum size modified created
    checksum=$(compute_sha256 "$file" 2>/dev/null || true)
    size=$(get_file_size_bytes "$file" 2>/dev/null || true)
    modified=$(get_file_timestamp "$file" "modified" 2>/dev/null || true)
    created=$(get_file_timestamp "$file" "created" 2>/dev/null || true)
    info "Binary details (${label}):"
    info "  path: $file"
    if [ -n "$size" ]; then
        info "  size: ${size} bytes"
    else
        info "  size: unavailable"
    fi
    if [ -n "$checksum" ]; then
        info "  sha256 (actual): $checksum"
    else
        info "  sha256 (actual): unavailable"
    fi
    if [ -n "$expected_digest" ]; then
        info "  sha256 (expected): $expected_digest"
    fi
    info "  modified: ${modified:-unavailable}"
    info "  created: ${created:-unavailable}"
}

log_core_info_for_binary() {
    local binary="$1"
    local label="$2"
    if [ -z "$label" ]; then
        label="existing binary"
    fi
    if [ ! -x "$binary" ]; then
        warn "Cannot run get-core-info for ${label}: $binary is not executable."
        return 1
    fi
    info "Collecting 'get-core-info' output for ${label}..."
    local output status
    set +e
    output=$("$binary" get-core-info 2>&1)
    status=$?
    set -e
    if [ $status -ne 0 ] && [ -n "$SUDO" ]; then
        info "Retrying 'get-core-info' with $SUDO for ${label}..."
        set +e
        output=$($SUDO "$binary" get-core-info 2>&1)
        status=$?
        set -e
    fi
    if [ $status -eq 0 ]; then
        if [ -n "$output" ]; then
            printf '%s\n' "$output" | while IFS= read -r line; do
                info "  $line"
            done
        else
            info "  (no output)"
        fi
    else
        warn "get-core-info failed for ${label} (exit code: $status)."
        if [ -n "$output" ]; then
            printf '%s\n' "$output" | while IFS= read -r line; do
                warn "  $line"
            done
        fi
    fi
}

REPO_BASE_URL="https://github.com/edamametechnologies/edamame_posture_cli"
FALLBACK_VERSION="0.9.75"
LATEST_RELEASE_TAG_PRIMARY=""
LATEST_RELEASE_TAG_SECONDARY=""
ARTIFACT_SECONDARY_URL=""
GITHUB_RELEASES_RESPONSE=""
ARTIFACT_SECONDARY_NAME=""
ARTIFACT_DIGEST=""
ARTIFACT_SECONDARY_DIGEST=""
ARTIFACT_FALLBACK_DIGEST=""

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
        json=$(curl --connect-timeout 10 --max-time 30 -fsSL "$api_url" 2>/dev/null) || json=""
    elif command -v wget >/dev/null 2>&1; then
        json=$(wget --timeout=30 -q -O - "$api_url" 2>/dev/null) || json=""
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

fetch_release_feed() {
    if [ -n "$GITHUB_RELEASES_RESPONSE" ]; then
        return 0
    fi
    local api="https://api.github.com/repos/edamametechnologies/edamame_posture_cli/releases?per_page=2"
    local response=""
    if command -v curl >/dev/null 2>&1; then
        response=$(curl --connect-timeout 10 --max-time 30 -fsSL "$api" 2>/dev/null) || response=""
    elif command -v wget >/dev/null 2>&1; then
        response=$(wget --timeout=30 -q -O - "$api" 2>/dev/null) || response=""
    fi
    if [ -n "$response" ]; then
        GITHUB_RELEASES_RESPONSE="$response"
        return 0
    fi
    return 1
}

fetch_latest_release_tag() {
    if [ -n "$LATEST_RELEASE_TAG_PRIMARY" ]; then
        return 0
    fi
    if ! fetch_release_feed; then
        return 1
    fi
    local response="$GITHUB_RELEASES_RESPONSE"
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

get_asset_digest_from_json() {
    local json="$1"
    local asset_name="$2"
    if [ -z "$json" ] || [ -z "$asset_name" ]; then
        return 1
    fi
    printf '%s\n' "$json" | awk -v asset="$asset_name" '
        BEGIN { in_asset=0 }
        /"name":/ {
            if (index($0, "\"" asset "\"") > 0) {
                in_asset=1
            } else if (index($0, "\"name\":") > 0) {
                in_asset=0
            }
        }
        in_asset && /"digest":/ {
            if (match($0, /"digest": *"([^"]+)"/, m)) {
                gsub(/^sha256:/, "", m[1])
                print m[1]
                exit
            }
        }
    '
}

get_release_asset_digest() {
    local asset_name="$1"
    if [ -z "$asset_name" ]; then
        return 1
    fi
    if [ -z "$GITHUB_RELEASES_RESPONSE" ]; then
        fetch_release_feed || return 1
    fi
    local digest
    digest=$(get_asset_digest_from_json "$GITHUB_RELEASES_RESPONSE" "$asset_name")
    if [ -n "$digest" ]; then
        printf '%s\n' "$digest"
        return 0
    fi
    return 1
}

fetch_release_by_tag() {
    local version="$1"
    if [ -z "$version" ]; then
        echo ""
        return 1
    fi
    local api="https://api.github.com/repos/edamametechnologies/edamame_posture_cli/releases/tags/v${version}"
    local response=""
    if command -v curl >/dev/null 2>&1; then
        response=$(curl --connect-timeout 10 --max-time 30 -fsSL "$api" 2>/dev/null) || response=""
    elif command -v wget >/dev/null 2>&1; then
        response=$(wget --timeout=30 -q -O - "$api" 2>/dev/null) || response=""
    fi
    printf '%s\n' "$response"
    if [ -n "$response" ]; then
        return 0
    fi
    return 1
}

get_release_asset_digest_by_tag() {
    local version="$1"
    local asset_name="$2"
    if [ -z "$version" ] || [ -z "$asset_name" ]; then
        return 1
    fi
    local response
    response=$(fetch_release_by_tag "$version")
    if [ -z "$response" ]; then
        return 1
    fi
    local digest
    digest=$(get_asset_digest_from_json "$response" "$asset_name")
    if [ -n "$digest" ]; then
        printf '%s\n' "$digest"
        return 0
    fi
    return 1
}

check_file_checksum() {
    local file="$1"
    local expected="$2"
    if [ -z "$file" ] || [ -z "$expected" ]; then
        return 2
    fi
    if [ ! -f "$file" ]; then
        return 2
    fi
    local actual
    actual=$(compute_sha256 "$file" 2>/dev/null || true)
    if [ -z "$actual" ]; then
        return 2
    fi
    if [ "$actual" = "$expected" ]; then
        return 0
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
    ARTIFACT_SECONDARY_NAME=""
    ARTIFACT_DIGEST=""
    ARTIFACT_SECONDARY_DIGEST=""
    ARTIFACT_FALLBACK_DIGEST=""
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

    ARTIFACT_DIGEST=$(get_release_asset_digest "$ARTIFACT_NAME" 2>/dev/null || true)
    if [ -n "$ARTIFACT_SECONDARY_NAME" ]; then
        ARTIFACT_SECONDARY_DIGEST=$(get_release_asset_digest "$ARTIFACT_SECONDARY_NAME" 2>/dev/null || true)
    fi
}

install_binary_release() {
    local platform="$1"
    local libc_flavor="$2"
    prepare_binary_artifact "$platform" "$libc_flavor"

    local tmp_bin
    tmp_bin=$(mktemp)

    local target_dir="$INSTALL_DIR"
    if [ -z "$target_dir" ]; then
        target_dir="$HOME"
    fi

    local target_name="edamame_posture${ARTIFACT_EXT}"
    local target_path="$target_dir/$target_name"
    local download_digest="$ARTIFACT_DIGEST"
    local download_label="latest release"
    local compare_existing_with_download="true"

    local existing_binary_mode="none"
    if [ -f "$target_path" ]; then
        info "Existing binary detected at $target_path; verifying checksum before deciding to reuse."
        log_file_metadata "$target_path" "existing edamame_posture binary" "$download_digest"
        log_core_info_for_binary "$target_path" "existing edamame_posture binary"
        existing_binary_mode="verify"
    fi

    if [ "$existing_binary_mode" = "verify" ]; then
        if [ -n "$download_digest" ]; then
            if check_file_checksum "$target_path" "$download_digest"; then
                info "Existing binary matches release checksum; reusing cached binary."
                FINAL_BINARY_PATH="$target_path"
                BINARY_PATH="$target_path"
                if [ -z "$INSTALL_METHOD" ] || [ "$INSTALL_METHOD" = "binary" ]; then
                    INSTALL_METHOD="existing-binary"
                fi
                INSTALLED_VIA_PACKAGE_MANAGER="false"
                BINARY_ALREADY_PRESENT="true"
                rm -f "$tmp_bin"
                return 0
            else
                local digest_status=$?
                if [ "$digest_status" -eq 1 ]; then
                    warn "Existing binary checksum does not match release digest; will compare against downloaded binary before replacing."
                else
                    warn "Unable to verify existing binary against release digest; falling back to download comparison."
                fi
            fi
        else
            warn "Release checksum unavailable for ${ARTIFACT_NAME}; falling back to download comparison."
        fi
    fi

    info "Downloading binary from ${ARTIFACT_URL}"
    if ! download_file "$ARTIFACT_URL" "$tmp_bin"; then
        warn "Primary binary download failed (URL: ${ARTIFACT_URL}), attempting fallback..."
        local downloaded="false"
        if [ -n "$ARTIFACT_SECONDARY_URL" ]; then
            info "Attempting previous release tag at ${ARTIFACT_SECONDARY_URL}"
            if download_file "$ARTIFACT_SECONDARY_URL" "$tmp_bin"; then
                info "Downloaded EDAMAME Posture from previous release tag."
                download_label="previous release"
                download_digest="$ARTIFACT_SECONDARY_DIGEST"
                downloaded="true"
            else
                warn "Previous release tag download failed (URL: ${ARTIFACT_SECONDARY_URL})"
            fi
        fi
        if [ "$downloaded" = "false" ]; then
            info "Attempting pinned fallback at ${ARTIFACT_FALLBACK_URL}"
            if download_file "$ARTIFACT_FALLBACK_URL" "$tmp_bin"; then
                if [ -z "$ARTIFACT_FALLBACK_DIGEST" ]; then
                    ARTIFACT_FALLBACK_DIGEST=$(get_release_asset_digest_by_tag "$FALLBACK_VERSION" "$ARTIFACT_FALLBACK_NAME" 2>/dev/null || true)
                fi
                download_label="fallback release v${FALLBACK_VERSION}"
                download_digest="$ARTIFACT_FALLBACK_DIGEST"
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

    log_file_metadata "$tmp_bin" "downloaded ${download_label} binary" "$download_digest"

    if [ -n "$download_digest" ]; then
        if check_file_checksum "$tmp_bin" "$download_digest"; then
            info "Release checksum verified for ${download_label} artifact."
        else
            local download_checksum_status=$?
            if [ "$download_checksum_status" -eq 1 ]; then
                rm -f "$tmp_bin"
                error "Checksum verification failed for ${download_label} artifact."
            else
                warn "Unable to verify downloaded binary checksum for ${download_label} artifact."
            fi
        fi
    else
        warn "No release checksum available for ${download_label} artifact; skipping verification."
    fi

    if [ "$platform" != "windows" ]; then
        chmod +x "$tmp_bin" || true
    fi

    if [ "$existing_binary_mode" = "verify" ]; then
        if [ "$compare_existing_with_download" = "true" ] && files_have_same_checksum "$target_path" "$tmp_bin"; then
            info "Existing binary matches latest download; reusing cached binary."
            FINAL_BINARY_PATH="$target_path"
            BINARY_PATH="$target_path"
            if [ -z "$INSTALL_METHOD" ] || [ "$INSTALL_METHOD" = "binary" ]; then
                INSTALL_METHOD="existing-binary"
            fi
            INSTALLED_VIA_PACKAGE_MANAGER="false"
            BINARY_ALREADY_PRESENT="true"
            rm -f "$tmp_bin"
            return 0
        fi
        info "Existing binary differs from release; refreshing with new binary."
        stop_existing_posture || true
        rm -f "$target_path" || warn "Failed to remove existing binary at $target_path"
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

# Deprecated: ci_stop_services() is no longer used
# GitHub Action manages daemon lifecycle explicitly via start/stop commands
# Keeping stub for backward compatibility with old install.sh versions
ci_stop_services() {
    return 0
}

write_state_file() {
    if [ -z "$STATE_FILE" ] || [ "$STATE_FILE_WRITTEN" = "true" ]; then
        return 0
    fi
    if { [ -z "$BINARY_PATH" ] || [ ! -e "$BINARY_PATH" ]; } && command -v edamame_posture >/dev/null 2>&1; then
        BINARY_PATH=$(command -v edamame_posture 2>/dev/null || true)
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
    STATE_FILE_WRITTEN="true"
}

install_linux_via_apk() {
    info "Installing via Alpine APK..."

    REPO_URL="https://edamame.s3.eu-west-1.amazonaws.com/repo/alpine/v3.15/main"

    if ! grep -q "$REPO_URL" /etc/apk/repositories 2>/dev/null; then
        info "Adding EDAMAME APK repository..."

        KEY_URL_MAIN="https://edamame.s3.eu-west-1.amazonaws.com/repo/alpine/v3.15/main/${ARCH}/edamame.rsa.pub"

        if command -v wget >/dev/null 2>&1; then
            wget -q -O /tmp/edamame.rsa.pub "$KEY_URL_MAIN" || \
            warn "Failed to download signing key"
        elif command -v curl >/dev/null 2>&1; then
            curl -sL -o /tmp/edamame.rsa.pub "$KEY_URL_MAIN" || \
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
    $SUDO apk update < /dev/null

    info "Installing edamame-posture (upgrading if already installed)..."
    $SUDO apk add --no-cache --upgrade edamame-posture < /dev/null

    info "Installation complete!"
    BINARY_PATH=$(command -v edamame_posture 2>/dev/null || echo "/usr/bin/edamame_posture")
    FINAL_BINARY_PATH="$BINARY_PATH"
}

# Determine whether dpkg's status line for edamame-posture indicates a broken install
package_state_is_broken() {
    local dpkg_line="$1"
    if [ -z "$dpkg_line" ]; then
        return 1
    fi
    local status_code="${dpkg_line%% *}"
    case "$status_code" in
        iU|iF|iH)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

# Remove any partially installed Debian package and repair dpkg/apt state
rollback_broken_deb_package() {
    warn "Removing broken edamame-posture package state..."
    $SUDO dpkg --remove --force-remove-reinstreq edamame-posture 2>/dev/null || true
    $SUDO dpkg --purge --force-remove-reinstreq edamame-posture 2>/dev/null || true
    $SUDO apt-get remove -y --purge edamame-posture 2>/dev/null || true
    $SUDO dpkg --configure -a 2>/dev/null || true
    $SUDO apt-get install -f -y 2>/dev/null || true
}

# Install libpcap runtime packages on Debian-based systems
ensure_libpcap_runtime() {
    if ! command -v apt-get >/dev/null 2>&1; then
        return 0
    fi

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
        if [ -n "$candidate" ] && [ -f "$candidate" ]; then
            echo "$candidate"
            return 0
        fi
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

# Ensure libpcap legacy soname is available (needed on Ubuntu 20.04)
ensure_libpcap_soname() {
    if ! command -v apt-get >/dev/null 2>&1; then
        return 0
    fi

    if command -v ldconfig >/dev/null 2>&1 && ldconfig -p 2>/dev/null | grep -q 'libpcap\.so\.0\.8'; then
        return 0
    fi

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
    fi

    info "Creating libpcap compatibility symlink: $target -> $latest_pcap"
    $SUDO ln -sf "$latest_pcap" "$target"
    if command -v ldconfig >/dev/null 2>&1; then
        $SUDO ldconfig 2>/dev/null || true
    fi
}

# Wrapper to ensure packet capture dependencies exist when using binary installs
ensure_linux_packet_capture_support() {
    if [ "$PLATFORM" != "linux" ]; then
        return 0
    fi
    case "$ID" in
        "ubuntu"|"debian"|"raspbian"|"pop"|"linuxmint"|"elementary"|"zorin")
            ensure_libpcap_runtime
            ensure_libpcap_soname || true
            ;;
    esac
}

# Fix broken edamame-posture package state - remove immediately if broken
# This prevents dpkg from trying to reconfigure broken packages during other installations
fix_broken_package_state() {
    PACKAGE_STATE=$(dpkg -l 2>/dev/null | grep "edamame-posture" || echo "")
    if package_state_is_broken "$PACKAGE_STATE"; then
        warn "Detected broken edamame-posture package state (likely due to systemd unavailability)"
        warn "Removing broken package immediately to prevent blocking other installations..."
        rollback_broken_deb_package
        return 1  # Signal that package was removed
    fi
    return 0
}

install_linux_via_apt() {
    info "Installing via APT..."
    APT_UPDATE_NEEDED="false"
    
    # Fix broken package state BEFORE any apt operations
    # This prevents dpkg errors when installing other packages
    fix_broken_package_state || true

    if ! systemd_available; then
        local init_name
        init_name=$(ps -p 1 -o comm= 2>/dev/null | tr -d ' ' || echo "unknown")
        warn "systemd is not available in this environment (PID 1: ${init_name})"
        warn "The edamame-posture Debian package requires systemd during installation."
        warn "Skipping APT installation and falling back to direct binary download..."
        return 1
    fi

    if ! grep -q "edamame.s3.eu-west-1.amazonaws.com/repo" /etc/apt/sources.list.d/edamame.list 2>/dev/null; then
        info "Adding EDAMAME APT repository..."

        if ! command -v gpg >/dev/null 2>&1; then
            info "Installing gnupg..."
            $SUDO apt-get install -y gnupg < /dev/null 2>/dev/null || {
                warn "Failed to install gnupg without update, trying with update..."
                $SUDO apt-get update -qq < /dev/null
                $SUDO apt-get install -y gnupg < /dev/null
            }
        fi

        if ! command -v wget >/dev/null 2>&1 && ! command -v curl >/dev/null 2>&1; then
            info "Installing wget..."
            $SUDO apt-get install -y wget < /dev/null 2>/dev/null || {
                warn "Failed to install wget without update, trying with update..."
                $SUDO apt-get update -qq < /dev/null
                $SUDO apt-get install -y wget < /dev/null
            }
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
        APT_UPDATE_NEEDED="true"
    fi

    # Decide if we really need to refresh package lists
    if ! dpkg -l edamame-posture 2>/dev/null | grep -q "^ii"; then
        APT_UPDATE_NEEDED="true"
    elif apt list --upgradable 2>/dev/null | grep -q "^edamame-posture/"; then
        APT_UPDATE_NEEDED="true"
    fi

    if [ "$APT_UPDATE_NEEDED" = "true" ]; then
        info "Updating package list..."
        $SUDO apt-get update -qq < /dev/null
    else
        info "Skipping apt-get update (package already installed and no upgrade detected)"
    fi

    info "Installing edamame-posture..."
    # Run apt-get install and capture output
    # Note: apt-get may return 0 even if dpkg configuration fails
    set +e
    INSTALL_OUTPUT=$($SUDO apt-get install -y edamame-posture 2>&1 < /dev/null)
    INSTALL_EXIT_CODE=$?
    set -e
    
    # Check installation output FIRST for error messages (most immediate indicator)
    # The error appears in output even before package state updates
    if echo "$INSTALL_OUTPUT" | grep -qiE "(dpkg.*error.*processing.*package.*edamame-posture|error processing package edamame-posture|Errors were encountered.*processing.*edamame-posture|System has not been booted with systemd|Failed to connect to bus|invoke-rc\.d: could not determine current runlevel)" || [ "$INSTALL_EXIT_CODE" -ne 0 ]; then
        warn "Detected APT installation failure (exit code: $INSTALL_EXIT_CODE)"
        warn "Rolling back Debian package installation and falling back to binary download..."
        rollback_broken_deb_package
        
        warn "Package removed - will use binary installation fallback"
        return 1  # Signal to caller to use binary installation fallback
    fi
    
    # Give dpkg a moment to update package state after installation
    sleep 0.5
    
    # Check package state - this is a reliable secondary indicator
    # apt-get can return 0 even when dpkg configuration fails
    PACKAGE_STATE=$(dpkg -l 2>/dev/null | grep "edamame-posture" || echo "")
    
    # Check if package is in broken/unconfigured state (iU = installed but unconfigured)
    # This happens when the postinst script fails (e.g., systemd not available in containers)
    if package_state_is_broken "$PACKAGE_STATE"; then
        warn "Package is in a broken/unconfigured state - service installation failed"
        warn "This is expected in containers without systemd (e.g., Ubuntu 20.04 containers)"
        warn "Rolling back package installation and falling back to binary download..."
        
        rollback_broken_deb_package
        
        warn "Package removed - will use binary installation fallback"
        return 1  # Signal to caller to use binary installation fallback
    fi
    
    # Package is successfully installed
    if echo "$PACKAGE_STATE" | grep -q "^ii"; then
        info "Package successfully installed and configured"
    elif [ "$INSTALL_EXIT_CODE" -ne 0 ]; then
        error "Failed to install edamame-posture (exit code: $INSTALL_EXIT_CODE)"
        error "Package state: $PACKAGE_STATE"
        exit $INSTALL_EXIT_CODE
    fi

    ensure_linux_packet_capture_support

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
        if ! choco upgrade edamame-posture -y 2>/dev/null < /dev/null; then
            warn "Chocolatey upgrade failed, continuing..."
        fi
    else
        if ! choco install edamame-posture -y 2>/dev/null < /dev/null; then
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
        if ! brew tap edamametechnologies/tap >/dev/null 2>&1 < /dev/null; then
            warn "Failed to tap edamametechnologies/tap"
            return 1
        fi
    fi

    if brew list edamame-posture >/dev/null 2>&1; then
        info "edamame-posture already installed via Homebrew, attempting upgrade..."
        brew upgrade edamame-posture >/dev/null 2>&1 < /dev/null || true
    else
        if ! brew install edamame-posture >/dev/null 2>&1 < /dev/null; then
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
CONFIG_DEVICE_ID=""
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
CONFIG_START_LANSCAN="false"
CONFIG_START_CAPTURE="false"
CONFIG_FAIL_ON_WHITELIST="false"
CONFIG_FAIL_ON_BLACKLIST="false"
CONFIG_FAIL_ON_ANOMALOUS="false"
CONFIG_CANCEL_ON_VIOLATION="false"
CONFIG_INCLUDE_LOCAL_TRAFFIC="false"
CONFIG_WHITELIST=""

while [ $# -gt 0 ]; do
    current_arg=$(normalize_cli_option "$1")
    case "$current_arg" in
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
        --device-id)
            CONFIG_DEVICE_ID="$2"
            shift 2
            ;;
        --whitelist)
            CONFIG_WHITELIST="$2"
            shift 2
            ;;
        --fail-on-whitelist)
            CONFIG_FAIL_ON_WHITELIST="true"
            shift
            ;;
        --fail-on-blacklist)
            CONFIG_FAIL_ON_BLACKLIST="true"
            shift
            ;;
        --fail-on-anomalous)
            CONFIG_FAIL_ON_ANOMALOUS="true"
            shift
            ;;
        --cancel-on-violation)
            CONFIG_CANCEL_ON_VIOLATION="true"
            shift
            ;;
        --include-local-traffic)
            CONFIG_INCLUDE_LOCAL_TRAFFIC="true"
            shift
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
        --force-binary)
            CONFIG_FORCE_BINARY="true"
            shift
            ;;
        --debug-build)
            CONFIG_DEBUG_BUILD="true"
            CONFIG_FORCE_BINARY="true"
            shift
            ;;
        --start-lanscan)
            CONFIG_START_LANSCAN="true"
            shift
            ;;
        --start-capture)
            CONFIG_START_CAPTURE="true"
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
STATE_FILE_WRITTEN="false"
INSTALL_DIR="$CONFIG_INSTALL_DIR"
INSTALL_METHOD=""
INSTALLED_VIA_PACKAGE_MANAGER="false"
FINAL_BINARY_PATH=""
BINARY_PATH=""
SKIP_INSTALLATION="false"
SKIP_CONFIGURATION="false"

if [ -n "$STATE_FILE" ]; then
    info "Installer state will be written to $STATE_FILE"
fi
trap 'write_state_file' EXIT

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
            case "$ARCH" in
                x86_64)
                    # We build the x86_64 deb binary on glibc 2.29 or older
                    if [ -n "$GLIBC_VERSION" ] && version_lt "$GLIBC_VERSION" "2.29"; then
                        LINUX_LIBC_FLAVOR="musl"
                        PLATFORM="linux-musl"
                    fi
                    ;;
                aarch64)
                    # We build the aarch64 deb binary on glibc 2.35 or older
                    if [ -n "$GLIBC_VERSION" ] && version_lt "$GLIBC_VERSION" "2.35"; then
                        LINUX_LIBC_FLAVOR="musl"
                        PLATFORM="linux-musl"
                    fi
                    ;;
                *)
                    ;;
            esac
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
else
    install_dir_check="$INSTALL_DIR"
    if [ -z "$install_dir_check" ]; then
        install_dir_check="$HOME"
    fi
    binary_candidate="$install_dir_check/edamame_posture"
    if [ "$PLATFORM" = "windows" ]; then
        binary_candidate="${binary_candidate}.exe"
    fi
    if [ -f "$binary_candidate" ]; then
        BINARY_ALREADY_PRESENT="true"
    fi
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
        # Use -E to preserve environment variables (needed for CI/CD detection)
        SUDO="sudo -E"
        return 0
    fi

    if command -v doas >/dev/null 2>&1; then
        # Note: doas environment preservation depends on doas.conf (keepenv rule)
        # For CI/CD detection, the cancellation script embeds values directly
        SUDO="doas"
        return 0
    fi

    if command -v su >/dev/null 2>&1; then
        if command -v apk >/dev/null 2>&1; then
            info "sudo not found. Attempting to install via apk (requires root credentials)..."
            if su -c "apk add --no-cache sudo" >/dev/null 2>&1; then
                SUDO="sudo -E"
                return 0
            else
                warn "Automatic sudo installation via apk failed."
            fi
        elif command -v apt-get >/dev/null 2>&1; then
            info "sudo not found. Attempting to install via apt-get (requires root credentials)..."
            if su -c "apt-get update -qq && apt-get install -y sudo" >/dev/null; then
                SUDO="sudo -E"
                return 0
            else
                warn "Automatic sudo installation via apt-get failed."
            fi
        fi
    fi

    error "This script requires sudo/doas privileges. Please install sudo (e.g., 'apk add sudo') or run as root."
}

ensure_privileged_runner

# Fix broken package state at the very start, before any operations
# This prevents dpkg errors when other packages are installed (e.g., in workflows)
if [ "$PLATFORM" = "linux" ] && command -v dpkg >/dev/null 2>&1 && command -v apt-get >/dev/null 2>&1; then
    fix_broken_package_state || true
fi

info "EDAMAME Posture Installer"
info "========================="
info "Platform: $PLATFORM"
info "Architecture: $ARCH"
if [ "$PLATFORM" = "linux" ]; then
    info "Detected OS: $ID"
fi

# Check if edamame_posture is already installed with matching credentials and version
check_existing_installation() {
    # Locate existing binary
    EXISTING_BINARY=$(command -v edamame_posture 2>/dev/null || true)
    
    # If not found in PATH, check common installation locations
    if [ -z "$EXISTING_BINARY" ]; then
        # Check platform-specific paths
        if [ "$PLATFORM" = "windows" ]; then
            # Windows: check home directory with .exe extension
            CANDIDATE_BINARY="$HOME/edamame_posture.exe"
            if [ -f "$CANDIDATE_BINARY" ]; then
                EXISTING_BINARY="$CANDIDATE_BINARY"
            fi
        else
            # Linux/macOS: check home directory and standard paths
            for CANDIDATE_BINARY in \
                "$HOME/edamame_posture" \
                "/usr/local/bin/edamame_posture" \
                "/usr/bin/edamame_posture"; do
                if [ -f "$CANDIDATE_BINARY" ]; then
                    EXISTING_BINARY="$CANDIDATE_BINARY"
                    break
                fi
            done
        fi
    fi
    
    if [ -z "$EXISTING_BINARY" ]; then
        return 1  # Not installed
    fi
    
    info "Found existing edamame_posture at: $EXISTING_BINARY"
    
    # Check version/SHA first - if outdated, always reinstall
    VERSION_CHECK_PASSED="false"
    
    # Determine if this is a package installation or binary
    IS_PACKAGE_INSTALL="false"
    if [ "$PLATFORM" = "linux" ]; then
        if command -v dpkg >/dev/null 2>&1 && dpkg -l edamame-posture 2>/dev/null | grep -q "^ii"; then
            IS_PACKAGE_INSTALL="true"
            info "Detected package installation (APT)"
        elif command -v apk >/dev/null 2>&1 && apk info -e edamame-posture 2>/dev/null; then
            IS_PACKAGE_INSTALL="true"
            info "Detected package installation (APK)"
        fi
    elif [ "$PLATFORM" = "macos" ] && command -v brew >/dev/null 2>&1; then
        if brew list edamame-posture >/dev/null 2>&1; then
            IS_PACKAGE_INSTALL="true"
            info "Detected package installation (Homebrew)"
        fi
    elif [ "$PLATFORM" = "windows" ] && command -v choco >/dev/null 2>&1; then
        if choco list --local-only --exact edamame-posture 2>/dev/null | grep -q "^edamame-posture "; then
            IS_PACKAGE_INSTALL="true"
            info "Detected package installation (Chocolatey)"
        fi
    fi
    
    if [ "$IS_PACKAGE_INSTALL" = "true" ]; then
        # For package installations, check if update is available
        info "Checking if package is up to date..."
        NEEDS_UPGRADE="false"
        
        if [ "$PLATFORM" = "linux" ]; then
            if command -v apt-get >/dev/null 2>&1; then
                # Check if apt upgrade would upgrade edamame-posture
                if apt list --upgradable 2>/dev/null | grep -q "edamame-posture"; then
                    info "Newer version available via APT"
                    NEEDS_UPGRADE="true"
                else
                    info "APT package is up to date"
                    VERSION_CHECK_PASSED="true"
                fi
            elif command -v apk >/dev/null 2>&1; then
                # For APK, check if upgrade would update the package
                if apk version edamame-posture 2>/dev/null | grep -q "<"; then
                    info "Newer version available via APK"
                    NEEDS_UPGRADE="true"
                else
                    info "APK package is up to date"
                    VERSION_CHECK_PASSED="true"
                fi
            fi
        elif [ "$PLATFORM" = "macos" ] && command -v brew >/dev/null 2>&1; then
            # Check if brew has an update
            if brew outdated edamame-posture 2>/dev/null | grep -q "edamame-posture"; then
                info "Newer version available via Homebrew"
                NEEDS_UPGRADE="true"
            else
                info "Homebrew package is up to date"
                VERSION_CHECK_PASSED="true"
            fi
        elif [ "$PLATFORM" = "windows" ] && command -v choco >/dev/null 2>&1; then
            # Chocolatey upgrade check
            if choco outdated --limit-output 2>/dev/null | grep -q "^edamame-posture|"; then
                info "Newer version available via Chocolatey"
                NEEDS_UPGRADE="true"
            else
                info "Chocolatey package is up to date"
                VERSION_CHECK_PASSED="true"
            fi
        fi
        
        if [ "$NEEDS_UPGRADE" = "true" ]; then
            info "Package needs upgrade, will proceed with installation"
            return 1  # Need to upgrade
        fi
    else
        # For binary installations, check SHA against latest release
        info "Checking binary version via SHA comparison..."
        
        # Prepare artifact info to get expected SHA
        prepare_binary_artifact "$PLATFORM" "$LINUX_LIBC_FLAVOR"
        
        if [ -n "$ARTIFACT_DIGEST" ]; then
            EXISTING_SHA=$(compute_sha256 "$EXISTING_BINARY" 2>/dev/null || true)
            
            if [ -n "$EXISTING_SHA" ]; then
                if [ "$EXISTING_SHA" = "$ARTIFACT_DIGEST" ]; then
                    DIGEST_SHORT=$(echo "$ARTIFACT_DIGEST" | cut -c1-16)
                    info "Binary SHA matches latest release (${DIGEST_SHORT}...)"
                    VERSION_CHECK_PASSED="true"
                else
                    EXISTING_SHORT=$(echo "$EXISTING_SHA" | cut -c1-16)
                    DIGEST_SHORT=$(echo "$ARTIFACT_DIGEST" | cut -c1-16)
                    info "Binary SHA differs from latest release"
                    info "  Existing: ${EXISTING_SHORT}..."
                    info "  Latest:   ${DIGEST_SHORT}..."
                    info "Will proceed with binary update"
                    return 1  # Need to update
                fi
            else
                warn "Cannot compute SHA of existing binary, will proceed with installation"
                return 1  # Cannot verify, reinstall
            fi
        else
            warn "Cannot fetch latest release SHA, will skip version check"
            # If we can't verify, assume it's ok (fail open for version check)
            VERSION_CHECK_PASSED="true"
        fi
    fi
    
    # Version check must pass before we consider credentials
    if [ "$VERSION_CHECK_PASSED" != "true" ]; then
        info "Version/SHA check failed, will proceed with installation"
        return 1
    fi
    
    # Version is OK, now check credentials
    if ! credentials_provided; then
        info "No credentials provided, version is up to date, reusing existing installation"
        BINARY_PATH="$EXISTING_BINARY"
        FINAL_BINARY_PATH="$EXISTING_BINARY"
        INSTALL_METHOD="existing"
        SKIP_INSTALLATION="true"
        SKIP_CONFIGURATION="true"
        return 0  # Skip everything
    fi
    
    # Credentials provided - check if service is running with matching credentials
    info "Checking if existing installation matches provided credentials..."
    
    # Try to get status (capture both stdout and stderr)
    if [ -n "$SUDO" ]; then
        STATUS_OUTPUT=$($SUDO "$EXISTING_BINARY" status 2>&1)
        STATUS_EXIT_CODE=$?
    else
        STATUS_OUTPUT=$("$EXISTING_BINARY" status 2>&1)
        STATUS_EXIT_CODE=$?
    fi
    
    # Check if status command succeeded
    if [ $STATUS_EXIT_CODE -ne 0 ] || [ -z "$STATUS_OUTPUT" ]; then
        warn "Cannot get status from existing installation (exit code: $STATUS_EXIT_CODE)"
        if [ -n "$STATUS_OUTPUT" ]; then
            warn "Status output:"
            echo "$STATUS_OUTPUT" | while IFS= read -r line; do
                warn "  $line"
            done
        else
            warn "Status command produced no output"
        fi
        
        # Try to verify credentials via config file as fallback (Linux only)
        CONFIG_MATCH="false"
        if [ "$PLATFORM" = "linux" ] && [ -f "/etc/edamame_posture.conf" ]; then
            info "Checking credentials in existing config file..."
            CONFIG_USER_RUNNING=$(grep "^edamame_user:" /etc/edamame_posture.conf 2>/dev/null | sed 's/.*: *"\([^"]*\)".*/\1/' || true)
            CONFIG_DOMAIN_RUNNING=$(grep "^edamame_domain:" /etc/edamame_posture.conf 2>/dev/null | sed 's/.*: *"\([^"]*\)".*/\1/' || true)
            
            if [ -n "$CONFIG_USER_RUNNING" ] && [ -n "$CONFIG_DOMAIN_RUNNING" ]; then
                if [ "$CONFIG_USER_RUNNING" = "$CONFIG_USER" ] && [ "$CONFIG_DOMAIN_RUNNING" = "$CONFIG_DOMAIN" ]; then
                    info "Config file credentials match provided credentials (user: $CONFIG_USER, domain: $CONFIG_DOMAIN)"
                    info "Service appears to be stopped or not responding, but credentials are correct"
                    CONFIG_MATCH="true"
                else
                    info "Config file credentials differ (user: $CONFIG_USER_RUNNING, domain: $CONFIG_DOMAIN_RUNNING)"
                fi
            else
                warn "Cannot parse credentials from config file"
            fi
        elif [ "$PLATFORM" = "linux" ]; then
            warn "No config file found at /etc/edamame_posture.conf (may be binary installation)"
        else
            info "Config file check not applicable on $PLATFORM (no system service)"
        fi
        
        if [ "$CONFIG_MATCH" = "true" ]; then
            # Credentials in config match, just need to ensure service is running
            info "Will use existing binary and restart service with existing configuration"
        else
            # Credentials don't match or can't verify - need to reconfigure
            if [ "$PLATFORM" = "linux" ]; then
                info "Will use existing binary and reconfigure with new credentials"
            else
                info "Will use existing binary (no service configuration on $PLATFORM)"
            fi
        fi
        
        BINARY_PATH="$EXISTING_BINARY"
        FINAL_BINARY_PATH="$EXISTING_BINARY"
        INSTALL_METHOD="existing"
        SKIP_INSTALLATION="true"
        # On non-Linux platforms, skip configuration since there's no service
        if [ "$PLATFORM" = "linux" ] && [ "$CONFIG_MATCH" != "true" ]; then
            SKIP_CONFIGURATION="false"
        else
            SKIP_CONFIGURATION="true"
        fi
        
        # Daemon is not responding - if credentials are provided, we need to start it
        # On non-Linux platforms (Windows/macOS), there's no service to restart,
        # so we must start the daemon manually
        if credentials_provided && [ "$PLATFORM" != "linux" ]; then
            info "Daemon not responding on $PLATFORM with credentials provided - will start daemon"
            SHOULD_START_DAEMON="true"
        fi
        
        return 1  # Skip installation, conditionally reconfigure
    fi
    
    # Parse credentials from status
    RUNNING_USER=$(echo "$STATUS_OUTPUT" | grep "Connected user:" | sed 's/.*Connected user: //' | tr -d ' ')
    RUNNING_DOMAIN=$(echo "$STATUS_OUTPUT" | grep "Connected domain:" | sed 's/.*Connected domain: //' | tr -d ' ')
    RUNNING_DEVICE_ID=$(echo "$STATUS_OUTPUT" | grep "Device ID:" | sed 's/.*Device ID: //' | tr -d ' ')
    IS_CONNECTED=$(echo "$STATUS_OUTPUT" | grep "Is connected:" | sed 's/.*Is connected: //' | tr -d ' ')
    
    # Check if credentials match (including device ID if both are non-empty)
    CREDENTIALS_MATCH="false"
    if [ "$IS_CONNECTED" = "true" ] && [ "$RUNNING_USER" = "$CONFIG_USER" ] && [ "$RUNNING_DOMAIN" = "$CONFIG_DOMAIN" ]; then
        # User and domain match - now check device ID if applicable
        if [ -n "$CONFIG_DEVICE_ID" ] && [ -n "$RUNNING_DEVICE_ID" ]; then
            # Both have device IDs - they must match
            if [ "$RUNNING_DEVICE_ID" = "$CONFIG_DEVICE_ID" ]; then
                CREDENTIALS_MATCH="true"
            else
                info "Device ID differs: running=$RUNNING_DEVICE_ID, config=$CONFIG_DEVICE_ID"
            fi
        else
            # At least one device ID is empty - ignore device ID in comparison
            CREDENTIALS_MATCH="true"
        fi
    fi
    
    if [ "$CREDENTIALS_MATCH" = "true" ]; then
        info "Existing installation is running with matching credentials (user: $CONFIG_USER, domain: $CONFIG_DOMAIN)"
        [ -n "$CONFIG_DEVICE_ID" ] && info "  Device ID: $CONFIG_DEVICE_ID"
        
        # Check if we need to update service configuration with new parameters
        # (e.g., network flags were added after initial install)
        NEED_CONFIG_UPDATE="false"
        if [ "$PLATFORM" = "linux" ] && [ -f "/etc/edamame_posture.conf" ]; then
            # Check if network flags are provided but missing from config
            if [ "$CONFIG_START_LANSCAN" = "true" ] || [ "$CONFIG_START_CAPTURE" = "true" ]; then
                CURRENT_LANSCAN=$(grep "^start_lanscan:" /etc/edamame_posture.conf 2>/dev/null | sed 's/.*: *"\([^"]*\)".*/\1/' || echo "false")
                CURRENT_CAPTURE=$(grep "^start_capture:" /etc/edamame_posture.conf 2>/dev/null | sed 's/.*: *"\([^"]*\)".*/\1/' || echo "false")
                
                if [ "$CONFIG_START_LANSCAN" = "true" ] && [ "$CURRENT_LANSCAN" != "true" ]; then
                    info "Network scan flag not in config, will update"
                    NEED_CONFIG_UPDATE="true"
                fi
                if [ "$CONFIG_START_CAPTURE" = "true" ] && [ "$CURRENT_CAPTURE" != "true" ]; then
                    info "Packet capture flag not in config, will update"
                    NEED_CONFIG_UPDATE="true"
                fi
            fi
        fi
        
        info "Skipping installation"
        BINARY_PATH="$EXISTING_BINARY"
        FINAL_BINARY_PATH="$EXISTING_BINARY"
        INSTALL_METHOD="existing"
        SKIP_INSTALLATION="true"
        
        if [ "$NEED_CONFIG_UPDATE" = "true" ]; then
            info "Configuration update needed for new parameters"
            SKIP_CONFIGURATION="false"
        else
            info "Configuration is up to date, skipping"
            SKIP_CONFIGURATION="true"
            return 0  # Skip everything
        fi
        
        return 1  # Skip installation but allow configuration update
    fi
    
    if [ "$IS_CONNECTED" = "true" ]; then
        info "Existing installation has different credentials (user: $RUNNING_USER, domain: $RUNNING_DOMAIN)"
        if [ "$PLATFORM" = "linux" ]; then
            info "Will skip installation but reconfigure with new credentials"
        else
            info "Will restart daemon on $PLATFORM with new credentials"
        fi
    else
        info "Existing installation is not connected"
        if [ "$PLATFORM" = "linux" ]; then
            info "Will skip installation but reconfigure"
        else
            info "Will start daemon on $PLATFORM with provided credentials"
        fi
    fi
    
    # Binary exists, skip installation
    BINARY_PATH="$EXISTING_BINARY"
    FINAL_BINARY_PATH="$EXISTING_BINARY"
    INSTALL_METHOD="existing"
    SKIP_INSTALLATION="true"
    # Only reconfigure on Linux (only platform with system service)
    if [ "$PLATFORM" = "linux" ]; then
        SKIP_CONFIGURATION="false"
    else
        SKIP_CONFIGURATION="true"
    fi
    
    # On non-Linux platforms (Windows/macOS), there's no service configuration,
    # so we must start/restart the daemon manually when credentials are provided
    # and either: daemon is not connected OR credentials don't match
    if credentials_provided && [ "$PLATFORM" != "linux" ]; then
        info "Will start/restart daemon on $PLATFORM with provided credentials"
        SHOULD_START_DAEMON="true"
    fi
    
    return 1  # Skip installation, conditionally reconfigure
}

# Early check: determine if we can skip installation and/or configuration
check_existing_installation || true  # Sets SKIP_INSTALLATION and SKIP_CONFIGURATION flags

if [ "$SKIP_INSTALLATION" = "true" ] && [ "$SKIP_CONFIGURATION" = "true" ]; then
    info "✓ Installation check complete - existing installation is perfect, nothing to do"
elif [ "$SKIP_INSTALLATION" = "true" ] && [ "$SKIP_CONFIGURATION" = "false" ]; then
    info "✓ Installation check complete - will use existing binary but reconfigure service"
fi

if [ "$SKIP_INSTALLATION" = "false" ]; then
    if [ "$PLATFORM" = "linux" ]; then
        linux_pkg_installed="false"

        if [ "$CONFIG_FORCE_BINARY" != "true" ]; then
            case "$ID" in
                "alpine")
                    if install_linux_via_apk; then
                        linux_pkg_installed="true"
                        INSTALL_METHOD="apk"
                        INSTALLED_VIA_PACKAGE_MANAGER="true"
                    fi
                    ;;
                "ubuntu"|"debian"|"raspbian"|"pop"|"linuxmint"|"elementary"|"zorin")
                    if install_linux_via_apt; then
                        linux_pkg_installed="true"
                        INSTALL_METHOD="apt"
                        INSTALLED_VIA_PACKAGE_MANAGER="true"
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
            ensure_linux_packet_capture_support
        fi
    elif [ "$PLATFORM" = "linux-musl" ]; then
        warn "Package install not supported or unsupported glibc version detected. Using musl binary."
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
fi

# Configure service if configuration parameters were provided
configure_service() {
    CONF_FILE="/etc/edamame_posture.conf"
    yaml_escape() {
        # Escape backslashes and double quotes for safe YAML double-quoted values
        # Uses a single sed pass to avoid placeholder churn
        printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
    }
    
    # Only configure if config file exists (Debian/Ubuntu/Raspbian/Alpine with service)
    if [ ! -f "$CONF_FILE" ]; then
        info "No service configuration file found at $CONF_FILE"
        info "Service configuration only available for APT/APK installations"
        return 0
    fi
    
    # Check if any configuration was provided
    if [ -z "$CONFIG_USER" ] && [ -z "$CONFIG_CLAUDE_KEY" ] && [ -z "$CONFIG_OPENAI_KEY" ] && [ -z "$CONFIG_OLLAMA_URL" ] && [ "$CONFIG_AGENTIC_MODE" = "disabled" ] && [ "$CONFIG_START_LANSCAN" != "true" ] && [ "$CONFIG_START_CAPTURE" != "true" ]; then
        info "No configuration parameters provided, skipping service configuration"
        return 0
    fi
    
    info "Configuring EDAMAME Posture service..."
    
    # Create temporary config file
    TMP_CONF=$(mktemp)
    ESC_USER=$(yaml_escape "$CONFIG_USER")
    ESC_DOMAIN=$(yaml_escape "$CONFIG_DOMAIN")
    ESC_PIN=$(yaml_escape "$CONFIG_PIN")
    ESC_DEVICE_ID=$(yaml_escape "$CONFIG_DEVICE_ID")
    ESC_WHITELIST=$(yaml_escape "$CONFIG_WHITELIST")
    ESC_AGENTIC_MODE=$(yaml_escape "$CONFIG_AGENTIC_MODE")
    ESC_CLAUDE_KEY=$(yaml_escape "$CONFIG_CLAUDE_KEY")
    ESC_OPENAI_KEY=$(yaml_escape "$CONFIG_OPENAI_KEY")
    ESC_OLLAMA_URL=$(yaml_escape "$CONFIG_OLLAMA_URL")
    ESC_AGENTIC_INTERVAL=$(yaml_escape "$CONFIG_AGENTIC_INTERVAL")
    ESC_SLACK_BOT_TOKEN=$(yaml_escape "$CONFIG_SLACK_BOT_TOKEN")
    ESC_SLACK_ACTIONS_CHANNEL=$(yaml_escape "$CONFIG_SLACK_ACTIONS_CHANNEL")
    ESC_SLACK_ESCALATIONS_CHANNEL=$(yaml_escape "$CONFIG_SLACK_ESCALATIONS_CHANNEL")

    cat > "$TMP_CONF" <<EOF
# EDAMAME Posture Service Configuration
# This file is read by the systemd service to configure edamame_posture

# ============================================================================
# Connection Settings (leave empty for disconnected mode)
# ============================================================================
edamame_user: "${ESC_USER}"
edamame_domain: "${ESC_DOMAIN}"
edamame_pin: "${ESC_PIN}"
edamame_device_id: "${ESC_DEVICE_ID}"

# ============================================================================
# Network Monitoring (optional)
# ============================================================================
start_lanscan: "${CONFIG_START_LANSCAN}"
start_capture: "${CONFIG_START_CAPTURE}"
whitelist_name: "${ESC_WHITELIST}"
fail_on_whitelist: "${CONFIG_FAIL_ON_WHITELIST}"
fail_on_blacklist: "${CONFIG_FAIL_ON_BLACKLIST}"
fail_on_anomalous: "${CONFIG_FAIL_ON_ANOMALOUS}"
cancel_on_violation: "${CONFIG_CANCEL_ON_VIOLATION}"
include_local_traffic: "${CONFIG_INCLUDE_LOCAL_TRAFFIC}"

# ============================================================================
# AI Assistant (Agentic) Configuration
# ============================================================================

# Agentic Mode
# - auto: Automatically process and resolve safe/low-risk todos; escalate high-risk items
# - analyze: Gather recommendations without executing changes
# - disabled: No AI processing (default)
agentic_mode: "${ESC_AGENTIC_MODE}"

# ============================================================================
# LLM Provider Configuration (first non-empty API key/URL will be used)
# ============================================================================

# Claude (Anthropic) - Recommended
claude_api_key: "${ESC_CLAUDE_KEY}"

# OpenAI
openai_api_key: "${ESC_OPENAI_KEY}"

# Ollama (Local) - Privacy First
ollama_base_url: "${ESC_OLLAMA_URL}"

# ============================================================================
# Slack Notifications (optional)
# ============================================================================

# Slack Bot Token (starts with xoxb-)
slack_bot_token: "${ESC_SLACK_BOT_TOKEN}"

# Slack Actions Channel (channel ID, e.g., C01234567)
slack_actions_channel: "${ESC_SLACK_ACTIONS_CHANNEL}"

# Slack Escalations Channel (channel ID, e.g., C07654321)
slack_escalations_channel: "${ESC_SLACK_ESCALATIONS_CHANNEL}"

# ============================================================================
# Agentic Processing Configuration
# ============================================================================

# Processing interval in seconds
agentic_interval: "${ESC_AGENTIC_INTERVAL}"
EOF
    
    # Copy to final location
    $SUDO cp "$TMP_CONF" "$CONF_FILE"
    $SUDO chmod 600 "$CONF_FILE"  # Protect API keys
    rm -f "$TMP_CONF"
    
    info "✓ Service configuration updated at $CONF_FILE"
    
    # Check if service is already running with proper credentials
    # Note: If NEED_CONFIG_UPDATE is set, we MUST restart to pick up new config
    SHOULD_RESTART="true"
    if credentials_provided; then
        info "Checking if service is already running with proper credentials..."
        
        # Check if service is active
        SERVICE_ACTIVE="false"
        case "$ID" in
            "alpine")
                if command -v rc-service >/dev/null 2>&1; then
                    if rc-service edamame_posture status 2>/dev/null | grep -q "started"; then
                        SERVICE_ACTIVE="true"
                    fi
                fi
                ;;
            "ubuntu"|"debian"|"raspbian"|"pop"|"linuxmint"|"elementary"|"zorin")
                if command -v systemctl >/dev/null 2>&1 && systemd_available; then
                    if systemctl is-active --quiet edamame_posture.service 2>/dev/null; then
                        SERVICE_ACTIVE="true"
                    fi
                fi
                ;;
        esac
        
        # If service is active, verify credentials match
        if [ "$SERVICE_ACTIVE" = "true" ]; then
            info "Service is active, verifying credentials..."
            # Wait a moment for service to fully initialize
            sleep 2
            
            # Get status output and parse credentials (capture both stdout and stderr)
            local status_exit_code
            STATUS_OUTPUT=$($SUDO edamame_posture status 2>&1)
            status_exit_code=$?
            
            if [ $status_exit_code -eq 0 ] && [ -n "$STATUS_OUTPUT" ]; then
                # Extract user, domain, and device ID from status output
                RUNNING_USER=$(echo "$STATUS_OUTPUT" | grep "Connected user:" | sed 's/.*Connected user: //' | tr -d ' ')
                RUNNING_DOMAIN=$(echo "$STATUS_OUTPUT" | grep "Connected domain:" | sed 's/.*Connected domain: //' | tr -d ' ')
                RUNNING_DEVICE_ID=$(echo "$STATUS_OUTPUT" | grep "Device ID:" | sed 's/.*Device ID: //' | tr -d ' ')
                IS_CONNECTED=$(echo "$STATUS_OUTPUT" | grep "Is connected:" | sed 's/.*Is connected: //' | tr -d ' ')
                
                # Check if credentials match (including device ID if both are non-empty)
                CREDENTIALS_MATCH="false"
                if [ "$IS_CONNECTED" = "true" ] && [ "$RUNNING_USER" = "$CONFIG_USER" ] && [ "$RUNNING_DOMAIN" = "$CONFIG_DOMAIN" ]; then
                    # User and domain match - now check device ID if applicable
                    if [ -n "$CONFIG_DEVICE_ID" ] && [ -n "$RUNNING_DEVICE_ID" ]; then
                        # Both have device IDs - they must match
                        if [ "$RUNNING_DEVICE_ID" = "$CONFIG_DEVICE_ID" ]; then
                            CREDENTIALS_MATCH="true"
                        else
                            info "Device ID differs: running=$RUNNING_DEVICE_ID, config=$CONFIG_DEVICE_ID"
                        fi
                    else
                        # At least one device ID is empty - ignore device ID in comparison
                        CREDENTIALS_MATCH="true"
                    fi
                fi
                
                if [ "$CREDENTIALS_MATCH" = "true" ]; then
                    # Check if config was just updated (e.g., network flags added)
                    if [ "${NEED_CONFIG_UPDATE:-false}" = "true" ]; then
                        info "Service is running with matching credentials but config was updated, will restart"
                        SHOULD_RESTART="true"
                    else
                        info "Service is running with matching credentials (user: $CONFIG_USER, domain: $CONFIG_DOMAIN), skipping restart"
                        [ -n "$CONFIG_DEVICE_ID" ] && info "  Device ID: $CONFIG_DEVICE_ID"
                        SHOULD_RESTART="false"
                    fi
                elif [ "$IS_CONNECTED" = "true" ]; then
                    info "Service is running with different credentials (user: $RUNNING_USER, domain: $RUNNING_DOMAIN), will restart"
                else
                    info "Service is not connected, will restart"
                fi
            else
                warn "Unable to get service status (exit code: $status_exit_code), will restart"
                if [ -n "$STATUS_OUTPUT" ]; then
                    warn "Status command output:"
                    echo "$STATUS_OUTPUT" | while IFS= read -r line; do
                        warn "  $line"
                    done
                fi
            fi
        else
            info "Service is not active, will start it"
        fi
    fi
    
    # Start or restart service only if needed
    if [ "$SHOULD_RESTART" = "true" ]; then
        info "Starting/restarting EDAMAME Posture service..."
        
        case "$ID" in
                "alpine")
                    service_started="false"
                    if command -v rc-service >/dev/null 2>&1; then
                        # Check if OpenRC is actually functional (e.g. /run/openrc/softlevel exists)
                        if [ -d "/run/openrc" ] && [ -f "/run/openrc/softlevel" ]; then
                            if command -v rc-update >/dev/null 2>&1; then
                                if rc-update show default 2>/dev/null | grep -q "edamame_posture"; then
                                    info "EDAMAME Posture already enabled in OpenRC default runlevel"
                                else
                                    info "Enabling EDAMAME Posture in OpenRC default runlevel..."
                                    $SUDO rc-update add edamame_posture default 2>/dev/null || \
                                        warn "Failed to add service to OpenRC default runlevel"
                                fi
                            fi
                            
                            if $SUDO rc-service edamame_posture restart >/dev/null 2>&1 || \
                               $SUDO rc-service edamame_posture start >/dev/null 2>&1; then
                                service_started="true"
                            else
                                warn "Failed to start service via rc-service"
                            fi
                        else
                            warn "OpenRC not initialized (container environment?), skipping service management"
                        fi
                    fi
                    
                    # If service failed to start (e.g. no OpenRC or init failed), try manual fallback
                    if [ "$service_started" != "true" ]; then
                        # First check if daemon is already running despite service failure
                        # This can happen if APK postinst started it before OpenRC was fully initialized
                        if edamame_posture status >/dev/null 2>&1; then
                            info "Daemon is already running (likely started by APK postinst)"
                            show_daemon_status "edamame_posture"
                            # Stop it first so we can restart with proper credentials
                            info "Stopping existing daemon to reconfigure with provided credentials..."
                            edamame_posture stop >/dev/null 2>&1 || true
                            sleep 2
                        fi
                        
                        warn "Falling back to manual background daemon start..."
                        
                        # Source the config manually to get variables
                        if [ -f "$CONF_FILE" ]; then
                            # We already have CONFIG_* variables in scope from the installer logic
                            # So we can just reuse the manual start logic that follows later in the script
                            # by setting SHOULD_START_DAEMON="true" and skipping the service check
                            SHOULD_START_DAEMON="true"
                            
                            info "Will launch daemon manually using provided credentials"
                        fi
                    fi
                    ;;
                "ubuntu"|"debian"|"raspbian"|"pop"|"linuxmint"|"elementary"|"zorin")
                    if command -v systemctl >/dev/null 2>&1 && systemd_available; then
                        $SUDO systemctl daemon-reload 2>/dev/null || true
                        $SUDO systemctl enable edamame_posture.service 2>/dev/null || true
                        if $SUDO systemctl restart edamame_posture.service 2>/dev/null; then
                            :
                        else
                            warn "Failed to restart service. Check: sudo systemctl status edamame_posture"
                            SHOULD_START_DAEMON="true"  # fall back to manual daemon start
                        fi
                    else
                        warn "systemd is not available in this environment (PID 1: $(ps -p 1 -o comm= 2>/dev/null | tr -d ' ' || echo 'unknown')). Skipping service enablement; start edamame_posture manually if needed."
                        SHOULD_START_DAEMON="true"  # fall back to manual daemon start when systemd missing
                    fi
                    ;;
            esac
    else
        info "✓ Service already running with valid credentials"
    fi
        
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

# Configure service only if needed
if [ "$PLATFORM" = "linux" ] && [ "$SKIP_CONFIGURATION" != "true" ]; then
    configure_service
elif [ "$SKIP_CONFIGURATION" = "true" ]; then
    info "Service configuration skipped (already configured with matching credentials)"
    # Display status of the daemon (don't fail if daemon is down)
    info "Daemon status:"
    show_daemon_status "$RESOLVED_BINARY_PATH"
fi

# For non-service installations with credentials, start background daemon
# This includes: binary installs, Homebrew (macOS), Chocolatey (Windows)
# Excludes: APT/APK (they have systemd/OpenRC services managed by configure_service)
# BUT: If OpenRC service failed to start in configure_service, we override it here to force manual start
# Note: SHOULD_START_DAEMON may have been set to "true" inside configure_service() if OpenRC failed
if [ -z "$SHOULD_START_DAEMON" ] || [ "$SHOULD_START_DAEMON" != "true" ]; then
    SHOULD_START_DAEMON="false"
fi

info "Daemon start decision:"
if credentials_provided; then
    info "  Credentials provided: yes"
else
    info "  Credentials provided: no"
fi
info "  SKIP_CONFIGURATION: $SKIP_CONFIGURATION"
info "  INSTALLED_VIA_PACKAGE_MANAGER: $INSTALLED_VIA_PACKAGE_MANAGER"
info "  INSTALL_METHOD: $INSTALL_METHOD"
info "  SHOULD_START_DAEMON (current): $SHOULD_START_DAEMON"

# Determine if we should run in disconnected mode (no credentials but network monitoring enabled)
DISCONNECTED_MODE="false"
if ! credentials_provided; then
    if [ "$CONFIG_START_LANSCAN" = "true" ] || [ "$CONFIG_START_CAPTURE" = "true" ] || \
       [ -n "$CONFIG_WHITELIST" ] || [ "$CONFIG_CANCEL_ON_VIOLATION" = "true" ]; then
        DISCONNECTED_MODE="true"
        info "  Disconnected mode: enabled (network monitoring without credentials)"
    fi
fi

if { credentials_provided || [ "$DISCONNECTED_MODE" = "true" ]; } && [ "$SKIP_CONFIGURATION" != "true" ]; then
    if [ "$SHOULD_START_DAEMON" = "true" ]; then
        # Already set to true by service failure fallback
        info "  Decision: Service failure fallback - will start daemon manually"
    elif [ "$INSTALLED_VIA_PACKAGE_MANAGER" = "false" ]; then
        # Binary installation - always start daemon
        info "  Decision: Binary installation - will start daemon"
        SHOULD_START_DAEMON="true"
    elif [ "$INSTALL_METHOD" = "homebrew" ] || [ "$INSTALL_METHOD" = "chocolatey" ]; then
        # Homebrew/Chocolatey don't install services - start daemon manually
        info "  Decision: Homebrew/Chocolatey - will start daemon"
        SHOULD_START_DAEMON="true"
    else
        info "  Decision: Service-based installation - daemon managed by service"
    fi
else
    info "  Decision: Skipping daemon start (no credentials/network config or already configured)"
fi

info "  SHOULD_START_DAEMON: $SHOULD_START_DAEMON"

if [ "$SHOULD_START_DAEMON" = "true" ]; then
    info ""
    if [ "$DISCONNECTED_MODE" = "true" ]; then
        info "Starting background daemon in disconnected mode..."
    else
        info "Starting background daemon with provided credentials..."
    fi
    
    # Stop any existing daemon before starting a new one
    # This is important on Windows/macOS where the daemon might be running with different credentials
    info "Stopping any existing daemon..."
    stop_existing_posture || true
    sleep 2
    
    # Export AI configuration before starting daemon
    AGENTIC_PROVIDER_NAME=""
    if [ "$CONFIG_AGENTIC_MODE" != "disabled" ]; then
        if [ -n "$CONFIG_CLAUDE_KEY" ]; then
            export EDAMAME_LLM_API_KEY="$CONFIG_CLAUDE_KEY"
            AGENTIC_PROVIDER_NAME="claude"
        elif [ -n "$CONFIG_OPENAI_KEY" ]; then
            export EDAMAME_LLM_API_KEY="$CONFIG_OPENAI_KEY"
            AGENTIC_PROVIDER_NAME="openai"
        elif [ -n "$CONFIG_OLLAMA_URL" ]; then
            export EDAMAME_LLM_BASE_URL="$CONFIG_OLLAMA_URL"
            AGENTIC_PROVIDER_NAME="ollama"
        fi
        
        if [ -n "$CONFIG_SLACK_BOT_TOKEN" ]; then
            export EDAMAME_AGENTIC_SLACK_BOT_TOKEN="$CONFIG_SLACK_BOT_TOKEN"
        fi
        if [ -n "$CONFIG_SLACK_ACTIONS_CHANNEL" ]; then
            export EDAMAME_AGENTIC_SLACK_ACTIONS_CHANNEL="$CONFIG_SLACK_ACTIONS_CHANNEL"
        fi
        if [ -n "$CONFIG_SLACK_ESCALATIONS_CHANNEL" ]; then
            export EDAMAME_AGENTIC_SLACK_ESCALATIONS_CHANNEL="$CONFIG_SLACK_ESCALATIONS_CHANNEL"
        fi
    fi
    
    info "Starting daemon in background..."
    
    # Build daemon command inside a subshell
    (
        NOHUP_CMD=""
        if command -v nohup >/dev/null 2>&1; then
            NOHUP_CMD="nohup"
        fi

        # Use different command based on mode
        if [ "$DISCONNECTED_MODE" = "true" ]; then
            # Disconnected mode - no credentials required
            set -- background-start-disconnected
        else
            # Connected mode - requires credentials
            set -- start \
                --user "$CONFIG_USER" \
                --domain "$CONFIG_DOMAIN" \
                --pin "$CONFIG_PIN"
            
            [ -n "$CONFIG_DEVICE_ID" ] && set -- "$@" --device-id "$CONFIG_DEVICE_ID"
        fi
        
        # Common options for both modes
        [ "$CONFIG_START_LANSCAN" = "true" ] && set -- "$@" --network-scan
        [ "$CONFIG_START_CAPTURE" = "true" ] && set -- "$@" --packet-capture
        [ -n "$CONFIG_WHITELIST" ] && set -- "$@" --whitelist "$CONFIG_WHITELIST"
        [ "$CONFIG_FAIL_ON_WHITELIST" = "true" ] && set -- "$@" --fail-on-whitelist
        [ "$CONFIG_FAIL_ON_BLACKLIST" = "true" ] && set -- "$@" --fail-on-blacklist
        [ "$CONFIG_FAIL_ON_ANOMALOUS" = "true" ] && set -- "$@" --fail-on-anomalous
        [ "$CONFIG_CANCEL_ON_VIOLATION" = "true" ] && set -- "$@" --cancel-on-violation
        [ "$CONFIG_INCLUDE_LOCAL_TRAFFIC" = "true" ] && set -- "$@" --include-local-traffic
        
        if [ "$CONFIG_AGENTIC_MODE" != "disabled" ]; then
            set -- "$@" --agentic-mode "$CONFIG_AGENTIC_MODE"
            [ -n "$AGENTIC_PROVIDER_NAME" ] && set -- "$@" --agentic-provider "$AGENTIC_PROVIDER_NAME"
            if [ -n "$CONFIG_AGENTIC_INTERVAL" ] && [ "$CONFIG_AGENTIC_INTERVAL" != "3600" ]; then
                set -- "$@" --agentic-interval "$CONFIG_AGENTIC_INTERVAL"
            fi
        fi
        
        if [ -n "$SUDO" ]; then
            if [ -n "$NOHUP_CMD" ]; then
                $SUDO $NOHUP_CMD "$RESOLVED_BINARY_PATH" "$@" >/dev/null 2>&1 &
            else
                $SUDO "$RESOLVED_BINARY_PATH" "$@" >/dev/null 2>&1 &
            fi
        else
            if [ -n "$NOHUP_CMD" ]; then
                $NOHUP_CMD "$RESOLVED_BINARY_PATH" "$@" >/dev/null 2>&1 &
            else
                "$RESOLVED_BINARY_PATH" "$@" >/dev/null 2>&1 &
            fi
        fi
    )
    
    info "✓ Background daemon started"
    
    # Give it time to initialize
    sleep 5
    
    # Verify it started
    show_daemon_status "$RESOLVED_BINARY_PATH"
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

