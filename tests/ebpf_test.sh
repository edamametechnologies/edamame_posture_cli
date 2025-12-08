#!/bin/bash
# eBPF Diagnostic Test - Comprehensive status and diagnostic for eBPF support
# This script runs as a first step to show eBPF status with extensive diagnostics
#
# Usage:
#   ./ebpf_test.sh                    # Auto-detect binary
#   ./ebpf_test.sh /path/to/binary    # Use specific binary
#   BINARY_PATH=/path/to/binary ./ebpf_test.sh
#
# Environment variables:
#   BINARY_PATH    - Path to edamame_posture or flodbadd binary
#   FLODBADD_PATH  - Path to flodbadd repo (for cargo-based testing)
#   SKIP_RUNTIME   - Set to skip runtime test (diagnostics only)

set -eo pipefail

echo "============================================================"
echo "           eBPF DIAGNOSTIC TEST"
echo "============================================================"
echo ""

# =============================================================================
# Distribution Detection
# =============================================================================
echo "=== Distribution Information ==="

OS_NAME=$(uname -s)
KERNEL_VERSION=$(uname -r)
ARCH=$(uname -m)

echo "OS: $OS_NAME"
echo "Kernel: $KERNEL_VERSION"
echo "Architecture: $ARCH"

# Detect specific distribution
DISTRO="unknown"
DISTRO_VERSION=""

if [[ "$OS_NAME" == "Linux" ]]; then
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        DISTRO="$ID"
        DISTRO_VERSION="$VERSION_ID"
        echo "Distribution: $PRETTY_NAME"
    elif [[ -f /etc/lsb-release ]]; then
        . /etc/lsb-release
        DISTRO="$DISTRIB_ID"
        DISTRO_VERSION="$DISTRIB_RELEASE"
        echo "Distribution: $DISTRIB_DESCRIPTION"
    elif [[ -f /etc/alpine-release ]]; then
        DISTRO="alpine"
        DISTRO_VERSION=$(cat /etc/alpine-release)
        echo "Distribution: Alpine Linux $DISTRO_VERSION"
    elif [[ -f /etc/debian_version ]]; then
        DISTRO="debian"
        DISTRO_VERSION=$(cat /etc/debian_version)
        echo "Distribution: Debian $DISTRO_VERSION"
    elif [[ -f /etc/redhat-release ]]; then
        DISTRO="rhel"
        echo "Distribution: $(cat /etc/redhat-release)"
    fi
    
    # Detect libc type
    if ldd --version 2>&1 | grep -qi musl; then
        LIBC_TYPE="musl"
        echo "C Library: musl"
    elif ldd --version 2>&1 | grep -qi glibc; then
        LIBC_TYPE="glibc"
        GLIBC_VERSION=$(ldd --version 2>&1 | head -1 | grep -oE '[0-9]+\.[0-9]+' | head -1 || echo "unknown")
        echo "C Library: glibc $GLIBC_VERSION"
    else
        LIBC_TYPE="unknown"
        echo "C Library: unknown"
    fi
fi

# Check if we're on Linux
if [[ "$OS_NAME" != "Linux" ]]; then
    echo ""
    echo "⏭️  eBPF is only supported on Linux. Skipping diagnostics."
    echo "   Current OS: $OS_NAME"
    echo ""
    echo "============================================================"
    echo "           eBPF DIAGNOSTIC COMPLETE (N/A)"
    echo "============================================================"
    exit 0
fi

# =============================================================================
# Container Detection
# =============================================================================
echo ""
echo "=== Container Detection ==="

IS_CONTAINER="no"
CONTAINER_TYPE="native"

if [[ -f /.dockerenv ]]; then
    IS_CONTAINER="yes"
    CONTAINER_TYPE="docker"
    echo "🐳 Running inside Docker container"
elif grep -q 'docker\|lxc\|containerd' /proc/1/cgroup 2>/dev/null; then
    IS_CONTAINER="yes"
    CONTAINER_TYPE="container (cgroup)"
    echo "📦 Running inside container (detected via cgroup)"
elif [[ -f /run/.containerenv ]]; then
    IS_CONTAINER="yes"
    CONTAINER_TYPE="podman"
    echo "🦭 Running inside Podman container"
elif [[ -n "$KUBERNETES_SERVICE_HOST" ]]; then
    IS_CONTAINER="yes"
    CONTAINER_TYPE="kubernetes"
    echo "☸️  Running inside Kubernetes pod"
elif [[ -n "$LIMA_CIDATA_MNT" ]] || [[ -d /Users ]]; then
    echo "🖥️  Running in Lima VM (macOS virtualization)"
    CONTAINER_TYPE="lima"
else
    echo "🖥️  Running on native host (not a container)"
fi

# =============================================================================
# Kernel Configuration
# =============================================================================
echo ""
echo "=== Kernel Configuration ==="

# Check kernel config for BPF support
if [[ -f /proc/config.gz ]]; then
    echo "Kernel config available at /proc/config.gz"
    BPF_ENABLED=$(zcat /proc/config.gz 2>/dev/null | grep -E "^CONFIG_BPF=|^CONFIG_BPF_SYSCALL=" || echo "unknown")
    echo "BPF config: $BPF_ENABLED"
elif [[ -f /boot/config-$KERNEL_VERSION ]]; then
    echo "Kernel config available at /boot/config-$KERNEL_VERSION"
    BPF_ENABLED=$(grep -E "^CONFIG_BPF=|^CONFIG_BPF_SYSCALL=" /boot/config-$KERNEL_VERSION 2>/dev/null || echo "unknown")
    echo "BPF config: $BPF_ENABLED"
else
    echo "⚠️  Kernel config not accessible"
fi

# =============================================================================
# BPF Sysctls
# =============================================================================
echo ""
echo "=== BPF Sysctl Settings ==="

if [[ -f /proc/sys/kernel/unprivileged_bpf_disabled ]]; then
    BPF_DISABLED=$(cat /proc/sys/kernel/unprivileged_bpf_disabled)
    case "$BPF_DISABLED" in
        0) echo "✅ unprivileged_bpf_disabled = 0 (unprivileged BPF allowed)" ;;
        1) echo "⚠️  unprivileged_bpf_disabled = 1 (unprivileged BPF disabled, root required)" ;;
        2) echo "🔒 unprivileged_bpf_disabled = 2 (permanently disabled until reboot)" ;;
        *) echo "❓ unprivileged_bpf_disabled = $BPF_DISABLED (unknown value)" ;;
    esac
else
    echo "⚠️  /proc/sys/kernel/unprivileged_bpf_disabled not available"
fi

if [[ -f /proc/sys/kernel/perf_event_paranoid ]]; then
    PERF_PARANOID=$(cat /proc/sys/kernel/perf_event_paranoid)
    case "$PERF_PARANOID" in
        -1) echo "✅ perf_event_paranoid = -1 (allow all)" ;;
        0)  echo "✅ perf_event_paranoid = 0 (allow raw tracepoint access)" ;;
        1)  echo "⚠️  perf_event_paranoid = 1 (restrict CPU events)" ;;
        2)  echo "⚠️  perf_event_paranoid = 2 (restrict kernel profiling)" ;;
        3)  echo "🔒 perf_event_paranoid = 3 (restrict all)" ;;
        *)  echo "❓ perf_event_paranoid = $PERF_PARANOID (unknown value)" ;;
    esac
else
    echo "⚠️  /proc/sys/kernel/perf_event_paranoid not available"
fi

# =============================================================================
# Required Filesystems
# =============================================================================
echo ""
echo "=== Required Filesystems ==="

# Check debugfs
if mount | grep -q "type debugfs"; then
    DEBUGFS_MOUNT=$(mount | grep "type debugfs" | head -1)
    echo "✅ debugfs mounted: $DEBUGFS_MOUNT"
else
    echo "⚠️  debugfs not mounted (may affect kprobe tracing)"
fi

# Check tracefs
if mount | grep -q "type tracefs"; then
    TRACEFS_MOUNT=$(mount | grep "type tracefs" | head -1)
    echo "✅ tracefs mounted: $TRACEFS_MOUNT"
else
    echo "⚠️  tracefs not mounted (may affect tracing)"
fi

# Check bpf filesystem
if mount | grep -q "type bpf"; then
    BPF_MOUNT=$(mount | grep "type bpf" | head -1)
    echo "✅ bpf filesystem mounted: $BPF_MOUNT"
else
    echo "⚠️  bpf filesystem not mounted"
fi

# =============================================================================
# Build Tools (for eBPF compilation)
# =============================================================================
echo ""
echo "=== Build Tools (for eBPF compilation) ==="

CLANG_AVAILABLE="no"
if command -v clang &> /dev/null; then
    CLANG_VERSION=$(clang --version | head -1)
    echo "✅ clang: $CLANG_VERSION"
    CLANG_AVAILABLE="yes"
else
    echo "❌ clang: NOT FOUND"
fi

if command -v llvm-strip &> /dev/null; then
    LLVM_STRIP_VERSION=$(llvm-strip --version 2>&1 | head -1 || echo "available")
    echo "✅ llvm-strip: $LLVM_STRIP_VERSION"
else
    echo "⚠️  llvm-strip: not found (optional)"
fi

BPFTOOL_AVAILABLE="no"
if command -v bpftool &> /dev/null; then
    BPFTOOL_VERSION=$(bpftool version 2>&1 | head -1 || echo "available")
    echo "✅ bpftool: $BPFTOOL_VERSION"
    BPFTOOL_AVAILABLE="yes"
else
    echo "⚠️  bpftool: not found (optional for debugging)"
fi

# Check for libbpf headers
LIBBPF_AVAILABLE="no"
if [[ -f /usr/include/bpf/bpf_helpers.h ]]; then
    echo "✅ libbpf headers: /usr/include/bpf/bpf_helpers.h"
    LIBBPF_AVAILABLE="yes"
elif [[ -f /usr/include/linux/bpf.h ]]; then
    echo "⚠️  libbpf-dev not installed, but kernel headers available"
else
    echo "❌ libbpf headers: NOT FOUND"
fi

# Check for kernel headers
KERNEL_HEADERS_AVAILABLE="no"
if [[ -d /lib/modules/$KERNEL_VERSION/build ]]; then
    echo "✅ kernel headers: /lib/modules/$KERNEL_VERSION/build"
    KERNEL_HEADERS_AVAILABLE="yes"
elif [[ -d /usr/src/linux-headers-$KERNEL_VERSION ]]; then
    echo "✅ kernel headers: /usr/src/linux-headers-$KERNEL_VERSION"
    KERNEL_HEADERS_AVAILABLE="yes"
else
    echo "⚠️  kernel headers: not found for $KERNEL_VERSION"
fi

# =============================================================================
# Rust/Cargo Environment
# =============================================================================
echo ""
echo "=== Rust Environment ==="

if command -v cargo &> /dev/null; then
    RUST_VERSION=$(rustc --version 2>/dev/null || echo "unknown")
    CARGO_VERSION=$(cargo --version 2>/dev/null || echo "unknown")
    echo "✅ Rust: $RUST_VERSION"
    echo "✅ Cargo: $CARGO_VERSION"
elif [[ -f "$HOME/.cargo/env" ]]; then
    echo "⚠️  Cargo not in PATH, but found at ~/.cargo/env"
    echo "   Run: source ~/.cargo/env"
else
    echo "⚠️  Rust/Cargo not found"
fi

# =============================================================================
# Current Process Capabilities
# =============================================================================
echo ""
echo "=== Current Process Capabilities ==="

if command -v capsh &> /dev/null; then
    CAPS=$(capsh --print 2>/dev/null | grep -E "^Current:|^Bounding" || echo "Unable to read capabilities")
    echo "$CAPS"
else
    echo "capsh not available, checking /proc/self/status"
    grep -E "^Cap" /proc/self/status 2>/dev/null || echo "Unable to read capabilities"
fi

# Check if running as root
if [[ $EUID -eq 0 ]]; then
    echo "✅ Running as root (UID 0)"
else
    echo "⚠️  Running as non-root (UID $EUID) - may need CAP_BPF, CAP_SYS_ADMIN"
fi

# =============================================================================
# Binary Detection
# =============================================================================
echo ""
echo "=== Binary Detection ==="

# Accept binary path as argument or environment variable
if [[ -n "$1" ]]; then
    BINARY_PATH="$1"
elif [[ -z "$BINARY_PATH" ]]; then
    # Try to find edamame_posture or flodbadd binary
    FOUND_BINARY=$(find ./target -type f \( -name edamame_posture -o -name edamame_posture.exe \) -print -quit 2>/dev/null || echo "")
    if [[ -z "$FOUND_BINARY" ]]; then
        # Try flodbadd examples
        FOUND_BINARY=$(find ./target -type f -name check_ebpf -print -quit 2>/dev/null || echo "")
    fi
    BINARY_PATH="$FOUND_BINARY"
fi

if [[ -z "$BINARY_PATH" ]] || [[ ! -f "$BINARY_PATH" ]]; then
    echo "⚠️  No binary found for runtime test"
    echo "   Searched: ./target for edamame_posture or check_ebpf"
    
    # Check if we have flodbadd path for cargo-based test
    if [[ -n "$FLODBADD_PATH" ]] && [[ -d "$FLODBADD_PATH" ]]; then
        echo "   FLODBADD_PATH set: $FLODBADD_PATH (will use cargo run)"
        BINARY_PATH=""
        USE_CARGO_RUN="yes"
    else
        BINARY_PATH=""
        USE_CARGO_RUN="no"
    fi
else
    echo "✅ Binary found: $BINARY_PATH"
    USE_CARGO_RUN="no"
    
    # Check if binary has eBPF object embedded
    if command -v strings &> /dev/null; then
        if strings "$BINARY_PATH" 2>/dev/null | grep -q "l7_ebpf\|l7_connections\|socket_to_process"; then
            echo "✅ eBPF symbols detected in binary (likely embedded)"
        else
            echo "⚠️  No eBPF symbols detected in binary"
        fi
    fi
fi

# =============================================================================
# Runtime eBPF Test
# =============================================================================
echo ""
echo "=== Runtime eBPF Test ==="

if [[ -n "$SKIP_RUNTIME" ]]; then
    echo "⏭️  Runtime test skipped (SKIP_RUNTIME set)"
    EBPF_STATUS="skipped"
    EBPF_DETAIL=""
else
    # Determine sudo command
    if [[ $EUID -eq 0 ]]; then
        SUDO_CMD=""
    elif command -v sudo &> /dev/null; then
        SUDO_CMD="sudo -E"
    else
        SUDO_CMD=""
    fi

    EBPF_STATUS="unknown"
    EBPF_DETAIL=""

    if [[ -n "$BINARY_PATH" ]]; then
        echo "Running short capture to test eBPF..."
        CAPTURE_OUTPUT=$($SUDO_CMD "$BINARY_PATH" -v capture 2 2>&1 || true)
        
        # Parse eBPF status from output
        if echo "$CAPTURE_OUTPUT" | grep -qi "eBPF.*enabled\|kprobe attached\|kprobe_tcp"; then
            EBPF_STATUS="enabled"
            EBPF_DETAIL=$(echo "$CAPTURE_OUTPUT" | grep -i "eBPF\|kprobe" | head -5)
            echo "✅ eBPF is ENABLED and working"
        elif echo "$CAPTURE_OUTPUT" | grep -qi "Loading embedded object"; then
            # Object is embedded
            if echo "$CAPTURE_OUTPUT" | grep -qi "failed to create map\|map error"; then
                EBPF_STATUS="kernel_restricted"
                EBPF_DETAIL="eBPF object embedded but map creation denied by kernel"
                echo "⚠️  eBPF object embedded, but KERNEL DENIED map creation"
                echo "   This is a runtime restriction, not a build issue"
            elif echo "$CAPTURE_OUTPUT" | grep -qi "failed to load\|error.*load"; then
                EBPF_STATUS="load_failed"
                EBPF_DETAIL=$(echo "$CAPTURE_OUTPUT" | grep -i "failed\|error" | head -3)
                echo "⚠️  eBPF object embedded, but LOADING FAILED"
            else
                EBPF_STATUS="unknown_embedded"
                echo "⚠️  eBPF object embedded, status unclear"
            fi
        elif echo "$CAPTURE_OUTPUT" | grep -qi "not embedded\|object not embedded"; then
            EBPF_STATUS="not_embedded"
            EBPF_DETAIL="eBPF object was not compiled/embedded during build"
            echo "❌ eBPF object NOT EMBEDDED (clang/llvm not available at build time)"
        elif echo "$CAPTURE_OUTPUT" | grep -qi "eBPF.*disabled\|eBPF.*not available"; then
            EBPF_STATUS="disabled"
            EBPF_DETAIL=$(echo "$CAPTURE_OUTPUT" | grep -i "eBPF\|disabled" | head -3)
            echo "⚠️  eBPF is DISABLED"
        else
            EBPF_STATUS="unknown"
            echo "⚠️  Could not determine eBPF status from capture output"
        fi
        
        # Show relevant log lines
        echo ""
        echo "Relevant eBPF log entries:"
        echo "$CAPTURE_OUTPUT" | grep -i "eBPF\|BPF\|kprobe\|l7_" | head -10 || echo "(none found)"
        
    elif [[ "$USE_CARGO_RUN" == "yes" ]]; then
        echo "Running flodbadd check_ebpf example via cargo..."
        cd "$FLODBADD_PATH"
        
        # Source cargo env if needed
        if [[ -f "$HOME/.cargo/env" ]]; then
            source "$HOME/.cargo/env"
        fi
        
        CARGO_OUTPUT=$($SUDO_CMD cargo run --release --features packetcapture,asyncpacketcapture,ebpf --example check_ebpf 2>&1 || true)
        
        if echo "$CARGO_OUTPUT" | grep -qi "eBPF support: Enabled\|eBPF available: true"; then
            EBPF_STATUS="enabled"
            EBPF_DETAIL="check_ebpf example reports eBPF enabled"
            echo "✅ eBPF is ENABLED (via check_ebpf example)"
        elif echo "$CARGO_OUTPUT" | grep -qi "not embedded\|clang"; then
            EBPF_STATUS="not_embedded"
            EBPF_DETAIL="eBPF not compiled (clang missing)"
            echo "❌ eBPF NOT EMBEDDED"
        else
            EBPF_STATUS="unknown"
            echo "⚠️  Status unclear from cargo output"
        fi
        
        echo ""
        echo "check_ebpf output:"
        echo "$CARGO_OUTPUT" | tail -10
    else
        echo "⚠️  No binary or cargo path available for runtime test"
        EBPF_STATUS="no_binary"
    fi
fi

# =============================================================================
# Summary
# =============================================================================
echo ""
echo "============================================================"
echo "           eBPF DIAGNOSTIC SUMMARY"
echo "============================================================"
echo ""
echo "Platform:          $DISTRO $DISTRO_VERSION ($ARCH)"
echo "Kernel:            $KERNEL_VERSION"
echo "Environment:       $CONTAINER_TYPE"
echo "C Library:         ${LIBC_TYPE:-unknown}"
echo ""
echo "Build Tools:"
echo "  Clang:           $(command -v clang &>/dev/null && echo "✅ installed" || echo "❌ NOT FOUND")"
echo "  libbpf headers:  $([[ "$LIBBPF_AVAILABLE" == "yes" ]] && echo "✅ installed" || echo "⚠️  not found")"
echo "  Kernel headers:  $([[ "$KERNEL_HEADERS_AVAILABLE" == "yes" ]] && echo "✅ installed" || echo "⚠️  not found")"
echo "  bpftool:         $([[ "$BPFTOOL_AVAILABLE" == "yes" ]] && echo "✅ installed" || echo "⚠️  not found")"
echo ""
echo "Runtime:"
echo "  Running as root: $([[ $EUID -eq 0 ]] && echo "✅ yes" || echo "⚠️  no")"
echo "  eBPF Status:     $EBPF_STATUS"
if [[ -n "$EBPF_DETAIL" ]]; then
    echo "  Detail:          $EBPF_DETAIL"
fi
echo ""

# Exit code based on status
case "$EBPF_STATUS" in
    enabled)
        echo "✅ eBPF is fully functional"
        exit 0
        ;;
    kernel_restricted)
        echo "⚠️  eBPF build OK, but kernel restrictions prevent loading"
        echo "   This is expected on some CI runners and containers"
        exit 0  # Not a failure - build is correct
        ;;
    not_embedded)
        echo "❌ eBPF was not compiled into the binary"
        echo "   Ensure clang and llvm are installed during build"
        exit 1  # This is a build failure
        ;;
    skipped|no_binary)
        echo "⏭️  Runtime test was skipped"
        exit 0
        ;;
    *)
        echo "⚠️  eBPF status inconclusive"
        exit 0  # Don't fail on inconclusive
        ;;
esac
