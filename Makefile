.PHONY: clean macos macos_release macos_debug macos_publish windows windows_debug windows_release windows_publish linux linux_debug linux_release linux_publish upgrade unused_dependencies format test completions

# Import and export env for edamame_core and edamame_foundation
-include ../secrets/lambda-signature.env
-include ../secrets/foundation.env
-include ../secrets/sentry.env
-include ../secrets/analytics.env
-include ../secrets/edamame.env
export

completions:
	mkdir -p ./completions
	./target/release/edamame_posture completion bash > ./completions/edamame_posture.bash
	./target/release/edamame_posture completion fish > ./completions/edamame_posture.fish
	./target/release/edamame_posture completion zsh > ./completions/_edamame_posture

macos: macos_release completions

macos_release:
	cargo build --release

macos_debug:
	cargo build
	sudo bash -c "export RUST_BACKTRACE=1; export EDAMAME_LOG_LEVEL=info; rust-lldb ./target/debug/edamame_posture"

macos_publish: macos_release
	# Sign + hardened runtime
	./macos/sign.sh ./target/release/edamame_posture

windows: windows_release completions

windows_debug:
	cargo build
 
windows_release:
	cargo build --release

windows_publish: windows_release

linux: linux_release completions

linux_debug:
	cargo build

linux_release:
	cargo build --release

linux_publish: linux_release
	cargo deb

linux_alpine: linux_alpine_release

linux_alpine_debug:
	rustup target add x86_64-unknown-linux-musl
	cargo build --target x86_64-unknown-linux-musl

linux_alpine_release:
	rustup target add x86_64-unknown-linux-musl
	cargo build --release --target x86_64-unknown-linux-musl

linux_alpine_publish: linux_alpine_release

upgrade:
	rustup update
	cargo install -f cargo-upgrades
	cargo upgrades
	cargo update

unused_dependencies:
	cargo +nightly udeps

format:
	cargo fmt

clean:
	cargo clean
	rm -rf ./build/
	rm -rf ./target/
	# Keep cleaning generated files here, scripts might create them outside temp dirs if run manually
	rm -f custom_whitelists.json custom_blacklist.json exceptions.log blacklisted_sessions.log
	# Clean temporary directories created by scripts
	rm -rf tests_temp

# Basic cargo tests
test:
	bash ./tests/basic_cargo_test.sh

# Define the binary based on the OS for script usage
# Ensure the path is relative to the Makefile location
BINARY_PATH := ./target/release/edamame_posture
ifeq ($(OS),Windows_NT)
    BINARY_PATH := ./target/release/edamame_posture.exe
endif
export BINARY_PATH # Export for the scripts to use

# Define SUDO_CMD based on OS
ifeq ($(OS),Windows_NT)
    SUDO_CMD :=
else
	SUDO_CMD := sudo -E
endif
export SUDO_CMD # Export for the scripts to use

# Standalone CLI commands test (mirrors old commands_test and initial workflow steps)
commands_test: macos_release # Ensure binary is built
	# Pass OS info for script's internal logic
	export RUNNER_OS=$(shell if [ "$(OS)" = "Windows_NT" ]; then echo "Windows_NT"; else echo "$(shell uname)"; fi); \
	bash ./tests/standalone_commands_test.sh

# Run integration tests in disconnected mode (local default)
test_integration_local: macos_release # Ensure binary is built
	# Pass OS info for script's internal logic
	# CI will be implicitly false as it's not set here
	export RUNNER_OS=$(shell if [ "$(OS)" = "Windows_NT" ]; then echo "Windows_NT"; else echo "$(shell uname)"; fi); \
	bash ./tests/integration_test.sh

# Run integration tests in connected mode (requires credentials).
# Requires credentials (EDAMAME_USER, EDAMAME_DOMAIN, EDAMAME_PIN) to be set in the environment.
# Warning: This will connect to the actual backend.
test_integration_connected: macos_release # Ensure binary is built
	# Pass OS info for script's internal logic
	export RUNNER_OS=$(shell if [ "$(OS)" = "Windows_NT" ]; then echo "Windows_NT"; else echo "$(shell uname)"; fi); \
	# Check for required env vars before running
	@[ "${EDAMAME_USER}" ] || (echo "Error: EDAMAME_USER env var is not set. Cannot run connected tests."; exit 1)
	@[ "${EDAMAME_DOMAIN}" ] || (echo "Error: EDAMAME_DOMAIN env var is not set. Cannot run connected tests."; exit 1)
	@[ "${EDAMAME_PIN}" ] || (echo "Error: EDAMAME_PIN env var is not set. Cannot run connected tests."; exit 1)
	# Explicitly set CI=true for this target
	export CI=true; \
	bash ./tests/integration_test.sh

# Aggregate target for local testing (excluding connected tests by default)
all_test: test commands_test test_integration_local
	@echo "--- All Local Tests Completed ---"
	@echo "Note: 'make test_integration_connected' can be run separately if credentials are configured."

# =============================================================================
# Lima VM targets for eBPF testing on macOS
# =============================================================================

LIMA_VM_NAME ?= posture-ebpf-test
LIMA_CONFIG  ?= Lima.linux-test.yml

.PHONY: lima_check lima_create lima_start lima_stop lima_delete lima_shell lima_test lima_status

# Check if Lima is installed
lima_check:
	@which limactl > /dev/null || (echo "Lima not installed. Install with: brew install lima" && exit 1)

# Create the Lima VM
lima_create: lima_check
	@echo "Creating Lima VM '$(LIMA_VM_NAME)'..."
	limactl create --name=$(LIMA_VM_NAME) $(LIMA_CONFIG)

# Start the Lima VM
lima_start: lima_check
	@if limactl list -q | grep -q "^$(LIMA_VM_NAME)$$"; then \
		echo "Starting Lima VM '$(LIMA_VM_NAME)'..."; \
		limactl start $(LIMA_VM_NAME); \
	else \
		echo "VM '$(LIMA_VM_NAME)' doesn't exist. Creating it first..."; \
		$(MAKE) lima_create; \
		limactl start $(LIMA_VM_NAME); \
	fi

# Stop the Lima VM
lima_stop: lima_check
	-limactl stop $(LIMA_VM_NAME)

# Delete the Lima VM
lima_delete: lima_check
	-limactl delete $(LIMA_VM_NAME)

# Open a shell in the Lima VM
lima_shell: lima_start
	limactl shell $(LIMA_VM_NAME)

# Show Lima VM status
lima_status: lima_check
	@limactl list

# Build and verify eBPF in Lima VM
# Since edamame_posture depends on private repos that need git auth,
# we test flodbadd directly which exercises the same eBPF code.
lima_test: lima_start
	@echo "============================================================"
	@echo "Testing eBPF support in Lima VM '$(LIMA_VM_NAME)'..."
	@echo "============================================================"
	limactl shell $(LIMA_VM_NAME) -- bash -c '\
		set -e; \
		\
		# Install Rust if not present \
		if [ ! -f $$HOME/.cargo/env ]; then \
			echo "Installing Rust..."; \
			curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y; \
		fi; \
		source $$HOME/.cargo/env; \
		\
		echo "=== Environment ==="; \
		echo "Kernel: $$(uname -r)"; \
		echo "Clang: $$(clang --version 2>/dev/null | head -1 || echo NOT INSTALLED)"; \
		echo "Rust: $$(rustc --version)"; \
		echo "Architecture: $$(uname -m)"; \
		echo ""; \
		\
		echo "=== Building flodbadd with eBPF (release) ==="; \
		cd /Users/flyonnet/Programming/flodbadd; \
		cargo build --release --features packetcapture,asyncpacketcapture,ebpf 2>&1 | tee /tmp/build.log; \
		\
		echo ""; \
		echo "=== Checking eBPF build output ==="; \
		grep -E "eBPF program compiled|eBPF program will be embedded" /tmp/build.log || echo "⚠️ No eBPF compilation messages"; \
		\
		echo ""; \
		echo "=== Testing eBPF runtime support ==="; \
		sudo -E RUSTUP_HOME=$$HOME/.rustup CARGO_HOME=$$HOME/.cargo \
			$$HOME/.cargo/bin/cargo run --release --features packetcapture,asyncpacketcapture,ebpf --example check_ebpf 2>&1 | tee /tmp/ebpf_check.log; \
		\
		echo ""; \
		echo "=== Final Status ==="; \
		if grep -q "eBPF support: Enabled" /tmp/ebpf_check.log; then \
			echo "✅ eBPF is ENABLED and working!"; \
		elif grep -q "eBPF available: true" /tmp/ebpf_check.log; then \
			echo "✅ eBPF is available!"; \
		else \
			echo "❌ eBPF not working:"; \
			grep -i "ebpf" /tmp/ebpf_check.log; \
			exit 1; \
		fi \
	'

# -----------------------------------------------------------------------------
# Ubuntu 22.04 LTS
# -----------------------------------------------------------------------------

UBUNTU2204_VM_NAME ?= posture-ubuntu2204-test
UBUNTU2204_CONFIG  ?= Lima.ubuntu2204-test.yml

.PHONY: ubuntu2204_create ubuntu2204_start ubuntu2204_stop ubuntu2204_delete ubuntu2204_test

ubuntu2204_create: lima_check
	limactl create --name=$(UBUNTU2204_VM_NAME) $(UBUNTU2204_CONFIG)

ubuntu2204_start: lima_check
	@if limactl list -q | grep -q "^$(UBUNTU2204_VM_NAME)$$"; then \
		limactl start $(UBUNTU2204_VM_NAME); \
	else \
		$(MAKE) ubuntu2204_create; \
		limactl start $(UBUNTU2204_VM_NAME); \
	fi

ubuntu2204_stop: lima_check
	-limactl stop $(UBUNTU2204_VM_NAME)

ubuntu2204_delete: lima_check
	-limactl delete $(UBUNTU2204_VM_NAME)

ubuntu2204_test: ubuntu2204_start
	@echo "============================================================"
	@echo "Testing eBPF on Ubuntu 22.04 LTS..."
	@echo "============================================================"
	limactl shell $(UBUNTU2204_VM_NAME) -- bash -c '\
		set -e; \
		if [ ! -f $$HOME/.cargo/env ]; then \
			echo "Installing Rust..."; \
			curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y; \
		fi; \
		source $$HOME/.cargo/env; \
		echo "=== Environment ==="; \
		cat /etc/lsb-release | grep DESCRIPTION || true; \
		echo "Kernel: $$(uname -r)"; \
		echo "Clang: $$(clang --version 2>/dev/null | head -1 || echo NOT INSTALLED)"; \
		echo "Architecture: $$(uname -m)"; \
		echo ""; \
		cd /Users/flyonnet/Programming/flodbadd; \
		cargo build --release --features packetcapture,asyncpacketcapture,ebpf 2>&1 | grep -E "eBPF|Compiling flodbadd|Finished" || true; \
		sudo -E RUSTUP_HOME=$$HOME/.rustup CARGO_HOME=$$HOME/.cargo \
			$$HOME/.cargo/bin/cargo run --release --features packetcapture,asyncpacketcapture,ebpf --example check_ebpf 2>&1 | tail -5; \
	'

# -----------------------------------------------------------------------------
# Ubuntu 20.04 LTS
# -----------------------------------------------------------------------------

UBUNTU2004_VM_NAME ?= posture-ubuntu2004-test
UBUNTU2004_CONFIG  ?= Lima.ubuntu2004-test.yml

.PHONY: ubuntu2004_create ubuntu2004_start ubuntu2004_stop ubuntu2004_delete ubuntu2004_test

ubuntu2004_create: lima_check
	limactl create --name=$(UBUNTU2004_VM_NAME) $(UBUNTU2004_CONFIG)

ubuntu2004_start: lima_check
	@if limactl list -q | grep -q "^$(UBUNTU2004_VM_NAME)$$"; then \
		limactl start $(UBUNTU2004_VM_NAME); \
	else \
		$(MAKE) ubuntu2004_create; \
		limactl start $(UBUNTU2004_VM_NAME); \
	fi

ubuntu2004_stop: lima_check
	-limactl stop $(UBUNTU2004_VM_NAME)

ubuntu2004_delete: lima_check
	-limactl delete $(UBUNTU2004_VM_NAME)

ubuntu2004_test: ubuntu2004_start
	@echo "============================================================"
	@echo "Testing eBPF on Ubuntu 20.04 LTS..."
	@echo "============================================================"
	limactl shell $(UBUNTU2004_VM_NAME) -- bash -c '\
		set -e; \
		if [ ! -f $$HOME/.cargo/env ]; then \
			echo "Installing Rust..."; \
			curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y; \
		fi; \
		source $$HOME/.cargo/env; \
		echo "=== Environment ==="; \
		cat /etc/lsb-release | grep DESCRIPTION || true; \
		echo "Kernel: $$(uname -r)"; \
		echo "Clang: $$(clang --version 2>/dev/null | head -1 || echo NOT INSTALLED)"; \
		echo "Architecture: $$(uname -m)"; \
		echo ""; \
		cd /Users/flyonnet/Programming/flodbadd; \
		cargo build --release --features packetcapture,asyncpacketcapture,ebpf 2>&1 | grep -E "eBPF|Compiling flodbadd|Finished" || true; \
		sudo -E RUSTUP_HOME=$$HOME/.rustup CARGO_HOME=$$HOME/.cargo \
			$$HOME/.cargo/bin/cargo run --release --features packetcapture,asyncpacketcapture,ebpf --example check_ebpf 2>&1 | tail -5; \
	'

# -----------------------------------------------------------------------------
# Alpine Linux 3.20
# -----------------------------------------------------------------------------

ALPINE_VM_NAME ?= posture-alpine-test
ALPINE_CONFIG  ?= Lima.alpine-test.yml

.PHONY: alpine_create alpine_start alpine_stop alpine_delete alpine_test

alpine_create: lima_check
	limactl create --name=$(ALPINE_VM_NAME) $(ALPINE_CONFIG)

alpine_start: lima_check
	@if limactl list -q | grep -q "^$(ALPINE_VM_NAME)$$"; then \
		limactl start $(ALPINE_VM_NAME); \
	else \
		$(MAKE) alpine_create; \
		limactl start $(ALPINE_VM_NAME); \
	fi

alpine_stop: lima_check
	-limactl stop $(ALPINE_VM_NAME)

alpine_delete: lima_check
	-limactl delete $(ALPINE_VM_NAME)

alpine_test: alpine_start
	@echo "============================================================"
	@echo "Testing eBPF on Alpine Linux (musl libc)..."
	@echo "============================================================"
	limactl shell $(ALPINE_VM_NAME) -- sh -c '\
		set -e; \
		if [ ! -f $$HOME/.cargo/env ]; then \
			echo "Installing Rust..."; \
			curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y; \
		fi; \
		. $$HOME/.cargo/env; \
		echo "=== Environment ==="; \
		cat /etc/alpine-release || true; \
		echo "Kernel: $$(uname -r)"; \
		echo "Clang: $$(clang --version 2>/dev/null | head -1 || echo NOT INSTALLED)"; \
		echo "Architecture: $$(uname -m)"; \
		echo "libc: musl"; \
		echo ""; \
		cd /Users/flyonnet/Programming/flodbadd; \
		cargo build --release --features packetcapture,asyncpacketcapture,ebpf 2>&1 | grep -E "eBPF|Compiling flodbadd|Finished" || true; \
		sudo -E RUSTUP_HOME=$$HOME/.rustup CARGO_HOME=$$HOME/.cargo \
			$$HOME/.cargo/bin/cargo run --release --features packetcapture,asyncpacketcapture,ebpf --example check_ebpf 2>&1 | tail -5; \
	'

# =============================================================================
# Test all distributions
# =============================================================================

.PHONY: test_all_distros stop_all_vms

test_all_distros:
	@echo "Testing eBPF on all supported distributions..."
	@echo ""
	@echo "=== Ubuntu 24.04 (latest) ===" && $(MAKE) lima_test && echo "✅ PASSED" || echo "❌ FAILED"
	@echo "=== Ubuntu 22.04 LTS ===" && $(MAKE) ubuntu2204_test && echo "✅ PASSED" || echo "❌ FAILED"
	@echo "=== Ubuntu 20.04 LTS ===" && $(MAKE) ubuntu2004_test && echo "✅ PASSED" || echo "❌ FAILED"
	@echo "=== Alpine 3.20 ===" && $(MAKE) alpine_test && echo "✅ PASSED" || echo "❌ FAILED"
	@echo ""
	@echo "All distribution tests complete!"

stop_all_vms:
	@echo "Stopping all Lima VMs..."
	-limactl stop posture-ebpf-test
	-limactl stop posture-ubuntu2204-test
	-limactl stop posture-ubuntu2004-test
	-limactl stop posture-alpine-test
	@echo "All VMs stopped."

