.PHONY: clean macos macos_release macos_debug macos_publish windows windows_debug windows_release windows_publish linux linux_debug linux_release linux_publish upgrade unused_dependencies format test completions

# Import and export env for edamame_core and edamame_foundation
-include ../secrets/lambda-signature.env
-include ../secrets/foundation.env
-include ../secrets/sentry.env
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

windows_pcap:
	choco install wget
	choco install autohotkey.portable
	wget https://nmap.org/npcap/dist/npcap-1.80.exe
	autohotkey ./windows/npcap.ahk ../npcap-1.80.exe
	sleep 20
	ls -la /c/Windows/System32/Npcap

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


