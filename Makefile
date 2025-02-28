.PHONY: clean macos macos_release macos_debug macos_publish windows windows_debug windows_release windows_publish linux linux_debug linux_release linux_publish upgrade unused_dependencies format test completions

# Import and export env for edamame_core and edamame_foundation
-include ../secrets/lambda-signature.env
-include ../secrets/foundation.env
-include ../secrets/sentry.env
export

macos: macos_release

macos_release:
	cargo build --release

macos_debug:
	cargo build
	sudo bash -c "export RUST_BACKTRACE=1; export EDAMAME_LOG_LEVEL=info; rust-lldb ./target/debug/edamame_posture"

macos_publish: macos_release
	# Sign + hardened runtime
	./macos/sign.sh ./target/release/edamame_posture

windows: windows_release

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

linux: linux_release

linux_debug:
	cargo build

linux_release:
	cargo build --release

completions:
	mkdir -p ./completions
	./target/release/edamame_posture completion bash > ./completions/edamame_posture.bash
	./target/release/edamame_posture completion fish > ./completions/edamame_posture.fish
	./target/release/edamame_posture completion zsh > ./completions/_edamame_posture

linux_publish: linux_release completions
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

test:
	# Simple test
	cargo test -- --nocapture

# Define the binary based on the OS
BINARY=$(shell if [ "$(RUNNER_OS)" = "Windows" ]; then echo "target/release/edamame_posture.exe"; else echo "target/release/edamame_posture"; fi)

commands_test:
	$(BINARY) score
	$(BINARY) lanscan
	$(BINARY) capture 5
	$(BINARY) get-core-info
	$(BINARY) get-device-info
	$(BINARY) get-system-info
	# Skipped for now
	#$(BINARY) request-pin
	$(BINARY) get-core-version
	$(BINARY) remediate
	$(BINARY) background-logs
	$(BINARY) background-wait-for-connection
	# Can fail because of whitelist conformance, ignore it
	-$(BINARY) background-sessions
	# Skipped for now
	#$(BINARY) background-start
	#$(BINARY) background-stop
	$(BINARY) background-status
	$(BINARY) background-last-report-signature
	$(BINARY) help


