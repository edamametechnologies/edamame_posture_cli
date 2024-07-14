.PHONY: clean

# Import and export env for edamame_core
-include ../secrets/lambda-signature.env
-include ../secrets/foundation.env
-include ../secrets/sentry.env
export

clean:
	cargo clean
	rm -rf ./build/
	rm -rf ./target/
	rm -rf ./macos/target

macos: macos_release

macos_release:
	cargo build --release

macos_debug:
	cargo build
	bash -c "export RUST_BACKTRACE=1; export EDAMAME_LOG_LEVEL=info; rust-lldb ./target/edamame_posture"

macos_publish: macos_release
	# Sign + hardened runtime
	./macos/sign.sh ./target/edamame_posture

windows: windows_release

windows_debug:
	cargo build

windows_release:
	cargo build --release

linux: linux_release

linux_debug:
	cargo build

linux_release:
	cargo build --release


