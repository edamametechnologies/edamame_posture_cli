.PHONY: clean update_threats switch_to_staticlib switch_to_cdylib

clean:
	cargo clean
	rm -rf ./build/
	rm -rf ./target/
	rm -rf ./macos/target

clean_frb:
	# Remove the add mod frb_generated* from ./rust/src/lib.rs
	cd ../edamame_core/src; if [ `uname` = "Darwin" ]; then sed -i "" '/mod frb_generated/d' ./lib.rs; else sed -i '/mod frb_generated/d' ./lib.rs; fi

update_threats:
	cd ../edamame_foundation; ./update-threats.sh $(OS)

switch_to_staticlib:
	cd ../edamame_foundation; cat ./Cargo.toml | sed 's/\"cdylib\"/\"staticlib\"/g' > ./Cargo.toml.static; cp ./Cargo.toml.static ./Cargo.toml
	cd ../edamame_core; cat ./Cargo.toml | sed 's/\"cdylib\"/\"staticlib\"/g' > ./Cargo.toml.static; cp ./Cargo.toml.static ./Cargo.toml
	cp ./Cargo.lib.toml ./Cargo.toml
	cat ./Cargo.toml | sed 's/\"cdylib\"/\"staticlib\"/g' > ./Cargo.toml.static; cp ./Cargo.toml.static ./Cargo.toml

switch_to_cdylib:
	cd ../edamame_foundation; cat ./Cargo.toml | sed 's/\"staticlib\"/\"cdylib\"/g' > ./Cargo.toml.static; cp ./Cargo.toml.static ./Cargo.toml
	cd ../edamame_core; cat ./Cargo.toml | sed 's/\"staticlib\"/\"cdylib\"/g' > ./Cargo.toml.static; cp ./Cargo.toml.static ./Cargo.toml
	cp ./Cargo.bin.toml ./Cargo.toml

macos: macos_release

macos_release: OS=macOS
macos_release: update_threats switch_to_staticlib clean_frb
	# Binary is not signed in the project
	xcodebuild -project ./macos/edamame_posture_xcode/edamame_posture_xcode.xcodeproj -scheme edamame_posture -configuration Release

macos_debug: OS=macOS
macos_debug: update_threats switch_to_staticlib clean_frb
	# Binary is not signed in the project
	xcodebuild -project ./macos/edamame_posture_xcode/edamame_posture_xcode.xcodeproj -scheme edamame_posture -configuration Debug
	# Sign to run locally
	./macos/localsign.sh ./macos/target/edamame_posture
	bash -c "export RUST_BACKTRACE=1; export EDAMAME_LOG_LEVEL=info; rust-lldb ./macos/target/edamame_posture"

macos_publish: OS=macOS
macos_publish: macos_release
	# Sign + hardened runtime
	./macos/sign.sh ./macos/target/edamame_posture

windows: windows_release

windows_debug: OS=Windows
windows_debug: update_threats switch_to_cdylib clean_frb
	cargo build

windows_release: OS=Windows
windows_release: update_threats switch_to_cdylib clean_frb
	cargo build --release

windows_publish: OS=Windows
windows_publish: windows_release
	# Signing is done in the CI/CD pipeline

linux: linux_release

linux_debug: OS=Linux
linux_debug: update_threats switch_to_cdylib clean_frb
	cargo build

linux_release: OS=Linux
linux_release: update_threats switch_to_cdylib clean_frb
	cargo build --release

linux_publish: OS=Linux
linux_publish: linux_release
	# Signing is done in the CI/CD pipeline

