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

macos: OS=macOS
macos: update_threats switch_to_staticlib clean_frb
	# Binary is not signed in the project
	xcodebuild -project ./macos/edamame_posture_xcode/edamame_posture_xcode.xcodeproj -scheme edamame_posture -configuration Release
	# Sign to run locally
	./localsign_macos.sh ./macos/target/edamame_posture

macos_debug: OS=macOS
macos_debug: update_threats switch_to_staticlib clean_frb
	# Binary is not signed in the project
	xcodebuild -project ./macos/edamame_posture_xcode/edamame_posture_xcode.xcodeproj -scheme edamame_posture -configuration Debug
	# Sign to run locally
	./localsign.sh ./macos/target/edamame_posture
	bash -c "export RUST_BACKTRACE=1; export EDAMAME_LOG_LEVEL=info; rust-lldb ./macos/target/edamame_posture"

windows: OS=Windows
windows: update_threats switch_to_cdylib clean_frb
	cargo build
