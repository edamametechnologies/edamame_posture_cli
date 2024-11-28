.PHONY: clean macos macos_release macos_debug macos_publish windows windows_debug windows_release windows_publish linux linux_debug linux_release linux_publish upgrade unused_dependencies format test

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
	RUSTFLAGS="-C target-feature=+crt-static" cargo build
 
windows_release:
	RUSTFLAGS="-C target-feature=+crt-static" cargo build --release

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

linux_publish: linux_release

linux_alpine: linux_alpine_release

linux_alpine_debug:
	rustup target add x86_64-unknown-linux-musl
	export OPENSSL_DIR=/usr
	export OPENSSL_STATIC=1
	cargo build --target x86_64-unknown-linux-musl

linux_alpine_release:
	rustup target add x86_64-unknown-linux-musl
	export OPENSSL_DIR=/usr
	export OPENSSL_STATIC=1
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
	cargo test

commands_test:
	./target/release/edamame_posture score                           	
	./target/release/edamame_posture lanscan                          
	./target/release/edamame_posture capture 5                          
	./target/release/edamame_posture get-core-info                     
	./target/release/edamame_posture get-device-info                   
	./target/release/edamame_posture get-system-info                   
	#./target/release/edamame_posture request-pin                      
	./target/release/edamame_posture get-core-version                 
	./target/release/edamame_posture remediate                        
	./target/release/edamame_posture background-logs                  
	./target/release/edamame_posture background-wait-for-connection    
	./target/release/edamame_posture background-sessions               
	./target/release/edamame_posture background-threats-info          
	#./target/release/edamame_posture background-start                  
	#./target/release/edamame_posture background-stop                   
	./target/release/edamame_posture background-status                 
	./target/release/edamame_posture background-last-report-signature  
	./target/release/edamame_posture help                             
