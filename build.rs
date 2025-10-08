#[cfg(target_os = "windows")]
use flodbadd::windows_npcap;

#[cfg(target_os = "windows")]
fn copy_npcap_dlls(npcap_dir: &std::path::Path) -> std::io::Result<()> {
    use std::env;
    use std::fs;
    use std::path::Path;

    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
    let profile = env::var("PROFILE").unwrap_or_else(|_| "debug".to_string());
    let target_dir = env::var("CARGO_TARGET_DIR")
        .unwrap_or_else(|_| format!("{}{}target", manifest_dir, std::path::MAIN_SEPARATOR));

    let profile_dir = Path::new(&target_dir).join(&profile);
    let deps_dir = profile_dir.join("deps");

    fs::create_dir_all(&profile_dir)?;
    fs::create_dir_all(&deps_dir)?;

    let wpcap_src = npcap_dir.join("wpcap.dll");
    let packet_src = npcap_dir.join("Packet.dll");

    for dest in [
        profile_dir.join("wpcap.dll"),
        profile_dir.join("Packet.dll"),
        deps_dir.join("wpcap.dll"),
        deps_dir.join("Packet.dll"),
    ] {
        let src = if dest
            .file_name()
            .and_then(|s| s.to_str())
            .map(|s| s.eq_ignore_ascii_case("wpcap.dll"))
            .unwrap_or(false)
        {
            &wpcap_src
        } else {
            &packet_src
        };
        let _ = fs::copy(src, &dest);
    }

    println!(
        "cargo:warning=[edamame_posture] Copied Npcap DLLs next to binary: {}",
        profile_dir.display()
    );
    Ok(())
}

use std::env;
use vergen_gitcl::*;

// To debug cfg, in particular vergen
fn dump_cfg() {
    for (key, value) in env::vars() {
        if key.starts_with("VERGEN_GIT_BRANCH") {
            eprintln!("{}: {:?}", key, value);
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Windows-specific linking/runtime assistance
    #[cfg(target_os = "windows")]
    {
        // Always emit MSVC delay-load flags so the process can start without the DLL present
        #[cfg(target_env = "msvc")]
        {
            println!("cargo:rustc-link-arg=/DELAYLOAD:wpcap.dll");
            println!("cargo:rustc-link-arg=/DELAYLOAD:Packet.dll");
            println!("cargo:rustc-link-lib=dylib=delayimp");
        }

        if let Some(npcap_dir) = windows_npcap::find_npcap_runtime_dir() {
            // Help the loader by placing DLLs next to the produced binary
            let _ = copy_npcap_dlls(&npcap_dir);
            // Also add to link search path for good measure
            println!("cargo:rustc-link-search=native={}", npcap_dir.display());
        } else {
            println!("cargo:warning=[edamame_posture] Npcap runtime not found during build");
        }
    }

    // Emit the instructions
    let build = BuildBuilder::all_build()?;
    let cargo = CargoBuilder::all_cargo()?;
    let gitcl = GitclBuilder::all_git()?;
    let rustc = RustcBuilder::all_rustc()?;
    let si = SysinfoBuilder::all_sysinfo()?;

    match Emitter::default()
        .add_instructions(&build)?
        .add_instructions(&cargo)?
        .add_instructions(&gitcl)?
        .add_instructions(&rustc)?
        .add_instructions(&si)?
        .emit()
    {
        Ok(_) => (),
        Err(e) => {
            eprintln!("Error emitting: {}", e);
            panic!("Error emitting: {}", e);
        }
    }

    dump_cfg();

    Ok(())
}
