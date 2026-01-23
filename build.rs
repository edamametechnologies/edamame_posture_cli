use std::env;
use vergen_gitcl::{Build, Cargo, Emitter, Gitcl, Rustc, Sysinfo};

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
    flodbadd::windows_npcap::configure_build_linking_from_metadata();

    // Emit the instructions (vergen-gitcl 10.x API)
    // Try without idempotent first to get real values on native builds.
    // Fall back to idempotent mode only if it fails (e.g., during cross-compilation).
    let build = Build::all_build();
    let cargo = Cargo::all_cargo();
    let gitcl = Gitcl::all_git();
    let rustc = Rustc::all_rustc();
    let si = Sysinfo::all_sysinfo();

    if Emitter::default()
        .add_instructions(&build)?
        .add_instructions(&cargo)?
        .add_instructions(&gitcl)?
        .add_instructions(&rustc)?
        .add_instructions(&si)?
        .emit()
        .is_err()
    {
        // Fallback to idempotent mode for cross-compilation
        eprintln!("cargo:warning=vergen failed to get system info, using idempotent defaults");
        Emitter::default()
            .idempotent()
            .add_instructions(&build)?
            .add_instructions(&cargo)?
            .add_instructions(&gitcl)?
            .add_instructions(&rustc)?
            .add_instructions(&si)?
            .emit()?;
    }

    dump_cfg();

    Ok(())
}
