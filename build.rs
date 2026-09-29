use std::env;
use vergen_gitcl::{Build, Cargo, Emitter, Gitcl, Rustc};

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
    // Fall back to idempotent mode only if it fails (e.g., no git metadata).
    // No vergen sysinfo instructions: they refresh every process on the build
    // host (sysinfo's System::new_all), the enumeration the Windows CI
    // detection gates flag. Nothing here reads VERGEN_SYSINFO_*.
    let build = Build::all_build();
    let cargo = Cargo::all_cargo();
    let gitcl = Gitcl::all_git();
    let rustc = Rustc::all_rustc();

    if Emitter::default()
        .add_instructions(&build)?
        .add_instructions(&cargo)?
        .add_instructions(&gitcl)?
        .add_instructions(&rustc)?
        .emit()
        .is_err()
    {
        eprintln!(
            "cargo:warning=vergen failed to collect build metadata, using idempotent defaults"
        );
        Emitter::default()
            .idempotent()
            .add_instructions(&build)?
            .add_instructions(&cargo)?
            .add_instructions(&gitcl)?
            .add_instructions(&rustc)?
            .emit()?;
    }

    dump_cfg();

    Ok(())
}
