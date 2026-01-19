use std::env;
use vergen_gitcl::{BuildBuilder, CargoBuilder, Emitter, GitclBuilder, RustcBuilder, SysinfoBuilder};

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

    // Emit the instructions with idempotent() for cross-compilation support
    let build = BuildBuilder::all_build()?;
    let cargo = CargoBuilder::all_cargo()?;
    let gitcl = GitclBuilder::all_git()?;
    let rustc = RustcBuilder::all_rustc()?;
    let si = SysinfoBuilder::all_sysinfo()?;

    Emitter::default()
        .idempotent()
        .add_instructions(&build)?
        .add_instructions(&cargo)?
        .add_instructions(&gitcl)?
        .add_instructions(&rustc)?
        .add_instructions(&si)?
        .emit()?;

    dump_cfg();

    Ok(())
}
