use clap::Command;
use clap_complete::{
    generate_to,
    shells::{Bash, Fish, Zsh},
};
use std::env;
use std::fs;
use std::path::Path;
use vergen_gitcl::*;

// To debug cfg, in particular vergen
fn dump_cfg() {
    for (key, value) in env::vars() {
        if key.starts_with("VERGEN_GIT_BRANCH") {
            eprintln!("{}: {:?}", key, value);
        }
    }
}

fn generate_completions() -> Result<(), Box<dyn std::error::Error>> {
    // Create debian/completions directory if it doesn't exist
    let outdir = Path::new("debian/completions");
    fs::create_dir_all(outdir)?;

    let mut cmd = Command::new("edamame_posture")
        .version(env!("CARGO_PKG_VERSION"))
        .author("Frank Lyonnet")
        .about("CLI interface to edamame_core");

    // Generate completion files
    generate_to(Bash, &mut cmd, "edamame_posture", outdir)?;
    generate_to(Fish, &mut cmd, "edamame_posture", outdir)?;
    generate_to(Zsh, &mut cmd, "edamame_posture", outdir)?;

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
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

    // Generate shell completions
    if let Err(e) = generate_completions() {
        eprintln!("Error generating completions: {}", e);
    }

    dump_cfg();

    Ok(())
}
