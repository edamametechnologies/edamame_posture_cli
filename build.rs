use std::env;
use vergen::EmitBuilder;

// To debug cfg, in particular vergen
fn dump_cfg() {
    for (key, value) in env::vars() {
        if key.starts_with("VERGEN_GIT_BRANCH") {
            eprintln!("{}: {:?}", key, value);
        }
    }
}

fn main() {
    
	// Emit the instructions
    let _ = EmitBuilder::builder()
        .all_build()
        .all_git()
        .all_sysinfo()
        .emit();

    dump_cfg();
}
