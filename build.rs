use vergen::EmitBuilder;

fn main() {

    // Dotenv build with a specific env path
    let config = dotenv_build::Config {
        filename: std::path::Path::new("../secrets/foundation.env"),
        recursive_search: false,
        fail_if_missing_dotenv: false,
        ..Default::default()
    };
    dotenv_build::output(config).unwrap();

    // Dotenv build with a specific env path
    let config = dotenv_build::Config {
        filename: std::path::Path::new("../secrets/sentry.env"),
        recursive_search: false,
        fail_if_missing_dotenv: false,
        ..Default::default()
    };
    dotenv_build::output(config).unwrap();

    // Emit the instructions
    let _ = EmitBuilder::builder()
        .all_build()
        .all_git()
        .all_sysinfo()
        .emit();

}
