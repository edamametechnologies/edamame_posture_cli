use glob::glob;
use std::fs;
use std::io;
use std::io::Write;
use std::path::PathBuf;

fn find_log_files(pattern: &str) -> Result<Vec<PathBuf>, glob::PatternError> {
    let mut log_files = Vec::new();
    for entry in glob(pattern)? {
        match entry {
            Ok(path) => log_files.push(path),
            Err(e) => eprintln!("Error processing entry: {:?}", e),
        }
    }
    Ok(log_files)
}

pub fn display_logs() {
    // Display the process logs stored in the executable directory with prefix "edamame_posture"
    match std::env::current_exe() {
        Ok(exe_path) => {
            let log_pattern = exe_path
                .with_file_name("edamame_posture.*")
                .to_string_lossy()
                .into_owned();
            match find_log_files(&log_pattern) {
                Ok(log_files) => {
                    for log_file in log_files {
                        match fs::read_to_string(&log_file) {
                            Ok(contents) => {
                                println!("{}", contents);
                                // Flush the output
                                match io::stdout().flush() {
                                    Ok(_) => (),
                                    Err(e) => eprintln!("Error flushing stdout: {}", e),
                                }
                            }
                            Err(err) => {
                                eprintln!("Error reading log file {}: {}", log_file.display(), err)
                            }
                        }
                    }
                }
                Err(err) => eprintln!("Error finding log files: {}", err),
            }
        }
        Err(err) => eprintln!("Error getting current executable path: {}", err),
    }
}
