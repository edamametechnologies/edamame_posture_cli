use clap::{arg, Command};
#[cfg(unix)]
use daemonize::Daemonize;
use edamame_core::api::api_core::*;
use edamame_core::api::api_score::*;
use edamame_core::api::api_score_threats::*;
use envcrypt::envc;
use fs2::FileExt;
use glob::glob;
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::Command as ProcessCommand;
#[cfg(windows)]
use std::ptr::null_mut;
use std::thread;
use std::time::Duration;
use sysinfo::{Pid, System};
use tracing::error;
#[cfg(windows)]
use widestring::U16CString;
#[cfg(windows)]
use winapi::um::winbase::DETACHED_PROCESS;
#[cfg(windows)]
use winapi::um::winnt::HANDLE;
#[cfg(windows)]
use winapi::{
    shared::minwindef::FALSE,
    um::{
        handleapi::CloseHandle,
        processthreadsapi::{CreateProcessW, PROCESS_INFORMATION, STARTUPINFOW},
    },
};

#[derive(Serialize, Deserialize, Debug)]
struct State {
    pid: Option<u32>,
    is_success: bool,
    connected_domain: String,
    connected_user: String,
    last_network_activity: String,
}

impl State {
    fn load() -> Self {
        let path = Self::state_file_path();
        if path.exists() {
            let mut file = File::open(&path).expect("Unable to open state file");
            file.lock_shared().expect("Unable to lock file for reading");
            let mut contents = String::new();
            file.read_to_string(&mut contents)
                .expect("Unable to read state file");
            let state: State = serde_yaml::from_str(&contents).expect("Unable to parse state file");
            file.unlock().expect("Unable to unlock file");
            state
        } else {
            State {
                pid: None,
                is_success: false,
                connected_domain: "".to_string(),
                connected_user: "".to_string(),
                last_network_activity: "".to_string(),
            }
        }
    }

    fn save(&self) {
        let path = Self::state_file_path();
        let mut file = File::create(&path).expect("Unable to create state file");
        file.lock_exclusive()
            .expect("Unable to lock file for writing");
        let contents = serde_yaml::to_string(self).expect("Unable to serialize state");
        file.write_all(contents.as_bytes())
            .expect("Unable to write state file");
        file.unlock().expect("Unable to unlock file");
    }

    fn state_file_path() -> PathBuf {
        dirs::home_dir()
            .expect("Unable to find home directory")
            .join(".edamame_posture.yaml")
    }

    fn clear() {
        let path = Self::state_file_path();
        if path.exists() {
            fs::remove_file(path).expect("Unable to delete state file");
        }
    }
}

fn handle_score() {
    // Update threats
    update_threats();
    let _ = get_score(true);
    let mut score = get_score(false);
    while score.compute_in_progress {
        thread::sleep(Duration::from_millis(100));
        score = get_score(false);
    }
    // Pretty print the final score with important details
    println!("Stars: {:?}", score.stars);
    println!("Network: {:?}", score.network);
    println!("System Integrity: {:?}", score.system_integrity);
    println!("System Services: {:?}", score.system_services);
    println!("Applications: {:?}", score.applications);
    println!("Credentials: {:?}", score.credentials);
    println!("Overall: {:?}", score.overall);
    // Active threats
    println!("Active threats:");
    for metric in score.active.iter() {
        println!("  - {}", metric.name);
    }
    // Unknown threats
    println!("Unknown threats:");
    for metric in score.unknown.iter() {
        println!("  - {}", metric.name);
    }
    // Inactive threats
    println!("Inactive threats:");
    for metric in score.inactive.iter() {
        println!("  - {}", metric.name);
    }
}

fn handle_wait_for_success(timeout: u64) {
    // Read the state and wait until a network activity is detected and the connection is successful
    let mut state = State::load();

    let mut timeout = timeout;
    while !(state.is_success && state.last_network_activity != "") && timeout > 0 {
        println!("Wait for score computation and reporting to complete... (success: {}, network activity: {})", state.is_success, state.last_network_activity);
        thread::sleep(Duration::from_secs(5));
        timeout = timeout - 5;
        state = State::load();
    }
    if timeout <= 0 {
        eprintln!(
            "Timeout waiting for background process to connect to domain, killing process..."
        );
        stop_background_process();
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
                                Ok(contents) => println!("{}", contents),
                                Err(err) => eprintln!(
                                    "Error reading log file {}: {}",
                                    log_file.display(),
                                    err
                                ),
                            }
                        }
                    }
                    Err(err) => eprintln!("Error finding log files: {}", err),
                }
            }
            Err(err) => eprintln!("Error getting current executable path: {}", err),
        }
        // Exit with an error code
        std::process::exit(1);
    } else {
        println!(
            "Connection successful with domain {} and user {} (success: {}, network activity: {})",
            state.connected_domain,
            state.connected_user,
            state.is_success,
            state.last_network_activity
        );
    }
}

fn handle_get_core_info() {
    let core_info = get_core_info();
    println!("Core information: {}", core_info);
}

fn handle_get_threats_info() {
    let threats = get_threats_info();
    println!("Threats information: {}", threats);
}

fn handle_connect_domain() {
    connect_domain();
}

fn handle_request_pin(user: String, domain: String) {
    set_credentials(user.clone(), domain.clone(), String::new());
    request_pin();
    println!("PIN requested for user: {}, domain: {}", user, domain);
}

fn handle_get_core_version() {
    let version = get_core_version();
    println!("Core version: {}", version);
}

fn run() {
    let device = DeviceInfoAPI {
        device_id: "".to_string(),
        model: "".to_string(),
        brand: "".to_string(),
        os_name: "".to_string(),
        os_version: "".to_string(),
    };

    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 && args[1] == "background-process" {
        // Debug logging
        //std::env::set_var("EDAMAME_LOG_LEVEL", "debug");

        // Reporting and community are on
        initialize(
            "posture".to_string(),
            envc!("VERGEN_GIT_BRANCH").to_string(),
            "EN".to_string(),
            device,
            false,
            // Disable community
            true,
        );

        if args.len() == 5 {
            // Save state
            let state = State {
                pid: Some(std::process::id()),
                is_success: false,
                connected_domain: args[3].clone(),
                connected_user: args[2].clone(),
                last_network_activity: "".to_string(),
            };
            state.save();

            background_process(args[2].clone(), args[3].clone(), args[4].clone());
        } else {
            eprintln!("Invalid arguments for background process");
            // Exit with an error code
            std::process::exit(1);
        }
    } else {
        // Reporting and community are off
        initialize(
            // "cli" will hide the logs from the user
            "debug".to_string(),
            envc!("VERGEN_GIT_BRANCH").to_string(),
            "EN".to_string(),
            device,
            true,
            true,
        );

        run_base();
    }
}

fn pid_exists(pid: u32) -> bool {
    let mut system = System::new_all();
    system.refresh_all();
    system.process(Pid::from_u32(pid)).is_some()
}

fn run_base() {
    let matches = Command::new("edamame_posture")
        .version("1.0")
        .author("Frank Lyonnet")
        .about("CLI interface to edamame_core")
        .subcommand(Command::new("score").about("Get score information"))
        .subcommand(
            Command::new("wait-for-success")
                .about("Wait for success")
                .arg(
                    arg!(<TIMEOUT> "Timeout in seconds")
                        .required(false)
                        .value_parser(clap::value_parser!(u64)),
                ),
        )
        .subcommand(Command::new("get-core-info").about("Get core information"))
        .subcommand(Command::new("get-threats-info").about("Get threats information"))
        .subcommand(
            Command::new("request-pin")
                .about("Request PIN")
                .arg(arg!(<USER> "User name").required(true))
                .arg(arg!(<DOMAIN> "Domain name").required(true)),
        )
        .subcommand(Command::new("get-core-version").about("Get core version"))
        .subcommand(
            Command::new("start")
                .about("Start reporting background process")
                .arg(arg!(<USER> "User name").required(true))
                .arg(arg!(<DOMAIN> "Domain name").required(true))
                .arg(arg!(<PIN> "PIN").required(true)),
        )
        .subcommand(Command::new("stop").about("Stop reporting background process"))
        .subcommand(Command::new("status").about("Get status of reporting background process"))
        .get_matches();

    match matches.subcommand() {
        Some(("score", _)) => handle_score(),
        Some(("wait-for-success", sub_matches)) => {
            let timeout = sub_matches
                .get_one::<u64>("TIMEOUT")
                .unwrap_or_else(|| &120);
            handle_wait_for_success(*timeout)
        }
        Some(("get-core-info", _)) => handle_get_core_info(),
        Some(("get-threats-info", _)) => handle_get_threats_info(),
        Some(("request-pin", sub_matches)) => {
            let user = sub_matches.get_one::<String>("USER").unwrap().to_string();
            let domain = sub_matches.get_one::<String>("DOMAIN").unwrap().to_string();
            handle_request_pin(user, domain);
        }
        Some(("get-core-version", _)) => handle_get_core_version(),
        Some(("start", sub_matches)) => {
            let user = sub_matches.get_one::<String>("USER").unwrap().to_string();
            let domain = sub_matches.get_one::<String>("DOMAIN").unwrap().to_string();
            let pin = sub_matches.get_one::<String>("PIN").unwrap().to_string();
            start_background_process(user, domain, pin);
        }
        Some(("stop", _)) => stop_background_process(),
        Some(("status", _)) => show_background_process_status(),
        _ => error!("Invalid command, use --help for more information"),
    }
}

fn start_background_process(user: String, domain: String, pin: String) {
    // Show core version
    handle_get_core_version();

    // Show core info
    handle_get_core_info();

    println!("Starting background process...");

    #[cfg(unix)]
    {
        let daemonize = Daemonize::new()
            .pid_file("/tmp/edamame.pid")
            .chown_pid_file(true)
            .working_directory("/tmp")
            .privileged_action(
                move || -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
                    let child = ProcessCommand::new(std::env::current_exe().unwrap())
                        .arg("background-process")
                        .arg(&user)
                        .arg(&domain)
                        .arg(&pin)
                        .spawn()
                        .expect("Failed to start background process");

                    println!("Background process ({}) launched", child.id());
                    Ok(())
                },
            );

        match daemonize.start() {
            Ok(_) => println!("Successfully daemonized"),
            Err(e) => eprintln!("Error daemonizing: {}", e),
        }
    }

    #[cfg(windows)]
    {
        let exe = std::env::current_exe().unwrap();
        let cmd = format!(
            "{} background-process {} {} {}",
            exe.display(),
            user,
            domain,
            pin
        );

        let cmd = U16CString::from_str(cmd).unwrap();
        let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
        let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

        let success = unsafe {
            CreateProcessW(
                null_mut(),
                cmd.as_ptr() as *mut _,
                null_mut(),
                null_mut(),
                0,
                DETACHED_PROCESS,
                null_mut(),
                null_mut(),
                &mut si,
                &mut pi,
            )
        };

        if success == FALSE {
            eprintln!("Failed to create background process");
            std::process::exit(1);
        } else {
            unsafe {
                CloseHandle(pi.hProcess as HANDLE);
                CloseHandle(pi.hThread as HANDLE);
            }
        }
    }
}

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

fn stop_background_process() {
    let state = State::load();
    if let Some(pid) = state.pid {
        if pid_exists(pid) {
            println!("Stopping background process ({})", pid);
            let _ = ProcessCommand::new("kill").arg(pid.to_string()).status();
            State::clear();

            // Disconnect domain
            disconnect_domain();
        } else {
            eprintln!("No background process found ({})", pid);
        }
    } else {
        eprintln!("No background process is running.");
    }
}

fn show_background_process_status() {
    let state = State::load();
    if let Some(pid) = state.pid {
        if pid_exists(pid) {
            println!("Background process running ({})", pid);
            // Read connection status
            let connection_status = get_connection();
            println!("Connection status:");
            println!("  - User: {}", connection_status.connected_user);
            println!("  - Domain: {}", connection_status.connected_domain);
            println!("  - PIN: {}", connection_status.pin);
            println!("  - Success: {}", connection_status.is_success);
            println!("  - Connected: {}", connection_status.is_connected);
            println!(
                "  - Outdated backend: {}",
                connection_status.is_outdated_backend
            );
            println!(
                "  - Outdated threats: {}",
                connection_status.is_outdated_threats
            );
            println!(
                "  - Last network activity: {}",
                connection_status.last_network_activity
            );
            println!(
                "  - Backend error code: {}",
                connection_status.backend_error_code
            );
        } else {
            eprintln!("Background process not found ({})", pid);
            State::clear();
            // Exit with an error code
            std::process::exit(1);
        }
    } else {
        println!("No background process is running.");
    }
}

fn background_process(user: String, domain: String, pin: String) {
    println!("Forcing update of threats...");
    // Update threats
    update_threats();

    // Show threats info
    handle_get_threats_info();

    // Set credentials
    set_credentials(user, domain, pin);

    // Request immediate score computation
    let _ = get_score(false);

    // Connect domain
    handle_connect_domain();

    // Loop for ever as background process is running, write the shared state based on the connection status
    loop {
        let connection_status = get_connection();
        let mut state = State::load();
        state.is_success = connection_status.is_success;
        state.last_network_activity = connection_status.last_network_activity;
        state.save();
        thread::sleep(Duration::from_secs(5));
    }
}

pub fn main() {
    run();
}
