use clap::{arg, Command};
use tracing::{info, warn};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use std::process::{Command as ProcessCommand};
use std::thread;
use std::time::Duration;
use edamame_core::api::api_core::*;
use edamame_core::api::api_score::*;
use sysinfo::{System, Pid};

#[derive(Serialize, Deserialize, Debug)]
struct State {
    pid: Option<u32>,
    user: String,
    domain: String,
    pin: String,
}

impl State {
    fn load() -> Self {
        let path = Self::state_file_path();
        if path.exists() {
            let contents = fs::read_to_string(path).expect("Unable to read state file");
            serde_yaml::from_str(&contents).expect("Unable to parse state file")
        } else {
            State {
                pid: None,
                user: String::new(),
                domain: String::new(),
                pin: String::new(),
            }
        }
    }

    fn save(&self) {
        let path = Self::state_file_path();
        let contents = serde_yaml::to_string(self).expect("Unable to serialize state");
        fs::write(path, contents).expect("Unable to write state file");
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
    info!(">>>> Score functionality executed");
    let _ = get_score(true);

    thread::sleep(Duration::from_secs(5));

    let mut score = get_score(false);
    while score.compute_in_progress {
        info!(">>>> Score: {:?}", score.stars);
        thread::sleep(Duration::from_secs(5));
        score = get_score(false);
    }
    info!(">>>> Final score: {:?}", score);
}

fn handle_get_connection() {
    let connection = get_connection();
    info!(">>>> Connection details: {:?}", connection);
}

fn handle_get_core_info() {
    let core_info = get_core_info();
    info!(">>>> Core information: {}", core_info);
}

fn handle_set_credentials(user: String, domain: String, pin: String) {
    set_credentials(user, domain, pin);
    info!(">>>> Credentials set");
}

fn handle_connect_domain() {
    connect_domain();
    info!(">>>> Connected to domain");
}

fn handle_disconnect_domain() {
    disconnect_domain();
    info!(">>>> Disconnected from domain");
}

fn handle_request_pin() {
    request_pin();
    info!(">>>> PIN requested");
}

fn handle_get_core_version() {
    let version = get_core_version();
    info!(">>>> Core version: {}", version);
}

fn handle_get_branch() {
    let branch = get_branch();
    info!(">>>> Branch: {}", branch);
}

fn handle_get_last_reported_secs() {
    let last_reported_secs = get_last_reported_secs();
    info!(">>>> Last reported seconds: {}", last_reported_secs);
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

        initialize("posture".to_string(), "EN".to_string(), device);

        if args.len() == 5 {
            
            // Save state
            let state = State {
                pid: Some(std::process::id()),
                user: args[2].clone(),
                domain: args[3].clone(),
                pin: args[4].clone(),
            };
            state.save();
            
            background_process(args[2].clone(), args[3].clone(), args[4].clone());
        } else {
            eprintln!("Invalid arguments for background process");
        }
    } else {
        initialize("cli".to_string(), "EN".to_string(), device);

        run_base();
    }
}

fn pid_exists(pid: u32) -> bool {
    let mut system = System::new_all();
    system.refresh_all();
    // Find the process by PID
    system.process(Pid::from_u32(pid)).is_some()
}

fn run_base() {
    let matches = Command::new("edamame_posture")
        .version("1.0")
        .author("Frank Lyonnet")
        .about("CLI interface to edamame_core")
        .subcommand(Command::new("score").about("Get score information"))
        .subcommand(
            Command::new("lanscan")
                .about("Performs a LAN scan")
                .arg(arg!(-i --interface [INTERFACE] "Optional interface to scan")),
        )
        .subcommand(
            Command::new("pwned")
                .about("Checks if an email is pwned")
                .arg(arg!(<EMAIL> "The email to check").required(true)),
        )
        .subcommand(
            Command::new("set-demo-mode")
                .about("Set demo mode")
                .arg(arg!(<MODE> "true or false").required(true)),
        )
        .subcommand(Command::new("get-connection").about("Get connection details"))
        .subcommand(Command::new("get-core-info").about("Get core information"))
        .subcommand(
            Command::new("set-credentials")
                .about("Set user credentials")
                .arg(arg!(<USER> "User name").required(true))
                .arg(arg!(<DOMAIN> "Domain name").required(true))
                .arg(arg!(<PIN> "PIN").required(true)),
        )
        .subcommand(Command::new("connect-domain").about("Connect to domain"))
        .subcommand(Command::new("disconnect-domain").about("Disconnect from domain"))
        .subcommand(Command::new("request-pin").about("Request PIN"))
        .subcommand(Command::new("get-core-version").about("Get core version"))
        .subcommand(Command::new("get-branch").about("Get branch"))
        .subcommand(Command::new("get-last-reported-secs").about("Get last reported seconds"))
        .subcommand(Command::new("interactive").about("Enter interactive mode"))
        .subcommand(Command::new("test").about("Run a sequence of test commands"))
        .subcommand(
            Command::new("start")
                .about("Start background process")
                .arg(arg!(<USER> "User name").required(true))
                .arg(arg!(<DOMAIN> "Domain name").required(true))
                .arg(arg!(<PIN> "PIN").required(true)),
        )
        .subcommand(Command::new("stop").about("Stop background process"))
        .get_matches();

    // Load existing state and check for running process
    let state = State::load();
    if let Some(pid) = state.pid {
        // Check if the process is still running
        if pid_exists(pid) {
            info!("Background process running with PID: {}", pid);
        } else {
            warn!("Background process not found with PID: {}", pid);
            State::clear();
        }
    }

    let command = matches.subcommand_name().unwrap_or("none");
    info!(">>>> Command: {}", command);

    match matches.subcommand() {
        Some(("score", _)) => handle_score(),
        Some(("get-connection", _)) => handle_get_connection(),
        Some(("get-core-info", _)) => handle_get_core_info(),
        Some(("set-credentials", sub_matches)) => {
            let user = sub_matches.get_one::<String>("USER").unwrap().to_string();
            let domain = sub_matches.get_one::<String>("DOMAIN").unwrap().to_string();
            let pin = sub_matches.get_one::<String>("PIN").unwrap().to_string();
            handle_set_credentials(user, domain, pin);
        }
        Some(("connect-domain", _)) => handle_connect_domain(),
        Some(("disconnect-domain", _)) => handle_disconnect_domain(),
        Some(("request-pin", _)) => handle_request_pin(),
        Some(("get-core-version", _)) => handle_get_core_version(),
        Some(("get-branch", _)) => handle_get_branch(),
        Some(("get-last-reported-secs", _)) => handle_get_last_reported_secs(),
        Some(("interactive", _)) => interactive_mode(),
        Some(("test", _)) => handle_test(),
        Some(("start", sub_matches)) => {
            let user = sub_matches.get_one::<String>("USER").unwrap().to_string();
            let domain = sub_matches.get_one::<String>("DOMAIN").unwrap().to_string();
            let pin = sub_matches.get_one::<String>("PIN").unwrap().to_string();
            start_background_process(user, domain, pin);
        }
        Some(("stop", _)) => stop_background_process(),
        _ => warn!("Invalid command, use --help for more information"),
    }
}

fn interactive_mode() {
    info!(">>>> Entering interactive mode. Type 'exit' to leave.");
    let stdin = io::stdin();
    let mut reader = stdin.lock();
    let mut line = String::new();

    loop {
        line.clear();
        print!("> ");
        io::stdout().flush().unwrap();
        reader.read_line(&mut line).unwrap();

        let trimmed = line.trim();
        if trimmed == "exit" {
            break;
        }

        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }

        let command = parts[0];
        let args: Vec<String> = parts[1..].iter().map(|&s| s.to_string()).collect();

        info!(">>>> Command: {}", command);
        
        match command {
            "score" => handle_score(),
            "get-connection" => handle_get_connection(),
            "get-core-info" => handle_get_core_info(),
            "set-credentials" => {
                if args.len() == 3 {
                    handle_set_credentials(args[0].clone(), args[1].clone(), args[2].clone());
                } else {
                    warn!(">>>> Three arguments are required for set-credentials command");
                }
            }
            "connect-domain" => handle_connect_domain(),
            "disconnect-domain" => handle_disconnect_domain(),
            "request-pin" => handle_request_pin(),
            "get-core-version" => handle_get_core_version(),
            "get-branch" => handle_get_branch(),
            "get-last-reported-secs" => handle_get_last_reported_secs(),
            "start" => {
                if args.len() == 3 {
                    start_background_process(args[0].clone(), args[1].clone(), args[2].clone());
                } else {
                    warn!(">>>> Three arguments are required for start command");
                }
            }
            "stop" => stop_background_process(),
            _ => warn!(">>>> Invalid command"),
        }
    }
}

fn handle_test() {
    handle_get_core_version();

    handle_get_core_info();

    handle_get_branch();

    handle_set_credentials(
        "test".to_string(),
        "edamame.tech".to_string(),
        "1234567".to_string(),
    );

    handle_connect_domain();

    handle_get_last_reported_secs();

    handle_disconnect_domain();

    handle_get_last_reported_secs();

    handle_score();
}

fn start_background_process(user: String, domain: String, pin: String) {

    let child = ProcessCommand::new(std::env::current_exe().unwrap())
        .arg("background-process")
        .arg(user)
        .arg(domain)
        .arg(pin)
        .spawn()
        .expect("Failed to start background process");

    info!("Background process started with PID: {}", child.id());
}

fn stop_background_process() {
    let state = State::load();
    if let Some(pid) = state.pid {
        if pid_exists(pid) {
            info!("Stopping background process with PID: {}", pid);
            let _ = ProcessCommand::new("kill").arg(pid.to_string()).status();
            State::clear();
        } else {
            warn!("No background process found with PID: {}", pid);
        }
    } else {
        warn!("No background process is running.");
    }
}

// Background process function
fn background_process(user: String, domain: String, pin: String) {
    handle_set_credentials(user, domain, pin);
    handle_connect_domain();

    loop {
        thread::sleep(Duration::from_secs(60));
    }
}

// Only macOS
#[cfg(target_os = "macos")]
#[no_mangle]
pub extern "C" fn rust_main() {
    run();
}

#[cfg(not(target_os = "macos"))]
pub fn main() {
    setup_logging();
    run();
}

