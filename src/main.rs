use clap::{arg, Command};
use edamame_core::api::api_core::*;
use edamame_core::api::api_score::*;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::process::Command as ProcessCommand;
use std::thread;
use std::time::Duration;
use sysinfo::{Pid, System};
use tracing::error;

#[derive(Serialize, Deserialize, Debug)]
struct State {
    pid: Option<u32>,
}

impl State {
    fn load() -> Self {
        let path = Self::state_file_path();
        if path.exists() {
            let contents = fs::read_to_string(path).expect("Unable to read state file");
            serde_yaml::from_str(&contents).expect("Unable to parse state file")
        } else {
            State { pid: None }
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

fn handle_get_core_info() {
    let core_info = get_core_info();
    println!("Core information: {}", core_info);
}

fn handle_connect_domain() {
    connect_domain();
    println!("Connected to domain");
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
        // Reporting and community are on
        initialize(
            "posture".to_string(),
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
            };
            state.save();

            background_process(args[2].clone(), args[3].clone(), args[4].clone());
        } else {
            eprintln!("Invalid arguments for background process");
        }
    } else {
        // Reporting and community are off
        initialize("cli".to_string(), "EN".to_string(), device, true, true);

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
        .subcommand(Command::new("get-core-info").about("Get core information"))
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
        Some(("get-core-info", _)) => handle_get_core_info(),
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
    let child = ProcessCommand::new(std::env::current_exe().unwrap())
        .arg("background-process")
        .arg(user)
        .arg(domain)
        .arg(pin)
        .spawn()
        .expect("Failed to start background process");

    println!("Background process started with PID: {}", child.id());
}

fn stop_background_process() {
    let state = State::load();
    if let Some(pid) = state.pid {
        if pid_exists(pid) {
            println!("Stopping background process with PID: {}", pid);
            let _ = ProcessCommand::new("kill").arg(pid.to_string()).status();
            State::clear();

            // Disconnect domain
            disconnect_domain();
        } else {
            eprintln!("No background process found with PID: {}", pid);
        }
    } else {
        eprintln!("No background process is running.");
    }
}

fn show_background_process_status() {
    let state = State::load();
    if let Some(pid) = state.pid {
        if pid_exists(pid) {
            println!("Background process running with PID: {}", pid);
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
            eprintln!("Background process not found with PID: {}", pid);
            State::clear();
        }
    } else {
        println!("No background process is running.");
    }
}

fn background_process(user: String, domain: String, pin: String) {
    // Set credentials
    set_credentials(user, domain, pin);
    // Connect domain
    handle_connect_domain();

    // Request immediate score computation
    let _ = get_score(false);

    // Loop for ever as background process is running
    loop {
        thread::sleep(Duration::from_secs(60));
    }
}

pub fn main() {
    run();
}
