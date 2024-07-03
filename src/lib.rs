use clap::{arg, Command};
use log::{info, warn};
use std::io::{self, BufRead, Write};
use std::thread::sleep;
use std::time::Duration;

use edamame_core::api::api_core::*;
use edamame_core::api::api_score::*;

fn handle_score() {
    info!(">>>> Score functionality executed");
    let _ = get_score(true);

    sleep(Duration::from_secs(5));

    let mut score = get_score(false);
    while score.compute_in_progress {
        info!(">>>> Score: {:?}", score.stars);
        sleep(Duration::from_secs(5));
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

    initialize("cli".to_string(), "EN".to_string(), device);

    let matches = Command::new("edamame_cli")
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
        .subcommand(
            Command::new("set-auto-scan")
                .about("Set auto scan mode")
                .arg(arg!(<MODE> "true or false").required(true)),
        )
        .subcommand(Command::new("interactive").about("Enter interactive mode"))
        .subcommand(Command::new("test").about("Run a sequence of test commands"))
        .get_matches();

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

// Only macOS
#[cfg(target_os = "macos")]
#[no_mangle]
pub extern "C" fn rust_main() {
    run();
}

#[cfg(not(target_os = "macos"))]
pub fn main() {
    run();
}
