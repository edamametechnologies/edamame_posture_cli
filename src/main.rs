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
use std::thread;
use std::time::Duration;
use sysinfo::{Disks, Networks, Pid, System};
use tracing::{error, info};
#[cfg(windows)]
use windows::Win32::System::Threading as WinThreading;
#[cfg(windows)]
use windows::core::{
    PCWSTR,
    PWSTR,
};
#[cfg(windows)]
use windows::Win32::Foundation::{
    HANDLE,
    CloseHandle,
};
#[cfg(windows)]
use windows::Win32::System::Threading::*;
#[cfg(windows)]
use widestring::U16CString;

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
        println!("Loading state from {}", path.display());
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
        println!("Saving state to {}", path.display());
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
        print!(".");
        thread::sleep(Duration::from_millis(100));
        score = get_score(false);
    }
    // Make sure we have the final score
    score = get_score(true);
    // Pretty print the final score with important details
    println!("Threat model version: {}", score.model_name);
    println!("Threat model date: {}", score.model_date);
    println!("Threat model signature: {}", score.model_signature);
    println!("Score computed at: {}", score.last_compute);
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

fn display_logs() {
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

fn handle_wait_for_success(timeout: u64) {
    // Read the state and wait until a network activity is detected and the connection is successful
    let mut state = State::load();

    handle_get_device_info();

    handle_get_system_info();

    let mut timeout = timeout;
    while !(state.is_success && state.last_network_activity != "") && timeout > 0 {
        println!("Wait for score computation and reporting to complete... (success: {}, network activity: {})", state.is_success, state.last_network_activity);
        thread::sleep(Duration::from_secs(5));
        timeout = timeout - 5;
        state = State::load();
    }

    // Print the score
    handle_score();

    if timeout <= 0 {
        eprintln!(
            "Timeout waiting for background process to connect to domain, killing process..."
        );
        stop_background_process();

        display_logs();

        // Exit with an error code
        std::process::exit(1);
    } else {
        display_logs();

        println!(
            "Connection successful with domain {} and user {} (success: {}, network activity: {}), pausing for 60 seconds to ensure access control is applied...",
            state.connected_domain,
            state.connected_user,
            state.is_success,
            state.last_network_activity
        );
        thread::sleep(Duration::from_secs(60));
    }
}

fn handle_get_core_info() {
    let core_info = get_core_info();
    println!("Core information: {}", core_info);
}

fn handle_get_device_info() {
    let device_info = get_device_info();
    println!("Device information:");
    println!("  - Device ID: {}", device_info.device_id);
    println!("  - Model: {}", device_info.model);
    println!("  - Brand: {}", device_info.brand);
    println!("  - OS Name: {}", device_info.os_name);
    println!("  - OS Version: {}", device_info.os_version);
    println!("  - IPv4: {}", device_info.ip4);
    println!("  - IPv6: {}", device_info.ip6);
    println!("  - MAC: {}", device_info.mac);
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
    let mut device = DeviceInfoAPI {
        device_id: "".to_string(),
        model: "".to_string(),
        brand: "".to_string(),
        os_name: "".to_string(),
        os_version: "".to_string(),
        ip4: "".to_string(),
        ip6: "".to_string(),
        mac: "".to_string(),
    };

    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 && args[1] == "background-process" {
        // Debug logging
        std::env::set_var("EDAMAME_LOG_LEVEL", "debug");

        if args.len() == 6 {
            // Save state
            let state = State {
                pid: Some(std::process::id()),
                is_success: false,
                connected_domain: args[3].clone(),
                connected_user: args[2].clone(),
                last_network_activity: "".to_string(),
            };
            state.save();

            // Set device ID
            // Prefix it with the machine uid
            let machine_uid = machine_uid::get().unwrap_or("".to_string());
            device.device_id =
                (machine_uid + "/" + args[5].clone().to_string().as_str()).to_string();

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

            background_process(args[2].clone(), args[3].clone(), args[4].clone());
        } else {
            eprintln!("Invalid arguments for background process: {:?}", args);
            // Exit with an error code
            std::process::exit(1);
        }
    } else {
        // Reporting and community are off
        initialize(
            // Use "cli-debug" to show the logs to the user, "cli" otherwise
            "cli".to_string(),
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
        .subcommand(Command::new("get-device-info").about("Get device information"))
        .subcommand(Command::new("get-threats-info").about("Get threats information"))
        .subcommand(Command::new("get-system-info").about("Get system information"))
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
                .arg(arg!(<PIN> "PIN").required(true))
                .arg(arg!(<DEVICE_ID> "Device ID").required(false)),
        )
        .subcommand(Command::new("stop").about("Stop reporting background process"))
        .subcommand(Command::new("status").about("Get status of reporting background process"))
        .get_matches();

    match matches.subcommand() {
        Some(("score", _)) => handle_score(),
        Some(("wait-for-success", sub_matches)) => {
            let timeout = sub_matches
                .get_one::<u64>("TIMEOUT")
                .unwrap_or_else(|| &180);
            handle_wait_for_success(*timeout)
        }
        Some(("get-core-info", _)) => handle_get_core_info(),
        Some(("get-device-info", _)) => handle_get_device_info(),
        Some(("get-threats-info", _)) => handle_get_threats_info(),
        Some(("get-system-info", _)) => handle_get_system_info(),
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
            // If no device ID is provided, use an empty string to trigger detection
            let device_id = sub_matches
                .get_one::<String>("DEVICE_ID")
                .unwrap_or(&"".to_string())
                .to_string();
            start_background_process(user, domain, pin, device_id);
        }
        Some(("stop", _)) => stop_background_process(),
        Some(("status", _)) => show_background_process_status(),
        _ => error!("Invalid command, use --help for more information"),
    }
}

fn start_background_process(user: String, domain: String, pin: String, device_id: String) {
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
                        .arg(&device_id)
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
        let exe = std::env::current_exe().expect("Failed to get current executable path").display().to_string();
        // Format the command line string, quoting the executable path if it contains spaces
        let cmd = format!("{} background-process {} {} {} {}", exe, user, domain, pin, device_id);

        let creation_flags = CREATE_UNICODE_ENVIRONMENT | DETACHED_PROCESS;
        let mut process_information = PROCESS_INFORMATION::default();
        let startup_info : WinThreading::STARTUPINFOW = WinThreading::STARTUPINFOW{
            cb: u32::try_from(std::mem::size_of::<WinThreading::STARTUPINFOW>()).unwrap(),
            lpReserved: PWSTR::null(),
            lpDesktop: PWSTR::null(),
            lpTitle: PWSTR::null(),
            dwX: 0,
            dwY: 0,
            dwXSize: 0,
            dwYSize: 0,
            dwXCountChars: 0,
            dwYCountChars: 0,
            dwFillAttribute: 0,
            dwFlags: WinThreading::STARTUPINFOW_FLAGS(0),
            wShowWindow: 0,
            cbReserved2: 0,
            lpReserved2: std::ptr::null_mut(),
            hStdInput: HANDLE::default(),
            hStdOutput: HANDLE::default(),
            hStdError: HANDLE::default(),
        };

        let mut cmd = U16CString::from_str(cmd).unwrap();
        let cmd_pwstr = PWSTR::from_raw(cmd.as_mut_ptr());

        let success = unsafe{ WinThreading::CreateProcessW(
            PCWSTR::null(),
            cmd_pwstr,
            None,
            None,
            false,
            creation_flags,
            None,
            PCWSTR::null(),
            &startup_info,
            &mut process_information
        )}.as_bool();

        if !success {
            eprintln!("Failed to create background process");
            std::process::exit(1);
        } else {
            println!("Background process ({}) launched", process_information.dwProcessId);

            unsafe {
                CloseHandle(process_information.hProcess);
                CloseHandle(process_information.hThread);
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

fn handle_get_system_info() {
    let mut sys = System::new_all();
    sys.refresh_all();
    sysinfo::set_open_files_limit(0);

    println!("System information:");
    // RAM and swap information
    println!("  - Total memory: {} bytes", sys.total_memory());
    println!("  - Used memory : {} bytes", sys.used_memory());
    println!("  - Total swap  : {} bytes", sys.total_swap());
    println!("  - Used swap   : {} bytes", sys.used_swap());

    // Display system information
    println!("  - System name:             {:?}", System::name());
    println!(
        "  - System kernel version:   {:?}",
        System::kernel_version()
    );
    println!("  - System OS version:       {:?}", System::os_version());
    println!("  - System host name:        {:?}", System::host_name());

    // Number of CPUs
    println!("NB CPUs: {}", sys.cpus().len());

    // We display all disks' information
    println!("Disks:");
    let disks = Disks::new_with_refreshed_list();
    for disk in &disks {
        println!("  - {disk:?}");
    }

    // Network interfaces name
    let networks = Networks::new_with_refreshed_list();
    println!("Networks:");
    for (interface_name, _data) in &networks {
        println!("  - {interface_name}",);
    }

    // Platform-specific information
    #[cfg(target_os = "macos")]
    {
        use std::process::Command;

        let output = Command::new("system_profiler")
            .arg("SPHardwareDataType")
            .output()
            .expect("Failed to execute command");

        println!("macOS specific information:");
        println!("System profiler hardware data:");
        println!("{}", String::from_utf8_lossy(&output.stdout));
    }

    #[cfg(target_os = "linux")]
    {
        use std::fs;

        let cpuinfo = fs::read_to_string("/proc/cpuinfo").expect("Failed to read /proc/cpuinfo");

        println!("Linux specific information:");
        println!("CPU information from /proc/cpuinfo:");
        println!("{}", cpuinfo);
    }

    #[cfg(target_os = "windows")]
    {
        use std::process::Command;

        let output = Command::new("powershell")
            .arg("-Command")
            .arg("Get-WmiObject -Class Win32_ComputerSystem | Select-Object -Property Model")
            .output()
            .expect("Failed to execute command");

        println!("Windows specific information:");
        println!("Computer system model from WMI:");
        println!("{}", String::from_utf8_lossy(&output.stdout));
    }
}

fn background_process(user: String, domain: String, pin: String) {

    // We are using the logger as we are in the background process
    info!("Forcing update of threats...");
    // Update threats
    update_threats();

    // Show threats info
    let threats = get_threats_info();
    info!("Threats information: {}", threats);

    // Set credentials
    info!("Setting credentials for user: {}, domain: {}", user, domain);
    set_credentials(user, domain, pin);

    // Request immediate score computation
    info!("Requesting immediate score computation...");
    let _ = get_score(true);

    // Connect domain
    info!("Connecting to domain...");
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
