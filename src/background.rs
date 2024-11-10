use crate::commands::handle_get_threats_info;
use crate::{connect_domain, handle_get_core_info, handle_get_core_version, handle_lanscan, State};
#[cfg(unix)]
use daemonize::Daemonize;
use edamame_core::api::api_core::{disconnect_domain, get_connection, set_credentials};
#[cfg(windows)]
use edamame_core::api::api_lanscan::LANScanAPI;
use edamame_core::api::api_lanscan::*;
#[cfg(windows)]
use edamame_core::api::api_score::ScoreAPI;
use edamame_core::api::api_score::{compute_score, get_score};
use std::io;
use std::io::Write;
#[cfg(unix)]
use std::process::Command as ProcessCommand;
use std::thread::sleep;
use std::time::Duration;
use sysinfo::{Pid, System};
use tracing::info;
#[cfg(windows)]
use widestring::U16CString;
#[cfg(windows)]
use windows::core::{PCWSTR, PWSTR};
#[cfg(windows)]
use windows::Win32::Foundation::{CloseHandle, HANDLE};
#[cfg(windows)]
use windows::Win32::System::Threading::*;

pub fn background_process(
    user: String,
    domain: String,
    pin: String,
    lan_scanning: bool,
    whitelist_name: String,
    local_traffic: bool,
) {
    info!(
        "Starting background process with user: {}, domain: {}, lan_scanning: {}, local_traffic: {}",
        user, domain, lan_scanning, local_traffic
    );

    // We are using the logger as we are in the background process

    // Load the state to get the current PID/handle
    let mut state = State::load();

    // Show threats info
    handle_get_threats_info();

    // Set credentials
    info!("Setting credentials for user: {}, domain: {}", user, domain);
    set_credentials(user, domain, pin);

    // Scan the network interfaces
    if lan_scanning {
        info!("Scanning network interfaces...");

        // Start capture
        set_whitelist(whitelist_name.clone());
        set_filter(if local_traffic {
            SessionFilterAPI::All
        } else {
            SessionFilterAPI::GlobalOnly
        });
        start_capture();

        // Initialize network to autodetect
        set_network(LANScanAPINetwork {
            interfaces: vec![],
            scanned_interfaces: vec![],
            is_ethernet: true,
            is_wifi: false,
            is_vpn: false,
            is_tethering: false,
            is_mobile: false,
            wifi_bssid: "".to_string(),
            wifi_ip: "".to_string(),
            wifi_submask: "".to_string(),
            wifi_gateway: "".to_string(),
            wifi_broadcast: "".to_string(),
            wifi_name: "".to_string(),
            wifi_ipv6: "".to_string(),
            // Must be in RFC3339 format, set to EPOCH
            last_seen: "1970-01-01T00:00:00Z".to_string(),
            last_name: "".to_string(),
        });

        // Grant consent
        grant_consent();

        // Wait for the gateway detection to complete
        let mut last_gateway_scan = get_last_gateway_scan();
        while last_gateway_scan == "" {
            info!("Waiting for gateway detection to complete...");
            sleep(Duration::from_secs(5));
            last_gateway_scan = get_last_gateway_scan();
        }

        info!("Gateway detection complete, requesting a LAN scan...");

        // Request a LAN scan
        _ = get_lan_devices(true, false, false);

        // Wait for the scan to complete
        handle_lanscan();
    }

    info!("LAN scan complete, starting connection status loop");

    // Connect domain
    info!("Connecting to domain...");
    connect_domain();

    // Force score computation
    compute_score();

    // Loop forever as background process is running, write the shared state based on the connection status
    loop {
        let connection_status = get_connection();
        state.devices = get_lan_devices(false, false, false);
        state.sessions = get_sessions();
        state.score = get_score(true);
        state.whitelist_conformance = get_whitelist_conformance();
        state.connected_user = connection_status.connected_user;
        state.connected_domain = connection_status.connected_domain;
        state.is_connected = connection_status.is_success;
        state.whitelist_name = whitelist_name.clone();
        state.last_network_activity = connection_status.last_network_activity;
        state.is_outdated_backend = connection_status.is_outdated_backend;
        state.is_outdated_threats = connection_status.is_outdated_threats;
        state.backend_error_code = connection_status.backend_error_code;
        // Load the state to detect exit conditions set by posture
        let current_state = State::load();
        state.pid = current_state.pid;
        state.handle = current_state.handle;
        // Save the state
        state.save();

        // Exit if there are no pid/handle anymore
        #[cfg(unix)]
        if state.pid.is_none() {
            std::process::exit(0);
        }

        #[cfg(windows)]
        if state.handle.is_none() {
            std::process::exit(0);
        }

        sleep(Duration::from_secs(5));
    }
}

fn pid_exists(pid: u32) -> bool {
    let mut system = System::new_all();
    system.refresh_all();
    system.process(Pid::from_u32(pid)).is_some()
}

pub fn show_background_process_status() {
    let state = State::load();
    if let Some(pid) = state.pid {
        if pid_exists(pid) {
            println!("Background process running ({})", pid);
            println!("Status:");
            println!("  - User: {}", state.connected_user);
            println!("  - Domain: {}", state.connected_domain);
            println!("  - Connected: {}", state.is_connected);
            println!("  - Last network activity: {}", state.last_network_activity);
            println!("  - Current sessions: {}", state.sessions.len());
            println!("  - Whitelist conformance: {}", state.whitelist_conformance);
            println!("  - Whitelist name: {}", state.whitelist_name);
            println!("  - Outdated backend: {}", state.is_outdated_backend);
            println!("  - Outdated threats: {}", state.is_outdated_threats);
            println!("  - Backend error code: {}", state.backend_error_code);
            // Flush the output
            match io::stdout().flush() {
                Ok(_) => (),
                Err(e) => eprintln!("Error flushing stdout: {}", e),
            }
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

pub fn is_background_process_running() -> bool {
    let state = State::load();
    state.pid.is_some() || state.handle.is_some()
}

pub fn start_background_process(
    user: String,
    domain: String,
    pin: String,
    device_id: String,
    lan_scanning: bool,
    whitelist_name: String,
    local_traffic: bool,
) {
    // Show core version
    handle_get_core_version();

    // Show core info
    handle_get_core_info();

    // Check if the background process is already running
    if is_background_process_running() {
        eprintln!("Background process already running.");
        std::process::exit(1);
    }

    println!("Starting background process...");

    #[cfg(unix)]
    {
        let daemonize = Daemonize::new()
            .pid_file("/tmp/edamame.pid")
            .chown_pid_file(true)
            .working_directory("/tmp");

        match daemonize.start() {
            Ok(_) => {
                let child = ProcessCommand::new(std::env::current_exe().unwrap())
                    .arg("background-process")
                    .arg(&user)
                    .arg(&domain)
                    .arg(&pin)
                    .arg(&device_id)
                    .arg(&lan_scanning.to_string())
                    .arg(&whitelist_name)
                    .arg(&local_traffic.to_string())
                    .spawn()
                    .expect("Failed to start background process");
                println!("Background process ({}) launched", child.id());
            }
            Err(e) => eprintln!("Error daemonizing: {}", e),
        }
    }

    #[cfg(windows)]
    {
        let exe = std::env::current_exe()
            .expect("Failed to get current executable path")
            .display()
            .to_string();
        // Format the command line string, quoting the executable path if it contains spaces
        let cmd = format!(
            "{} background-process {} {} {} {} {} {} {}",
            exe,
            user,
            domain,
            pin,
            device_id,
            lan_scanning.to_string(),
            whitelist_name,
            local_traffic.to_string()
        );

        let creation_flags = CREATE_UNICODE_ENVIRONMENT | DETACHED_PROCESS;
        let mut process_information = PROCESS_INFORMATION::default();
        let startup_info: STARTUPINFOW = STARTUPINFOW {
            cb: u32::try_from(std::mem::size_of::<STARTUPINFOW>()).unwrap(),
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
            dwFlags: STARTUPINFOW_FLAGS(0),
            wShowWindow: 0,
            cbReserved2: 0,
            lpReserved2: std::ptr::null_mut(),
            hStdInput: HANDLE::default(),
            hStdOutput: HANDLE::default(),
            hStdError: HANDLE::default(),
        };

        let mut cmd = U16CString::from_str(cmd).unwrap();
        let cmd_pwstr = PWSTR::from_raw(cmd.as_mut_ptr());

        match unsafe {
            CreateProcessW(
                PCWSTR::null(),
                cmd_pwstr,
                None,
                None,
                false,
                creation_flags,
                None,
                PCWSTR::null(),
                &startup_info,
                &mut process_information,
            )
        } {
            Ok(_) => {
                println!(
                    "Background process ({}) launched",
                    process_information.dwProcessId
                );

                // In order to debug the launched process, uncomment this
                //unsafe { WaitForSingleObject(process_information.hProcess, INFINITE); }
                //let mut exit_code: u32 = 0;
                //unsafe { GetExitCodeProcess(process_information.hProcess, &mut exit_code); }
                //println!("exitcode: {}", exit_code);

                // Save state within the parent for Windows
                let state = State {
                    pid: Some(process_information.dwProcessId),
                    handle: Some(process_information.hProcess.0 as u64),
                    is_connected: false,
                    connected_domain: domain,
                    connected_user: user,
                    last_network_activity: "".to_string(),
                    devices: LANScanAPI::default(),
                    score: ScoreAPI::default(),
                    sessions: vec![],
                    whitelist_name: whitelist_name,
                    whitelist_conformance: true,
                    is_outdated_backend: false,
                    is_outdated_threats: false,
                    backend_error_code: "".to_string(),
                };
                state.save();

                unsafe {
                    CloseHandle(process_information.hProcess).unwrap();
                    CloseHandle(process_information.hThread).unwrap();
                }
            }
            Err(e) => {
                eprintln!("Failed to create background process ({:?})", e);
                std::process::exit(1)
            }
        }
    }
}

#[cfg(unix)]
pub fn stop_background_process() {
    let state = State::load();
    if let Some(pid) = state.pid {
        if pid_exists(pid) {
            println!("Stopping background process ({})", pid);
            // Don't kill, rather stop the child loop
            //let _ = ProcessCommand::new("kill").arg(pid.to_string()).status();
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

#[cfg(windows)]
pub fn stop_background_process() {
    let state = State::load();
    if let Some(_handle) = state.handle {
        println!("Stopping background process ({})", state.handle.unwrap());
        // Don't kill, rather stop the child loop
        //let process_handle = HANDLE(handle.as_mut_ptr());
        //if !process_handle.is_invalid() {
        //  unsafe {
        //      TerminateProcess(process_handle, 1);
        //      CloseHandle(process_handle);
        //  }
        //} else {
        //      eprintln!("Invalid process handle ({})", handle);
        //}
        State::clear();

        sleep(Duration::from_secs(10));

        // Disconnect domain
        disconnect_domain();
    } else {
        eprintln!("No background process is running.");
    }
}
