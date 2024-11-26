use crate::commands::process_get_threats_info;
use crate::EDAMAME_CA_PEM;
use crate::EDAMAME_CLIENT_KEY;
use crate::EDAMAME_CLIENT_PEM;
use crate::EDAMAME_TARGET;
use crate::{connect_domain, process_get_core_info, process_get_core_version, process_lanscan};
#[cfg(unix)]
use daemonize::Daemonize;
use edamame_core::api::api_core::*;
use edamame_core::api::api_lanscan::*;
use edamame_core::api::api_score::*;
use std::thread::sleep;
use std::time::Duration;
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

    // Show threats info
    process_get_threats_info();

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
        process_lanscan();
    }

    info!("LAN scan complete, starting connection status loop");

    // Connect domain
    info!("Connecting to domain...");
    connect_domain();

    // Force score computation
    compute_score();

    // Loop forever as background process is running
    loop {
        // Sleep for 5 seconds
        sleep(Duration::from_secs(5));
    }
}

pub fn is_background_process_running() -> bool {
    match rpc_get_core_info(
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(_) => true,
        Err(_) => false,
    }
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
    process_get_core_version();

    // Show core info
    process_get_core_info();

    // Check if the background process is already running
    if is_background_process_running() {
        eprintln!("Background process already running.");
        std::process::exit(1);
    }

    println!("Starting background process...");

    #[cfg(unix)]
    {
        use std::process::Command;

        let daemonize = Daemonize::new()
            .pid_file("/tmp/edamame_posture.pid")
            .chown_pid_file(true)
            .working_directory("/tmp");

        match daemonize.start() {
            Ok(_) => {
                // We can't launch the background loop directly as the double fork will break the tokio runtime
                // So we need to fork a new process but make sure it's tied to this one
                // Otherwise it will go defunct when terminated
                // So we don't use spawn() but output() here
                let _ = Command::new(std::env::current_exe().unwrap())
                    .arg("background-process")
                    .arg(&user)
                    .arg(&domain)
                    .arg(&pin)
                    .arg(&device_id)
                    .arg(&lan_scanning.to_string())
                    .arg(&whitelist_name)
                    .arg(&local_traffic.to_string())
                    .output()
                    .expect("Failed to start background process");
                std::process::exit(0);
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
        // Format the command line string, we must quote all strings
        let cmd = format!(
            "\"{}\" background-process \"{}\" \"{}\" \"{}\" \"{}\" {} \"{}\" {}",
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

        println!("Command: {}", cmd);

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

pub fn stop_background_process() {
    match rpc_disconnect_domain(
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(_) => match rpc_terminate(
            true,
            &EDAMAME_CA_PEM,
            &EDAMAME_CLIENT_PEM,
            &EDAMAME_CLIENT_KEY,
            &EDAMAME_TARGET,
        ) {
            Ok(_) => (),
            Err(e) => eprintln!("Error terminating background process: {}", e),
        },
        Err(e) => eprintln!("Error disconnecting domain: {}", e),
    }
}
