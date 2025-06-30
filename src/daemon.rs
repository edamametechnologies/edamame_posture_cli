use crate::background::background_get_threats_info;
use crate::EDAMAME_CA_PEM;
use crate::EDAMAME_CLIENT_KEY;
use crate::EDAMAME_CLIENT_PEM;
use crate::EDAMAME_TARGET;
use crate::{base_flodbadd, base_get_core_info, base_get_core_version, connect_domain};
use edamame_core::api::api_core::*;
use edamame_core::api::api_flodbadd::*;
use edamame_core::api::api_score::*;
use edamame_core::api::api_trust::*;
use std::thread::sleep;
use std::time::Duration;
use tracing::info;

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
    background_get_threats_info();

    // Set credentials if not empty, otherwise the core will load saved credentials
    if user != "" && domain != "" {
        info!("Setting credentials for user: {}, domain: {}", user, domain);
        set_credentials(user, domain, pin);
    }

    // Initialize network to autodetect (this will allow the core to detect the network interfaces and support whitelist operations)
    set_network(NetworkAPI {
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

    // Scan the network interfaces
    if lan_scanning {
        info!("Scanning network interfaces...");

        // Grant consent
        grant_consent();

        // Start capture
        set_whitelist(whitelist_name.clone());
        set_filter(if local_traffic {
            SessionFilterAPI::All
        } else {
            SessionFilterAPI::GlobalOnly
        });
        start_capture();

        // Wait for the gateway detection to complete
        let mut last_gateway_scan = get_last_gateway_scan();
        while last_gateway_scan == "" {
            info!("Waiting for gateway detection to complete...");
            sleep(Duration::from_secs(5));
            last_gateway_scan = get_last_gateway_scan();
        }

        info!("Gateway detection complete, requesting a LAN scan...");

        // Request a LAN scan
        _ = get_lanscan(true, false, false);

        // Wait for the scan to complete
        base_flodbadd();
    }

    info!("LAN scan complete, starting connection status loop");

    // Connect domain
    info!("Connecting to domain...");
    connect_domain();

    // Request a score computation
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

pub fn background_start(
    user: String,
    domain: String,
    pin: String,
    device_id: String,
    lan_scanning: bool,
    whitelist_name: String,
    local_traffic: bool,
) {
    // Show core version
    base_get_core_version();

    // Show core info
    base_get_core_info();

    // Check if the background process is already running
    if is_background_process_running() {
        eprintln!("Core services are already running.");
        std::process::exit(1);
    }

    println!("Starting background process with provided parameters, user: {}, domain: {}, device_id: {}, lan_scanning: {}, whitelist_name: {}, local_traffic: {}", user, domain, device_id, lan_scanning, whitelist_name, local_traffic);

    #[cfg(unix)]
    {
        use daemonize::Daemonize;
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
            Err(e) => {
                eprintln!("Error daemonizing: {}", e);
                std::process::exit(1);
            }
        }
    }

    #[cfg(windows)]
    {
        use widestring::U16CString;
        use windows::core::PWSTR;
        use windows::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
        use windows::Win32::System::Threading::{
            CreateProcessW, CREATE_UNICODE_ENVIRONMENT, DETACHED_PROCESS, PROCESS_INFORMATION,
            STARTF_USESTDHANDLES, STARTUPINFOW,
        };

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

        // Add CREATE_NEW_CONSOLE and CREATE_NO_WINDOW flags
        let creation_flags = CREATE_UNICODE_ENVIRONMENT | DETACHED_PROCESS;
        let mut process_information = PROCESS_INFORMATION::default();
        let startup_info = STARTUPINFOW {
            cb: std::mem::size_of::<STARTUPINFOW>() as u32,
            dwFlags: STARTF_USESTDHANDLES,
            hStdInput: INVALID_HANDLE_VALUE,
            hStdOutput: INVALID_HANDLE_VALUE,
            hStdError: INVALID_HANDLE_VALUE,
            ..Default::default()
        };

        println!("Command: {}", cmd);

        let mut cmd = U16CString::from_str(cmd).unwrap();
        let cmd_pwstr = PWSTR::from_raw(cmd.as_mut_ptr());

        match unsafe {
            CreateProcessW(
                PWSTR::null(),            // lpApplicationName
                cmd_pwstr,                // lpCommandLine
                None,                     // lpProcessAttributes
                None,                     // lpThreadAttributes
                false,                    // bInheritHandles
                creation_flags,           // dwCreationFlags
                None,                     // lpEnvironment
                PWSTR::null(),            // lpCurrentDirectory
                &startup_info,            // lpStartupInfo
                &mut process_information, // lpProcessInformation
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
                    let _ = CloseHandle(process_information.hProcess);
                    let _ = CloseHandle(process_information.hThread);
                }
            }
            Err(e) => {
                eprintln!("Failed to create background process ({:?})", e);
                std::process::exit(1)
            }
        }
    }
}
