use crate::background::background_display_sessions;
use crate::EDAMAME_CA_PEM;
use crate::EDAMAME_CLIENT_KEY;
use crate::EDAMAME_CLIENT_PEM;
use crate::EDAMAME_TARGET;
use crate::{
    base_get_core_info, base_get_core_version, base_lanscan, connect_domain, ERROR_CODE_MISMATCH,
    ERROR_CODE_PARAM,
};
use edamame_core::api::api_core::*;
use edamame_core::api::api_flodbadd::*;
use edamame_core::api::api_score::*;
use edamame_core::api::api_trust::*;
use std::env;
use std::thread::sleep;
use std::time::Duration;
use tracing::{error, info, warn};

pub fn background_process(
    user: String,
    domain: String,
    pin: String,
    lan_scanning: bool,
    packet_capture: bool,
    whitelist_name: String,
    fail_on_whitelist: bool,
    fail_on_blacklist: bool,
    fail_on_anomalous: bool,
    cancel_on_violation: bool,
    local_traffic: bool,
    agentic_mode: String,
    agentic_provider: Option<String>,
    agentic_interval: u64,
) {
    let whitelist_display = if whitelist_name.is_empty() {
        "<none>"
    } else {
        whitelist_name.as_str()
    };

    info!(
        "Starting background process with user: {}, domain: {}, lan_scanning: {}, packet_capture: {}, whitelist: {}, fail_on_whitelist: {}, fail_on_blacklist: {}, fail_on_anomalous: {}, local_traffic: {}",
        user, domain, lan_scanning, packet_capture, whitelist_display, fail_on_whitelist, fail_on_blacklist, fail_on_anomalous, local_traffic
    );

    if fail_on_whitelist && whitelist_name.is_empty() {
        error!(
            "Whitelist fail handling requires a whitelist name. Provide --whitelist <NAME> when enabling --fail-on-whitelist."
        );
        std::process::exit(ERROR_CODE_PARAM);
    }

    info!(
        "Session check settings -> whitelist: {}, blacklist: {}, anomalous: {}, cancel_on_violation: {}",
        fail_on_whitelist, fail_on_blacklist, fail_on_anomalous, cancel_on_violation
    );

    // We are using the logger as we are in the background process

    // Show threats info (call core directly to avoid local RPC chatter)
    let score = get_score(false);
    println!(
        "Threat model name: {}, date: {}, signature: {}",
        score.model_name, score.model_date, score.model_signature
    );

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

    if lan_scanning || packet_capture {
        // Grant consent when either capability is required
        grant_consent();
    }

    if packet_capture {
        if whitelist_name.is_empty() {
            info!("Packet capture enabled without whitelist enforcement.");
        } else {
            set_whitelist(whitelist_name.clone());
        }
        set_filter(if local_traffic {
            SessionFilterAPI::All
        } else {
            SessionFilterAPI::GlobalOnly
        });
        start_capture();
    } else {
        info!("Packet capture disabled. Skipping capture initialization.");
    }

    // Scan the network interfaces
    if lan_scanning {
        info!("Scanning network interfaces...");

        if packet_capture {
            // Wait for the gateway detection to complete
            let mut last_gateway_scan = get_last_gateway_scan();
            while last_gateway_scan.is_empty() {
                info!("Waiting for gateway detection to complete...");
                sleep(Duration::from_secs(5));
                last_gateway_scan = get_last_gateway_scan();
            }

            info!("Gateway detection complete, requesting a LAN scan...");
        } else {
            info!("Packet capture disabled; requesting LAN scan without waiting for gateway detection.");
        }

        // Request a LAN scan
        _ = get_lanscan(true, false, false);

        // Wait for the scan to complete
        base_lanscan();
    }

    info!("LAN scan complete, starting connection status loop");

    // Connect domain
    info!("Connecting to domain...");
    connect_domain();

    // Request a score computation
    compute_score();

    // Configure agentic AI if enabled
    let agentic_enabled = agentic_mode != "disabled";
    if agentic_enabled {
        info!(
            "AI Assistant enabled: mode={}, provider={:?}, interval={}s",
            agentic_mode, agentic_provider, agentic_interval
        );

        // Set LLM configuration if provider specified
        if let Some(provider) = &agentic_provider {
            crate::background_configure_agentic(provider.clone());
        }
    }

    if !crate::background_set_agentic_loop(agentic_enabled, agentic_interval, &agentic_mode) {
        warn!("Failed to configure AI Assistant background loop");
    }

    // Initial processing of todos if agentic mode enabled
    if agentic_enabled {
        info!("AI Assistant: Processing security todos...");
        crate::background_process_agentic(&agentic_mode);
    }

    // Loop forever as background process is running
    let mut violation_check_counter = 0u64;
    const VIOLATION_CHECK_INTERVAL: u64 = 10; // seconds (reduced from 30 for faster response)
    loop {
        // Sleep for 5 seconds
        sleep(Duration::from_secs(5));
        violation_check_counter += 5;

        if cancel_on_violation && violation_check_counter >= VIOLATION_CHECK_INTERVAL {
            violation_check_counter = 0;
            match collect_policy_violations(
                fail_on_whitelist,
                fail_on_blacklist,
                fail_on_anomalous,
                local_traffic,
            ) {
                Ok(violating_sessions) => {
                    if !violating_sessions.is_empty() {
                        println!("\n=== Violating Sessions Detected ===");
                        background_display_sessions(
                            violating_sessions,
                            false,
                            local_traffic,
                            false,
                        );
                        println!(
                            "Policy violations detected by background daemon. Attempting to cancel CI pipeline..."
                        );
                        if let Err(e) = halt_ci_pipeline(
                            "edamame_posture background daemon detected policy violations",
                        ) {
                            eprintln!("Failed to cancel pipeline: {}", e);
                        }
                        std::process::exit(ERROR_CODE_MISMATCH);
                    }
                }
                Err(e) => {
                    eprintln!("Error checking policy violations: {}", e);
                }
            }
        }
    }
}

fn collect_policy_violations(
    fail_on_whitelist: bool,
    fail_on_blacklist: bool,
    fail_on_anomalous: bool,
    include_local_traffic: bool,
) -> Result<Vec<SessionInfoAPI>, String> {
    let mut violating_sessions: Vec<SessionInfoAPI> = Vec::new();

    if fail_on_whitelist {
        let conforms = rpc_get_whitelist_conformance(
            &EDAMAME_CA_PEM,
            &EDAMAME_CLIENT_PEM,
            &EDAMAME_CLIENT_KEY,
            &EDAMAME_TARGET,
        )
        .map_err(|e| format!("Error getting whitelist conformance: {}", e))?;

        if !conforms {
            let mut sessions = rpc_get_lan_sessions(
                true,
                &EDAMAME_CA_PEM,
                &EDAMAME_CLIENT_PEM,
                &EDAMAME_CLIENT_KEY,
                &EDAMAME_TARGET,
            )
            .map_err(|e| format!("Error retrieving LAN sessions: {}", e))?
            .sessions;

            if !include_local_traffic {
                sessions = filter_global_sessions(sessions);
            }

            let non_conforming: Vec<SessionInfoAPI> = sessions
                .into_iter()
                .filter(|session| session.is_whitelisted != WhiteListStateAPI::Conforming)
                .collect();

            violating_sessions.extend(non_conforming);
        }
    }

    if fail_on_blacklist {
        let mut blacklisted = rpc_get_blacklisted_sessions(
            &EDAMAME_CA_PEM,
            &EDAMAME_CLIENT_PEM,
            &EDAMAME_CLIENT_KEY,
            &EDAMAME_TARGET,
        )
        .map_err(|e| format!("Error retrieving blacklisted sessions: {}", e))?;

        if !blacklisted.is_empty() {
            if !include_local_traffic {
                blacklisted = filter_global_sessions(blacklisted);
            }
            violating_sessions.extend(blacklisted);
        }
    }

    if fail_on_anomalous {
        let mut anomalous = rpc_get_anomalous_sessions(
            &EDAMAME_CA_PEM,
            &EDAMAME_CLIENT_PEM,
            &EDAMAME_CLIENT_KEY,
            &EDAMAME_TARGET,
        )
        .map_err(|e| format!("Error retrieving anomalous sessions: {}", e))?;

        if !anomalous.is_empty() {
            if !include_local_traffic {
                anomalous = filter_global_sessions(anomalous);
            }
            violating_sessions.extend(anomalous);
        }
    }

    Ok(violating_sessions)
}

fn halt_ci_pipeline(reason: &str) -> Result<(), String> {
    // Check for custom cancellation script first (most secure - no token passing to daemon)
    // The script is created by the CI action and has access to original environment including tokens
    let cancel_script_path = if let Ok(custom_path) = env::var("EDAMAME_CANCEL_PIPELINE_SCRIPT") {
        custom_path
    } else {
        // Default to $HOME/cancel_pipeline.sh
        let home = env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        format!("{}/cancel_pipeline.sh", home)
    };

    // Try external script first if it exists
    if std::path::Path::new(&cancel_script_path).exists() {
        info!(
            "Using external cancellation script: {} (reason: {})",
            cancel_script_path, reason
        );

        let status = std::process::Command::new("bash")
            .arg(&cancel_script_path)
            .arg(reason)
            .status()
            .map_err(|e| format!("Failed to execute cancellation script: {}", e))?;

        if status.success() {
            info!("Pipeline cancelled successfully via script");
            return Ok(());
        } else {
            return Err(format!(
                "Cancellation script failed (exit code = {:?})",
                status.code()
            ));
        }
    }

    // Fallback to built-in cancellation logic
    info!(
        "No cancellation script found at {}, using built-in logic",
        cancel_script_path
    );

    if env::var("GITHUB_ACTIONS").is_ok() {
        let run_id = env::var("GITHUB_RUN_ID")
            .map_err(|_| "GITHUB_RUN_ID environment variable not set".to_string())?;
        let repo = env::var("GITHUB_REPOSITORY")
            .map_err(|_| "GITHUB_REPOSITORY environment variable not set".to_string())?;

        info!(
            "Attempting to cancel GitHub Actions run {} for repo {} (reason: {})",
            run_id, repo, reason
        );

        // Check for GitHub token from file first (more secure), then environment variable
        let gh_token = if let Ok(token_file) = env::var("GH_TOKEN_FILE") {
            match std::fs::read_to_string(&token_file) {
                Ok(token) => {
                    info!("Using GitHub token from secure file: {}", token_file);
                    Some(token.trim().to_string())
                }
                Err(e) => {
                    warn!("GH_TOKEN_FILE specified but couldn't read file: {}", e);
                    env::var("GH_TOKEN").ok()
                }
            }
        } else {
            env::var("GH_TOKEN").ok()
        };

        let mut cmd = std::process::Command::new("gh");
        cmd.args(["run", "cancel", &run_id, "--repo", &repo]);

        // Set GH_TOKEN environment variable for gh CLI if we found a token
        if let Some(token) = gh_token {
            cmd.env("GH_TOKEN", token);
        } else {
            warn!("No GitHub token found (GH_TOKEN_FILE or GH_TOKEN). Cancellation may fail if authentication is required.");
        }

        let status = cmd
            .status()
            .map_err(|e| format!("Failed to execute 'gh' command: {}", e))?;

        if status.success() {
            info!("GitHub Actions run cancelled successfully");
        } else {
            return Err(format!(
                "Failed to cancel GitHub Actions run (exit code = {:?})",
                status.code()
            ));
        }
    } else if env::var("GITLAB_CI").is_ok() {
        let project_id = env::var("CI_PROJECT_ID")
            .map_err(|_| "CI_PROJECT_ID environment variable not set".to_string())?;
        let pipeline_id = env::var("CI_PIPELINE_ID")
            .map_err(|_| "CI_PIPELINE_ID environment variable not set".to_string())?;
        let token = env::var("GITLAB_TOKEN")
            .map_err(|_| "GITLAB_TOKEN environment variable not set".to_string())?;

        info!(
            "Attempting to cancel GitLab pipeline {} for project {} (reason: {})",
            pipeline_id, project_id, reason
        );

        let url = format!(
            "https://gitlab.com/api/v4/projects/{}/pipelines/{}/cancel",
            project_id, pipeline_id
        );

        let status = std::process::Command::new("curl")
            .args([
                "-s",
                "-X",
                "POST",
                "-H",
                &format!("PRIVATE-TOKEN: {}", token),
                &url,
            ])
            .status()
            .map_err(|e| format!("Failed to execute 'curl' command: {}", e))?;

        if status.success() {
            info!("GitLab pipeline cancelled successfully");
        } else {
            return Err(format!(
                "Failed to cancel GitLab pipeline (exit code = {:?})",
                status.code()
            ));
        }
    } else {
        info!(
            "Pipeline cancellation requested (reason: {}), but no supported CI environment detected.",
            reason
        );
    }

    Ok(())
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
    packet_capture: bool,
    whitelist_name: String,
    fail_on_whitelist: bool,
    fail_on_blacklist: bool,
    fail_on_anomalous: bool,
    cancel_on_violation: bool,
    local_traffic: bool,
    agentic_mode: String,
    agentic_provider: Option<String>,
    agentic_interval: u64,
) {
    if fail_on_whitelist && whitelist_name.is_empty() {
        eprintln!(
            "Whitelist checks require a whitelist name. Provide --whitelist <NAME> when enabling --check-whitelist."
        );
        std::process::exit(ERROR_CODE_PARAM);
    }

    // Show core version
    base_get_core_version();

    // Show core info
    base_get_core_info();

    // Check if the background process is already running
    if is_background_process_running() {
        eprintln!("Core services are already running.");
        std::process::exit(1);
    }

    let whitelist_display = if whitelist_name.is_empty() {
        "<none>"
    } else {
        whitelist_name.as_str()
    };

    println!("Starting background process with provided parameters, user: {}, domain: {}, device_id: {}, lan_scanning: {}, packet_capture: {}, whitelist_name: {}, fail_on_whitelist: {}, fail_on_blacklist: {}, fail_on_anomalous: {}, cancel_on_violation: {}, local_traffic: {}, agentic_mode: {}, agentic_interval: {}s", 
             user, domain, device_id, lan_scanning, packet_capture, whitelist_display, fail_on_whitelist, fail_on_blacklist, fail_on_anomalous, cancel_on_violation, local_traffic, agentic_mode, agentic_interval);

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
                    .arg(&packet_capture.to_string())
                    .arg(&whitelist_name)
                    .arg(&fail_on_whitelist.to_string())
                    .arg(&fail_on_blacklist.to_string())
                    .arg(&fail_on_anomalous.to_string())
                    .arg(&cancel_on_violation.to_string())
                    .arg(&local_traffic.to_string())
                    .arg(&agentic_mode)
                    .arg(agentic_provider.as_deref().unwrap_or("none"))
                    .arg(&agentic_interval.to_string())
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
        // Must match the 15-arg format expected by background-process handler
        let cmd = format!(
            "\"{}\" background-process \"{}\" \"{}\" \"{}\" \"{}\" {} {} \"{}\" {} {} {} {} {} \"{}\" \"{}\" {}",
            exe,
            user,
            domain,
            pin,
            device_id,
            lan_scanning.to_string(),
            packet_capture.to_string(),
            whitelist_name,
            fail_on_whitelist.to_string(),
            fail_on_blacklist.to_string(),
            fail_on_anomalous.to_string(),
            cancel_on_violation.to_string(),
            local_traffic.to_string(),
            agentic_mode,
            agentic_provider.as_deref().unwrap_or("none"),
            agentic_interval.to_string()
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
