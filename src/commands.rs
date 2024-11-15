use crate::state::*;
use crate::stop_background_process;
use edamame_core::api::api_core::*;
use edamame_core::api::api_lanscan::*;
use edamame_core::api::api_score::*;
use edamame_core::api::api_score_threats::*;
use indicatif::{ProgressBar, ProgressStyle};
use std::io;
use std::io::Write;
use std::thread::sleep;
use std::time::Duration;
use sysinfo::{Disks, Networks, System};

pub fn handle_wait_for_connection(timeout: u64) {
    handle_get_device_info();

    handle_get_system_info();

    println!("Waiting for score computation and reporting to complete...");
    let mut timeout = timeout;
    // Read the state and wait until a network activity is detected and the connection is successful
    let mut state = load_state();
    while !(state.is_connected && state.last_network_activity != "") && timeout > 0 {
        sleep(Duration::from_secs(5));
        timeout = timeout - 5;
        state = load_state();
        println!("Waiting for score computation and reporting to complete... (connected: {}, network activity: {})", state.is_connected, state.last_network_activity);
    }

    if timeout <= 0 {
        eprintln!(
            "Timeout waiting for background process to connect to domain, killing process..."
        );
        stop_background_process();

        // Exit with an error code
        std::process::exit(1);
    } else {
        println!(
            "Connection successful with domain {} and user {} (connected: {}, network activity: {})",
            state.connected_domain,
            state.connected_user,
            state.is_connected,
            state.last_network_activity
        );

        // Print the score results stored in the state
        display_score(&state.score);

        // Print the lanscan results stored in the state
        display_lanscan(&state.devices);

        // Print the connections stored in the state
        format_sessions_log(state.sessions);
    }
}

pub fn handle_get_core_info() {
    let core_info = get_core_info();
    println!("Core information: {}", core_info);
}

pub fn handle_get_device_info() {
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
    // Flush the output
    match io::stdout().flush() {
        Ok(_) => (),
        Err(e) => eprintln!("Error flushing stdout: {}", e),
    }
}

pub fn handle_get_threats_info() {
    let score = get_score(false);
    let threats = format!(
        "Threat model name: {}, date: {}, signature: {}",
        score.model_name, score.model_date, score.model_signature
    );
    println!("Threats information: {}", threats);
}

pub fn handle_request_pin(user: String, domain: String) {
    set_credentials(user.clone(), domain.clone(), String::new());
    request_pin();
    println!("PIN requested for user: {}, domain: {}", user, domain);
}

pub fn handle_get_core_version() {
    let version = get_core_version();
    println!("Core version: {}", version);
}

pub fn display_lanscan(devices: &LANScanAPI) {
    println!("LAN scan completed at: {}", devices.last_scan);
    // Interfaces are in the form (ip, subnet, name)
    let interfaces = devices
        .network
        .interfaces
        .iter()
        .map(|interface| format!("{} ({}/{})", interface.2, interface.0, interface.1))
        .collect::<Vec<String>>()
        .join(", ");
    println!("Network interfaces scanned: {}", interfaces);
    if devices.devices.len() > 0 {
        println!("Devices found:");
    }
    for device in devices.devices.iter() {
        println!("  - '{}'", device.hostname);
        println!("    - Type: {}", device.device_type);
        println!("    - Vendor: {}", device.device_vendor);
        println!("    - IPs: {}", device.ip_addresses.join(", "));
        println!("    - MACs: {}", device.mac_addresses.join(", "));
        println!("    - Has EDAMAME: {}", device.has_edamame);
        println!("    - Criticality: {}", device.criticality);
        println!(
            "    - Open ports: {}",
            device
                .open_ports
                .iter()
                .map(|port| port.port.to_string())
                .collect::<Vec<String>>()
                .join(", ")
        );
    }
    println!(
        "Total devices: {}, {} devices have EDAMAME, {} devices are highly critical",
        devices.devices.len(),
        devices
            .devices
            .iter()
            .filter(|device| device.has_edamame)
            .count(),
        devices
            .devices
            .iter()
            .filter(|device| device.criticality == "High")
            .count()
    );
    // Flush the output
    match io::stdout().flush() {
        Ok(_) => (),
        Err(e) => eprintln!("Error flushing stdout: {}", e),
    }
}

pub fn handle_lanscan() {
    // The network, has been set, consent has been granted and a scan has been requested if needed
    let total_steps = 100;
    let pb = ProgressBar::new(total_steps);
    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos:>7}/{len:7} ({eta})")
        .expect("failed to set progress style")
        .progress_chars("#>-"));

    // Wait completion of the scan
    let mut devices = get_lan_devices(false, false, false);
    println!("Waiting for LAN scan to complete...");
    while devices.scan_in_progress {
        pb.set_position(devices.scan_progress_percent as u64);
        sleep(Duration::from_secs(5));
        devices = get_lan_devices(false, false, false);
    }

    // Display the devices
    display_lanscan(&devices);
}

pub fn handle_get_sessions(local_traffic: bool, zeek_format: bool) -> i32 {
    // Read the connections in the state
    let state = load_state();
    let sessions = if !local_traffic {
        // Filter out local traffic
        filter_global_sessions(state.sessions)
    } else {
        state.sessions
    };

    // Format the connections and display them
    let sessions = if zeek_format {
        format_sessions_zeek(sessions)
    } else {
        format_sessions_log(sessions)
    };
    for session in sessions.iter() {
        println!("{}", session);
    }
    // Check whitelist conformance
    if !state.whitelist_conformance {
        eprintln!("Some connections failed the whitelist check");
        return 1;
    } else {
        return 0;
    }
}

pub fn handle_capture(seconds: u64, whitelist_name: &str, zeek_format: bool, local_traffic: bool) {
    // Start capturing packets
    set_whitelist(whitelist_name.to_string());
    // Filter sessions based on local_traffic
    set_filter(if local_traffic {
        SessionFilterAPI::All
    } else {
        SessionFilterAPI::GlobalOnly
    });
    start_capture();

    // Wait for the specified number of seconds
    sleep(Duration::from_secs(seconds));

    // Stop capturing packets
    stop_capture();

    // Display the captured connections
    let sessions = get_sessions();

    let sessions = if zeek_format {
        format_sessions_zeek(sessions)
    } else {
        format_sessions_log(sessions)
    };
    for session in sessions.iter() {
        println!("{}", session);
    }
}

pub fn display_score(score: &ScoreAPI) {
    let url = get_threats_url().to_string();
    // Pretty print the final score with important details
    println!("Security Score summary:");
    println!("  - Threat model version: {}", score.model_name);
    println!("  - Threat model date: {}", score.model_date);
    println!("  - Threat model signature: {}", score.model_signature);
    println!("  - Threat model URL: {}", url);
    println!("  - Score computed at: {}", score.last_compute);
    println!("  - Stars: {:?}", score.stars);
    println!("  - Network: {:?}", score.network);
    println!("  - System Integrity: {:?}", score.system_integrity);
    println!("  - System Services: {:?}", score.system_services);
    println!("  - Applications: {:?}", score.applications);
    println!("  - Credentials: {:?}", score.credentials);
    println!("  - Overall: {:?}", score.overall);
    // Active threats
    println!("  - Active threats:");
    for metric in score.active.iter() {
        println!("    - {}", metric.name);
    }
    // Inactive threats
    println!("  - Inactive threats:");
    for metric in score.inactive.iter() {
        println!("    - {}", metric.name);
    }
    // Unknown threats
    println!("  - Unknown threats:");
    for metric in score.unknown.iter() {
        println!("    - {}", metric.name);
    }
    // Flush the output
    match io::stdout().flush() {
        Ok(_) => (),
        Err(e) => eprintln!("Error flushing stdout: {}", e),
    }
}

pub fn handle_score(progress_bar: bool) {
    let total_steps = 100;
    let pb = ProgressBar::new(total_steps);
    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos:>7}/{len:7} ({eta})")
        .expect("failed to set progress style")
        .progress_chars("#>-"));

    let mut score = get_score(false);
    while score.compute_in_progress {
        if progress_bar {
            pb.set_position(score.compute_progress_percent as u64);
        }
        sleep(Duration::from_millis(100));
        score = get_score(false);
    }

    // Make sure we have the final score
    score = get_score(true);
    display_score(&score);
}

pub fn handle_get_system_info() {
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
    println!("  - NB CPUs: {}", sys.cpus().len());

    // We display all disks' information
    println!("  - Disks:");
    let disks = Disks::new_with_refreshed_list();
    for disk in &disks {
        println!("    - {disk:?}");
    }

    // Network interfaces name
    let networks = Networks::new_with_refreshed_list();
    println!("  - Networks:");
    for (interface_name, _data) in &networks {
        println!("    - {interface_name}",);
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
        println!("  - System profiler hardware data:");
        println!("{}", String::from_utf8_lossy(&output.stdout));
    }

    #[cfg(target_os = "linux")]
    {
        use std::fs;

        let cpuinfo = fs::read_to_string("/proc/cpuinfo").expect("Failed to read /proc/cpuinfo");

        println!("Linux specific information:");
        println!("  - CPU information from /proc/cpuinfo:");
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
        println!("  - Computer system model from WMI:");
        println!("{}", String::from_utf8_lossy(&output.stdout));
    }
    // Flush the output
    match io::stdout().flush() {
        Ok(_) => (),
        Err(e) => eprintln!("Error flushing stdout: {}", e),
    }
}

pub fn handle_remediate(remediations_to_skip: &str) {
    println!("Score before remediation:");
    println!("-------------------------");
    println!();

    // Show the score before remediation
    handle_score(false);

    // Get the score
    let score = get_score(true);

    // Print the threats that can be remediated
    println!("Threats that can be remediated:");
    for metric in score.auto_remediate.iter() {
        println!("  - {}", metric.name);
    }

    // Extract the remediations to skip
    let mut remediations_to_skip = remediations_to_skip.split(',').collect::<Vec<&str>>();
    // Add "remote login enabled" to the list of exceptions (to prevent being locked out...)
    remediations_to_skip.push("remote login enabled");

    // Remediate the threats with "remote login" as an exception
    println!();
    println!("Remediating threats:");
    for metric in score.auto_remediate.iter() {
        if !remediations_to_skip.contains(&metric.name.as_str()) {
            println!("  - {}", metric.name);
            remediate(metric.name.clone(), true);
        }
    }

    println!();
    println!("Score after remediation:");
    println!("------------------------");

    // Show the score after remediation
    handle_score(false);
}
