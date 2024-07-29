use crate::{display_logs, stop_background_process, State};
use edamame_core::api::api_core::{
    connect_domain, get_core_info, get_core_version, get_device_info, request_pin, set_credentials,
};
use edamame_core::api::api_lanscan::{get_lan_devices, set_network, LANScanAPINetwork};
use edamame_core::api::api_score::{compute_score, get_score};
use edamame_core::api::api_score_threats::{get_threats_url, remediate};
use indicatif::{ProgressBar, ProgressStyle};
use std::thread::sleep;
use std::time::Duration;
use sysinfo::{Disks, Networks, System};

pub fn handle_wait_for_connection(timeout: u64) {
    handle_get_device_info();

    handle_get_system_info();

    println!("Waiting for score computation and reporting to complete...");
    let mut timeout = timeout;
    // Read the state and wait until a network activity is detected and the connection is successful
    let mut state = State::load();
    while !(state.is_success && state.last_network_activity != "") && timeout > 0 {
        sleep(Duration::from_secs(5));
        timeout = timeout - 5;
        state = State::load();
        println!("Waiting for score computation and reporting to complete... (success: {}, network activity: {})", state.is_success, state.last_network_activity);
    }

    if timeout <= 0 {
        eprintln!(
            "Timeout waiting for background process to connect to domain, killing process..."
        );
        stop_background_process();

        display_logs();

        // Exit with an error code
        std::process::exit(1);
    } else {
        // Compute and display the score
        compute_score();
        handle_score(true);

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
        });

        // Consent has been granted and scan has completed by the child

        // Print the lanscan results
        handle_lanscan();

        display_logs();

        println!(
            "Connection successful with domain {} and user {} (success: {}, network activity: {}), pausing for 60 seconds to ensure access control is applied...",
            state.connected_domain,
            state.connected_user,
            state.is_success,
            state.last_network_activity
        );
        sleep(Duration::from_secs(60));
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
}

pub fn handle_get_threats_info() {
    let score = get_score(false);
    let threats = format!(
        "Threat model name: {}, date: {}, signature: {}",
        score.model_name, score.model_date, score.model_signature
    );
    println!("Threats information: {}", threats);
}

pub fn handle_connect_domain() {
    connect_domain();
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

pub fn handle_lanscan() {
    let mut devices = get_lan_devices(false, false, false);
    // Interfaces are in the form (ip, subnet, name)
    let interfaces = devices
        .network
        .network
        .interfaces
        .iter()
        .map(|interface| format!("{} ({}/{})", interface.2, interface.0, interface.1))
        .collect::<Vec<String>>()
        .join(", ");
    println!("Final network interfaces: {}", interfaces);

    // The network, has been set, consent has been granted and a scan has been requested if needed

    // Display the lanscan results
    let total_steps = 100;
    let pb = ProgressBar::new(total_steps);
    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos:>7}/{len:7} ({eta})")
        .progress_chars("#>-"));

    // Wait completion of the scan
    devices = get_lan_devices(false, false, false);
    while devices.scan_in_progress {
        pb.set_position(devices.scan_progress_percent as u64);
        sleep(Duration::from_secs(5));
        devices = get_lan_devices(false, false, false);
    }

    println!("LAN scan completed at: {}", devices.last_scan);
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
    println!("");
}

pub fn handle_score(progress_bar: bool) {
    let total_steps = 100;
    let pb = ProgressBar::new(total_steps);
    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos:>7}/{len:7} ({eta})")
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
    println!("");
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
}

pub fn handle_remediate(remediations_to_skip: &str) {
    println!("Score before remediation:");
    println!("-------------------------");
    println!("");

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
    println!("");
    println!("Remediating threats:");
    for metric in score.auto_remediate.iter() {
        if !remediations_to_skip.contains(&metric.name.as_str()) {
            println!("  - {}", metric.name);
            remediate(metric.name.clone(), true);
        }
    }

    println!("");
    println!("Score after remediation:");
    println!("------------------------");
    println!("");

    // Show the score after remediation
    handle_score(false);
}
