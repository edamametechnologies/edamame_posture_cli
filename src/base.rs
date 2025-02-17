use crate::display::*;
use edamame_core::api::api_core::*;
use edamame_core::api::api_lanscan::*;
use edamame_core::api::api_score::*;
use edamame_core::api::api_score_threats::*;
use edamame_core::api::api_trust::*;
use indicatif::{ProgressBar, ProgressStyle};
use std::io;
use std::io::Write;
use std::thread::sleep;
use std::time::Duration;
use sysinfo::{Disks, Networks, System};

pub fn base_score(progress_bar: bool) {
    // Request a score computation
    compute_score();

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

pub fn base_get_system_info() {
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

pub fn base_remediate(remediations_to_skip: &str) {
    println!("Score before remediation:");
    println!("-------------------------");
    println!();

    // Show the score before remediation
    base_score(false);

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
    base_score(false);
}

pub fn base_capture(seconds: u64, whitelist_name: &str, zeek_format: bool, local_traffic: bool) {
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

pub fn base_lanscan() {
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

pub fn base_request_pin(user: String, domain: String) {
    set_credentials(user.clone(), domain.clone(), String::new());
    request_pin();
    println!("PIN requested for user: {}, domain: {}", user, domain);
}

pub fn base_get_core_version() {
    let version = get_core_version();
    println!("Core version: {}", version);
}

pub fn base_get_core_info() {
    let core_info = get_core_info();
    println!("Core information: {}", core_info);
}

pub fn base_get_device_info() {
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
