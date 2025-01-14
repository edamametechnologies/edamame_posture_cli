use edamame_core::api::api_lanscan::*;
use edamame_core::api::api_score::*;
use edamame_core::api::api_score_threats::*;
use std::io;
use std::io::Write;

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

pub fn display_lanscan(devices: &LANScanAPI) {
    println!("LAN scan completed at: {}", devices.last_scan);
    // Interfaces are in the form (ip, subnet, name)
    let interfaces = devices
        .network
        .interfaces
        .iter()
        .map(|interface| {
            format!(
                "{} ({}/{})",
                interface.name, interface.ipv4, interface.prefixv4
            )
        })
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
        println!("    - v4 IPs: {}", device.ip_addresses_v4.join(", "));
        println!("    - v6 IPs: {}", device.ip_addresses_v6.join(", "));
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
