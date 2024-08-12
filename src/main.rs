mod state;
use state::*;
mod logs;
use logs::*;
mod commands;
use commands::*;
mod background;
use background::*;
use clap::{arg, Command};
use edamame_core::api::api_core::*;
use edamame_core::api::api_lanscan::*;
use edamame_core::api::api_score::*;
use envcrypt::envc;
use machine_uid;
use std::thread::sleep;
use std::time::Duration;

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
        //std::env::set_var("EDAMAME_LOG_LEVEL", "debug");

        if args.len() == 7 {
            // Save state within the child for unix
            #[cfg(unix)]
            {
                let state = State {
                    pid: Some(std::process::id()),
                    handle: None,
                    is_success: false,
                    connected_domain: args[3].clone(),
                    connected_user: args[2].clone(),
                    last_network_activity: "".to_string(),
                };
                state.save();
            }

            // Set device ID
            // Prefix it with the machine uid
            let machine_uid = machine_uid::get().unwrap_or("".to_string());
            device.device_id =
                (machine_uid + "/" + args[5].clone().to_string().as_str()).to_string();

            // Reporting is on community is off
            initialize(
                "posture".to_string(),
                envc!("VERGEN_GIT_BRANCH").to_string(),
                "EN".to_string(),
                device,
                true,
                false,
            );

            let admin_status = get_admin_status();
            if !admin_status {
                eprintln!("This command requires admin privileges, exiting...");
                // Exit with an error code
                std::process::exit(1);
            }

            let lan_scanning = if args[6] == "true" { true } else { false };

            background_process(
                args[2].clone(),
                args[3].clone(),
                args[4].clone(),
                lan_scanning,
            );
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
            false,
            false,
        );

        let admin_status = get_admin_status();
        if !admin_status {
            eprintln!("This command requires admin privileges, exiting...");
            // Exit with an error code
            std::process::exit(1);
        }

        run_base();
    }
}

fn run_base() {
    let matches = Command::new("edamame_posture")
        .version("1.0")
        .author("Frank Lyonnet")
        .about("CLI interface to edamame_core")
        .subcommand(Command::new("score").about("Get score information"))
        .subcommand(Command::new("lanscan").about("Performs a LAN scan"))
        .subcommand(
            Command::new("wait-for-connection")
                .about("Wait for connection")
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
        .subcommand(Command::new("remediate").about("Remediate threats").arg(
            arg!(<REMEDIATIONS> "Remediations to skip (comma separated list)").required(false),
        ))
        .subcommand(
            Command::new("start")
                .about("Start reporting background process")
                .arg(arg!(<USER> "User name").required(true))
                .arg(arg!(<DOMAIN> "Domain name").required(true))
                .arg(arg!(<PIN> "PIN").required(true))
                .arg(arg!(<DEVICE_ID> "Device ID in the form of a string, this will be used as a suffix to the detected hardware ID").required(true))
                .arg(
                    arg!(<LAN_SCANNING> "LAN scanning enabled")
                        .required(false)
                        .value_parser(clap::value_parser!(bool)),
                ),
        )
        .subcommand(Command::new("stop").about("Stop reporting background process"))
        .subcommand(Command::new("status").about("Get status of reporting background process"))
        .get_matches();

    match matches.subcommand() {
        Some(("score", _)) => {
            // Request a score computation
            compute_score();
            handle_score(true);
        }
        Some(("lanscan", _)) => {
            // Initialize network
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
                println!("Waiting for gateway detection to complete...");
                sleep(Duration::from_secs(20));
                last_gateway_scan = get_last_gateway_scan();
            }
            println!("Gateway detection complete");

            // Request a LAN scan
            _ = get_lan_devices(true, false, false);

            handle_lanscan(true);
        }
        Some(("wait-for-connection", sub_matches)) => {
            let timeout = match sub_matches.get_one::<u64>("TIMEOUT") {
                Some(timeout) => timeout,
                None => {
                    println!("Timeout not provided, defaulting to 600 seconds");
                    &600
                }
            };
            handle_wait_for_connection(*timeout);
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
        Some(("remediate", sub_matches)) => {
            let remediations_to_skip = sub_matches
                .get_one::<String>("REMEDIATIONS")
                .unwrap_or(&String::new())
                .to_string();
            handle_remediate(&remediations_to_skip)
        }
        Some(("start", sub_matches)) => {
            let user = sub_matches
                .get_one::<String>("USER")
                .expect("USER not provided")
                .to_string();
            let domain = sub_matches
                .get_one::<String>("DOMAIN")
                .expect("DOMAIN not provided")
                .to_string();
            let pin = sub_matches
                .get_one::<String>("PIN")
                .expect("PIN not provided")
                .to_string();
            // If no device ID is provided, use an empty string to trigger detection
            let device_id = sub_matches
                .get_one::<String>("DEVICE_ID")
                .expect("DEVICE_ID not provided")
                .to_string();
            // Default to false if not provided
            let lan_scanning = sub_matches
                .get_one::<bool>("LAN_SCANNING")
                .unwrap_or(&false);
            start_background_process(user, domain, pin, device_id, *lan_scanning);
        }
        Some(("stop", _)) => stop_background_process(),
        Some(("status", _)) => show_background_process_status(),
        _ => eprintln!("Invalid command, use --help for more information"),
    }
}

pub fn main() {
    run();
}
