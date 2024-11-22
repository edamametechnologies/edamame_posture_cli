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
use regex::Regex;
use std::process::exit;
use std::thread::sleep;
use std::time::Duration;

fn parse_digits_only(s: &str) -> Result<String, String> {
    if s.chars().all(|c| c.is_ascii_digit()) {
        Ok(s.to_string())
    } else {
        Err(String::from("PIN must contain digits only"))
    }
}

fn parse_fqdn(s: &str) -> Result<String, String> {
    // This regex matches valid FQDNs according to RFC 1035
    let fqdn_regex =
        Regex::new(r"^(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+)(?:[A-Za-z]{2,})$")
            .unwrap();

    if fqdn_regex.is_match(s) {
        Ok(s.to_string())
    } else {
        Err(String::from("Invalid FQDN"))
    }
}

pub fn initialize_core(device_id: String, reporting: bool, community: bool) {
    // Set device ID
    // Prefix is the machine uid
    let machine_uid = machine_uid::get().unwrap_or("".to_string());

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
    if device_id != "" {
        device.device_id = (machine_uid + "/" + device_id.as_str()).to_string();
    }

    // Reporting is on community is off
    initialize(
        "posture".to_string(),
        envc!("VERGEN_GIT_BRANCH").to_string(),
        "EN".to_string(),
        device,
        reporting,
        community,
    );
}

fn run() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 && args[1] == "background-process" {
        // Debug logging
        //std::env::set_var("EDAMAME_LOG_LEVEL", "debug");

        // Don't call ensure_admin() here, the core is not initialized yet

        if args.len() == 9 {
            run_background(
                args[2].to_string(),
                args[3].to_string(),
                args[4].to_string(),
                args[5].to_string(),
                args[6].to_string() == "true",
                args[7].to_string(),
                args[8].to_string() == "true",
            );
        } else {
            eprintln!("Invalid arguments for background process: {:?}", args);
            // Exit with an error code
            std::process::exit(1);
        }
    } else {
        run_base();
    }
}

pub fn run_background(
    user: String,
    domain: String,
    pin: String,
    device_id: String,
    lan_scanning: bool,
    whitelist_name: String,
    local_traffic: bool,
) {
    // Save state within the child for unix
    #[cfg(unix)]
    {
        let state = State {
            pid: Some(std::process::id()),
            handle: None,
            is_connected: false,
            connected_domain: domain.clone(),
            connected_user: user.clone(),
            last_network_activity: "".to_string(),
            score: ScoreAPI::default(),
            devices: LANScanAPI::default(),
            sessions: Vec::new(),
            whitelist_name: whitelist_name.clone(),
            whitelist_conformance: true,
            is_outdated_backend: false,
            is_outdated_threats: false,
            backend_error_code: "".to_string(),
            last_report_signature: "".to_string(),
        };
        save_state(&state);
    }

    // Initialize the core with reporting enabled
    initialize_core(device_id, true, false);

    background_process(
        user,
        domain,
        pin,
        lan_scanning,
        whitelist_name,
        local_traffic,
    );
}

fn ensure_admin() {
    let admin_status = get_admin_status();
    if !admin_status {
        eprintln!("This command requires admin privileges, exiting...");
        std::process::exit(1);
    }
}

fn run_base() {
    // Initialize the core with reporting disabled
    initialize_core("".to_string(), false, false);

    let mut exit_code = 0;
    let matches = Command::new("edamame_posture")
        .version("1.0")
        .author("Frank Lyonnet")
        .about("CLI interface to edamame_core")
        .subcommand(Command::new("logs").about("Display logs"))
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
        .subcommand(
            Command::new("get-sessions")
                .about("Get connections")
                .arg(
                    arg!(<ZEEK_FORMAT> "Zeek format")
                        .required(false)
                        .value_parser(clap::value_parser!(bool)),
                )
                .arg(
                    arg!(<LOCAL_TRAFFIC> "Include local traffic")
                        .required(false)
                        .default_value("false")
                        .value_parser(clap::value_parser!(bool)),
                ),
        )
        .subcommand(
            Command::new("capture")
                .about("Capture packets")
                .arg(
                    arg!(<SECONDS> "Number of seconds to capture")
                        .required(false)
                        .value_parser(clap::value_parser!(u64)),
                )
                // Required whitelist name
                .arg(
                    arg!(<WHITELIST_NAME> "Whitelist name")
                        .required(false)
                        .value_parser(clap::value_parser!(String)),
                )
                // Optional Zeek format
                .arg(
                    arg!(<ZEEK_FORMAT> "Zeek format")
                        .required(false)
                        .value_parser(clap::value_parser!(bool)),
                )
                .arg(
                    arg!(<LOCAL_TRAFFIC> "Include local traffic")
                        .required(false)
                        .default_value("false")
                        .value_parser(clap::value_parser!(bool)),
                ),
        )
        .subcommand(Command::new("get-core-info").about("Get core information"))
        .subcommand(Command::new("get-device-info").about("Get device information"))
        .subcommand(Command::new("get-threats-info").about("Get threats information"))
        .subcommand(Command::new("get-system-info").about("Get system information"))
        .subcommand(
            Command::new("request-pin")
                .about("Request PIN")
                .arg(
                    arg!(<USER> "User name")
                        .required(true)
                        .value_parser(clap::value_parser!(String)),
                )
                .arg(
                    arg!(<DOMAIN> "Domain name")
                        .required(true)
                        .value_parser(clap::value_parser!(String)),
                ),
        )
        .subcommand(Command::new("get-core-version").about("Get core version"))
        .subcommand(
            Command::new("remediate").about("Remediate threats").arg(
                arg!(<REMEDIATIONS> "Remediations to skip (comma separated list)")
                    .required(false),
            ),
        )
        .subcommand(
            Command::new("start")
                .about("Start reporting background process")
                .arg(
                    arg!(<USER> "User name")
                        .required(true)
                        .value_parser(clap::value_parser!(String)),
                )
                .arg(
                    arg!(<DOMAIN> "Domain name")
                        .required(true)
                        // FQDN only
                        .value_parser(parse_fqdn),
                )
                .arg(
                    arg!(<PIN> "PIN")
                        .required(true)
                        // String with digits only
                        .value_parser(parse_digits_only),
                )
                .arg(
                    arg!(<DEVICE_ID> "Device ID in the form of a string, this will be used as a suffix to the detected hardware ID")
                        .required(true)
                        .value_parser(clap::value_parser!(String)),
                )
                .arg(
                    arg!(<LAN_SCANNING> "LAN scanning enabled")
                        .required(false)
                        .value_parser(clap::value_parser!(bool)),
                )
                .arg(
                    arg!(<WHITELIST_NAME> "Whitelist name")
                        .required(false)
                        .value_parser(clap::value_parser!(String)),
                )
                .arg(
                    arg!(<LOCAL_TRAFFIC> "Include local traffic")
                        .required(false)
                        .default_value("false")
                        .value_parser(clap::value_parser!(bool)),
                ),
        )
        .subcommand(Command::new("stop").about("Stop reporting background process"))
        .subcommand(Command::new("status").about("Get status of reporting background process"))
        .get_matches();

    match matches.subcommand() {
        Some(("logs", _)) => {
            display_logs();
        }
        Some(("score", _)) => {
            ensure_admin(); // Admin check here
                            // Request a score computation
            compute_score();
            handle_score(true);
        }
        Some(("lanscan", _)) => {
            ensure_admin();
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

            // Wait for the LAN scan to complete
            handle_lanscan();
        }
        Some(("wait-for-connection", sub_matches)) => {
            ensure_admin();
            let timeout = match sub_matches.get_one::<u64>("TIMEOUT") {
                Some(timeout) => timeout,
                None => {
                    println!("Timeout not provided, defaulting to 600 seconds");
                    &600
                }
            };
            handle_wait_for_connection(*timeout);
        }
        Some(("get-sessions", sub_matches)) => {
            ensure_admin();

            let zeek_format = sub_matches.get_one::<bool>("ZEEK_FORMAT").unwrap_or(&false);
            let local_traffic = sub_matches
                .get_one::<bool>("LOCAL_TRAFFIC")
                .unwrap_or(&false);
            exit_code = handle_get_sessions(*zeek_format, *local_traffic);
        }
        Some(("capture", sub_matches)) => {
            ensure_admin(); // Admin check here

            let seconds = sub_matches.get_one::<u64>("SECONDS").unwrap_or(&600);
            let whitelist_name = sub_matches
                .get_one::<String>("WHITELIST_NAME")
                .map_or("", |v| v);
            let zeek_format = sub_matches.get_one::<bool>("ZEEK_FORMAT").unwrap_or(&false);
            let local_traffic = sub_matches
                .get_one::<bool>("LOCAL_TRAFFIC")
                .unwrap_or(&false);
            handle_capture(*seconds, whitelist_name, *zeek_format, *local_traffic);
        }
        Some(("get-core-info", _)) => {
            ensure_admin();

            handle_get_core_info();
        }
        Some(("get-device-info", _)) => {
            ensure_admin();

            handle_get_device_info();
        }
        Some(("get-threats-info", _)) => {
            ensure_admin();

            handle_get_threats_info();
        }
        Some(("get-system-info", _)) => {
            ensure_admin();

            handle_get_system_info();
        }
        Some(("request-pin", sub_matches)) => {
            // No admin check needed here
            let user = sub_matches.get_one::<String>("USER").unwrap().to_string();
            let domain = sub_matches.get_one::<String>("DOMAIN").unwrap().to_string();
            handle_request_pin(user, domain);
        }
        Some(("get-core-version", _)) => {
            // No admin check needed here
            handle_get_core_version();
        }
        Some(("remediate", sub_matches)) => {
            ensure_admin();

            let remediations_to_skip = sub_matches
                .get_one::<String>("REMEDIATIONS")
                .unwrap_or(&String::new())
                .to_string();
            handle_remediate(&remediations_to_skip)
        }
        Some(("start", sub_matches)) => {
            ensure_admin();

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
            let whitelist_name = sub_matches
                .get_one::<String>("WHITELIST_NAME")
                .map_or("", |v| v)
                .to_string();
            let local_traffic = sub_matches
                .get_one::<bool>("LOCAL_TRAFFIC")
                .unwrap_or(&false);
            start_background_process(
                user,
                domain,
                pin,
                device_id,
                *lan_scanning,
                whitelist_name,
                *local_traffic,
            );
        }
        Some(("stop", _)) => {
            ensure_admin();
            stop_background_process();
        }
        Some(("status", _)) => {
            ensure_admin();
            show_background_process_status();
        }
        _ => eprintln!("Invalid command, use --help for more information"),
    }

    // Properly terminate the core
    terminate();

    exit(exit_code);
}

pub fn main() {
    run();
}
