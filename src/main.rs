mod background;
mod base;
mod daemon;
mod display;
use anyhow::Result;
use background::*;
use base::*;
use base64::prelude::*;
use clap::{arg, Command};
use daemon::*;
use edamame_core::api::api_core::*;
use edamame_core::api::api_lanscan::*;
use edamame_core::api::api_trust::*;
use envcrypt::envc;
use lazy_static::lazy_static;
use machine_uid;
use regex::Regex;
use std::process::exit;
use std::thread::sleep;
use std::time::Duration;

lazy_static! {
    pub static ref EDAMAME_TARGET: String =
        envc!("EDAMAME_CORE_TARGET").trim_matches('"').to_string();
    pub static ref EDAMAME_CA_PEM: String = envc!("EDAMAME_CA_PEM").trim_matches('"').to_string();
    pub static ref EDAMAME_CLIENT_PEM: String =
        envc!("EDAMAME_CLIENT_PEM").trim_matches('"').to_string();
    pub static ref EDAMAME_CLIENT_KEY: String =
        envc!("EDAMAME_CLIENT_KEY").trim_matches('"').to_string();
}

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

pub fn initialize_core(
    device_id: String,
    computing: bool,
    reporting: bool,
    community: bool,
    server: bool,
    service: bool,
) {
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

    let executable_type = if service {
        "service".to_string()
    } else {
        "posture".to_string()
    };

    initialize(
        executable_type,
        envc!("VERGEN_GIT_BRANCH").to_string(),
        "EN".to_string(),
        device,
        computing,
        reporting,
        community,
        server,
        // Analytics is enabled by default
        true,
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
    // Initialize the core with reporting and server enabled
    initialize_core(device_id, true, true, false, true, true);

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
    let mut background_exit_code = 0;
    let matches = Command::new("edamame_posture")
        .version("1.0")
        .author("Frank Lyonnet")
        .about("CLI interface to edamame_core")
        ////////////////
        // Base commands
        ////////////////
        .subcommand(Command::new("score").about("Get score information"))
        .subcommand(Command::new("lanscan").about("Performs a LAN scan"))
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
        .subcommand(Command::new("request-signature").about("Report the security posture anonymously and get a signature for later retrieval"))
        .subcommand(Command::new("request-report").about("Send a report from a signature to an email address").arg(
            arg!(<EMAIL> "Email address")
                    .required(true)
                    .value_parser(clap::value_parser!(String))).arg(
                arg!(<SIGNATURE> "Signature")
                    .required(true)
                    .value_parser(clap::value_parser!(String)),
            ),
        )
        //////////////////////
        // Background commands
        //////////////////////
        .subcommand(Command::new("background-logs").alias("logs").about("Display logs from the background process"))
        .subcommand(
            Command::new("background-wait-for-connection")
                .alias("wait-for-connection")
                .about("Wait for connection of the background process")
                .arg(
                    arg!(<TIMEOUT> "Timeout in seconds")
                        .required(false)
                        .value_parser(clap::value_parser!(u64)),
                ),
        )
        .subcommand(
            Command::new("background-sessions")
                .alias("get-sessions")
                .about("Get connections of the background process")
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
        .subcommand(Command::new("background-threats-info").alias("get-threats-info").about("Get threats information of the background process"))
        .subcommand(
            Command::new("foreground-start")
                .about("Start reporting in the foreground (used by the systemd service)")
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
        )
        .subcommand(
            Command::new("background-start")
                .alias("start")
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
                    arg!([DEVICE_ID] "Device ID in the form of a string, this will be used as a suffix to the detected hardware ID. When non empty, the endpoint will be flagged as a CI/CD runner.")
                        .required(false)
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
                )
        )
        .subcommand(Command::new("background-stop").alias("stop").about("Stop reporting background process"))
        .subcommand(Command::new("background-status").alias("status").about("Get status of reporting background process"))
        .subcommand(Command::new("background-last-report-signature").alias("get-last-report-signature").about("Get last report signature of background process"))
        .subcommand(Command::new("background-get-history").alias("get-history").about("Get history of score modifications"))
        .get_matches();

    match matches.subcommand() {
        ////////////////
        // Base commands
        ////////////////
        Some(("score", _)) => {
            // Initialize the core with computin enabled and reporting and server disabled
            initialize_core("".to_string(), true, false, false, false, false);
            ensure_admin(); // Admin check here
            base_score(true);
        }
        Some(("lanscan", _)) => {
            // Initialize the core with reporting and server disabled
            initialize_core("".to_string(), false, false, false, false, false);
            ensure_admin();
            // Initialize network
            set_network(LANScanNetworkAPI {
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
            base_lanscan();
        }
        Some(("capture", sub_matches)) => {
            // Initialize the core with reporting and server disabled
            initialize_core("".to_string(), false, false, false, false, false);
            ensure_admin(); // Admin check here

            let seconds = sub_matches.get_one::<u64>("SECONDS").unwrap_or(&600);
            let whitelist_name = sub_matches
                .get_one::<String>("WHITELIST_NAME")
                .map_or("", |v| v);
            let zeek_format = sub_matches.get_one::<bool>("ZEEK_FORMAT").unwrap_or(&false);
            let local_traffic = sub_matches
                .get_one::<bool>("LOCAL_TRAFFIC")
                .unwrap_or(&false);
            base_capture(*seconds, whitelist_name, *zeek_format, *local_traffic);
        }
        Some(("get-core-info", _)) => {
            // Initialize the core with reporting and server disabled
            initialize_core("".to_string(), false, false, false, false, false);
            base_get_core_info();
        }
        Some(("get-device-info", _)) => {
            // Initialize the core with reporting and server disabled
            initialize_core("".to_string(), false, false, false, false, false);
            ensure_admin();
            base_get_device_info();
        }
        Some(("request-pin", sub_matches)) => {
            // No admin check needed here
            let user = sub_matches.get_one::<String>("USER").unwrap().to_string();
            let domain = sub_matches.get_one::<String>("DOMAIN").unwrap().to_string();
            // Initialize the core with reporting and server disabled
            initialize_core("".to_string(), false, false, false, false, false);
            base_request_pin(user, domain);
        }
        Some(("get-core-version", _)) => {
            // No admin check needed here
            // Initialize the core with reporting and server disabled
            initialize_core("".to_string(), false, false, false, false, false);
            base_get_core_version();
        }
        Some(("remediate", sub_matches)) => {
            let remediations_to_skip = sub_matches
                .get_one::<String>("REMEDIATIONS")
                .unwrap_or(&String::new())
                .to_string();
            // Initialize the core with computin enabled and reporting and server disabled
            initialize_core("".to_string(), true, false, false, false, false);
            ensure_admin();
            base_remediate(&remediations_to_skip)
        }
        Some(("get-system-info", _)) => {
            // Initialize the core with reporting and server disabled
            initialize_core("".to_string(), false, false, false, false, false);
            ensure_admin();
            base_get_system_info();
        }
        Some(("request-signature", _)) => {
            // Initialize the core with reporting and server disabled
            initialize_core("".to_string(), true, false, false, false, false);
            ensure_admin(); // Admin check here
            base_score(true);
            let signature =
                get_signature_from_score_with_email("anonymous@anonymous.eda".to_string());
            println!("Signature: {}", signature);
        }
        Some(("request-report", sub_matches)) => {
            // Check email format
            let email = sub_matches.get_one::<String>("EMAIL").unwrap().to_string();
            if !email.contains('@') || !email.contains('.') {
                eprintln!("Invalid email format");
                std::process::exit(1);
            }
            // Check signature format (32 bytes in base 64)
            let signature = sub_matches
                .get_one::<String>("SIGNATURE")
                .unwrap()
                .to_string();
            // Try decode the base64 string
            match BASE64_STANDARD.decode(&signature) {
                Ok(decoded_signature) => {
                    // Check if 32 bytes
                    if decoded_signature.len() != 32 {
                        eprintln!("Invalid signature format");
                        std::process::exit(1);
                    }
                }
                Err(_) => {
                    eprintln!("Invalid signature format");
                    std::process::exit(1);
                }
            }
            // Initialize the core with reporting and server disabled
            initialize_core("".to_string(), false, false, false, false, false);
            request_report_from_signature(email, signature, "JSON".to_string());
        }
        //////////////////////
        // Background commands
        //////////////////////
        Some(("background-logs", _)) => {
            // Initialize the core with reporting and server disabled
            initialize_core("".to_string(), false, false, false, false, false);

            let logs = match rpc_get_all_logs(
                &EDAMAME_CA_PEM,
                &EDAMAME_CLIENT_PEM,
                &EDAMAME_CLIENT_KEY,
                &EDAMAME_TARGET,
            ) {
                Ok(logs) => logs,
                Err(e) => {
                    eprintln!("Error getting logs: {:?}", e);
                    "".to_string()
                }
            };
            println!("{}", logs);
        }
        Some(("background-wait-for-connection", sub_matches)) => {
            let timeout = match sub_matches.get_one::<u64>("TIMEOUT") {
                Some(timeout) => timeout,
                None => {
                    println!("Timeout not provided, defaulting to 600 seconds");
                    &600
                }
            };
            // Initialize the core with reporting and server disabled
            initialize_core("".to_string(), false, false, false, false, false);

            background_exit_code = background_wait_for_connection(*timeout);
        }
        Some(("background-sessions", sub_matches)) => {
            let zeek_format = sub_matches.get_one::<bool>("ZEEK_FORMAT").unwrap_or(&false);
            let local_traffic = sub_matches
                .get_one::<bool>("LOCAL_TRAFFIC")
                .unwrap_or(&false);

            // Initialize the core with reporting and server disabled
            initialize_core("".to_string(), false, false, false, false, false);
            background_exit_code = background_get_sessions(*zeek_format, *local_traffic);
        }
        Some(("background-threats-info", _)) => {
            // Initialize the core with reporting and server disabled
            initialize_core("".to_string(), false, false, false, false, false);
            ensure_admin();
            background_get_threats_info();
        }
        Some(("background-get-history", _)) => {
            // Initialize the core with reporting and server disabled
            initialize_core("".to_string(), false, false, false, false, false);
            background_get_history();
        }
        Some(("background-start", sub_matches)) => {
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
            // If no device ID is provided, use an empty string
            let device_id = sub_matches
                .get_one::<String>("DEVICE_ID")
                .map_or("".to_string(), |v| v.to_string());
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
            // Initialize the core with reporting and server disabled
            initialize_core("".to_string(), false, false, false, false, false);
            ensure_admin();
            background_start(
                user,
                domain,
                pin,
                device_id,
                *lan_scanning,
                whitelist_name,
                *local_traffic,
            );
        }
        Some(("foreground-start", sub_matches)) => {
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
            // Directly call the background process
            run_background(
                user,
                domain,
                pin,
                "".to_string(),
                false,
                "".to_string(),
                false,
            );
        }
        Some(("background-stop", _)) => {
            // Initialize the core with reporting and server disabled
            initialize_core("".to_string(), false, false, false, false, false);
            background_exit_code = background_stop();
        }
        Some(("background-status", _)) => {
            // Initialize the core with reporting and server disabled
            initialize_core("".to_string(), false, false, false, false, false);
            background_exit_code = background_get_status();
        }
        Some(("background-last-report-signature", _)) => {
            // Initialize the core with reporting and server disabled
            initialize_core("".to_string(), false, false, false, false, false);
            background_exit_code = background_get_last_report_signature();
        }
        _ => {
            // Initialize the core with reporting and server disabled
            initialize_core("".to_string(), false, false, false, false, false);
            eprintln!("Invalid command, use --help for more information");
        }
    }

    // Dump the logs in case of error
    if background_exit_code != 0 {
        let logs = match rpc_get_all_logs(
            &EDAMAME_CA_PEM,
            &EDAMAME_CLIENT_PEM,
            &EDAMAME_CLIENT_KEY,
            &EDAMAME_TARGET,
        ) {
            Ok(logs) => logs,
            Err(e) => {
                eprintln!("Error getting logs: {:?}", e);
                "".to_string()
            }
        };
        println!("{}", logs);
    }

    // Properly terminate the core
    terminate(false);

    exit(background_exit_code);
}

pub fn main() {
    run();
}
