mod background;
mod base;
mod cli;
mod daemon;
use anyhow::Result;
use background::*;
use base::*;
use base64::prelude::*;
use clap::Command;
use clap_complete::{generate, Generator, Shell};
use cli::build_cli;
use daemon::*;
use edamame_core::api::api_core::*;
use edamame_core::api::api_lanscan::*;
use edamame_core::api::api_trust::*;
use envcrypt::envc;
use lazy_static::lazy_static;
use machine_uid;
use regex::Regex;
use std::io;
use std::process::exit;
use std::thread::sleep;
use std::time::Duration;
use uuid::Uuid;

const ERROR_CODE_MISMATCH: i32 = 1;
const ERROR_CODE_SERVER_ERROR: i32 = 2;
const ERROR_CODE_PARAM: i32 = 3;
const ERROR_CODE_TIMEOUT: i32 = 4;

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

// Must be a valid FQDN, allow empty strings
fn parse_fqdn(s: &str) -> Result<String, String> {
    if s.is_empty() {
        return Ok(s.to_string());
    }
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

// Must not be an email address, allow empty strings
fn parse_username(s: &str) -> Result<String, String> {
    if s.is_empty() {
        return Ok(s.to_string());
    }
    if s.contains('@') {
        return Err(String::from("Invalid username format"));
    }
    Ok(s.to_string())
}

// Must be an email address, allow empty strings
fn parse_email(s: &str) -> Result<String, String> {
    if s.is_empty() {
        return Ok(s.to_string());
    }
    if !s.contains('@') || !s.contains('.') {
        return Err(String::from("Invalid email format"));
    }
    Ok(s.to_string())
}

fn parse_signature(s: &str) -> Result<String, String> {
    // Try decode the base64 string
    match BASE64_STANDARD.decode(&s) {
        Ok(decoded_signature) => {
            // Check if 32 bytes
            if decoded_signature.len() != 32 {
                return Err(String::from("Invalid signature format"));
            }
        }
        Err(_) => {
            return Err(String::from("Invalid signature format"));
        }
    }
    Ok(s.to_string())
}

pub fn initialize_core(
    device_id: String,
    computing: bool,
    reporting: bool,
    community: bool,
    server: bool,
    verbose: bool,
) {
    // Set device ID
    // Prefix is the machine uid
    // Can return an empty string under Linux
    let mut machine_uid = match machine_uid::get() {
        Ok(uid) => uid,
        Err(_) => "".to_string(),
    };
    machine_uid = if machine_uid.is_empty() {
        // Create a fallback for Linux
        match std::fs::read_to_string("/sys/class/dmi/id/product_uuid") {
            Ok(uid) => uid,
            Err(_) => {
                // Create a random UUID
                let uuid = Uuid::new_v4();
                uuid.to_string()
            }
        }
    } else {
        machine_uid
    };

    let mut device = SystemInfoAPI {
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

    // By changing the executable type, we can have different logging behavior
    // "cli" is a special case in the logger that logs to file
    // "posture_verbose" falls into the default case and logs to stdout
    let executable_type = if verbose {
        "posture_verbose".to_string()
    } else {
        "cli".to_string()
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

    // Initialize network to autodetect (this will allow the core to detect the network interfaces and support whitelist operations)
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
        last_seen: "1970-01-01T00:00:00Z".to_string(),
        last_name: "".to_string(),
    });
}

fn print_completions<G: Generator>(gen: G, cmd: &mut Command) {
    generate(gen, cmd, cmd.get_name().to_string(), &mut io::stdout());
}

fn run() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() > 1 && args[1] == "background-process" {
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
                false,
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
    verbose: bool,
) {
    // Initialize the core with all options enabled
    // Verbose is set by the caller
    initialize_core(device_id, true, true, true, true, verbose);

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
    let mut exit_code = 0;
    let mut is_background = false;

    let mut cmd = build_cli();
    let matches = cmd.clone().get_matches();

    // Handle completion subcommand before other commands
    if let Some(("completion", sub_matches)) = matches.subcommand() {
        let shell = sub_matches.get_one::<Shell>("SHELL").unwrap();
        print_completions(*shell, &mut cmd);
        return;
    }

    // Check for verbose flag count
    let verbose_level = matches.get_count("verbose");
    let log_level = match verbose_level {
        0 => None,
        1 => {
            println!("Info logging enabled.");
            Some("info")
        }
        2 => {
            println!("Debug logging enabled.");
            Some("debug")
        }
        _ => {
            println!("Trace logging enabled.");
            Some("trace")
        }
    };

    if let Some(level) = log_level {
        std::env::set_var("EDAMAME_LOG_LEVEL", level);
    }

    let verbose = verbose_level > 0;

    match matches.subcommand() {
        ////////////////
        // Base commands
        ////////////////
        Some(("get-score", _)) => {
            // Initialize the core with computing enabled
            initialize_core("".to_string(), true, false, false, false, verbose);
            ensure_admin(); // Admin check here
            base_get_score(true);
        }
        Some(("lanscan", _)) => {
            // Initialize the core with all options disabled
            initialize_core("".to_string(), false, false, false, false, verbose);
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
            _ = get_lanscan(true, false, false);

            // Wait for the LAN scan to complete
            base_lanscan();
        }
        Some(("capture", sub_matches)) => {
            // Initialize the core with all options disabled
            initialize_core("".to_string(), false, false, false, false, verbose);
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
            // Initialize the core with all options disabled
            initialize_core("".to_string(), false, false, false, false, verbose);
            base_get_core_info();
        }
        Some(("get-device-info", _)) => {
            // Initialize the core with all options disabled
            initialize_core("".to_string(), false, false, false, false, verbose);
            ensure_admin();
            base_get_device_info();
        }
        Some(("request-pin", sub_matches)) => {
            // No admin check needed here
            let user = sub_matches.get_one::<String>("USER").unwrap().to_string();
            let domain = sub_matches.get_one::<String>("DOMAIN").unwrap().to_string();
            // Initialize the core with all options disabled
            initialize_core("".to_string(), false, false, false, false, verbose);
            exit_code = base_request_pin(user, domain);
        }
        Some(("get-core-version", _)) => {
            // No admin check needed here
            // Initialize the core with all options disabled
            initialize_core("".to_string(), false, false, false, false, verbose);
            base_get_core_version();
        }
        Some(("remediate-all-threats", sub_matches)) => {
            let remediations_to_skip = sub_matches
                .get_one::<String>("REMEDIATIONS")
                .unwrap_or(&String::new())
                .to_string();
            // Initialize the core with computing enabled
            initialize_core("".to_string(), true, false, false, false, false);
            ensure_admin();
            base_remediate(&remediations_to_skip)
        }
        Some(("remediate-all-threats-force", _)) => {
            // Initialize the core with computing enabled
            initialize_core("".to_string(), true, false, false, false, false);
            ensure_admin();
            base_remediate("");
        }
        Some(("remediate-threat", sub_matches)) => {
            let threat_id = sub_matches
                .get_one::<String>("THREAT_ID")
                .expect("THREAT_ID not provided")
                .to_string();
            // Initialize the core with computing enabled
            initialize_core("".to_string(), true, false, false, false, false);
            ensure_admin();
            exit_code = base_remediate_threat(threat_id);
        }
        Some(("check-policy-for-domain", sub_matches)) => {
            let domain = sub_matches.get_one::<String>("DOMAIN").unwrap().to_string();
            let policy_name = sub_matches
                .get_one::<String>("POLICY_NAME")
                .unwrap()
                .to_string();
            // Initialize the core with computing enabled
            initialize_core("".to_string(), true, false, false, false, verbose);
            // Needed as we will compute the score
            ensure_admin();
            exit_code = base_check_policy_for_domain(domain, policy_name);
        }
        Some(("check-policy-for-domain-with-signature", sub_matches)) => {
            let signature = sub_matches
                .get_one::<String>("SIGNATURE")
                .unwrap()
                .to_string();
            let domain = sub_matches.get_one::<String>("DOMAIN").unwrap().to_string();
            let policy_name = sub_matches
                .get_one::<String>("POLICY_NAME")
                .unwrap()
                .to_string();
            // Initialize the core with all options disabled (we will not compute the score not rely on local score but rather call the backend)
            initialize_core("".to_string(), false, false, false, false, verbose);
            exit_code = base_check_policy_for_domain_with_signature(signature, domain, policy_name);
        }
        Some(("check-policy", sub_matches)) => {
            let minimum_score = *sub_matches.get_one::<f32>("MINIMUM_SCORE").unwrap();
            let threat_ids = sub_matches
                .get_one::<String>("THREAT_IDS")
                .unwrap()
                .to_string();
            let tag_prefixes = sub_matches
                .get_one::<String>("TAG_PREFIXES")
                .map(|s| s.to_string())
                .unwrap_or_else(|| String::new());
            // Initialize the core with computing enabled
            initialize_core("".to_string(), true, false, false, false, verbose);
            ensure_admin();
            exit_code = base_check_policy(minimum_score, threat_ids, tag_prefixes);
        }
        Some(("get-tag-prefixes", _)) => {
            // Initialize the core with computing enabled
            initialize_core("".to_string(), true, false, false, false, verbose);
            ensure_admin();
            base_get_tag_prefixes();
        }
        Some(("rollback-threat", sub_matches)) => {
            let threat_id = sub_matches
                .get_one::<String>("THREAT_ID")
                .expect("THREAT_ID not provided")
                .to_string();
            // Initialize the core with computing enabled
            initialize_core("".to_string(), true, false, false, false, false);
            ensure_admin();
            exit_code = base_rollback_threat(threat_id);
        }
        Some(("get-threat-info", sub_matches)) => {
            let threat_id = sub_matches
                .get_one::<String>("THREAT_ID")
                .expect("THREAT_ID not provided")
                .to_string();
            // Initialize the core with computing enabled
            initialize_core("".to_string(), true, false, false, false, verbose);
            base_get_threat_info(threat_id);
        }
        Some(("list-threats", _)) => {
            // Initialize the core with computing enabled
            initialize_core("".to_string(), true, false, false, false, verbose);
            base_list_threats();
        }
        Some(("get-system-info", _)) => {
            // Initialize the core with all options disabled
            initialize_core("".to_string(), false, false, false, false, verbose);
            ensure_admin();
            base_get_system_info();
        }
        Some(("request-signature", _)) => {
            // Initialize the core with computing enabled
            initialize_core("".to_string(), true, false, false, false, false);
            ensure_admin();
            // Display the score
            base_get_score(true);
            // Request the signature
            exit_code = base_request_signature();
        }
        Some(("request-report", sub_matches)) => {
            let email = sub_matches.get_one::<String>("EMAIL").unwrap().to_string();
            let signature = sub_matches
                .get_one::<String>("SIGNATURE")
                .unwrap()
                .to_string();
            // Initialize the core with all options disabled
            initialize_core("".to_string(), false, false, false, false, verbose);
            exit_code = base_request_report(email, signature);
        }
        //////////////////////
        // Background commands
        //////////////////////
        Some(("background-logs", _)) => {
            // Initialize the core with all options disabled
            initialize_core("".to_string(), false, false, false, false, verbose);

            let logs = match rpc_get_all_logs(
                &EDAMAME_CA_PEM,
                &EDAMAME_CLIENT_PEM,
                &EDAMAME_CLIENT_KEY,
                &EDAMAME_TARGET,
            ) {
                Ok(logs) => logs,
                Err(e) => {
                    eprintln!("Error getting logs: {:?}", e);
                    exit_code = ERROR_CODE_SERVER_ERROR;
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
            // Initialize the core with all options disabled
            initialize_core("".to_string(), false, false, false, false, verbose);
            is_background = true;
            exit_code = background_wait_for_connection(*timeout);
        }
        Some(("background-get-sessions", sub_matches)) => {
            let zeek_format = sub_matches.get_one::<bool>("ZEEK_FORMAT").unwrap_or(&false);
            let local_traffic = sub_matches
                .get_one::<bool>("LOCAL_TRAFFIC")
                .unwrap_or(&false);
            let check_anomalous = sub_matches
                .get_one::<bool>("CHECK_ANOMALOUS")
                .unwrap_or(&false);
            let check_blacklisted = sub_matches
                .get_one::<bool>("CHECK_BLACKLIST")
                .unwrap_or(&true);
            let check_whitelisted = sub_matches
                .get_one::<bool>("CHECK_WHITELIST")
                .unwrap_or(&true);

            // Initialize the core with all options disabled
            initialize_core("".to_string(), false, false, false, false, verbose);
            exit_code = background_get_sessions(
                *zeek_format,
                *local_traffic,
                *check_anomalous,
                *check_blacklisted,
                *check_whitelisted,
            );
            is_background = true;
        }
        Some(("background-get-exceptions", sub_matches)) => {
            let zeek_format = sub_matches.get_one::<bool>("ZEEK_FORMAT").unwrap_or(&false);
            let local_traffic = sub_matches
                .get_one::<bool>("LOCAL_TRAFFIC")
                .unwrap_or(&false);

            // Initialize the core with all options disabled
            initialize_core("".to_string(), false, false, false, false, verbose);
            exit_code = background_get_exceptions(*zeek_format, *local_traffic);
            is_background = true;
        }
        Some(("background-get-anomalous-sessions", sub_matches)) => {
            let zeek_format = sub_matches.get_one::<bool>("ZEEK_FORMAT").unwrap_or(&false);

            // Initialize the core with all options disabled
            initialize_core("".to_string(), false, false, false, false, verbose);
            exit_code = background_get_anomalous_sessions(*zeek_format);
            is_background = true;
        }
        Some(("background-get-blacklisted-sessions", sub_matches)) => {
            let zeek_format = sub_matches.get_one::<bool>("ZEEK_FORMAT").unwrap_or(&false);

            // Initialize the core with all options disabled
            initialize_core("".to_string(), false, false, false, false, verbose);
            exit_code = background_get_blacklisted_sessions(*zeek_format);
            is_background = true;
        }
        Some(("background-threats-info", _)) => {
            // Initialize the core with all options disabled
            initialize_core("".to_string(), false, false, false, false, verbose);
            ensure_admin();
            exit_code = background_get_threats_info();
            is_background = true;
        }
        Some(("background-get-history", _)) => {
            // Initialize the core with all options disabled
            initialize_core("".to_string(), false, false, false, false, verbose);
            exit_code = background_get_history();
            is_background = true;
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
            // Initialize the core with all options disabled
            initialize_core("".to_string(), false, false, false, false, verbose);
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
            is_background = true;
        }
        Some(("background-start-disconnected", sub_matches)) => {
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

            // Initialize the core with all options disabled
            initialize_core("".to_string(), false, false, false, false, verbose);
            ensure_admin();
            background_start(
                "".to_string(),
                "".to_string(),
                "".to_string(),
                "".to_string(),
                *lan_scanning,
                whitelist_name,
                *local_traffic,
            );
            is_background = true;
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
                verbose,
            );
        }
        Some(("background-stop", _)) => {
            // Initialize the core with all options disabled
            initialize_core("".to_string(), false, false, false, false, verbose);
            exit_code = background_stop();
            is_background = true;
        }
        Some(("background-status", _)) => {
            // Initialize the core with all options disabled
            initialize_core("".to_string(), false, false, false, false, verbose);
            exit_code = background_get_status();
            is_background = true;
        }
        Some(("background-last-report-signature", _)) => {
            // Initialize the core with all options disabled
            initialize_core("".to_string(), false, false, false, false, verbose);
            exit_code = background_get_last_report_signature();
            is_background = true;
        }
        Some(("background-set-custom-whitelists", sub_matches)) => {
            let whitelist_json = sub_matches
                .get_one::<String>("WHITELIST_JSON")
                .expect("WHITELIST_JSON not provided")
                .to_string();
            // Initialize the core with all options disabled
            initialize_core("".to_string(), false, false, false, false, verbose);
            exit_code = background_set_custom_whitelists(whitelist_json);
            is_background = true;
        }
        Some(("background-set-custom-blacklists", sub_matches)) => {
            let blacklist_json = sub_matches
                .get_one::<String>("BLACKLIST_JSON")
                .expect("BLACKLIST_JSON not provided")
                .to_string();
            // Initialize the core with all options disabled
            initialize_core("".to_string(), false, false, false, false, verbose);
            exit_code = background_set_custom_blacklists(blacklist_json);
            is_background = true;
        }
        Some(("background-create-custom-whitelists", _)) => {
            // Initialize the core with all options disabled
            initialize_core("".to_string(), false, false, false, false, verbose);
            exit_code = background_create_custom_whitelists();
            is_background = true;
        }
        Some(("background-create-and-set-custom-whitelists", _)) => {
            // Initialize the core with all options disabled
            initialize_core("".to_string(), false, false, false, false, verbose);
            exit_code = background_create_and_set_custom_whitelists();
            is_background = true;
        }
        Some(("background-score", _)) => {
            // Initialize the core with all options disabled
            initialize_core("".to_string(), false, false, false, false, verbose);
            exit_code = background_get_score();
            is_background = true;
        }
        Some(("background-get-blacklists", _)) => {
            // Initialize the core with all options disabled
            initialize_core("".to_string(), false, false, false, false, verbose);
            exit_code = background_get_blacklists();
            is_background = true;
        }
        Some(("background-get-whitelists", _)) => {
            // Initialize the core with all options disabled
            initialize_core("".to_string(), false, false, false, false, verbose);
            exit_code = background_get_whitelists();
            is_background = true;
        }
        Some(("background-get-whitelist-name", _)) => {
            // Initialize the core with all options disabled
            initialize_core("".to_string(), false, false, false, false, verbose);
            exit_code = background_get_whitelist_name();
            is_background = true;
        }
        _ => {
            // Initialize the core with all options disabled
            initialize_core("".to_string(), false, false, false, false, verbose);
            eprintln!("Invalid command, use --help for more information");
            exit_code = ERROR_CODE_PARAM;
        }
    }

    // Dump the logs in case of server or timeout error when calling the background process
    if is_background && (exit_code == ERROR_CODE_SERVER_ERROR || exit_code == ERROR_CODE_TIMEOUT) {
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

    exit(exit_code);
}

pub fn main() {
    run();
}
